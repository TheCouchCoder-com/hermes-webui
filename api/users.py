"""
User records for multi-user RBAC (issue #2).

Persists per-user accounts to STATE_DIR/.users.json (atomic write + .bak).
Each record carries:
  - id, username, password_hash (PBKDF2-SHA256 via api.auth._hash_password)
  - role: 'admin' | 'user'
  - assigned_profile: the user's default Hermes profile (cookie set on login)
  - allowed_profiles: list of profiles the user may switch to (None = all)
  - permissions: per-feature toggles (see _DEFAULT_PERMISSIONS)
  - must_change_password: forces a password change on next login
  - created_at, last_login_at: ISO-8601 UTC timestamps

Design notes
  - This module does NOT take any web-layer dependency. The caller provides
    plaintext passwords; api.auth._hash_password produces the stored hash.
    Keeping the hash function out of this module avoids an import cycle
    (api.auth imports STATE_DIR from api.config; api.users imports auth's
    hash function only inside functions that need it).
  - File access is wrapped in a single RLock (_users_lock) — the call rate
    is dominated by login lookups (cache hit) and rare admin mutations.
  - load_users() returns a deep copy so callers can mutate freely without
    leaking state into the cache.
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
import time
import uuid
from copy import deepcopy
from typing import Any, Optional

from api._atomic import atomic_write_json
from api.config import STATE_DIR

logger = logging.getLogger(__name__)

USERS_FILE = STATE_DIR / '.users.json'
USERS_BAK = STATE_DIR / '.users.json.bak'

SCHEMA_VERSION = 1
ROLES = frozenset({'admin', 'user'})

# Permissions exposed in the admin UI. manage_users is stored on the record
# for completeness but is implicitly true for role==admin and never editable
# via the per-user toggle.
PERMISSION_KEYS = (
    'switch_profile',
    'edit_settings',
    'manage_cron',
    'manage_skills',
    'manage_users',
)

_DEFAULT_PERMISSIONS = {
    'switch_profile': True,
    'edit_settings': False,
    'manage_cron': True,
    'manage_skills': True,
    'manage_users': False,
}

# Username syntax: lowercase, alphanumeric + . _ -, 1-32 chars, must start
# with a letter or digit. Lowercase-only avoids case-collision ambiguity.
USERNAME_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,31}$')

# Profile name regex (mirrors api.profiles._PROFILE_ID_RE). Duplicated here
# rather than imported to avoid pulling api.profiles (which imports the
# Hermes agent) into auth-only paths.
_PROFILE_ID_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')

MIN_PASSWORD_LENGTH = 8

_users_lock = threading.RLock()
_users_cache: Optional[dict] = None


# ── Validation ──────────────────────────────────────────────────────────────

class UserValidationError(ValueError):
    """Raised when a user record fails validation. Distinguishes structural
    errors from runtime errors (e.g. duplicate username, last-admin guard)."""


def _now_iso() -> str:
    """UTC ISO-8601 timestamp with second resolution and 'Z' suffix."""
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _validate_username(name: Any) -> str:
    if not isinstance(name, str) or not USERNAME_RE.fullmatch(name):
        raise UserValidationError(
            f"username must match {USERNAME_RE.pattern!r}; got {name!r}"
        )
    return name


def _validate_role(role: Any) -> str:
    if role not in ROLES:
        raise UserValidationError(f"role must be one of {sorted(ROLES)!r}; got {role!r}")
    return role


def _validate_profile_name(name: Any, *, field: str) -> str:
    if not isinstance(name, str) or not _PROFILE_ID_RE.fullmatch(name):
        raise UserValidationError(
            f"{field} must match {_PROFILE_ID_RE.pattern!r}; got {name!r}"
        )
    return name


def _validate_allowed_profiles(value: Any) -> Optional[list[str]]:
    """None or [] means 'all profiles'. Otherwise a list of valid names."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise UserValidationError("allowed_profiles must be a list or null")
    if not value:
        return None  # empty list normalised to None
    out = []
    for n in value:
        out.append(_validate_profile_name(n, field='allowed_profiles entry'))
    # Deduplicate while preserving order.
    seen = set()
    deduped = []
    for n in out:
        if n not in seen:
            seen.add(n)
            deduped.append(n)
    return deduped


def _coerce_permissions(p: Any) -> dict:
    """Fill missing keys with defaults; coerce values to bool. Unknown keys
    are dropped silently to keep the file format forward-compatible."""
    out = dict(_DEFAULT_PERMISSIONS)
    if isinstance(p, dict):
        for k in PERMISSION_KEYS:
            if k in p:
                out[k] = bool(p[k])
    return out


def _validate_password(plain: Any) -> str:
    if not isinstance(plain, str):
        raise UserValidationError("password must be a string")
    if len(plain) < MIN_PASSWORD_LENGTH:
        raise UserValidationError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    return plain


def _validate_record(rec: Any) -> dict:
    """Validate a single user record (raises on failure). Returns a normalised
    copy with all canonical fields present."""
    if not isinstance(rec, dict):
        raise UserValidationError("user record must be a dict")
    out = {
        'id': rec.get('id'),
        'username': _validate_username(rec.get('username')),
        'password_hash': rec.get('password_hash'),
        'role': _validate_role(rec.get('role')),
        'assigned_profile': _validate_profile_name(
            rec.get('assigned_profile'), field='assigned_profile'
        ),
        'allowed_profiles': _validate_allowed_profiles(rec.get('allowed_profiles')),
        'permissions': _coerce_permissions(rec.get('permissions')),
        'must_change_password': bool(rec.get('must_change_password', False)),
        'created_at': rec.get('created_at') or _now_iso(),
        'last_login_at': rec.get('last_login_at'),
    }
    if not isinstance(out['id'], str) or not out['id']:
        raise UserValidationError("id must be a non-empty string")
    if not isinstance(out['password_hash'], str) or not out['password_hash']:
        raise UserValidationError("password_hash must be a non-empty string")
    # If allowed_profiles is set, assigned_profile must be in it.
    if out['allowed_profiles'] is not None and out['assigned_profile'] not in out['allowed_profiles']:
        raise UserValidationError(
            f"assigned_profile {out['assigned_profile']!r} must be in allowed_profiles"
        )
    return out


# ── Persistence ─────────────────────────────────────────────────────────────

def _empty_payload() -> dict:
    return {'version': SCHEMA_VERSION, 'users': []}


def _load_from_disk() -> dict:
    """Read .users.json (or .users.json.bak), validate, return normalised
    payload. On unrecoverable corruption returns an empty payload and logs."""
    for path in (USERS_FILE, USERS_BAK):
        if not path.exists():
            continue
        try:
            import json
            data = json.loads(path.read_text(encoding='utf-8'))
        except Exception as e:
            logger.warning("users file %s failed to parse: %s", path, e)
            continue
        if not isinstance(data, dict):
            logger.warning("users file %s is not a dict, ignoring", path)
            continue
        if data.get('version') != SCHEMA_VERSION:
            logger.warning(
                "users file %s has unknown schema version %r, ignoring",
                path, data.get('version'),
            )
            continue
        users_raw = data.get('users')
        if not isinstance(users_raw, list):
            logger.warning("users file %s has malformed 'users' field, ignoring", path)
            continue
        normalised = []
        for u in users_raw:
            try:
                normalised.append(_validate_record(u))
            except UserValidationError as e:
                logger.warning("users file %s: dropping invalid record: %s", path, e)
        if path is USERS_BAK:
            logger.warning("Recovered users from backup: %s", USERS_BAK)
        return {'version': SCHEMA_VERSION, 'users': normalised}
    return _empty_payload()


def _ensure_cache_loaded() -> None:
    global _users_cache
    if _users_cache is None:
        _users_cache = _load_from_disk()


def _persist(payload: dict) -> None:
    atomic_write_json(USERS_FILE, payload, mode=0o600, backup_path=USERS_BAK)


def load_users() -> list[dict]:
    """Return a deep copy of all user records. Caller may mutate freely."""
    with _users_lock:
        _ensure_cache_loaded()
        return [deepcopy(u) for u in _users_cache['users']]


def reload_users() -> None:
    """Force re-read from disk (for tests and admin reload)."""
    global _users_cache
    with _users_lock:
        _users_cache = None
        _ensure_cache_loaded()


def get_user_by_id(user_id: str) -> Optional[dict]:
    with _users_lock:
        _ensure_cache_loaded()
        for u in _users_cache['users']:
            if u['id'] == user_id:
                return deepcopy(u)
    return None


def get_user_by_username(username: str) -> Optional[dict]:
    if not isinstance(username, str):
        return None
    target = username.lower()
    with _users_lock:
        _ensure_cache_loaded()
        for u in _users_cache['users']:
            if u['username'] == target:
                return deepcopy(u)
    return None


def count_admins() -> int:
    with _users_lock:
        _ensure_cache_loaded()
        return sum(1 for u in _users_cache['users'] if u['role'] == 'admin')


# ── Mutations ───────────────────────────────────────────────────────────────

def _hash(plain: str) -> str:
    # Imported lazily to break the api.auth ↔ api.users cycle.
    from api.auth import _hash_password
    return _hash_password(plain)


def create_user(
    *,
    username: str,
    password: str,
    role: str,
    assigned_profile: str,
    allowed_profiles: Optional[list[str]] = None,
    permissions: Optional[dict] = None,
    must_change_password: bool = False,
    password_hash: Optional[str] = None,
) -> dict:
    """Create and persist a user.

    Either `password` (plaintext, will be hashed) or `password_hash` (already
    hashed by api.auth._hash_password) must be supplied. The migration path
    uses `password_hash` to copy a legacy single-password hash directly.
    """
    if password_hash is None:
        _validate_password(password)
        password_hash = _hash(password)

    record = _validate_record({
        'id': uuid.uuid4().hex,
        'username': username.lower() if isinstance(username, str) else username,
        'password_hash': password_hash,
        'role': role,
        'assigned_profile': assigned_profile,
        'allowed_profiles': allowed_profiles,
        'permissions': permissions or {},
        'must_change_password': must_change_password,
        'created_at': _now_iso(),
        'last_login_at': None,
    })

    with _users_lock:
        _ensure_cache_loaded()
        if any(u['username'] == record['username'] for u in _users_cache['users']):
            raise UserValidationError(f"username {record['username']!r} already exists")
        _users_cache['users'].append(record)
        _persist(_users_cache)
    return deepcopy(record)


def update_user(user_id: str, **patch) -> dict:
    """Apply a subset of fields to a user record. Username is NOT editable.
    `password` (plaintext) and `password_hash` (pre-hashed) are both accepted;
    the latter wins if both are provided.
    """
    allowed = {
        'role', 'assigned_profile', 'allowed_profiles',
        'permissions', 'must_change_password',
    }
    unknown = set(patch.keys()) - (allowed | {'password', 'password_hash'})
    if unknown:
        raise UserValidationError(f"unknown patch fields: {sorted(unknown)}")

    with _users_lock:
        _ensure_cache_loaded()
        for i, u in enumerate(_users_cache['users']):
            if u['id'] != user_id:
                continue
            merged = dict(u)
            for k in allowed:
                if k in patch:
                    merged[k] = patch[k]
            if 'password_hash' in patch and patch['password_hash']:
                merged['password_hash'] = patch['password_hash']
            elif 'password' in patch and patch['password'] is not None:
                _validate_password(patch['password'])
                merged['password_hash'] = _hash(patch['password'])
            # Validating before commit ensures no partial state on failure.
            normalised = _validate_record(merged)
            # Last-admin demotion guard.
            if u['role'] == 'admin' and normalised['role'] != 'admin':
                if count_admins() <= 1:
                    raise UserValidationError(
                        "cannot demote the only remaining admin"
                    )
            _users_cache['users'][i] = normalised
            _persist(_users_cache)
            return deepcopy(normalised)
    raise KeyError(user_id)


def set_password(user_id: str, new_password: str, *, must_change: bool = False) -> dict:
    """Convenience wrapper for the 'admin resets a user's password' path.
    Always (re)hashes the plaintext."""
    _validate_password(new_password)
    return update_user(
        user_id,
        password=new_password,
        must_change_password=must_change,
    )


def delete_user(user_id: str) -> dict:
    """Remove a user. Last-admin guard: refuses if it would leave zero admins."""
    with _users_lock:
        _ensure_cache_loaded()
        for i, u in enumerate(_users_cache['users']):
            if u['id'] != user_id:
                continue
            if u['role'] == 'admin' and count_admins() <= 1:
                raise UserValidationError(
                    "cannot delete the only remaining admin"
                )
            removed = _users_cache['users'].pop(i)
            _persist(_users_cache)
            return deepcopy(removed)
    raise KeyError(user_id)


def record_login(user_id: str) -> None:
    """Bump last_login_at on successful login. Best-effort: never raises."""
    try:
        with _users_lock:
            _ensure_cache_loaded()
            for u in _users_cache['users']:
                if u['id'] == user_id:
                    u['last_login_at'] = _now_iso()
                    _persist(_users_cache)
                    return
    except Exception as e:
        logger.debug("record_login(%s) failed: %s", user_id, e)


# ── Authorization helpers ───────────────────────────────────────────────────

def has_permission(user: Optional[dict], key: str) -> bool:
    """Resolve a permission for a user record.

    Admins have every permission. Non-admins consult `permissions[key]`,
    falling back to `_DEFAULT_PERMISSIONS` if the key is missing. The
    special `manage_users` key is admin-only by design.
    """
    if user is None:
        return False
    if user.get('role') == 'admin':
        return True
    if key == 'manage_users':
        return False
    perms = user.get('permissions') or {}
    if key in perms:
        return bool(perms[key])
    return _DEFAULT_PERMISSIONS.get(key, False)


def is_profile_allowed(user: Optional[dict], profile: str) -> bool:
    """True if `user` is permitted to switch into `profile`. Admins and users
    with allowed_profiles==None can use any profile; otherwise the profile
    must appear in their allowed_profiles list."""
    if user is None:
        return False
    if user.get('role') == 'admin':
        return True
    allowed = user.get('allowed_profiles')
    if allowed is None:
        return True
    return profile in allowed


# ── Bootstrap / migration helpers ──────────────────────────────────────────

def has_users() -> bool:
    """True iff at least one user record is configured."""
    return bool(load_users())


def generate_user_id() -> str:
    """Convenience for tests and migration code that pre-mints IDs."""
    return uuid.uuid4().hex


def generate_token() -> str:
    """Return a fresh hex token (for password-reset flows etc.)."""
    return secrets.token_hex(16)
