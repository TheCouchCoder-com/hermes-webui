"""
Hermes Web UI -- optional authentication.
Off by default. Enable by setting HERMES_WEBUI_PASSWORD, configuring a
password in Settings, or registering passkeys and then going passwordless.
"""
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import secrets
import tempfile
import threading
import time

from api._atomic import atomic_write_json
from api.config import STATE_DIR, load_settings

logger = logging.getLogger(__name__)


# Default session TTL — 30 days. Kept as a module-level constant for backwards
# compatibility with downstream code and regression tests that import it.
# At runtime, prefer ``_resolve_session_ttl()`` which honours the env var and
# settings.json overrides; this constant is the floor / fallback.
SESSION_TTL = 86400 * 30  # 30 days


def _resolve_session_ttl() -> int:
    """Resolve session TTL from env > settings > default.

    Priority mirrors get_password_hash(): HERMES_WEBUI_SESSION_TTL env var
    first, then settings.json, falling back to ``SESSION_TTL`` (30 days).
    Clamped to [60s, 1 year] to prevent runaway cookies or self-lockout.
    """
    env_v = os.getenv('HERMES_WEBUI_SESSION_TTL', '').strip()
    if env_v.isdigit():
        val = int(env_v)
        if 60 <= val <= 86400 * 365:
            return val
    s = load_settings()
    v = s.get('session_ttl_seconds')
    if isinstance(v, int) and 60 <= v <= 86400 * 365:
        return v
    return SESSION_TTL


# ── Public paths (no auth required) ─────────────────────────────────────────
PUBLIC_PATHS = frozenset({
    '/login', '/health', '/favicon.ico', '/sw.js',
    '/api/auth/login', '/api/auth/status', '/api/auth/bootstrap',
    '/api/auth/passkey/options', '/api/auth/passkey/login',
    '/manifest.json', '/manifest.webmanifest',
    '/session/manifest.json', '/session/manifest.webmanifest',
})

COOKIE_NAME = 'hermes_session'
CSRF_HEADER_NAME = 'X-Hermes-CSRF-Token'

_SESSIONS_FILE = STATE_DIR / '.sessions.json'


def _session_expiry(entry) -> float:
    """Extract the expiry timestamp from a session record.

    Two record shapes are accepted (issue #2 schema bump):
      - float / int     — legacy single-password session, no user_id binding
      - dict {expiry, user_id?} — new multi-user record

    Tests assign raw floats directly to _sessions[token], so this helper
    keeps that ergonomic while internal callers can rely on a float.
    """
    if isinstance(entry, (int, float)):
        return float(entry)
    if isinstance(entry, dict):
        exp = entry.get('expiry')
        if isinstance(exp, (int, float)):
            return float(exp)
    return 0.0


def _session_user_id(entry):
    """Return the user_id attached to a session record, or None for legacy
    float records and any malformed entry."""
    if isinstance(entry, dict):
        uid = entry.get('user_id')
        return uid if isinstance(uid, str) else None
    return None


def _load_sessions() -> dict:
    """Load persisted sessions from STATE_DIR, pruning expired entries.

    Returns an empty dict on any read or parse error so startup is never
    blocked by a corrupt or missing sessions file.
    """
    try:
        if _SESSIONS_FILE.exists():
            data = json.loads(_SESSIONS_FILE.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('malformed sessions file — expected dict')
            now = time.time()
            out = {}
            for t, entry in data.items():
                if not isinstance(t, str):
                    continue
                exp = _session_expiry(entry)
                if exp <= now:
                    continue
                out[t] = entry
            return out
    except Exception as e:
        logger.debug("Failed to load sessions file, starting fresh: %s", e)
    return {}


def _save_sessions(sessions: dict) -> None:
    """Atomically persist sessions to STATE_DIR/.sessions.json (0600)."""
    try:
        atomic_write_json(_SESSIONS_FILE, sessions, mode=0o600)
    except Exception as e:
        logger.debug("Failed to persist sessions: %s", e)


# Active sessions: token -> expiry timestamp (persisted across restarts via STATE_DIR)
_sessions = _load_sessions()
_SESSIONS_LOCK = threading.Lock()

# ── Login rate limiter ──────────────────────────────────────────────────────
# Two parallel buckets: per-IP and per-username (issue #2). The per-username
# bucket prevents an attacker from cycling source IPs to brute-force one
# account. Both buckets persist across restarts (upstream v0.51.29) so an
# attacker can't dodge the limiter by triggering a process restart.
_LOGIN_ATTEMPTS_FILE = STATE_DIR / '.login_attempts.json'
_LOGIN_ATTEMPTS_USER_FILE = STATE_DIR / '.login_attempts_user.json'
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 60  # seconds


def _load_login_attempts_from(path) -> dict[str, list[float]]:
    """Load persisted login attempts from *path*, pruning expired entries."""
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('malformed login-attempts file — expected dict')
            now = time.time()
            attempts: dict[str, list[float]] = {}
            for key, raw_times in data.items():
                if not isinstance(key, str) or not isinstance(raw_times, list):
                    continue
                fresh = [
                    float(t)
                    for t in raw_times
                    if isinstance(t, (int, float)) and now - float(t) < _LOGIN_WINDOW
                ]
                if fresh:
                    attempts[key] = fresh
            return attempts
    except Exception as e:
        logger.debug("Failed to load login attempts file %s, starting fresh: %s", path, e)
    return {}


def _save_login_attempts_to(path, attempts: dict[str, list[float]]) -> None:
    """Atomically persist login attempts to *path* (0600)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix='.login_attempts.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(attempts, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.debug("Failed to persist login attempts to %s: %s", path, e)


# Back-compat aliases. Upstream's issue-#1910 tests reference the
# single-bucket helpers `_load_login_attempts` / `_save_login_attempts`; our
# fork's _from/_to variants take an explicit path so the IP bucket and the
# (fork-only) per-username bucket can share the same persistence logic.
def _load_login_attempts() -> dict[str, list[float]]:
    return _load_login_attempts_from(_LOGIN_ATTEMPTS_FILE)


def _save_login_attempts(attempts: dict[str, list[float]]) -> None:
    _save_login_attempts_to(_LOGIN_ATTEMPTS_FILE, attempts)


_login_attempts = _load_login_attempts_from(_LOGIN_ATTEMPTS_FILE)              # ip -> [timestamp, ...]
_login_attempts_user = _load_login_attempts_from(_LOGIN_ATTEMPTS_USER_FILE)    # username (lower) -> [timestamp, ...]
_LOGIN_ATTEMPTS_LOCK = threading.Lock()


def _check_login_rate(ip: str, username: str | None = None) -> bool:
    """Return True if the request is allowed to attempt login (thread-safe).
    Either bucket exhausted (IP or username) blocks the attempt."""
    with _LOGIN_ATTEMPTS_LOCK:
        now = time.time()
        ip_attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_WINDOW]
        if ip_attempts:
            _login_attempts[ip] = ip_attempts
        else:
            _login_attempts.pop(ip, None)
        _save_login_attempts_to(_LOGIN_ATTEMPTS_FILE, _login_attempts)
        if len(ip_attempts) >= _LOGIN_MAX_ATTEMPTS:
            return False
        if username:
            u = username.lower()
            u_attempts = [t for t in _login_attempts_user.get(u, []) if now - t < _LOGIN_WINDOW]
            if u_attempts:
                _login_attempts_user[u] = u_attempts
            else:
                _login_attempts_user.pop(u, None)
            _save_login_attempts_to(_LOGIN_ATTEMPTS_USER_FILE, _login_attempts_user)
            if len(u_attempts) >= _LOGIN_MAX_ATTEMPTS:
                return False
        return True


def _record_login_attempt(ip: str, username: str | None = None) -> None:
    """Record a login attempt for rate limiting (thread-safe)."""
    with _LOGIN_ATTEMPTS_LOCK:
        now = time.time()
        _login_attempts.setdefault(ip, []).append(now)
        _save_login_attempts_to(_LOGIN_ATTEMPTS_FILE, _login_attempts)
        if username:
            _login_attempts_user.setdefault(username.lower(), []).append(now)
            _save_login_attempts_to(_LOGIN_ATTEMPTS_USER_FILE, _login_attempts_user)


def _clear_login_attempts(ip: str) -> None:
    """Clear failed login attempts after a successful login (thread-safe)."""
    with _LOGIN_ATTEMPTS_LOCK:
        if ip in _login_attempts:
            _login_attempts.pop(ip, None)
            _save_login_attempts(_login_attempts)


def _load_key(filename: str) -> bytes:
    """Load a 32-byte key from STATE_DIR, generating and persisting one if missing."""
    key_file = STATE_DIR / filename
    try:
        if key_file.exists():
            raw = key_file.read_bytes()
            if len(raw) >= 32:
                return raw[:32]
    except OSError:
        logger.debug("Failed to read key %s", filename)
    key = secrets.token_bytes(32)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        key_file.chmod(0o600)
    except OSError:
        logger.debug("Failed to persist key %s", filename)
    return key


_PBKDF2_KEY_CACHE: bytes | None = None
_SIGNING_KEY_CACHE: bytes | None = None


def _pbkdf2_key() -> bytes:
    global _PBKDF2_KEY_CACHE
    if _PBKDF2_KEY_CACHE is None:
        _PBKDF2_KEY_CACHE = _load_key('.pbkdf2_key')
    return _PBKDF2_KEY_CACHE


def _signing_key() -> bytes:
    global _SIGNING_KEY_CACHE
    if _SIGNING_KEY_CACHE is None:
        _SIGNING_KEY_CACHE = _load_key('.signing_key')
    return _SIGNING_KEY_CACHE


def _hash_password(password, *, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256 with 600k iterations (OWASP recommendation).
    Salt is the persisted PBKDF2 key, which is secret and unique per
    installation. This keeps the stored hash format a plain hex string
    (no format change to settings.json) while replacing the predictable
    STATE_DIR-derived salt from the original implementation.

    The iteration count is fixed at the OWASP recommendation in production.
    The test suite overrides it via HERMES_WEBUI_PBKDF2_ITERATIONS to a much
    smaller value so the ~150 password-hashing tests don't bottleneck CI;
    the env var is **never** honoured outside conftest-managed test runs.

    The *salt* parameter exists solely to support transparent migration of
    password hashes computed with a different key (the legacy `.signing_key`
    vs. `.pbkdf2_key` upstream introduced). Normal callers should never pass
    it. Default stays on `.signing_key` to preserve existing fork installs.
    """
    if salt is None:
        salt = _signing_key()
    iters_override = os.getenv('HERMES_WEBUI_PBKDF2_ITERATIONS', '').strip()
    iters = 600_000
    if iters_override.isdigit() and os.getenv('HERMES_WEBUI_TEST_FAST_HASH') == '1':
        iters = max(1000, int(iters_override))
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iters)
    return dk.hex()


_AUTH_HASH_LOCK = threading.Lock()
_AUTH_HASH_COMPUTED: bool = False
_AUTH_HASH_CACHE: str | None = None


def _invalidate_password_hash_cache() -> None:
    """Invalidate the in-process password hash cache so the next call to
    get_password_hash() re-reads from settings.json or the env var."""
    global _AUTH_HASH_COMPUTED, _AUTH_HASH_CACHE
    with _AUTH_HASH_LOCK:
        _AUTH_HASH_COMPUTED = False
        _AUTH_HASH_CACHE = None


def get_password_hash() -> str | None:
    """Return the active password hash, or None if auth is disabled.
    Priority: env var > settings.json.

    The hash is computed once and cached for the lifetime of the process.
    PBKDF2-600k takes ~1 s and is called on nearly every HTTP request via
    check_auth → is_auth_enabled, so caching avoids wasting a full second
    of CPU per request after the first one.

    Thread-safe: double-checked locking ensures that under a burst of
    concurrent requests only one thread computes PBKDF2, while the fast
    path (after initialisation) requires zero locks.
    """
    global _AUTH_HASH_COMPUTED, _AUTH_HASH_CACHE

    # Fast path — no lock needed once cache is populated.
    if _AUTH_HASH_COMPUTED:
        return _AUTH_HASH_CACHE

    with _AUTH_HASH_LOCK:
        # Re-check inside lock — another thread may have populated while
        # we were waiting to acquire.
        if _AUTH_HASH_COMPUTED:
            return _AUTH_HASH_CACHE

        env_pw = os.getenv('HERMES_WEBUI_PASSWORD', '').strip()
        if env_pw:
            result = _hash_password(env_pw)
        else:
            result = load_settings().get('password_hash') or None

        _AUTH_HASH_CACHE = result
        _AUTH_HASH_COMPUTED = True
        return result


def is_password_auth_enabled() -> bool:
    """True if a password is configured (env var or settings), or one or more
    multi-user records exist in .users.json (issue #2).

    Fork note: upstream's helper only checks the legacy single-password path.
    We extend it with the multi-user (has_users) check so that creating the
    first admin via bootstrap flips auth on even when no shared password is set.
    """
    if get_password_hash() is not None:
        return True
    try:
        from api.users import has_users
        return has_users()
    except Exception:
        return False


def _passkey_feature_flag_enabled() -> bool:
    """Return True if the passkey/WebAuthn surface is enabled for this deployment.

    Passkey support is opt-in default-off behind a feature flag so deployments
    that don't want the WebAuthn surface (or whose RP-ID setup isn't ready for
    non-localhost hosts) can disable it entirely with no UI surface, no
    endpoints, no credential storage. To enable:

      - Set ``HERMES_WEBUI_PASSKEY=1`` in the environment, OR
      - Set ``webui_passkey_enabled: true`` in the per-profile config.yaml

    With the flag off, ``are_passkeys_enabled()`` always returns False even if
    credentials were registered in the past, and ``/login`` shows password-only.
    """
    env_value = os.getenv("HERMES_WEBUI_PASSKEY", "")
    if env_value:
        return env_value.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from api.config import get_config

        cfg = get_config()
        if isinstance(cfg, dict):
            raw = cfg.get("webui_passkey_enabled")
            if isinstance(raw, bool):
                return raw
            if isinstance(raw, str):
                return raw.strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        pass
    return False


def are_passkeys_enabled() -> bool:
    """True if the passkey feature flag is on AND at least one local passkey credential is registered."""
    if not _passkey_feature_flag_enabled():
        return False
    try:
        from api.passkeys import passkeys_available

        return passkeys_available()
    except Exception as exc:
        logger.debug("Failed to inspect passkey availability: %s", exc)
        return False


def is_auth_enabled() -> bool:
    """True if password auth or passkey-only auth is configured."""
    return is_password_auth_enabled() or are_passkeys_enabled()


def verify_password(plain: str) -> bool:
    """Verify a plaintext password against the legacy single-shared-password
    hash. Used only by the migration path in api.startup; new logins go
    through verify_user_credentials. Removed in commit 9 of issue #2.

    Also supports transparent migration of hashes computed with a different
    key (legacy `.signing_key` vs. `.pbkdf2_key`): if the keys differ and
    the legacy-salted hash matches, the password is transparently re-hashed
    with the default salt and persisted to settings.json.
    """
    expected = get_password_hash()
    if not expected:
        return False
    # Fast path: current PBKDF2 key
    if hmac.compare_digest(_hash_password(plain), expected):
        return True
    # Migration: some hashes were computed with `.signing_key` before the
    # PBKDF2 key was separated.  Try the legacy salt; if it matches,
    # transparently upgrade so the next login uses the fast path.
    legacy_salt = _signing_key()
    current_salt = _pbkdf2_key()
    if legacy_salt != current_salt:
        if hmac.compare_digest(_hash_password(plain, salt=legacy_salt), expected):
            from api.config import save_settings

            save_settings({'_set_password': plain})
            # Password re-hashed and persisted to disk using the current salt.
            # Cache invalidation is handled by fix 2/3 (#2192) which adds the
            # _invalidate_password_hash_cache() call inside save_settings().
            return True
    return False


def verify_user_credentials(username: str, password: str):
    """Look up a user by username and compare passwords in constant time.
    Returns the user record on success, None on failure.
    Imported lazily to avoid api.users <-> api.auth import cycle."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    from api.users import get_user_by_username
    user = get_user_by_username(username)
    if not user:
        # Constant-time-equivalent dummy hash so timing doesn't leak
        # whether the username exists.
        _hash_password(password)
        return None
    if hmac.compare_digest(_hash_password(password), user['password_hash']):
        return user
    return None


def create_session(user_id: str | None = None) -> str:
    """Create a new auth session. Returns the signed cookie value.
    `user_id` binds the session to a multi-user record (issue #2). None is
    accepted for backwards compatibility with legacy single-password code
    paths and tests."""
    token = secrets.token_hex(32)
    with _SESSIONS_LOCK:
        _sessions[token] = {'user_id': user_id, 'expiry': time.time() + _resolve_session_ttl()}
        _save_sessions(_sessions)
    sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{sig}"


def _prune_expired_sessions():
    """Remove all expired session entries to prevent unbounded memory growth."""
    now = time.time()
    with _SESSIONS_LOCK:
        expired = [t for t, entry in _sessions.items() if now > _session_expiry(entry)]
        if expired:
            for token in expired:
                _sessions.pop(token, None)
            _save_sessions(_sessions)


def verify_session(cookie_value: str) -> bool:
    """Verify a signed session cookie. Returns True if valid and not expired."""
    return _session_record_for_cookie(cookie_value) is not None


def _session_record_for_cookie(cookie_value):
    """Return (token, entry) for a valid signed cookie, or None.
    Centralised so verify_session and current_session share validation."""
    if not cookie_value or '.' not in cookie_value:
        return None
    _prune_expired_sessions()
    token, sig = cookie_value.rsplit('.', 1)
    full_sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()
    # Accept both new (64-char) and legacy (32-char truncated) signatures so
    # existing sessions survive the upgrade without a forced global logout.
    # The legacy branch can be removed once session TTLs have expired (~30 days).
    valid = hmac.compare_digest(sig, full_sig) or (
        len(sig) == 32 and hmac.compare_digest(sig, full_sig[:32])
    )
    if not valid:
        return None
    with _SESSIONS_LOCK:
        entry = _sessions.get(token)
        if entry is None:
            return None
        if time.time() > _session_expiry(entry):
            _sessions.pop(token, None)
            _save_sessions(_sessions)
            return None
    return (token, entry)


def current_session(cookie_value):
    """Return a normalised session dict {token, user_id, expiry} or None."""
    rec = _session_record_for_cookie(cookie_value)
    if rec is None:
        return None
    token, entry = rec
    return {
        'token': token,
        'user_id': _session_user_id(entry),
        'expiry': _session_expiry(entry),
    }


def current_user(handler):
    """Resolve the user record bound to the request, or None.

    None covers three cases: auth disabled, no/invalid cookie, or
    legacy unbound session (user_id=None). Callers needing 'logged in
    AND has user record' should treat None as 'unauthenticated'.
    """
    if not is_auth_enabled():
        return None
    cookie_val = parse_cookie(handler)
    sess = current_session(cookie_val)
    if not sess or not sess.get('user_id'):
        return None
    from api.users import get_user_by_id
    return get_user_by_id(sess['user_id'])


def require_user(handler):
    """Check that the request comes from a logged-in user with a bound user
    record. Sends 401 and returns None on failure; returns the user record
    on success.

    When auth is disabled (no legacy password and no users configured),
    returns a synthetic "anonymous admin" record so any caller that gates
    on require_user / require_admin / require_perm passes through. This
    preserves the legacy "auth off = wide open" contract that existing
    callers (and tests) depend on. Once any user is created, real auth
    kicks in and this fallback is bypassed.

    Callers pattern:
        u = require_user(handler)
        if u is None:
            return True   # response already sent; abort handler
        ...
    """
    if not is_auth_enabled():
        return _ANONYMOUS_ADMIN
    user = current_user(handler)
    if user is None:
        _send_json(handler, 401, {'error': 'authentication required'})
        return None
    return user


# Synthetic record returned by require_* when auth is disabled. role==admin
# so require_admin and require_perm both pass; manage_users is True so the
# admin endpoints behave consistently. Not persisted, not returned by
# /api/me — only handed back from require_user as an in-memory shim.
_ANONYMOUS_ADMIN = {
    'id': '__anonymous__',
    'username': '__anonymous__',
    'role': 'admin',
    'assigned_profile': 'default',
    'allowed_profiles': None,
    'permissions': {
        'switch_profile': True,
        'edit_settings': True,
        'manage_cron': True,
        'manage_skills': True,
        'manage_users': True,
    },
    'must_change_password': False,
}


def require_admin(handler):
    """As require_user, but additionally requires role==admin (sends 403)."""
    user = require_user(handler)
    if user is None:
        return None
    if user.get('role') != 'admin':
        _send_json(handler, 403, {'error': 'admin role required'})
        return None
    return user


def require_perm(handler, key: str):
    """As require_user, plus checks the named permission via
    api.users.has_permission. Admins always pass."""
    user = require_user(handler)
    if user is None:
        return None
    from api.users import has_permission
    if not has_permission(user, key):
        _send_json(handler, 403, {'error': f'permission denied: {key}'})
        return None
    return user


def _send_json(handler, status: int, payload: dict) -> None:
    """Tiny helper for require_* short-circuits. Doesn't touch CORS or any
    headers beyond Content-Type — those are set by the route layer."""
    body = json.dumps(payload).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _session_token_from_cookie_value(cookie_value: str) -> str | None:
    """Return the raw server-side session token from a signed cookie value."""
    if not cookie_value or '.' not in cookie_value:
        return None
    token, _sig = cookie_value.rsplit('.', 1)
    return token or None


def csrf_token_for_session(cookie_value: str) -> str | None:
    """Return the CSRF token bound to an authenticated WebUI session.

    The browser can read this token from the authenticated shell and echoes it
    in ``X-Hermes-CSRF-Token`` on unsafe API requests. The token is derived
    from the HttpOnly session cookie's server-side token, so it automatically
    rotates on login and is invalidated when the auth session expires or logs
    out. Callers must still verify the auth session before trusting it.
    """
    token = _session_token_from_cookie_value(cookie_value)
    if not token:
        return None
    return hmac.new(_signing_key(), f"csrf:{token}".encode(), hashlib.sha256).hexdigest()


def verify_csrf_token(cookie_value: str, csrf_token: str) -> bool:
    """Verify a submitted CSRF token against the authenticated session."""
    if not cookie_value or not csrf_token or not verify_session(cookie_value):
        return False
    expected = csrf_token_for_session(cookie_value)
    return bool(expected and hmac.compare_digest(str(csrf_token), expected))


def invalidate_session(cookie_value) -> None:
    """Remove a session token."""
    if cookie_value and '.' in cookie_value:
        token = cookie_value.rsplit('.', 1)[0]
        with _SESSIONS_LOCK:
            if token in _sessions:
                _sessions.pop(token, None)
                _save_sessions(_sessions)


def invalidate_sessions_for_user(user_id: str) -> int:
    """Remove every session bound to `user_id` (admin password-reset / delete).
    Returns the count of sessions removed."""
    if not user_id:
        return 0
    to_remove = [t for t, entry in _sessions.items() if _session_user_id(entry) == user_id]
    for t in to_remove:
        _sessions.pop(t, None)
    if to_remove:
        _save_sessions(_sessions)
    return len(to_remove)


def drop_unbound_legacy_sessions() -> int:
    """One-time cleanup at startup after the multi-user migration: drop any
    session record that has no user_id binding. Returns count removed.

    Decision: legacy sessions are unbindable to a user record (they were
    issued before .users.json existed). Forcing one re-login at upgrade is
    cleaner than carrying around sessions that can't be revoked when a user
    is deleted. See issue #2 design notes."""
    to_remove = [t for t, entry in _sessions.items() if _session_user_id(entry) is None]
    for t in to_remove:
        _sessions.pop(t, None)
    if to_remove:
        _save_sessions(_sessions)
    return len(to_remove)


def parse_cookie(handler) -> str | None:
    """Extract the auth cookie from the request headers."""
    cookie_header = handler.headers.get('Cookie', '')
    if not cookie_header:
        return None
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = cookie.get(COOKIE_NAME)
    return morsel.value if morsel else None


def check_auth(handler, parsed) -> bool:
    """Check if request is authorized. Returns True if OK.
    If not authorized, sends 401 (API) or 302 redirect (page) and returns False."""
    if not is_auth_enabled():
        return True
    # Public paths don't require auth
    if parsed.path in PUBLIC_PATHS or parsed.path.startswith('/static/') or parsed.path.startswith('/session/static/'):
        return True
    # Check session cookie
    cookie_val = parse_cookie(handler)
    if cookie_val and verify_session(cookie_val):
        return True
    # Not authorized
    if parsed.path.startswith('/api/'):
        body = b'{"error":"Authentication required"}'
        handler.send_response(401)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    else:
        handler.send_response(302)
        # Pass the original path as ?next= so login.js redirects back after auth.
        # SECURITY/CORRECTNESS: the inner `?` and `&` MUST be percent-encoded
        # when stuffed into the outer `?next=` parameter, otherwise:
        #   (a) multi-param query strings get truncated at the first inner `&`
        #       (e.g. `/api/sessions?limit=50&offset=0` would round-trip as
        #       just `/api/sessions?limit=50` after the browser parses the
        #       outer URL — `offset=0` becomes a separate top-level query
        #       parameter that the login page ignores).
        #   (b) attacker-controlled paths could inject a second `next=`
        #       parameter; per RFC 3986 the duplicate behaviour is undefined
        #       and parsers diverge (Python's parse_qs returns last-match,
        #       URLSearchParams returns first-match), opening a query-pollution
        #       footgun even though _safeNextPath() rejects most malicious
        #       shapes downstream.
        # Encoding the entire `path?query` blob with quote(safe='/') turns
        # `?` → `%3F` and `&` → `%26`, so the outer parameter holds exactly
        # one path-with-query string and `searchParams.get('next')` returns
        # the full original URL (the browser auto-decodes once).
        # (Opus pre-release advisor finding for v0.50.258.)
        import urllib.parse as _urlparse
        _path_with_query = parsed.path or '/'
        if parsed.query:
            _path_with_query += '?' + parsed.query
        # safe='/' keeps path separators readable; everything else (including
        # `?`, `&`, `=`) gets percent-encoded.
        _next = _urlparse.quote(_path_with_query, safe='/')
        handler.send_header('Location', 'login?next=' + _next)
        handler.send_header('Content-Length', '0')
        handler.end_headers()
    return False


def _is_loopback(addr: str) -> bool:
    """Return True if *addr* is a loopback address (127.x.x.x, ::1, or ::ffff:127.x.x.x)."""
    import ipaddress as _ipaddress
    try:
        ip = _ipaddress.ip_address(addr)
        if ip.is_loopback:
            return True
        # Python < 3.12: is_loopback is False for ::ffff:127.x.x.x (gh-117566)
        if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped.is_loopback
        return False
    except ValueError:
        return False


def _is_secure_context(handler=None) -> bool:
    """Return True if cookies should carry the Secure flag.

    Priority order:
    1. ``HERMES_WEBUI_SECURE`` env var: 1/true/yes -> True; 0/false/no -> False.
    2. Direct TLS socket (handler.request.getpeercert present) -> True.
    3. ``HERMES_WEBUI_TRUST_FORWARDED_PROTO=1`` opt-in: trust
       ``X-Forwarded-Proto: https`` header from a known reverse proxy.
    4. Otherwise -> False (loopback or non-loopback, plain HTTP is not secure).

    .. warning::
       ``X-Forwarded-Proto`` is only trustworthy behind a reverse proxy.
       It is ignored unless ``HERMES_WEBUI_TRUST_FORWARDED_PROTO=1`` is
       set explicitly, preventing header-injection attacks on plain-HTTP
       deployments.
    """
    env = os.getenv('HERMES_WEBUI_SECURE', '').strip().lower()
    if env in ('1', 'true', 'yes'):
        return True
    if env in ('0', 'false', 'no'):
        return False
    if handler is not None:
        if getattr(handler.request, 'getpeercert', None) is not None:
            return True
        trust_fwd = os.getenv('HERMES_WEBUI_TRUST_FORWARDED_PROTO', '').strip().lower()
        if trust_fwd in ('1', 'true', 'yes'):
            if handler.headers.get('X-Forwarded-Proto', '') == 'https':
                return True
    return False


def set_auth_cookie(handler, cookie_value) -> None:
    """Set the auth cookie on the response."""
    cookie = http.cookies.SimpleCookie()
    cookie[COOKIE_NAME] = cookie_value
    cookie[COOKIE_NAME]['httponly'] = True
    cookie[COOKIE_NAME]['samesite'] = 'Lax'
    cookie[COOKIE_NAME]['path'] = '/'
    cookie[COOKIE_NAME]['max-age'] = str(_resolve_session_ttl())
    if _is_secure_context(handler):
        cookie[COOKIE_NAME]['secure'] = True
    handler.send_header('Set-Cookie', cookie[COOKIE_NAME].OutputString())


def clear_auth_cookie(handler) -> None:
    """Clear the auth cookie on the response."""
    cookie = http.cookies.SimpleCookie()
    cookie[COOKIE_NAME] = ''
    cookie[COOKIE_NAME]['httponly'] = True
    cookie[COOKIE_NAME]['path'] = '/'
    cookie[COOKIE_NAME]['max-age'] = '0'
    handler.send_header('Set-Cookie', cookie[COOKIE_NAME].OutputString())
