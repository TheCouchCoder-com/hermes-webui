"""
Hermes Web UI -- Optional password authentication.
Off by default. Enable by setting HERMES_WEBUI_PASSWORD env var
or configuring a password in the Settings panel.
"""
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import secrets
import tempfile
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
    '/manifest.json', '/manifest.webmanifest',
})

COOKIE_NAME = 'hermes_session'

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


_login_attempts = _load_login_attempts_from(_LOGIN_ATTEMPTS_FILE)              # ip -> [timestamp, ...]
_login_attempts_user = _load_login_attempts_from(_LOGIN_ATTEMPTS_USER_FILE)    # username (lower) -> [timestamp, ...]


def _check_login_rate(ip: str, username: str | None = None) -> bool:
    """Return True if the request is allowed to attempt login.
    Either bucket exhausted (IP or username) blocks the attempt."""
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
    now = time.time()
    _login_attempts.setdefault(ip, []).append(now)
    _save_login_attempts_to(_LOGIN_ATTEMPTS_FILE, _login_attempts)
    if username:
        _login_attempts_user.setdefault(username.lower(), []).append(now)
        _save_login_attempts_to(_LOGIN_ATTEMPTS_USER_FILE, _login_attempts_user)


def _signing_key():
    """Return a random signing key, generating and persisting one on first call."""
    key_file = STATE_DIR / '.signing_key'
    try:
        if key_file.exists():
            raw = key_file.read_bytes()
            if len(raw) >= 32:
                return raw[:32]
    except Exception:
        logger.debug("Failed to read or access signing key file, using in-memory key")
    # Generate a new random key
    key = secrets.token_bytes(32)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        key_file.chmod(0o600)
    except Exception:
        logger.debug("Failed to persist signing key, using in-memory key only")
    return key


def _hash_password(password):
    """PBKDF2-SHA256 with 600k iterations (OWASP recommendation).
    Salt is the persisted random signing key, which is secret and unique per
    installation. This keeps the stored hash format a plain hex string
    (no format change to settings.json) while replacing the predictable
    STATE_DIR-derived salt from the original implementation.

    The iteration count is fixed at the OWASP recommendation in production.
    The test suite overrides it via HERMES_WEBUI_PBKDF2_ITERATIONS to a much
    smaller value so the ~150 password-hashing tests don't bottleneck CI;
    the env var is **never** honoured outside conftest-managed test runs."""
    salt = _signing_key()
    iters_override = os.getenv('HERMES_WEBUI_PBKDF2_ITERATIONS', '').strip()
    iters = 600_000
    if iters_override.isdigit() and os.getenv('HERMES_WEBUI_TEST_NETWORK_BLOCK') == '1':
        # The TEST_NETWORK_BLOCK env var is set exclusively by tests/conftest.py
        # for the test server subprocess, so honouring the iteration override
        # only when it is present prevents accidental production exposure even
        # if HERMES_WEBUI_PBKDF2_ITERATIONS leaks into a real deployment env.
        iters = max(1000, int(iters_override))
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iters)
    return dk.hex()


def get_password_hash() -> str | None:
    """Return the active password hash, or None if auth is disabled.
    Priority: env var > settings.json."""
    env_pw = os.getenv('HERMES_WEBUI_PASSWORD', '').strip()
    if env_pw:
        return _hash_password(env_pw)
    settings = load_settings()
    return settings.get('password_hash') or None


def is_auth_enabled() -> bool:
    """True if auth is required: either a legacy single-password is configured,
    or one or more multi-user records exist in .users.json (issue #2)."""
    if get_password_hash() is not None:
        return True
    try:
        from api.users import has_users
        return has_users()
    except Exception:
        return False


def verify_password(plain) -> bool:
    """Verify a plaintext password against the legacy single-shared-password
    hash. Used only by the migration path in api.startup; new logins go
    through verify_user_credentials. Removed in commit 9 of issue #2."""
    expected = get_password_hash()
    if not expected:
        return False
    return hmac.compare_digest(_hash_password(plain), expected)


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
    _sessions[token] = {'user_id': user_id, 'expiry': time.time() + _resolve_session_ttl()}
    _save_sessions(_sessions)
    sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{token}.{sig}"


def _prune_expired_sessions():
    """Remove all expired session entries to prevent unbounded memory growth."""
    now = time.time()
    expired = [t for t, entry in _sessions.items() if now > _session_expiry(entry)]
    if expired:
        for token in expired:
            _sessions.pop(token, None)
        _save_sessions(_sessions)


def verify_session(cookie_value) -> bool:
    """Verify a signed session cookie. Returns True if valid and not expired."""
    return _session_record_for_cookie(cookie_value) is not None


def _session_record_for_cookie(cookie_value):
    """Return (token, entry) for a valid signed cookie, or None.
    Centralised so verify_session and current_session share validation."""
    if not cookie_value or '.' not in cookie_value:
        return None
    _prune_expired_sessions()
    token, sig = cookie_value.rsplit('.', 1)
    expected_sig = hmac.new(_signing_key(), token.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected_sig):
        return None
    entry = _sessions.get(token)
    if entry is None:
        return None
    if time.time() > _session_expiry(entry):
        _sessions.pop(token, None)
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


def invalidate_session(cookie_value) -> None:
    """Remove a session token."""
    if cookie_value and '.' in cookie_value:
        token = cookie_value.rsplit('.', 1)[0]
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
        handler.send_response(401)
        handler.send_header('Content-Type', 'application/json')
        handler.end_headers()
        handler.wfile.write(b'{"error":"Authentication required"}')
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
        handler.end_headers()
    return False


def set_auth_cookie(handler, cookie_value) -> None:
    """Set the auth cookie on the response."""
    cookie = http.cookies.SimpleCookie()
    cookie[COOKIE_NAME] = cookie_value
    cookie[COOKIE_NAME]['httponly'] = True
    cookie[COOKIE_NAME]['samesite'] = 'Lax'
    cookie[COOKIE_NAME]['path'] = '/'
    cookie[COOKIE_NAME]['max-age'] = str(_resolve_session_ttl())
    # Set Secure flag when connection is HTTPS
    if getattr(handler.request, 'getpeercert', None) is not None or handler.headers.get('X-Forwarded-Proto', '') == 'https':
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
