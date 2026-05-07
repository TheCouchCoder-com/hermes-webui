"""
Issue #2: session schema bump + current_user / require_* helpers + per-username
rate limiting.

Schema bump
  Before: _sessions[token] = expiry_float
  After:  _sessions[token] = {'user_id': str|None, 'expiry': float}

  Both shapes remain readable so existing tests that poke a float into
  _sessions[token] still work.

Helpers added
  current_session(cookie)        — normalised dict {token, user_id, expiry}
  current_user(handler)          — user record or None
  require_user / require_admin / require_perm   — short-circuit handlers
  invalidate_sessions_for_user(user_id) — bulk revoke for delete + reset
  drop_unbound_legacy_sessions()  — one-time startup cleanup

Per-username rate limit
  Cycling source IPs no longer dodges per-account brute force.
"""
import time
from unittest.mock import MagicMock

import pytest

from api import auth, users as users_mod


@pytest.fixture(autouse=True)
def _isolate_auth_state(tmp_path, monkeypatch):
    """Reset session + rate-limit state per test, redirect users storage."""
    monkeypatch.setattr(auth, '_sessions', {})
    monkeypatch.setattr(auth, '_login_attempts', {})
    monkeypatch.setattr(auth, '_login_attempts_user', {})
    monkeypatch.setattr(users_mod, 'USERS_FILE', tmp_path / '.users.json')
    monkeypatch.setattr(users_mod, 'USERS_BAK', tmp_path / '.users.json.bak')
    monkeypatch.setattr(users_mod, '_users_cache', None)
    yield


def _create_user(username='alice', role='user', allowed_profiles=None,
                 permissions=None, password='supersecret'):
    return users_mod.create_user(
        username=username, password=password, role=role,
        assigned_profile='default',
        allowed_profiles=allowed_profiles, permissions=permissions or {},
    )


def _handler_with_session_cookie(cookie_value):
    h = MagicMock()
    h.headers = {'Cookie': f'hermes_session={cookie_value}'}
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.wfile = MagicMock()
    return h


# ── Schema bump backward compatibility ─────────────────────────────────────-

def test_create_session_with_user_id_persists_dict_shape():
    cookie = auth.create_session(user_id='u1')
    token = cookie.split('.')[0]
    entry = auth._sessions[token]
    assert isinstance(entry, dict)
    assert entry['user_id'] == 'u1'
    assert entry['expiry'] > time.time()


def test_legacy_float_entry_still_readable():
    """Tests that pre-existing code paths assigning floats keep working."""
    auth._sessions['legacytoken'] = time.time() + 3600
    assert auth._session_expiry(auth._sessions['legacytoken']) > time.time()
    assert auth._session_user_id(auth._sessions['legacytoken']) is None


def test_load_sessions_accepts_mixed_shapes(tmp_path, monkeypatch):
    """A persisted file with both dict and float entries must load cleanly."""
    import json
    sf = tmp_path / '.sessions.json'
    payload = {
        'newshape': {'user_id': 'u1', 'expiry': time.time() + 3600},
        'legacy_float': time.time() + 3600,
        'expired': time.time() - 1,
    }
    sf.write_text(json.dumps(payload), encoding='utf-8')
    monkeypatch.setattr(auth, '_SESSIONS_FILE', sf)
    loaded = auth._load_sessions()
    assert 'newshape' in loaded
    assert 'legacy_float' in loaded
    assert 'expired' not in loaded


# ── verify_session: signature + expiry + cross-shape ────────────────────────

def test_verify_session_round_trips_with_user_id():
    cookie = auth.create_session(user_id='u1')
    assert auth.verify_session(cookie) is True


def test_verify_session_rejects_tampered_signature():
    cookie = auth.create_session(user_id='u1')
    token, sig = cookie.rsplit('.', 1)
    bad = token + '.' + ('0' * 32)
    assert auth.verify_session(bad) is False


def test_verify_session_rejects_expired_dict_entry():
    cookie = auth.create_session(user_id='u1')
    token = cookie.split('.')[0]
    auth._sessions[token]['expiry'] = time.time() - 1
    assert auth.verify_session(cookie) is False


# ── current_session / current_user / require_* ─────────────────────────────-

def test_current_session_returns_normalised_dict():
    cookie = auth.create_session(user_id='u1')
    s = auth.current_session(cookie)
    assert s['token'] == cookie.split('.')[0]
    assert s['user_id'] == 'u1'


def test_current_user_resolves_user_record():
    user = _create_user('alice')
    cookie = auth.create_session(user_id=user['id'])
    h = _handler_with_session_cookie(cookie)
    # is_auth_enabled needs a stored hash; fake it via the user record.
    # current_user calls is_auth_enabled which checks env var or settings.json.
    # Test environment has neither, so simulate auth enabled.
    import api.auth as a
    a._test_force_auth_enabled = True  # just for test introspection — not used
    # Instead, monkeypatch is_auth_enabled to True for this test.
    orig = a.is_auth_enabled
    a.is_auth_enabled = lambda: True
    try:
        u = auth.current_user(h)
    finally:
        a.is_auth_enabled = orig
    assert u is not None
    assert u['username'] == 'alice'


def test_current_user_returns_none_when_session_has_no_user_id():
    """A legacy float-shape session has no user binding → current_user None."""
    auth._sessions['legacy'] = time.time() + 3600
    # Construct a valid signed cookie for token 'legacy'.
    import hmac, hashlib
    sig = hmac.new(auth._signing_key(), b'legacy', hashlib.sha256).hexdigest()[:32]
    h = _handler_with_session_cookie(f'legacy.{sig}')
    import api.auth as a
    orig = a.is_auth_enabled
    a.is_auth_enabled = lambda: True
    try:
        assert auth.current_user(h) is None
    finally:
        a.is_auth_enabled = orig


def test_require_admin_rejects_non_admin():
    user = _create_user('alice', role='user')
    cookie = auth.create_session(user_id=user['id'])
    h = _handler_with_session_cookie(cookie)
    import api.auth as a
    orig = a.is_auth_enabled
    a.is_auth_enabled = lambda: True
    try:
        result = auth.require_admin(h)
    finally:
        a.is_auth_enabled = orig
    assert result is None
    h.send_response.assert_called_with(403)


def test_require_admin_accepts_admin():
    user = _create_user('admin', role='admin')
    cookie = auth.create_session(user_id=user['id'])
    h = _handler_with_session_cookie(cookie)
    import api.auth as a
    orig = a.is_auth_enabled
    a.is_auth_enabled = lambda: True
    try:
        result = auth.require_admin(h)
    finally:
        a.is_auth_enabled = orig
    assert result is not None
    assert result['username'] == 'admin'


def test_require_perm_checks_permission_key():
    user = _create_user(
        'alice', role='user',
        permissions={'manage_cron': False},
    )
    cookie = auth.create_session(user_id=user['id'])
    h = _handler_with_session_cookie(cookie)
    import api.auth as a
    orig = a.is_auth_enabled
    a.is_auth_enabled = lambda: True
    try:
        result = auth.require_perm(h, 'manage_cron')
    finally:
        a.is_auth_enabled = orig
    assert result is None
    h.send_response.assert_called_with(403)


# ── verify_user_credentials ────────────────────────────────────────────────-

def test_verify_user_credentials_success_returns_record():
    _create_user('alice', password='supersecret')
    rec = auth.verify_user_credentials('alice', 'supersecret')
    assert rec is not None
    assert rec['username'] == 'alice'


def test_verify_user_credentials_wrong_password():
    _create_user('alice', password='supersecret')
    assert auth.verify_user_credentials('alice', 'WRONG') is None


def test_verify_user_credentials_unknown_user_constant_time():
    # Unknown username still returns None (exercises the dummy hash path).
    assert auth.verify_user_credentials('ghost', 'whatever') is None


def test_verify_user_credentials_rejects_non_string_inputs():
    assert auth.verify_user_credentials(None, 'pw') is None
    assert auth.verify_user_credentials('alice', None) is None
    assert auth.verify_user_credentials(123, 'pw') is None


# ── Per-username rate limiting ─────────────────────────────────────────────-

def test_per_ip_bucket_blocks_after_max_attempts():
    for _ in range(5):
        auth._record_login_attempt('1.2.3.4')
    assert auth._check_login_rate('1.2.3.4') is False


def test_per_username_bucket_blocks_across_ips():
    """Cycling IPs must not bypass the per-account brute-force lockout."""
    for i in range(5):
        auth._record_login_attempt(f'10.0.0.{i}', username='alice')
    # A fresh IP would have an empty per-IP bucket, but the per-username
    # bucket is exhausted, so the request is still blocked.
    assert auth._check_login_rate('99.99.99.99', username='alice') is False
    # Different username still allowed from a fresh IP.
    assert auth._check_login_rate('99.99.99.99', username='bob') is True


def test_rate_limit_window_expires_attempts():
    auth._login_attempts['1.2.3.4'] = [time.time() - 120 for _ in range(10)]
    assert auth._check_login_rate('1.2.3.4') is True


# ── Bulk revocation ────────────────────────────────────────────────────────-

def test_invalidate_sessions_for_user_removes_all_matching():
    auth.create_session(user_id='u1')
    auth.create_session(user_id='u1')
    auth.create_session(user_id='u2')
    auth.create_session(user_id=None)
    removed = auth.invalidate_sessions_for_user('u1')
    assert removed == 2
    remaining_uids = [auth._session_user_id(e) for e in auth._sessions.values()]
    assert 'u1' not in remaining_uids
    assert 'u2' in remaining_uids
    # Unbound legacy session untouched.
    assert None in remaining_uids


def test_invalidate_sessions_for_user_empty_user_id_is_noop():
    auth.create_session(user_id='u1')
    assert auth.invalidate_sessions_for_user('') == 0
    assert len(auth._sessions) == 1


def test_drop_unbound_legacy_sessions_removes_only_floats():
    auth.create_session(user_id='u1')
    auth._sessions['legacy_float'] = time.time() + 3600
    auth._sessions['legacy_dict_no_uid'] = {'expiry': time.time() + 3600, 'user_id': None}
    removed = auth.drop_unbound_legacy_sessions()
    assert removed == 2
    assert all(auth._session_user_id(e) is not None for e in auth._sessions.values())
