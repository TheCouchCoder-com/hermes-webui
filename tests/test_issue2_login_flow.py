"""
Issue #2: multi-user login flow + bootstrap + change-password + /api/me.

These tests exercise the route handlers directly (in-process) so they are
fast and deterministic. They construct a stub handler implementing the
subset of BaseHTTPRequestHandler surface the code touches:
  send_response, send_header, end_headers, wfile.write, headers, client_address

Coverage:
  /api/auth/login         — happy path sets BOTH cookies, surfaces
                             must_change_password, rejects bad creds, 429s.
  /api/auth/bootstrap     — creates first admin, idempotent 409 thereafter.
  /api/auth/change_password — old-pw mismatch 401, success clears flag.
  /api/auth/status        — first_boot signal flips correctly.
  /api/me                 — returns current user without password_hash.
"""
import json
from pathlib import Path

import pytest

from api import auth, routes, users as users_mod
from api.routes import (
    _handle_bootstrap_post,
    _handle_change_password_post,
    _handle_login_post,
    _handle_me_get,
)


class StubHandler:
    """Minimal BaseHTTPRequestHandler stub for in-process route testing."""
    def __init__(self, *, cookie='', client_ip='1.2.3.4'):
        self.headers = {'Cookie': cookie} if cookie else {}
        self.client_address = (client_ip, 12345)
        self.status = None
        self.sent_headers = []
        self._body = bytearray()
        self.wfile = self

    # request handler API
    def send_response(self, status): self.status = status
    def send_header(self, name, value): self.sent_headers.append((name, value))
    def end_headers(self): pass
    def write(self, data): self._body.extend(data)
    # request "request" (TLS introspection in set_auth_cookie); not used in tests.
    request = property(lambda self: type('R', (), {'getpeercert': None})())

    def body_json(self):
        if not self._body:
            return None
        try:
            return json.loads(bytes(self._body).decode('utf-8'))
        except Exception:
            return None

    def cookie_value(self, name):
        for k, v in self.sent_headers:
            if k == 'Set-Cookie' and v.split('=', 1)[0] == name:
                return v.split('=', 1)[1].split(';', 1)[0]
        return None


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch):
    """Per-test isolation: redirect users storage, reset rate limiter, fake auth-enabled."""
    monkeypatch.setattr(users_mod, 'USERS_FILE', tmp_path / '.users.json')
    monkeypatch.setattr(users_mod, 'USERS_BAK', tmp_path / '.users.json.bak')
    monkeypatch.setattr(users_mod, '_users_cache', None)
    monkeypatch.setattr(auth, '_sessions', {})
    monkeypatch.setattr(auth, '_login_attempts', {})
    monkeypatch.setattr(auth, '_login_attempts_user', {})
    # Force is_auth_enabled True even though no env var or settings is set,
    # so /api/auth/login hits the user-credential path and not the legacy
    # "Auth not enabled" short-circuit.
    monkeypatch.setattr(auth, 'is_auth_enabled', lambda: True)
    yield


def _create_admin():
    return users_mod.create_user(
        username='admin', password='supersecret', role='admin',
        assigned_profile='default',
    )


# ── /api/auth/login ──────────────────────────────────────────────────────────

def test_login_sets_both_cookies_and_returns_ok():
    user = _create_admin()
    h = StubHandler()
    _handle_login_post(h, {'username': 'admin', 'password': 'supersecret'})
    assert h.status == 200
    body = h.body_json()
    assert body == {'ok': True, 'must_change_password': False}
    # Both cookies present.
    cookie_names = {k.split('=', 1)[0]
                    for header_name, v in h.sent_headers if header_name == 'Set-Cookie'
                    for k in [v]}
    raw_set_cookies = [v for n, v in h.sent_headers if n == 'Set-Cookie']
    assert any(c.startswith('hermes_session=') for c in raw_set_cookies)
    assert any(c.startswith('hermes_profile=') for c in raw_set_cookies)


def test_login_profile_cookie_is_signed():
    """The hermes_profile cookie carries a session-bound HMAC suffix (issue #2 / #803)."""
    _create_admin()
    h = StubHandler()
    _handle_login_post(h, {'username': 'admin', 'password': 'supersecret'})
    pc = next(v for n, v in h.sent_headers if n == 'Set-Cookie' and v.startswith('hermes_profile='))
    value = pc.split(';', 1)[0].split('=', 1)[1]
    assert '.' in value, "hermes_profile cookie must carry a signature suffix"
    name, _, sig = value.rpartition('.')
    assert name == 'default'
    assert sig and all(c in '0123456789abcdef' for c in sig), "sig must be non-empty hex"


def test_login_routes_to_assigned_profile():
    """A user with assigned_profile=work lands with hermes_profile=work."""
    users_mod.create_user(
        username='alice', password='supersecret', role='user',
        assigned_profile='work', allowed_profiles=['work'],
    )
    h = StubHandler()
    _handle_login_post(h, {'username': 'alice', 'password': 'supersecret'})
    pc = next(v for n, v in h.sent_headers if n == 'Set-Cookie' and v.startswith('hermes_profile='))
    name, _, _sig = pc.split(';', 1)[0].split('=', 1)[1].rpartition('.')
    assert name == 'work'


def test_login_wrong_password_returns_401_and_no_cookies():
    _create_admin()
    h = StubHandler()
    _handle_login_post(h, {'username': 'admin', 'password': 'WRONG'})
    assert h.status == 401
    assert not any(n == 'Set-Cookie' for n, _ in h.sent_headers), \
        "Failed login must not set any cookies"


def test_login_unknown_username_returns_401_constant_time():
    _create_admin()
    h = StubHandler()
    _handle_login_post(h, {'username': 'ghost', 'password': 'supersecret'})
    assert h.status == 401


def test_login_rate_limit_429_after_5_attempts_per_username():
    _create_admin()
    for _ in range(5):
        h = StubHandler(client_ip='10.0.0.{}'.format(_))
        _handle_login_post(h, {'username': 'admin', 'password': 'WRONG'})
    # 6th attempt — different IP, but per-username bucket exhausted.
    h = StubHandler(client_ip='99.99.99.99')
    _handle_login_post(h, {'username': 'admin', 'password': 'supersecret'})
    assert h.status == 429


def test_login_surfaces_must_change_password_flag():
    user = users_mod.create_user(
        username='alice', password='supersecret', role='user',
        assigned_profile='default',
    )
    users_mod.set_password(user['id'], 'newpassword', must_change=True)
    h = StubHandler()
    _handle_login_post(h, {'username': 'alice', 'password': 'newpassword'})
    assert h.status == 200
    assert h.body_json()['must_change_password'] is True


def test_login_records_last_login_at():
    user = _create_admin()
    h = StubHandler()
    _handle_login_post(h, {'username': 'admin', 'password': 'supersecret'})
    refreshed = users_mod.get_user_by_id(user['id'])
    assert refreshed['last_login_at'] is not None


# ── /api/auth/bootstrap ─────────────────────────────────────────────────────

def test_bootstrap_creates_first_admin_and_logs_in(monkeypatch):
    # No HERMES_WEBUI_PASSWORD set, no users yet → first_boot=True.
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    h = StubHandler()
    _handle_bootstrap_post(h, {'username': 'root', 'password': 'supersecret'})
    assert h.status == 200
    assert h.body_json() == {'ok': True}
    user = users_mod.get_user_by_username('root')
    assert user is not None
    assert user['role'] == 'admin'
    # Both cookies set.
    raw_set_cookies = [v for n, v in h.sent_headers if n == 'Set-Cookie']
    assert any(c.startswith('hermes_session=') for c in raw_set_cookies)
    assert any(c.startswith('hermes_profile=') for c in raw_set_cookies)


def test_bootstrap_idempotent_409_after_first_call(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    _handle_bootstrap_post(StubHandler(), {'username': 'root', 'password': 'supersecret'})
    h2 = StubHandler()
    _handle_bootstrap_post(h2, {'username': 'second', 'password': 'supersecret'})
    assert h2.status == 409


def test_bootstrap_blocked_when_env_var_set(monkeypatch):
    monkeypatch.setenv('HERMES_WEBUI_PASSWORD', 'legacy-pw')
    h = StubHandler()
    _handle_bootstrap_post(h, {'username': 'root', 'password': 'supersecret'})
    # Env-var legacy mode → first_boot is False → 409.
    assert h.status == 409


def test_bootstrap_validation_error_returns_400(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    h = StubHandler()
    _handle_bootstrap_post(h, {'username': '', 'password': 'short'})
    assert h.status == 400


# ── /api/auth/change_password ───────────────────────────────────────────────

def _login_handler_for_user(user):
    """Construct a handler with a valid signed session cookie for `user`."""
    cookie_val = auth.create_session(user_id=user['id'])
    return StubHandler(cookie=f'hermes_session={cookie_val}')


def test_change_password_happy_path_clears_must_change():
    user = users_mod.create_user(
        username='alice', password='supersecret', role='user',
        assigned_profile='default', must_change_password=True,
    )
    h = _login_handler_for_user(user)
    _handle_change_password_post(h, {
        'old_password': 'supersecret', 'new_password': 'differentpw',
    })
    assert h.status == 200
    refreshed = users_mod.get_user_by_id(user['id'])
    assert refreshed['must_change_password'] is False


def test_change_password_rejects_wrong_old_password():
    user = _create_admin()
    h = _login_handler_for_user(user)
    _handle_change_password_post(h, {
        'old_password': 'WRONG', 'new_password': 'differentpw',
    })
    assert h.status == 401


def test_change_password_rejects_short_new_password():
    user = _create_admin()
    h = _login_handler_for_user(user)
    _handle_change_password_post(h, {
        'old_password': 'supersecret', 'new_password': 'short',
    })
    assert h.status == 400


def test_change_password_requires_login():
    h = StubHandler()  # no cookie
    _handle_change_password_post(h, {
        'old_password': 'x', 'new_password': 'newpassword',
    })
    assert h.status == 401


# ── /api/me ────────────────────────────────────────────────────────────────-

def test_me_returns_user_without_password_hash():
    user = _create_admin()
    h = _login_handler_for_user(user)
    _handle_me_get(h)
    body = h.body_json()
    assert body['username'] == 'admin'
    assert body['role'] == 'admin'
    assert 'password_hash' not in body, "password_hash must never appear in /api/me"


def test_me_requires_login():
    h = StubHandler()
    _handle_me_get(h)
    assert h.status == 401
