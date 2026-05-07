"""
Issue #2 regression: is_auth_enabled() must return True when only
multi-user records exist (no legacy single-shared-password configured).

Background
----------
The original is_auth_enabled() only checked the legacy code path:
  - HERMES_WEBUI_PASSWORD env var, or
  - settings.json:password_hash

After the multi-user migration (issue #2), neither is set on:
  (a) Fresh installs that bootstrap their first admin via /api/auth/bootstrap.
  (b) Upgrades from legacy single-password — the migration copies the hash
      into a new admin user record AND strips password_hash from settings,
      leaving an empty get_password_hash() but a populated .users.json.

In both cases is_auth_enabled() returned False, which made:
  - check_auth() short-circuit to "auth disabled" → all routes pass.
  - current_user() short-circuit to None unconditionally.
  - require_user() always send 401.

Net effect for the user: log in, page loads, frontend hits /api/me, gets
401, _redirectIfUnauth() bounces to /login — infinite loop.

These tests exercise the real is_auth_enabled() (not the autouse stub
used in test_issue2_login_flow.py:76) against both deployment shapes.
"""
import json
from pathlib import Path

import pytest

from api import auth, routes, users as users_mod
from api.routes import _handle_me_get
from api.startup import run_first_boot_migration


class StubHandler:
    """Minimal BaseHTTPRequestHandler stub. Mirrors test_issue2_login_flow."""
    def __init__(self, *, cookie='', client_ip='1.2.3.4'):
        self.headers = {'Cookie': cookie} if cookie else {}
        self.client_address = (client_ip, 12345)
        self.status = None
        self.sent_headers = []
        self._body = bytearray()
        self.wfile = self

    def send_response(self, status): self.status = status
    def send_header(self, name, value): self.sent_headers.append((name, value))
    def end_headers(self): pass
    def write(self, data): self._body.extend(data)
    request = property(lambda self: type('R', (), {'getpeercert': None})())

    def body_json(self):
        if not self._body:
            return None
        try:
            return json.loads(bytes(self._body).decode('utf-8'))
        except Exception:
            return None


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch):
    """Redirect users storage, reset session table, force no env-var password.

    Critically, we do NOT stub is_auth_enabled — that's what we're testing.
    """
    monkeypatch.setattr(users_mod, 'USERS_FILE', tmp_path / '.users.json')
    monkeypatch.setattr(users_mod, 'USERS_BAK', tmp_path / '.users.json.bak')
    monkeypatch.setattr(users_mod, '_users_cache', None)
    monkeypatch.setattr(auth, '_sessions', {})
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)

    # api.auth.get_password_hash() reads settings.json via api.config; force
    # it to return None so we're testing the multi-user-only state.
    monkeypatch.setattr(auth, 'get_password_hash', lambda: None)
    yield


# ── is_auth_enabled() ───────────────────────────────────────────────────────

def test_auth_enabled_false_when_no_password_and_no_users():
    """Sanity: with neither legacy password nor users, auth is disabled."""
    assert users_mod.has_users() is False
    assert auth.is_auth_enabled() is False


def test_auth_enabled_true_after_first_admin_created():
    """Bootstrap path: creating the first admin flips is_auth_enabled True
    even though no legacy password was ever configured."""
    users_mod.create_user(
        username='admin', password='supersecret', role='admin',
        assigned_profile='default',
    )
    assert auth.is_auth_enabled() is True


def test_auth_enabled_true_after_legacy_to_multiuser_migration(monkeypatch):
    """Upgrade path: simulate a legacy install with password_hash in
    settings.json, run the migration, then assert is_auth_enabled() stays
    True after the migration strips password_hash from settings."""
    # Pretend settings.json had a legacy password hash. The migration reads
    # via api.config.load_settings and writes via save_settings.
    legacy_hash = auth._hash_password('legacy-pw')
    settings_state = {'data': {'password_hash': legacy_hash}}
    monkeypatch.setattr('api.config.load_settings',
                        lambda: dict(settings_state['data']))
    monkeypatch.setattr('api.config.save_settings',
                        lambda s: settings_state.update(data=dict(s)) or s)

    # Migration uses api.auth.get_password_hash to gate behavior, but our
    # autouse fixture stubs it to None. For this one test, restore the
    # real function so the migration sees the legacy hash in settings.
    monkeypatch.setattr(auth, 'get_password_hash',
                        lambda: settings_state['data'].get('password_hash') or None)

    status = run_first_boot_migration()
    assert status['action'] == 'upgraded'
    assert users_mod.has_users() is True
    # The migration strips password_hash from settings — now restore the
    # post-migration get_password_hash() shape (returns None) and confirm
    # auth still reads as enabled because users exist.
    monkeypatch.setattr(auth, 'get_password_hash', lambda: None)
    assert auth.get_password_hash() is None
    assert auth.is_auth_enabled() is True


# ── End-to-end: /api/me works after bootstrap ───────────────────────────────

def test_api_me_returns_200_after_bootstrap_login():
    """Regression for the auth-loop bug: with only multi-user records (no
    legacy password), a valid signed session cookie must resolve to the
    user via current_user(), and /api/me must return 200 — not 401."""
    user = users_mod.create_user(
        username='admin', password='supersecret', role='admin',
        assigned_profile='default',
    )
    cookie_val = auth.create_session(user_id=user['id'])
    h = StubHandler(cookie=f'hermes_session={cookie_val}')
    _handle_me_get(h)
    assert h.status == 200, (
        f"/api/me returned {h.status} after bootstrap login — "
        "is_auth_enabled() likely returned False, breaking current_user()."
    )
    body = h.body_json()
    assert body['username'] == 'admin'
    assert 'password_hash' not in body


def test_current_user_resolves_after_bootstrap():
    """Direct test of the current_user() short-circuit that caused the loop."""
    user = users_mod.create_user(
        username='admin', password='supersecret', role='admin',
        assigned_profile='default',
    )
    cookie_val = auth.create_session(user_id=user['id'])
    h = StubHandler(cookie=f'hermes_session={cookie_val}')
    resolved = auth.current_user(h)
    assert resolved is not None, (
        "current_user() returned None despite a valid signed cookie — "
        "is_auth_enabled() short-circuit is masking the user lookup."
    )
    assert resolved['username'] == 'admin'
