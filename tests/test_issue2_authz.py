"""
Issue #2: authorization wiring tests.

Per the design table in §5 of the plan, the following endpoints become
gated when users are configured:

  POST /api/profile/switch  — permissions.switch_profile + allowed_profiles
  POST /api/profile/create  — admin only
  POST /api/profile/delete  — admin only
  POST /api/admin/reload    — admin only
  GET  /api/profiles        — filter to allowed_profiles for non-admin
  GET  /api/projects        — same filter

Legacy fallback: when no users exist (env-var deployment / fresh install),
the endpoints behave as before. These tests focus on the user-configured
state since that's where the new code lives.
"""
import json
from pathlib import Path

import pytest

from api import auth, users as users_mod
from api.routes import handle_get, handle_post


import io
import urllib.parse as _up


class StubHandler:
    """In-process stub for HTTP request handlers.

    Provides enough surface that read_body, parse_cookie, the require_*
    helpers, and the route handlers all run without a real http.server
    instance behind them.
    """
    def __init__(self, *, cookie='', client_ip='1.2.3.4', body=None,
                 path='/', method='POST', origin=None):
        self._body_bytes = json.dumps(body or {}).encode('utf-8') if body is not None else b''
        # Headers must be a real CaseInsensitiveDict-shaped object that
        # read_body can call .get('Content-Length') on.
        hdr = {'Cookie': cookie} if cookie else {}
        hdr['Content-Length'] = str(len(self._body_bytes))
        # CSRF: same-origin (Host=Origin) keeps _check_csrf happy.
        hdr['Host'] = '127.0.0.1:8787'
        if origin is None:
            origin = 'http://127.0.0.1:8787'
        if origin:
            hdr['Origin'] = origin
        self.headers = hdr
        self.rfile = io.BytesIO(self._body_bytes)
        self.client_address = (client_ip, 12345)
        self.status = None
        self.sent_headers = []
        self._out = bytearray()
        self.wfile = self
        self.command = method
        self.path = path

    def send_response(self, s): self.status = s
    def send_header(self, n, v): self.sent_headers.append((n, v))
    def end_headers(self): pass
    def write(self, d): self._out.extend(d)
    request = property(lambda self: type('R', (), {'getpeercert': None})())

    def body_json(self):
        if not self._out:
            return None
        try:
            return json.loads(bytes(self._out).decode('utf-8'))
        except Exception:
            return None


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(users_mod, 'USERS_FILE', tmp_path / '.users.json')
    monkeypatch.setattr(users_mod, 'USERS_BAK', tmp_path / '.users.json.bak')
    monkeypatch.setattr(users_mod, '_users_cache', None)
    monkeypatch.setattr(auth, '_sessions', {})
    monkeypatch.setattr(auth, '_login_attempts', {})
    monkeypatch.setattr(auth, '_login_attempts_user', {})
    monkeypatch.setattr(auth, 'is_auth_enabled', lambda: True)
    yield


def _user(username='alice', role='user', allowed_profiles=None,
          permissions=None, password='supersecret', assigned_profile='default'):
    if allowed_profiles is not None and assigned_profile not in allowed_profiles:
        allowed_profiles = [assigned_profile, *allowed_profiles]
    return users_mod.create_user(
        username=username, password=password, role=role,
        assigned_profile=assigned_profile,
        allowed_profiles=allowed_profiles,
        permissions=permissions or {},
    )


def _handler_for(user, *, body=None, path='/', method='POST'):
    cookie = auth.create_session(user_id=user['id'])
    return StubHandler(cookie=f'hermes_session={cookie}',
                       body=body, path=path, method=method)


# ── /api/profile/switch authorization ──────────────────────────────────────-

def test_profile_switch_blocked_when_switch_profile_perm_false():
    user = _user(permissions={'switch_profile': False})
    h = _handler_for(user, body={'name': 'default'}, path='/api/profile/switch')
    handle_post(h, _up.urlparse('/api/profile/switch'))
    assert h.status == 403


def test_profile_switch_blocked_outside_allowed_profiles():
    user = _user(assigned_profile='work', allowed_profiles=['work'])
    h = _handler_for(user, body={'name': 'personal'}, path='/api/profile/switch')
    handle_post(h, _up.urlparse('/api/profile/switch'))
    assert h.status == 403


def test_admin_can_switch_to_any_profile():
    """Admins bypass allowed_profiles entirely (is_profile_allowed)."""
    user = _user(role='admin')
    h = _handler_for(user, body={'name': 'nonexistent_profile'}, path='/api/profile/switch')
    # The actual switch may fail because the test profile doesn't exist
    # on disk, but the *authorization* check must pass — no 403.
    handle_post(h, _up.urlparse('/api/profile/switch'))
    assert h.status != 403, "admin must bypass allowed_profiles RBAC"


# ── /api/profile/create + delete admin gating ───────────────────────────────

def test_profile_create_requires_admin():
    user = _user(role='user')
    h = _handler_for(user, body={'name': 'newprofile'}, path='/api/profile/create')
    handle_post(h, _up.urlparse('/api/profile/create'))
    assert h.status == 403


def test_profile_delete_requires_admin():
    user = _user(role='user')
    h = _handler_for(user, body={'name': 'whatever'}, path='/api/profile/delete')
    handle_post(h, _up.urlparse('/api/profile/delete'))
    assert h.status == 403


# ── /api/admin/reload admin gating ─────────────────────────────────────────-

def test_admin_reload_requires_admin():
    user = _user(role='user')
    h = _handler_for(user, body={}, path='/api/admin/reload')
    handle_post(h, _up.urlparse('/api/admin/reload'))
    assert h.status == 403


# ── /api/profiles filters by allowed_profiles ──────────────────────────────-

def test_profiles_get_filtered_by_allowed_for_non_admin(monkeypatch):
    user = _user(allowed_profiles=['work'])
    h = _handler_for(user)
    # Stub list_profiles_api to return three known profiles.
    fake_profiles = [
        {'name': 'default'}, {'name': 'work'}, {'name': 'personal'},
    ]
    import api.profiles as profiles_mod
    monkeypatch.setattr(profiles_mod, 'list_profiles_api', lambda: list(fake_profiles))
    monkeypatch.setattr(profiles_mod, 'get_active_profile_name', lambda: 'default')
    handle_get(h, _up.urlparse('/api/profiles'))
    body = h.body_json()
    names = [p['name'] for p in body['profiles']]
    # 'default' was added because allowed_profiles=['work'] auto-extends to
    # include the assigned_profile ('default').
    assert set(names) == {'default', 'work'}, (
        f"non-admin must only see allowed profiles, got {names}"
    )


def test_profiles_get_unrestricted_for_admin(monkeypatch):
    user = _user(role='admin')
    h = _handler_for(user)
    fake_profiles = [
        {'name': 'default'}, {'name': 'work'}, {'name': 'personal'}, {'name': 'secret'},
    ]
    import api.profiles as profiles_mod
    monkeypatch.setattr(profiles_mod, 'list_profiles_api', lambda: list(fake_profiles))
    monkeypatch.setattr(profiles_mod, 'get_active_profile_name', lambda: 'default')
    handle_get(h, _up.urlparse('/api/profiles'))
    body = h.body_json()
    names = {p['name'] for p in body['profiles']}
    assert names == {'default', 'work', 'personal', 'secret'}


def test_profiles_get_user_with_null_allowed_sees_all(monkeypatch):
    """allowed_profiles=None means 'all' — no filter applied."""
    user = _user()  # allowed_profiles defaults to None
    h = _handler_for(user)
    fake_profiles = [{'name': 'a'}, {'name': 'b'}, {'name': 'c'}]
    import api.profiles as profiles_mod
    monkeypatch.setattr(profiles_mod, 'list_profiles_api', lambda: list(fake_profiles))
    monkeypatch.setattr(profiles_mod, 'get_active_profile_name', lambda: 'a')
    handle_get(h, _up.urlparse('/api/profiles'))
    body = h.body_json()
    names = {p['name'] for p in body['profiles']}
    assert names == {'a', 'b', 'c'}
