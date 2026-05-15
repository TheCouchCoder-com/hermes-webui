"""
Issue #2: permission gating on cron / skills / settings mutation endpoints.

The user record carries four user-facing permission keys:
  - switch_profile  → already gated on /api/profile/switch
  - manage_cron     → /api/crons/{create,update,delete,run,pause,resume}
  - manage_skills   → /api/skills/{save,delete}
  - edit_settings   → /api/settings (POST), allowing personal display keys
                       through (theme, skin, show_thinking, show_token_usage)

Admins always pass via require_perm. Auth-disabled deployments (no users
configured, no env-var password) keep working unchanged via the synthetic
"anonymous admin" record returned by require_user — that path is covered
by the broader sprint suite.
"""
import io
import json
from pathlib import Path
import urllib.parse as _up

import pytest

from api import auth, users as users_mod
from api.routes import handle_post


class StubHandler:
    """Mirrors the helper in test_issue2_authz.py so this file stands alone."""
    def __init__(self, *, cookie='', client_ip='1.2.3.4', body=None,
                 path='/', method='POST', origin=None):
        self._body_bytes = json.dumps(body or {}).encode('utf-8') if body is not None else b''
        hdr = {'Cookie': cookie} if cookie else {}
        hdr['Content-Length'] = str(len(self._body_bytes))
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
    monkeypatch.setattr(auth, 'is_auth_enabled', lambda: True)

    # Settings writes that flow through handle_post (e.g. the admin bot_name
    # test below) land in the shared test SETTINGS_FILE and leak into later
    # tests like test_sprint27::test_settings_default_bot_name. Snapshot the
    # file at setup and restore it on teardown so these write-heavy gating
    # tests don't poison the rest of the suite.
    from api import config as _cfg
    settings_path = getattr(_cfg, 'SETTINGS_FILE', None)
    snapshot = None
    if settings_path is not None and settings_path.exists():
        snapshot = settings_path.read_bytes()

    yield

    if settings_path is not None:
        if snapshot is None:
            try:
                settings_path.unlink()
            except FileNotFoundError:
                pass
        else:
            settings_path.write_bytes(snapshot)


def _user(username='alice', role='user', permissions=None,
          assigned_profile='default'):
    return users_mod.create_user(
        username=username, password='supersecret', role=role,
        assigned_profile=assigned_profile,
        permissions=permissions or {},
    )


def _handler_for(user, *, body=None, path='/', method='POST'):
    cookie = auth.create_session(user_id=user['id'])
    return StubHandler(cookie=f'hermes_session={cookie}',
                       body=body, path=path, method=method)


# ── manage_cron ─────────────────────────────────────────────────────────────-

CRON_MUTATION_PATHS = (
    '/api/crons/create',
    '/api/crons/update',
    '/api/crons/delete',
    '/api/crons/run',
    '/api/crons/pause',
    '/api/crons/resume',
)


@pytest.mark.parametrize('path', CRON_MUTATION_PATHS)
def test_cron_mutation_blocked_without_manage_cron_perm(path):
    user = _user(permissions={'manage_cron': False})
    h = _handler_for(user, body={}, path=path)
    handle_post(h, _up.urlparse(path))
    assert h.status == 403, f"{path} should 403 without manage_cron, got {h.status}"


@pytest.mark.parametrize('path', CRON_MUTATION_PATHS)
def test_cron_mutation_allowed_for_user_with_manage_cron(path):
    user = _user(permissions={'manage_cron': True})
    h = _handler_for(user, body={}, path=path)
    handle_post(h, _up.urlparse(path))
    # The handler may 400/404 due to missing job_id/etc. but must not 403/401.
    assert h.status not in (401, 403), \
        f"{path} should pass auth for user with manage_cron, got {h.status}"


@pytest.mark.parametrize('path', CRON_MUTATION_PATHS)
def test_cron_mutation_allowed_for_admin(path):
    user = _user(role='admin')
    h = _handler_for(user, body={}, path=path)
    handle_post(h, _up.urlparse(path))
    assert h.status not in (401, 403), \
        f"{path} should pass auth for admin, got {h.status}"


# ── manage_skills ───────────────────────────────────────────────────────────-

SKILLS_MUTATION_PATHS = ('/api/skills/save', '/api/skills/delete')


@pytest.mark.parametrize('path', SKILLS_MUTATION_PATHS)
def test_skill_mutation_blocked_without_manage_skills_perm(path):
    user = _user(permissions={'manage_skills': False})
    h = _handler_for(user, body={}, path=path)
    handle_post(h, _up.urlparse(path))
    assert h.status == 403


@pytest.mark.parametrize('path', SKILLS_MUTATION_PATHS)
def test_skill_mutation_allowed_for_admin(path):
    user = _user(role='admin')
    h = _handler_for(user, body={}, path=path)
    handle_post(h, _up.urlparse(path))
    assert h.status not in (401, 403)


# ── edit_settings ──────────────────────────────────────────────────────────-

def test_settings_post_blocked_without_edit_settings_perm():
    """Non-personal settings keys (like bot_name) require edit_settings."""
    user = _user(permissions={'edit_settings': False})
    h = _handler_for(user, body={'bot_name': 'NewName'}, path='/api/settings')
    handle_post(h, _up.urlparse('/api/settings'))
    assert h.status == 403


def test_settings_post_personal_keys_allowed_for_user():
    """Theme + skin are personal display preferences and must remain
    user-mutable even without edit_settings."""
    user = _user(permissions={'edit_settings': False})
    for key in ('theme', 'skin', 'show_thinking', 'show_token_usage'):
        h = _handler_for(user, body={key: 'whatever'}, path='/api/settings')
        handle_post(h, _up.urlparse('/api/settings'))
        assert h.status != 403, \
            f"personal key {key} must not require edit_settings, got 403"


def test_settings_post_mixed_keys_blocked_without_edit_settings():
    """A request that bundles a personal key with an admin-shaped key must
    still be blocked — otherwise an attacker could smuggle a bot_name change
    behind a theme toggle."""
    user = _user(permissions={'edit_settings': False})
    h = _handler_for(user, body={'theme': 'dark', 'bot_name': 'Eve'},
                     path='/api/settings')
    handle_post(h, _up.urlparse('/api/settings'))
    assert h.status == 403


def test_settings_post_admin_allowed_for_anything():
    user = _user(role='admin')
    h = _handler_for(user, body={'bot_name': 'AdminPick'}, path='/api/settings')
    handle_post(h, _up.urlparse('/api/settings'))
    assert h.status not in (401, 403)


# ── Auth-disabled fallback ─────────────────────────────────────────────────-

def test_perm_gates_open_when_auth_disabled(monkeypatch):
    """Sanity: when no users are configured and no env-var password is set,
    require_perm returns the synthetic anonymous-admin record so the gates
    pass through. This preserves the legacy 'auth off = wide open' contract
    that the existing sprint suite depends on."""
    monkeypatch.setattr(auth, 'is_auth_enabled', lambda: False)
    h = StubHandler(body={}, path='/api/crons/create')
    handle_post(h, _up.urlparse('/api/crons/create'))
    assert h.status not in (401, 403), \
        f"auth-disabled mode must not 401/403 mutation endpoints, got {h.status}"
