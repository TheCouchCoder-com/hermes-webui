"""
Issue #2: first-boot migration paths.

run_first_boot_migration() in api/startup.py covers four states:

  (1) already_migrated         — .users.json populated → no-op
  (2) upgraded                 — settings.json has password_hash, no env var,
                                  → create admin user with that hash, strip
                                    password_hash from settings.json
  (3) env_var_legacy_preserved — HERMES_WEBUI_PASSWORD set → leave alone
  (4) first_boot               — fresh install → /api/auth/bootstrap path

Plus:
  cleanup_legacy_sessions() drops session records with no user_id.
  is_first_boot() returns True only for state (4).
"""
import json
from pathlib import Path

import pytest

from api import auth, users as users_mod
from api.startup import (
    cleanup_legacy_sessions,
    is_first_boot,
    run_first_boot_migration,
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch):
    """Per-test isolation: redirect every state path the migration touches."""
    monkeypatch.setattr(users_mod, 'USERS_FILE', tmp_path / '.users.json')
    monkeypatch.setattr(users_mod, 'USERS_BAK', tmp_path / '.users.json.bak')
    monkeypatch.setattr(users_mod, '_users_cache', None)
    monkeypatch.setattr(auth, '_sessions', {})

    # api.config.load_settings reads from a path baked into the module; the
    # cleanest knob is to monkeypatch it to return a controllable dict.
    settings_state = {'data': {}}
    def _fake_load_settings():
        return dict(settings_state['data'])
    def _fake_save_settings(s):
        settings_state['data'] = dict(s)
        return s
    monkeypatch.setattr('api.config.load_settings', _fake_load_settings)
    monkeypatch.setattr('api.config.save_settings', _fake_save_settings)

    # Yield the settings dict so tests can pre-populate it.
    yield settings_state


# ── State (4): first boot, fresh install ────────────────────────────────────

def test_first_boot_when_nothing_configured(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    status = run_first_boot_migration()
    assert status['action'] == 'first_boot'
    assert status['first_boot'] is True
    # is_first_boot() concurs.
    assert is_first_boot() is True


def test_first_boot_does_not_create_users(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    run_first_boot_migration()
    assert users_mod.has_users() is False


# ── State (3): legacy env-var preserved ─────────────────────────────────────

def test_env_var_password_blocks_migration(monkeypatch):
    monkeypatch.setenv('HERMES_WEBUI_PASSWORD', 'legacy-pw')
    status = run_first_boot_migration()
    assert status['action'] == 'env_var_legacy_preserved'
    # Users untouched, no admin auto-created.
    assert users_mod.has_users() is False
    # is_first_boot is False — login form stays in normal mode.
    assert is_first_boot() is False


# ── State (2): upgrade from settings.json password_hash ────────────────────

def test_upgrade_creates_admin_from_legacy_hash(monkeypatch, _isolate):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    # Pre-populate settings.json with a legacy hash.
    legacy_hash = auth._hash_password('legacy-password')
    _isolate['data']['password_hash'] = legacy_hash

    status = run_first_boot_migration()
    assert status['action'] == 'upgraded'
    assert status['admin_username'] == 'admin'
    user = users_mod.get_user_by_username('admin')
    assert user is not None
    assert user['role'] == 'admin'
    assert user['password_hash'] == legacy_hash
    # password_hash stripped from settings.json.
    assert 'password_hash' not in _isolate['data']


def test_upgrade_admin_can_log_in_with_legacy_password(monkeypatch, _isolate):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    legacy_hash = auth._hash_password('legacy-password')
    _isolate['data']['password_hash'] = legacy_hash
    run_first_boot_migration()
    # The original password still works.
    rec = auth.verify_user_credentials('admin', 'legacy-password')
    assert rec is not None
    assert rec['role'] == 'admin'


def test_upgrade_idempotent_on_second_run(monkeypatch, _isolate):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    _isolate['data']['password_hash'] = auth._hash_password('legacy-password')
    run_first_boot_migration()
    second = run_first_boot_migration()
    assert second['action'] == 'already_migrated'
    # No second admin created.
    admins = [u for u in users_mod.load_users() if u['role'] == 'admin']
    assert len(admins) == 1


# ── State (1): already migrated ────────────────────────────────────────────-

def test_already_migrated_no_op(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    users_mod.create_user(
        username='admin', password='supersecret', role='admin',
        assigned_profile='default',
    )
    status = run_first_boot_migration()
    assert status['action'] == 'already_migrated'
    # is_first_boot is False once any user exists.
    assert is_first_boot() is False


# ── cleanup_legacy_sessions ────────────────────────────────────────────────-

def test_cleanup_legacy_sessions_drops_unbound():
    auth.create_session(user_id='u1')
    import time
    auth._sessions['legacyfloat'] = time.time() + 3600
    auth._sessions['legacydict'] = {'expiry': time.time() + 3600, 'user_id': None}

    removed = cleanup_legacy_sessions()
    assert removed == 2
    # u1's session survives.
    assert any(auth._session_user_id(e) == 'u1' for e in auth._sessions.values())


def test_cleanup_legacy_sessions_noop_when_all_bound():
    auth.create_session(user_id='u1')
    auth.create_session(user_id='u2')
    removed = cleanup_legacy_sessions()
    assert removed == 0
    assert len(auth._sessions) == 2


# ── /api/auth/status reflects first_boot ───────────────────────────────────-

def test_is_first_boot_true_on_fresh_install(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    assert is_first_boot() is True


def test_is_first_boot_false_when_users_exist(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_PASSWORD', raising=False)
    users_mod.create_user(
        username='alice', password='supersecret', role='admin',
        assigned_profile='default',
    )
    assert is_first_boot() is False


def test_is_first_boot_false_when_env_var_set(monkeypatch):
    monkeypatch.setenv('HERMES_WEBUI_PASSWORD', 'x')
    assert is_first_boot() is False
