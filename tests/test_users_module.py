"""
Unit tests for api.users — the multi-user RBAC data layer (issue #2).

Covers:
  - Validation: username regex, role, profile-name regex, allowed_profiles,
    permissions defaults, password length, assigned_profile-in-allowed.
  - Persistence: atomic write + .bak rotation, recovery from corrupt main,
    schema-version gate.
  - CRUD: create / get / update / set_password / delete; username
    uniqueness; last-admin guards on delete and demote.
  - Authorization helpers: has_permission, is_profile_allowed.

These tests bypass HTTP — they exercise api.users in-process. Each test
points USERS_FILE / USERS_BAK at a tmp_path location and resets the
module-level cache, so tests are fully isolated from each other and from
the production users file.
"""
import json
from pathlib import Path

import pytest

# Importing the module is safe because api/users.py only imports api._atomic
# and api.config; no agent / network deps.
from api import users as users_mod
from api.users import (
    USERNAME_RE,
    UserValidationError,
    _coerce_permissions,
    _validate_record,
    create_user,
    delete_user,
    get_user_by_id,
    get_user_by_username,
    has_permission,
    is_profile_allowed,
    load_users,
    set_password,
    update_user,
)


@pytest.fixture(autouse=True)
def _isolate_users_state(tmp_path: Path, monkeypatch):
    """Redirect the module's persistence to a per-test tmp dir and reset the cache."""
    users_file = tmp_path / '.users.json'
    bak = tmp_path / '.users.json.bak'
    monkeypatch.setattr(users_mod, 'USERS_FILE', users_file)
    monkeypatch.setattr(users_mod, 'USERS_BAK', bak)
    monkeypatch.setattr(users_mod, '_users_cache', None)
    yield
    monkeypatch.setattr(users_mod, '_users_cache', None)


# ── Validation: usernames, roles, profile names ───────────────────────────-

@pytest.mark.parametrize('name', ['alice', 'a', 'a1', 'user.name', 'user_name', 'user-name', 'a' * 32])
def test_username_regex_accepts_valid(name):
    assert USERNAME_RE.fullmatch(name)


@pytest.mark.parametrize('name', [
    '', 'A', 'ALICE',           # uppercase rejected
    '1abc', 'abc',              # 1abc allowed (digit start ok), 'abc' valid
    '_alice',                   # leading underscore rejected
    'alice space',              # space rejected
    'a' * 33,                   # too long
    'al/ce',                    # slash
])
def test_username_regex_rejects_invalid(name):
    if name in ('1abc', 'abc'):
        # These two are actually valid — they're in the parametrize set as
        # negative controls to confirm the helper doesn't over-reject.
        assert USERNAME_RE.fullmatch(name)
    else:
        assert USERNAME_RE.fullmatch(name) is None


def test_validate_record_requires_role_in_set():
    rec = _stub_user_dict(role='superadmin')
    with pytest.raises(UserValidationError, match='role'):
        _validate_record(rec)


def test_validate_record_requires_assigned_profile_in_allowed():
    rec = _stub_user_dict(assigned_profile='work', allowed_profiles=['personal'])
    with pytest.raises(UserValidationError, match='assigned_profile'):
        _validate_record(rec)


def test_validate_record_normalises_empty_allowed_to_none():
    rec = _stub_user_dict(allowed_profiles=[])
    out = _validate_record(rec)
    assert out['allowed_profiles'] is None


def test_validate_record_drops_duplicate_allowed_profiles():
    rec = _stub_user_dict(
        assigned_profile='work',
        allowed_profiles=['work', 'personal', 'work'],
    )
    out = _validate_record(rec)
    assert out['allowed_profiles'] == ['work', 'personal']


def test_coerce_permissions_fills_defaults():
    p = _coerce_permissions({'switch_profile': False})
    assert p['switch_profile'] is False
    assert p['edit_settings'] is False
    assert p['manage_cron'] is True  # default


def test_coerce_permissions_drops_unknown_keys():
    p = _coerce_permissions({'switch_profile': True, 'become_root': True})
    assert 'become_root' not in p


# ── Persistence: atomic write, .bak, corruption recovery ───────────────────-

def test_create_user_writes_users_file_with_secure_perms(tmp_path):
    create_user(
        username='alice', password='supersecret', role='admin',
        assigned_profile='default',
    )
    assert users_mod.USERS_FILE.exists()
    st_mode = users_mod.USERS_FILE.stat().st_mode & 0o777
    # 0600 was requested. On some FSes umask masks low bits — but group/world
    # write must always be off.
    assert (st_mode & 0o077) == 0


def test_load_users_returns_deep_copy():
    create_user(username='alice', password='supersecret', role='admin', assigned_profile='default')
    a = load_users()
    a[0]['username'] = 'mutated'
    b = load_users()
    assert b[0]['username'] == 'alice'


def test_corrupt_users_file_recovers_from_bak():
    # First write produces a real users file.
    create_user(username='alice', password='supersecret', role='admin', assigned_profile='default')
    # Second write triggers the .bak rotation: previous content is now in .bak.
    create_user(username='bob', password='supersecret', role='user', assigned_profile='default')
    # Both users present.
    assert {u['username'] for u in load_users()} == {'alice', 'bob'}
    # Corrupt the main file — reload should fall back to .bak (alice only).
    users_mod.USERS_FILE.write_text('{not json', encoding='utf-8')
    users_mod.reload_users()
    names = {u['username'] for u in load_users()}
    assert names == {'alice'}, (
        f"expected backup to restore the gen-1 state with just 'alice', got {names}"
    )


def test_unknown_schema_version_ignored():
    users_mod.USERS_FILE.write_text(
        json.dumps({'version': 999, 'users': [{'username': 'x'}]}),
        encoding='utf-8',
    )
    users_mod.reload_users()
    assert load_users() == []


# ── CRUD ───────────────────────────────────────────────────────────────────-

def test_create_then_get_by_id_and_username():
    rec = create_user(
        username='alice', password='supersecret', role='admin',
        assigned_profile='default',
    )
    assert get_user_by_id(rec['id'])['username'] == 'alice'
    assert get_user_by_username('alice')['id'] == rec['id']
    # Username lookup is case-insensitive on the input side.
    assert get_user_by_username('ALICE')['id'] == rec['id']


def test_create_user_normalises_username_to_lowercase():
    rec = create_user(
        username='Alice', password='supersecret', role='user',
        assigned_profile='default',
    )
    assert rec['username'] == 'alice'


def test_create_rejects_duplicate_username():
    create_user(username='alice', password='supersecret', role='admin', assigned_profile='default')
    with pytest.raises(UserValidationError, match='already exists'):
        create_user(username='alice', password='supersecret', role='user', assigned_profile='default')


def test_create_rejects_short_password():
    with pytest.raises(UserValidationError, match='at least'):
        create_user(username='alice', password='short', role='admin', assigned_profile='default')


def test_create_with_password_hash_skips_validation():
    """Migration path: copy a legacy hash without re-hashing."""
    rec = create_user(
        username='alice', password='', role='admin',
        assigned_profile='default',
        password_hash='deadbeef' * 8,  # opaque hex
    )
    assert rec['password_hash'] == 'deadbeef' * 8


def test_update_user_changes_role_and_persists():
    rec = create_user(username='alice', password='supersecret', role='user', assigned_profile='default')
    create_user(username='admin', password='supersecret', role='admin', assigned_profile='default')
    updated = update_user(rec['id'], role='admin')
    assert updated['role'] == 'admin'
    # Reload to confirm persistence.
    users_mod.reload_users()
    assert get_user_by_id(rec['id'])['role'] == 'admin'


def test_update_user_password_via_plaintext():
    rec = create_user(username='alice', password='supersecret', role='admin', assigned_profile='default')
    old_hash = rec['password_hash']
    updated = update_user(rec['id'], password='differentpw')
    assert updated['password_hash'] != old_hash


def test_update_rejects_unknown_field():
    rec = create_user(username='alice', password='supersecret', role='admin', assigned_profile='default')
    with pytest.raises(UserValidationError, match='unknown'):
        update_user(rec['id'], extra_field='x')


def test_set_password_forces_must_change_when_requested():
    rec = create_user(username='alice', password='supersecret', role='user', assigned_profile='default')
    create_user(username='admin', password='supersecret', role='admin', assigned_profile='default')
    set_password(rec['id'], 'newpassword', must_change=True)
    assert get_user_by_id(rec['id'])['must_change_password'] is True


def test_delete_removes_user_and_persists():
    rec = create_user(username='alice', password='supersecret', role='user', assigned_profile='default')
    create_user(username='admin', password='supersecret', role='admin', assigned_profile='default')
    delete_user(rec['id'])
    users_mod.reload_users()
    assert get_user_by_id(rec['id']) is None


def test_delete_blocks_last_admin():
    rec = create_user(username='admin', password='supersecret', role='admin', assigned_profile='default')
    with pytest.raises(UserValidationError, match='only remaining admin'):
        delete_user(rec['id'])


def test_demote_blocks_last_admin():
    rec = create_user(username='admin', password='supersecret', role='admin', assigned_profile='default')
    with pytest.raises(UserValidationError, match='only remaining admin'):
        update_user(rec['id'], role='user')


def test_demote_allowed_when_other_admin_exists():
    a = create_user(username='admin1', password='supersecret', role='admin', assigned_profile='default')
    create_user(username='admin2', password='supersecret', role='admin', assigned_profile='default')
    update_user(a['id'], role='user')
    assert get_user_by_id(a['id'])['role'] == 'user'


# ── Authorization helpers ──────────────────────────────────────────────────-

def test_has_permission_admin_overrides_all():
    admin = {'role': 'admin', 'permissions': {}}
    for k in ('switch_profile', 'edit_settings', 'manage_cron', 'manage_skills', 'manage_users'):
        assert has_permission(admin, k) is True


def test_has_permission_manage_users_is_admin_only():
    # A regular user with manage_users:true on their record still gets False.
    user = {'role': 'user', 'permissions': {'manage_users': True}}
    assert has_permission(user, 'manage_users') is False


def test_has_permission_falls_back_to_default():
    user = {'role': 'user', 'permissions': {}}
    assert has_permission(user, 'switch_profile') is True   # default True
    assert has_permission(user, 'edit_settings') is False   # default False


def test_has_permission_none_user_is_false():
    for k in ('switch_profile', 'edit_settings', 'manage_users'):
        assert has_permission(None, k) is False


def test_is_profile_allowed_admin_anywhere():
    admin = {'role': 'admin', 'allowed_profiles': ['nope']}
    assert is_profile_allowed(admin, 'work') is True


def test_is_profile_allowed_none_means_all():
    user = {'role': 'user', 'allowed_profiles': None}
    assert is_profile_allowed(user, 'anything') is True


def test_is_profile_allowed_filters_by_list():
    user = {'role': 'user', 'allowed_profiles': ['work']}
    assert is_profile_allowed(user, 'work') is True
    assert is_profile_allowed(user, 'personal') is False


# ── Helpers ────────────────────────────────────────────────────────────────-

def _stub_user_dict(**overrides):
    """Minimal user dict for _validate_record tests."""
    base = {
        'id': 'abc123',
        'username': 'alice',
        'password_hash': 'deadbeef' * 8,
        'role': 'user',
        'assigned_profile': 'default',
        'allowed_profiles': None,
        'permissions': {},
        'must_change_password': False,
        'created_at': '2026-05-07T00:00:00Z',
        'last_login_at': None,
    }
    base.update(overrides)
    return base
