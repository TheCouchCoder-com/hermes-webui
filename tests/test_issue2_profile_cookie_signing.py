"""
Issue #2: HMAC-sign the hermes_profile cookie.

The cookie is now "<name>.<32-hex sig>" where sig is HMAC-SHA256 of the
name with _signing_key as the key. This is tamper-evidence on top of the
hard wall at /api/profile/switch (allowed_profiles enforcement).

Validation matrix
  - Valid signed cookie  → returns the profile name.
  - Tampered name        → returns None (cookie ignored).
  - Tampered signature   → returns None.
  - Unsigned legacy form → returns None UNLESS the transition env var is set.
  - Missing cookie       → returns None.
  - Malformed (e.g. just a dot) → returns None.

build_profile_cookie always emits the signed form.
"""
import os
from unittest.mock import MagicMock

import pytest

from api.helpers import (
    build_profile_cookie,
    get_profile_cookie,
    _profile_cookie_signature,
)


def _handler_with_cookie(cookie_value: str):
    """Stand-in for an http.server BaseHTTPRequestHandler. The helper only
    reads headers.get('Cookie', '') — a plain dict satisfies that."""
    h = MagicMock()
    h.headers = {'Cookie': f'hermes_profile={cookie_value}'} if cookie_value else {}
    return h


def test_build_profile_cookie_emits_signed_form():
    set_cookie = build_profile_cookie('work')
    # Format: "hermes_profile=work.<32hex>; Path=/; HttpOnly; SameSite=Lax"
    assert set_cookie.startswith('hermes_profile=work.')
    payload = set_cookie.split(';', 1)[0]
    _, _, value = payload.partition('=')
    name, _, sig = value.rpartition('.')
    assert name == 'work'
    assert len(sig) == 32 and all(c in '0123456789abcdef' for c in sig)


def test_get_profile_cookie_accepts_valid_signed():
    sig = _profile_cookie_signature('work')
    h = _handler_with_cookie(f'work.{sig}')
    assert get_profile_cookie(h) == 'work'


def test_get_profile_cookie_rejects_tampered_name():
    sig = _profile_cookie_signature('work')
    # Attacker swaps name from 'work' to 'admin' but keeps the work signature.
    h = _handler_with_cookie(f'admin.{sig}')
    assert get_profile_cookie(h) is None


def test_get_profile_cookie_rejects_tampered_signature():
    h = _handler_with_cookie('work.deadbeefdeadbeefdeadbeefdeadbeef')
    assert get_profile_cookie(h) is None


def test_get_profile_cookie_rejects_malformed_cookie():
    for v in ('.', 'a.', '.a', '...'):
        h = _handler_with_cookie(v)
        assert get_profile_cookie(h) is None, f'should reject {v!r}'


def test_get_profile_cookie_no_cookie_returns_none():
    h = _handler_with_cookie('')
    assert get_profile_cookie(h) is None


def test_unsigned_cookie_rejected_by_default(monkeypatch):
    monkeypatch.delenv('HERMES_WEBUI_ACCEPT_UNSIGNED_PROFILE_COOKIE', raising=False)
    h = _handler_with_cookie('work')
    assert get_profile_cookie(h) is None


def test_unsigned_cookie_accepted_when_transition_flag_set(monkeypatch):
    monkeypatch.setenv('HERMES_WEBUI_ACCEPT_UNSIGNED_PROFILE_COOKIE', '1')
    h = _handler_with_cookie('work')
    assert get_profile_cookie(h) == 'work'


def test_unsigned_cookie_still_validated_against_profile_regex(monkeypatch):
    """Even with the legacy flag on, an obviously bogus name is rejected."""
    monkeypatch.setenv('HERMES_WEBUI_ACCEPT_UNSIGNED_PROFILE_COOKIE', '1')
    h = _handler_with_cookie('../../etc/passwd')
    assert get_profile_cookie(h) is None


def test_signed_cookie_for_default_profile_works():
    """The literal name 'default' is a valid profile, must sign + verify too."""
    sig = _profile_cookie_signature('default')
    h = _handler_with_cookie(f'default.{sig}')
    assert get_profile_cookie(h) == 'default'


def test_signature_is_deterministic_within_same_signing_key():
    a = _profile_cookie_signature('work')
    b = _profile_cookie_signature('work')
    assert a == b


def test_signature_differs_per_profile_name():
    assert _profile_cookie_signature('work') != _profile_cookie_signature('personal')
