"""
Issue #2: tamper-proof the hermes_profile cookie.

The original implementation (issue #2) HMAC-signed the cookie using only the
profile name. Upstream v0.51.368 (#803) superseded that with a stronger
session-bound signing scheme: the cookie is now bound to the active auth
session so it cannot be forged or replayed across sessions. No-auth mode
keeps the legacy plain-name cookie (not a security boundary there).

This file retains regression coverage for the original concern (profile
isolation / tamper prevention) expressed in terms of the current
implementation. Detailed new-cookie tests live in test_issue803.py.
"""
from unittest.mock import MagicMock

import pytest


def _handler(cookie_str: str):
    h = MagicMock()
    h.headers.get = lambda k, d='': cookie_str if k == 'Cookie' else d
    return h


# ── No-auth mode: plain profile name, still validated ────────────────────────

class TestNoAuthMode:
    def test_plain_cookie_accepted(self, monkeypatch):
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: False)
        assert get_profile_cookie(_handler('hermes_profile=work')) == 'work'

    def test_default_profile_accepted(self, monkeypatch):
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: False)
        assert get_profile_cookie(_handler('hermes_profile=default')) == 'default'

    def test_missing_cookie_returns_none(self, monkeypatch):
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: False)
        assert get_profile_cookie(_handler('')) is None

    def test_invalid_profile_name_rejected(self, monkeypatch):
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: False)
        for bad in ('../etc', 'a/b', 'WithCaps', 'has space', '.hidden'):
            assert get_profile_cookie(_handler(f'hermes_profile={bad}')) is None, bad

    def test_build_emits_plain_value(self, monkeypatch):
        from api.helpers import build_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: False)
        s = build_profile_cookie('work')
        assert 'hermes_profile=work' in s
        assert 'HttpOnly' in s
        assert 'SameSite=Lax' in s


# ── Auth mode: session-bound signed cookie, tamper-proof ─────────────────────

class TestAuthMode:
    SESSION = 'session-token.session-sig'

    def _auth_handler(self, profile_cookie_value: str) -> MagicMock:
        h = MagicMock()
        h.headers.get = lambda k, d='': (
            f'hermes_session={self.SESSION}; hermes_profile={profile_cookie_value}'
            if k == 'Cookie' else d
        )
        return h

    def test_valid_signed_cookie_accepted(self, monkeypatch):
        from api.auth import sign_profile_cookie_value
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: True)
        monkeypatch.setattr('api.auth.verify_session', lambda c: c == self.SESSION)
        signed = sign_profile_cookie_value('work', self.SESSION)
        assert get_profile_cookie(self._auth_handler(signed)) == 'work'

    def test_unsigned_plain_cookie_rejected(self, monkeypatch):
        """Tamper-proofing: a plain name cookie must be rejected when auth is on."""
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: True)
        monkeypatch.setattr('api.auth.verify_session', lambda c: c == self.SESSION)
        assert get_profile_cookie(self._auth_handler('work')) is None

    def test_cross_session_cookie_rejected(self, monkeypatch):
        """Cookie signed for a different session must not grant access."""
        from api.auth import sign_profile_cookie_value
        from api.helpers import get_profile_cookie
        other_session = 'other-token.other-sig'
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: True)
        monkeypatch.setattr(
            'api.auth.verify_session',
            lambda c: c in {self.SESSION, other_session},
        )
        signed = sign_profile_cookie_value('work', other_session)
        assert get_profile_cookie(self._auth_handler(signed)) is None

    def test_tampered_profile_name_rejected(self, monkeypatch):
        """Attacker replaces profile name but keeps the original signature."""
        from api.auth import sign_profile_cookie_value
        from api.helpers import get_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: True)
        monkeypatch.setattr('api.auth.verify_session', lambda c: c == self.SESSION)
        signed_for_work = sign_profile_cookie_value('work', self.SESSION)
        # Strip the real sig and replace the name
        _, sig = signed_for_work.rsplit('.', 1)
        tampered = f'admin.{sig}'
        assert get_profile_cookie(self._auth_handler(tampered)) is None

    def test_build_requires_handler_when_auth_on(self, monkeypatch):
        from api.helpers import build_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: True)
        with pytest.raises(RuntimeError):
            build_profile_cookie('work')  # no handler

    def test_build_with_handler_emits_session_bound_cookie(self, monkeypatch):
        from api.auth import verify_profile_cookie_value
        from api.helpers import build_profile_cookie
        monkeypatch.setattr('api.auth.is_auth_enabled', lambda: True)
        monkeypatch.setattr('api.auth.verify_session', lambda c: c == self.SESSION)
        handler = MagicMock()
        handler.headers.get = lambda k, d='': f'hermes_session={self.SESSION}' if k == 'Cookie' else d
        cookie = build_profile_cookie('work', handler)
        value = cookie.split('hermes_profile=', 1)[1].split(';', 1)[0]
        assert value != 'work'  # must be signed, not plain
        assert verify_profile_cookie_value(value, self.SESSION) == 'work'
