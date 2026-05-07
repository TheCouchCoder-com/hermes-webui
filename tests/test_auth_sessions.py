"""
Tests for auth session lifecycle — session creation, verification, expiry,
and lazy pruning of expired entries.
"""
import time
import unittest
from pathlib import Path
import tempfile
import os

# Isolate state dir so we don't touch real sessions
_TEST_STATE = Path(tempfile.mkdtemp())
os.environ["HERMES_WEBUI_STATE_DIR"] = str(_TEST_STATE)

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import importlib

# Force re-import of auth module so it picks up our TEST_STATE_DIR
auth = importlib.import_module("api.auth")


class TestSessionPruning(unittest.TestCase):
    """Verify expired session cleanup works correctly."""

    def setUp(self):
        # Clear any leftover sessions from other tests
        auth._sessions.clear()

    def test_session_created_valid(self):
        """A fresh session token should verify as valid."""
        token = auth.create_session()
        self.assertTrue(auth.verify_session(token))

    def test_expired_session_pruned(self):
        """Manually inserting an expired entry should be pruned on next verify_session call."""
        # Insert sessions that have already expired
        auth._sessions["fake_token"] = time.time() - 100
        auth._sessions["another_fake"] = time.time() - 50
        # Insert one valid session (far future)
        auth._sessions["good_token"] = time.time() + 3600

        # _sessions has 3 entries, 2 expired
        self.assertEqual(len(auth._sessions), 3)

        # Call verify_session — this triggers _prune_expired_sessions()
        # Cookie format is token.signature, so we need a dot to pass the early check
        auth.verify_session("fake_token.fake_sig")

        # After verification, only the valid session should remain
        self.assertEqual(len(auth._sessions), 1)
        self.assertIn("good_token", auth._sessions)
        self.assertNotIn("fake_token", auth._sessions)
        self.assertNotIn("another_fake", auth._sessions)

    def test_prune_does_not_remove_valid_sessions(self):
        """_prune_expired_sessions should never remove sessions that are still active."""
        auth._sessions["active_1"] = time.time() + 86400  # 24 hours from now
        auth._sessions["active_2"] = time.time() + 7200    # 2 hours from now
        auth._sessions["expired_1"] = time.time() - 10

        auth._prune_expired_sessions()

        self.assertEqual(len(auth._sessions), 2)
        self.assertIn("active_1", auth._sessions)
        self.assertIn("active_2", auth._sessions)
        self.assertNotIn("expired_1", auth._sessions)

    def test_verify_session_prunes_before_verification(self):
        """verify_session should prune expired entries before checking the target token.

        This ensures that _prune_expired_sessions() is called at the very top
        of verify_session(), so cleanup happens on every auth check.
        """
        auth._sessions["expired_for_test"] = time.time() - 999

        # verify_session with an invalid cookie triggers the full path:
        # _prune_expired_sessions -> signature check -> return False
        result = auth.verify_session("nonexistent.bad_sig")
        self.assertFalse(result)

        # The expired entry should have been cleaned up
        self.assertNotIn("expired_for_test", auth._sessions)

    def test_prune_handles_empty_dict(self):
        """_prune_expired_sessions should be safe on an empty dict."""
        auth._sessions.clear()
        auth._prune_expired_sessions()
        self.assertEqual(len(auth._sessions), 0)

    def test_session_ttl_matches_constant(self):
        """Newly created sessions expire SESSION_TTL seconds in the future.

        Issue #2 changed the in-memory shape from `token -> expiry_float` to
        `token -> {user_id, expiry}`. _session_expiry abstracts both shapes
        so legacy tests can still assign a raw float to _sessions[token].
        """
        auth._sessions.clear()
        token_hex = auth.create_session().split(".")[0]
        from api.auth import _sessions, SESSION_TTL, _session_expiry
        entry = _sessions.get(token_hex)
        self.assertIsNotNone(entry, "Session token not found in _sessions")
        expected = time.time() + SESSION_TTL
        self.assertAlmostEqual(_session_expiry(entry), expected, delta=5)


class TestSessionInvalidation(unittest.TestCase):
    """Test session logout / invalidation."""

    def setUp(self):
        auth._sessions.clear()

    def test_invalidate_session_removes_token(self):
        """Calling invalidate_session should remove the token from _sessions."""
        token = auth.create_session()
        self.assertTrue(auth.verify_session(token))

        auth.invalidate_session(token)
        # Token should be gone
        self.assertFalse(auth.verify_session(token))

    def test_invalidate_unknown_token_is_safe(self):
        """Invalidating a non-existent token should not raise."""
        auth._sessions.clear()
        auth.invalidate_session("nonexistent_token")
        # Should not raise


if __name__ == "__main__":
    unittest.main()
