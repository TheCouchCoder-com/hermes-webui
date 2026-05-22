from api import streaming


class FakeSession:
    def __init__(self):
        self.session_id = "new_session"
        self.parent_session_id = "original_parent"
        self.active_stream_id = "live-stream"
        self.pending_user_message = "current prompt"
        self.pending_attachments = [{"name": "file.txt"}]
        self.pending_started_at = 123.0
        self.messages = [{"role": "user", "content": "current prompt"}]
        self.saved_payload = None

    def save(self, *, touch_updated_at=True, skip_index=False):
        self.saved_payload = {
            "session_id": self.session_id,
            "parent_session_id": self.parent_session_id,
            "active_stream_id": self.active_stream_id,
            "pending_user_message": self.pending_user_message,
            "pending_attachments": list(self.pending_attachments),
            "pending_started_at": self.pending_started_at,
            "touch_updated_at": touch_updated_at,
            "skip_index": skip_index,
        }


def test_pre_compression_snapshot_clears_runtime_fields_while_restoring_continuation_state():
    session = FakeSession()

    streaming._save_pre_compression_snapshot(session, "old_session")

    assert session.saved_payload == {
        "session_id": "old_session",
        "parent_session_id": "original_parent",
        "active_stream_id": None,
        "pending_user_message": None,
        "pending_attachments": [],
        "pending_started_at": None,
        "touch_updated_at": False,
        "skip_index": True,
    }
    assert session.session_id == "new_session"
    assert session.active_stream_id == "live-stream"
    assert session.pending_user_message == "current prompt"
    assert session.pending_attachments == [{"name": "file.txt"}]
    assert session.pending_started_at == 123.0
