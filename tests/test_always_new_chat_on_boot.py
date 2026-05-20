"""Regression tests for the 'Always start new chat' boot setting (issue #19).

When the ``hermes-webui-always-new-chat`` localStorage key is ``'true'``,
the boot path in ``boot.js`` must skip restoring the saved session unless
the user navigated via a deep link (``?session=…``) or the saved session
has an in-flight stream to resume.
"""
from pathlib import Path
import re

REPO = Path(__file__).parent.parent
BOOT_JS = (REPO / "static" / "boot.js").read_text(encoding="utf-8")


def _boot_restore_block() -> str:
    """Extract the full boot restore section from boot.js."""
    idx = BOOT_JS.find("const urlSession=")
    assert idx > 0, "boot.js must contain urlSession resolution"
    # Return ~5KB after — covers the full if(saved) + empty-state blocks
    return BOOT_JS[idx:idx + 5000]


def test_always_new_chat_key_is_read_on_boot() -> None:
    """Boot must read hermes-webui-always-new-chat from localStorage."""
    block = _boot_restore_block()
    assert "hermes-webui-always-new-chat" in block, (
        "boot.js must read hermes-webui-always-new-chat to gate session restore"
    )


def test_always_new_chat_guard_present() -> None:
    """When the key is 'true' and there's no deep link, boot must skip
    loadSession() and go to the empty state."""
    block = _boot_restore_block()
    # The guard must appear after saved is computed
    saved_idx = block.find("const saved=urlSession||savedLocal")
    always_new_idx = block.find("hermes-webui-always-new-chat")
    assert always_new_idx > saved_idx, (
        "always-new-chat check must happen after saved is computed"
    )


def test_deep_link_still_restores() -> None:
    """The always-new guard must NOT block a urlSession — deep links
    are explicit user intent and must always restore."""
    block = _boot_restore_block()
    # The guard must check !urlSession
    assert "!urlSession" in block, (
        "always-new guard must check !urlSession so deep links still work"
    )


def test_inflight_stream_check_retained() -> None:
    """When always-new is ON, the boot path must still call
    _savedSessionShouldStaySidebarOnly to check for in-flight streams."""
    block = _boot_restore_block()
    assert "_savedSessionShouldStaySidebarOnly" in block, (
        "always-new path must still check for in-flight streams via "
        "_savedSessionShouldStaySidebarOnly"
    )


def test_default_behavior_unchanged() -> None:
    """The always-new check is gated on '===true' — absence of key or
    value 'false' must not change behavior."""
    block = _boot_restore_block()
    assert "if(saved)" in block, (
        "existing if(saved) block must still exist for default behavior"
    )
    assert "loadSession" in block, (
        "loadSession must still be called in the default path"
    )
