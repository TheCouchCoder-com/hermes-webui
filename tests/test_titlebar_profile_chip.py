"""
Issue #1: Surface profile switcher in the top titlebar
https://github.com/TheCouchCoder-com/hermes-webui/issues/1

Adds a compact profile chip to the right side of <header class="app-titlebar">
so the active profile is visible — and clickable — from every panel, not just
the chat composer. The titlebar chip and the composer chip drive the same
#profileDropdown via _forEachProfileChip / _setProfileChipLabel helpers.

These tests are static (regex over source) and assert the structural contract:

  1. The titlebar chip markup exists and lives inside the app titlebar.
  2. The composer chip is preserved (regression guard).
  3. The titlebar chip wrapper opts out of the macOS frameless drag region
     (-webkit-app-region:no-drag) so the chip stays clickable.
  4. The shared helpers _setProfileChipLabel / _forEachProfileChip are
     defined and used by switchToProfile so both chips stay in sync.
  5. The profile-dropdown is position:fixed so a single dropdown DOM can
     attach to whichever chip was clicked.
  6. The "Manage profiles…" entry still routes via mobileSwitchPanel('profiles').
"""

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
INDEX_HTML = (REPO_ROOT / "static" / "index.html").read_text(encoding="utf-8")
STYLE_CSS = (REPO_ROOT / "static" / "style.css").read_text(encoding="utf-8")
UI_JS = (REPO_ROOT / "static" / "ui.js").read_text(encoding="utf-8")
PANELS_JS = (REPO_ROOT / "static" / "panels.js").read_text(encoding="utf-8")
BOOT_JS = (REPO_ROOT / "static" / "boot.js").read_text(encoding="utf-8")


def _slice_between(text, start_marker, end_marker):
    s = text.find(start_marker)
    assert s != -1, f"start marker not found: {start_marker!r}"
    e = text.find(end_marker, s)
    assert e != -1, f"end marker not found after start: {end_marker!r}"
    return text[s:e]


# ── 1. Markup present and located inside the titlebar ─────────────────────────

def test_titlebar_chip_markup_present():
    assert 'id="profileChipTitlebar"' in INDEX_HTML
    assert 'id="profileChipTitlebarLabel"' in INDEX_HTML
    assert 'id="profileChipTitlebarWrap"' in INDEX_HTML


def test_titlebar_chip_lives_inside_app_titlebar():
    titlebar = _slice_between(INDEX_HTML, '<header class="app-titlebar"', "</header>")
    assert 'id="profileChipTitlebar"' in titlebar, (
        "Titlebar chip must live inside <header class='app-titlebar'>, not "
        "elsewhere in the document."
    )


def test_titlebar_chip_calls_toggle_with_anchor():
    # The titlebar chip must pass `this` to toggleProfileDropdown so the
    # dropdown re-anchors to the titlebar chip rather than the composer chip.
    titlebar = _slice_between(INDEX_HTML, '<header class="app-titlebar"', "</header>")
    assert 'toggleProfileDropdown(this)' in titlebar


# ── 2. Composer chip preserved ────────────────────────────────────────────────

def test_composer_chip_preserved():
    """Regression guard for issue #1: the composer chip must continue to exist."""
    assert 'id="profileChipWrap"' in INDEX_HTML
    assert 'id="profileChip"' in INDEX_HTML
    assert 'id="profileChipLabel"' in INDEX_HTML


# ── 3. Drag region opt-out ────────────────────────────────────────────────────

def test_titlebar_chip_wrap_is_no_drag():
    # The titlebar has -webkit-app-region:drag for macOS frameless windows;
    # the chip wrapper and chip itself must opt out so they stay clickable.
    assert ".titlebar-profile-wrap{" in STYLE_CSS
    rule = _slice_between(STYLE_CSS, ".titlebar-profile-wrap{", "}")
    assert "-webkit-app-region:no-drag" in rule, (
        ".titlebar-profile-wrap must include -webkit-app-region:no-drag so the "
        "chip is clickable when the titlebar is a draggable window region."
    )


def test_app_titlebar_right_is_no_drag():
    assert ".app-titlebar-right{" in STYLE_CSS
    rule = _slice_between(STYLE_CSS, ".app-titlebar-right{", "}")
    assert "-webkit-app-region:no-drag" in rule


# ── 4. Shared helpers wired through switchToProfile ───────────────────────────

def test_set_profile_chip_label_helper_defined():
    assert "function _setProfileChipLabel(" in UI_JS
    helper = _slice_between(UI_JS, "function _setProfileChipLabel(", "function _forEachProfileChip(")
    # Both chip label IDs must be referenced by the helper.
    assert "profileChipLabel" in helper
    assert "profileChipTitlebarLabel" in helper


def test_for_each_profile_chip_helper_defined():
    assert "function _forEachProfileChip(" in UI_JS
    helper = _slice_between(UI_JS, "function _forEachProfileChip(", "function syncTopbar(")
    # Both chip IDs must be referenced by the helper.
    assert "'profileChip'" in helper
    assert "'profileChipTitlebar'" in helper


def test_switch_profile_uses_for_each_chip_helper():
    # switchToProfile mirrors spinner/disabled state on the titlebar chip via
    # _forEachProfileChip, in addition to the composer-only _chip locals.
    idx = PANELS_JS.find("async function switchToProfile(name) {")
    assert idx != -1
    end = PANELS_JS.find("\n}\n", idx)
    fn = PANELS_JS[idx:end]
    assert "_forEachProfileChip" in fn, (
        "switchToProfile must use _forEachProfileChip so both chip surfaces "
        "(composer + titlebar) get the spinner/disabled state, not just the composer."
    )
    assert "_setProfileChipLabel" in fn, (
        "switchToProfile must use _setProfileChipLabel so the optimistic name "
        "update reaches both chips."
    )


def test_boot_uses_set_profile_chip_label():
    # boot.js applies the freshly-fetched active profile to both chips.
    assert "_setProfileChipLabel(S.activeProfile" in BOOT_JS


# ── 5. Profile dropdown is position:fixed ────────────────────────────────────-

def test_profile_dropdown_uses_position_fixed():
    # Find the .profile-dropdown rule (not .profile-dropdown.open).
    idx = STYLE_CSS.find(".profile-dropdown{")
    assert idx != -1
    rule = STYLE_CSS[idx:STYLE_CSS.find("}", idx)]
    assert "position:fixed" in rule, (
        "The profile dropdown must be position:fixed so it can attach to "
        "either the composer chip or the titlebar chip via viewport coordinates."
    )


def test_position_profile_dropdown_takes_anchor():
    # _positionProfileDropdown(anchor) should accept an anchor element so it
    # can attach to whichever chip was clicked.
    assert "function _positionProfileDropdown(anchor)" in PANELS_JS


def test_outside_click_handler_includes_titlebar_wrap():
    # The dropdown stays open while clicking inside either chip wrapper.
    assert "#profileChipTitlebarWrap" in PANELS_JS


# ── 6. Manage profiles entry routes via mobileSwitchPanel('profiles') ─────────

def test_manage_profiles_routes_to_profiles_panel():
    # renderProfileDropdown wires the mgmt entry to mobileSwitchPanel('profiles').
    # This is structurally guaranteed by sharing one dropdown DOM between chips,
    # but assert the wiring directly so a future refactor can't quietly break it.
    assert "mobileSwitchPanel('profiles')" in PANELS_JS
