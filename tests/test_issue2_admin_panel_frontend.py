"""
Issue #2: smoke tests for the admin panel frontend.

Static regex assertions over the source — the actual interaction tests
require a real browser. The contract these tests enforce is:

  1. Markup: rail + mobile nav-tab + panel-view div all present, both
     hidden by default (display:none on the nav buttons; only revealed by
     boot.js after /api/me confirms role==admin). The middle pane
     (#mainAdmin) carries the detail/edit/empty surface mirroring the
     Profiles panel layout.

  2. Wiring: switchPanel('admin') routes to loadAdminPanel via the lazy-
     load chain in panels.js, and 'admin' is in the main-class-toggle list.

  3. Confirm dialogs: per CLAUDE.md "no native confirm()", admin
     deletions go through showConfirmDialog. Forms render inline in the
     detail pane rather than via showPromptDialog popups.

  4. boot.js fetches /api/me and reveals the admin tab only for admin.

  5. Endpoints touched: /api/admin/users (list/create), /api/admin/users/<id>
     (PATCH/DELETE), /api/admin/users/<id>/password.

  6. Detail-pane shape: the layout mirrors the Profiles panel —
     #adminDetailTitle, #adminDetailBody, #adminDetailEmpty, plus the
     header buttons that drive read/edit/create/reset modes.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent
INDEX_HTML = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
PANELS_JS = (ROOT / 'static' / 'panels.js').read_text(encoding='utf-8')
BOOT_JS = (ROOT / 'static' / 'boot.js').read_text(encoding='utf-8')


# ── 1. Markup ───────────────────────────────────────────────────────────────

def test_admin_rail_button_present_and_hidden_by_default():
    assert 'id="adminRailBtn"' in INDEX_HTML
    rail_idx = INDEX_HTML.find('id="adminRailBtn"')
    rail_block = INDEX_HTML[rail_idx:INDEX_HTML.find('</button>', rail_idx)]
    assert 'display:none' in rail_block, \
        "admin rail button must start with display:none so non-admins never see it"


def test_admin_mobile_button_present_and_hidden_by_default():
    assert 'id="adminMobileBtn"' in INDEX_HTML
    mob_idx = INDEX_HTML.find('id="adminMobileBtn"')
    mob_block = INDEX_HTML[mob_idx:INDEX_HTML.find('</button>', mob_idx)]
    assert 'display:none' in mob_block


def test_admin_panel_view_div_present():
    assert 'id="panelAdmin"' in INDEX_HTML
    assert 'id="adminPanel"' in INDEX_HTML, \
        "the inner content container must be #adminPanel for loadAdminPanel"


def test_admin_buttons_invoke_switch_panel():
    rail_idx = INDEX_HTML.find('id="adminRailBtn"')
    rail_block = INDEX_HTML[rail_idx:INDEX_HTML.find('</button>', rail_idx)]
    assert "switchPanel('admin')" in rail_block


# ── 2. switchPanel dispatcher ───────────────────────────────────────────────

def test_switch_panel_routes_admin_to_load_admin_panel():
    assert "if (nextPanel === 'admin') await loadAdminPanel()" in PANELS_JS


def test_switch_panel_includes_admin_in_main_class_list():
    # 'admin' must appear in the class-toggle list near switchPanel so CSS
    # selectors like `main.main.showing-admin` work for layout.
    sp_idx = PANELS_JS.find("['settings','skills','memory','tasks','kanban','workspaces','profiles','admin'")
    assert sp_idx != -1, "main-class-toggle list must include 'admin'"


# ── 3. Dialog usage (CLAUDE.md hard rule: no native confirm()) ─────────────-

def test_admin_uses_show_confirm_dialog_not_native_confirm():
    """Delete-flow uses showConfirmDialog. Forms (create/edit/reset)
    render inline in the detail pane — they do not call showPromptDialog.
    """
    # Locate the admin section and inspect everything from there to end of file.
    block_start = PANELS_JS.find('// ── Admin panel (issue #2: multi-user RBAC)')
    assert block_start != -1, "Admin panel block delimiter not found"
    block = PANELS_JS[block_start:]
    assert 'showConfirmDialog' in block, \
        "Delete confirmation must use showConfirmDialog (CLAUDE.md hard rule)"
    # Native confirm() / prompt() would be a CLAUDE.md violation.
    assert '\nconfirm(' not in block and ' confirm(' not in block, \
        "Admin block must not call native confirm()"
    assert '\nprompt(' not in block and ' prompt(' not in block, \
        "Admin block must not call native prompt()"


def test_admin_forms_render_inline_not_via_show_prompt_dialog():
    """The new design renders create/edit/reset forms inside #adminDetailBody.
    showPromptDialog is no longer used in the admin block."""
    block_start = PANELS_JS.find('// ── Admin panel (issue #2: multi-user RBAC)')
    block = PANELS_JS[block_start:]
    assert 'showPromptDialog' not in block, \
        "Admin forms render inline in the detail pane — no popup prompts"


# ── 4. boot.js: /api/me probe gates the admin tab ──────────────────────────-

def test_boot_fetches_me_and_reveals_admin_tab():
    assert "api('/api/me')" in BOOT_JS
    idx = BOOT_JS.find("api('/api/me')")
    block = BOOT_JS[idx:idx + 800]
    assert "role==='admin'" in block or "role === 'admin'" in block


def test_boot_404_or_401_does_not_block_chat():
    assert 'S.currentUser=null' in BOOT_JS or 'S.currentUser = null' in BOOT_JS


# ── 5. Endpoints used by the panel ─────────────────────────────────────────-

def test_admin_panel_uses_correct_endpoints():
    assert "api('/api/admin/users')" in PANELS_JS                  # list
    assert "api('/api/admin/users'," in PANELS_JS                  # create POST
    # PATCH/DELETE addresses /api/admin/users/<id> via concatenation.
    assert "api('/api/admin/users/' + " in PANELS_JS
    # password reset endpoint
    assert "/password'" in PANELS_JS or "/password\"" in PANELS_JS


def test_admin_panel_fetches_profiles_for_assignment_dropdowns():
    """Create/edit forms expose an 'assigned profile' dropdown and an
    'allowed profiles' checklist, which need the live profile list."""
    block_start = PANELS_JS.find('// ── Admin panel (issue #2: multi-user RBAC)')
    block = PANELS_JS[block_start:]
    assert "api('/api/profiles')" in block, \
        "Admin panel must fetch /api/profiles to populate the assignment controls"


# ── 6. Detail-pane mirrors Profiles layout ─────────────────────────────────-

def test_main_admin_view_present_with_detail_surface():
    """The middle pane mirrors the Profiles panel: title, body, empty state."""
    assert 'id="mainAdmin"' in INDEX_HTML, "missing #mainAdmin main-view container"
    assert 'id="adminDetailTitle"' in INDEX_HTML
    assert 'id="adminDetailBody"' in INDEX_HTML
    assert 'id="adminDetailEmpty"' in INDEX_HTML


def test_admin_detail_header_buttons_present():
    """The detail pane carries action buttons (edit / reset password / delete /
    cancel / save) that toggle visibility based on read vs form mode."""
    for btn_id in (
        'btnEditAdminUser',
        'btnResetPwAdminUser',
        'btnDeleteAdminUser',
        'btnCancelAdminDetail',
        'btnSaveAdminDetail',
    ):
        assert f'id="{btn_id}"' in INDEX_HTML, f"missing detail-pane button #{btn_id}"


def test_admin_panel_supports_read_create_edit_reset_modes():
    """The mode state machine drives header-button visibility; assert the
    enumeration is present in panels.js."""
    for mode in ("'read'", "'create'", "'edit'", "'reset'", "'empty'"):
        assert mode in PANELS_JS, f"admin mode {mode} not handled"


def test_admin_form_validates_password_confirmation():
    """Per the design: create + reset forms require 'password' and
    'confirm password' fields; mismatch must produce an inline error."""
    block_start = PANELS_JS.find('// ── Admin panel (issue #2: multi-user RBAC)')
    block = PANELS_JS[block_start:]
    assert 'adminFormPasswordConfirm' in block, \
        "Form must collect a confirm-password value"
    assert 'Passwords do not match' in block, \
        "Mismatch must surface inline to the admin"


def test_main_admin_view_is_gated_by_showing_admin_class():
    """The .main-view container is shared by every panel; each one is
    hidden by default and revealed only when its showing-* class is on
    main.main. If #mainAdmin isn't in all three rules (hide list, chat
    fallback :not() chain, and showing-admin reveal), the admin pane
    bleeds through on top of chat and other panels."""
    css = (ROOT / 'static' / 'style.css').read_text(encoding='utf-8')
    assert 'main.main > #mainAdmin' in css, \
        "#mainAdmin missing from the hide-by-default block — it'll show on every page"
    assert ':not(.showing-admin)' in css, \
        "chat fallback :not() chain must exclude showing-admin"
    assert 'main.main.showing-admin > #mainAdmin{display:flex' in css, \
        "no rule reveals #mainAdmin when admin tab is active"


def test_admin_admin_role_greys_allowed_profiles_with_note():
    """When role=admin the allowed-profiles checklist is disabled and a
    note reminds the operator that admins access all profiles."""
    block_start = PANELS_JS.find('// ── Admin panel (issue #2: multi-user RBAC)')
    block = PANELS_JS[block_start:]
    assert 'Admins can access all profiles' in block
    # Disabled attribute is applied per-checkbox when isAdmin is true.
    assert "isAdmin ? ' disabled' : ''" in block
