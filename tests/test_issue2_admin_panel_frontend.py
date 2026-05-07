"""
Issue #2: smoke tests for the admin panel frontend.

Static regex assertions over the source — the actual interaction tests
require a real browser. The contract these tests enforce is:

  1. Markup: rail + mobile nav-tab + panel-view div all present, both
     hidden by default (display:none on the nav buttons; only revealed by
     boot.js after /api/me confirms role==admin).

  2. Wiring: switchPanel('admin') routes to loadAdminPanel via the lazy-
     load chain in panels.js.

  3. Confirm/prompt dialogs: per CLAUDE.md "no native confirm()", admin
     deletions go through showConfirmDialog / showPromptDialog.

  4. boot.js fetches /api/me and reveals the admin tab only for admin.

  5. Endpoints touched: /api/admin/users (list/create), /api/admin/users/<id>
     (PATCH/DELETE), /api/admin/users/<id>/password.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent
INDEX_HTML = (ROOT / 'static' / 'index.html').read_text(encoding='utf-8')
PANELS_JS = (ROOT / 'static' / 'panels.js').read_text(encoding='utf-8')
BOOT_JS = (ROOT / 'static' / 'boot.js').read_text(encoding='utf-8')


# ── 1. Markup ───────────────────────────────────────────────────────────────

def test_admin_rail_button_present_and_hidden_by_default():
    assert 'id="adminRailBtn"' in INDEX_HTML
    # The button must start hidden — boot.js reveals it only for admin role.
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
    # The mainEl class toggle list now carries 'admin' so CSS can target it.
    assert "'admin'" in PANELS_JS
    # Confirm it's specifically in the class-toggle list near switchPanel.
    sp_idx = PANELS_JS.find("['settings','skills','memory','tasks','kanban','workspaces','profiles','admin'")
    assert sp_idx != -1, "main-class-toggle list must include 'admin'"


# ── 3. Dialog usage (CLAUDE.md hard rule: no native confirm()) ─────────────-

def test_admin_uses_show_confirm_dialog_not_native_confirm():
    # Find the loadAdminPanel block and the adminDeleteUser function.
    assert 'function adminDeleteUser(' in PANELS_JS
    block_start = PANELS_JS.find('async function adminDeleteUser(')
    # The whole admin-panel block runs to end of file; scan the rest.
    block = PANELS_JS[block_start:]
    assert 'showConfirmDialog' in block, \
        "Delete confirmation must use showConfirmDialog (CLAUDE.md hard rule)"
    # Native confirm() would be a CLAUDE.md violation.
    assert '\nconfirm(' not in block and ' confirm(' not in block


def test_admin_password_reset_uses_show_prompt_dialog():
    block_start = PANELS_JS.find('async function adminResetPassword(')
    block_end = PANELS_JS.find('async function adminDeleteUser(', block_start)
    block = PANELS_JS[block_start:block_end]
    assert 'showPromptDialog' in block


# ── 4. boot.js: /api/me probe gates the admin tab ──────────────────────────-

def test_boot_fetches_me_and_reveals_admin_tab():
    assert "api('/api/me')" in BOOT_JS
    # The reveal must be gated on me.role === 'admin'.
    idx = BOOT_JS.find("api('/api/me')")
    block = BOOT_JS[idx:idx + 800]
    assert "role==='admin'" in block or "role === 'admin'" in block


def test_boot_404_or_401_does_not_block_chat():
    """The /api/me try/catch must swallow errors silently — auth-disabled
    deployments must still load."""
    assert 'S.currentUser=null' in BOOT_JS or 'S.currentUser = null' in BOOT_JS


# ── 5. Endpoints used by the panel ─────────────────────────────────────────-

def test_admin_panel_uses_correct_endpoints():
    assert "api('/api/admin/users')" in PANELS_JS                  # list
    assert "api('/api/admin/users'," in PANELS_JS                  # create
    # PATCH (edit role) — uses concatenated URL.
    assert "api('/api/admin/users/' + userId" in PANELS_JS
    # password reset endpoint
    assert "/password'" in PANELS_JS or "/password\"" in PANELS_JS


def test_admin_loads_at_most_one_endpoint_per_action():
    """Sanity: every mutation in adminEditUser/adminResetPassword/
    adminDeleteUser/openAdminUserCreate makes exactly one fetch."""
    for fn in ('openAdminUserCreate', 'adminEditUser', 'adminResetPassword', 'adminDeleteUser'):
        idx = PANELS_JS.find('function ' + fn + '(')
        assert idx != -1, f"missing function {fn}"
        # Find the next blank-line + function-definition break.
        block_end = PANELS_JS.find('\nasync function ', idx + 5)
        if block_end == -1:
            block_end = len(PANELS_JS)
        block = PANELS_JS[idx:block_end]
        # Each mutation function has at most one api() call (the GET happens
        # afterwards via loadAdminPanel which is not counted here).
        api_calls_to_admin = block.count("api('/api/admin/")
        assert api_calls_to_admin == 1, (
            f"{fn} must make exactly one /api/admin/* call, found {api_calls_to_admin}"
        )
