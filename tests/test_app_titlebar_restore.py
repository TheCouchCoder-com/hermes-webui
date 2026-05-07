from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
STYLE_CSS = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
PANELS_JS = (ROOT / "static" / "panels.js").read_text(encoding="utf-8")
UI_JS = (ROOT / "static" / "ui.js").read_text(encoding="utf-8")


def test_app_titlebar_no_longer_contains_tps_chip():
    assert 'id="tpsStat"' not in INDEX_HTML


def test_app_titlebar_uses_three_column_flex_layout():
    """
    Issue #1 added a profile chip to the right of the titlebar, so the layout
    moved from centered (justify-content:center) to three-column flex
    (hamburger | inner | right). The inner block keeps justify-content:center
    so the title stays visually centered when the right slot is empty.
    """
    assert ".app-titlebar{display:flex;align-items:center;justify-content:space-between;" in STYLE_CSS
    assert ".app-titlebar-inner{display:flex;align-items:center;gap:8px;min-width:0;flex:1 1 auto;justify-content:center;}" in STYLE_CSS
    assert ".app-titlebar-right{" in STYLE_CSS


def test_app_titlebar_subtitle_shows_message_count_again():
    assert "subText = t('n_messages', vis.length);" in PANELS_JS


def test_queue_updates_do_not_hijack_app_titlebar_subtitle():
    assert "_syncQueueTitlebar" not in UI_JS
