"""Issue #3 — wiki browse endpoints (/pages, /page, /raw).

Mirrors the test pattern of test_issue1257_llm_wiki_status.py: synthesize a wiki
under tmp_path, point WIKI_PATH at it via monkeypatch, and exercise the route
handlers directly with a mocked `j`/`bad` capture.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]


def _write(path: Path, text: str = "# Synthetic\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _wbytes(path: Path, body: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return path


def _capture(routes_mod):
    """Return (captured_state, fake_j, fake_bad) helpers for handler tests."""
    captured = {}

    def fake_j(handler, payload, status=200, extra_headers=None):
        captured["status"] = status
        captured["payload"] = payload
        return True

    def fake_bad(handler, msg, status=400):
        captured["status"] = status
        captured["payload"] = {"error": msg}
        return True

    return captured, fake_j, fake_bad


def _populated_wiki(tmp_path: Path) -> Path:
    wiki = tmp_path / "wiki"
    _write(wiki / "index.md", "# Index\n")
    _write(wiki / "SCHEMA.md", "# Schema\n")
    _write(wiki / "log.md", "# Log\n")
    _write(wiki / "entities" / "alice.md", "# Alice\nA person.\n")
    _write(wiki / "entities" / "people" / "bob.md", "# Bob\nNested entity.\n")
    _write(wiki / "concepts" / "machine-learning.md", "# Machine Learning\nBody.\n")
    # No H1 — title should fall back to filename stem.
    _write(wiki / "concepts" / "no-title.md", "Just body text without a heading.\n")
    _write(wiki / "comparisons" / "alice-vs-bob.md", "# Alice vs Bob\n")
    _write(wiki / "queries" / "what-is-it.md", "# What is it?\n")
    _wbytes(wiki / "raw" / "diagram.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    _wbytes(wiki / "raw" / "notes.txt", b"plain notes\n")
    # A non-md file inside a category dir to confirm rglob('*.md') filtering.
    _wbytes(wiki / "concepts" / "scratch.txt", b"ignored\n")
    return wiki


# ── /api/wiki/pages ────────────────────────────────────────────────────────


def test_pages_lists_categories_with_titles_and_metadata(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        handled = routes._handle_llm_wiki_pages(SimpleNamespace(), urlparse("/api/wiki/pages"))

    assert handled is True
    assert captured["status"] == 200
    payload = captured["payload"]
    assert payload["root"] == str(wiki)
    cats = payload["categories"]
    assert set(cats.keys()) == {"entities", "concepts", "comparisons", "queries"}

    # Entities: alice.md (top-level) + people/bob.md (nested via rglob).
    entity_paths = {e["path"] for e in cats["entities"]}
    assert "entities/alice.md" in entity_paths
    assert "entities/people/bob.md" in entity_paths
    assert all(e["title"] for e in cats["entities"])  # no empty titles
    alice = next(e for e in cats["entities"] if e["path"] == "entities/alice.md")
    assert alice["title"] == "Alice"
    assert alice["size"] > 0
    assert alice["mtime"] is not None

    # Concepts: H1 fallback. no-title.md should fall back to filename stem.
    concept_titles = {c["path"]: c["title"] for c in cats["concepts"]}
    assert concept_titles["concepts/machine-learning.md"] == "Machine Learning"
    assert concept_titles["concepts/no-title.md"] == "no-title"
    # The .txt file under concepts/ must not appear.
    assert "concepts/scratch.txt" not in concept_titles

    # Top-level files include index/SCHEMA/log only.
    top_paths = {t["path"] for t in payload["top_level"]}
    assert top_paths == {"index.md", "SCHEMA.md", "log.md"}


def test_pages_returns_404_when_wiki_path_missing(tmp_path, monkeypatch):
    import api.routes as routes
    missing = tmp_path / "nope"
    monkeypatch.setenv("WIKI_PATH", str(missing))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_pages(SimpleNamespace(), urlparse("/api/wiki/pages"))

    assert captured["status"] == 404


def test_pages_empty_wiki_returns_empty_categories(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_pages(SimpleNamespace(), urlparse("/api/wiki/pages"))

    assert captured["status"] == 200
    cats = captured["payload"]["categories"]
    assert cats == {"entities": [], "concepts": [], "comparisons": [], "queries": []}
    assert captured["payload"]["top_level"] == []


# ── /api/wiki/page?path= ───────────────────────────────────────────────────


def test_page_returns_markdown_for_valid_path(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=concepts/machine-learning.md"))

    assert captured["status"] == 200
    p = captured["payload"]
    assert p["path"] == "concepts/machine-learning.md"
    assert p["title"] == "Machine Learning"
    assert "Body." in p["markdown"]
    assert p["size"] > 0


def test_page_handles_nested_subdirs(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=entities/people/bob.md"))

    assert captured["status"] == 200
    assert captured["payload"]["title"] == "Bob"


def test_page_rejects_path_traversal(tmp_path, monkeypatch):
    """Traversal must 404 (not 500) and must not leak the resolved path."""
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    # Plant a target outside the wiki to confirm it never gets read.
    secret = tmp_path / "secret.txt"
    secret.write_text("DO NOT LEAK", encoding="utf-8")
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=../secret.txt"))

    assert captured["status"] == 404
    assert "DO NOT LEAK" not in repr(captured["payload"])
    assert str(secret) not in repr(captured["payload"])


def test_page_rejects_absolute_path(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=/etc/passwd"))

    # Either 404 (path rejected) or 400 (non-.md extension) is acceptable —
    # the contract is "don't read it". Reject both 200 and 500.
    assert captured["status"] in (400, 404)
    assert "passwd" not in repr(captured["payload"]) or "not found" in repr(captured["payload"]).lower()


def test_page_rejects_hidden_segment(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    _write(wiki / ".hidden" / "secret.md", "# secret\n")
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=.hidden/secret.md"))

    assert captured["status"] == 404


def test_page_rejects_non_md_extension(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=raw/notes.txt"))

    assert captured["status"] == 400


def test_page_404_when_file_missing(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=concepts/nope.md"))

    assert captured["status"] == 404


def test_page_rejects_oversized_file(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    big = wiki / "concepts" / "huge.md"
    big.write_bytes(b"# Big\n" + (b"x" * (routes._LLM_WIKI_MAX_PAGE_BYTES + 1)))
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path=concepts/huge.md"))

    assert captured["status"] == 413


def test_page_rejects_empty_path(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_page(SimpleNamespace(), urlparse("/api/wiki/page?path="))

    assert captured["status"] == 404


# ── /api/wiki/raw?path= ────────────────────────────────────────────────────


def test_raw_serves_allowed_asset(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))

    written = {}

    class FakeWfile:
        def write(self, b): written["body"] = b

    class FakeHandler:
        def __init__(self):
            self.headers_sent = []
            self.status = None
            self.wfile = FakeWfile()
        def send_response(self, code): self.status = code
        def send_header(self, k, v): self.headers_sent.append((k, v))
        def end_headers(self): pass

    handler = FakeHandler()
    handled = routes._handle_llm_wiki_raw(handler, urlparse("/api/wiki/raw?path=raw/diagram.png"))

    assert handled is True
    assert handler.status == 200
    types = dict(handler.headers_sent).get("Content-Type")
    assert types == "image/png"
    assert written["body"].startswith(b"\x89PNG")


def test_raw_strips_optional_raw_prefix(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))

    class H:
        def __init__(self):
            self.status=None; self.headers={}
            class W:
                def write(self,b): pass
            self.wfile=W()
        def send_response(self,c): self.status=c
        def send_header(self,k,v): self.headers[k]=v
        def end_headers(self): pass

    h = H()
    # No "raw/" prefix — should still resolve into raw/.
    handled = routes._handle_llm_wiki_raw(h, urlparse("/api/wiki/raw?path=diagram.png"))
    assert handled is True
    assert h.status == 200


def test_raw_rejects_outside_raw_dir(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        # SCHEMA.md exists at the wiki root, but it's outside raw/ — must be rejected.
        routes._handle_llm_wiki_raw(SimpleNamespace(), urlparse("/api/wiki/raw?path=../SCHEMA.md"))

    assert captured["status"] == 404


def test_raw_rejects_disallowed_extension(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    _wbytes(wiki / "raw" / "danger.exe", b"MZ\x00")
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_raw(SimpleNamespace(), urlparse("/api/wiki/raw?path=raw/danger.exe"))

    assert captured["status"] == 415


def test_raw_404_when_raw_dir_missing(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = tmp_path / "wiki"
    wiki.mkdir()
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured, fake_j, fake_bad = _capture(routes)

    with patch("api.routes.j", side_effect=fake_j), patch("api.routes.bad", side_effect=fake_bad):
        routes._handle_llm_wiki_raw(SimpleNamespace(), urlparse("/api/wiki/raw?path=anything.png"))

    assert captured["status"] == 404


# ── Route registration ─────────────────────────────────────────────────────


def test_pages_route_is_registered(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured = {}

    def fake_j(handler, payload, status=200, extra_headers=None):
        captured["status"] = status; captured["payload"] = payload; return True

    with patch("api.routes.j", side_effect=fake_j):
        handled = routes.handle_get(SimpleNamespace(), urlparse("/api/wiki/pages"))

    assert handled is True
    assert captured["status"] == 200
    assert "categories" in captured["payload"]


def test_page_route_is_registered(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))
    captured = {}

    def fake_j(handler, payload, status=200, extra_headers=None):
        captured["status"] = status; captured["payload"] = payload; return True

    with patch("api.routes.j", side_effect=fake_j):
        handled = routes.handle_get(SimpleNamespace(), urlparse("/api/wiki/page?path=concepts/machine-learning.md"))

    assert handled is True
    assert captured["status"] == 200
    assert captured["payload"]["title"] == "Machine Learning"


def test_raw_route_is_registered(tmp_path, monkeypatch):
    import api.routes as routes
    wiki = _populated_wiki(tmp_path)
    monkeypatch.setenv("WIKI_PATH", str(wiki))

    class H:
        def __init__(self):
            self.status=None
            class W:
                def write(self,b): pass
            self.wfile=W()
        def send_response(self,c): self.status=c
        def send_header(self,k,v): pass
        def end_headers(self): pass

    h = H()
    handled = routes.handle_get(h, urlparse("/api/wiki/raw?path=raw/diagram.png"))
    assert handled is True
    assert h.status == 200


# ── Frontend wiring sanity checks (issue #3) ────────────────────────────────


def test_frontend_has_wiki_menu_item_and_panel():
    """Confirm rail+mobile buttons, panel-view, main-view, and CSS show-rule
    are all wired up so the menu actually renders when revealed."""
    index_src = (REPO / "static" / "index.html").read_text(encoding="utf-8")
    style_src = (REPO / "static" / "style.css").read_text(encoding="utf-8")
    panels_src = (REPO / "static" / "panels.js").read_text(encoding="utf-8")
    boot_src = (REPO / "static" / "boot.js").read_text(encoding="utf-8")
    ui_src = (REPO / "static" / "ui.js").read_text(encoding="utf-8")

    # Conditional menu visibility (issue #3): rail+mobile buttons exist with
    # display:none and live in the DOM ready to be revealed.
    assert 'id="wikiRailBtn"' in index_src
    assert 'id="wikiMobileBtn"' in index_src

    # Both panel-view (left sidebar) and main-view (middle pane) exist.
    assert 'id="panelWiki"' in index_src
    assert 'id="mainWiki"' in index_src

    # CSS toggles middle pane on `showing-wiki`.
    assert "showing-wiki" in style_src
    assert "#mainWiki" in style_src

    # boot.js gates the buttons on /api/wiki/status.available.
    assert "/api/wiki/status" in boot_src
    assert "wikiRailBtn" in boot_src

    # panels.js wires up switchPanel('wiki') and the wiki module.
    assert "loadWikiPanel" in panels_src
    assert "openWikiPage" in panels_src
    assert "/api/wiki/pages" in panels_src
    assert "/api/wiki/page?path=" in panels_src
    assert "data-wiki-path" in panels_src
    assert "data-wiki-link" in panels_src

    # renderMd accepts wikiContext and the sanitizer passes wiki data-attrs through.
    assert "wikiContext" in ui_src
    assert "data-wiki-path" in ui_src
    assert "data-wiki-link" in ui_src


def test_render_md_chat_transcript_unaffected_by_wiki_extension():
    """Without wikiContext, [[X]] and relative .md links must NOT become
    in-app navigation — chat transcripts are unrelated to the wiki."""
    ui_src = (REPO / "static" / "ui.js").read_text(encoding="utf-8")
    # The [[WikiLink]] / relative.md substitutions are gated on `if (_wikiCtx)`
    # in two places: inside inlineMd and at the paragraph-level pass.
    # If anyone accidentally drops the gate the chat renderer would start
    # rewriting [[Foo]] in transcripts, which would be a regression.
    assert ui_src.count("if (_wikiCtx)") >= 2, "wikiContext gating regressed"
