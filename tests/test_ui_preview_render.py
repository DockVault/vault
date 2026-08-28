"""UI: the file-preview "Render" toggle (Markdown / HTML / source).

  * unit — the toggle + the sandboxed-iframe render path are wired in the frontend, and the server
           endpoint + renderer are wired in the backend.
  * ui   — a real browser: a Markdown file gains a "Render" button; clicking it shows the rendered
           content in a FULLY SANDBOXED iframe (sandbox="" + srcdoc, no scripts, no external loads);
           an embedded <script> never executes; toggling returns to the raw text.
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_preview_render_is_wired():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    api = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    core = (ROOT / "app" / "core" / "preview_render.py").read_text(encoding="utf-8")
    # frontend: the renderable-ext set, the toggle builder, the sandboxed-iframe fetch.
    assert "RENDERABLE_PREVIEW_EXTS" in app
    assert "function _buildRenderablePreview(" in app
    assert "preview-render" in app
    assert "setAttribute('sandbox', '')" in app
    assert ".srcdoc = data.html" in app or "frame.srcdoc" in app
    # backend: the endpoint + the renderer wiring.
    assert "/preview-render" in api and "render_preview_document" in api
    assert "def sanitize_preview_html(" in core and "attribute_filter" in core


# --------------------------------------------------------------------------- ui lane


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_text_preview(page: Page, vault_id: str, name: str, content: bytes):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.set_input_files("#file-upload-input",
                         files=[{"name": name, "mimeType": "text/markdown", "buffer": content}])
    page.click('[data-files-view="grid"]')
    tile = page.locator("#vault-files-grid .file-tile").first
    expect(tile).to_be_visible(timeout=15000)
    tile.locator(".tile-icon").first.click()
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)


@pytest.mark.ui
def test_markdown_render_toggle_is_sandboxed_and_script_free(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("prev"))
    vid = v["id"]
    # An embedded <script> would fire a dialog if it ever executed; fail loudly if it does.
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        body = b"# Heading One\n\n<script>alert('XSS')</script>\n\nHello **world**\n"
        _open_text_preview(page, vid, unique("doc") + ".md", body)

        # Raw text is shown first, with a Render toggle.
        pre = page.locator("#file-preview-modal .preview-text")
        expect(pre).to_be_visible(timeout=8000)
        toggle = page.locator("#file-preview-modal .preview-render-toolbar button")
        expect(toggle).to_have_text("Render")

        # Render -> a sandboxed iframe appears; the raw <pre> hides.
        toggle.click()
        frame = page.locator("#file-preview-modal iframe.preview-render-frame")
        expect(frame).to_be_visible(timeout=8000)
        assert frame.get_attribute("sandbox") == "", "iframe must have an EMPTY sandbox"
        srcdoc = frame.get_attribute("srcdoc") or ""
        assert "<h1>Heading One</h1>" in srcdoc      # markdown actually rendered
        assert "<script" not in srcdoc.lower()        # script stripped server-side
        assert "Content-Security-Policy" in srcdoc    # CSP baked in
        expect(toggle).to_have_text("View raw")

        # The rendered content is inside the sandbox and the script did not run.
        heading = page.frame_locator("#file-preview-modal iframe.preview-render-frame").locator("h1")
        expect(heading).to_have_text("Heading One")
        page.wait_for_timeout(300)
        assert not dialogs, f"a script executed in the preview: {dialogs}"

        # Toggle back to raw.
        toggle.click()
        expect(pre).to_be_visible()
        expect(page.locator("#file-preview-modal iframe.preview-render-frame")).to_be_hidden()
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_plain_text_file_has_no_render_toggle(page: Page, admin, admin_creds):
    """A .txt/.log file is not a render target -- it shows raw text with no toggle."""
    v = admin.create_vault(name=unique("prevtxt"))
    vid = v["id"]
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_text_preview(page, vid, unique("notes") + ".txt", b"just plain text, nothing to render")
        expect(page.locator("#file-preview-modal .preview-text")).to_be_visible(timeout=8000)
        expect(page.locator("#file-preview-modal .preview-render-toolbar")).to_have_count(0)
    finally:
        admin.delete_vault(vid)
