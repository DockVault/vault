"""Bounded-memory preview: refuse huge media inline, window big text.

  * unit — the media size guard + the windowed big-text reader are wired in.
  * ui   — a real browser: a huge media file is refused for inline preview WITHOUT fetching its body;
           a big (>2 MB) Standard-vault text file is previewed from just its first window (a Range
           request), with a truncation note, instead of being loaded whole.
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_preview_bounds_are_wired():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert "MEDIA_PREVIEW_MAX_BYTES" in app
    assert "TEXT_PREVIEW_WINDOW_BYTES" in app
    assert "function _renderTextWindow(" in app
    assert "function _renderPreviewTooLarge(" in app
    assert "'Range': `bytes=0-" in app                 # the windowed read is a real Range request
    assert "reader.cancel()" in app                    # and stops after the first window


# --------------------------------------------------------------------------- ui lane


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


@pytest.mark.ui
def test_huge_media_is_refused_without_fetching(page: Page, admin, admin_creds):
    """A media file over the cap shows a 'too large to preview inline' message and does NOT fetch
    the body (bounded memory). Driven with a synthetic large-media listing entry so no multi-hundred-
    MB upload is needed; a fetch to /download would fail the no-network assertion if one happened."""
    v = admin.create_vault(name=unique("pbig"))
    requested = []
    page.on("request", lambda r: requested.append(r.url) if "/download" in r.url else None)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        page.evaluate(
            """() => {
                if (!Array.isArray(state.currentFiles)) state.currentFiles = [];
                state.currentFiles.push({ id: 'huge-media', name: 'huge.mp4', type: 'file',
                    size: 500 * 1024 * 1024 });
                openFilePreview('huge-media', 'huge.mp4', 'video/mp4');
            }"""
        )
        expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)
        expect(page.locator("#file-preview-body")).to_contain_text("too large to preview inline")
        page.wait_for_timeout(400)
        assert not requested, f"a huge media preview must not fetch the body, but did: {requested}"
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_big_text_is_previewed_from_its_first_window(page: Page, admin, admin_creds):
    """A >2 MB Standard-vault text file is previewed from just its first ~512 KB via a Range request,
    with a truncation note -- not loaded whole."""
    v = admin.create_vault(name=unique("ptxt"))
    vid = v["id"]
    # ~2.6 MB of line-numbered text, so the window boundary is deterministic and visibly truncated.
    body = ("".join(f"line {i:07d} ................................................\n"
                    for i in range(45000))).encode()
    assert len(body) > 2 * 1024 * 1024
    admin.post(f"/vaults/{vid}/files", files=[("files", ("big.txt", body, "text/plain"))]).raise_for_status()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        expect(page.locator(".file-name[data-file-id]").first).to_be_visible(timeout=10000)
        fid = page.locator(".file-name[data-file-id]").first.get_attribute("data-file-id")
        page.evaluate("(fid) => openFilePreview(fid, 'big.txt', 'text/plain')", fid)
        expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)
        # the truncation note + the leading content are shown ...
        expect(page.locator("#file-preview-body .preview-window-note")).to_contain_text("Showing the first")
        pre = page.locator("#file-preview-body .preview-text")
        expect(pre).to_contain_text("line 0000000")
        # ... but only the first window, not the whole 2.6 MB (well under the full size).
        length = pre.evaluate("el => el.textContent.length")
        assert length < 700 * 1024, f"windowed preview rendered too much text: {length}"
        assert length > 100 * 1024, f"windowed preview rendered too little: {length}"
    finally:
        admin.delete_vault(vid)
