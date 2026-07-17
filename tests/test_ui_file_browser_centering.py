"""The file-browser placeholder + grid text must be horizontally centered.

A shared `p { max-width: 70ch }` base rule left the empty-state subtext and the no-preview
fallback lines anchored to the left of their centered containers, and the grid tile name
inherited `display:flex` (so `text-align:center` had no effect). These assert the fix in the
default (Console) skin: the placeholder paragraphs sit on their container's centre line, and the
grid name renders as a centred block with working ellipsis.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _center_x(page: Page, selector: str) -> float:
    return page.evaluate(
        """(sel) => { const el = document.querySelector(sel);
            const r = el.getBoundingClientRect(); return r.left + r.width / 2; }""",
        selector,
    )


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


def test_empty_state_subtext_is_centered(page: Page, admin, admin_creds):
    v = admin.create_vault(name="center-empty")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        page.click('[data-files-view="grid"]')
        empty = page.locator("#vault-files-grid .empty-state")
        expect(empty).to_be_visible(timeout=8000)
        # the subtext paragraph must sit on the container's centre line, not left of it
        pc = _center_x(page, "#vault-files-grid .empty-state p:last-of-type")
        cc = _center_x(page, "#vault-files-grid .empty-state")
        assert abs(pc - cc) <= 2, f"empty-state subtext not centered: p={pc} container={cc}"
    finally:
        admin.delete_vault(v["id"])


def test_grid_tile_name_centered_block(page: Page, admin, admin_creds):
    v = admin.create_vault(name="center-grid")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        page.set_input_files(
            "#file-upload-input",
            files=[{"name": "a-name-long-enough-to-need-ellipsis.bin",
                    "mimeType": "application/octet-stream", "buffer": b"x" * 32}],
        )
        page.click('[data-files-view="grid"]')
        name = page.locator("#vault-files-grid .file-tile .tile-name").first
        expect(name).to_be_visible(timeout=10000)
        style = name.evaluate(
            "el => ({ display: getComputedStyle(el).display, textAlign: getComputedStyle(el).textAlign })"
        )
        assert style["display"] == "block", style   # was flex (inherited) -> text-align couldn't center
        assert style["textAlign"] == "center", style
        # functional check that block+overflow actually clip the long name (the inherited flex
        # context made text-overflow:ellipsis inert); a truncated block has scrollWidth > clientWidth
        assert name.evaluate("el => el.scrollWidth > el.clientWidth"), "long grid name not truncated"
        nc = name.evaluate("el => { const r = el.getBoundingClientRect(); return r.left + r.width/2; }")
        tc = name.evaluate(
            "el => { const t = el.closest('.file-tile'); const r = t.getBoundingClientRect(); return r.left + r.width/2; }"
        )
        assert abs(nc - tc) <= 2, f"tile name not centered in tile: name={nc} tile={tc}"
    finally:
        admin.delete_vault(v["id"])


def test_preview_fallback_text_centered(page: Page, admin, admin_creds):
    v = admin.create_vault(name="center-preview")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        page.set_input_files(
            "#file-upload-input",
            files=[{"name": "no-preview.bin", "mimeType": "application/octet-stream", "buffer": b"y" * 16}],
        )
        # open the file preview (name label is the click target in either view)
        name = page.locator(".file-name[data-file-id]").first
        expect(name).to_be_visible(timeout=10000)
        name.click()
        none = page.locator("#file-preview-body .preview-none")
        expect(none).to_be_visible(timeout=8000)
        for line in ("p.mt-sm", "p.text-sm"):
            pc = _center_x(page, f"#file-preview-body .preview-none {line}")
            cc = _center_x(page, "#file-preview-body .preview-none")
            assert abs(pc - cc) <= 2, f"preview {line} not centered: p={pc} container={cc}"
    finally:
        admin.delete_vault(v["id"])
