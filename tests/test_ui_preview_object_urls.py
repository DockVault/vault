"""UI: a previewed file's address, opened in a tab of its own, runs nothing with this vault's origin.

The stored MIME type of a file is whatever the uploading browser claimed. The preview shows images,
video and audio from an object URL, and an object URL opened as a page of its own runs with the
vault's origin and none of the page's Content-Security-Policy. These tests upload pictures whose
stored type is a scriptable one, open the preview, then open the preview's own address in a new
tab, the way a person who copies the image address would.

The type rule and the source pins are the unit lane (``test_preview_object_url_types.py``).
"""
import struct
import zlib

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

RAN = "SCRIPT-RAN"
XHTML = (f'<html xmlns="http://www.w3.org/1999/xhtml"><head><title>quiet</title></head>'
         f"<body><script>document.title = '{RAN}';</script></body></html>").encode()
SVG = (f'<svg xmlns="http://www.w3.org/2000/svg" width="40" height="30">'
       f"<script>document.title = '{RAN}';</script>"
       f'<rect width="40" height="30" fill="#3a6"/></svg>').encode()


def _png() -> bytes:
    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 4, 3, 8, 2, 0, 0, 0)
    idat = zlib.compress((b"\x00" + bytes((200, 80, 80)) * 4) * 3, 6)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _preview_image(page: Page, vault_id: str, name: str, mime: str, content: bytes) -> str:
    """Upload one file, open its preview, and return the preview image's address."""
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.set_input_files("#file-upload-input", files=[{"name": name, "mimeType": mime, "buffer": content}])
    page.click('[data-files-view="grid"]')
    tile = page.locator("#vault-files-grid .file-tile").first
    expect(tile).to_be_visible(timeout=15000)
    tile.locator(".tile-icon").first.click()
    img = page.locator("#file-preview-modal img.preview-media")
    expect(img).to_be_visible(timeout=8000)
    return img.get_attribute("src") or ""


def _open_alone(page: Page, address: str):
    """Open an address in a new tab of the same browser, as a person pasting it would. Returns the
    tab, or None when the browser refuses to open it at all (which is as safe)."""
    tab = page.context.new_page()
    try:
        tab.goto(address, wait_until="load", timeout=10000)
    except Exception:
        tab.close()
        return None
    tab.wait_for_timeout(500)
    return tab


def test_a_picture_still_previews_under_its_own_type(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("prvtype"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        src = _preview_image(page, v["id"], unique("pic") + ".png", "image/png", _png())
        assert src.startswith("blob:"), src
        page.wait_for_function("() => { const i = document.querySelector('#file-preview-modal img.preview-media');"
                               " return i && i.complete && i.naturalWidth === 4; }", timeout=8000)
        assert page.evaluate("async (u) => (await (await fetch(u)).blob()).type", src) == "image/png"
    finally:
        admin.delete_vault(v["id"])


def test_a_page_stored_as_a_picture_does_not_run_when_its_address_is_opened(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("prvxhtml"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        src = _preview_image(page, v["id"], unique("pic") + ".png", "application/xhtml+xml", XHTML)
        assert src.startswith("blob:"), src
        # The object URL carries a picture's type, not the stored one.
        assert page.evaluate("async (u) => (await (await fetch(u)).blob()).type", src) == "image/png"
        tab = _open_alone(page, src)
        if tab is not None:
            try:
                assert tab.title() != RAN, "the stored page ran with the vault's origin"
            finally:
                tab.close()
    finally:
        admin.delete_vault(v["id"])


def test_an_svg_previews_from_a_data_address_that_cannot_reach_the_sign_in(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("prvsvg"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        src = _preview_image(page, v["id"], unique("chart") + ".svg", "image/svg+xml", SVG)
        assert src.startswith("data:image/svg+xml"), src[:40]
        # The drawing still shows, and its script does not run inside the page.
        page.wait_for_function("() => { const i = document.querySelector('#file-preview-modal img.preview-media');"
                               " return i && i.complete && i.naturalWidth === 40; }", timeout=8000)
        assert page.title() != RAN
        tab = _open_alone(page, src)
        if tab is not None:
            try:
                # Whatever runs there runs in an opaque origin: no storage of this vault, no token.
                assert tab.evaluate("() => location.origin") == "null"
                token = tab.evaluate("() => { try { return String(localStorage.getItem('authToken'))"
                                     " + String(sessionStorage.getItem('authToken')); }"
                                     " catch (e) { return 'denied'; } }")
                assert token == "denied", token
            finally:
                tab.close()
    finally:
        admin.delete_vault(v["id"])
