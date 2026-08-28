"""Image preview: fit-to-view (both skins) + isolated zoom.

Two lanes:
  * unit  — read the repo files, assert the fit/zoom rules live in the SHARED base stylesheet
            (components.css) and that app.js renders images through the zoom container. No server.
  * ui    — a real browser: upload a large image, open its preview, and prove the image is
            fit-to-view in BOTH skins (it never overflowed the modal) and that the zoom controls
            transform only the image.

Regression this guards: the v2 "Console" skin (the default) had NO .preview-media rule, so images
rendered at intrinsic pixel size and overflowed with a scrollbar; the fit rule only existed in the
v1 skin. The fix moved the rules to components.css (loaded by both skins).
"""
import base64
import struct
import zlib
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_fit_and_zoom_rules_live_in_shared_base():
    """The fit-to-view + zoom rules must be in components.css (both skins load it), NOT in a
    single skin file — that split was the original bug."""
    components = (STATIC / "css" / "components.css").read_text(encoding="utf-8")
    redesign = (STATIC / "css" / "redesign.css").read_text(encoding="utf-8")
    uiv2 = (STATIC / "css" / "ui-v2.css").read_text(encoding="utf-8")

    # object-fit: contain is what makes an oversized image fit without a scrollbar.
    assert ".preview-media" in components and "object-fit: contain" in components
    # the preview body must clip, not scroll, around the media.
    assert "#file-preview-body" in components and "overflow: hidden" in components
    # the zoom container + controls are shared too.
    assert ".preview-zoom" in components and ".preview-zoom-controls" in components
    assert "#file-preview-body.preview-has-image" in components

    # the old per-skin duplicate must be gone from redesign.css so the two skins can't diverge.
    assert "#file-preview-body { min-height: 220px; max-height: 72vh; overflow: auto" not in redesign
    # v2 never had a rule; it must still not define its own conflicting one.
    assert ".preview-media" not in uiv2


@pytest.mark.unit
def test_app_js_renders_image_through_zoom_container():
    app = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    # images go through the dedicated zoom path, distinct from pdf/video/audio.
    assert "function setupImageZoom(" in app
    assert "function buildZoomControls(" in app
    assert "preview-zoom" in app
    assert "preview-has-image" in app
    # the zoom transform is applied to the <img>, never the page/body.
    assert "img.style.transform" in app


# --------------------------------------------------------------------------- ui lane

pytest_ui = pytest.mark.ui


def _png(width: int, height: int, rgb=(200, 80, 80)) -> bytes:
    """A real, decodable solid-colour PNG. A solid image compresses to a few KB even at large
    dimensions, so we can make an image bigger than the modal cheaply."""
    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit, truecolour RGB
    row = b"\x00" + bytes(rgb) * width
    idat = zlib.compress(row * height, 6)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_image_preview(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.set_input_files(
        "#file-upload-input",
        files=[{"name": "big.png", "mimeType": "image/png", "buffer": _png(1800, 1400)}],
    )
    page.click('[data-files-view="grid"]')
    tile = page.locator("#vault-files-grid .file-tile").first
    expect(tile).to_be_visible(timeout=15000)
    tile.locator(".tile-icon").first.click()
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)
    img = page.locator("#file-preview-modal .preview-zoom img.preview-media")
    expect(img).to_be_visible(timeout=8000)
    page.wait_for_function(
        "() => { const i = document.querySelector('#file-preview-modal img.preview-media');"
        " return i && i.complete && i.naturalWidth > 0; }",
        timeout=8000,
    )
    return img


@pytest_ui
@pytest.mark.parametrize("skin", ["v2", "v1"])
def test_image_preview_fits_in_both_skins(page: Page, admin, admin_creds, skin):
    """An oversized image must fit inside the preview body in BOTH skins — no overflow, no
    scrollbar. Pre-fix, the default v2 skin rendered it at 1800px and overflowed."""
    v = admin.create_vault(name=f"prev-fit-{skin}")
    try:
        if skin == "v1":
            page.add_init_script("try{localStorage.setItem('ui','v1')}catch(e){}")
        _login(page, admin_creds["username"], admin_creds["password"])
        img = _open_image_preview(page, v["id"])

        # fit-to-view: the rendered image never exceeds the preview body box.
        body = page.locator("#file-preview-body")
        assert body.evaluate("el => getComputedStyle(el).overflowY") == "hidden"
        ib = img.bounding_box()
        bb = body.bounding_box()
        assert ib and bb
        assert ib["width"] <= bb["width"] + 1, f"image wider than body ({ib} vs {bb})"
        assert ib["height"] <= bb["height"] + 1, f"image taller than body ({ib} vs {bb})"
        # the fit is enforced by object-fit (not a lucky small image).
        assert img.evaluate("el => getComputedStyle(el).objectFit") == "contain"
    finally:
        admin.delete_vault(v["id"])


@pytest_ui
def test_zoom_controls_transform_only_the_image(page: Page, admin, admin_creds):
    v = admin.create_vault(name="prev-zoom")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        img = _open_image_preview(page, v["id"])
        controls = page.locator("#file-preview-modal .preview-zoom-controls")
        expect(controls).to_be_visible()

        # baseline: no transform, level 100%, page not scrolled by zoom
        assert (img.evaluate("el => el.style.transform") or "") == ""
        page_scroll_before = page.evaluate("() => window.scrollY")

        page.locator('#file-preview-modal .preview-zoom-controls button[aria-label="Zoom in"]').click()
        # the image now carries a scale transform; the level readout moved off 100%
        expect(page.locator("#file-preview-modal .preview-zoom-level")).not_to_have_text("100%")
        assert "scale(" in (img.evaluate("el => el.style.transform") or "")
        # zooming the preview did not scroll/zoom the page itself
        assert page.evaluate("() => window.scrollY") == page_scroll_before

        # reset returns to 100% and clears the transform
        page.locator('#file-preview-modal .preview-zoom-controls button[aria-label="Reset zoom"]').click()
        expect(page.locator("#file-preview-modal .preview-zoom-level")).to_have_text("100%")
        assert (img.evaluate("el => el.style.transform") or "") == ""
    finally:
        admin.delete_vault(v["id"])
