"""Brand asset upload tests (A4): an admin uploads a logo / favicon that is stored in a
writable volume, served from ``/brand-assets/`` with hardening headers, and pointed at by
the effective ``logo_url`` / ``favicon_url`` (via the ``SystemSetting('brand')`` row) so
``/branding`` and the rendered shell use it. Type + size are validated; a reset reverts to
the built-in default.

The upload/reset path is admin-gated; the served asset is public (branding, like /static).
Each test resets both slots so no uploaded override leaks into the next test / the live app.
"""
import base64

# a real 1x1 PNG — its first 8 bytes are the PNG signature, so it passes magic-byte
# sniffing. Kept as base64 (ASCII) so the test source carries no raw binary bytes.
_PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC"
)
# a 1x1 GIF (magic "GIF89a") to exercise the gif branch of the magic-byte sniffer.
_GIF_1x1 = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
# a HOSTILE svg (carries a <script>) — allowed by the sniffer's <svg head, but the served
# CSP + sandbox + nosniff must neutralise it so it cannot execute even on direct navigation.
_SVG_HOSTILE = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
    b'<script>window.__pwned=1</script></svg>'
)


def _reset_assets(admin) -> None:
    for slot in ("logo", "favicon"):
        try:
            admin.delete(f"/settings/brand/asset/{slot}")
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass


def test_upload_logo_serves_and_drives_branding(admin, anon):
    """Upload a logo -> it serves publicly with hardening headers and the exact bytes, and
    every logo slot in /branding points at it; reset reverts to the built-in default."""
    _reset_assets(admin)
    try:
        r = admin.post("/settings/brand/asset/logo",
                       files={"file": ("logo.png", _PNG_1x1, "image/png")})
        assert r.status_code == 200, r.text
        url = r.json()["url"]
        assert url.startswith("/brand-assets/logo."), url

        b = anon.get("/branding").json()
        assert b["logo_url"] == url
        assert b["assets"]["logo"] == url
        assert b["assets"]["logo_small"] == url  # one upload drives all logo slots

        a = anon.get(url)
        assert a.status_code == 200
        assert a.content == _PNG_1x1
        assert a.headers.get("content-type") == "image/png"
        assert a.headers.get("x-content-type-options") == "nosniff"
        assert "sandbox" in (a.headers.get("content-security-policy") or "")

        assert admin.delete("/settings/brand/asset/logo").status_code == 200
        b2 = anon.get("/branding").json()
        assert b2["logo_url"] == "/static/assets/logo.png"   # env default restored
        assert b2["logo_url"] != url
    finally:
        _reset_assets(admin)


def test_upload_favicon_drives_branding(admin, anon):
    _reset_assets(admin)
    try:
        r = admin.post("/settings/brand/asset/favicon",
                       files={"file": ("fav.png", _PNG_1x1, "image/png")})
        assert r.status_code == 200, r.text
        url = r.json()["url"]
        assert url.startswith("/brand-assets/favicon.")
        assert anon.get("/branding").json()["assets"]["favicon"] == url
    finally:
        _reset_assets(admin)


def test_upload_svg_served_sandboxed(admin, anon):
    """SVG is allowed (sniffed by its <svg/<?xml head), but MUST be served with nosniff +
    a locked-down CSP/sandbox so an uploaded <script> cannot execute even on direct
    navigation to the asset URL — the stored-XSS mitigation."""
    _reset_assets(admin)
    try:
        r = admin.post("/settings/brand/asset/logo",
                       files={"file": ("logo.svg", _SVG_HOSTILE, "image/svg+xml")})
        assert r.status_code == 200, r.text
        url = r.json()["url"]
        assert url.endswith(".svg"), url
        a = anon.get(url)
        assert a.status_code == 200
        assert a.headers.get("content-type") == "image/svg+xml"
        csp = a.headers.get("content-security-policy") or ""
        assert "sandbox" in csp and "default-src 'none'" in csp, f"CSP not locked down: {csp!r}"
        assert a.headers.get("x-content-type-options") == "nosniff"
    finally:
        _reset_assets(admin)


def test_upload_gif_accepted(admin, anon):
    """The gif branch of the magic-byte sniffer accepts a real GIF."""
    _reset_assets(admin)
    try:
        r = admin.post("/settings/brand/asset/logo",
                       files={"file": ("logo.gif", _GIF_1x1, "image/gif")})
        assert r.status_code == 200, r.text
        assert r.json()["url"].endswith(".gif")
        assert anon.get("/branding").json()["logo_url"].endswith(".gif")
    finally:
        _reset_assets(admin)


def test_upload_rejects_non_image(admin):
    """A payload with no image magic bytes is rejected (sniffed by content, not name/type)."""
    r = admin.post("/settings/brand/asset/logo",
                   files={"file": ("logo.png", b"this is definitely not an image", "image/png")})
    assert r.status_code == 400, r.text


def test_upload_rejects_oversize(admin):
    """Over the 2 MB cap -> 413 (rejected on the size check before sniffing)."""
    big = b"0" * (2 * 1024 * 1024 + 16)
    r = admin.post("/settings/brand/asset/logo",
                   files={"file": ("big.png", big, "image/png")})
    assert r.status_code == 413, r.text


def test_upload_unknown_slot_rejected(admin):
    r = admin.post("/settings/brand/asset/banner",
                   files={"file": ("x.png", _PNG_1x1, "image/png")})
    assert r.status_code == 404, r.text


def test_upload_requires_admin(anon):
    r = anon.post("/settings/brand/asset/logo",
                  files={"file": ("x.png", _PNG_1x1, "image/png")})
    assert r.status_code in (401, 403), r.status_code


def test_brand_asset_missing_returns_404(anon):
    assert anon.get("/brand-assets/does-not-exist.png").status_code == 404


def test_brand_asset_name_allow_list_rejected_at_handler(anon):
    """The get_brand_asset allow-list rejects disallowed single-segment names. These names
    survive routing (no literal '/', so they stay ONE path segment and match {name}), so
    they REACH the handler — proven by the handler-origin 404 body "Not found" (lowercase),
    which is distinct from Starlette's router-default "Not Found" (capital F). A '..'/space/
    backslash/control char must be rejected by _is_safe_asset_name -> 404, never served."""
    for name in ("logo..png", "a b.png", "..%5capi_server.py", "%2e%2e%5cmodels.py"):
        r = anon.get(f"/brand-assets/{name}")
        assert r.status_code == 404, f"{name} -> {r.status_code} {r.text[:120]}"
        assert r.json().get("detail") == "Not found", \
            f"{name} was blocked by the router, not the handler allow-list: {r.text[:120]}"


def test_brand_asset_encoded_slash_traversal_blocked(anon):
    """Encoded-slash traversal (%2f) is decoded to a multi-segment path that fails to match
    the single-segment route and 404s at the router — either way, no source file is served."""
    for name in ("..%2fapi_server.py", "%2e%2e%2f%2e%2e%2fapi_server.py", "logo%2f..%2fmodels.py"):
        r = anon.get(f"/brand-assets/{name}")
        assert r.status_code == 404, f"{name} -> {r.status_code}"
        assert "def " not in r.text and "import " not in r.text  # never leaked a source file
