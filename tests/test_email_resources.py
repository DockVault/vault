"""Email Studio — the private image resource folder.

Admin-only. Images are stored as bytes in the DB, keyed by UUID; the content type is decided by
SNIFFING the magic bytes (never the client's Content-Type); only raster formats are accepted (no
SVG). The byte-serving route is admin-gated and used by the editor preview, which now resolves a
real uploaded image (a dangling / deleted reference is dropped).
"""

import base64
import re

import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_UUID = "11111111-1111-1111-1111-111111111111"

# Minimal byte payloads whose MAGIC bytes identify the format (content is opaque to the vault).
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
GIF = b"GIF89a" + b"\x00" * 32
JPEG = b"\xff\xd8\xff" + b"\x00" * 32
WEBP = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 24
NOT_IMAGE = b"%PDF-1.4\nnot an image\n"


def _delete_all_resources(admin):
    for r in admin.get("/email/resources").json().get("resources", []):
        admin.delete(f"/email/resources/{r['id']}")


@pytest.fixture
def clean_resources(admin):
    _delete_all_resources(admin)
    yield
    _delete_all_resources(admin)


def _upload(client, data, filename="pic.png", content_type="application/octet-stream"):
    return client.post("/email/resources", files={"file": (filename, data, content_type)})


# -- upload / sniff ----------------------------------------------------------------------------

@pytest.mark.parametrize("data,ct", [(PNG, "image/png"), (GIF, "image/gif"),
                                     (JPEG, "image/jpeg"), (WEBP, "image/webp")])
def test_upload_accepts_supported_images(admin, clean_resources, data, ct):
    r = _upload(admin, data)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["content_type"] == ct              # type comes from the bytes, not the request
    assert body["byte_size"] == len(data)
    assert "data" not in body                       # never echoes the bytes


def test_upload_content_type_is_sniffed_not_trusted(admin, clean_resources):
    # PNG bytes with a lying text/plain content-type -> accepted as image/png.
    r = _upload(admin, PNG, filename="x.txt", content_type="text/plain")
    assert r.status_code == 201 and r.json()["content_type"] == "image/png"
    # HTML bytes with a lying image/png content-type -> rejected (sniff wins).
    r2 = _upload(admin, b"<html><script>x</script></html>", filename="x.png", content_type="image/png")
    assert r2.status_code == 400


def test_upload_rejects_non_image(admin, clean_resources):
    assert _upload(admin, NOT_IMAGE).status_code == 400


def test_upload_accepts_gif87a(admin, clean_resources):
    r = _upload(admin, b"GIF87a" + b"\x00" * 32)
    assert r.status_code == 201 and r.json()["content_type"] == "image/gif"


@pytest.mark.parametrize("truncated", [b"\x89PN", b"GIF8", b"RIFF\x00\x00\x00\x00WEB"])
def test_upload_rejects_truncated_magic(admin, clean_resources, truncated):
    # startswith / the len>=12 WebP guard must not misclassify a partial header as an image.
    assert _upload(admin, truncated).status_code == 400


def test_polyglot_is_served_as_image_with_nosniff(admin, clean_resources):
    # THE security keystone: a script-bearing GIF is accepted (sniff only reads the prefix) but is
    # served with the sniffed image content-type + nosniff, so a browser can't render it as HTML.
    poly = b"GIF89a" + b"<html><script>alert(1)</script></html>" + b"\x00" * 8
    up = _upload(admin, poly).json()
    assert up["content_type"] == "image/gif"
    r = admin.get(f"/email/resources/{up['id']}")
    assert r.content == poly                                    # exact bytes
    assert r.headers.get("content-type", "").startswith("image/gif")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("content-disposition") == "inline"


def test_upload_accepts_exactly_at_limit(admin, clean_resources):
    at_limit = b"\x89PNG\r\n\x1a\n" + b"\x00" * (5 * 1024 * 1024 - len(b"\x89PNG\r\n\x1a\n"))
    assert len(at_limit) == 5 * 1024 * 1024
    assert _upload(admin, at_limit).status_code == 201


def test_upload_rejects_empty(admin, clean_resources):
    assert _upload(admin, b"").status_code == 400


def test_upload_rejects_oversize(admin, clean_resources):
    big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (5 * 1024 * 1024 + 1)   # > 5 MB
    assert _upload(admin, big).status_code == 413


def test_upload_sanitizes_filename(admin, clean_resources):
    r = _upload(admin, PNG, filename="../../etc/passwd\x00.png")
    assert r.status_code == 201
    assert "/" not in r.json()["filename"] and "\x00" not in r.json()["filename"]


# -- list / serve / delete ---------------------------------------------------------------------

def test_list_is_metadata_only_newest_first(admin, clean_resources):
    a = _upload(admin, PNG).json()
    b = _upload(admin, GIF).json()
    rows = admin.get("/email/resources").json()["resources"]
    ids = [x["id"] for x in rows]
    assert ids[0] == b["id"] and ids[1] == a["id"]   # newest first
    assert all("data" not in row and "sha256" not in row for row in rows)


def test_duplicate_bytes_make_two_distinct_rows(admin, clean_resources):
    a = _upload(admin, PNG).json()
    b = _upload(admin, PNG).json()
    assert a["id"] != b["id"]                          # no dedup, no 500
    assert admin.get(f"/email/resources/{a['id']}").content == PNG
    assert admin.get(f"/email/resources/{b['id']}").content == PNG


def test_serve_returns_the_exact_bytes_with_headers(admin, clean_resources):
    up = _upload(admin, PNG).json()
    r = admin.get(f"/email/resources/{up['id']}")
    assert r.status_code == 200
    assert r.content == PNG                          # exact bytes round-trip
    assert r.headers.get("content-type", "").startswith("image/png")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("content-disposition") == "inline"
    cc = r.headers.get("cache-control", "")
    assert "private" in cc and "no-store" in cc      # admin image is never publicly cacheable


def test_serve_is_admin_gated(admin, clean_resources):
    up = _upload(admin, PNG).json()
    # non-admin
    u = admin.create_user(role="user")
    cu = admin.clone_anonymous()
    cu.login(u["_username"], u["_password"])
    # unauthenticated
    anon = admin.clone_anonymous()
    try:
        assert cu.get(f"/email/resources/{up['id']}").status_code == 403
        assert anon.get(f"/email/resources/{up['id']}").status_code in (401, 403)
    finally:
        admin.delete_user(u["id"])


def test_delete_removes_and_then_404(admin, clean_resources):
    up = _upload(admin, PNG).json()
    assert admin.delete(f"/email/resources/{up['id']}").status_code == 204
    assert admin.get(f"/email/resources/{up['id']}").status_code == 404


def test_upload_delete_require_interactive_admin(admin, clean_resources):
    up = _upload(admin, PNG).json()
    tc = admin.post("/auth/temp-credentials", json={"note": unique("r")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    assert _upload(ct, PNG).status_code == 403
    assert ct.delete(f"/email/resources/{up['id']}").status_code == 403
    assert ct.get("/email/resources").status_code == 403
    assert ct.get(f"/email/resources/{up['id']}").status_code == 403   # serve is gated too


def test_unauthenticated_upload_and_delete_rejected(admin, clean_resources):
    up = _upload(admin, PNG).json()
    anon = admin.clone_anonymous()
    assert _upload(anon, PNG).status_code in (401, 403)
    assert anon.delete(f"/email/resources/{up['id']}").status_code in (401, 403)


# -- template/preview integration --------------------------------------------------------------

def test_preview_resolves_a_real_uploaded_image(admin, clean_resources):
    up = _upload(admin, PNG).json()
    rid = up["id"]
    r = admin.post("/email/templates/preview",
                   json={"body_html": f'<p>hi</p><img data-resource-id="{rid}">'})
    assert r.status_code == 200, r.text
    html = r.json()["html"]
    # The preview INLINES the bytes as a data: URI so the sandboxed (opaque-origin) iframe can render
    # them without authenticating to the admin-gated byte route. The location is never a URL/path.
    assert 'src="data:image/png;base64,' in html
    assert "/email/resources/" not in html
    assert rid not in html                                       # the UUID location is not disclosed
    # The inlined payload must be THE uploaded bytes (not empty / a wrong row).
    m = re.search(r'src="data:image/png;base64,([^"]+)"', html)
    assert m, html
    assert base64.b64decode(m.group(1)) == PNG
    assert rid in r.json()["referenced_resource_ids"]


def test_preview_drops_a_deleted_image_reference(admin, clean_resources):
    up = _upload(admin, PNG).json()
    rid = up["id"]
    admin.delete(f"/email/resources/{rid}")
    r = admin.post("/email/templates/preview",
                   json={"body_html": f'<img data-resource-id="{rid}">'})
    assert r.status_code == 200
    assert f"/email/resources/{rid}" not in r.json()["html"]     # dangling -> dropped
    assert "<img" not in r.json()["html"]


def test_preview_drops_nonexistent_resource(admin, clean_resources):
    r = admin.post("/email/templates/preview",
                   json={"body_html": f'<img data-resource-id="{_UUID}">'})
    assert r.status_code == 200
    assert _UUID not in r.json()["html"]


def test_saved_template_retains_resource_ref_even_after_delete(admin, clean_resources):
    # Storage retains the data-resource-id; only serve/preview stop resolving a deleted resource.
    up = _upload(admin, PNG).json()
    rid = up["id"]
    t = admin.post("/email/templates", json={"name": unique("t"), "subject": "s",
                                             "body_html": f'<img data-resource-id="{rid}">'}).json()
    try:
        got = admin.get(f"/email/templates/{t['id']}").json()
        assert rid in got["referenced_resource_ids"]
        assert f'data-resource-id="{rid}"' in got["body_html"]
        admin.delete(f"/email/resources/{rid}")
        got2 = admin.get(f"/email/templates/{t['id']}").json()
        assert f'data-resource-id="{rid}"' in got2["body_html"]      # reference persists in storage
        assert rid in got2["referenced_resource_ids"]
    finally:
        admin.delete(f"/email/templates/{t['id']}")
