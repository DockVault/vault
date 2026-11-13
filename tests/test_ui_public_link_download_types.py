"""UI: a public file link's download, named by a page of the vault's own origin, runs nothing there.

A public file link's download address needs no sign-in, so a page can name it as the source of a script. The
stored MIME type of a file is whatever its uploader claimed, and the vault's pages take their scripts from this
origin only: a download answered under a script's type would run as one of them. These tests store a file as
JavaScript, make a public link to it, and have a page of this origin load the download address as a script, the
way markup on that page would. A control first shows that the same page does run a script it loads from this
origin, so a pass means the download's answer cannot be run, not that the page refused everything.

They also check what must not change: the link page's own Download still saves such a file, under its own name,
with every byte.

The rule, its type table and the headers of the answer are the unit lane (``test_download_answer_types.py``);
``test_api_public_links_native.py`` reads the same headers from a running deployment.
"""
import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

MARK = "__ran_from_a_download"
SCRIPT = f"window.{MARK} = true;\n".encode()
PAGE = (b'<html xmlns="http://www.w3.org/1999/xhtml"><head><title>quiet</title></head>'
        b"<body><script>document.title = 'SCRIPT-RAN';</script></body></html>")

LOAD_AS_A_SCRIPT = """(src) => new Promise((resolve) => {
    const script = document.createElement('script');
    script.onload = () => resolve('ran');
    script.onerror = () => resolve('refused');
    script.src = src;
    document.head.appendChild(script);
})"""


@pytest.fixture
def files_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    r = admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def vault(admin):
    v = admin.create_vault(name=unique("dltype"))
    yield v
    admin.delete_vault(v["id"])


def _stored(admin, vault_id, name, content, mime):
    """Upload one file under the type its uploader claims, and return its id."""
    r = admin.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, mime))])
    assert r.status_code in (200, 201), r.text
    item = next(it for it in admin.get(f"/vaults/{vault_id}/files").json()["items"] if it.get("name") == name)
    assert item["mime_type"] == mime, "the file was not stored under the type it was uploaded with"
    return item["id"]


def _link(admin, vault_id, file_id, cap=2):
    tag = admin.post("/note-link-tags", json={
        "name": unique("dltag"), "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "require_secret": "none", "max_uses_cap": cap})
    assert tag.status_code in (200, 201), tag.text
    link = admin.post("/public-links", json={"vault_id": vault_id, "target_type": "file", "target_file_id": file_id,
                                             "tag_id": tag.json()["id"], "ttl_hours": 1, "max_uses": cap})
    assert link.status_code == 200, link.text
    return link.json()


def _grant(base_url, link):
    r = requests.post(f"{base_url}/public-links/{link['token']}/redeem", json={}, timeout=30)
    assert r.status_code == 200, r.text
    return r.json()["grant"]


def test_a_download_stored_as_a_script_does_not_run_when_a_page_of_this_origin_loads_it(
        page: Page, admin, base_url, files_enabled, vault):
    name = unique("code") + ".js"
    file_id = _stored(admin, vault["id"], name, SCRIPT, "text/javascript")
    link = _link(admin, vault["id"], file_id)

    # A page of the vault's own origin, under the policy every page of it has: scripts from this origin only.
    page.goto(f"/p/{link['token']}")
    expect(page.locator("#listing button")).to_have_text("Download", timeout=15000)
    policy = requests.get(f"{base_url}/p/{link['token']}", timeout=30).headers["Content-Security-Policy"]
    assert "script-src 'self'" in policy

    # The control: this page does run a script it loads from this origin.
    assert page.evaluate("() => typeof TransferGate") == "undefined"
    assert page.evaluate(LOAD_AS_A_SCRIPT, "/static/js/transfer_gate.js") == "ran"
    assert page.evaluate("() => typeof TransferGate") == "function", "control: the page ran no script of this origin"

    # The download's own address, with a grant no one has used: the browser fetches it and refuses to run it.
    address = f"/public-links/{link['token']}/download/{file_id}?grant={_grant(base_url, link)}"
    seen = []
    page.on("response", lambda response: seen.append(response) if "/download/" in response.url else None)
    assert page.evaluate(LOAD_AS_A_SCRIPT, address) == "refused"
    assert page.evaluate(f"() => window.{MARK}") is None, "the stored file ran as a script of the vault's origin"
    # It was this answer the browser refused, not a missing file: the server sent the file, as plain bytes.
    [answer] = seen
    assert answer.status == 200
    headers = answer.all_headers()
    assert headers["content-type"] == "application/octet-stream"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert headers["content-disposition"].startswith("attachment;")


@pytest.mark.parametrize("name, mime, content", [
    ("page.xhtml", "application/xhtml+xml", PAGE),
    ("code.js", "text/javascript", SCRIPT),
], ids=["stored-as-a-page", "stored-as-a-script"])
def test_the_link_pages_own_download_still_saves_such_a_file(page: Page, admin, base_url, files_enabled, vault,
                                                             tmp_path, name, mime, content):
    name = unique("kept") + "-" + name
    file_id = _stored(admin, vault["id"], name, content, mime)
    link = _link(admin, vault["id"], file_id)
    page.goto(f"/p/{link['token']}")
    expect(page.locator("#listing button")).to_have_text("Download", timeout=15000)
    with page.expect_download(timeout=30000) as info:
        page.click("#listing button")
    download = info.value
    saved = tmp_path / "saved.bin"
    download.save_as(saved)
    assert download.failure() is None
    assert download.suggested_filename == name
    assert saved.read_bytes() == content
    # The page that started it is still the link page: the file was saved, not opened in its place.
    assert page.url.endswith(f"/p/{link['token']}")
    assert page.title() != "SCRIPT-RAN"
