"""Live API: the download address the link page hands the browser, with its grant in the query.

The page's Download is an ordinary GET of /public-links/{token}/download/{file_id}?grant=<grant>, which
the browser saves itself. A prefetch or preview of that address (one that says so) must spend nothing
and leave the grant to the person's own request; the address and the page it is started from send at
most the origin in a Referer; a refusal is a page a browser can show; and the X-Download-Grant header
an API client sends still works as before. The address needs no sign-in, so another page can name it:
whatever type the file was stored with, the answer is an attachment under a type no browser runs.
tests/test_ui_public_link_native_download.py and tests/test_ui_public_link_download_types.py check the
same in a browser.
"""
import os
import time

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration


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
    v = admin.create_vault(name=unique("nativeapi"))
    yield v
    admin.delete_vault(v["id"])


def _file(admin, vault_id, content):
    name = unique("native") + ".pdf"
    r = admin.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, "application/pdf"))])
    assert r.status_code in (200, 201), r.text
    return next(it["id"] for it in admin.get(f"/vaults/{vault_id}/files").json()["items"] if it.get("name") == name)


def _link(admin, vault_id, file_id, cap=2):
    tag = admin.post("/note-link-tags", json={
        "name": unique("natag"), "min_token_len": 20, "auto_enroll_new_users": True,
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


def _card(admin, link_id, downloads=None):
    deadline = time.monotonic() + 15
    while True:
        card = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link_id)
        if downloads is None or card["download_count"] >= downloads or time.monotonic() > deadline:
            return card
        time.sleep(0.2)


@pytest.mark.parametrize("ahead", [{"Sec-Purpose": "prefetch"}, {"Sec-Purpose": "prefetch;prerender"},
                                   {"Purpose": "prefetch"}, {"X-Moz": "prefetch"}, {"X-Purpose": "preview"}])
def test_a_prefetch_of_the_download_spends_nothing_and_leaves_the_grant_to_its_click(
        admin, base_url, files_enabled, vault, ahead):
    content = os.urandom(20_000)
    file_id = _file(admin, vault["id"], content)
    link = _link(admin, vault["id"], file_id)
    address = f"{base_url}/public-links/{link['token']}/download/{file_id}?grant={_grant(base_url, link)}"
    early = requests.get(address, headers=ahead, timeout=30)
    assert early.status_code == 404 and content[:64] not in early.content
    got = requests.get(address, timeout=30)
    assert got.status_code == 200 and got.content == content
    card = _card(admin, link["id"], downloads=1)
    assert (card["use_count"], card["download_count"]) == (1, 1), card


def test_the_query_address_downloads_as_an_attachment_once(admin, base_url, files_enabled, vault):
    content = os.urandom(50_000)
    file_id = _file(admin, vault["id"], content)
    link = _link(admin, vault["id"], file_id)
    address = f"{base_url}/public-links/{link['token']}/download/{file_id}?grant={_grant(base_url, link)}"
    got = requests.get(address, timeout=30)
    assert got.status_code == 200 and got.content == content
    assert got.headers["Content-Disposition"].startswith("attachment;")
    assert got.headers["Referrer-Policy"] == "strict-origin"
    again = requests.get(address, timeout=30)
    assert again.status_code == 404
    assert again.headers["content-type"].startswith("text/html")
    assert "<title>This file could not be downloaded</title>" in again.text
    assert content[:64] not in again.content
    assert _card(admin, link["id"], downloads=1)["download_count"] == 1


def test_the_header_form_still_answers_in_json(admin, base_url, files_enabled, vault):
    content = os.urandom(10_000)
    file_id = _file(admin, vault["id"], content)
    link = _link(admin, vault["id"], file_id)
    grant = _grant(base_url, link)
    url = f"{base_url}/public-links/{link['token']}/download/{file_id}"
    got = requests.get(url, headers={"X-Download-Grant": grant}, timeout=30)
    assert got.status_code == 200 and got.content == content
    again = requests.get(url, headers={"X-Download-Grant": grant}, timeout=30)
    assert again.status_code == 404 and again.json() == {"detail": "This file is not available."}


def _stored(admin, vault_id, name, content, mime):
    """Upload one file under the type its uploader claims, and return its id."""
    r = admin.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, mime))])
    assert r.status_code in (200, 201), r.text
    item = next(it for it in admin.get(f"/vaults/{vault_id}/files").json()["items"] if it.get("name") == name)
    assert item["mime_type"] == mime, "the file was not stored under the type it was uploaded with"
    return item["id"]


@pytest.mark.parametrize("name, stored, sent", [
    # a type a browser runs, or applies to the page that names it: sent as plain bytes
    ("code.js", "text/javascript", "application/octet-stream"),
    ("code.mjs", "application/javascript", "application/octet-stream"),
    ("look.css", "text/css", "application/octet-stream"),
    ("page.html", "text/html", "application/octet-stream"),
    ("page.xhtml", "application/xhtml+xml", "application/octet-stream"),
    ("drawing.svg", "image/svg+xml", "application/octet-stream"),
    ("module.wasm", "application/wasm", "application/octet-stream"),
    # any other type: as it was stored
    ("contract.pdf", "application/pdf", "application/pdf"),
    ("data.json", "application/json", "application/json"),
])
def test_a_download_is_never_answered_under_a_type_a_browser_runs(admin, base_url, files_enabled, vault, name,
                                                                  stored, sent):
    """The download address needs no sign-in, so any page can name it. Whatever type the file was stored with,
    both ways of presenting the grant answer with an attachment that no browser runs: plain bytes where the
    stored type is one it would, sniffing off, and a policy under which nothing runs."""
    content = b"window.ran = true;\n" + os.urandom(64)
    name = unique("typed") + "-" + name
    file_id = _stored(admin, vault["id"], name, content, stored)
    link = _link(admin, vault["id"], file_id)
    url = f"{base_url}/public-links/{link['token']}/download/{file_id}"
    by_query = requests.get(f"{url}?grant={_grant(base_url, link)}", timeout=30)
    by_header = requests.get(url, headers={"X-Download-Grant": _grant(base_url, link)}, timeout=30)
    for got in (by_query, by_header):
        assert got.status_code == 200 and got.content == content
        assert got.headers["Content-Type"] == sent
        saved_as = got.headers["Content-Disposition"]
        assert saved_as.startswith("attachment;") and name in saved_as
        assert got.headers["X-Content-Type-Options"] == "nosniff"
        assert got.headers.get("Content-Security-Policy") == "default-src 'none'; sandbox"


def test_the_link_page_sends_the_origin_alone_and_other_pages_keep_the_default(admin, base_url, files_enabled,
                                                                              vault):
    link = _link(admin, vault["id"], _file(admin, vault["id"], os.urandom(5_000)))
    assert requests.get(f"{base_url}/p/{link['token']}", timeout=30).headers["Referrer-Policy"] == "strict-origin"
    redeemed = requests.post(f"{base_url}/public-links/{link['token']}/redeem", json={"peek": True}, timeout=30)
    assert redeemed.headers["Referrer-Policy"] == "strict-origin"
    for path in ("/", "/recording", "/public-link-policy"):
        assert requests.get(f"{base_url}{path}", timeout=30).headers["Referrer-Policy"] == \
            "strict-origin-when-cross-origin", path
