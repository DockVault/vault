"""UI — a public file link's Download is the browser's own download, in a real browser.

The recipient opens the link, gives its password, and clicks Download. The file must arrive through
the browser's own download (a navigation it saves, not a fetch the page turns into a blob), with the
exact bytes, for a small file and for one over 100 MB; the page must never hold it. The grant that
download used must not work again, the address it rode in must not reach the server's logs, and the
page's own requests must carry no more than the origin in a Referer. Nothing a prefetch or a link
preview does may spend a use.
"""
import hashlib
import os
import subprocess
import time
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

PASSWORD = "Recipient-Pass9"
MB = 1024 * 1024
_OCTET = {"Content-Type": "application/octet-stream"}
_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    result = subprocess.run(["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
                             "-tAc", sql], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


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
    v = admin.create_vault(name=unique("native"))
    yield v
    admin.delete_vault(v["id"])


def _upload(admin, vault_id, name, content, chunk_size=5 * MB):
    total = max(1, (len(content) + chunk_size - 1) // chunk_size)
    init = admin.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content), "total_chunks": total, "chunk_size": chunk_size,
        "mime_type": "application/pdf"})
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    for i in range(total):
        r = admin.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}",
                      data=content[i * chunk_size:(i + 1) * chunk_size], headers=_OCTET)
        assert r.status_code == 200, r.text
    done = admin.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    return done.json()["id"]


def _link(admin, vault_id, file_id, cap=1, password=PASSWORD):
    tag = admin.post("/note-link-tags", json={
        "name": unique("natag"), "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "require_secret": "password" if password else "none", "password_min_len": 8,
        "password_require_alnum": True, "max_uses_cap": cap})
    assert tag.status_code in (200, 201), tag.text
    body = {"vault_id": vault_id, "target_type": "file", "target_file_id": file_id,
            "tag_id": tag.json()["id"], "ttl_hours": 1, "max_uses": cap}
    if password:
        body.update(password=password, secret_kind="password")
    link = admin.post("/public-links", json=body)
    assert link.status_code == 200, link.text
    return link.json()


def _card(admin, link_id, downloads=None):
    deadline = time.monotonic() + 15
    while True:
        card = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link_id)
        if downloads is None or card["download_count"] >= downloads or time.monotonic() > deadline:
            return card
        time.sleep(0.2)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(MB), b""):
            h.update(block)
    return h.hexdigest()


def _download_in_the_browser(page, link, tmp_path, timeout=30000):
    """Open the link, unlock it, click Download, and return (the saved path, the download's request, every
    request the page made)."""
    seen = []
    page.on("request", lambda req: seen.append(req))
    page.goto(f"/p/{link['token']}")
    expect(page.locator("#secret-form")).to_be_visible(timeout=15000)
    page.fill("#secret-input", PASSWORD)
    page.click("#secret-submit")
    expect(page.locator("#content")).to_be_visible(timeout=15000)
    with page.expect_download(timeout=timeout) as info:
        page.click("#listing button")
    download = info.value
    saved = tmp_path / "saved.bin"
    download.save_as(saved)
    assert download.failure() is None
    [fetched] = [r for r in seen if "/download/" in r.url]
    return saved, download, fetched, seen


def _assert_a_native_download(fetched, base_url):
    # A navigation the browser saves itself: not a fetch, no grant header, the grant in the query only.
    assert fetched.resource_type == "document", fetched.resource_type
    assert fetched.method == "GET"
    sent = fetched.all_headers()
    assert "x-download-grant" not in sent
    grant = parse_qs(urlparse(fetched.url).query)["grant"][0]
    assert len(grant) >= 40
    # At most the origin in the Referer: the page's address (its token) is never repeated.
    referer = sent.get("referer")
    assert referer in (None, base_url.rstrip("/") + "/"), referer
    return grant


@pytest.mark.timeout(240)
def test_a_small_capped_file_arrives_through_the_browsers_own_download(page: Page, admin, base_url,
                                                                      files_enabled, vault, tmp_path):
    content = os.urandom(300_000)
    file_id = _upload(admin, vault["id"], "contract.pdf", content)
    link = _link(admin, vault["id"], file_id)
    saved, download, fetched, seen = _download_in_the_browser(page, link, tmp_path)
    assert download.suggested_filename == "contract.pdf"
    assert saved.read_bytes() == content
    grant = _assert_a_native_download(fetched, base_url)
    for req in seen:                                  # every request the page made, the redeems included
        assert link["token"] not in (req.all_headers().get("referer") or ""), req.url
    card = _card(admin, link["id"], downloads=1)
    assert (card["use_count"], card["download_count"], card["status"]) == (1, 1, "exhausted"), card

    # The grant cannot be used again, by the browser or by anyone holding the address.
    again = requests.get(fetched.url, timeout=30)
    assert again.status_code == 404 and "text/html" in again.headers["content-type"]
    assert content[:64] not in again.content
    assert requests.get(f"{base_url}/public-links/{link['token']}/download/{file_id}",
                        headers={"X-Download-Grant": grant}, timeout=30).status_code == 404
    assert _card(admin, link["id"])["download_count"] == 1

    # Neither the grant nor the link's token reached a log line or an audit row.
    logs = subprocess.run(["docker", "logs", _API_CONTAINER], capture_output=True, text=True, timeout=60)
    assert logs.returncode == 0
    lines = logs.stdout + logs.stderr
    assert f"/download/{file_id}?grant" in lines, "the download's access line was not found"
    assert grant not in lines and link["token"] not in lines
    held = _psql("SELECT count(*) FROM audit_logs WHERE "
                 f"coalesce(endpoint, '') || coalesce(details::text, '') LIKE '%{grant}%' "
                 f"OR coalesce(endpoint, '') || coalesce(details::text, '') LIKE '%{link['token']}%'")
    assert held == "0"

    # A reload shows the used-up notice.
    page.reload()
    expect(page.locator("#notice")).to_have_text(
        "This link is not available. It may have expired, been used up, or been revoked.", timeout=15000)


@pytest.mark.timeout(600)
def test_a_file_over_100_mb_arrives_whole_through_the_browsers_own_download(page: Page, admin, base_url,
                                                                           files_enabled, vault, tmp_path):
    size = 105 * MB + 12345
    content = os.urandom(size)
    want = hashlib.sha256(content).hexdigest()
    file_id = _upload(admin, vault["id"], "archive.pdf", content)
    del content
    link = _link(admin, vault["id"], file_id)
    saved, download, fetched, _seen = _download_in_the_browser(page, link, tmp_path, timeout=120000)
    _assert_a_native_download(fetched, base_url)
    assert saved.stat().st_size == size
    assert _sha256(saved) == want
    card = _card(admin, link["id"], downloads=1)
    assert (card["use_count"], card["download_count"], card["bytes_served"]) == (1, 1, size), card


def test_opening_the_page_and_a_link_preview_spend_nothing(page: Page, admin, base_url, files_enabled, vault):
    content = os.urandom(20_000)
    file_id = _upload(admin, vault["id"], "preview.pdf", content)
    link = _link(admin, vault["id"], file_id, password=None)
    url = f"{base_url}/p/{link['token']}"
    # A preview service fetches the page (no script) and a prefetch fetches it ahead of a click.
    for headers in ({"User-Agent": "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"},
                    {"User-Agent": "facebookexternalhit/1.1"}, {"Sec-Purpose": "prefetch"},
                    {"Purpose": "prefetch"}):
        assert requests.get(url, headers=headers, timeout=30).status_code == 200
    # A preview that runs the page's script: it shows the file and waits for a click.
    page.goto(f"/p/{link['token']}")
    expect(page.locator("#listing button")).to_have_text("Download", timeout=15000)
    page.wait_for_timeout(1500)
    card = _card(admin, link["id"])
    assert (card["use_count"], card["download_count"], card["status"]) == (0, 0, "active"), card
