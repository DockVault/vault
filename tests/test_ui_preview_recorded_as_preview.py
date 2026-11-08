"""The web app's preview is recorded as a preview, not a download.

Opening a file's preview, or the text window of a large text file, read the file through the download route and
was recorded as "File download started" and "File download finished". The web app now asks for those bytes as a
preview, and the record says the content was sent to the browser for a preview. A download from the same page
is recorded as a download, as before.
"""
import os
import subprocess

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _actions(file_id):
    out = _psql(f"SELECT action FROM audit_logs WHERE resource_id='{file_id}' AND resource_type='file' "
                "ORDER BY timestamp, id")
    return [line for line in out.splitlines() if line]


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def owner_with_a_file(admin):
    u = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(u["_username"], u["_password"])
    vault = client.create_vault(name=unique("previews"))
    name = unique("readme") + ".txt"
    r = client.post(f"/vaults/{vault['id']}/files", files=[("files", (name, b"preview me, do not count me\n" * 3, "text/plain"))])
    assert r.status_code == 200, r.text
    file_id = next(f["id"] for f in client.get(f"/vaults/{vault['id']}/files").json()["items"] if f["name"] == name)
    try:
        yield u, vault, file_id
    finally:
        client.delete_vault(vault["id"])
        admin.delete_user(u["id"])


def test_a_preview_in_the_browser_writes_preview_rows_only(page: Page, owner_with_a_file):
    user, vault, file_id = owner_with_a_file
    _login(page, user)
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    before = _actions(file_id)
    page.click(f'.file-name[data-file-id="{file_id}"]')
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
    expect(page.locator("#file-preview-body")).to_contain_text("preview me, do not count me", timeout=10000)
    page.wait_for_timeout(800)  # the finished row is written when the response ends
    new = _actions(file_id)[len(before):]
    assert new == ["file_previewed", "file_preview_completed"], new
    assert not [a for a in new if a.startswith("file_download")]
