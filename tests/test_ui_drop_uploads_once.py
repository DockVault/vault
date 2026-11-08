"""A file dropped on the files tab is uploaded once, however many vaults were opened before.

The drag-and-drop wiring runs on every vault open; it used to add another set of listeners to the files tab
each time, so a drop after three opens uploaded the file three times (and the tab grew heavier with every
open). The listeners are wired once now.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_dropped_file_is_uploaded_once_after_several_vault_opens(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("drop"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        for _ in range(3):
            page.click('.sidebar-item[data-section="vaults"]')
            page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
            expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
            page.wait_for_timeout(300)
        starts = []
        page.on("request", lambda r: starts.append(r.url) if r.method == "POST"
                and re.search(rf"/vaults/{v['id']}/(uploads|files)(\?|$)", r.url) else None)
        dt = page.evaluate_handle("() => { const dt = new DataTransfer(); dt.items.add(new File(['dropped once'], 'dropped.txt', { type: 'text/plain' })); return dt; }")
        page.locator("#vault-files-tab").dispatch_event("drop", {"dataTransfer": dt})
        expect(page.locator('#vault-files-table-body .file-name[data-file-name="dropped.txt"]')).to_have_count(1, timeout=20000)
        page.wait_for_timeout(1500)
        assert len(starts) == 1, starts
        assert len(admin.get(f"/vaults/{v['id']}/files").json()["items"]) == 1
        assert page.evaluate("() => document.getElementById('vault-files-tab').dataset.dropWired") == "1"
    finally:
        admin.delete_vault(v["id"])
