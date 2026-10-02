"""Unlocking a password-protected vault's names from the Activity page's details, in a browser.

An event in a vault with a vault password shows its file's name as hidden, with a field for the vault password;
the password shows the name as it was recorded, without a reload, and the field goes. The levels are set back
afterwards.
"""
import uuid

import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import psql
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.ui


def test_the_vault_password_shows_the_recorded_name(page: Page, admin, admin_creds, temp_vault_pw, levels_restored):
    store(dict(levels_restored, names="full"))
    name = f"ui-unlock-{uuid.uuid4().hex[:12]}.txt"
    up = admin.post(f"/vaults/{temp_vault_pw['id']}/files", files=[("files", (name, b"0123456789", "text/plain"))],
                    headers={"X-Vault-Password": temp_vault_pw["_password"]})
    assert up.status_code in (200, 201), up.text[:200]
    row_id = wait_for(lambda: psql("SELECT id FROM audit_logs WHERE details->>'vault_id' = '%s' AND resource_type = "
                                   "'file' AND recorded->'names'->'values' ? 'file_name' ORDER BY timestamp DESC "
                                   "LIMIT 1" % temp_vault_pw["id"]))
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto("/")
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    # A link to the event, opened as a person opens a copied link: the signed-in app reads it as it starts.
    page.goto(f"/#activity?ev={row_id}")
    page.reload()
    detail = page.locator("#act-detail")
    expect(detail).to_contain_text("Name hidden: the vault has a password", timeout=15000)
    form = detail.locator("form.act-unlock")
    expect(form).to_be_visible()
    form.locator("input[type=password]").fill(temp_vault_pw["_password"])
    form.locator("button[type=submit]").click()
    expect(detail).to_contain_text(name, timeout=15000)
    expect(detail.locator("form.act-unlock")).to_have_count(0)
