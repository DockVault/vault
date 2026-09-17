"""Browser (Playwright) proof of the two-section temp-credentials page: both sections render, the
per-computer section names the device by its DISPLAY NAME, and a device-minted credential appears in
the per-computer section -- not the shared one. The lifecycle/finished behaviour and scoping are
proven over HTTP; this is the render.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique
from _device_boundary_helpers import grant, mint_sync_cred, register_device

pytestmark = pytest.mark.ui


def _login_admin(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_temp_creds_page_splits_into_two_sections_and_names_the_device(page, admin, admin_creds, temp_vault):
    handout = admin.post("/auth/temp-credentials", json={"note": unique("handout")}).json()
    dev = register_device(admin, label="Studio-Mac")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()

    _login_admin(page, admin_creds)
    page.click('.sidebar-item[data-section="temp-creds"]')
    expect(page.locator("#active-temp-creds")).to_be_visible(timeout=10000)

    # Show every credential, so a status filter can never hide a section's fixture row.
    page.select_option("#tc-status-filter", "all")

    # Both sections render.
    expect(page.locator("#tc-shared-heading")).to_be_visible(timeout=10000)
    expect(page.locator("#tc-per-computer-heading")).to_be_visible()

    # The per-computer section names WHICH computer (the display name) and lists the minted credential.
    per = page.locator("#tc-per-computer-table")
    expect(per).to_contain_text(dev["label"])
    expect(per).to_contain_text(minted["temp_username"])

    # The device credential is in the per-computer section, never the shared one; the hand-out
    # credential is in the shared table.
    shared_table = page.locator("#tc-shared-table")   # its own id: table.exp-table is rendered twice
    expect(shared_table).to_contain_text(handout["temp_username"])
    expect(shared_table).not_to_contain_text(minted["temp_username"])
