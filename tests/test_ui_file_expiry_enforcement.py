"""UI: a vault's file expiry reads as what this server does.

The panels describe the setting as it applies ("3 hours after upload"), and when the server's operator
has postponed enforcement (ENFORCE_FILE_EXPIRY=false) every place that would promise a deletion says
that nothing is being deleted. The deployment under test enforces expiry, so the postponed case is
driven by answering /zk-enabled, where the web app reads it, with the flag off.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

NOT_ENFORCED = "not enforced on this server: no files are being deleted"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _answer_expiry_postponed(page: Page):
    def handle(route):
        real = route.fetch()
        body = real.json()
        body["file_expiry_enforced"] = False
        route.fulfill(response=real, body=json.dumps(body))
    page.route("**/zk-enabled", handle)


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    card = page.locator(f'.vault-card[data-vault-id="{vault_id}"]')
    expect(card).to_be_visible(timeout=10000)
    card.locator(".open-vault-btn").click()
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


@pytest.fixture
def expiring_vault(admin):
    v = admin.create_vault()
    r = admin.patch(f"/vaults/{v['id']}/settings",
                    json={"expire_files_after_days": 3, "expire_files_unit": "hours"})
    assert r.status_code == 200, r.text
    yield v
    admin.delete_vault(v["id"])


@pytest.mark.parametrize("postponed", [False, True], ids=["enforced", "postponed"])
def test_the_vault_panels_and_dialog_say_what_this_server_does(page: Page, admin_creds,
                                                              expiring_vault, postponed):
    if postponed:
        _answer_expiry_postponed(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_vault(page, expiring_vault["id"])

    page.click('[data-vault-tab="info"]')
    info = page.locator("#info-file-expiration")
    expect(info).to_contain_text("3 hours after upload")
    page.click('[data-vault-tab="settings"]')
    panel = page.locator("#settings-file-expiry")
    expect(panel).to_contain_text("3 hours after upload")

    page.click("#set-expiry-btn")
    expect(page.locator("#set-expiry-modal")).to_be_visible()
    expect(page.locator("#expire-files-help")).to_contain_text(
        "Files already in the vault keep their current deadline.")
    note = page.locator("#expire-files-not-enforced")
    if postponed:
        expect(info).to_contain_text(NOT_ENFORCED)
        expect(panel).to_contain_text(NOT_ENFORCED)
        expect(note).to_be_visible()
        expect(note).to_contain_text("no files are being deleted")
    else:
        expect(info).not_to_contain_text("not enforced")
        expect(panel).not_to_contain_text("not enforced")
        expect(note).to_be_hidden()
