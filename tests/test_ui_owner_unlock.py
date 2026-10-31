"""A vault's owner gives the vault's password on Access to my vaults, in a real browser (static/js/compliance.js
unlock, the app's prompt in static/js/app.js).

A case opened a file in a vault of olga's with a vault password: her page lists it with its name hidden and offers
to unlock the vault. The prompt for the password is asked over the dialog, where a click reaches its buttons; once
the password is given the file's name shows and the offer goes. The prompt goes back to its place under the dialogs
once it has asked.

Waits are on state, never on time (the timing rules of the browser tests).
"""
import pytest
from playwright.sync_api import Page, expect

from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, owner_with_vault
from conftest import unique

pytestmark = pytest.mark.ui

PASSWORD = "Vault-Pass-2026!"
HIDDEN = "(name hidden until the vault is unlocked)"


@pytest.fixture(scope="module")
def world(admin):
    """A case on olga's vault with a vault password, in which uma, its auditor, opened a file."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, plain = owner_with_vault(admin)
        pv = olga_c.create_vault(name=unique("locked"), password=PASSWORD)["id"]
        opened = f"{unique('salaries')}.txt"
        up = olga_c.post(f"/vaults/{pv}/files", files=[("files", (opened, b"the plan", "text/plain"))],
                         headers={"X-Vault-Password": PASSWORD})
        assert up.status_code in (200, 201), up.text
        fid = up.json()["files"][0]["id"]
        case = approved_case(admins, (uma, uma_c, codes), [pv])
        try:
            r = uma_c.post(f"/compliance/cases/{case['id']}/vaults/{pv}/unlock", json={"password": PASSWORD})
            assert r.status_code == 200, r.text
            r = uma_c.get(f"/compliance/cases/{case['id']}/files/{fid}/content",
                          headers={"X-Case-Unlock": f"{pv}={r.json()['receipt']}"})
            assert r.status_code == 200, r.text
            yield {"olga": olga, "pv": pv, "opened": opened}
        finally:
            forget_cases([case["id"]], [pv])
            forget_grants(uma["id"])
            olga_c.delete_vault(pv, vault_password=PASSWORD)
            olga_c.delete_vault(plain)


def test_the_owner_gives_a_vaults_password_and_sees_the_names_of_the_files_opened(page: Page, world):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", world["olga"]["_username"])
    page.fill("#password", world["olga"]["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.evaluate("() => window.openMyAccess()")
    dialog = page.locator("#my-access-modal")
    expect(dialog.locator(".my-access-file").filter(has_text=HIDDEN)).to_have_count(1, timeout=15000)
    expect(dialog).not_to_contain_text(world["opened"])
    dialog.locator(".my-access-unlock").click()
    prompt = page.locator("#confirm-modal.active")
    expect(prompt).to_be_visible(timeout=10000)
    prompt.locator("#confirm-modal-input").fill(PASSWORD)
    # Clicked as a person clicks: on the button where it is drawn, so a dialog over it would take the click.
    prompt.locator("#confirm-modal-confirm-btn").click(timeout=10000)
    expect(prompt).to_have_count(0)
    expect(dialog.locator(".my-access-file").filter(has_text=world["opened"])).to_have_count(1, timeout=15000)
    expect(dialog.locator(".my-access-unlock")).to_have_count(0)
    assert page.evaluate("() => document.getElementById('confirm-modal').style.zIndex") == ""
    assert errors == []
