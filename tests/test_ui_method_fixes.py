"""UI regression for the two method-mismatch 405s.

Both were the frontend sending the wrong HTTP verb, so the action silently failed with a
"Method Not Allowed" error toast:
  * vault delete  -> DELETE /vaults/{id}  (real route: POST /vaults/{id}/delete)
  * user edit     -> PUT   /users/{id}    (real route: PATCH /users/{id})
These drive the real buttons and assert the action actually takes effect server-side.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def admin_page(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def test_vault_delete_from_card_works(admin_page: Page, admin):
    """Deleting a (password-less) vault from its card removes it — no 405."""
    page = admin_page
    v = admin.create_vault(name="uir-del-target")
    vid = v["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        card_del = page.locator(f'.delete-vault-btn[data-vault-id="{vid}"]')
        expect(card_del).to_be_visible(timeout=10000)
        card_del.click()
        page.click("#confirm-modal-confirm-btn")
        # authoritative: the vault is actually gone server-side (a 405 would leave it)
        expect(page.locator(".toast-success")).to_be_visible(timeout=10000)
        expect(page.locator(f'.delete-vault-btn[data-vault-id="{vid}"]')).to_have_count(0)
        assert admin.get(f"/vaults/{vid}").status_code in (403, 404)
    finally:
        if admin.get(f"/vaults/{vid}").status_code == 200:
            admin.delete_vault(vid)


def test_password_vault_delete_from_card_prompts_and_works(admin_page: Page, admin):
    """A password-protected vault deleted from its card prompts for the password
    (via showPrompt) and sends it as the X-Vault-Password header — no 405, no 401."""
    page = admin_page
    vpw = "CardDelPass!123long"
    v = admin.create_vault(name="uir-pw-del-target", password=vpw)
    vid = v["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        card_del = page.locator(f'.delete-vault-btn[data-vault-id="{vid}"]')
        expect(card_del).to_be_visible(timeout=10000)
        card_del.click()
        # first modal: the delete confirmation
        page.click("#confirm-modal-confirm-btn")
        # second modal: the password prompt (same #confirm-modal DOM, reused by showPrompt)
        pw_input = page.locator("#confirm-modal-input")
        expect(pw_input).to_be_visible(timeout=10000)
        pw_input.fill(vpw)
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator(".toast-success")).to_be_visible(timeout=10000)
        assert admin.get(f"/vaults/{vid}").status_code in (403, 404)
    finally:
        if admin.get(f"/vaults/{vid}").status_code == 200:
            admin.delete_vault(vid, vault_password=vpw)


def test_user_edit_saves(admin_page: Page, admin):
    """Editing a user's email persists — no 405."""
    page = admin_page
    u = admin.create_user(role="user")
    uid = u["id"]
    new_email = "uir-edited@example.com"
    try:
        page.click('.sidebar-item[data-section="users"]')
        row = page.locator(f'tr.exp-row[data-id="{uid}"]')
        expect(row).to_be_visible(timeout=10000)
        row.click()  # expand the row to reveal the Edit button
        edit_btn = page.locator(f'.edit-user-btn[data-user-id="{uid}"]')
        expect(edit_btn).to_be_visible(timeout=10000)
        edit_btn.click()
        email_field = page.locator("#edit-user-email")
        expect(email_field).to_be_visible(timeout=10000)
        email_field.fill(new_email)
        page.click("#edit-user-form button[type=submit]")
        expect(page.locator(".toast-success")).to_be_visible(timeout=10000)
        # authoritative: the change actually persisted (a 405 would not have)
        got = admin.get(f"/users/{uid}").json()
        assert got["email"] == new_email
    finally:
        admin.delete_user(uid)
