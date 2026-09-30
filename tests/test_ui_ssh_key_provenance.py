"""Browser: an SSH key says who added it, and a link to Your account (#profile, in the email about the keys
an administrator who has left added) opens that dialog once the person has signed in.

test_ssh_key_provenance_live.py covers the API; this checks the page."""
import base64
import os

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _pubkey():
    blob = (len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + os.urandom(32))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def test_the_link_to_your_account_opens_it_and_each_key_says_who_added_it(page: Page, admin, admin_creds):
    bob = admin.create_user(role="user")
    try:
        r = admin.post(f"/users/{bob['id']}/ssh-keys", json={"name": "desk", "public_key": _pubkey()})
        assert r.status_code == 200, r.text
        page.goto("/#profile")
        expect(page.locator("#login-screen")).to_be_visible()
        page.fill("#username", bob["_username"])
        page.fill("#password", bob["_password"])
        page.click("#login-form button[type=submit]")
        modal = page.locator("#user-settings-modal")
        expect(modal).to_be_visible(timeout=15000)
        item = modal.locator(".ssh-key-item").filter(has_text="desk")
        expect(item.locator(".ssh-key-by")).to_have_text(f"Added by {admin_creds['username']}", timeout=10000)
        # Opened once: the link is dropped, so a reload does not open it again.
        assert page.evaluate("location.hash") == ""

        # A key the person added: "Added by you".
        modal.locator(".ssh-key-name").scroll_into_view_if_needed()
        modal.locator(".ssh-key-name").fill("laptop")
        modal.locator(".ssh-key-public").fill(_pubkey())
        modal.locator("#us-ssh-add").scroll_into_view_if_needed()
        modal.locator("#us-ssh-add").click()
        own = modal.locator(".ssh-key-item").filter(has_text="laptop")
        expect(own.locator(".ssh-key-by")).to_have_text("Added by you", timeout=10000)
    finally:
        admin.delete_user(bob["id"])


def test_the_link_opens_your_account_when_already_signed_in(page: Page, admin):
    bob = admin.create_user(role="user")
    try:
        page.goto("/")
        page.fill("#username", bob["_username"])
        page.fill("#password", bob["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        expect(page.locator("#user-settings-modal")).to_be_hidden()
        page.goto("/#profile")
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        expect(page.locator("#user-settings-modal")).to_be_visible(timeout=15000)
        assert page.evaluate("location.hash") == ""
    finally:
        admin.delete_user(bob["id"])
