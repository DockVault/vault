"""In real browsers: the rule for a new passphrase, the nudge for an old one, and the envelope hold.

* Setting up a key with a passphrase shorter than 12 characters, or a common one, is refused with the reason;
  a passphrase set before the rule still unlocks, and the person is told once to change it.
* After an administrator set the person's password, unlocking the key asks to send a code by email, takes the
  code, and then unlocks as before.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from conftest import BASE_URL, ApiClient
from test_ui_e2e import _login
from _account_change_helpers import MAILPIT_URL, mail_sink, mail_to

pytestmark = pytest.mark.ui

needs_mailpit = pytest.mark.skipif(not MAILPIT_URL, reason="no mail sink (VAULT_MAILPIT_URL) for this run")


@pytest.fixture
def account(admin):
    made = []

    def make():
        p = admin.create_user(role="user")
        made.append(p)
        return p

    yield make
    for p in made:
        admin.delete_user(p["id"])


def _open_key_setup(page: Page):
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    page.click("#encryption-key-setup-btn")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
    page.click("#confirm-modal-confirm-btn")


def _type(page: Page, text: str):
    expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
    page.fill("#confirm-modal-input", text)
    page.click("#confirm-modal-confirm-btn")


def _set_up(page: Page, passphrase: str):
    _open_key_setup(page)
    _type(page, passphrase)
    _type(page, passphrase)
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
    page.locator("#encryption-key-modal .close-modal-btn").first.click()
    expect(page.locator("#encryption-key-modal")).to_be_hidden(timeout=5000)


@pytest.mark.parametrize("passphrase,reason", [
    ("short-pass1", "at least 12 characters"),
    ("Password1234!", "a common one"),
    ("abcabcabcabc", "repeats itself"),
])
def test_a_weak_new_passphrase_is_refused_with_the_reason(browser, account, passphrase, reason):
    person = account()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    try:
        _login(page, person["_username"], person["_password"])
        _open_key_setup(page)
        _type(page, passphrase)
        expect(page.locator(".toast-error").last).to_contain_text(reason, timeout=10000)
        c = ApiClient()
        c.login(person["_username"], person["_password"])
        assert c.get("/ecc/keys/public").json()["has_keypair"] is False
    finally:
        ctx.close()


def test_an_old_weak_passphrase_still_unlocks_and_the_person_is_told_once(browser, account):
    person = account()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    try:
        _login(page, person["_username"], person["_password"])
        # A key set up before the rule, with a passphrase it would refuse now.
        page.evaluate("() => { window.__rule = ZkPassphrase.problem; ZkPassphrase.problem = () => null; }")
        _set_up(page, "hunter22")
        page.evaluate("() => { ZkPassphrase.problem = window.__rule; zkLockAllVaults(); }")
        page.evaluate("() => { window.__unlock = zkUnlockAllVaults(); }")
        _type(page, "hunter22")
        page.evaluate("() => window.__unlock")
        assert page.evaluate("() => zkKeyUnlocked()") is True
        expect(page.locator(".toast-warning")).to_contain_text("weaker than new ones may be", timeout=10000)
        # Once a session.
        page.evaluate("() => { zkLockAllVaults(); window.__unlock = zkUnlockAllVaults(); }")
        _type(page, "hunter22")
        page.evaluate("() => window.__unlock")
        assert page.locator(".toast-warning", has_text="weaker than new ones may be").count() <= 1
    finally:
        ctx.close()


@needs_mailpit
def test_after_an_administrator_set_the_password_unlocking_takes_the_emailed_code(browser, account, admin):
    person = account()
    with mail_sink(admin):
        ctx = browser.new_context(base_url=BASE_URL)
        page = ctx.new_page()
        try:
            _login(page, person["_username"], person["_password"])
            _set_up(page, "orchid-lantern-72")
            new_password = "Admin-Set-Pass-9x!"
            assert admin.patch(f"/users/{person['id']}", json={"password": new_password}).status_code == 200
            ctx.close()
            ctx = browser.new_context(base_url=BASE_URL)
            page = ctx.new_page()
            _login(page, person["_username"], new_password)
            page.evaluate("() => { window.__unlock = zkUnlockAllVaults(); }")
            expect(page.locator("#confirm-modal-message")).to_contain_text("code sent to your email", timeout=10000)
            page.click("#confirm-modal-confirm-btn")
            expect(page.locator("#confirm-modal-message")).to_contain_text("Enter the code sent to", timeout=15000)
            message = mail_to(f"{person['_username']}@example.com",
                              subject_contains="Your code to open your encryption key")
            assert message, "no code arrived"
            code = re.search(r"\b[0-9a-f]{12}\b", message["text"]).group(0)
            _type(page, code)
            # Then the passphrase, as always.
            expect(page.locator("#confirm-modal-message")).to_contain_text("encryption passphrase", timeout=15000)
            _type(page, "orchid-lantern-72")
            page.evaluate("() => window.__unlock")
            assert page.evaluate("() => zkKeyUnlocked()") is True
        finally:
            ctx.close()
