"""UI — the owner-encrypted "Show link again" main path, in a real browser.

An owner WITH an ECC keypair creates a note link (seeing its URL once at creation), then on the
Shared tab clicks "Show link again", and the revealed URL equals the one shown at creation -- the
client wrapped the token to the owner's own public key at creation and decrypts it here. An account
WITHOUT a keypair sees the set-up hint and no "Show link again" button. Cross-user and rotated-key
failures are pinned at the crypto layer (tests/js/link_token_wrap.js) and stay in the runner's suite.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

_PASSPHRASE = "recopy-pass-phrase-123"


@pytest.fixture
def links_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _client_for(user):
    c = ApiClient(BASE_URL)
    c.login(user["_username"], user["_password"])
    return c


def _setup_encryption_key(page: Page):
    """Standalone 'Set up encryption key' flow -- leaves the keypair registered AND unlocked in the
    browser (mirrors test_ui_e2e._create_zk_vault_via_ui)."""
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    page.click("#encryption-key-setup-btn")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
    page.click("#confirm-modal-confirm-btn")
    for _ in range(2):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", _PASSPHRASE)
        page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
    page.locator("#encryption-key-modal .close-modal-btn").first.click()
    expect(page.locator("#encryption-key-modal")).to_be_hidden(timeout=5000)


def _create_open_note_link(page: Page) -> str:
    """Create a note link on the first note via the Public tile ('Open' tag), return the one-time URL."""
    page.click('.sidebar-item[data-section="notes"]')
    expect(page.locator("#notes-section")).to_be_visible(timeout=10000)
    page.locator("#notes-list .card").first.get_by_role("button", name="Share", exact=True).click()
    page.click("#note-share-public")
    expect(page.locator("#note-public-link-modal")).to_be_visible()
    page.select_option("#note-public-tag", label="Open")
    page.click("#note-public-create")
    expect(page.locator("#note-public-result")).to_be_visible(timeout=10000)
    url = page.locator("#note-public-link-value").input_value()
    assert re.search(r"/l/[0-9A-Za-z]+$", url), url
    # Close the create modal so the Shared tab is reachable.
    page.locator("#note-public-link-modal .close-modal-btn").first.click()
    return url


def test_owner_with_a_keypair_can_show_a_note_link_again(page: Page, admin, links_on):
    page.context.grant_permissions(["clipboard-read", "clipboard-write"])
    user = admin.create_user(role="user")
    _client_for(user).post("/notes", json={"title": unique("RC"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _setup_encryption_key(page)                      # keypair set up AND unlocked
        created = _create_open_note_link(page)           # wrap-at-creation runs (public key only)

        page.click('.tab-btn[data-notes-tab="shared"]')
        card = page.locator("#notes-shared-list .note-link-card").first
        expect(card).to_be_visible(timeout=10000)
        again = card.get_by_role("button", name="Show link again", exact=True)
        expect(again).to_be_visible()
        again.click()
        # The key is unlocked, so the reveal copies the URL to the clipboard.
        expect(page.locator(".toast, #toast, .notification").filter(
            has_text=re.compile("Link copied", re.I))).to_be_visible(timeout=10000)
        revealed = page.evaluate("() => navigator.clipboard.readText()")
        assert revealed == created, "the revealed URL does not match the one shown at creation"
    finally:
        admin.delete_user(user["id"])


def test_a_no_keypair_account_sees_the_setup_hint_and_no_show_again(page: Page, admin, links_on):
    user = admin.create_user(role="user")
    _client_for(user).post("/notes", json={"title": unique("NK"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])     # NO encryption key set up
        _create_open_note_link(page)                            # no keypair -> no re-copy saved
        page.click('.tab-btn[data-notes-tab="shared"]')
        card = page.locator("#notes-shared-list .note-link-card").first
        expect(card).to_be_visible(timeout=10000)
        # No "Show link again" (there is no re-copy), and the set-up hint is shown instead.
        expect(card.get_by_role("button", name="Show link again", exact=True)).to_have_count(0)
        expect(card).to_contain_text("Set up your encryption key to be able to see links again.")
    finally:
        admin.delete_user(user["id"])
