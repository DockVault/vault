"""Browser coverage for the public invitation-acceptance page.

The link is /?invite=<token>. The page must render in the SPA shell WITHOUT login and without flashing
the authenticated app or the login screen — even when a stale session token is cached — then, on
success, route to the login screen (the invitee is NOT auto-signed-in).
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

ACCOUNT_KEYS = ("invite_enabled", "invite_ttl_hours", "email_requirement",
                "signup_email_domain_mode", "signup_email_domains")
STRONG_PW = "AcceptPassw0rd!123"


@pytest.fixture
def invites_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional",
                                 "signup_email_domain_mode": "off"})
    yield
    admin.put("/settings", json=snap)


def _mint(admin, username):
    r = admin.post("/invites", json={"username": username, "role": "user"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _cleanup(admin, username):
    for u in admin.get("/users").json():
        if u.get("username") == username:
            admin.delete_user(u["id"])
            return


def test_accept_page_does_not_flash_the_app_even_with_a_stale_token(page: Page, admin, invites_on):
    uname = "uiflash" + str(abs(hash(page)) % 100000)
    token = _mint(admin, uname)
    try:
        # plant a stale session token, then open the invite link
        page.goto("/")
        page.evaluate("() => localStorage.setItem('authToken', 'stale-garbage-token')")
        page.goto(f"/?invite={token}")
        # only the invite screen shows; the app shell and login never do
        expect(page.locator("#invite-screen")).to_be_visible(timeout=10000)
        expect(page.locator("#dashboard-screen")).to_be_hidden()
        expect(page.locator("#login-screen")).to_be_hidden()
        expect(page.locator("#boot-screen")).to_be_hidden()
        # the pre-paint gate is set
        assert page.evaluate("() => document.documentElement.getAttribute('data-invite')") == "1"
    finally:
        _cleanup(admin, uname)


def test_accept_end_to_end_lands_on_login(page: Page, admin, invites_on):
    uname = "uie2e" + str(abs(hash(page)) % 100000)
    token = _mint(admin, uname)
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        page.goto(f"/?invite={token}")
        expect(page.locator("#invite-screen")).to_be_visible(timeout=10000)
        # the form renders with the claimed username and a password field
        expect(page.locator("#invite-card-body")).to_contain_text(uname)
        pw = page.locator("#invite-card-body input[type=password]")
        expect(pw).to_be_visible()
        pw.fill(STRONG_PW)
        page.locator("#invite-card-body button[type=submit]").click()
        # success -> confirmation, then the login screen; the ?invite= is stripped
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        assert "invite=" not in page.url
        # the account really exists
        assert any(u.get("username") == uname for u in admin.get("/users").json())
        assert not errors, f"console errors: {errors}"
    finally:
        _cleanup(admin, uname)


def test_invalid_link_shows_one_generic_message(page: Page, admin, invites_on):
    page.goto("/?invite=" + ("z" * 43))
    expect(page.locator("#invite-screen")).to_be_visible(timeout=10000)
    expect(page.locator("#invite-card-body")).to_contain_text("invalid or has expired")
    # no form, no token stored
    expect(page.locator("#invite-card-body input[type=password]")).to_have_count(0)
    assert page.evaluate("() => localStorage.getItem('authToken')") in (None, "")
