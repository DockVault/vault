"""Signing in straight after accepting an invitation or setting a new password gives a working app.

An /?invite= or /?reset= link shows its own screen, and the page's startup stops there: it runs that
flow instead of wiring up the app. So on that load the sidebar, the profile and notification menus,
sign-out, the phone menu button and the rest have no handlers. Success used to switch to the sign-in
screen in place, and the person signed in to an app that ignored every click until they reloaded
(the reload worked because the token had already left the URL, so the whole startup ran).

Success now loads the clean page for real, from the confirmation's button and from its timer alike.

Lanes:
  * ui   — the reported path, in a fresh browser with no reload by the test: accept an invitation
           (or use a reset link), arrive at sign-in, sign in, then use the sidebar, the profile menu
           and sign-out. Desktop and phone width, the button and the timer.
  * unit — a cheap source guard that neither success path switches screens in place again. It reads
           text and proves nothing about behaviour; the ui lane is the real one.
"""
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"

PHONE = {"width": 390, "height": 844}
DESKTOP = {"width": 1280, "height": 800}
VIEWPORTS = {"desktop": DESKTOP, "phone": PHONE}

ACCOUNT_KEYS = ("invite_enabled", "invite_ttl_hours", "email_requirement",
                "signup_email_domain_mode", "signup_email_domains")
NEW_PW = "SignInAfter-Passw0rd!42"


# --------------------------------------------------------------------------- unit lane

def _function_body(src: str, name: str) -> str:
    """The text of the top-level `function <name>(` up to its closing brace in column 0."""
    start = src.index(f"\nfunction {name}(")
    end = src.index("\n}\n", start)
    return src[start:end]


@pytest.mark.unit
@pytest.mark.parametrize("name", ["_inviteAccepted", "_resetDone"])
def test_success_paths_do_not_switch_to_sign_in_in_place(name):
    src = APP_JS.read_text(encoding="utf-8")
    assert src.count(f"\nfunction {name}(") == 1, name
    body = _function_body(src, name)
    assert "showScreen(" not in body, (
        f"{name} switches screens in place; the app was never wired on this load, so the person "
        "signs in to an app that ignores every click")
    assert "_reloadToSignIn" in body, f"{name} must leave for sign-in with a real page load"


@pytest.mark.unit
def test_the_sign_in_reload_uses_the_clean_path_and_replaces_history():
    src = APP_JS.read_text(encoding="utf-8")
    assert src.count("\nfunction _reloadToSignIn(") == 1
    body = _function_body(src, "_reloadToSignIn")
    assert "location.replace(location.pathname)" in body, body
    assert "location.assign(" not in body and "location.href" not in body, body


# --------------------------------------------------------------------------- ui lane

@pytest.fixture
def invites_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional",
                                 "signup_email_domain_mode": "off"})
    yield
    admin.put("/settings", json=snap)


def _delete_by_name(admin, username):
    for u in admin.get("/users").json():
        if u.get("username") == username:
            admin.delete_user(u["id"])
            return


def _history_length(page: Page) -> int:
    return page.evaluate("() => history.length")


def _leave_confirmation(page: Page, card: str, route: str):
    """From the success confirmation to the sign-in screen, by its button or by waiting for its timer."""
    if route == "button":
        page.locator(f"{card} button", has_text="Go to sign in").click()
    # route == "timer": touch nothing; the confirmation moves on by itself after a few seconds
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def _arrived_at_sign_in_signed_out(page: Page, param: str, history_before: int):
    assert f"{param}=" not in page.url, page.url
    # replace(), not a new entry: the link's entry was already rewritten to the clean path on arrival
    assert _history_length(page) == history_before, "leaving for sign-in added a history entry"
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    assert page.evaluate(
        "() => localStorage.getItem('authToken') || sessionStorage.getItem('authToken')") in (None, ""), \
        "the person was signed in without entering the password"


def _sign_in(page: Page, username: str, password: str):
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _the_app_answers_clicks(page: Page, viewport: str):
    """Use the controls the startup wires up: the sidebar (behind the menu button on a phone), the
    profile menu, and sign-out from it."""
    if viewport == "phone":
        toggle = page.locator("#mobile-nav-toggle")
        expect(toggle).to_be_visible()
        toggle.click()
        expect(toggle).to_have_attribute("aria-expanded", "true", timeout=5000)
    page.locator('.sidebar-item[data-section="vaults"]').click()
    expect(page.locator("#vaults-section")).to_have_class(re.compile(r"\bactive\b"), timeout=5000)
    expect(page.locator("#vaults-section")).to_be_visible()

    page.locator("#profile-btn").click()
    expect(page.locator(".profile-menu")).to_have_class(re.compile(r"\bactive\b"), timeout=5000)
    expect(page.locator("#profile-dropdown")).to_be_visible()
    page.locator("#dropdown-logout-btn").click()
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    expect(page.locator("#dashboard-screen")).to_be_hidden()


@pytest.mark.ui
@pytest.mark.parametrize("viewport,route", [("desktop", "button"), ("phone", "timer")])
def test_signing_in_after_accepting_an_invitation_gives_a_working_app(
        page: Page, admin, invites_on, viewport, route):
    uname = unique("uiinv").replace("_", "")
    r = admin.post("/invites", json={"username": uname, "role": "user"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    try:
        page.set_viewport_size(VIEWPORTS[viewport])
        page.goto(f"/?invite={token}")
        expect(page.locator("#invite-screen")).to_be_visible(timeout=10000)
        pw = page.locator("#invite-card-body input[type=password]")
        expect(pw).to_be_visible(timeout=10000)
        history_before = _history_length(page)

        pw.fill(NEW_PW)
        page.locator("#invite-card-body button[type=submit]").click()
        expect(page.locator("#invite-card-body")).to_contain_text("Account created", timeout=10000)
        _leave_confirmation(page, "#invite-card-body", route)
        _arrived_at_sign_in_signed_out(page, "invite", history_before)

        _sign_in(page, uname, NEW_PW)
        _the_app_answers_clicks(page, viewport)
    finally:
        _delete_by_name(admin, uname)


@pytest.mark.ui
@pytest.mark.parametrize("viewport,route", [("desktop", "timer"), ("phone", "button")])
def test_signing_in_after_a_password_reset_gives_a_working_app(page: Page, admin, viewport, route):
    u = admin.create_user(role="user", email=None)
    try:
        r = admin.post(f"/users/{u['id']}/reset-link")
        assert r.status_code == 200, r.text
        link = r.json()["reset_link"]
        assert "?reset=" in link, link
        token = link.split("?reset=", 1)[1]

        page.set_viewport_size(VIEWPORTS[viewport])
        page.goto(f"/?reset={token}")
        expect(page.locator("#reset-screen")).to_be_visible(timeout=10000)
        pw = page.locator("#reset-card-body input[type=password]")
        expect(pw).to_be_visible(timeout=10000)
        history_before = _history_length(page)

        pw.fill(NEW_PW)
        page.locator("#reset-card-body button[type=submit]").click()
        expect(page.locator("#reset-card-body")).to_contain_text("Password updated", timeout=10000)
        _leave_confirmation(page, "#reset-card-body", route)
        _arrived_at_sign_in_signed_out(page, "reset", history_before)

        _sign_in(page, u["_username"], NEW_PW)
        _the_app_answers_clicks(page, viewport)
    finally:
        admin.delete_user(u["id"])
