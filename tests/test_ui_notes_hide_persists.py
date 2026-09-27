"""UI: "Hide note text" follows the account, not the browser.

The owner turned it on, signed out and in again (or opened another browser) and found it off. It is
kept on the account now: it survives a sign-out and a browser with nothing stored, until it is turned
off. A choice an older release kept in this browser is moved to the account once, and removed from
the browser so it cannot apply to the next person who signs in here."""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui

PREFS = "/users/me/preferences"


@pytest.fixture
def person(admin):
    user = admin.create_user(role="user")
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    note = c.post("/notes", json={"title": unique("hidden"), "body": "the private body"}).json()
    user["_client"], user["_note"] = c, note
    yield user
    admin.delete_user(user["id"])


def _login(page: Page, user):
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_notes(page: Page):
    page.click('.sidebar-item[data-section="notes"]')
    expect(page.locator("#notes-section")).to_be_visible(timeout=10000)


def _sign_out(page: Page):
    page.evaluate("logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)


def _account_choice(page: Page, person, want):
    """The account's saved choice, once it reads `want` (the page saves it in the background)."""
    got = None
    for _ in range(30):
        got = person["_client"].get(PREFS).json().get("hide_note_text")
        if got == want:
            break
        page.wait_for_timeout(100)
    return got


def _body_is_hidden(page: Page, note):
    card = page.locator("#notes-list .card", has_text=note["title"])
    expect(card).to_be_visible(timeout=10000)
    expect(page.locator("#notes-list .note-body", has_text="the private body")).to_have_count(0)
    expect(card).to_contain_text("hidden")


def test_the_choice_survives_a_sign_out_and_a_browser_with_nothing_stored(page: Page, person):
    page.goto("/")
    _login(page, person)
    _open_notes(page)
    expect(page.locator("#notes-list .note-body", has_text="the private body")).to_have_count(1)
    page.check("#notes-hide-toggle")
    _body_is_hidden(page, person["_note"])
    assert _account_choice(page, person, "on") == "on"
    _sign_out(page)
    # A browser that remembers nothing: what was kept there is gone.
    page.evaluate("localStorage.clear(); sessionStorage.clear()")
    page.goto("/")
    _login(page, person)
    _open_notes(page)
    expect(page.locator("#notes-hide-toggle")).to_be_checked()
    _body_is_hidden(page, person["_note"])
    # Turning it off is kept too.
    page.uncheck("#notes-hide-toggle")
    expect(page.locator("#notes-list .note-body", has_text="the private body")).to_have_count(1)
    assert _account_choice(page, person, "off") == "off"


def test_a_choice_this_browser_kept_is_moved_to_the_account_once(page: Page, person):
    page.goto("/")
    page.evaluate("localStorage.setItem('notesHideText', '1')")        # what an older release stored
    _login(page, person)
    _open_notes(page)
    expect(page.locator("#notes-hide-toggle")).to_be_checked()
    _body_is_hidden(page, person["_note"])
    assert page.evaluate("localStorage.getItem('notesHideText')") is None
    assert _account_choice(page, person, "on") == "on"


def test_a_kept_browser_value_does_not_override_the_accounts_choice(page: Page, person):
    person["_client"].put(PREFS, json={"hide_note_text": "off"})
    page.goto("/")
    page.evaluate("localStorage.setItem('notesHideText', '1')")
    _login(page, person)
    _open_notes(page)
    expect(page.locator("#notes-hide-toggle")).not_to_be_checked()
    expect(page.locator("#notes-list .note-body", has_text="the private body")).to_have_count(1)
    assert page.evaluate("localStorage.getItem('notesHideText')") is None
    assert person["_client"].get(PREFS).json()["hide_note_text"] == "off"
