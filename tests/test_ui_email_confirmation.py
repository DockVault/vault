"""Confirming the address an account already holds, on the pages (static/js/sso.js, static/js/app.js).

Your account offers a code where confirming the address would let the organisation's sign-in find the account:
the code is asked for, typed back, and the offer is gone once the address is confirmed; where the vault sends no
email it says who can confirm instead. On the Users page an administrator confirms an address a person typed
themselves, after being asked, and the account's line then says so no longer.

The account page's answers from the server are stood in for (what the server answers is held by
tests/test_email_confirmation_admin.py and tests/test_api_email_confirmation_live.py); the administrator's
confirmation goes to the running vault.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui


@pytest.fixture(autouse=True)
def _no_route_outlives_its_test(page: Page):
    yield
    page.unroute_all(behavior="ignoreErrors")


def _login(page: Page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_account(page: Page):
    page.click("#profile-btn")
    page.click("#settings-btn")
    expect(page.locator("#user-settings-modal")).to_be_visible(timeout=10000)


def test_your_account_offers_a_code_for_an_address_the_vault_has_not_confirmed(page: Page, temp_user):
    state = {"identities": [], "providers": [], "email": {"address": "typed@example.com", "can_send_code": True}}
    asked, tried = [], []
    page.route("**/users/me/identities", lambda route: route.fulfill(status=200, json=state))

    def request_code(route):
        asked.append(route.request.method)
        route.fulfill(status=202, json={"sent": True, "expires_in_minutes": 5})
    page.route("**/users/me/email/confirmation/request", request_code)

    def confirm(route):
        code = (route.request.post_data_json or {}).get("code")
        tried.append(code)
        if code == "ab12cd34ef56":
            state["email"] = None
            route.fulfill(status=200, json={"email": "typed@example.com", "email_confirmed": True})
        else:
            route.fulfill(status=400, json={"detail": "That code is invalid or has expired."})
    page.route("**/users/me/email/confirmation", confirm)

    _login(page, temp_user["_username"], temp_user["_password"])
    _open_account(page)
    box = page.locator("#us-email-confirm")
    expect(box).to_be_visible(timeout=10000)
    expect(box).to_contain_text("typed@example.com")
    expect(box).to_contain_text("is not confirmed yet")
    expect(page.locator("#us-email-confirm-row")).to_be_hidden()          # no code to type before one was sent
    assert asked == [] and tried == []
    page.click("#us-email-confirm-send")
    expect(page.locator("#us-email-confirm-row")).to_be_visible(timeout=8000)
    expect(page.locator("#us-email-confirm-send")).to_have_text("Send another code")
    assert asked == ["POST"]
    # Nothing typed: nothing is sent. A wrong code: said in the server's words, and the offer stays.
    page.click("#us-email-confirm-submit")
    page.wait_for_timeout(300)
    assert tried == []
    # The code is letters and digits: the field asks a phone for its full keyboard, without capitals.
    field = page.locator("#us-email-confirm-code")
    assert field.get_attribute("inputmode") == "text" and field.get_attribute("autocapitalize") == "off"
    page.fill("#us-email-confirm-code", "000000000000")
    page.click("#us-email-confirm-submit")
    expect(page.locator(".toast").filter(has_text="invalid or has expired").first).to_be_visible(timeout=8000)
    assert tried == ["000000000000"]
    expect(box).to_be_visible()
    expect(page.locator("#us-email-confirm-submit")).to_be_enabled()
    # The right code, with Enter: confirmed, and there is nothing left to offer.
    page.fill("#us-email-confirm-code", " ab12cd34ef56 ")
    page.press("#us-email-confirm-code", "Enter")
    expect(page.locator("#us-email-confirm")).to_have_count(0, timeout=10000)
    assert tried == ["000000000000", "ab12cd34ef56"]
    expect(page.locator("#us-identities-section")).to_be_hidden()


def test_where_the_vault_sends_no_email_your_account_says_who_can_confirm(page: Page, temp_user):
    state = {"identities": [], "providers": [], "email": {"address": "typed@example.com", "can_send_code": False}}
    page.route("**/users/me/identities", lambda route: route.fulfill(status=200, json=state))
    _login(page, temp_user["_username"], temp_user["_password"])
    _open_account(page)
    box = page.locator("#us-email-confirm")
    expect(box).to_be_visible(timeout=10000)
    # What an administrator's confirmation costs here is said with it; no provider can be linked from this page,
    # so nothing points to one.
    expect(page.locator("#us-email-confirm-by-admin")).to_contain_text("An administrator can confirm your address")
    expect(page.locator("#us-email-confirm-by-admin")).to_contain_text("held for up to 14 days")
    expect(box).not_to_contain_text("Link your organisation")
    expect(page.locator("#us-email-confirm-send")).to_have_count(0)
    # Where a provider can be linked from this page, that way comes first: it needs no confirmed address.
    state["providers"] = [{"id": "11111111-1111-4111-8111-111111111111", "label": "Sign in with Contoso",
                           "name": "Contoso", "sso_only": False}]
    page.evaluate("() => window.Sso && Sso.renderAccount && Sso.renderAccount()")
    expect(box).to_contain_text("Link your organisation's sign-in above instead", timeout=10000)
    state["providers"] = []
    # And with nothing to say of the address, the section says nothing of it.
    state["email"] = None
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _open_account(page)
    page.wait_for_timeout(500)
    expect(page.locator("#us-email-confirm")).to_have_count(0)


def test_an_administrator_confirms_on_the_users_page_an_address_a_person_typed(page: Page, admin):
    """The Users page offers it where the server says a confirmation would help (stood in for here: no provider
    is set up on this stack); the confirmation itself goes to the running vault."""
    driver, made = admin.create_user(role="admin"), admin.create_user(role="user")
    try:
        person = ApiClient()
        person.login(made["_username"], made["_password"])
        typed = unique("typed") + "@example.com"
        r = person.patch("/users/me", json={"email": typed, "current_password": made["_password"]})
        if r.status_code == 202 or (r.status_code == 200 and r.json().get("email") != typed):
            pytest.skip("this stack asks for an emailed code before an address changes")
        assert r.status_code == 200, r.text
        sent = []

        def users(route):
            if route.request.method == "PATCH":
                sent.append(route.request.post_data_json)
                return route.continue_()
            response = route.fetch()
            rows = response.json()
            for row in rows if isinstance(rows, list) else []:
                row["email_confirm_wanted"] = row.get("id") == made["id"] and not row.get("email_confirmed")
            route.fulfill(response=response, json=rows)
        page.route("**/users", users)
        page.route(f"**/users/{made['id']}", users)
        _login(page, driver["_username"], driver["_password"])
        page.evaluate("document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
        expect(page.locator("#users-section")).to_be_visible(timeout=10000)
        page.fill("#users-search", made["_username"])
        row = page.locator(f'.exp-row[data-id="{made["id"]}"]')
        expect(row).to_have_count(1, timeout=10000)
        row.click()
        note = page.locator(f'.credential-change-note[data-user-id="{made["id"]}"]')
        expect(note).to_contain_text("Email address not confirmed")
        button = page.locator(f'.confirm-email-btn[data-user-id="{made["id"]}"]')
        expect(button).to_be_visible(timeout=8000)
        # Asked first, with the address named; Escape answers no.
        button.click()
        modal = page.locator("#confirm-modal.active")
        expect(modal).to_be_visible(timeout=8000)
        expect(modal).to_contain_text(typed)
        expect(modal).to_contain_text("zero-knowledge vaults ask for a code")      # what else the confirmation does
        page.keyboard.press("Escape")
        page.wait_for_timeout(300)
        assert sent == []
        button.click()
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator(".toast").filter(has_text="Email address confirmed for").first).to_be_visible(timeout=10000)
        assert sent == [{"confirm_email": typed}]                # the address that was shown, named
        mine = next(u for u in admin.get("/users").json() if u["id"] == made["id"])
        assert mine["email_confirmed"] is True and mine["email"] == typed
        # The list was read again. With the account's row open once more, its other actions are there and the
        # confirmation is not: nothing is left to confirm, and its line says so no longer.
        opened = page.locator(f'.copy-reset-link-btn[data-user-id="{made["id"]}"]')
        for _ in range(20):
            if opened.count() and opened.first.is_visible():
                break
            page.locator(f'.exp-row[data-id="{made["id"]}"]').click()
            page.wait_for_timeout(300)
        expect(opened.first).to_be_visible(timeout=8000)
        expect(page.locator(f'.confirm-email-btn[data-user-id="{made["id"]}"]')).to_have_count(0)
        expect(page.locator(f'.credential-change-note[data-user-id="{made["id"]}"]')).not_to_contain_text(
            "Email address not confirmed")
    finally:
        admin.delete_user(made["id"])
        admin.delete_user(driver["id"])
