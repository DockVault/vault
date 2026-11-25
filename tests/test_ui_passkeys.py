"""Passkeys in the browser (static/js/passkeys.js and its callers in app.js) against a running vault, with Chromium's
virtual authenticator (the DevTools WebAuthn domain): a person adds a first passkey from Your account (proving the
password), signs in with it from the button without a username, renames and removes it under the step-up proved with
the passkey itself; an administrator's passkey leads to the password step and then serves as the second factor.

Needs the vault at a localhost address (a secure context) that is its configured address (the first ALLOWED_HOSTS
entry): its host is the relying-party id."""
import pytest
import requests
from playwright.sync_api import Page, expect

from _ui_hand_over import expect_reason, mark_old, replaced, still_old, wait_new_page

pytestmark = pytest.mark.ui


@pytest.fixture(autouse=True)
def _a_stack_where_a_passkey_can_be_made(base_url):
    """Every test here makes or uses a passkey. A vault with no configured address refuses them all (and has its own
    tests for that), so on such a stack these are skipped, with the reason, instead of failing one by one."""
    methods = requests.get(f"{base_url}/auth/policy", timeout=15).json().get("methods") or {}
    if not methods.get("passkeys"):
        pytest.skip("this stack offers no passkey sign-in: no address a passkey can be made at (ALLOWED_HOSTS)")


@pytest.fixture
def authenticator(page: Page):
    """A platform authenticator that holds discoverable keys, verifies the person and answers at once."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    made = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True}})
    yield cdp, made["authenticatorId"]
    try:
        cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": made["authenticatorId"]})
    except Exception:  # noqa: BLE001 -- the page may be gone already
        pass


# Chromium's virtual authenticator completes the browser's offer on the username field (conditional mediation) on its
# own, the moment it starts, where a person would choose from the field. The tests of the button and the forms switch
# the offer off; the offer has tests of its own.
NO_OFFER = "PublicKeyCredential.isConditionalMediationAvailable = async () => false;"


@pytest.fixture
def no_offer(page: Page):
    page.add_init_script(NO_OFFER)


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_account(page: Page):
    page.click("#profile-btn")
    page.click("#settings-btn")
    expect(page.locator("#user-settings-modal")).to_be_visible(timeout=8000)
    expect(page.locator("#us-passkeys-section")).to_be_visible(timeout=8000)


def _answer_prompt(page: Page, value: str):
    expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=8000)
    page.fill("#confirm-modal-input", value)
    page.click("#confirm-modal-confirm-btn")


def _add_first_passkey(page: Page, password: str, label: str):
    _open_account(page)
    page.click("#us-passkey-add")
    _answer_prompt(page, password)            # an account with no factor yet proves its password
    _answer_prompt(page, label)               # the name for the new passkey
    expect(page.locator("#us-passkeys-body .passkey-row")).to_have_count(1, timeout=10000)
    expect(page.locator("#us-passkeys-body .passkey-row").first).to_contain_text(label)


def _close_account(page: Page):
    page.click("#user-settings-modal .modal-close")
    expect(page.locator("#user-settings-modal")).to_be_hidden(timeout=8000)


def _sign_out(page: Page, stays: bool = False):
    """Sign out with the button. The page that showed the app is replaced by a new one on the sign-in screen, and
    that is the page the next sign-in is made on; ``stays`` is for a test that holds the replacement back and reads
    the page the session ended on."""
    if page.locator("#user-settings-modal").is_visible():
        _close_account(page)
    if stays:
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        return
    with replaced(page):
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")


def test_a_person_adds_a_passkey_signs_in_with_it_and_manages_it(page: Page, no_offer, authenticator, fresh_user):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _add_first_passkey(page, fresh_user["_password"], "Laptop")
    _sign_out(page)
    # The button signs in without a username: the authenticator offers the discoverable key.
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible(timeout=8000)
    assert "webauthn" in (page.get_attribute("#username", "autocomplete") or "")
    page.click("#passkey-sign-in-btn")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    # A rename is the person's own label; a removal rides the account's step-up, proved here with the passkey itself.
    _open_account(page)
    row = page.locator("#us-passkeys-body .passkey-row").first
    row.get_by_role("button", name="Rename").click()
    _answer_prompt(page, "Work laptop")
    expect(page.locator("#us-passkeys-body .passkey-row").first).to_contain_text("Work laptop", timeout=10000)
    page.locator("#us-passkeys-body .passkey-row").first.get_by_role("button", name="Remove").click()
    page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#stepup-passkey-btn")).to_be_visible(timeout=8000)
    # The passkey is the only factor: no Confirm that could never succeed, and the dialog focuses itself, not the button.
    expect(page.locator("#stepup-modal .modal-footer .btn-primary")).to_be_hidden()
    assert page.get_attribute("#stepup-modal", "data-no-autofocus") is not None
    page.click("#stepup-passkey-btn")
    expect(page.locator("#us-passkeys-body .passkey-row")).to_have_count(0, timeout=10000)


def test_an_administrators_passkey_leads_to_the_password_step_and_together_they_sign_in(
        page: Page, no_offer, authenticator, fresh_admin):
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _add_first_passkey(page, fresh_admin["_password"], "Security key")
    _sign_out(page)
    page.click("#passkey-sign-in-btn")
    # An administrator always types the password after a passkey: the form comes back with the name filled in.
    expect(page.locator("#login-stage-note")).to_contain_text("Enter your password", timeout=10000)
    assert page.input_value("#username") == fresh_admin["_username"]
    assert page.get_attribute("#username", "readonly") is not None
    expect(page.locator("#passkey-sign-in-btn")).to_be_hidden()
    page.fill("#password", fresh_admin["_password"])
    page.click("#login-form button[type=submit]")
    # The passkey and the password are two factors: signed in, no further step.
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_after_a_password_the_card_offers_the_accounts_passkey_as_the_second_factor(
        page: Page, no_offer, authenticator, fresh_admin):
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _add_first_passkey(page, fresh_admin["_password"], "Security key")
    _sign_out(page)
    page.fill("#username", fresh_admin["_username"])
    page.fill("#password", fresh_admin["_password"])
    page.click("#login-form button[type=submit]")
    card = page.locator("#login-second-factor")
    expect(card.get_by_role("button", name="Use a passkey")).to_be_visible(timeout=10000)
    card.get_by_role("button", name="Use a passkey").click()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_wrong_password_at_the_password_step_keeps_the_step(page: Page, no_offer, authenticator, fresh_admin):
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _add_first_passkey(page, fresh_admin["_password"], "Security key")
    _sign_out(page)
    page.click("#passkey-sign-in-btn")
    expect(page.locator("#login-stage-note")).to_be_visible(timeout=10000)
    page.fill("#password", "not-the-password")
    page.click("#login-form button[type=submit]")
    expect(page.locator("#login-error")).to_be_visible(timeout=10000)
    # Still the passkey's sign-in: the name stays filled in and fixed.
    assert page.input_value("#username") == fresh_admin["_username"]
    assert page.get_attribute("#username", "readonly") is not None


def test_the_browsers_offer_on_the_username_field_signs_a_person_in(page: Page, authenticator, fresh_user):
    """With the offer on (the virtual authenticator answers it at once), the sign-in page signs the person in through
    it after a sign-out, with no button pressed and no username typed."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _add_first_passkey(page, fresh_user["_password"], "Laptop")
    _sign_out(page)
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible(timeout=8000)    # the page has read its policy
    page.locator("#username").blur()
    page.focus("#username")                   # the offer starts as the person comes to the field
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_the_offer_and_the_button_never_both_act(page: Page, authenticator, fresh_admin):
    """An administrator's passkey leads to the password step. With the offer completing on its own and the button
    pressed as well, the page holds one password step, and the password typed there signs in."""
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _add_first_passkey(page, fresh_admin["_password"], "Security key")
    _sign_out(page)
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible(timeout=8000)    # the page has read its policy
    tokens = []
    page.on("response", lambda r: tokens.append(r) if r.url.endswith("/auth/passkeys/sign-in/verify") else None)
    page.locator("#username").blur()
    page.focus("#username")                   # the offer starts, and completes on its own
    # The button pressed as well (by script: the offer may already have hidden it, which is the race).
    page.evaluate("document.getElementById('passkey-sign-in-btn').click()")
    expect(page.locator("#login-stage-note")).to_be_visible(timeout=10000)
    page.wait_for_timeout(1500)               # let any second flow land: it must change nothing
    # Whatever answered last is the step the page holds, and the page shows it once.
    answered = [r.json().get("pre_auth_token") for r in tokens if r.ok]
    assert answered and page.evaluate("_passwordStage && _passwordStage.token") in answered
    assert page.locator("#login-stage-note").count() == 1
    page.fill("#password", fresh_admin["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_browser_that_never_used_a_passkey_here_asks_for_no_challenge_from_the_username_field(
        page: Page, authenticator):
    """The username field's offer is for a browser that has used or added a passkey here; any other browser keeps
    the button and asks the server for nothing as the field is used."""
    asked = []
    page.on("request", lambda r: asked.append(r.url) if "/auth/passkeys/sign-in/options" in r.url else None)
    page.goto("/")
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible(timeout=8000)
    page.focus("#username")
    page.fill("#username", "someone")
    page.wait_for_timeout(1000)
    assert asked == []


def test_a_field_that_already_has_the_cursor_gets_its_offer(page: Page, authenticator, fresh_user):
    """The cursor is in the username field before the page has read its policy: the offer starts as soon as it has,
    without waiting for a focus event that will not come."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _add_first_passkey(page, fresh_user["_password"], "Laptop")
    _sign_out(page)
    # The policy is held back until the cursor is in the field, so no focus event can start the offer.
    held = []

    def hold(route):
        held.append(route)

    page.route("**/auth/policy", hold)
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=8000)
    page.evaluate("document.getElementById('username').focus()")
    page.wait_for_timeout(300)
    assert held, "the page asked for its policy"
    assert page.evaluate("document.activeElement && document.activeElement.id") == "username"
    for route in held:
        route.continue_()
    page.unroute("**/auth/policy")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_the_password_step_has_a_way_out_and_ends_when_the_attempt_is_over(page: Page, no_offer, authenticator,
                                                                             fresh_admin):
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _add_first_passkey(page, fresh_admin["_password"], "Security key")
    _sign_out(page)
    page.click("#passkey-sign-in-btn")
    expect(page.locator("#login-stage-note")).to_be_visible(timeout=10000)
    # "Use another account": the name free again, the passkey button back.
    page.click("#login-stage-cancel")
    assert page.get_attribute("#username", "readonly") is None and page.input_value("#username") == ""
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible()
    expect(page.locator("#login-stage-note")).to_be_hidden()
    # Back into the step, then wrong passwords until the attempt is spent: the step ends on its own.
    page.click("#passkey-sign-in-btn")
    expect(page.locator("#login-stage-note")).to_be_visible(timeout=10000)
    for _ in range(8):
        page.fill("#password", "not-the-password")
        page.click("#login-form button[type=submit]")
        expect(page.locator("#login-error")).to_be_visible(timeout=10000)
        if page.get_attribute("#username", "readonly") is None:
            break
        page.wait_for_timeout(200)
    assert page.get_attribute("#username", "readonly") is None
    expect(page.locator("#login-error")).to_contain_text("start again")
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible()


def test_a_structured_refusal_is_shown_in_words(page: Page, no_offer, fresh_user):
    """A refusal the server words as {reason, message} reaches the person as its message."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    said = page.evaluate("""apiRequest('/users/me/passkeys/register/verify', {method: 'POST', silent: true,
        body: JSON.stringify({challenge_id: 'no-such-challenge', credential: {type: 'public-key'}})})
        .then(() => 'accepted', (e) => e.message)""")
    assert said and said != "[object Object]" and said != "accepted", said



def _signed_out_with_the_replacement_waiting(page: Page, user):
    """Signed out with a passkey on the account, on the page the session ended on: the page that replaces it waits
    for the server to answer (/health), and it does not answer yet."""
    _login(page, user["_username"], user["_password"])
    _add_first_passkey(page, user["_password"], "Laptop")
    _close_account(page)
    mark_old(page)
    page.route("**/health", lambda route: route.abort())
    _sign_out(page, stays=True)
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible(timeout=8000)
    assert still_old(page)


def _hold_the_passkey_answer(page: Page):
    held = []
    page.route("**/auth/passkeys/sign-in/verify", lambda route: held.append(route))
    page.click("#passkey-sign-in-btn")
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(100)
    assert len(held) == 1, "the passkey's answer never left the page"
    # The server answers again: without a sign-in under way the page would be replaced within a few seconds.
    page.unroute("**/health")
    page.wait_for_timeout(4500)
    assert still_old(page), "the page was replaced under a passkey sign-in"
    return held[0]


def test_a_passkey_sign_in_under_way_is_not_cut_off_by_the_page_that_replaces_a_signed_out_one(
        page: Page, no_offer, authenticator, fresh_user):
    """After a sign-out a fresh page replaces the one the session ended on. A person who pressed the passkey button
    meanwhile is signing in: the page waits for that sign-in, as it does for a password, and the session it makes
    is opened by the new page."""
    _signed_out_with_the_replacement_waiting(page, fresh_user)
    answer = _hold_the_passkey_answer(page)
    answer.continue_()
    wait_new_page(page, 20000)                # never the app on the page that ended a session
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=20000)


def test_a_refused_passkey_sign_in_lets_the_page_be_replaced_and_the_new_page_says_why(
        page: Page, no_offer, authenticator, fresh_user):
    _signed_out_with_the_replacement_waiting(page, fresh_user)
    answer = _hold_the_passkey_answer(page)
    answer.fulfill(status=401, content_type="application/json",
                   body='{"detail": "That passkey was not accepted here."}')
    wait_new_page(page, 15000)
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    expect_reason(page, "That passkey was not accepted here.")


def test_the_users_page_lists_how_each_account_signs_in(page: Page, no_offer, authenticator, fresh_user, admin_creds):
    """An administrator sees, for every account, the ways it signs in: the password, and its passkeys once it has
    any. The column sits between the role and the departments, and an opened row still spans the whole table."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _add_first_passkey(page, fresh_user["_password"], "Laptop")
    _sign_out(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    table = page.locator("#users-list table")
    expect(table).to_be_visible(timeout=10000)
    titles = [t.strip() for t in table.locator("thead th").all_text_contents()]
    assert titles[titles.index("Role") + 1] == "Sign-in methods" and titles[titles.index("Role") + 2] == "Departments"
    page.fill("#users-search", fresh_user["_username"])
    row = table.locator("tbody tr", has_text=fresh_user["_username"]).first
    methods = row.locator("td.col-methods .badge")
    expect(methods).to_have_text(["Password", "Passkey"])
    # The account's details, opened, take the table's full width with the new column in it.
    row.locator(".exp-toggle").click()
    detail = table.locator("tbody td[colspan]").first
    expect(detail).to_be_visible()
    assert detail.get_attribute("colspan") == str(len(titles))


def test_an_administrator_removes_someones_passkey_from_the_users_page(page: Page, no_offer, authenticator, fresh_user,
                                                                       admin_creds):
    """The account's details list its passkeys; "Remove" says what a removal does (it signs the person out everywhere
    and counts as a change to their sign-in details) before it is sent, under the step-up of managing users when one
    is asked, and the list is read again."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _add_first_passkey(page, fresh_user["_password"], "Laptop")
    _sign_out(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    table = page.locator("#users-list table")
    expect(table).to_be_visible(timeout=10000)
    page.fill("#users-search", fresh_user["_username"])
    row = table.locator("tbody tr", has_text=fresh_user["_username"]).first
    row.locator(".exp-toggle").click()
    passkeys = table.locator(".user-passkeys-list .user-passkey-item")
    expect(passkeys).to_have_count(1, timeout=10000)
    expect(passkeys.first).to_contain_text("Laptop")
    passkeys.first.get_by_role("button", name="Remove the passkey Laptop").click()
    message = page.locator("#confirm-modal-message")
    expect(message).to_contain_text("sessions end, everywhere", timeout=8000)
    expect(message).to_contain_text("It counts as a change to their sign-in details")
    page.click("#confirm-modal-confirm-btn")
    stepup = page.locator("#stepup-modal.active")
    removed = table.locator(".user-passkeys-list", has_text="No passkeys.")
    expect(stepup.or_(removed)).to_be_visible(timeout=10000)
    if stepup.is_visible():
        page.fill("#stepup-password-input", admin_creds["password"])
        page.locator("#stepup-modal-body .btn-primary").click()
    expect(removed).to_be_visible(timeout=10000)
    expect(row.locator("td.col-methods .badge")).to_have_text(["Password"])


def test_the_questions_asked_around_a_passkey_are_the_pages_ordinary_dialogs(page: Page, no_offer, authenticator,
                                                                           fresh_user):
    """Removing and naming a passkey ask through the page's own dialogs: named for assistive technology, closed by
    Escape as an answer of no, with focus back on the button that asked and the account dialog under them standing."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _add_first_passkey(page, fresh_user["_password"], "Laptop")
    row = page.locator("#us-passkeys-body .passkey-row").first
    confirm = page.locator("#confirm-modal")
    row.get_by_role("button", name="Remove").click()
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=8000)
    assert confirm.get_attribute("role") == "dialog" and confirm.get_attribute("aria-modal") == "true"
    expect(page.locator("#confirm-modal-title")).to_have_text("Remove passkey")
    assert page.evaluate("() => document.getElementById('confirm-modal').contains(document.activeElement)")
    page.keyboard.press("Escape")
    expect(page.locator("#confirm-modal.active")).to_have_count(0)
    expect(page.locator("#user-settings-modal")).to_be_visible()
    expect(page.locator("#stepup-modal.active")).to_have_count(0)      # an answer of no asks nothing of the server
    expect(page.locator("#us-passkeys-body .passkey-row")).to_have_count(1)
    assert page.evaluate("() => document.activeElement && document.activeElement.textContent") == "Remove"
    # The name: the cursor is in the field, and Escape leaves the name as it was.
    row.get_by_role("button", name="Rename").click()
    expect(page.locator("#confirm-modal-input")).to_be_focused(timeout=8000)
    page.fill("#confirm-modal-input", "Something else")
    page.keyboard.press("Escape")
    expect(page.locator("#confirm-modal.active")).to_have_count(0)
    assert page.evaluate("() => document.activeElement && document.activeElement.textContent") == "Rename"
    _close_account(page)
    _open_account(page)
    expect(page.locator("#us-passkeys-body .passkey-row").first).to_contain_text("Laptop")
    expect(page.locator("#us-passkeys-body .passkey-row").first).not_to_contain_text("Something else")


# --------------------------------------------------------------------------- a passkey the role must hold, at the sign-in

def _held(pre_auth_token, **fields):
    """A sign-in held for one more step, as the server answers it."""
    body = {"access_token": None, "second_factor_required": True, "stage": "second_factor", "enrollment_required": False,
            "methods": [], "enrollment_methods": [], "pre_auth_token": pre_auth_token}
    body.update(fields)
    return body


class HeldSignIn:
    """The server's side of a sign-in that is held step by step, stood in for at the page's requests: a grace that
    has run out cannot be made on a running vault, so the holds are answered here. The registration options are the
    account's own from the vault (the device makes a real key), and the last answer carries a real session of the
    account, so the page ends signed in. ``seen`` is every request, in order, with the token it carried."""

    def __init__(self, page: Page, user, *, first, after_code=None):
        from conftest import ApiClient
        self.user = user
        self.api = ApiClient()
        self.api.login(user["_username"], user["_password"])
        self.options = self.fresh_options()
        self.seen = []
        self.sent = None
        self.verify_answer = (201, {"passkey": {"id": "k"}, "access_token": self.api.token, "token_type": "bearer"})

        def bearer(route):
            return (route.request.headers.get("authorization") or "").replace("Bearer ", "")

        def login(route):
            self.seen.append(("login", ""))
            route.fulfill(status=200, json=first)

        def code(route):
            self.seen.append(("code", bearer(route)))
            route.fulfill(status=200, json=after_code)

        def options(route):
            self.seen.append(("options", bearer(route)))
            route.fulfill(status=200, json=self.options)

        def verify(route):
            self.sent = route.request.post_data_json or {}
            self.seen.append(("verify", bearer(route)))
            route.fulfill(status=self.verify_answer[0], json=self.verify_answer[1])

        page.route("**/auth/login", login)
        page.route("**/auth/second-factor/verify", code)
        page.route("**/users/me/passkeys/register/options", options)
        page.route("**/users/me/passkeys/register/verify", verify)

    def fresh_options(self):
        r = self.api.post("/users/me/passkeys/register/options", json={"current_password": self.user["_password"]})
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture(autouse=True)
def _no_stand_in_outlives_its_test(page: Page):
    yield
    page.unroute_all(behavior="ignoreErrors")


def _type_the_password(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")


def test_a_required_passkey_is_set_up_at_the_sign_in_after_the_accounts_code(page: Page, no_offer, authenticator,
                                                                             fresh_user):
    """An account that holds an authenticator and owes the passkey of its role: the page asks for the code, then
    shows the enrollment that follows the code (a hold after a step is shown, not dropped), and the answer to the
    new key signs the person in. Each request carries the token of the hold it answers."""
    held = HeldSignIn(page, fresh_user, first=_held("held-1", methods=["totp", "recovery"]),
                      after_code=_held("held-2", enrollment_required=True, enrollment_methods=["passkey"]))
    _type_the_password(page, fresh_user)
    expect(page.locator("#sf-code-input")).to_be_visible(timeout=8000)
    expect(page.locator("#sf-passkey-enroll")).to_have_count(0)            # no enrollment before the code
    page.fill("#sf-code-input", "123456")
    page.keyboard.press("Enter")
    expect(page.locator("#sf-passkey-enroll")).to_be_visible(timeout=8000)
    expect(page.locator("#login-second-factor")).to_contain_text("Add a passkey to finish signing in")
    expect(page.locator("#sf-enroll-authenticator")).to_have_count(0)      # only the passkey is owed
    expect(page.locator("#sf-code-input")).to_have_count(0)
    page.click("#sf-passkey-enroll")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert held.seen == [("login", ""), ("code", "held-1"), ("options", "held-2"), ("verify", "held-2")], held.seen
    assert held.sent["challenge_id"] == held.options["challenge_id"] and held.sent["credential"]["id"], held.sent
    assert held.sent["credential"]["type"] == "public-key" and held.sent["label"] is None


WHY_AGAIN = {
    "passkeys_at_another_address": "Your passkeys cannot be used at the address this vault has now, so you set a "
                                   "second factor up again here.",
    "passkeys_no_longer_accepted": "Your passkeys are of a kind this vault no longer accepts, so you set a second "
                                   "factor up again here.",
    "passkeys_without_verification": "Your passkeys that work here have never checked a PIN, a fingerprint or a "
                                     "face, which this vault now asks for, so you set a second factor up again here.",
    "passkeys_turned_off": "Passkeys are turned off on this vault, so you set a second factor up again here. Your "
                           "passkeys are kept, and count again if passkeys are turned back on.",
}


@pytest.mark.parametrize("why", [*WHY_AGAIN, None])
def test_an_account_that_holds_passkeys_and_sets_a_factor_up_again_is_told_why(page: Page, no_offer, authenticator,
                                                                              fresh_user, why):
    """The vault moved to another address, the account's keys are of a kind that was removed or never checked the
    person while the vault asks for that, or passkeys are turned off: the sign-in is held for a set-up though the
    account holds passkeys. The card says why, in the server's reason's words; an account that simply owes its first
    factor is told nothing of the kind. With passkeys turned off the server offers no passkey: the authenticator app
    is what is set up."""
    more = {"set_up_again": why} if why else {}
    kinds = ["totp"] if why == "passkeys_turned_off" else ["passkey"]
    HeldSignIn(page, fresh_user, first=_held("held-1", enrollment_required=True, enrollment_methods=kinds, **more))
    if kinds == ["totp"]:
        page.route("**/users/me/second-factor/totp/enroll", lambda route: route.fulfill(status=200, json={
            "secret": "JBSWY3DPEHPK3PXP", "otpauth_uri": "otpauth://totp/x", "qr_svg": ""}))
    _type_the_password(page, fresh_user)
    if kinds == ["totp"]:
        expect(page.locator("#login-second-factor")).to_contain_text("Scan this QR code", timeout=10000)
    else:
        expect(page.locator("#sf-passkey-enroll")).to_be_visible(timeout=8000)
    note = page.locator("#login-second-factor .sf-set-up-again")
    if why:
        expect(note).to_have_text(WHY_AGAIN[why])
    else:
        expect(note).to_have_count(0)


def test_the_authenticators_set_up_says_why_on_the_step_with_the_code(page: Page, no_offer, fresh_user):
    """Where an authenticator is what is set up again, the reason stays on the step the person reads: the one with
    the QR code, not only the moment before it."""
    HeldSignIn(page, fresh_user, first=_held("held-1", enrollment_required=True, enrollment_methods=["totp"],
                                             set_up_again="passkeys_at_another_address"))
    page.route("**/users/me/second-factor/totp/enroll", lambda route: route.fulfill(status=200, json={
        "secret": "JBSWY3DPEHPK3PXP", "otpauth_uri": "otpauth://totp/x", "qr_svg": ""}))
    _type_the_password(page, fresh_user)
    box = page.locator("#login-second-factor")
    expect(box).to_contain_text("Scan this QR code", timeout=10000)
    expect(box.locator(".sf-set-up-again")).to_have_text(WHY_AGAIN["passkeys_at_another_address"])
    expect(box.locator(".sf-set-up-again")).to_have_count(1)


def test_an_account_with_no_factor_sets_its_required_passkey_up_after_the_password(page: Page, no_offer, authenticator,
                                                                                   fresh_user):
    """The first hold is the enrollment itself: the passkey card, never the authenticator-app wizard nobody asked
    for. A refusal is shown in the words the server gave and the card stays; the next try signs in."""
    held = HeldSignIn(page, fresh_user, first=_held("held-1", enrollment_required=True, enrollment_methods=["passkey"]))
    refusal = "Your role needs a passkey bound to one device: this one is synced between devices."
    held.verify_answer = (400, {"detail": {"reason": "synced_not_allowed", "message": refusal}})
    _type_the_password(page, fresh_user)
    expect(page.locator("#sf-passkey-enroll")).to_be_visible(timeout=8000)
    expect(page.locator("#sf-enroll-secret")).to_have_count(0)
    page.click("#sf-passkey-enroll")
    expect(page.locator("#login-second-factor [role=alert]")).to_have_text(refusal, timeout=10000)
    expect(page.locator("#sf-passkey-enroll")).to_be_enabled()
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    held.verify_answer = (201, {"passkey": {"id": "k"}, "access_token": held.api.token, "token_type": "bearer"})
    held.options = held.fresh_options()
    page.click("#sf-passkey-enroll")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert [kind for kind, _token in held.seen] == ["login", "options", "verify", "options", "verify"], held.seen
    assert {token for kind, token in held.seen if kind != "login"} == {"held-1"}


def test_where_an_authenticator_is_owed_too_the_passkey_comes_first_with_the_app_as_the_other_way(
        page: Page, no_offer, authenticator, fresh_user):
    """Both may be set up: the passkey card, with a way to the authenticator-app wizard, which starts with the same
    held sign-in and the password just typed. A browser that cannot make a passkey goes to the wizard at once."""
    HeldSignIn(page, fresh_user, first=_held("held-1", enrollment_required=True, enrollment_methods=["totp", "passkey"]))
    asked = []

    def enroll(route):
        asked.append((route.request.headers.get("authorization"), route.request.post_data_json))
        route.fulfill(status=409, json={"detail": "Stopped here by the test."})
    page.route("**/users/me/second-factor/totp/enroll", enroll)
    _type_the_password(page, fresh_user)
    expect(page.locator("#sf-passkey-enroll")).to_be_visible(timeout=8000)
    page.click("#sf-enroll-authenticator")
    expect(page.locator("#login-second-factor")).to_contain_text("Stopped here by the test.", timeout=8000)
    assert asked == [("Bearer held-1", {"current_password": fresh_user["_password"]})], asked
    # The same answer in a browser without passkeys: the wizard, with no passkey card before it.
    page.add_init_script("delete window.PublicKeyCredential;")
    asked.clear()
    _type_the_password(page, fresh_user)
    expect(page.locator("#login-second-factor")).to_contain_text("Stopped here by the test.", timeout=8000)
    expect(page.locator("#sf-passkey-enroll")).to_have_count(0)
    assert len(asked) == 1


def test_a_required_passkey_in_a_browser_that_cannot_make_one_says_so(page: Page, no_offer, fresh_user):
    page.add_init_script("delete window.PublicKeyCredential;")
    HeldSignIn(page, fresh_user, first=_held("held-1", enrollment_required=True, enrollment_methods=["passkey"]))
    _type_the_password(page, fresh_user)
    expect(page.locator("#login-second-factor")).to_contain_text("this browser cannot make one here", timeout=8000)
    expect(page.locator("#sf-passkey-enroll")).to_have_count(0)
    expect(page.locator("#login-second-factor")).to_contain_text("Back to sign in")


# --------------------------------------------------------------------------- a page opened at another address

ELSEWHERE = "https://vault.example.test"


def test_a_page_opened_at_another_address_says_where_passkeys_work_and_offers_none(page: Page, no_offer, fresh_user):
    """The vault answers to more than one name, and a passkey works at one: the configured address. A page opened at
    another offers no passkey button (the browser would refuse, in words that say nothing) and says where to go;
    the password form stays. Your account says the same in place of the Add button. The address the server names
    is stood in for: this stack is opened at its configured address, where every other test here finds the button."""
    def policy(route):
        response = route.fetch()
        body = response.json()
        body["methods"]["passkeys"] = True
        body["methods"]["origin"] = ELSEWHERE
        route.fulfill(response=response, json=body)

    def passkeys(route):
        if route.request.method != "GET":
            return route.fallback()
        response = route.fetch()
        body = response.json()
        body["origin"] = ELSEWHERE
        route.fulfill(response=response, json=body)
    page.route("**/auth/policy", policy)
    page.route("**/users/me/passkeys", passkeys)
    page.goto("/")
    note = page.locator("#login-origin-note")
    expect(note).to_be_visible(timeout=8000)
    # The vault's address may be the wrong one: where this page's address could serve passkeys in its place (a host
    # name over https, or localhost), the note says what to tell the administrator.
    here, host = page.evaluate("location.origin"), page.evaluate("location.hostname")
    told = ((here.startswith("https://") or host == "localhost")
            and not (host.startswith("[") or host.replace(".", "").isdigit()))
    tell = (f" If nothing answers there, tell your administrator: the vault's address is set to {ELSEWHERE}, and you "
            f"opened it at {here}.") if told else ""
    expect(note).to_have_text(f"Signing in with a passkey works at {ELSEWHERE}. Open the vault there to use it." + tell)
    assert note.locator("a").get_attribute("href") == ELSEWHERE + "/"
    expect(page.locator("#passkey-sign-in-btn")).to_be_hidden()
    expect(page.locator("#login-form")).to_be_visible()
    page.fill("#username", fresh_user["_username"])
    page.fill("#password", fresh_user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _open_account(page)
    expect(page.locator("#us-passkeys-body")).to_contain_text(
        f"Passkeys are added and used at {ELSEWHERE}. Open the vault there to add one." + tell, timeout=8000)
    expect(page.locator("#us-passkey-add")).to_have_count(0)


def test_at_the_configured_address_nothing_is_said_of_another(page: Page, no_offer, fresh_user):
    page.goto("/")
    expect(page.locator("#passkey-sign-in-btn")).to_be_visible(timeout=8000)
    expect(page.locator("#login-origin-note")).to_be_hidden()
    assert page.locator("#login-origin-note").text_content() == ""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    _open_account(page)
    expect(page.locator("#us-passkey-add")).to_be_visible(timeout=8000)
    expect(page.locator("#us-passkeys-body")).not_to_contain_text("Passkeys are added and used at")
