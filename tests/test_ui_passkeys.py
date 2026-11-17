"""Passkeys in the browser (static/js/passkeys.js and its callers in app.js) against a running vault, with Chromium's
virtual authenticator (the DevTools WebAuthn domain): a person adds a first passkey from Your account (proving the
password), signs in with it from the button without a username, renames and removes it under the step-up proved with
the passkey itself; an administrator's passkey leads to the password step and then serves as the second factor.

Needs the vault at a localhost address (a secure context) that is its configured address (the first ALLOWED_HOSTS
entry): its host is the relying-party id."""
import pytest
from playwright.sync_api import Page, expect

from _ui_hand_over import expect_reason, mark_old, replaced, still_old, wait_new_page

pytestmark = pytest.mark.ui


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
