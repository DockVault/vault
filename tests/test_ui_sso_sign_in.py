"""Single sign-on in the browser (static/js/sso.js and its callers in app.js): the provider buttons on the sign-in
screen, the page leaving for the provider and coming back, the tab's proof going out as a hash and coming back as
itself, a refusal said in the server's words, and what Your account shows of the linked providers.

The provider and the server's single sign-on routes are stood in for (the server's side has its own tests; a real
provider has its own lane): the page's part is what is proved here, against the running vault for everything else.
The stand-in for the provider is a page of the vault's own address that sends the browser back with the fragment
the callback would send."""
import hashlib
import re
import uuid

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import ApiClient

pytestmark = pytest.mark.ui

PROVIDER = str(uuid.uuid4())
OTHER = str(uuid.uuid4())
BUTTONS = [{"id": PROVIDER, "label": "Company sign-in", "kind": "oidc", "icon": "microsoft", "order": 1},
           {"id": OTHER, "label": "Contractors", "kind": "oidc", "icon": "generic", "order": 2}]


@pytest.fixture(autouse=True)
def _no_route_outlives_its_test(page: Page):
    yield
    page.unroute_all(behavior="ignoreErrors")


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


class Stand:
    """The server's single sign-on answers and the provider, stood in for on one page; what the page sent is kept."""

    def __init__(self, page: Page, base_url: str, providers=BUTTONS):
        self.page, self.base, self.starts, self.finishes, self.returns = page, base_url, [], [], "sso=code-1"
        self.finish_answer = None

        def policy(route):
            response = route.fetch()
            body = response.json()
            body.setdefault("methods", {})["providers"] = providers
            route.fulfill(response=response, json=body)
        page.route("**/auth/policy", policy)

        def start(route):
            self.starts.append((route.request.url, route.request.post_data_json or {}))
            route.fulfill(status=200, json={"authorization_url": f"{base_url}/__provider/authorize?x=1",
                                             "expires_in": 600})
        page.route(re.compile(r".*/auth/sso/[0-9a-f-]{36}/start$"), start)
        page.route(re.compile(r".*/users/me/identities/[0-9a-f-]{36}/(start|reauth)$"), start)

        def provider(route):
            route.fulfill(status=200, content_type="text/html",
                          body=f"<!doctype html><title>provider</title><script>location.replace('{base_url}/#{self.returns}')</script>")
        page.route("**/__provider/authorize*", provider)

        def finish(route):
            self.finishes.append((route.request.url, route.request.post_data_json or {}))
            status, body = self.finish_answer or (401, {"detail": "This sign-in code is not valid; start again."})
            route.fulfill(status=status, json=body)
        page.route("**/auth/finish", finish)
        page.route("**/users/me/identities/finish", finish)
        page.route("**/users/me/identities/reauth/finish", finish)

    def proof_matches(self) -> bool:
        """The verifier the finish carried is the one whose hash the start carried."""
        sent = self.starts[-1][1]["verifier_hash"]
        proof = self.finishes[-1][1]["verifier"]
        return hashlib.sha256(proof.encode()).hexdigest() == sent and len(sent) == 64


def _sign_in_screen(page: Page):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def _login(page: Page, username, password):
    _sign_in_screen(page)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_vault_without_providers_shows_no_button(page: Page):
    _sign_in_screen(page)
    expect(page.locator("#login-submit")).to_be_enabled(timeout=15000)
    expect(page.locator("#sso-sign-in")).to_be_hidden()
    assert page.locator("#sso-sign-in button").count() == 0


def test_a_sign_in_through_a_provider_leaves_the_page_and_comes_back_into_the_app(page: Page, base_url, fresh_user):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    stand = Stand(page, base_url)
    stand.finish_answer = (200, ApiClient(base_url).login(fresh_user["_username"], fresh_user["_password"]))
    _sign_in_screen(page)
    buttons = page.locator("#sso-sign-in .sso-sign-in-btn")
    expect(buttons).to_have_text(["Company sign-in", "Contractors"], timeout=15000)      # the administrator's order
    assert buttons.first.get_attribute("data-provider") == PROVIDER
    buttons.first.click()
    # The page left for the provider and came back; the code was turned into the session with this tab's proof.
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=20000)
    (url, sent), = stand.starts
    assert url.endswith(f"/auth/sso/{PROVIDER}/start") and set(sent) == {"verifier_hash"}
    (_url, finished), = stand.finishes
    assert finished["code"] == "code-1" and set(finished) == {"code", "verifier"} and stand.proof_matches()
    # Nothing of the flow is left: not in the address, not in the tab's storage.
    assert "#" not in page.url and "sso" not in page.url
    assert page.evaluate("() => sessionStorage.getItem('dv_sso_flow')") is None
    expect(page.locator("#profile-btn")).to_be_visible()
    assert errors == [], errors


def test_a_refusal_is_said_in_the_servers_words_for_its_reason_and_an_unknown_one_in_general_words(page: Page, base_url):
    reasons = requests.get(f"{base_url}/auth/sso/reasons", timeout=15).json()["reasons"]
    assert "no account for you here" in reasons["no_account"]
    Stand(page, base_url)
    page.goto("/#sso-error=no_account")
    note = page.locator("#login-error")
    expect(note).to_have_text(reasons["no_account"], timeout=15000)
    assert "#" not in page.url
    expect(page.locator("#login-form")).to_be_visible()            # the form is there to sign in another way
    # (A provider's redirect is a new page load; two visits that differ only by the fragment are not.)
    page.goto("about:blank")
    page.goto("/#sso-error=something_made_up")
    expect(page.locator("#login-error")).to_have_text("Single sign-on did not finish. Try again.", timeout=15000)
    # A provider's own words never reach the page: a fragment that is not a reason code is not single sign-on's.
    page.goto("about:blank")
    page.goto("/#sso-error=<b>pay%20here</b>")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    assert "pay here" not in page.locator("#login-screen").inner_text()


def test_a_code_that_came_to_a_tab_that_did_not_start_it_is_not_used(page: Page, base_url):
    stand = Stand(page, base_url)
    page.goto("/#sso=someone-elses-code")
    expect(page.locator("#login-error")).to_have_text(
        "That sign-in did not come back to the tab that started it. Start again.", timeout=15000)
    assert stand.finishes == [] and "#" not in page.url


def test_a_finish_the_server_refuses_is_shown_and_the_page_can_be_used_again(page: Page, base_url, fresh_user):
    stand = Stand(page, base_url)
    _sign_in_screen(page)
    page.locator("#sso-sign-in .sso-sign-in-btn").nth(1).click()
    expect(page.locator("#login-error")).to_have_text("This sign-in code is not valid; start again.", timeout=20000)
    assert stand.starts[0][0].endswith(f"/auth/sso/{OTHER}/start") and len(stand.finishes) == 1
    expect(page.locator("#login-screen")).to_be_visible()
    expect(page.locator("#sso-sign-in .sso-sign-in-btn").first).to_be_enabled()
    # The password form still signs in.
    page.fill("#username", fresh_user["_username"])
    page.fill("#password", fresh_user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_start_the_server_refuses_is_said_on_the_sign_in_screen(page: Page, base_url):
    Stand(page, base_url)
    page.route(re.compile(r".*/auth/sso/[0-9a-f-]{36}/start$"), lambda route: route.fulfill(status=409, json={
        "detail": {"reason": "no_public_address", "message": "Single sign-on needs the vault's public address."}}))
    _sign_in_screen(page)
    page.locator("#sso-sign-in .sso-sign-in-btn").first.click()
    expect(page.locator("#login-error")).to_have_text("Single sign-on needs the vault's public address.", timeout=15000)
    expect(page.locator("#sso-sign-in .sso-sign-in-btn").first).to_be_enabled()
    assert page.evaluate("() => sessionStorage.getItem('dv_sso_flow')") is None


def test_a_link_an_organisation_hands_out_starts_its_provider_at_once(page: Page, base_url, fresh_user):
    stand = Stand(page, base_url, providers=[])          # a provider that has no button on the sign-in page
    stand.finish_answer = (200, ApiClient(base_url).login(fresh_user["_username"], fresh_user["_password"]))
    page.goto(f"/?sso={PROVIDER}")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=20000)
    assert stand.starts[0][0].endswith(f"/auth/sso/{PROVIDER}/start") and stand.proof_matches()
    assert "sso=" not in page.url
    # Anything that is not a provider's id starts nothing.
    stand.starts.clear()
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.goto("/?sso=javascript:alert(1)")
    expect(page.locator("#login-submit")).to_be_enabled(timeout=15000)
    assert stand.starts == [] and "sso=" not in page.url


def test_your_account_lists_the_linked_providers_and_links_and_unlinks(page: Page, base_url, fresh_user):
    stand = Stand(page, base_url, providers=[])
    stand.finish_answer = (200, {"linked": True})
    state = {"identities": [{"id": "identity-1", "provider_id": OTHER, "provider": "Contractors",
                             "linked_at": "2026-11-01T10:00:00Z", "linked_by": "self", "last_sign_in_at": None}],
             "providers": [{"id": PROVIDER, "label": "Company sign-in", "icon": "microsoft", "linked": False, "reauth": True},
                           {"id": OTHER, "label": "Contractors", "icon": "generic", "linked": True, "reauth": False}]}
    removed = []

    def identities(route):
        if route.request.method == "DELETE":
            removed.append(route.request.url.rsplit("/", 1)[1])
            state["identities"] = []
            route.fulfill(status=200, json={"unlinked": True})
        else:
            route.fulfill(status=200, json=state)
    page.route("**/users/me/identities", identities)
    page.route("**/users/me/identities/identity-1", identities)
    _login(page, fresh_user["_username"], fresh_user["_password"])
    page.click("#profile-btn")
    page.click("#settings-btn")
    section = page.locator("#us-identities-section")
    expect(section).to_be_visible(timeout=10000)
    row = section.locator(".identity-row")
    expect(row).to_have_count(1)
    expect(row).to_contain_text("Contractors")
    expect(row).to_contain_text("never signed in through it")
    expect(section.locator(".identity-link")).to_have_text(["Link Company sign-in"])       # not the one already linked
    # Unlink asks first; Escape answers no.
    row.get_by_role("button", name="Unlink").click()
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=8000)
    page.keyboard.press("Escape")
    assert removed == []
    row.get_by_role("button", name="Unlink").click()
    page.click("#confirm-modal-confirm-btn")
    expect(section.locator(".identity-row")).to_have_count(0, timeout=10000)
    assert removed == ["identity-1"]
    # Link leaves for the provider and comes back; the link is claimed with this tab's proof and the dialog reopens.
    stand.returns = "sso-linked=link-code"
    section.locator(".identity-link").click()
    for _ in range(100):
        if stand.finishes:
            break
        page.wait_for_timeout(200)
    expect(page.locator("#user-settings-modal")).to_be_visible(timeout=20000)
    assert stand.starts[-1][0].endswith(f"/users/me/identities/{PROVIDER}/start")
    assert stand.finishes[-1][0].endswith("/users/me/identities/finish")
    assert stand.finishes[-1][1]["code"] == "link-code" and stand.proof_matches()
    assert "#" not in page.url


def test_a_provider_only_account_is_told_what_a_passkey_is_for_and_confirms_at_its_provider_first(page: Page, base_url,
                                                                                               fresh_user):
    sentence = ("Your organisation signs you in through Company sign-in; this passkey confirms it's you after that, it "
                "does not replace it.")
    stand = Stand(page, base_url, providers=[])
    stand.finish_answer = (200, {"staged": True, "action": "account.second_factor", "expires_in": 120})
    asked = []

    def passkeys(route):
        route.fulfill(status=200, json={
            "passkeys": [], "limit": 20, "enabled": True, "requirement": {}, "provider_only": sentence,
            "first_proof": {"kind": "provider", "action": "account.second_factor",
                            "providers": [{"id": PROVIDER, "label": "Company sign-in"}]}})
    page.route("**/users/me/passkeys", passkeys)

    def options(route):
        asked.append(route.request.post_data_json or {})
        route.fulfill(status=409, json={"detail": "Stopped here by the test."})
    page.route("**/users/me/passkeys/register/options", options)
    _login(page, fresh_user["_username"], fresh_user["_password"])
    page.click("#profile-btn")
    page.click("#settings-btn")
    expect(page.locator("#us-passkeys-section .passkey-provider-only")).to_have_text(sentence, timeout=10000)
    stand.returns = "sso-stepup=confirm-code"
    page.click("#us-passkey-add")
    expect(page.locator("#confirm-modal-message")).to_contain_text("fresh sign-in at Company sign-in", timeout=8000)
    assert asked == []                                   # nothing is asked of the server before the confirmation
    page.click("#confirm-modal-confirm-btn")
    # Back from the provider: the confirmation is staged with this tab's proof, and the registration goes on.
    expect(page.locator("#user-settings-modal")).to_be_visible(timeout=20000)
    for _ in range(75):
        if asked:
            break
        page.wait_for_timeout(200)
    assert len(asked) == 1 and asked[0] == {}            # no password is sent: nobody knows one
    start_url, start_body = stand.starts[-1]
    assert start_url.endswith(f"/users/me/identities/{PROVIDER}/reauth")
    assert start_body["action"] == "account.second_factor" and len(start_body["verifier_hash"]) == 64
    assert stand.finishes[-1][0].endswith("/users/me/identities/reauth/finish")
    assert stand.finishes[-1][1]["code"] == "confirm-code" and stand.proof_matches()
