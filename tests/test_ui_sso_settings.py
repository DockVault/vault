"""Settings -> Sign-in -> Single sign-on in the browser (static/js/settings-sso.js), against the running vault: an
administrator adds a provider from a preset and finds the addresses to copy, fills in its connection with their
password, reads the server's sentence when a save or a turning-on is refused, runs a test sign-in and reads what
came back, sets who may sign in, and removes the provider.

The provider itself is stood in for (a page of the vault's own address that sends the browser back as the callback
would); everything an administrator saves goes to the running vault, under its real step-up.

Needs a stack with an address a provider can send a browser back to (ALLOWED_HOSTS naming the address the test
opens)."""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui

ISSUER = "https://login.example.org/realms/staff"
ACTION = "admin.auth_policy.write"


def _receipt(admin, boss):
    r = admin.post("/auth/second-factor/step-up", json={"action": ACTION, "password": boss["password"]})
    assert r.status_code == 200, r.text
    return {"X-Second-Factor": r.json()["receipt"]}


def _remove_by_api(admin, boss, name):
    """Take the test's provider away whatever state the test left it in."""
    for row in admin.get("/admin/sso/providers").json().get("providers", []):
        if row["name"] != name:
            continue
        if row["state"] == "enabled":
            admin.post(f"/admin/sso/providers/{row['id']}/state", json={"state": "disabled"},
                       headers=_receipt(admin, boss))
        admin.delete(f"/admin/sso/providers/{row['id']}", headers=_receipt(admin, boss))


@pytest.fixture(autouse=True)
def _no_route_outlives_its_test(page: Page):
    yield
    page.unroute_all(behavior="ignoreErrors")


@pytest.fixture
def boss(admin, base_url):
    """An administrator of the test's own: every change here asks the step-up, whose budget is kept per account, so
    the tests of this file do not spend the stack administrator's (nor each other's)."""
    made = admin.create_user(role="admin")
    yield {"username": made["_username"], "password": made["_password"]}
    admin.delete_user(made["id"])


@pytest.fixture
def provider_name(boss, base_url):
    name = unique("idp")
    yield name
    client = ApiClient(base_url)
    client.login(boss["username"], boss["password"])
    _remove_by_api(client, boss, name)


def _open(page: Page, boss):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", boss["username"])
    page.fill("#password", boss["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.locator('#settings-section .tab-btn[data-tab="signin"]').click()
    expect(page.locator("#signin-sso-card")).to_be_visible(timeout=10000)
    line = page.locator("#signin-sso-address")
    expect(line).to_be_visible(timeout=10000)
    if "No provider can be tested" in (line.text_content() or ""):
        pytest.skip("this stack has no address a provider can send a browser back to (ALLOWED_HOSTS)")


def _with_the_password(page: Page, boss):
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    page.fill("#stepup-password-input", boss["password"])
    page.locator("#stepup-modal-body .btn-primary").click()
    expect(page.locator("#stepup-modal.active")).to_be_hidden(timeout=10000)


def _add(page: Page, boss, name, preset="keycloak"):
    page.click("#signin-sso-add")
    expect(page.locator("#sso-provider-modal.active")).to_be_visible(timeout=8000)
    expect(page.locator("#sso-provider-modal .modal-close")).to_have_text("×")      # the close sign, not two wrong characters
    page.select_option("#sso-new-preset", preset)
    page.fill("#sso-new-name", name)
    page.click("#sso-new-add")
    _with_the_password(page, boss)
    expect(page.locator("#sso-provider-state")).to_have_text("Draft", timeout=10000)


def _fill_connection(page: Page, boss):
    page.fill("#sso-issuer", ISSUER)
    page.fill("#sso-client-id", "vault-client")
    page.fill("#sso-client-secret", "s3cret-value")
    page.click("#sso-save")
    _with_the_password(page, boss)
    expect(page.locator("#sso-provider-state")).to_have_text("Off · not tested", timeout=10000)


def test_an_administrator_adds_a_provider_and_finds_its_addresses(page: Page, boss, provider_name):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _open(page, boss)
    origin = page.evaluate("() => location.origin")
    expect(page.locator("#signin-sso-address")).to_contain_text("Providers send people back to " + origin)
    # The kind names the provider until the administrator types a name of their own.
    page.click("#signin-sso-add")
    page.select_option("#sso-new-preset", "entra")
    expect(page.locator("#sso-new-name")).to_have_value("Microsoft Entra ID")
    page.keyboard.press("Escape")
    expect(page.locator("#sso-provider-modal.active")).to_have_count(0)
    _add(page, boss, provider_name)
    # The draft has its addresses before anything else is typed, on the vault's own address.
    redirect = page.input_value("#sso-redirect-uri")
    assert re.fullmatch(re.escape(origin) + r"/auth/sso/[0-9a-f-]{36}/callback", redirect), redirect
    assert page.input_value("#sso-logout-uri") == redirect.replace("/callback", "/backchannel-logout")
    assert page.input_value("#sso-sign-in-link") == origin + "/?sso=" + redirect.split("/")[-2]
    expect(page.locator("#sso-icon")).to_have_value("keycloak")
    expect(page.locator("#sso-test")).to_be_disabled()            # nothing to test yet
    expect(page.locator("#sso-remove")).to_be_visible()
    # The list behind the dialog has it, in words.
    row = page.locator(f'#signin-sso-providers .sso-provider-row:has-text("{provider_name}")')
    expect(row.locator(".sso-provider-status")).to_have_text("Draft")
    expect(row).to_contain_text("0 linked accounts")
    assert errors == [], errors


def test_the_connection_is_saved_with_the_password_and_the_secret_is_never_shown_again(page: Page, boss,
                                                                                     provider_name):
    _open(page, boss)
    _add(page, boss, provider_name)
    # A value the server refuses is said in its words, by the field's name, and asks for no password.
    page.fill("#sso-issuer", "http://plain.example.org")
    page.click("#sso-save")
    said = page.locator("#sso-page-connection .sso-said")
    expect(said).to_have_text("Issuer: The endpoint must use https.", timeout=10000)
    expect(said).to_have_attribute("role", "alert")
    expect(page.locator("#stepup-modal.active")).to_have_count(0)
    _fill_connection(page, boss)
    expect(page.locator("#sso-client-secret")).to_have_value("")
    expect(page.locator("#sso-client-secret")).to_have_attribute("placeholder", "Stored. Type a new one to replace it.")
    assert "s3cret-value" not in page.content()
    expect(page.locator("#sso-test")).to_be_enabled()
    # Saving with nothing changed says so and asks for nothing.
    page.click("#sso-save")
    expect(page.locator("#sso-page-connection .sso-said")).to_have_text("Nothing was changed.")
    expect(page.locator("#stepup-modal.active")).to_have_count(0)
    # It holds after a reload, the secret still out of sight.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    page.locator('#settings-section .tab-btn[data-tab="signin"]').click()
    row = page.locator(f'#signin-sso-providers .sso-provider-row:has-text("{provider_name}")')
    expect(row.locator(".sso-provider-status")).to_have_text("Off · not tested", timeout=10000)
    expect(row).to_contain_text(ISSUER)
    row.get_by_role("button", name="Open").click()
    expect(page.locator("#sso-issuer")).to_have_value(ISSUER, timeout=10000)
    expect(page.locator("#sso-client-secret")).to_have_value("")
    assert "s3cret-value" not in page.content()


def test_a_provider_is_not_turned_on_before_a_test_sign_in_passed(page: Page, boss, provider_name):
    _open(page, boss)
    _add(page, boss, provider_name)
    _fill_connection(page, boss)
    page.click("#sso-toggle")
    toast = page.locator(".toast", has_text="Run a test sign-in first")
    expect(toast).to_be_visible(timeout=10000)
    expect(page.locator("#stepup-modal.active")).to_have_count(0)        # refused before anything is asked
    expect(page.locator("#sso-provider-state")).to_have_text("Off · not tested")
    expect(page.locator("#sso-toggle")).to_have_text("Turn on")


def test_a_test_sign_in_leaves_for_the_provider_and_comes_back_with_what_it_sent(page: Page, boss, base_url,
                                                                               provider_name):
    _open(page, boss)
    _add(page, boss, provider_name)
    _fill_connection(page, boss)
    summary = {"outcome": "ok", "at": "2026-11-20T10:00:00Z", "tester": boss["username"],
               "claim_names": ["email", "groups", "sub"], "auth_time_present": True, "amr": ["pwd", "mfa"],
               "acr": None, "email_verified": True, "email_present": True, "groups": ["staff", "vault-admins"],
               "subject_length": 36, "mfa_trusted": False, "restriction": "passes",
               "would": "refuse: no account is linked to this identity, and none would be made or linked"}
    sent = {}

    def start(route):
        sent["start"] = route.request.post_data_json or {}
        route.fulfill(status=200, json={"authorization_url": f"{base_url}/__provider/authorize", "expires_in": 600})
    page.route("**/admin/sso/providers/*/test/start", start)
    page.route("**/__provider/authorize*", lambda route: route.fulfill(
        status=200, content_type="text/html",
        body=f"<!doctype html><script>location.replace('{base_url}/#sso-test=test-code')</script>"))

    def finish(route):
        sent["finish"] = route.request.post_data_json or {}
        route.fulfill(status=200, json={"tested": True, "summary": summary})
    page.route("**/admin/sso/providers/*/test/finish", finish)

    def tested(route):
        if route.request.method != "GET":
            route.continue_()
            return
        response = route.fetch()
        body = response.json()
        body["provider"]["last_test"] = summary
        body["provider"]["tested"] = True
        route.fulfill(response=response, json=body)
    page.route(re.compile(r".*/admin/sso/providers/[0-9a-f-]{36}$"), tested)
    page.click("#sso-test")
    # Back from the provider: the Sign-in settings are open on the provider, with what it sent.
    box = page.locator("#sso-test-summary")
    expect(box).to_be_visible(timeout=20000)
    expect(box).to_contain_text("The last test sign-in passed (" + boss["username"] + ").")
    expect(box).to_contain_text("What the vault would do with this person: refuse: no account is linked")
    expect(box).to_contain_text("Email address: sent, verified by the provider.")
    expect(box).to_contain_text("Second factor at the provider: amr pwd, mfa (does not count here).")
    expect(box).to_contain_text("Groups: staff, vault-admins.")
    expect(page.locator("#sso-provider-state")).to_have_text("Off · tested")
    assert len(sent["start"]["verifier_hash"]) == 64 and sent["finish"]["code"] == "test-code"
    assert sent["finish"]["verifier"] and "#" not in page.url


def test_who_may_sign_in_is_set_on_its_own_page_and_a_rule_the_server_holds_is_said(page: Page, boss,
                                                                                  provider_name, admin):
    _open(page, boss)
    _add(page, boss, provider_name)
    page.locator('.sso-tabs [data-sso-page="access"]').click()
    expect(page.locator("#sso-page-access")).to_be_visible()
    # Accounts at the first sign-in need a provider that says who may sign in: refused, in the server's words.
    page.select_option("#sso-creation", "jit")
    page.click("#sso-save")
    said = page.locator("#sso-page-access .sso-said")
    expect(said).to_contain_text("only for a provider that says who may sign in", timeout=10000)
    expect(page.locator("#stepup-modal.active")).to_have_count(0)
    page.fill("#sso-groups", "Vault Users\nstaff")
    page.click("#sso-save")
    _with_the_password(page, boss)
    expect(page.locator(".toast", has_text="Saved.").first).to_be_visible(timeout=10000)
    expect(page.locator("#sso-creation")).to_have_value("jit", timeout=10000)
    expect(page.locator("#sso-groups")).to_have_value("Vault Users\nstaff")
    saved = next(p for p in admin.get("/admin/sso/providers").json()["providers"] if p["name"] == provider_name)
    assert saved["policy"]["sso_required_groups"] == ["Vault Users", "staff"]
    assert saved["policy"]["sso_account_creation"] == "jit" and saved["policy"]["sso_freshness_days"] == 30
    # The other pages each save their own.
    page.locator('.sso-tabs [data-sso-page="sessions"]').click()
    page.fill("#sso-freshness", "7")
    page.click("#sso-save")
    _with_the_password(page, boss)
    expect(page.locator("#sso-page-sessions .sso-said")).to_have_text("", timeout=10000)      # drawn again: saved
    expect(page.locator("#sso-freshness")).to_have_value("7", timeout=10000)
    page.wait_for_load_state("networkidle", timeout=10000)
    saved = next(p for p in admin.get("/admin/sso/providers").json()["providers"] if p["name"] == provider_name)
    assert saved["policy"]["sso_freshness_days"] == 7 and saved["policy"]["sso_required_groups"] == ["Vault Users", "staff"]


def test_a_provider_is_removed_after_a_question_and_the_password(page: Page, boss, provider_name):
    _open(page, boss)
    _add(page, boss, provider_name)
    row = page.locator(f'#signin-sso-providers .sso-provider-row:has-text("{provider_name}")')
    expect(row).to_have_count(1, timeout=10000)
    page.click("#sso-remove")
    expect(page.locator("#confirm-modal-message")).to_contain_text(f"Remove {provider_name}?", timeout=8000)
    page.keyboard.press("Escape")                                   # an answer of no
    expect(page.locator("#sso-provider-modal.active")).to_be_visible()
    expect(row).to_have_count(1)
    page.click("#sso-remove")
    page.click("#confirm-modal-confirm-btn")
    _with_the_password(page, boss)
    expect(page.locator("#sso-provider-modal.active")).to_have_count(0, timeout=10000)
    expect(row).to_have_count(0, timeout=10000)
