"""Settings -> Sign-in in the browser (static/js/settings-signin.js): an administrator sees whether a passkey can be
made at the vault's address, changes a passkey setting with their password, finds the change still there after a
reload, and reads the server's own sentence when a change is refused.

Needs a stack with an address passkeys can be made at (ALLOWED_HOSTS naming the address the test opens)."""
import re

import pytest
from playwright.sync_api import Page, expect

from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

VERIFY = '#signin-passkey-settings [data-setting="webauthn_require_uv"]'
ATTESTATION = '#signin-passkey-settings [data-setting="webauthn_attestation"]'


def _open(page: Page, admin_creds):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _open_page(page)


def _open_page(page: Page):
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(page.locator("#settings-tab-signin")).to_be_visible()
    expect(page.locator('#signin-passkey-settings [data-setting="webauthn_mode"]')).to_be_visible(timeout=10000)


def _save_with_the_password(page: Page, row, admin_creds):
    row.get_by_role("button", name="Save").click()
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    page.fill("#stepup-password-input", admin_creds["password"])
    page.locator("#stepup-modal-body .btn-primary").click()
    expect(page.locator("#stepup-modal.active")).to_be_hidden(timeout=10000)


def test_the_page_says_where_passkeys_are_made_and_lists_the_settings(page: Page, admin_creds):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _open(page, admin_creds)
    line = page.locator("#signin-passkey-readiness")
    expect(line).to_be_visible()
    if "No passkey can be made" in (line.text_content() or ""):
        pytest.skip("this stack has no address a passkey can be made at (ALLOWED_HOSTS)")
    expect(line).to_contain_text("Passkeys can be made at " + page.evaluate("() => location.origin"))
    # The essential settings show; the rest wait for the Advanced switch, like on every other page.
    box = page.locator("#signin-passkey-settings")
    expect(box.locator('[data-setting="webauthn_mode"] select')).to_have_value("optional")
    expect(box.locator('[data-setting="webauthn_sign_in"]')).to_be_visible()
    # 'Required for roles' needs its roles and their days: they show with it.
    expect(box.locator('[data-setting="webauthn_required_roles"]')).to_be_visible()
    expect(box.locator('[data-setting="webauthn_enrollment_grace_days"]')).to_be_visible()
    expect(box.locator('[data-setting="webauthn_allowed_algs"]')).to_be_hidden()
    show_advanced(page, "signin")
    expect(box.locator('[data-setting="webauthn_allowed_algs"]')).to_be_visible()
    assert box.locator("[data-setting]").count() == 9
    # Nothing to save until something is changed.
    expect(page.locator(VERIFY).get_by_role("button", name="Save")).to_be_disabled()
    assert errors == [], errors


def test_a_change_asks_for_the_password_and_holds_after_a_reload(page: Page, admin_creds):
    _open(page, admin_creds)
    box = page.locator(VERIFY + " input[type=checkbox]")
    expect(box).to_be_checked()
    try:
        box.uncheck()
        _save_with_the_password(page, page.locator(VERIFY), admin_creds)
        expect(page.locator(VERIFY + " input[type=checkbox]")).not_to_be_checked(timeout=10000)
        # The row drawn again says the change can be undone, and has nothing more to save.
        expect(page.locator(VERIFY).get_by_role("button", name="Use the default")).to_be_visible()
        expect(page.locator(VERIFY).get_by_role("button", name="Save")).to_be_disabled()
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        _open_page(page)
        expect(page.locator(VERIFY + " input[type=checkbox]")).not_to_be_checked()
    finally:
        # Back to the deployment's value, through the page, with the password again.
        back = page.locator(VERIFY).get_by_role("button", name="Use the default")
        if back.count():
            back.click()
            expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
            page.fill("#stepup-password-input", admin_creds["password"])
            page.locator("#stepup-modal-body .btn-primary").click()
            expect(page.locator(VERIFY + " input[type=checkbox]")).to_be_checked(timeout=10000)
    expect(page.locator(VERIFY).get_by_role("button", name="Use the default")).to_have_count(0)


def test_a_change_the_server_refuses_is_said_in_its_words_and_asks_for_no_password(page: Page, admin_creds):
    _open(page, admin_creds)
    show_advanced(page, "signin")
    row = page.locator(ATTESTATION)
    row.locator("select").select_option("direct")
    row.get_by_role("button", name="Save").click()
    said = row.locator(".signin-setting-said")
    expect(said).to_contain_text("Direct attestation needs trust anchors", timeout=10000)
    expect(said).to_have_attribute("role", "alert")
    expect(page.locator("#stepup-modal.active")).to_have_count(0)
    # Nothing changed: the page read again shows the value in force.
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(page.locator(ATTESTATION + " select")).to_have_value("none", timeout=10000)


def _with_the_answer_changed(page: Page, change):
    """The page's read of the Sign-in settings, with ``change`` applied to the server's own answer."""
    def answer(route):
        if route.request.method != "GET":
            return route.fallback()
        response = route.fetch()
        body = response.json()
        change(body)
        route.fulfill(response=response, json=body)
    page.route("**/settings/sign-in", answer)


def test_the_page_says_when_it_was_opened_at_another_address_than_passkeys_are_made_at(page: Page, admin_creds):
    def elsewhere(body):
        body["readiness"] = {"usable": True, "rp_id": "vault.example.test", "origin": "https://vault.example.test",
                             "reason": "ok"}
        body["why_not"] = ""
    _with_the_answer_changed(page, elsewhere)
    _open(page, admin_creds)
    line = page.locator("#signin-passkey-readiness")
    here = page.evaluate("() => location.origin")
    host = page.evaluate("() => location.hostname")
    # Where this address could carry passkeys, the line also says how to make it the vault's.
    could = not re.fullmatch(r"\d+(\.\d+){3}|\[.*\]", host) and (here.startswith("https://") or host == "localhost")
    fix = (f" If people open the vault at {here}, put that address first in ALLOWED_HOSTS in .env and run python "
           "dockvault.py restart.") if could else ""
    expect(line).to_have_text(f"Passkeys can be made at https://vault.example.test, which is not the address this "
                              f"page was opened at ({here}). Open the vault there to add or use one: here the "
                              "browser refuses." + fix)
    assert "alert-warning" in (line.get_attribute("class") or "")
    page.unroute_all(behavior="ignoreErrors")


def test_the_page_says_that_a_requirement_waits_and_how_many_older_passkeys_there_are(page: Page, admin_creds):
    def waiting(body):
        body["readiness"] = {"usable": False, "rp_id": "", "origin": "", "reason": "no_public_host"}
        body["why_not"] = "The vault has no public address."
        body["requirement_paused"] = True
        body["unattested_passkeys"] = 3
    _with_the_answer_changed(page, waiting)
    _open(page, admin_creds)
    line = page.locator("#signin-passkey-readiness")
    expect(line).to_contain_text("No passkey can be made at this vault yet")
    expect(line).to_contain_text("The passkey requirement below is paused until then")
    older = page.locator("#signin-passkey-older")
    expect(older).to_have_text("3 passkeys in use were added before this vault checked authenticator makes. They keep "
                               "signing in and serving as a second factor, and do not prove a compliance step-up until "
                               "their owners add them again.")
    page.unroute_all(behavior="ignoreErrors")
    # The server's own answer: nothing waits, and no older passkey is counted where attestation is not asked.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _open_page(page)
    expect(page.locator("#signin-passkey-readiness")).not_to_contain_text("paused")
    expect(page.locator("#signin-passkey-older")).to_be_hidden()


MODE = '#signin-passkey-settings [data-setting="webauthn_mode"]'


def _value(body, key, value):
    """The value in force of ``key`` in an answer of the Sign-in settings, changed to ``value``."""
    for row in body["settings"]:
        if row["key"] == key:
            row["value"] = value


def test_the_page_says_under_two_rows_what_the_counts_mean(page: Page, admin_creds):
    def counted(body):
        _value(body, "webauthn_require_uv", True)
        _value(body, "webauthn_mode", "optional")
        body["passkeys_without_verification"] = 3
        body["accounts_with_only_such_passkeys"] = 1
        body["accounts_with_only_a_passkey"] = 2
        body["administrators_with_only_a_passkey"] = 1
    _with_the_answer_changed(page, counted)
    _open(page, admin_creds)
    expect(page.locator(VERIFY + " .signin-setting-note")).to_have_text(
        "3 passkeys in use never checked a PIN, fingerprint or face: while this is on, they count as no second factor "
        "and are refused at any use that does not check one. 1 account holds no passkey that did: without an "
        "authenticator app, it sets a second factor up again at its next sign-in.")
    expect(page.locator(MODE + " .signin-setting-note")).to_have_text(
        "2 accounts (1 of them an administrator) have a passkey as their only second factor. With Passkeys set to "
        "Off, they set an authenticator app up at their next sign-in.")
    page.unroute_all(behavior="ignoreErrors")

    def none(body):
        for key in ("passkeys_without_verification", "accounts_with_only_such_passkeys",
                    "accounts_with_only_a_passkey", "administrators_with_only_a_passkey"):
            body[key] = 0
    _with_the_answer_changed(page, none)
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(page.locator(VERIFY + " .signin-setting-note")).to_have_count(0, timeout=10000)
    expect(page.locator("#signin-passkey-settings .signin-setting-note")).to_have_count(0)
    page.unroute_all(behavior="ignoreErrors")


def test_a_save_reads_the_page_again_and_draws_the_counts_it_changed(page: Page, admin_creds):
    reads = []

    def counted(body):
        reads.append(1)
        body["passkeys_without_verification"] = 3 if len(reads) == 1 else 4
        body["accounts_with_only_such_passkeys"] = 0
    _with_the_answer_changed(page, counted)
    _open(page, admin_creds)
    expect(page.locator(VERIFY + " .signin-setting-note")).to_contain_text("3 passkeys in use never checked")
    box = page.locator(VERIFY + " input[type=checkbox]")
    expect(box).to_be_checked()
    try:
        with page.expect_request(lambda r: r.method == "GET" and r.url.endswith("/settings/sign-in"), timeout=15000):
            box.uncheck()
            _save_with_the_password(page, page.locator(VERIFY), admin_creds)
        # The rule is off now: the count read again is said as what turning it on would do.
        expect(page.locator(VERIFY + " .signin-setting-note")).to_have_text(
            "4 passkeys in use never checked a PIN, fingerprint or face: turned on, this makes them count as no "
            "second factor and refuses them at any use that does not check one.", timeout=10000)
    finally:
        back = page.locator(VERIFY).get_by_role("button", name="Use the default")
        if back.count():
            back.click()
            expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
            page.fill("#stepup-password-input", admin_creds["password"])
            page.locator("#stepup-modal-body .btn-primary").click()
            expect(page.locator(VERIFY + " input[type=checkbox]")).to_be_checked(timeout=10000)
        page.unroute_all(behavior="ignoreErrors")


def test_the_page_says_when_direct_attestation_has_no_trust_anchors(page: Page, admin_creds, base_url):
    from urllib.parse import urlsplit
    here = {"usable": True, "rp_id": urlsplit(base_url).hostname, "origin": base_url, "reason": "ok"}

    def without(body):
        body["readiness"] = here
        _value(body, "webauthn_attestation", "direct")
        _value(body, "webauthn_mode", "required_for_roles")
        _value(body, "webauthn_required_roles", ["admin"])
        body["trust_anchors"] = 0
        body["requirement_paused"] = False
    _with_the_answer_changed(page, without)
    _open(page, admin_creds)
    alert = page.locator("#signin-passkey-anchors")
    expect(alert).to_be_visible()
    expect(alert).to_contain_text("finds no trust anchors")
    expect(alert).to_contain_text("keeps running meanwhile")
    expect(page.locator("#signin-passkey-readiness")).to_contain_text("None can be added now")
    expect(page.locator("#signin-passkey-readiness")).not_to_contain_text("can be made")
    page.unroute_all(behavior="ignoreErrors")

    def one_anchor(body):
        body["readiness"] = here
        _value(body, "webauthn_attestation", "direct")
        body["trust_anchors"] = 1
    _with_the_answer_changed(page, one_anchor)
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(alert).to_be_hidden(timeout=10000)
    page.unroute_all(behavior="ignoreErrors")
    # The server's own answer: attestation is not direct.
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(page.locator(ATTESTATION + " select")).to_have_value("none", timeout=10000)
    expect(alert).to_be_hidden()


def test_required_for_roles_with_no_role_chosen_says_nobody_is_required(page: Page, admin_creds):
    def no_role(body):
        _value(body, "webauthn_mode", "required_for_roles")
        _value(body, "webauthn_required_roles", [])
    _with_the_answer_changed(page, no_role)
    _open(page, admin_creds)
    note = page.locator(MODE + " .signin-roles-note")
    expect(note).to_have_text("No role is chosen under “Roles that must have a passkey”: nobody is required "
                              "to hold a passkey.")
    # The roles are there to choose, without "Show advanced settings".
    expect(page.locator('#signin-passkey-settings [data-setting="webauthn_required_roles"]')).to_be_visible()
    page.unroute_all(behavior="ignoreErrors")

    def a_role(body):
        _value(body, "webauthn_mode", "required_for_roles")
        _value(body, "webauthn_required_roles", ["user"])
    _with_the_answer_changed(page, a_role)
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(page.locator(MODE + " .signin-roles-note")).to_have_count(0, timeout=10000)
    page.unroute_all(behavior="ignoreErrors")


def test_the_page_lists_the_accounts_the_requirement_was_lifted_for_as_text(page: Page, admin_creds):
    def lifted(body):
        body["requirement_lifted_for"] = [
            {"username": "<img src=x onerror=alert(1)>", "role": "user", "lifted_at": "2026-11-20T10:00:00Z"},
            {"username": "bob", "role": "admin", "lifted_at": "2026-11-21T10:00:00Z"}]
    _with_the_answer_changed(page, lifted)
    _open(page, admin_creds)
    box = page.locator("#signin-passkey-lifted")
    expect(box).to_be_visible()
    expect(box).to_contain_text("2 accounts")
    expect(box.locator("li")).to_have_count(2)
    assert (box.locator("li").first.text_content() or "").startswith("<img")
    expect(box.locator("img")).to_have_count(0)
    expect(box).to_contain_text("bob (Administrators)")
    page.unroute_all(behavior="ignoreErrors")
    # The server's own answer: nobody's requirement was lifted on this stack.
    page.locator('#sidebar .sidebar-settings-item[data-tab="signin"]').click()
    expect(page.locator('#signin-passkey-settings [data-setting="webauthn_mode"]')).to_be_visible(timeout=10000)
    expect(box).to_be_hidden(timeout=10000)
