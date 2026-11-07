"""UI — Settings -> Activity and records: erase a person's records (static/js/settings-erase.js).

A name is previewed before it can be asked for: the preview says what it would change, and asking stays off until
there is a preview of the name in the field (changing the name asks for a new one). Asking shows a confirmation that
needs "erase" typed: dismissed, nothing is sent; confirmed, it asks for the password, the field is cleared and the
erase is listed by its placeholder, never by the name, with a Cancel any administrator can use. An account's name
is previewed as refused, and asking stays off. The name is never kept in the browser. The card fits a phone. No
console error. A sign-out takes the name typed, its preview (with the near-miss names the records hold) and the Ask
button it turned on out of the page, so the next person on the tab finds none of them, and a preview on its way at
the sign-out is drawn for nobody.
"""
import re
import uuid

import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import psql
from _ui_hand_over import sign_in_on_the_tab

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str, width=1440):
    page.set_viewport_size({"width": width, "height": 900})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open(page: Page):
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.locator('#settings-section .tab-btn[data-tab="records"]').click()
    expect(page.locator("#erase-card")).to_be_visible(timeout=10000)
    expect(page.locator("#erase-list")).not_to_be_empty(timeout=10000)


def _chain_started():
    import time
    for _ in range(80):
        if psql("SELECT count(*) FROM audit_seals WHERE kind = 'policy'") not in ("", "0"):
            return
        time.sleep(3)
    raise AssertionError("the audit chain never started")


def _typed(name):
    """A failed sign-in with ``name`` typed, dated now (a row dated before the stack's chain began would be a
    finding of its own)."""
    psql("INSERT INTO audit_logs (id, action, status, timestamp, username, details, seal_nonce) "
         f"VALUES ('{uuid.uuid4()}', 'login_failed', 'failure', now() at time zone 'utc', "
         f"'{name}', '{{}}', decode('{uuid.uuid4().hex}', 'hex'))")


def _preview(page: Page, name):
    page.fill("#erase-name", name)
    page.click("#erase-preview-btn")
    expect(page.locator("#erase-preview")).not_to_be_empty(timeout=10000)


def test_a_name_is_previewed_before_it_can_be_asked_for_and_dismissing_sends_nothing(page: Page, admin_creds):
    errors, sent = [], []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("request", lambda r: sent.append((r.method, r.url)) if "/settings/erase-requests" in r.url else None)
    name = "ui-erase-" + uuid.uuid4().hex[:8]
    _typed(name)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    expect(page.locator("#erase-ask")).to_be_disabled()
    _preview(page, name)
    expect(page.locator("#erase-preview")).to_contain_text("1 audit row")
    expect(page.locator("#erase-preview")).to_contain_text("What an erase does not reach")
    expect(page.locator("#erase-ask")).to_be_enabled()
    page.fill("#erase-name", name + "x")
    expect(page.locator("#erase-ask")).to_be_disabled()
    expect(page.locator("#erase-preview")).to_contain_text("preview it again")
    _preview(page, name)
    page.click("#erase-ask")
    expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    expect(page.locator("#confirm-modal-confirm-btn")).to_be_disabled()
    page.click("#confirm-modal-cancel-btn")
    page.wait_for_timeout(500)
    assert [m for m, u in sent if m == "POST" and u.endswith("/settings/erase-requests")] == [], sent
    assert all(name not in u for _m, u in sent), sent
    assert errors == []


def test_an_erase_asked_for_is_listed_by_its_placeholder_and_any_administrator_cancels_it(page: Page, admin_creds):
    _chain_started()
    name = "ui-erase-" + uuid.uuid4().hex[:8]
    _typed(name)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    _preview(page, name)
    page.click("#erase-ask")
    expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    page.fill("#confirm-modal-input", "erase")
    page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    page.fill("#stepup-password-input", admin_creds["password"])
    page.locator("#stepup-modal-body .btn-primary").click()
    waiting = page.locator('#erase-list .erase-request[data-status="pending"]').first
    expect(waiting).to_be_visible(timeout=15000)
    expect(page.locator("#erase-name")).to_have_value("")
    placeholder = waiting.locator("strong").inner_text()
    assert re.fullmatch(r"erased-[0-9a-f]{8}", placeholder)
    assert name not in page.locator("#erase-list").inner_text()
    stored = page.evaluate("() => JSON.stringify(Object.assign({}, localStorage, sessionStorage))")
    assert name not in stored
    # Another name previewed and not asked for: the list, drawn again by the cancel, never shows it either.
    other = "ui-erase-" + uuid.uuid4().hex[:8]
    _preview(page, other)
    waiting.locator(".erase-cancel").click()
    expect(page.locator(f'#erase-list .erase-request[data-status="cancelled"]:has-text("{placeholder}")')).to_be_visible(
        timeout=15000)
    assert other not in page.locator("#erase-list").inner_text()


def test_an_accounts_name_is_previewed_as_refused_and_cannot_be_asked_for(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    _preview(page, admin_creds["username"])
    expect(page.locator("#erase-preview")).to_contain_text("cannot be erased now")
    expect(page.locator("#erase-ask")).to_be_disabled()


def test_the_erase_card_fits_a_phone(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"], width=375)
    _open(page)
    _preview(page, "ui-erase-" + uuid.uuid4().hex[:8])
    overflow = page.evaluate("() => { const c = document.getElementById('erase-card');"
                             " return c.scrollWidth - c.clientWidth; }")
    assert overflow <= 1
    assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth + 1")


def _signed_out(page: Page):
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def test_the_form_and_a_preview_on_its_way_are_gone_for_the_next_person_on_the_tab(page: Page, admin):
    # Errors of the page's code (a request of the person who signed out may still meet the ended session, which
    # the console reports as a failed load: that is not one).
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    ada = admin.create_user(role="admin")
    ben = admin.create_user(role="admin")
    try:
        name = "ui-erase-" + uuid.uuid4().hex[:8]
        near = name.upper()                                 # a near miss: the same name in another case
        _typed(name)
        _typed(near)
        _login(page, ada["_username"], ada["_password"])
        _open(page)
        _preview(page, name)
        expect(page.locator("#erase-preview")).to_contain_text(near)
        expect(page.locator("#erase-ask")).to_be_enabled()
        _signed_out(page)
        # Out of the page at once, though it is hidden behind the sign-in screen.
        assert page.input_value("#erase-name") == ""
        assert page.locator("#erase-preview").evaluate("(n) => n.childNodes.length") == 0
        assert near not in (page.locator("#erase-card").text_content() or "")
        expect(page.locator("#erase-ask")).to_be_disabled()
        # ben signs in on the tab and opens the card: nothing of ada's.
        sign_in_on_the_tab(page, ben)
        _open(page)
        expect(page.locator("#erase-name")).to_have_value("")
        expect(page.locator("#erase-preview")).to_be_empty()
        expect(page.locator("#erase-ask")).to_be_disabled()

        # ben's own preview, answered for him and held on its way; he signs out, ada signs in again and opens the
        # card, and then it arrives.
        held = []

        def hold_the_first(route):
            if held:
                route.continue_()
            else:
                held.append((route, route.fetch()))

        page.route("**/settings/erase-requests/preview", hold_the_first)
        page.fill("#erase-name", name)
        page.click("#erase-preview-btn")
        for _ in range(300):
            if held:
                break
            page.wait_for_timeout(50)
        assert len(held) == 1, "the preview was not asked for"
        _signed_out(page)
        sign_in_on_the_tab(page, ada)
        _open(page)
        route, answer = held[0]
        with page.expect_event("requestfinished", lambda r: r.url.endswith("/settings/erase-requests/preview"),
                               timeout=15000):
            route.fulfill(response=answer)
        page.unroute("**/settings/erase-requests/preview")
        page.evaluate("() => fetch('/health').then((r) => r.text())")
        page.evaluate("() => new Promise((done) => setTimeout(() => setTimeout(done, 0), 0))")
        expect(page.locator("#erase-preview")).to_be_empty()
        # The name ben previewed, typed by ada: no preview of hers, so asking stays off.
        page.fill("#erase-name", name)
        expect(page.locator("#erase-ask")).to_be_disabled()
        expect(page.locator("#erase-preview")).not_to_contain_text(near)
        assert errors == []
    finally:
        admin.delete_user(ada["id"])
        admin.delete_user(ben["id"])
