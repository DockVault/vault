"""UI: Settings -> Activity and records: remove the values recorded under earlier levels
(static/js/settings-removal.js).

At full the preview says there is nothing to remove and asking stays off. With a level lowered the preview lists each
kind below full with the rows above it; asking shows a confirmation that needs "remove" typed (dismissed, nothing is
sent), then the password; the removal is listed waiting, with its levels and when it runs, and any administrator
cancels it. A preview that ran out of time says "at least", and one that could not count says so. The confirmation
counts the archived days too; a removal that waits says why on its card; a level changed since the preview is
refused, and the preview is made again. The page says how long addresses stay in full when that is set. The card
fits a phone. No console error.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import psql
from _recording_levels import levels_restored, store  # noqa: F401 -- a fixture
from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

FULL = {"names": "full", "signin_names": "full", "emails": "full", "ip": "full", "user_agent": "full"}


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
    show_advanced(page, "records")
    expect(page.locator("#removal-card")).to_be_visible(timeout=10000)
    expect(page.locator("#removal-list")).not_to_be_empty(timeout=10000)


def _chain_started():
    import time
    for _ in range(80):
        if psql("SELECT count(*) FROM audit_seals WHERE kind = 'policy'") not in ("", "0"):
            return
        time.sleep(3)
    raise AssertionError("the audit chain never started")


def test_at_full_there_is_nothing_to_remove(page: Page, admin_creds, levels_restored):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    store(dict(FULL))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    expect(page.locator("#removal-ask")).to_be_disabled()
    page.click("#removal-preview-btn")
    expect(page.locator("#removal-preview")).to_contain_text("nothing to remove", timeout=15000)
    expect(page.locator("#removal-ask")).to_be_disabled()
    assert errors == []


def test_a_removal_is_previewed_confirmed_asked_for_with_the_password_and_cancelled(page: Page, admin, admin_creds,
                                                                                    levels_restored):
    _chain_started()
    errors, sent = [], []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("request", lambda r: sent.append((r.method, r.url)) if "/settings/value-removals" in r.url else None)
    store(dict(FULL, ip="shortened"))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    page.click("#removal-preview-btn")
    item = page.locator('#removal-preview li[data-kind="ip"]')
    expect(item).to_contain_text("IP addresses, shortened", timeout=15000)
    expect(item).to_contain_text(re.compile(r"\d+ rows?"))
    expect(page.locator("#removal-preview")).to_contain_text("What a removal does not reach")
    expect(page.locator("#removal-ask")).to_be_enabled()
    page.click("#removal-ask")
    expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    expect(page.locator("#confirm-modal-confirm-btn")).to_be_disabled()
    page.click("#confirm-modal-cancel-btn")
    page.wait_for_timeout(500)
    assert [m for m, u in sent if m == "POST" and u.endswith("/settings/value-removals")] == [], sent
    page.click("#removal-ask")
    expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    page.fill("#confirm-modal-input", "remove")
    page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    page.fill("#stepup-password-input", admin_creds["password"])
    page.locator("#stepup-modal-body .btn-primary").click()
    waiting = page.locator('#removal-list .removal-request[data-status="pending"]').first
    expect(waiting).to_be_visible(timeout=15000)
    expect(waiting).to_contain_text("IP addresses: shortened")
    expect(waiting).to_contain_text("runs on")
    request_id = waiting.get_attribute("data-request")
    try:
        waiting.locator(".removal-cancel").click()
        expect(page.locator(f'#removal-list .removal-request[data-request="{request_id}"][data-status="cancelled"]')
               ).to_be_visible(timeout=15000)
    finally:
        admin.post(f"/settings/value-removals/{request_id}/cancel")     # never left waiting on the stack
    assert psql(f"SELECT status FROM audit_value_removals WHERE id = '{request_id}'") == "cancelled"
    # The one console line: the browser's own for the 403 that asks for the password (the step-up).
    assert [e for e in errors if "status of 403" not in e] == [], errors


@pytest.mark.parametrize("change, total, each", [
    ({"rows": 1200, "counted": False}, r"At least 1,?200 rows in all \(there are too many to count", r"\d+ rows?"),
    ({"rows": None, "counted": False, "kinds": None}, "could not be counted just now", "too many to count just now"),
])
def test_a_preview_not_fully_counted_says_so(page: Page, admin_creds, levels_restored, change, total, each):
    """A preview that ran out of time says "at least"; one that could not count says so, for each kind too."""
    store(dict(FULL, ip="shortened"))

    def answer(route):
        response = route.fetch()
        data = response.json()
        if change.get("kinds", 0) is None:
            data["kinds"] = [dict(k, rows=None) for k in data["kinds"]]
        data.update({k: v for k, v in change.items() if k != "kinds"})
        route.fulfill(response=response, json=data)
    page.route("**/settings/value-removals/preview", answer)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    page.click("#removal-preview-btn")
    expect(page.locator("#removal-preview .removal-total")).to_have_text(re.compile(total), timeout=15000)
    expect(page.locator('#removal-preview li[data-kind="ip"]')).to_contain_text(re.compile(each))


def test_the_card_fits_a_phone(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"], width=375)
    _open(page)
    width = page.evaluate("() => [document.getElementById('removal-card').scrollWidth, "
                          "document.getElementById('removal-card').clientWidth]")
    assert width[0] <= width[1] + 1, width


def test_the_confirmation_counts_the_archived_days_too(page: Page, admin_creds, levels_restored):
    """The confirmation names the archived days the removal changes as well as the rows it counted."""
    store(dict(FULL, ip="shortened"))

    def answer(route):
        response = route.fetch()
        data = response.json()
        data.update({"rows": 3, "counted": True, "archived_days": 2, "waiting": False})
        route.fulfill(response=response, json=data)
    page.route("**/settings/value-removals/preview", answer)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    page.click("#removal-preview-btn")
    expect(page.locator("#removal-preview .removal-total")).to_have_text(re.compile(r"^3 rows in all"), timeout=15000)
    page.click("#removal-ask")
    expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    expect(page.locator("#confirm-modal")).to_contain_text("Remove from 3 audit rows and the rows of 2 archived days "
                                                           "written before")
    page.click("#confirm-modal-cancel-btn")


def test_a_removal_that_waits_says_why_on_its_card(page: Page, admin_creds):
    """The list shows why a removal waits (here at a day a later release archived, which this release cannot
    change)."""
    why = ("It waits: 2026-07-10 is archived in a later release's block format, which this release does not change, "
           "so this release cannot complete it.")

    def answer(route):
        if route.request.method != "GET":
            route.continue_()
            return
        response = route.fetch()
        data = response.json()
        data["requests"] = [{"id": "00000000-0000-4000-8000-000000000001", "status": "running", "request_seq": 7,
                             "levels": dict(FULL, ip="shortened"), "before": "2026-10-01T10:00:00Z",
                             "requested_by": "ada", "requested_at": "2026-10-01T09:30:00Z",
                             "effective_at": "2026-10-08T09:30:00Z", "started_at": "2026-10-08T12:00:00Z",
                             "completed_at": None, "decided_by": None, "decided_at": None, "waiting": why,
                             "counts": {"rows": 5, "archived_rows": 0}, "cancellable": False}]
        route.fulfill(response=response, json=data)
    page.route("**/settings/value-removals", answer)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    item = page.locator('#removal-list .removal-request[data-status="running"]')
    expect(item).to_be_visible(timeout=15000)
    expect(item.locator(".removal-waiting")).to_have_text(why)
    expect(item.locator(".removal-cancel")).to_have_count(0)


def test_a_level_changed_since_the_preview_is_refused_and_the_preview_made_again(page: Page, admin, admin_creds,
                                                                                levels_restored):
    """Another administrator changes a level between the preview and the ask: nothing is asked for, the page says
    so, and the preview is made again with the levels in force."""
    _chain_started()
    store(dict(FULL, ip="shortened"))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    page.click("#removal-preview-btn")
    expect(page.locator('#removal-preview li[data-kind="ip"]')).to_contain_text("IP addresses, shortened",
                                                                              timeout=15000)
    store(dict(FULL, ip="none"))
    count = psql("SELECT count(*) FROM audit_value_removals")
    try:
        page.click("#removal-ask")
        expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
        page.fill("#confirm-modal-input", "remove")
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
        page.fill("#stepup-password-input", admin_creds["password"])
        page.locator("#stepup-modal-body .btn-primary").click()
        expect(page.locator("body")).to_contain_text("changed since the preview", timeout=15000)
        expect(page.locator('#removal-preview li[data-kind="ip"]')).to_contain_text("IP addresses, not recorded",
                                                                                  timeout=15000)
        assert psql("SELECT count(*) FROM audit_value_removals") == count
    finally:
        # Never one left waiting on the stack, whatever went wrong above.
        for rid in (psql("SELECT string_agg(id::text, ' ') FROM audit_value_removals WHERE status = 'pending'")
                    or "").split():
            admin.post(f"/settings/value-removals/{rid}/cancel")
