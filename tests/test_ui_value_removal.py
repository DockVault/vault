"""UI: Settings -> Activity and records: remove the values recorded under earlier levels
(static/js/settings-removal.js).

At full the preview says there is nothing to remove and asking stays off. With a level lowered the preview lists each
kind below full with the rows above it; asking shows a confirmation that needs "remove" typed (dismissed, nothing is
sent), then the password; the removal is listed waiting, with its levels and when it runs, and any administrator
cancels it. The page says how long addresses stay in full when that is set. The card fits a phone. No console error.
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


def test_the_card_fits_a_phone(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"], width=375)
    _open(page)
    width = page.evaluate("() => [document.getElementById('removal-card').scrollWidth, "
                          "document.getElementById('removal-card').clientWidth]")
    assert width[0] <= width[1] + 1, width
