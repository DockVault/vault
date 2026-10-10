"""UI — Settings -> Activity and records: how long records are kept (static/js/settings-retention.js).

Each setting shows the value in force with a badge saying where it comes from; a locked setting (the page is
served its own description with one locked) and one only .env sets show the .env line instead of a field. A change
that deletes records sooner first shows what it would delete (the preview) and asks to confirm: dismissed, nothing
is sent; confirmed, it asks for the password and then waits in the list of changes, where any administrator can
cancel it. The Storage card warns from 80 % of the size cap; an install that ran before this release is told what
changed, once per browser; the screen fits a phone. No console error.
"""
import json
import re

import pytest
from playwright.sync_api import Page, expect

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
    expect(page.locator("#retention-groups .retention-row").first).to_be_visible(timeout=10000)


def _row(page: Page, key):
    return page.locator(f'#retention-groups .retention-row[data-key="{key}"]')


def _serve_managed(page: Page, edit):
    def handle(route):
        if route.request.method != "GET":
            return route.continue_()
        response = route.fetch()
        data = response.json()
        edit(data)
        route.fulfill(response=response, body=json.dumps(data))
    page.route(re.compile(r"/settings/managed$"), handle)


def _serve_storage(page: Page, edit):
    def handle(route):
        response = route.fetch()
        data = response.json()
        edit(data)
        route.fulfill(response=response, body=json.dumps(data))
    page.route(re.compile(r"/settings/managed/storage$"), handle)


def _chain_started():
    """The web process's pruner starts the audit chain a minute after the server starts, and a change that deletes
    sooner is refused until it has: wait for its first policy seal on a fresh stack."""
    import time
    from _account_change_helpers import psql
    for _ in range(80):
        if psql("SELECT count(*) FROM audit_seals WHERE kind = 'policy'") not in ("", "0"):
            return
        time.sleep(3)
    raise AssertionError("the audit chain never started")


def _cancel_waiting(admin, key):
    for change in admin.get("/settings/managed").json()["pending"]:
        if change["key"] == key:
            admin.post(f"/settings/managed/changes/{change['id']}/cancel")


def test_values_show_their_source_and_a_locked_one_its_env_line(page: Page, admin_creds):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

    def lock_hot_days(data):
        for row in data["settings"]:
            if row["key"] == "audit_hot_days":
                row["locked"], row["source"] = True, "locked"
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_managed(page, lock_hot_days)
    _open(page)
    hot = _row(page, "audit_hot_days")
    expect(hot.locator(".retention-source")).to_have_text("Locked")
    expect(hot).to_contain_text("Locked by the deployment (SETTINGS_LOCKED_KEYS). To change it, set AUDIT_HOT_DAYS=")
    expect(hot.locator("input")).to_have_count(0)
    start = _row(page, "audit_archive_start_after_days")
    expect(start).to_contain_text("Set in .env: AUDIT_ARCHIVE_START_AFTER_DAYS=")
    expect(start.locator("input")).to_have_count(0)
    keep = _row(page, "audit_max_days")
    expect(keep.locator("input[type=number]")).to_be_visible()
    expect(keep.locator(".retention-source")).to_have_text(re.compile(r"^(Default|From \.env|Set here)$"))
    expect(page.locator('#retention-groups .retention-group[data-group="working_records"]')).to_contain_text("Fixed")
    expect(page.locator("#retention-storage")).to_contain_text("Audit rows:")
    expect(page.locator("#retention-storage")).to_contain_text("The database's volume is in another container")
    expect(page.locator("#retention-storage .retention-archive")).to_contain_text("The oldest day still kept as rows is ")
    assert not errors, errors


def test_a_change_that_deletes_sooner_shows_what_it_would_delete_before_anything_is_sent(page: Page, admin_creds):
    sent = []
    page.on("request", lambda r: sent.append((r.method, r.url)) if "/settings/managed" in r.url else None)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    keep = _row(page, "audit_max_days")
    field = keep.locator("input[type=number]")
    field.fill("400")
    keep.locator(".retention-save").click()
    modal = page.locator("#confirm-modal")
    expect(modal).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    expect(page.locator("#confirm-modal-title")).to_have_text("Delete records sooner?")
    expect(page.locator("#confirm-modal-message")).to_contain_text("If it applied now, it would delete")
    expect(page.locator("#confirm-modal-message")).to_contain_text("waits")
    previews = [u for m, u in sent if m == "GET" and "/settings/managed/audit/preview?max_days=400" in u]
    assert previews, sent
    page.click("#confirm-modal-cancel-btn")
    expect(modal).not_to_have_class(re.compile(r"\bactive\b"))
    page.wait_for_timeout(500)
    assert not [u for m, u in sent if m == "PUT"], sent


def test_a_change_waits_and_any_administrator_can_cancel_it(page: Page, admin_creds, admin):
    key = "security_record_days"
    _chain_started()
    _cancel_waiting(admin, key)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open(page)
        row = _row(page, key)
        current = int(row.locator("input[type=number]").input_value())
        row.locator("input[type=number]").fill(str(max(8, current - 5)))
        row.locator(".retention-save").click()
        expect(page.locator("#confirm-modal")).to_have_class(re.compile(r"\bactive\b"), timeout=10000)
        expect(page.locator("#confirm-modal-message")).to_contain_text("deletes records sooner")
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
        page.fill("#stepup-password-input", admin_creds["password"])
        page.locator("#stepup-modal-body .btn-primary").click()
        waiting = page.locator("#retention-pending .retention-change")
        expect(waiting).to_have_count(1, timeout=15000)
        expect(waiting).to_contain_text("Keep failed sign-ins in full for")
        expect(waiting).to_contain_text("unless an administrator cancels it")
        waiting.locator(".retention-cancel").click()
        expect(page.locator("#retention-pending")).to_contain_text("No change is waiting.", timeout=15000)
        assert not [c for c in admin.get("/settings/managed").json()["pending"] if c["key"] == key]
    finally:
        _cancel_waiting(admin, key)


def test_the_storage_card_warns_from_80_percent_of_the_cap(page: Page, admin_creds):
    def near(data):
        data["cap"] = {"cap_bytes": 100 * 1048576, "counted_bytes": 85 * 1048576, "fraction": 0.85, "warn": True}
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_storage(page, near)
    _open(page)
    storage = page.locator("#retention-storage")
    expect(storage).to_contain_text("the cap counts 85.0 MB of its 100.0 MB (85 %)")
    expect(storage.locator(".retention-cap-warning")).to_contain_text("is at 85 % of its size cap")


def test_an_install_from_before_this_release_is_told_once(page: Page, admin_creds):
    def existing(data):
        data["existing_install"] = True
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => { try { localStorage.removeItem('dockvault.retention.banner.dismissed'); } catch (e) {} }")
    _serve_storage(page, existing)
    _open(page)
    banner = page.locator("#retention-banner")
    expect(banner).to_be_visible()
    expect(banner).to_contain_text("keeps the audit log for good unless you choose otherwise")
    page.click("#retention-banner-dismiss")
    expect(banner).to_be_hidden()
    page.locator('#settings-section .tab-btn[data-tab="records"]').click()
    page.wait_for_timeout(800)
    expect(banner).to_be_hidden()
    page.evaluate("() => { try { localStorage.removeItem('dockvault.retention.banner.dismissed'); } catch (e) {} }")


def test_the_screen_fits_a_phone(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"], width=375)
    _open(page)
    for card in ("retention-card", "retention-storage-card"):
        width = page.evaluate(f"() => document.getElementById('{card}').scrollWidth")
        assert width <= 375, (card, width)
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 375
