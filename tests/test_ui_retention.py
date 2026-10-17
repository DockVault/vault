"""UI — Settings -> Activity and records: how long records are kept (static/js/settings-retention.js).

Each setting shows the value in force with a badge saying where it comes from; a locked setting (the page is
served its own description with one locked) and one only .env sets show the .env line instead of a field. A change
that deletes records sooner first shows what it would delete (the preview) and asks to confirm: dismissed, nothing
is sent; confirmed, it asks for the password and then waits in the list of changes, where any administrator can
cancel it. That list is the audit chain's: it says beside a change what the database says when that differs (and,
while sealing is stopped, offers no cancel the server could only refuse), and which changes wait for the host
operator. The Storage card warns from 80 % of the size cap, and says so when the log is at or over the cap but
the cap does not count it all yet; an install that ran before this release is told what changed, once per
browser; the screen fits a phone. No console error.
"""
import json
import re

import pytest
from playwright.sync_api import Page, expect
from _settings_ui import show_advanced

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
    show_advanced(page, "records")
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
    expect(hot).to_contain_text("Set by your provider and locked (SETTINGS_LOCKED_KEYS). Whoever runs the vault changes "
                                "it: AUDIT_HOT_DAYS=")
    expect(hot.locator("input")).to_have_count(0)
    start = _row(page, "audit_archive_start_after_days")
    expect(start).to_contain_text("Set in .env: AUDIT_ARCHIVE_START_AFTER_DAYS=")
    expect(start.locator("input")).to_have_count(0)
    keep = _row(page, "audit_max_days")
    expect(keep.locator("input[type=number]")).to_be_visible()
    expect(keep.locator(".retention-source")).to_have_text(re.compile(r"^(Default|From \.env|Set here)$"))
    expect(page.locator('#retention-groups .retention-group[data-group="working_records"]')).to_contain_text("Fixed")
    # One of a unit is said in the singular.
    expect(_row(page, "rate_limit_records_hours").locator(".retention-value")).to_have_text("1 hour")
    expect(_row(page, "session_records_days").locator(".retention-value")).to_have_text(re.compile(r"^\d+ days$"))
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


def _waiting_entry(**over):
    entry = {"id": "x", "request_seq": 11, "key": "security_record_days", "label": "Keep failed sign-ins in full for",
             "old": 30, "new": 20, "setting": 20, "status": "pending", "requested_by": "ada",
             "requested_at": "2026-10-01T10:00:00Z", "effective_at": "2026-10-08T10:00:00Z", "another_writer": False,
             "waits_for_host": False, "applied_by": None, "counts_from": None, "cancellable": True, "database": None,
             "decided_by": None, "decided_at": None, "reason": None}
    entry.update(over)
    return entry


def test_the_waiting_list_says_what_the_chain_holds_beside_each_change(page: Page, admin_creds):
    """The list is the audit chain's (served here, as the server gives it while sealing is stopped): a change the
    database marks cancelled says so, and that its end is recorded once sealing runs again, with no cancel; one
    another writer added waits for the host; one another writer's seal applied cannot be cancelled; a stop of
    sealing is said above the list."""
    def edit(data):
        data["pending"] = [
            _waiting_entry(id="a", request_seq=11, database="cancelled", cancellable=False),
            _waiting_entry(id="b", request_seq=12, another_writer=True, waits_for_host=True),
            _waiting_entry(id="c", request_seq=13, status="applied-waiting-for-host", applied_by=14,
                           waits_for_host=True, cancellable=False)]
        data["pending_chain"] = {"read": True, "stopped": "head-record-mismatch"}
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_managed(page, edit)
    _open(page)
    box = page.locator("#retention-pending")
    items = box.locator(".retention-change")
    expect(items).to_have_count(3, timeout=10000)
    expect(box).to_contain_text("Sealing is stopped just now (head-record-mismatch)")
    expect(items.nth(0)).to_contain_text("The database marks this change cancelled")
    expect(items.nth(0)).to_contain_text("The audit log records its end once sealing runs again.")
    expect(items.nth(0)).not_to_contain_text("Cancel it here")
    expect(items.nth(0).locator(".retention-cancel")).to_have_count(0)
    expect(items.nth(1)).to_contain_text("Another writer added this request")
    expect(items.nth(1)).to_contain_text("waits for the host operator")
    expect(items.nth(1).locator(".retention-cancel")).to_have_count(1)
    expect(items.nth(2)).to_contain_text("Applied by seal 14")
    expect(items.nth(2)).to_contain_text("can no longer be cancelled")
    expect(items.nth(2).locator(".retention-cancel")).to_have_count(0)
    expect(items.nth(1)).not_to_contain_text("The database")


def test_while_sealing_runs_a_change_the_database_no_longer_shows_waiting_can_be_cancelled(page: Page, admin_creds):
    """Sealing runs: a change the database marks cancelled, or holds no row of, says so and offers the cancel that
    records it in the audit log now."""
    def edit(data):
        data["pending"] = [_waiting_entry(id="a", request_seq=11, database="cancelled"),
                           _waiting_entry(id="b", request_seq=12, database="missing")]
        data["pending_chain"] = {"read": True, "stopped": None}
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_managed(page, edit)
    _open(page)
    box = page.locator("#retention-pending")
    items = box.locator(".retention-change")
    expect(items).to_have_count(2, timeout=10000)
    expect(box).not_to_contain_text("Sealing is stopped")
    expect(items.nth(0)).to_contain_text("The database marks this change cancelled")
    expect(items.nth(1)).to_contain_text("The database holds no row of this change")
    for n in (0, 1):
        expect(items.nth(n)).to_contain_text("Cancel it here to record the cancel in the audit log now.")
        expect(items.nth(n).locator(".retention-cancel")).to_have_count(1)


def test_before_the_chain_is_read_the_list_says_so(page: Page, admin_creds):
    def edit(data):
        data["pending"] = []
        data["pending_chain"] = {"read": False, "stopped": None}
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_managed(page, edit)
    _open(page)
    box = page.locator("#retention-pending")
    expect(box).to_contain_text("which this server has not read yet", timeout=10000)
    expect(box).not_to_contain_text("No change is waiting.")


def test_the_storage_card_warns_from_80_percent_of_the_cap(page: Page, admin_creds):
    """The warning is on the bytes now: the log takes 85 MB of a 100 MB cap, though the cap counts 40 MB so far
    (growth counts only after the delay)."""
    def near(data):
        data["cap"] = {"cap_bytes": 100 * 1048576, "counted_bytes": 40 * 1048576, "now_bytes": 85 * 1048576,
                       "fraction": 0.85, "warn": True, "over_from": None}
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_storage(page, near)
    _open(page)
    storage = page.locator("#retention-storage")
    expect(storage).to_contain_text("The audit log takes 85.0 MB of it now (85 %)")
    expect(storage).to_contain_text("the cap counts 40.0 MB so far")
    warning = storage.locator(".retention-cap-warning")
    expect(warning).to_contain_text("is at 85 % of its size cap")
    expect(warning).to_contain_text("Once it is reached, the oldest events are deleted")


@pytest.mark.parametrize("now_mb", [100, 105])
def test_at_or_over_the_cap_with_no_date_the_warning_says_the_cap_does_not_count_it_all_yet(page: Page, admin_creds,
                                                                                           now_mb):
    """The log takes the cap's size or more, but what the cap counts does not pass it on what is sealed now (the
    rest is in rows not sealed yet, or the count only reaches the cap): no date, and no "once it is reached"."""
    def full(data):
        data["cap"] = {"cap_bytes": 100 * 1048576, "counted_bytes": 40 * 1048576, "now_bytes": now_mb * 1048576,
                       "fraction": now_mb / 100, "warn": True, "over_from": None}
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_storage(page, full)
    _open(page)
    warning = page.locator("#retention-storage .retention-cap-warning")
    expect(warning).to_contain_text(f"is at {now_mb} % of its size cap")
    expect(warning).to_contain_text("The cap does not count all of it yet")
    expect(warning).to_contain_text("so nothing is deleted for now; once its count passes the cap, the oldest events")
    expect(warning).not_to_contain_text("Once it is reached")
    expect(warning).not_to_contain_text("at the earliest")


def test_over_the_cap_the_warning_says_from_when_and_what_it_would_delete(page: Page, admin_creds):
    """Over the cap now: the card says the earliest day the cap starts deleting, and what the preview with the
    bytes now counts (asked for only then)."""
    asked = []

    def over(data):
        data["cap"] = {"cap_bytes": 100 * 1048576, "counted_bytes": 60 * 1048576, "now_bytes": 120 * 1048576,
                       "fraction": 1.2, "warn": True, "over_from": "2026-11-02T10:00:00Z"}

    def preview(route):
        asked.append(route.request.url)
        route.fulfill(status=200, json={"by_age": {"rows": 0, "bytes": 0, "newest": None},
                                        "by_size": {"rows": 7, "bytes": 5 * 1048576, "newest": None},
                                        "archived": {"by_age": {"rows": 0, "bytes": 0}, "by_size": {"rows": 3,
                                                                                                  "bytes": 1048576}},
                                        "cap_met": True, "counted_bytes": 0, "protected_bytes": 0})
    _login(page, admin_creds["username"], admin_creds["password"])
    _serve_storage(page, over)
    page.route(re.compile(r"/settings/managed/audit/preview\?bytes_now=true$"), preview)
    _open(page)
    warning = page.locator("#retention-storage .retention-cap-warning")
    expect(warning).to_contain_text("is at 120 % of its size cap")
    expect(warning).to_contain_text("at the earliest, the size cap deletes the oldest events")
    expect(warning).to_contain_text("As things stand it would delete 10 events (6.0 MB)")
    assert len(asked) == 1, asked


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
    show_advanced(page, "records")
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
