"""The Audit Log: two views, a remembered choice, a time-aware range, and live that is really live.

The Live Monitor page is not touched by any of this.

THE PART WORTH READING: "live" here is a POLL, and the websocket is only an accelerator.

The activity socket carries a small minority of what is audited — 19 broadcast sites against 91 that
write an audit row, counted in the source rather than estimated. Creating a vault is one of the four
in five that never reaches the socket. A socket-only implementation would therefore look live, tick
its box, and silently miss most events; on a page whose entire purpose is completeness that is worse
than offering nothing. So the poll is the mechanism and the socket nudge makes the events it does
carry appear at once.

The range filter gained a time. `datetime.fromisoformat` already accepted either spelling, but the
end of the range unconditionally added a whole day — correct for a bare date, and a silent 24-hour
widening for an instant, so "up to 14:30" also returned tomorrow lunchtime. The two are now told
apart.

Lanes:
  * unit — the end-of-range arithmetic for both spellings, and source guards that live does not rely
           on the socket alone.
  * ui   — the switch, the remembered choice, and live picking up a new event with NO manual refresh.
           That last assertion is a strict increase: an earlier version asserted "not fewer", which
           passes when live does nothing at all.
"""
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from playwright.sync_api import Page

from app.core import audit_range

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"
APP_JS = ROOT / "static" / "js" / "app.js"


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("2026-09-11",        datetime(2026, 9, 12)),           # a day: through its last second
    ("2026-09-11T14:30",  datetime(2026, 9, 11, 14, 30)),   # an instant: exactly that
    ("2026-09-11T00:00",  datetime(2026, 9, 11, 0, 0)),     # midnight NAMED is still an instant
    ("2026-09-11 14:30",  datetime(2026, 9, 11, 14, 30)),   # space separator, same meaning
])
def test_the_end_of_the_range_means_what_it_says(value, expected):
    """Calls the REAL function.

    The first version of this test defined its own copy of the rule and asserted against that, which
    proves only that the copy is self-consistent — the endpoint could have been changed to anything
    and it would still have passed. The logic now lives in app.core.audit_range precisely so this can
    exercise it rather than a restatement of it.

    The midnight case is the one worth having: "2026-09-11T00:00" is ten characters longer than a
    bare date but means the very start of the day, so a length check that counted wrong would return
    the 12th and quietly include a whole day nobody asked for.
    """
    assert audit_range.upper_bound(value) == expected


@pytest.mark.unit
def test_a_range_end_only_ever_widens_for_a_bare_date():
    """Stated as a property rather than a table: a timed end must never reach past itself."""
    for value in ("2026-09-11T14:30", "2026-09-11T00:00", "2026-01-01T23:59:59"):
        assert audit_range.upper_bound(value) == datetime.fromisoformat(value), (
            f"{value} names an instant; the range must not run past it")
    for value in ("2026-09-11", "2026-01-01"):
        widened = audit_range.upper_bound(value) - datetime.fromisoformat(value)
        assert widened == timedelta(days=1), f"{value} names a day and must cover all of it"


@pytest.mark.unit
@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-date", "2026-13-45"])
def test_an_unusable_filter_value_is_ignored_rather_than_fatal(bad):
    """A filter nobody can parse must drop out of the query, not 500 the page."""
    assert audit_range.upper_bound(bad) is None
    assert audit_range.lower_bound(bad) is None


@pytest.mark.unit
def test_the_start_of_the_range_is_inclusive_and_unmodified():
    assert audit_range.lower_bound("2026-09-11") == datetime(2026, 9, 11)
    assert audit_range.lower_bound("2026-09-11T14:30") == datetime(2026, 9, 11, 14, 30)


@pytest.mark.unit
def test_the_query_uses_the_shared_range_rather_than_its_own_copy():
    """One place decides what a range means.

    This used to grep the endpoint for the length check itself, which is the weakest kind of test:
    it passes on the text and says nothing about the behaviour, and it broke the moment the logic
    moved somewhere it could actually be tested. What is worth pinning is that the endpoint DELEGATES
    — a second implementation inside the query is how the two ends drift apart again.
    """
    src = API.read_text(encoding="utf-8")
    start = src.index("def _build_audit_query(")
    body = src[start:src.index("\ndef ", start + 1)]

    assert "audit_range.lower_bound(from_date)" in body, "the start must come from the shared module"
    assert "audit_range.upper_bound(to_date)" in body, "the end must come from the shared module"
    assert "timedelta(days=1)" not in body, (
        "the query is doing range arithmetic of its own again; that is the copy this split removed")


@pytest.mark.unit
def test_live_does_not_depend_on_the_socket_alone():
    """The finding this feature turns on.

    If the poll is ever removed, live keeps working for the minority of actions the socket
    broadcasts and quietly stops working for the rest — the worst possible failure for this page,
    because it still looks live.
    """
    app = APP_JS.read_text(encoding="utf-8")
    start = app.index("function setAuditLive(")
    body = app[start:app.index("\nfunction ", start + 1)]
    assert "setInterval" in body, (
        "live must poll; the activity socket carries roughly one audited action in five")
    assert "_AUDIT_LIVE_POLL_MS" in body, "the interval should be a named constant"
    assert "clearInterval" in body, "switching live off must stop the poll"

    # And switching off must not leave either timer running.
    assert "_auditLiveTimer = null" in body and "_auditLivePoll = null" in body


@pytest.mark.unit
def test_the_two_views_render_from_one_page_slice():
    """Two drawings of one list. If the card view fetched or sliced separately the two could
    disagree about what is on screen, which on an audit page is a correctness problem."""
    app = APP_JS.read_text(encoding="utf-8")
    start = app.index("function renderAuditPage(")
    body = app[start:app.index("\nfunction ", start + 1)]
    assert "renderAuditCards(logs, start)" in body, (
        "the detailed view must render from the same slice the table does")


@pytest.mark.unit
def test_the_live_monitor_page_is_untouched():
    """The owner's explicit constraint. The audit hook is additive and must stay that way."""
    app = APP_JS.read_text(encoding="utf-8")
    assert "function handleMonitorEvent(" in app, "the monitor's handler must still exist"
    start = app.index("function handleMonitorEvent(")
    body = app[start:app.index("\nfunction ", start + 1)]
    assert "auditLiveNote()" in body, "the audit view listens to the same feed"
    assert "try { auditLiveNote(); }" in body, (
        "the hook must be wrapped — a fault in the audit view must not take the monitor down")
    # The monitor's own rendering must still be there.
    assert "monitor-events-list" in app, "the Live Monitor feed element must not have been removed"
    assert "function initMonitor" in app or "connectMonitorWebSocket" in app


# --------------------------------------------------------------------------- ui lane
#
# These three existed only as a claim until now. The commit that added the feature described this
# lane in its own message, and the behaviour had been proved with a throwaway script rather than a
# test in the repo — so anyone reading that commit would believe coverage existed where none did.
# That is the settings-blob diff again, in prose: a description of a check nobody can run.


def _login(page: Page, username: str, password: str):
    """Sign in, waiting out the login rate limit rather than failing on it."""
    for _ in range(8):
        page.fill("#username", username)
        page.fill("#password", password)
        page.click("#login-form button[type=submit]")
        try:
            page.wait_for_selector("#dashboard-screen.active", timeout=8000)
            return
        except Exception:
            msg = page.evaluate(
                "() => (document.getElementById('login-error') || {}).textContent || ''")
            m = re.search(r"(\d+) seconds", msg or "")
            if not m:
                raise AssertionError(f"login failed, and not because of rate limiting: {msg!r}")
            time.sleep(int(m.group(1)) + 3)
    raise AssertionError("login was rate limited on every attempt")


def _open_audit_tab(page: Page):
    page.evaluate("() => navigateToSection('settings')")
    page.wait_for_selector("#settings-section.active", timeout=15000)
    page.evaluate(
        """() => { const t = [...document.querySelectorAll('.tabs .tab-btn')]
               .find(x => x.getAttribute('data-tab') === 'audit'); if (t) t.click(); }"""
    )
    page.wait_for_selector("#settings-tab-audit.active", timeout=10000)


def _which_view(page: Page) -> dict:
    """What is on screen, by computed style — not by class name."""
    return page.evaluate(
        """() => {
            const wrap = document.querySelector('#settings-tab-audit .data-table-wrapper');
            const cards = document.getElementById('audit-log-cards');
            const shown = (el) => el ? getComputedStyle(el).display !== 'none' : null;
            let stored = null;
            try { stored = localStorage.getItem('auditView'); } catch (_) { stored = 'BLOCKED'; }
            return { table: shown(wrap), cards: shown(cards), stored };
        }"""
    )


def _entry_count(page: Page) -> int:
    text = page.evaluate("() => (document.getElementById('audit-count') || {}).textContent || ''")
    m = re.search(r"(\d+)", text or "")
    return int(m.group(1)) if m else -1


@pytest.mark.ui
def test_the_range_filters_accept_a_time_not_just_a_date(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_audit_tab(page)
    kinds = page.evaluate(
        """() => ({ from: (document.getElementById('audit-filter-from') || {}).type,
                    to:   (document.getElementById('audit-filter-to')   || {}).type })"""
    )
    assert kinds == {"from": "datetime-local", "to": "datetime-local"}, (
        f"the range must accept a time, since the endpoint distinguishes the spellings: {kinds}")


@pytest.mark.ui
def test_the_view_switches_and_the_choice_is_remembered(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_audit_tab(page)
    page.click("#audit-search-btn")
    page.wait_for_function("() => document.querySelectorAll('#audit-log-body tr').length > 0",
                           timeout=15000)

    start = _which_view(page)
    assert start["table"] is True and start["cards"] is False, (
        f"the compact table is the default: {start}")

    page.click("#audit-view-cards")
    page.wait_for_function(
        "() => getComputedStyle(document.getElementById('audit-log-cards')).display !== 'none'",
        timeout=10000)
    switched = _which_view(page)
    assert switched["cards"] is True and switched["table"] is False, switched
    # Non-vacuous: the detailed view actually drew rows, rather than being an empty box that still
    # counts as "displayed".
    drawn = page.evaluate("() => document.querySelectorAll('#audit-log-cards .audit-card').length")
    assert drawn > 0, "the detailed view is showing but drew nothing"

    # Surviving a reload is the half a class toggle alone would not give.
    page.reload()
    page.wait_for_selector("#dashboard-screen.active", timeout=20000)
    _open_audit_tab(page)
    after = _which_view(page)
    assert after["stored"] == "cards", f"the choice was not remembered: {after}"
    assert after["cards"] is True and after["table"] is False, (
        f"the choice was stored but not applied on load: {after}")


@pytest.mark.ui
def test_live_picks_up_a_new_event_without_being_asked(page: Page, admin_creds):
    """The assertion is a STRICT increase.

    An earlier version asked for "not fewer", which passes when live does nothing at all — and it did
    pass, while live was doing nothing. Tightening it is what exposed that the activity socket
    carries only a minority of audited actions, and why live polls rather than trusting the socket.
    """
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_audit_tab(page)
    page.click("#audit-search-btn")
    page.wait_for_function("() => document.querySelectorAll('#audit-log-body tr').length > 0",
                           timeout=15000)

    # Tick live FIRST, and let its one-shot refresh settle, before reading the baseline.
    #
    # Reading the count before ticking made this vacuous: switching live on re-reads immediately, so
    # it swept up whatever had been logged since the manual search — the login itself, the search —
    # and the number rose whether or not live went on to track anything. Mutation caught it: removing
    # the poll entirely left the test passing. The baseline has to be taken from the state live has
    # already brought up to date, so the only thing left that can move it is the new event.
    page.check("#audit-live")
    page.wait_for_timeout(2500)
    before = _entry_count(page)
    assert before >= 0, "the entry count should be readable once live has settled"

    # Creating a vault is chosen deliberately: it is one of the four in five audited actions the
    # activity socket does NOT broadcast, so this can only pass if the poll is doing the work.
    page.evaluate(
        """async () => { await apiRequest('/vaults', { method: 'POST',
               body: JSON.stringify({ name: 'audit-live-' + Date.now(), description: '' }) }); }"""
    )
    # No manual search anywhere below. If the number moves, the page moved it.
    page.wait_for_function(
        "(n) => { const el = document.getElementById('audit-count');"
        " const m = (el ? el.textContent : '').match(/(\\d+)/);"
        " return !!m && Number(m[1]) > n; }",
        arg=before, timeout=30000)
    after = _entry_count(page)
    assert after > before, f"live did not pick the event up on its own: {before} -> {after}"
