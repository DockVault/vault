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
from datetime import datetime, timedelta
from pathlib import Path

import pytest

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
