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

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"
APP_JS = ROOT / "static" / "js" / "app.js"


def _upper_bound(to_date: str):
    """The rule the endpoint applies, restated so the two spellings can be compared directly."""
    parsed = datetime.fromisoformat(to_date)
    return parsed + timedelta(days=1) if len(to_date.strip()) <= 10 else parsed


@pytest.mark.unit
def test_a_bare_date_covers_its_whole_day_and_an_instant_does_not():
    assert _upper_bound("2026-09-11") == datetime(2026, 9, 12), (
        "a date-only end must include everything that happened that day")
    assert _upper_bound("2026-09-11T14:30") == datetime(2026, 9, 11, 14, 30), (
        "an end that names a time must mean that instant — adding a day here silently widens the "
        "range by 24 hours")


@pytest.mark.unit
def test_the_endpoint_distinguishes_the_two_spellings():
    src = API.read_text(encoding="utf-8")
    start = src.index("def _build_audit_query(")
    body = src[start:src.index("\ndef ", start + 1)]
    assert "timedelta(days=1)" in body, "a bare date must still cover its whole day"
    assert re.search(r"len\(to_date\.strip\(\)\) <= 10", body), (
        "the query must tell a bare date from an instant; without that check every timed end is "
        "widened by a day")


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
