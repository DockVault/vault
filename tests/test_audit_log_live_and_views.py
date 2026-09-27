"""The audit log's time range: a bare date means the whole day, an instant means exactly that.

`datetime.fromisoformat` accepts either spelling, but the end of the range used to add a whole day
unconditionally: correct for a bare date, and a silent 24-hour widening for an instant, so "up to 14:30"
also returned tomorrow lunchtime. The two are told apart in app/core/audit_range.py, which the Events API
and the audit log API both use.

The Settings -> Audit Log tab that this file also covered (its two views and its live poll) was removed in
0.33.0; the Activity page replaced it.

Lanes:
  * unit        -- the range arithmetic for both spellings, and that the query uses the shared module.
  * integration -- a window spelled in another zone finds a row written inside it.
"""
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.core import audit_range

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"


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
@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-date", "2026-13-45",
                                 # Instants that, moved to UTC, fall off either end of the calendar.
                                 "0001-01-01T00:00:00+01:00", "9999-12-31T23:30:00-01:00"])
def test_an_unusable_filter_value_is_ignored_rather_than_fatal(bad):
    """A filter nobody can parse must drop out of the query, not 500 the page."""
    assert audit_range.upper_bound(bad) is None
    assert audit_range.lower_bound(bad) is None


@pytest.mark.unit
def test_the_calendars_last_day_runs_to_its_end():
    """A day ends at the next midnight, which the last day of the calendar does not have."""
    assert audit_range.upper_bound("9999-12-31") == datetime.max
    assert audit_range.upper_bound("9999-12-31T23:00:00") == datetime(9999, 12, 31, 23, 0)


@pytest.mark.unit
def test_the_start_of_the_range_is_inclusive_and_unmodified():
    assert audit_range.lower_bound("2026-09-11") == datetime(2026, 9, 11)
    assert audit_range.lower_bound("2026-09-11T14:30") == datetime(2026, 9, 11, 14, 30)


@pytest.mark.unit
@pytest.mark.parametrize("value,expected", [
    ("2026-09-11T12:30:00.000Z",     datetime(2026, 9, 11, 12, 30)),   # what the page now sends
    ("2026-09-11T12:30:00Z",         datetime(2026, 9, 11, 12, 30)),
    ("2026-09-11T14:30:00+02:00",    datetime(2026, 9, 11, 12, 30)),   # east of Greenwich
    ("2026-09-11T03:30:00-09:00",    datetime(2026, 9, 11, 12, 30)),   # west of it
    ("2026-09-12T01:30:00+13:00",    datetime(2026, 9, 11, 12, 30)),   # across midnight
])
def test_an_instant_carrying_its_zone_is_compared_in_utc(value, expected):
    """The column is naive UTC. A value that says which zone it is in must land on the same
    instant however it was spelled, and must come back naive so the comparison is like with like.
    Every one of these is an instant, so the upper bound must not add a day to it either."""
    lo, hi = audit_range.lower_bound(value), audit_range.upper_bound(value)
    assert lo == expected and hi == expected, (value, lo, hi)
    assert lo.tzinfo is None and hi.tzinfo is None, "bounds must be naive, like the column"


@pytest.mark.unit
def test_a_value_without_a_zone_is_taken_as_it_stands():
    """Not everyone types a filter into the page. A bare wall-clock value is still read as the UTC
    the column is in — the same as before — so a hand-written query does not change meaning."""
    assert audit_range.lower_bound("2026-09-11T14:30") == datetime(2026, 9, 11, 14, 30)
    assert audit_range.lower_bound("2026-09-11T14:30").tzinfo is None


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


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_a_window_spelled_in_another_zone_finds_a_row_written_inside_it(admin, temp_vault, temp_user):
    """A row at a known instant, then a From/To window around it spelled in a zone that is not UTC.

    This pins the server's side of the contract: an instant is an instant however its zone is
    written. It is not the lane that goes red for the reported bug — a database that casts an
    offset-bearing literal itself can pass this on the old code too. What the page actually sent
    was a zone-less local wall-clock; the page's own conversion is the Activity page's to test.
    """
    from datetime import datetime, timedelta, timezone

    r = admin.post(f"/vaults/{temp_vault['id']}/permissions",
                   json={"user_id": temp_user["id"], "level": "read"})
    assert r.status_code in (200, 201), r.text
    rows = admin.get("/audit/log?action=vault_permission_granted").json()
    row = next(x for x in rows if x["resource_id"] == temp_vault["id"])
    at = datetime.fromisoformat(row["timestamp"]).replace(tzinfo=timezone.utc)

    # Not a whole number of hours, and no daylight saving to muddy it.
    zone = timezone(timedelta(hours=5, minutes=30))
    window = {"action": "vault_permission_granted",
              "from_date": (at - timedelta(minutes=1)).astimezone(zone).isoformat(),
              "to_date": (at + timedelta(minutes=1)).astimezone(zone).isoformat()}
    found = admin.get("/audit/log", params=window).json()
    assert any(x["resource_id"] == temp_vault["id"] for x in found), (
        f"a two-minute window around the row, spelled in +05:30, did not find it: {window}")

    # And the same instants, one minute AFTER the row: the window must genuinely bound.
    later = {"action": "vault_permission_granted",
             "from_date": (at + timedelta(minutes=1)).astimezone(zone).isoformat()}
    assert not any(x["resource_id"] == temp_vault["id"]
                   for x in admin.get("/audit/log", params=later).json()), (
        "a window that starts after the row must not contain it")
