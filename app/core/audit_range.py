"""Turning a from/to filter into the range the audit query actually uses.

Split out so it can be tested against the real function rather than a copy of it. The first test of
this behaviour restated the rule inside the test file and asserted its own restatement, which proves
only that the restatement is self-consistent: the endpoint could have been changed to anything at all
and the test would still have passed.

Importing the API module is not an option for a unit test — it runs the whole runtime bootstrap and
exits when no secrets are configured — so the logic lives here, side-effect-free, exactly as
`admin_bootstrap` and `settings_bootstrap` do.

WHAT ZONE A VALUE IS IN
-----------------------
The audit `timestamp` column is naive UTC. The page's From/To inputs are `datetime-local`: a
wall-clock time in the viewer's zone with no zone attached. Sent as typed, that value was read here
as if it were UTC, so every timed filter was off by the viewer's UTC offset — an admin two hours
east of Greenwich filtering around an event they could see on the same screen got nothing, and the
CSV export had the same hole. The page now sends an explicit instant (an ISO string with its offset)
and both bounds below convert such a value to UTC before comparing. A value with no offset is still
taken as it stands, which is what anyone calling the endpoint by hand with a UTC wall-clock gets.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

# "YYYY-MM-DD" is ten characters. Anything longer names a time as well.
_DATE_ONLY_LEN = 10


def is_date_only(value: str) -> bool:
    """Whether this filter value names a day, or an instant within one."""
    return len(value.strip()) <= _DATE_ONLY_LEN


def as_naive_utc(value: Optional[str]) -> Optional[datetime]:
    """A filter value as a naive UTC datetime — the column's own terms — or None if unreadable.

    An offset-bearing value (what the page sends: `2026-09-11T12:30:00.000Z`, or `+02:00`) is moved
    to UTC and its zone dropped, so it compares against the column as the instant it names. A value
    with no offset is returned as parsed.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def lower_bound(from_date: Optional[str]) -> Optional[datetime]:
    """The inclusive start of the range, or None when the value is absent or unparseable.

    A bare date starts at midnight, which is what `fromisoformat` already gives, so both spellings
    need the same treatment here. Only the upper bound differs.
    """
    return as_naive_utc(from_date)


def upper_bound(to_date: Optional[str]) -> Optional[datetime]:
    """The EXCLUSIVE end of the range, or None when the value is absent or unparseable.

    A bare date means "up to the end of that day", so a whole day is added: `to=2026-09-11` must
    include something logged at 23:59 on the 11th.

    A value that names a time means exactly that instant. Adding a day there — which is what the
    query did for every value, because `fromisoformat` accepts both spellings and nothing told them
    apart — silently widened the range by 24 hours, so "up to 14:30" also returned tomorrow
    lunchtime's events. That was invisible until the filter inputs gained a time.
    """
    parsed = as_naive_utc(to_date)
    if parsed is None:
        return None
    return parsed + timedelta(days=1) if is_date_only(to_date) else parsed
