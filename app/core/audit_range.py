"""Turning a from/to filter into the range the audit query actually uses.

Split out so it can be tested against the real function rather than a copy of it. The first test of
this behaviour restated the rule inside the test file and asserted its own restatement, which proves
only that the restatement is self-consistent: the endpoint could have been changed to anything at all
and the test would still have passed.

Importing the API module is not an option for a unit test — it runs the whole runtime bootstrap and
exits when no secrets are configured — so the logic lives here, side-effect-free, exactly as
`admin_bootstrap` and `settings_bootstrap` do.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

# "YYYY-MM-DD" is ten characters. Anything longer names a time as well.
_DATE_ONLY_LEN = 10


def is_date_only(value: str) -> bool:
    """Whether this filter value names a day, or an instant within one."""
    return len(value.strip()) <= _DATE_ONLY_LEN


def lower_bound(from_date: Optional[str]) -> Optional[datetime]:
    """The inclusive start of the range, or None when the value is absent or unparseable.

    A bare date starts at midnight, which is what `fromisoformat` already gives, so both spellings
    need the same treatment here. Only the upper bound differs.
    """
    if not from_date:
        return None
    try:
        return datetime.fromisoformat(from_date)
    except ValueError:
        return None


def upper_bound(to_date: Optional[str]) -> Optional[datetime]:
    """The EXCLUSIVE end of the range, or None when the value is absent or unparseable.

    A bare date means "up to the end of that day", so a whole day is added: `to=2026-09-11` must
    include something logged at 23:59 on the 11th.

    A value that names a time means exactly that instant. Adding a day there — which is what the
    query did for every value, because `fromisoformat` accepts both spellings and nothing told them
    apart — silently widened the range by 24 hours, so "up to 14:30" also returned tomorrow
    lunchtime's events. That was invisible until the filter inputs gained a time.
    """
    if not to_date:
        return None
    try:
        parsed = datetime.fromisoformat(to_date)
    except ValueError:
        return None
    return parsed + timedelta(days=1) if is_date_only(to_date) else parsed
