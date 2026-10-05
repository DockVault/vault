"""Case numbers: C-2026-0007, one sequence per year, given when a case is approved.

allocate() takes the next number of the year in the caller's transaction (the approval's) and never commits.
On Postgres one statement inserts the year's counter or adds one to it, and keeps that row locked until the
transaction ends: a second approval at the same moment waits for the first, then gets the next number; an
approval that is rolled back takes its number back with it. So two cases never share a number, and the numbers
of approved cases have no gaps. Owners see the number, and an export's manifest cites it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

PREFIX = "C"

_NEXT_SQL = text(
    "INSERT INTO compliance_case_counters (year, last_number) VALUES (:year, 1) "
    "ON CONFLICT (year) DO UPDATE SET last_number = compliance_case_counters.last_number + 1 "
    "RETURNING last_number")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def format_number(year: int, number: int) -> str:
    """C-<year>-<number>, the number at least four digits long."""
    return f"{PREFIX}-{year}-{number:04d}"


def allocate(db, now: Optional[datetime] = None) -> str:
    """The next case number of ``now``'s year (UTC), taken in ``db``'s transaction. Never commits."""
    from app.core.models import ComplianceCaseCounter
    year = (now or utcnow()).year
    if db.get_bind().dialect.name == "postgresql":
        number = db.execute(_NEXT_SQL, {"year": year}).scalar_one()
    else:
        # Elsewhere (the offline tests' SQLite, which serializes writers anyway) the same result in two steps.
        row = db.get(ComplianceCaseCounter, year)
        if row is None:
            row = ComplianceCaseCounter(year=year, last_number=0)
            db.add(row)
        row.last_number += 1
        db.flush()
        number = row.last_number
    return format_number(year, int(number))
