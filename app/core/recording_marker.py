"""Keep an older release from starting on data recorded at lower levels than it would record.

A release before the recording levels records everything it always did: names typed at sign-in, email addresses,
addresses and browser descriptions in full, with no version on its rows. Rolled back while the levels record less
of any of those, it would go on recording them in full, behind the notice that tells users otherwise.

So while the newest version of the levels records less of any kind than earlier releases did (STRICTER_SQL), this
module keeps a row in ``data_requirements``: the table every release from the one that reads it on checks at start,
refusing to start when a row names a version above its own (the operator's undo, or an explicit override, lets it
start). The row goes when the levels are set back. It is written in the transaction that writes the version, and
checked again at each start and once a day.

A release older than the reader of that table is not protected by the row; the upgrade notes say so.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Optional

from sqlalchemy import text

from app.core import audit_privacy as ap

KEY = "recording-levels"
TABLE = "data_requirements"
# The first release that records under the levels: the oldest that can be rolled back to safely.
INTRODUCED = "0.34.0"
REASON = ("The recording levels record less than releases before {introduced} do (names typed at sign-in, email "
          "addresses, IP addresses or browser descriptions). An earlier release would record them all in full.")
# How to undo it, as an older release prints it after "To go back to this version, first undo it with the newer
# version:", so it names the release that removes the marker ({version}: the one the marker asks for), never "this
# version", which there reads as the older release that refuses.
UNDO = ("Set the recording levels back to Full for names typed at sign-in, email addresses, IP addresses and browser "
        "descriptions (Settings, Activity and records), and remove any AUDIT_MAX_* line in .env that lowers one, then "
        "start DockVault {version} or later once so it removes this marker.")

# The detect query of the upgrade condition: a row when the newest version records less than earlier releases.
STRICTER_SQL = ("SELECT 1 FROM audit_privacy_policies WHERE version = (SELECT max(version) FROM audit_privacy_policies) "
                "AND (signin_names <> 'full' OR emails <> 'full' OR ip <> 'full' OR user_agent <> 'full')")

# The table as the reader expects it, column by column (the newer release's model may add columns).
_DDL_POSTGRES = ("CREATE TABLE IF NOT EXISTS data_requirements (key VARCHAR(64) PRIMARY KEY, "
                 "requires_at_least VARCHAR(32) NOT NULL, reason TEXT NOT NULL, undo TEXT, "
                 "since TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'))")
_DDL_OTHER = ("CREATE TABLE IF NOT EXISTS data_requirements (key VARCHAR(64) PRIMARY KEY, "
              "requires_at_least VARCHAR(32) NOT NULL, reason TEXT NOT NULL, undo TEXT, since TIMESTAMP NOT NULL)")

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse(version: str):
    match = _VERSION.fullmatch((version or "").strip())
    return tuple(int(p) for p in match.groups()) if match else None


def running_version() -> str:
    """This image's version, from the VERSION file baked into it."""
    for path in (Path(__file__).resolve().parents[2] / "VERSION", Path("/app/VERSION")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return ""


def required_version(running: Optional[str] = None) -> str:
    """The version the marker asks for: the release that introduced the levels, or this build's own version when
    it is an earlier one (a build made before the release must still be able to start on its own data)."""
    running = running if running is not None else running_version()
    have = _parse(running)
    return running if have is not None and have < _parse(INTRODUCED) else INTRODUCED


def records_less(levels) -> bool:
    """Whether ``levels`` record less, of any kind, than releases before the levels did."""
    return any(ap.rank(levels[key]) < ap.rank(ap.POLICY_ONE[key]) for key in ap.POLICY_KEYS)


def stricter_now(db) -> bool:
    """The upgrade condition's detect query, run against this database."""
    return db.execute(text(STRICTER_SQL)).first() is not None


def _ensure_table(db) -> None:
    postgres = db.bind is not None and db.bind.dialect.name == "postgresql"
    db.execute(text(_DDL_POSTGRES if postgres else _DDL_OTHER))


def sync(db, levels=None, *, now=None) -> bool:
    """Bring the marker in line with the levels, in the caller's transaction (the caller commits): kept while the
    newest version (or ``levels``, about to be written) records less than earlier releases, removed otherwise.
    Returns whether the marker is there."""
    from datetime import datetime, timezone
    stricter = records_less(levels) if levels is not None else stricter_now(db)
    _ensure_table(db)
    if not stricter:
        db.execute(text(f"DELETE FROM {TABLE} WHERE key = :key"), {"key": KEY})
        return False
    when = now or datetime.now(timezone.utc).replace(tzinfo=None)
    version = required_version()
    params = {"key": KEY, "version": version, "reason": REASON.format(introduced=INTRODUCED),
              "undo": UNDO.format(version=version), "since": when}
    updated = db.execute(text(f"UPDATE {TABLE} SET requires_at_least = :version, reason = :reason, undo = :undo "
                              "WHERE key = :key"), params).rowcount
    if not updated:
        db.execute(text(f"INSERT INTO {TABLE} (key, requires_at_least, reason, undo, since) "
                        "VALUES (:key, :version, :reason, :undo, :since)"), params)
    return True


# Checked again once a day by the levels' background refresher.
CHECK_SECONDS = 24 * 3600.0
_last_check: Optional[float] = None


def check_daily(session_factory, *, now: Optional[float] = None) -> Optional[bool]:
    """sync() in a transaction of its own, at most once a day. Never raises. Returns whether the marker is there,
    or None when it was not checked."""
    global _last_check
    now = time.monotonic() if now is None else now
    if _last_check is not None and now - _last_check < CHECK_SECONDS:
        return None
    try:
        db = session_factory()
    except Exception:  # noqa: BLE001
        return None
    try:
        ap.lock_policies(db)
        there = sync(db)
        db.commit()
        _last_check = now
        return there
    except Exception:  # noqa: BLE001 -- tried again at the next turn
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None
    finally:
        db.close()


def _reset_for_tests() -> None:
    global _last_check
    _last_check = None
