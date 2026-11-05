"""Keep an older release from starting while legal holds stand, or what they kept waits for its purge.

A release before the legal holds ignores the kept tables: it deletes a held file's blob when its row is deleted
(the database's trigger still keeps the row, but its bytes are gone), keeps nothing on a same-name replacement or
an expiry, retires a zero-knowledge vault's older key versions that kept files, folders and old names were sealed
under, and the vaults trigger refuses its deletion of a held vault with an error. So while any hold stands or any
kept row remains (DETECT_SQL: a kept file, folder or old name), this module keeps a row in ``data_requirements``:
every release from the one that reads that table refuses to start when a row names a version above its own (the
operator's undo, or the escape variable, lets it start), and ``dockvault.py update`` refuses the rollback unless
forced, naming the row (app/core/host_operator.py, downgrade-blockers). The row goes when the last hold is
released and what the holds kept is purged. It is written in the transaction that places a hold or restores one,
removed by the one that purges the last kept row, and checked again at each start and by every pass of the
pruner's legal_holds job.

Those transactions do not all take the same turn (the purge's last one takes none), so the row is written and
removed in a way that holds when two of them run at once (sync): its row is locked before the detect query runs,
so a placing that refreshed it is waited for and its hold seen; it is written with one upsert, so two first writers
do not collide; and it is removed only while the detect query still finds nothing, so one that commits a hold
before the removal's statement starts keeps it.

A release older than the reader of that table (before 0.33.1) is not protected by the row; the upgrade notes
say so. CONDITION is the upgrade matrix's condition for the edge back to an earlier release, written into the
matrix in the release commit.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

KEY = "legal-holds"
TABLE = "data_requirements"
# The first release with the legal holds: the oldest that can be rolled back to while they keep anything.
INTRODUCED = "0.34.0"
REASON = ("Legal holds keep files deleted from vaults, and the old names of renamed ones, until their release and "
          "purge. A release before {introduced} would destroy the kept files and keep nothing more.")
# How to undo it, as an older release prints it after "To go back to this version, first undo it with the newer
# version:", so it names the release that removes the marker ({version}: the one the marker asks for), never "this
# version", which there reads as the older release that refuses.
UNDO = ("Release every legal hold (on the Compliance page, or with dockvault.py cases), wait until what they kept "
        "is purged (COMPLIANCE_HOLD_PURGE_DELAY_DAYS after the release), then start DockVault {version} or later "
        "once so it removes this marker.")

# The detect query of the upgrade condition: a row while a hold stands or a kept row remains (the three kept tables
# the vaults trigger counts, app/core/kept_tables.py).
DETECT_SQL = ("SELECT 1 FROM legal_hold_vaults WHERE released_at IS NULL "
              "UNION ALL SELECT 1 FROM held_files UNION ALL SELECT 1 FROM held_folders "
              "UNION ALL SELECT 1 FROM held_name_history LIMIT 1")

# The matrix's condition on the edge from 0.34.0 back to earlier releases (written in the release commit).
CONDITION = {
    "id": "legal-holds-block-rollback",
    "summary": ("While a legal hold stands, or what a hold kept (files, folders, the old names of renamed ones) waits "
                "for its purge, going back to a release before 0.34.0 would destroy it: release the holds and let "
                "the purge run first."),
    "detect": DETECT_SQL,
    "blocks_rollback": True,
}


def holds_or_kept(db) -> bool:
    """The upgrade condition's detect query, run against this database."""
    return db.execute(text(DETECT_SQL)).first() is not None


def required_version() -> str:
    """The version the marker asks for: the release that introduced the holds, or this build's own version when
    it is an earlier one (a build made before the release must still start on its own data)."""
    from app.core import recording_marker
    running = recording_marker.running_version()
    have = recording_marker._parse(running)
    return running if have is not None and have < recording_marker._parse(INTRODUCED) else INTRODUCED


def sync(db, *, now: Optional[datetime] = None) -> bool:
    """Bring the marker in line with the holds, in the caller's transaction (the caller commits): kept while a
    hold stands or a kept row remains, removed otherwise. Returns whether the marker is there.

    Safe beside another transaction doing the same (see the module's docstring). At READ COMMITTED each statement
    reads what was committed when it starts, and a removal that waited for the row's lock checks again only its own
    row, not the holds; so the row is locked first (on Postgres), and the detect query runs after: a placing that
    refreshed the row has committed by then, and its hold is seen. The row is written with one upsert (two first
    writers would collide on its key), and removed only while the detect query, run again by the removal itself,
    finds nothing."""
    from app.core import recording_marker
    db.flush()      # the caller's own holds and kept rows, not yet written (the sessions do not autoflush)
    recording_marker._ensure_table(db)
    if recording_marker._on_postgres(db):
        db.execute(text(f"SELECT key FROM {TABLE} WHERE key = :key FOR UPDATE"), {"key": KEY})
    there = holds_or_kept(db)
    if not there:
        db.execute(text(f"DELETE FROM {TABLE} WHERE key = :key AND NOT EXISTS ({DETECT_SQL})"), {"key": KEY})
        # Kept when a hold committed before the removal started: say so.
        return db.execute(text(f"SELECT 1 FROM {TABLE} WHERE key = :key"), {"key": KEY}).first() is not None
    when = now or datetime.now(timezone.utc).replace(tzinfo=None)
    version = required_version()
    recording_marker.write_row(db, KEY, version, REASON.format(introduced=INTRODUCED),
                               UNDO.format(version=version), when)
    return True


def check_at_start() -> Optional[bool]:
    """sync() in a transaction of its own, at the start. Never raises: a failure is said, and the pruner's next
    pass syncs again. Returns whether the marker is there, or None when it could not be checked."""
    from app.core.database import get_db_context
    try:
        with get_db_context() as db:
            there = sync(db)
            db.commit()
            return there
    except Exception as exc:  # noqa: BLE001
        print(f"Warning: the legal holds' rollback marker was not checked ({type(exc).__name__})")
        return None
