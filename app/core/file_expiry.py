"""File expiry: once a file's retention has run out, the file is gone.

A vault can expire its files a number of minutes, hours or days after they are uploaded (its
``expire_files_after_days`` and ``expire_files_unit``), and an upload link's "delete uploads after"
retention is the same setting on the link's own vault. The deadline is stamped on each file at upload
as ``File.expires_at``: UTC, in a column WITHOUT a time zone.

Two things make that deadline real, and both go through this module:

* Every read path treats a file past its deadline as absent -- the vault and folder listing, the web
  download (whole or ranged), the rendered preview, file info, copy and move, SFTP listing, stat and
  open, public file links and shares. A file stops being reachable the moment it expires, not when
  the sweep next runs. Paths that look a file up by id apply :func:`live_clause` to the query, or
  :func:`is_expired` to the row they already hold.
* A sweep in the web process (:func:`run_forever`, started at boot) deletes expired files and their
  stored bytes in batches, once a minute, and records one ``file_expired`` audit row for each.

The comparison is always made against a naive UTC "now" (:func:`utc_now`). Every app connection's
session runs in UTC (app/core/database.py), so an aware datetime bound into a query against this column
is converted to UTC too. Deadlines written before 0.32.6 were stamped with an aware time through the
session's zone, which was the database's: on a database set to a zone behind UTC those files expire
early by that offset.

A vault whose expiry is off has no file deadlines. Changing the setting leaves the deadlines files
already have, but turning it off takes the deadline off every file in the vault in the same
transaction (``VaultService.set_file_expiry``). Versions before enforcement did not, so at boot, before
the sweep's first run, the web process clears the deadlines left in vaults whose expiry is off
(:func:`prepare_at_startup`); and the sweep itself only ever deletes from vaults whose expiry is on.

``ENFORCE_FILE_EXPIRY=false`` switches both off, so an operator can postpone enforcement while
reviewing what it would remove: nothing is hidden and nothing is deleted. Deadlines are still stamped
at upload, so turning enforcement back on applies them, including to files that expired meanwhile.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import and_, or_, select, true

from app.core.config import settings
from app.core.models import File, Vault
from app.core.safe_log import safe_event

# How often the sweep runs, how many files one transaction deletes, and how many batches one run
# may take. A run removes up to BATCH_SIZE * MAX_BATCHES files, so a large backlog -- enforcement
# switched on over a deployment that has been accumulating expired files -- drains over a few runs
# in short transactions rather than one long one.
SWEEP_INTERVAL_SECONDS = 60
SWEEP_BATCH_SIZE = 200
SWEEP_MAX_BATCHES = 25

# One thread of its own: the sweep does blocking database and disk work, so it must stay off the
# event loop, and it must not take a slot another caller is queued for.
_sweep_executor = None


def enforcement_enabled() -> bool:
    """True unless the operator has set ENFORCE_FILE_EXPIRY=false."""
    return bool(getattr(settings, "enforce_file_expiry", True))


def utc_now() -> datetime:
    """Now, in the form ``File.expires_at`` is stored in: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_stored_utc(value: datetime) -> datetime:
    """``value`` in the stored form. An aware datetime is converted to UTC and its zone dropped; a
    naive one is taken to be UTC already, which is how the column is written."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def is_past(expires_at: Optional[datetime], now: Optional[datetime] = None) -> bool:
    """True when a deadline has been reached. No deadline never expires.

    Ignores the switch; :func:`is_expired` is the one read paths ask."""
    if expires_at is None:
        return False
    now = as_stored_utc(now) if now is not None else utc_now()
    return as_stored_utc(expires_at) <= now


def is_expired(file, now: Optional[datetime] = None) -> bool:
    """True when ``file`` must be treated as gone: enforcement is on and its deadline has passed.

    For a path that already holds the row. With enforcement off, never True."""
    if file is None or not enforcement_enabled():
        return False
    return is_past(getattr(file, "expires_at", None), now)


def live_clause(now: Optional[datetime] = None):
    """A filter for ``File`` queries that keeps only files that have not expired.

    With enforcement off it keeps every file, so a query that applies it reads exactly as it did
    before enforcement existed. The boundary matches :func:`is_past`: a file whose deadline is
    exactly now has expired."""
    if not enforcement_enabled():
        return true()
    now = as_stored_utc(now) if now is not None else utc_now()
    return or_(File.expires_at.is_(None), File.expires_at > now)


def expired_clause(now: Optional[datetime] = None):
    """The complement of :func:`live_clause`: files whose deadline has passed. Ignores the switch;
    the sweep checks it before deleting anything, and the startup report counts either way."""
    now = as_stored_utc(now) if now is not None else utc_now()
    return and_(File.expires_at.isnot(None), File.expires_at <= now)


def expiry_is_off(value) -> bool:
    """True when a vault's "expire files after" value means its files never expire: blank or 0.
    A value below 0 counts as off too; this version refuses to store one, but earlier ones did not
    check, and a negative retention must never make every upload expire on arrival."""
    return value is None or value <= 0


# The longest a vault's "expire files after" may be, in each unit it can be given in: 100 years.
# Nothing longer is of use, and a deadline far enough out does not fit a date at all: working it out
# failed every upload into the vault, and a value past the column's range failed the save itself.
MAX_EXPIRY = {"minutes": 52_560_000, "hours": 876_000, "days": 36_500}


def max_expiry(unit) -> int:
    """The largest "expire files after" value ``unit`` takes. A unit that is not minutes or hours
    is read as days, as it is when the deadline is worked out."""
    return MAX_EXPIRY.get(unit, MAX_EXPIRY["days"])


def check_not_too_long(value, unit) -> None:
    """Raise ValueError, with a message fit to show, when ``value`` ``unit`` is longer than 100
    years. A value that turns expiry off is never too long."""
    if not expiry_is_off(value) and value > max_expiry(unit):
        unit = unit if unit in MAX_EXPIRY else "days"
        raise ValueError(f"File expiry can be at most 100 years ({max_expiry(unit):,} {unit}).")


def vault_expiry_on():
    """A filter for ``Vault`` queries: vaults whose files expire (a positive setting)."""
    return Vault.expire_files_after_days > 0


def vault_expiry_off():
    """The complement of :func:`vault_expiry_on`, NULL included: vaults whose files never expire."""
    return or_(Vault.expire_files_after_days.is_(None), Vault.expire_files_after_days <= 0)


def clear_vault_deadlines(db, vault_id) -> int:
    """Take the deadline off every file in one vault, in the caller's transaction, and return how
    many files had one. For a vault whose expiry has just been turned off.

    The files' modified time is kept: removing a deadline does not change a file."""
    return (db.query(File)
            .filter(File.vault_id == vault_id, File.expires_at.isnot(None))
            .update({File.expires_at: None, File.updated_at: File.updated_at},
                    synchronize_session=False))


def clear_deadlines_where_expiry_is_off(db) -> int:
    """Take the deadline off every file whose vault has expiry off, in the caller's transaction,
    and return how many files had one.

    Turning a vault's expiry off did not always do this: before enforcement, deadlines stayed on
    the files, harmless because nothing read them. Enforcing them would delete files from a vault
    whose owner turned expiry off long ago. One statement; with nothing to clear it changes no row,
    so it can run on every boot."""
    off_vaults = select(Vault.id).where(vault_expiry_off())
    return (db.query(File)
            .filter(File.expires_at.isnot(None), File.vault_id.in_(off_vaults))
            .update({File.expires_at: None, File.updated_at: File.updated_at},
                    synchronize_session=False))


def clear_at_startup() -> bool:
    """:func:`clear_deadlines_where_expiry_is_off` in a session of its own. Returns whether it ran;
    never raises. Runs whether or not expiry is enforced: a deadline in a vault whose expiry is off
    is wrong either way, and would be enforced the moment enforcement is switched on."""
    try:
        from app.core.database import get_db_context
        with get_db_context() as db:
            n = clear_deadlines_where_expiry_is_off(db)
    except Exception as e:  # noqa: BLE001
        safe_event('file-expiry.clear-off-vaults.failed', e)
        return False
    if n:
        print(f"[OK] File expiry: removed the deadline from {n} file(s) in vaults whose expiry is "
              f"off")
    return True


def count_past_expiry(db, now: Optional[datetime] = None) -> int:
    """How many stored files are past their deadline right now, whether or not it is enforced."""
    from sqlalchemy import func
    return int(db.query(func.count(File.id)).filter(expired_clause(now)).scalar() or 0)


def report_at_startup() -> None:
    """Log once, at boot, how many files are already past their expiry and what will happen to them.

    Never raises: a report that cannot be made must not stop the server starting."""
    try:
        from app.core.database import get_db_context
        with get_db_context() as db:
            n = count_past_expiry(db)
    except Exception as e:  # noqa: BLE001
        safe_event('file-expiry.startup-count.failed', e)
        return
    if enforcement_enabled():
        print(f"[OK] File expiry is enforced: {n} file(s) are past their expiry and will be "
              f"deleted by the sweep")
    else:
        print(f"⚠ File expiry is NOT enforced (ENFORCE_FILE_EXPIRY=false): {n} file(s) are past "
              f"their expiry and are being kept")


def prepare_at_startup() -> bool:
    """What the web process does once at boot, before the sweep's first run: clear the deadlines left
    in vaults whose expiry is off (:func:`clear_at_startup`), then report what is past its expiry.
    Returns whether the deadlines were cleared; pass it to :func:`run_forever`, which retries the
    clearing before it sweeps anything if it did not. Never raises."""
    cleared = clear_at_startup()
    report_at_startup()
    return cleared


def sweep_once(batch_size: int = SWEEP_BATCH_SIZE, max_batches: int = SWEEP_MAX_BATCHES) -> int:
    """Delete expired files, one batch per transaction, each in a session of its own. Returns how
    many were deleted.

    Does nothing with enforcement off. Never raises: a failed batch is rolled back and logged, and
    the run stops there for the next one to retry, because a batch that failed once will usually
    fail again straight away. A batch smaller than ``batch_size`` means nothing else is due (rows
    another sweeper holds are skipped, not waited for), so the run ends."""
    if not enforcement_enabled():
        return 0
    from app.core.authorization import PermissionService
    from app.core.database import get_db_context
    from app.services.vault_service import VaultService

    total = 0
    for _ in range(max(1, int(max_batches))):
        try:
            with get_db_context() as db:
                deleted = VaultService(db, PermissionService(db)).cleanup_expired_files(
                    batch_size=batch_size)
        except Exception as e:  # noqa: BLE001
            safe_event('file-expiry.sweep.failed', e, removed=total)
            break
        total += len(deleted)
        if len(deleted) < batch_size:
            break
    if total:
        safe_event('file-expiry.swept', removed=total)
    return total


def _executor() -> ThreadPoolExecutor:
    global _sweep_executor
    if _sweep_executor is None:
        _sweep_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="file-expiry")
    return _sweep_executor


async def run_forever(interval_seconds: float = SWEEP_INTERVAL_SECONDS, *,
                      cleared: bool = False) -> None:
    """The web process's expiry loop: :func:`sweep_once` every ``interval_seconds``, on a thread
    of its own. Started only by the web process, so a split deployment's SFTP container never runs
    a second sweeper. Survives any error; ends only when cancelled.

    ``cleared`` says whether the deadlines left in vaults whose expiry is off have been cleared
    (:func:`prepare_at_startup`). Until they have, each pass retries that instead of sweeping."""
    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            if not cleared:
                cleared = await loop.run_in_executor(_executor(), clear_at_startup)
                if not cleared:
                    continue
            await loop.run_in_executor(_executor(), sweep_once)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            safe_event('file-expiry.loop.failed', e)
