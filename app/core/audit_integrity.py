"""The audit log's integrity chain: hourly seals over the audit rows, chained under a key the database never
holds, and a copy of the chain's head kept outside the database.

What it gives. Every closed UTC hour of audit rows, empty ones included, is sealed: its seal holds two Merkle
roots, one over the fields of each row that never change, one over a commitment to the row's personal values
under a random per-row nonce, so a later change of personal values (an erase, a shortened address) touches the
second root only. Each seal's link hashes the previous link and the seal's body, and carries an HMAC under the
chain's key (AUDIT_CHAIN_KEY, or a key derived from ENCRYPTION_KEY). Against someone who can write to the
database but holds no key, a changed, added or removed sealed row is found down to its hour, and a changed,
forged, reordered or cut seal is found. It is tamper-evident against changes made in the database without the
server's key; not against the server's operator, who holds the key. A head kept elsewhere (printed by
``dockvault.py audit verify``, shown on the Activity page, written into every export) makes the operator's
later changes to the history before it visible, as seals after it.

Rows are sealed AUDIT_SEAL_LAG_MINUTES after their hour closes, once no transaction that began before the hour
closed is still open (for at most 6 hours). Rows that arrive in an hour sealed within the last 6 hours are
sealed by a ``late`` seal, which stays a warning until it is acknowledged; anything else is a failure. The first
start seals the existing log gradually, oldest first, never at start.

Who writes. The pruner (app/core/retention.py), one seal per transaction, and the paths that write a seal with
a change (a retention request, a cancel). Each writer takes the chain lock (a mutex in this process, then a
session-level advisory lock on the connection that writes the seal), reads the head record
(app/core/audit_head_record.py), and checks the database's chain against it before it writes: the chain must
reach the recorded head with every link recomputed from seal 1. A failure there stops sealing and writes an
``audit_integrity_failed`` row; the integrity status is read from the head record, never from those rows.

The verified view. This process keeps, in memory, the link of every seal it has accepted, recomputed from the
seal's body, and an index of every seal field the pruner acts on, so no such field is read from a column the
process has not authenticated.

The encoding is app/core/audit_chain_format.py; the keys app/core/audit_chain_keys.py; the verifier
app/core/audit_chain_verify.py (``python -m app.core.audit_integrity verify``).
"""
from __future__ import annotations

if __name__ == "__main__":
    # Run as the host command: hand over to the verifier, which imports this module under its own name (run as
    # __main__, this file would register its settings a second time when the app imports it).
    from app.core.audit_chain_verify import main as _main
    raise SystemExit(_main())

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

from sqlalchemy import Text, cast, func, text

from app.core import audit_chain_format as fmt
from app.core import audit_chain_keys as keys
from app.core import settings_registry as registry
from app.core.audit_head_record import HeadStore, LINK_EVERY
from app.core.audit_chain_view import (ArchiveEntry, ArchivePart, HourEntry, RootEntry,  # noqa: F401
                                      View, archive_parts)

# The lock that keeps writers of seals apart, in every process (distinct from every other lock class).
CHAIN_LOCK = (0x6163, 1)
LATE_WINDOW = timedelta(hours=6)
OPEN_TRANSACTION_WAIT = timedelta(hours=6)
FUTURE_SLACK = timedelta(hours=1)
SEAL_STATEMENT_TIMEOUT_MS = 60000
ROW_BUDGET = 50000
PASS_SECONDS = 60.0
DAILY = timedelta(hours=24)
KEY_WAIT_GRACE = timedelta(hours=24)
HOUR = timedelta(hours=1)

LAG_KEY = "audit_seal_lag_minutes"
registry.register(registry.SettingSpec(
    key=LAG_KEY, kind="int", default=60, env="audit_seal_lag_minutes", minimum=0, maximum=1440,
    editable=registry.ENV_ONLY, group="audit_integrity", unit="minutes",
    label="Wait after an hour closes before its audit rows are sealed",
    help="Each closed hour of audit rows is sealed this long after it ends, so the rows written in it have "
         "landed."))

# The kinds of seal, and which set an hour's roots.
KINDS = ("genesis", "policy", "request", "cancel", "hour", "late", "prune", "rewrite", "erase", "archive", "key",
         "ack", "restore")
# Kinds of seal another writer may not append after the head record in this release, because nothing here
# checks their fields (none now: every kind's checks are in audit verify's step 4).
UNCHECKED_KINDS: tuple = ()
ROOT_KINDS = ("hour", "late", "prune", "rewrite")
BODY_ROOT_KINDS = ("genesis", "hour", "late")

# The audit rows this module writes.
FAILED_ACTION = "audit_integrity_failed"
LATE_ACTION = "audit_rows_sealed_late"
ACKNOWLEDGED_ACTION = "audit_integrity_acknowledged"

FAILURE_KINDS = frozenset({
    "link-broken", "mac-invalid", "key-sequence", "key-unverified", "key-not-current", "seq-gap",
    "head-record-mismatch", "head-record-missing", "host-seal-unrecorded", "after-record-invalid",
    "anchor-mismatch", "key-change-waiting", "hour-missing", "rows-missing", "rows-added", "rows-altered",
    "stable-changed", "nonce-missing", "row-in-archived-day", "undated-row", "row-before-genesis",
    "backlog-count", "block-altered", "block-missing", "block-unsealed", "unjustified", "unjustified-input",
    "user-mismatch", "user-unlinked", "future-dated", "db-hooks"})
WARNING_KINDS = frozenset({"late", "veto-from-database", "after-record", "sealed-at-backwards", "restore-pending",
                           "head-record-unwritable", "key-change-waiting"})


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hour_floor(t: datetime) -> datetime:
    return t.replace(minute=0, second=0, microsecond=0)


def _say(message: str) -> None:
    registry._say(message)


def lag() -> timedelta:
    try:
        return timedelta(minutes=int(registry.resolve(LAG_KEY)))
    except KeyError:          # a registry a test set aside: the deployment's value
        return timedelta(minutes=int(getattr(_settings(), "audit_seal_lag_minutes", 60)))


def _settings():
    from app.core.config import settings
    return settings


def _release() -> str:
    try:
        from app.config import branding
        return str(branding.app_version or "unknown")
    except Exception:  # noqa: BLE001
        return "unknown"


class ChainStopped(Exception):
    """Sealing stops: the database's chain does not check out against the head record or the keys."""

    def __init__(self, kind: str, message: str, seq: Optional[int] = None):
        super().__init__(message)
        self.kind = kind
        self.seq = seq


class ChainBusy(Exception):
    """Another writer holds the chain lock."""


# --------------------------------------------------------------------------- seals

@dataclass
class Seal:
    seq: int
    kind: str
    period_start: Optional[datetime]
    period_end: Optional[datetime]
    format: int
    row_count: int
    row_bytes: int
    root_s: Optional[bytes]
    root_c: Optional[bytes]
    ids_digest: Optional[bytes]
    detail: Any
    key_id: str
    sealed_at: datetime
    mac: bytes = b""
    link: Optional[bytes] = None        # as stored; never trusted
    detail_text: Optional[str] = None   # as stored
    salt: Optional[bytes] = None        # the hour's salt for rows without a nonce, when the hour has one

    def detail_digest(self) -> bytes:
        if self.detail_text is not None:
            try:
                return fmt.detail_digest(fmt.parse_json(self.detail_text))
            except fmt.NotCanonical:
                import hashlib
                return hashlib.sha256(self.detail_text.encode("utf-8", "surrogatepass")).digest()
        return fmt.detail_digest(self.detail)

    def body(self) -> bytes:
        return fmt.body(self.seq, self.kind, self.period_start, self.period_end, self.format, self.row_count,
                        self.row_bytes, _b(self.root_s), _b(self.root_c), _b(self.ids_digest), self.detail_digest(),
                        self.key_id, self.sealed_at)


def _b(v) -> Optional[bytes]:
    return bytes(v) if v is not None else None


def _seal_columns():
    from app.core.models import AuditSeal as S
    return (S.seq, S.kind, S.period_start, S.period_end, S.format, S.row_count, S.row_bytes, S.root_s, S.root_c,
            S.ids_digest, cast(S.detail, Text), S.key_id, S.sealed_at, S.mac, S.link)


def _seal_from_row(r) -> Seal:
    import json
    detail_text = r[10]
    try:
        detail = json.loads(detail_text) if detail_text is not None else None
    except ValueError:
        detail = None
    return Seal(int(r[0]), r[1], r[2], r[3], int(r[4]), int(r[5]), int(r[6]), _b(r[7]), _b(r[8]), _b(r[9]), detail,
                r[11], r[12], _b(r[13]) or b"", _b(r[14]), detail_text)


def read_seals(db, after_seq: int = 0, upto: Optional[int] = None) -> Iterator[Seal]:
    """The seals after ``after_seq`` (up to ``upto``), body columns only, in seq order, streamed."""
    from app.core.models import AuditSeal as S
    q = db.query(*_seal_columns()).filter(S.seq > after_seq)
    if upto is not None:
        q = q.filter(S.seq <= upto)
    for r in q.order_by(S.seq).yield_per(500):
        yield _seal_from_row(r)


def read_seal(db, seq: int) -> Optional[Seal]:
    from app.core.models import AuditSeal as S
    r = db.query(*_seal_columns()).filter(S.seq == seq).first()
    return _seal_from_row(r) if r is not None else None


def newest_seq(db) -> int:
    from app.core.models import AuditSeal as S
    return int(db.query(func.max(S.seq)).scalar() or 0)


# --------------------------------------------------------------------------- the verified view

# The view itself is app/core/audit_chain_view.py: flat arrays, with every hour's roots read again
# through the link table when they are needed (hour_root below).


def foreign_entries(view: View, record: Optional[dict]) -> Dict[int, dict]:
    """The seals of the view's generation the head record lists as appended by another writer after it, not
    discarded: {seq: entry}. The list decides, not the recorded head, which later writes move past them."""
    return {int(e["seq"]): e for e in (record or {}).get("after_record") or []
            if e.get("generation") == view.generation and not e.get("discarded")}


def unacknowledged_foreign(view: View, record: Optional[dict]) -> set:
    """Another writer's seals the host has not acknowledged yet."""
    return {seq for seq, e in foreign_entries(view, record).items() if not e.get("acknowledged")}


def acknowledged(view: View, record: Optional[dict]) -> set:
    """The seals an acknowledgment that counts names: an ``ack`` or ``restore`` seal another writer appended
    after the head record acknowledges nothing, even once the host has acknowledged it."""
    foreign = set(foreign_entries(view, record))
    return {seq for seq, by in view.acked.items() if any(a not in foreign for a in by)}


def view_warning_seqs(view: View, record: Optional[dict]) -> Dict[str, List[int]]:
    """The warning seals the view holds that no acknowledgment that counts names: the late seals, and the seals
    the pruner wrote from the database's values."""
    done = acknowledged(view, record)
    return {"late": [s for s in view.late_seqs if s not in done],
            "veto-from-database": [s for s in database_seqs(view) if s not in done]}


def database_seqs(view: View) -> List[int]:
    """The seals the pruner wrote from the database's values (a veto, a request the database no longer shows
    pending ended): warnings until the host acknowledges them."""
    out = [seq for seq, d in view.policies if d.get("cause") == "database"]
    out += [seq for seq, by in view.cancel_by.items() if by == "database"]
    return sorted(out)


def hour_held(view: View, record: Optional[dict], hour: datetime) -> Optional[int]:
    """The seal that keeps the pruner from changing ``hour``: its root seal, or an erase seal after it, when that is
    a seal another writer appended after the head record and the host has not acknowledged (the hour's rows may
    have been edited and sealed over). None when there is none."""
    entry = view.entry_for(hour)
    if entry is None:
        return None
    waiting = unacknowledged_foreign(view, record)
    for seq in [entry.root.seq] + list(entry.erases):
        if seq in waiting:
            return seq
    return None


# --------------------------------------------------------------------------- the process's state

class ChainState:
    """What one process keeps: its head record, its verified view, the seals it committed and could not
    record, and the lock that keeps its own writers apart."""

    def __init__(self, head_path: Optional[str] = None, settings=None, clock: Callable[[], datetime] = utcnow):
        self.settings = settings
        self.head_path = head_path
        self.store: Optional[HeadStore] = None
        self.view = View()
        self.own: Dict[int, bytes] = {}
        self.mutex = threading.Lock()
        self.clock = clock
        self.stopped: Optional[ChainStopped] = None
        self.started = False
        # When this process started: the head record says which start first accepted each seal another
        # writer appended (accept-restore acknowledges those of the first start after a restore).
        self.process_started_at = clock()
        # "server" for the web process, "host" for a host command's process (where it accepted a seal).
        self.process_kind = "server"
        # Seals another writer appended after the head record, accepted into the view and not yet listed in
        # the record: a writer whose own work failed (or whose record write did not happen) leaves them here,
        # and the next record write lists them.
        self.pending_after: List[dict] = []
        # The first start's backlog is not sealed yet: the pruner's passes then follow each other closely.
        self.backlog = False
        # Archived days the audit job found nothing to delete in, by (day, archive seq, reason): (the UTC date of
        # that look, the time before which it looked). It looks again the next day, or once that time moves on.
        self.archive_checked: Dict[tuple, Any] = {}

    def cfg(self):
        return self.settings or _settings()

    def head_store(self) -> HeadStore:
        if self.store is None:
            self.store = HeadStore(self.head_path or self.cfg().audit_chain_head_file)
        return self.store

    def keys_held(self) -> Dict[str, keys.ChainKey]:
        return keys.held(self.cfg())

    def current_key(self) -> keys.ChainKey:
        return keys.current(self.cfg())

    def restore_mark(self) -> Optional[dict]:
        """The restore mark beside the head record (a restore of a whole backup not finished), or None."""
        from app.core import audit_head_record
        try:
            return audit_head_record.read_mark(self.head_store().path)
        except Exception:  # noqa: BLE001 -- a path that cannot be looked at holds no mark
            return None

    def holds_deletion(self) -> Optional[str]:
        """Why the pruner may delete, erase or rewrite nothing now, or None: a restore of a whole backup not
        finished (its mark), or the grace after a restore still running."""
        if self.restore_mark() is not None:
            return "a restore is not finished: run dockvault.py audit accept-restore"
        if self.view.position:
            from app.core import audit_chain_honour as honour
            until = honour.grace_until(self.view, self.known_record(), self.clock())
            if until is not None:
                return f"the grace after a restore runs until {fmt.time_text(until)}"
        return None

    def known_record(self) -> Optional[dict]:
        """The head record as this process knows it: its copy, with the seals it accepted after it and has not
        written into it yet."""
        import copy
        record = copy.deepcopy(self.head_store().memory)
        if self.pending_after:
            record = with_pending(record or {}, self.pending_after)
        return record


def with_pending(record: dict, pending: List[dict]) -> dict:
    after = record.setdefault("after_record", [])
    for entry in pending:
        if not any(e.get("generation") == entry["generation"] and e.get("seq") == entry["seq"] for e in after):
            after.append(dict(entry))
    return record


_state: Optional[ChainState] = None
_state_lock = threading.Lock()


def state() -> ChainState:
    global _state
    with _state_lock:
        if _state is None:
            _state = ChainState()
        return _state


def set_state(new: Optional[ChainState]) -> None:
    """For tests: use ``new`` as this process's chain state."""
    global _state
    with _state_lock:
        _state = new


# --------------------------------------------------------------------------- recording what was found

def _merge_findings(record: dict, kinds: Dict[str, str], now: datetime, table: str) -> dict:
    stamp = fmt.time_text(now)
    entries = record.setdefault(table, {})
    for kind, message in kinds.items():
        have = entries.get(kind)
        if have is None or (have.get("acknowledged_at") and have["acknowledged_at"] >= have.get("last_seen", "")):
            entries[kind] = {"first_seen": stamp, "last_seen": stamp, "message": message,
                             "acknowledged_at": have.get("acknowledged_at") if have else None}
        else:
            have["last_seen"] = stamp
            have["message"] = message
    return record


def open_failures(record: Optional[dict]) -> Dict[str, dict]:
    """The failures the host has not acknowledged since they were last seen."""
    out = {}
    for kind, e in ((record or {}).get("failures") or {}).items():
        if not e.get("acknowledged_at") or e["acknowledged_at"] < e.get("last_seen", ""):
            out[kind] = e
    return out


def open_warnings(record: Optional[dict]) -> Dict[str, dict]:
    out = {}
    for kind, e in ((record or {}).get("warnings") or {}).items():
        if e.get("resolved_at") and e["resolved_at"] >= e.get("last_seen", ""):
            continue
        if not e.get("acknowledged_at") or e["acknowledged_at"] < e.get("last_seen", ""):
            out[kind] = e
    return out


def report_failures(st: ChainState, db_factory: Optional[Callable], failures: Dict[str, str],
                    warnings: Optional[Dict[str, str]] = None, *, outcome: Optional[str] = None) -> None:
    """Keep ``failures`` and ``warnings`` in the head record, and announce each failure not already open with
    an ``audit_integrity_failed`` row. Never raises."""
    now = st.clock()
    try:
        before = open_failures(st.head_store().memory)
        new = {k: v for k, v in failures.items() if k not in before}

        def change(record):
            _merge_findings(record, failures, now, "failures")
            _merge_findings(record, warnings or {}, now, "warnings")
            if outcome is not None or failures:
                record["status"] = {"outcome": "failed" if failures else (outcome or "clean"),
                                    "at": fmt.time_text(now), "kinds": sorted(failures)}
            return record

        st.head_store().write(change, now)
    except Exception as exc:  # noqa: BLE001
        _say(f"Warning: the audit chain's findings were not recorded ({type(exc).__name__})")
        new = failures
    if new and db_factory is not None:
        try:
            from app.services.audit_logger import AuditLogger
            db = db_factory()
            try:
                db.add(AuditLogger(db).build_row(
                    action=FAILED_ACTION, status="failure", resource_type="audit_log",
                    details={"kinds": sorted(new), "messages": [new[k] for k in sorted(new)]}))
                db.commit()
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001
            _say(f"Warning: the audit chain's failure was not announced ({type(exc).__name__})")


# --------------------------------------------------------------------------- the writer

def _is_pg(bind) -> bool:
    return bind is not None and bind.dialect.name == "postgresql"


class ChainWriter:
    """One transaction that may write seals, holding the chain lock from the head record check through the
    record's write. ``wait`` is how long to wait for the lock (ChainBusy after it)."""

    def __init__(self, engine, st: Optional[ChainState] = None, *, wait: float = 30.0, writer: str = "pruner",
                 check_key: bool = True, check_chain: bool = True, snapshot: bool = False):
        self.engine = engine
        self.st = st or state()
        self.wait = wait
        self.writer = writer
        # The host's commands read everything their write phase compares with what the read phase showed in one
        # snapshot (repeatable read), which Postgres takes only as the transaction's first statement: before the
        # head record check reads the chain.
        self.snapshot = snapshot
        # The host's commands that resolve a stop run less of the check: rekey all of it but the key's step,
        # after-record and the restore commands none of it (they build and judge their own view).
        self.check_key = check_key
        self.check_chain = check_chain
        self.conn = None
        self.db = None
        self.record: Optional[dict] = None
        self.written: List[tuple] = []          # (Seal, link)
        self.accepted: List[tuple] = []         # (Seal, link) of the seals another writer appended, accepted here
        self._mutex_held = False
        self._lock_held = False

    # -- the lock

    def _take_mutex(self) -> None:
        if not self.st.mutex.acquire(timeout=self.wait):
            raise ChainBusy("busy, retry")
        self._mutex_held = True

    def _take_advisory(self) -> None:
        if not _is_pg(self.engine):
            return
        deadline = time.monotonic() + self.wait
        while True:
            got = self.conn.execute(text("SELECT pg_try_advisory_lock(:c, :k)"),
                                    {"c": CHAIN_LOCK[0], "k": CHAIN_LOCK[1]}).scalar()
            self.conn.commit()
            if got:
                self._lock_held = True
                return
            if time.monotonic() >= deadline:
                raise ChainBusy("busy, retry")
            time.sleep(0.1)

    def still_locked(self) -> bool:
        if not _is_pg(self.engine):
            return True
        try:
            n = self.conn.execute(text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() "
                "AND classid = :c AND objid = :k AND granted"), {"c": CHAIN_LOCK[0], "k": CHAIN_LOCK[1]}).scalar()
            self.conn.commit()
            return bool(n)
        except Exception:  # noqa: BLE001
            return False

    def __enter__(self) -> "ChainWriter":
        from sqlalchemy.orm import Session
        self._take_mutex()
        try:
            self.conn = self.engine.connect()
            self._take_advisory()
            self.db = Session(bind=self.conn, expire_on_commit=False)
            self._begin(self.db)
            if self.check_chain:
                self.check()
            else:
                try:
                    self.record = self.st.head_store().load()
                except ValueError:
                    self.record = None
        except BaseException:
            self._list_accepted()
            self._release()
            raise
        return self

    def _begin(self, db) -> None:
        """The transaction's settings, before any statement reads: the statement timeout, and the snapshot."""
        if _is_pg(self.engine):
            db.execute(text(f"SET LOCAL statement_timeout = {SEAL_STATEMENT_TIMEOUT_MS}"))
            if self.snapshot:
                db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))

    # Set by a caller whose transaction must commit even when it wrote no seal (a change that alters no entry).
    commit_without_seal = False

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None and self.written:
                self._finish()
            elif exc_type is None and self.commit_without_seal and self.db is not None:
                self._commit()
                self._list_accepted()
            else:
                self._abandon()
        finally:
            self._release()

    def _commit(self) -> None:
        try:
            self.db.commit()
        except BaseException:
            self._abandon()
            raise

    def _abandon(self) -> None:
        """Roll this writer's own work back. Its seals never reached the table, so nothing of them goes into
        the head record; the seals it accepted from another writer are listed all the same."""
        try:
            if self.db is not None:
                self.db.rollback()
        except Exception as exc:  # noqa: BLE001 -- the transaction is gone with the connection
            _say(f"Warning: the audit chain's transaction was not rolled back cleanly ({type(exc).__name__})")
        finally:
            self.written = []
            self._list_accepted()

    def _list_accepted(self) -> None:
        """Write the seals accepted after the head record into it, whatever became of this writer's own work:
        a seal in the view that the record does not list would be trusted as this process's own once the next
        record write moves the head past it. Never raises."""
        if not self.st.pending_after:
            return
        try:
            self._write_record()
        except Exception as exc:  # noqa: BLE001 -- they stay pending for the next record write
            _say(f"Warning: the seals accepted after the head record were not recorded ({type(exc).__name__})")

    def _release(self) -> None:
        try:
            if self.db is not None:
                self.db.close()
            if self.conn is not None:
                if self._lock_held:
                    try:
                        self.conn.execute(text("SELECT pg_advisory_unlock(:c, :k)"),
                                          {"c": CHAIN_LOCK[0], "k": CHAIN_LOCK[1]})
                        self.conn.commit()
                    except Exception:  # noqa: BLE001
                        pass
                if _is_pg(self.engine):
                    self.conn.invalidate()   # a session lock must never go back to the pool
                self.conn.close()
        finally:
            self.db = self.conn = None
            if self._mutex_held:
                self._mutex_held = False
                self.st.mutex.release()

    # -- the check before extending

    def check(self) -> None:
        """Before extending: bring the view up to date and check the database's chain against the head
        record and the keys. Raises ChainStopped."""
        st = self.st
        store = st.head_store()
        try:
            record = store.load()
        except ValueError:
            raise ChainStopped("head-record-missing", "the head record cannot be read: " + store.path)
        if record is not None and not record.get("link"):
            # Only findings were kept (before the first seal, or after the record was lost): no head to check
            # against, and no list of another writer's seals.
            record = None
        if record is not None and st.pending_after:
            record = with_pending(record, st.pending_after)
        self.record = record
        db = self.db
        view = st.view
        if record is not None and (int(record.get("generation", 1)), int(record.get("discards", 0))) > \
                (view.generation, view.discards):
            view.reset(int(record.get("generation", 1)), int(record.get("discards", 0)))
            st.own.clear()
        newest = newest_seq(db)
        if record is None:
            if newest == 0:
                return            # only now may genesis run
            raise ChainStopped("head-record-missing",
                               f"the audit chain has {newest} seals but no head record at {store.path}; "
                               "the keys volume was lost or replaced. Put the head record back from a backup of "
                               "the keys volume: sealing stays stopped until then")
        rec_seq = int(record.get("seq") or 0)
        rec_link = bytes.fromhex(record["link"]) if record.get("link") else None
        if newest < rec_seq:
            raise ChainStopped("head-record-mismatch",
                               f"the database's chain ends at seal {newest}, before the recorded head {rec_seq}")
        # The seal at the view's position, read again: its link must still be the one the view holds.
        if view.position:
            seal = read_seal(db, view.position)
            if seal is None or fmt.link(view.link_at(view.position - 1), seal.body()) != view.link_at(view.position):
                raise ChainStopped("head-record-mismatch",
                                   f"seal {view.position} changed or went after this process accepted it")
        held = st.keys_held()
        early: Optional[ChainStopped] = None
        for seal in read_seals(db, view.position):
            if seal.seq != view.position + 1:
                raise ChainStopped("seq-gap", f"the seals jump from {view.position} to {seal.seq}")
            link = fmt.link(view.link_at(seal.seq - 1), seal.body())
            if seal.seq <= rec_seq:
                # Up to the record, the seals are authenticated by the recorded link alone: a seal edited
                # anywhere before it changes that link. A break of the key sequence there is reported once
                # the link checks out.
                problem = key_sequence_problem(view, seal)
                if problem and early is None:
                    early = ChainStopped("key-sequence", problem, seal.seq)
                if seal.seq == rec_seq:
                    if link != rec_link:
                        raise ChainStopped("head-record-mismatch",
                                           f"seal {rec_seq} is not the one the head record holds")
                    if early is not None:
                        raise early
                view.accept(seal, link)
                continue
            self._accept_after_record(seal, link, held)
            if seal.kind in ROOT_KINDS:
                seal.salt = _salt_of(db, seal)
            self.accepted.append((seal, link))
            view.accept(seal, link)
        view.record_seq = rec_seq
        if self.check_key:
            self._check_current_key(held)

    def _accept_after_record(self, seal: Seal, link: bytes, held) -> None:
        st, view, record = self.st, self.st.view, self.record or {}
        if st.own.get(seal.seq) == link:
            return
        if is_host_kind(seal):
            if not _record_lists(record, view.generation, seal.seq, link):
                raise ChainStopped("host-seal-unrecorded",
                                   f"seal {seal.seq} ({seal.kind}) is one only the host writes, and the head record "
                                   "does not list it: sealing stays stopped", seal.seq)
            return
        problem = key_sequence_problem(view, seal)
        if problem:
            raise ChainStopped("key-sequence", problem, seal.seq)
        k = held.get(seal.key_id)
        if k is None:
            raise ChainStopped("key-unverified", f"seal {seal.seq} is under a key this process does not hold",
                               seal.seq)
        if not _mac_ok(k.key, link, seal.mac):
            raise ChainStopped("mac-invalid", f"seal {seal.seq}'s MAC does not verify", seal.seq)
        if seal.kind == "key":
            old = held.get((seal.detail or {}).get("old_key_id"))
            proof = (seal.detail or {}).get("old_key_proof")
            if old is None or not proof or not _proof_ok(old.key, view.link_at(seal.seq - 1), seal.key_id, proof):
                raise ChainStopped("key-unverified", f"key seal {seal.seq} has no proof this process can check",
                                   seal.seq)
        listed = _record_lists(record, view.generation, seal.seq, link)
        if not listed:
            problem = face_problem(view, seal, st.clock(), first_acceptance=True, record=self.record)
            if problem:
                raise ChainStopped("after-record-invalid", f"seal {seal.seq}: {problem}", seal.seq)
            # The delay honoured when the server first accepted it: a request among them waits that long from
            # then (plus the gaps after), whatever its own dates say.
            from app.core import audit_chain_honour as honour
            try:
                delay = honour.honoured_delay(view, self.record, st.clock()).days
            except Exception:  # noqa: BLE001 -- before the first policy seal: the chain's own delay
                delay = None
            entry = {"generation": view.generation, "seq": seal.seq, "kind": seal.kind, "link": link.hex(),
                     "accepted_at": fmt.time_text(st.clock()),
                     "where": "host" if st.process_kind == "host" else ("start" if not st.started else "running"),
                     "process_started_at": fmt.time_text(st.process_started_at), "delay_days": delay,
                     "acknowledged": False, "discarded": False}
            st.pending_after.append(entry)
            if self.record is not None:
                with_pending(self.record, [entry])

    def _check_current_key(self, held) -> None:
        view = self.st.view
        if not view.position:
            return
        current = self.st.current_key()
        in_force = view.key_in_force()
        if in_force == current.key_id:
            newest = read_seal(self.db, view.position)
            if newest is None or not _mac_ok(current.key, view.link_at(view.position), newest.mac):
                raise ChainStopped("key-unverified",
                                   f"the newest seal ({view.position}) does not verify under the key in force")
            return
        record = self.record or {}
        if _ever_in_force(record, current.key_id) or view.ever_in_force(current.key_id):
            raise ChainStopped("key-not-current",
                               f"the current key {current.key_id} is one the chain has left; set AUDIT_CHAIN_KEY "
                               f"back to the key in force ({in_force}): sealing stays stopped until then")
        if in_force in held:
            self.key_move = (held[in_force], current)
            return
        raise ChainStopped("key-change-waiting",
                           f"the chain is under key {in_force}, which this process does not hold, and the current "
                           f"key {current.key_id} has never been in force: set AUDIT_CHAIN_KEY back to the key in "
                           "force (this release moves the chain to a new key only from the one derived from "
                           "ENCRYPTION_KEY)")

    key_move = None
    # A change the caller makes to the head record with this writer's own (an acknowledgment marks entries).
    after_record_change = None

    # -- writing

    def append(self, kind: str, *, period_start=None, period_end=None, row_count=0, row_bytes=0, root_s=None,
               root_c=None, ids_dig=None, detail=None, row_ids=None, legacy_salt=None,
               key: Optional[keys.ChainKey] = None) -> Seal:
        from app.core.models import AuditSeal
        view = self.st.view
        key = key or self.st.current_key()
        prev_seq = view.position + len(self.written)
        prev_link = self.written[-1][1] if self.written else view.link_at(view.position)
        if _is_pg(self.engine):
            self.db.execute(text(f"SET LOCAL statement_timeout = {SEAL_STATEMENT_TIMEOUT_MS}"))
        sealed_at = self.st.clock()
        if self.written and sealed_at < self.written[-1][0].sealed_at:
            sealed_at = self.written[-1][0].sealed_at
        if callable(detail):
            detail = detail(prev_seq + 1, sealed_at)
        seal = Seal(prev_seq + 1, kind, period_start, period_end, fmt.FORMAT, int(row_count), int(row_bytes),
                    root_s, root_c, ids_dig, detail if detail is not None else {}, key.key_id, sealed_at)
        link = fmt.link(prev_link, seal.body())
        seal.mac = fmt.mac(key.key, link)
        seal.link = link
        self.db.add(AuditSeal(seq=seal.seq, kind=kind, period_start=period_start, period_end=period_end,
                              format=fmt.FORMAT, row_count=seal.row_count, row_bytes=seal.row_bytes, root_s=root_s,
                              root_c=root_c, ids_digest=ids_dig, detail=seal.detail, key_id=key.key_id,
                              sealed_at=sealed_at, mac=seal.mac, link=link, row_ids=row_ids,
                              legacy_salt=legacy_salt))
        self.db.flush()
        seal.salt = legacy_salt
        self.written.append((seal, link))
        return seal

    def _finish(self) -> None:
        st = self.st
        self._commit()
        for seal, link in self.written:
            st.own[seal.seq] = link
            st.view.accept(seal, link)
        if self.still_locked():
            self._write_record()
            for seal, _link in self.written:
                st.own.pop(seal.seq, None)
        else:
            _say("Warning: the audit chain's lock was lost after a commit; the head record was not written")

    def _write_record(self) -> None:
        st, view, written, accepted = self.st, self.st.view, list(self.written), list(self.st.pending_after)
        now = st.clock()

        def change(record):
            if view.position:
                record["seq"] = view.position
                record["link"] = view.link_at(view.position).hex()
                record["key_id"] = view.key_at(view.position)
                record["sealed_at"] = fmt.time_text(view.newest_at())
            record["generation"] = max(int(record.get("generation") or 1), view.generation)
            if view.newest_hour_end is not None:
                record["newest_hour_end"] = fmt.time_text(view.newest_hour_end)
            keys_list = record.setdefault("keys", [])
            for kid, start, end in view.key_history:
                found = [k for k in keys_list if k.get("generation") == view.generation and k.get("key_id") == kid
                         and k.get("from_seq") == start]
                if found:
                    if end is not None:
                        found[0]["to_seq"] = end
                else:
                    keys_list.append({"generation": view.generation, "key_id": kid, "from_seq": start,
                                      "to_seq": end, "link": view.link_at(start).hex()})
            links = record.setdefault("links", {})
            for k in range(LINK_EVERY, view.position + 1, LINK_EVERY):
                links.setdefault(f"{view.generation}:{k}", view.link_at(k).hex())
            for seal, _link in list(self.accepted) + written:
                if seal.seq <= view.position:
                    _summarise(record, view, seal)
            after = record.setdefault("after_record", [])
            for entry in accepted:
                if not any(e.get("generation") == entry["generation"] and e.get("seq") == entry["seq"]
                           for e in after):
                    after.append(entry)
            if self.after_record_change is not None:
                record = self.after_record_change(record)
            # The retention checkpoints (with the honoured state as the record now lists another writer's seals)
            # and the digests of the days older than the hour summaries.
            from app.core import audit_head_record as hr
            record["checkpoints"] = hr.merge_checkpoints(record.get("checkpoints") or {},
                                                          checkpoints(view, record, now))
            if self.db is not None:
                try:
                    day_digests(self.db, view, record, now, [s for s, _l in list(self.accepted) + written])
                except Exception as exc:  # noqa: BLE001 -- the next record write computes them
                    _say(f"Warning: the audit chain's day digests were not computed ({type(exc).__name__})")
            # The warnings that come from the seals, as this writer's view gives them: shown from here after a
            # restart, until the process has read the chain again.
            record["view_warnings"] = view_warning_seqs(view, record)
            return record

        st.head_store().write(change, now)
        st.pending_after = [e for e in st.pending_after if e not in accepted]


def _salt_of(db, seal: Seal) -> Optional[bytes]:
    """The salt the hour a root seal covers has (its working row's), or None."""
    try:
        if seal.kind in ("hour", "late") and seal.period_start is not None:
            hour = seal.period_start
            if seal.kind == "late" and isinstance(seal.detail, dict) and seal.detail.get("hour"):
                hour = fmt.parse_time_text(seal.detail["hour"])
            wr = working_row(db, hour)
            return bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
    except Exception:  # noqa: BLE001 -- a summary without its salt compares without personal values
        return None
    return None


def checkpoints(view: View, record: Optional[dict], now: datetime) -> dict:
    """The retention checkpoints of the view's generation: the newest policy seal (its seq, link, state,
    inputs and cause) with every entry where the honoured state differs from it in its honoured form; each
    cancel with the seq and link of the request it cancels; and each erase or removal a final seal completed
    (ids only). They let the host's restore commands say what a restore lost."""
    out: dict = {"generation": view.generation}
    newest = view.newest_policy()
    if newest is not None:
        from app.core import audit_chain_honour as honour
        seq, d = newest
        state = d.get("state") or {}
        try:
            honoured = honour.honoured_state(view, record, now)
        except Exception:  # noqa: BLE001 -- the chain's form alone, never a guess
            honoured = state
        out["policy"] = {"generation": view.generation, "seq": seq, "link": view.link_at(seq).hex(),
                         "state": state, "inputs": d.get("inputs") or {}, "cause": d.get("cause"),
                         "honoured": {n: e for n, e in honoured.items() if e != state.get(n)}}
    out["cancels"] = [{"generation": view.generation, "seq": c, "request_seq": r,
                       "request_link": view.link_at(r).hex()} for r, c in sorted(view.cancels.items())
                      if 1 <= r <= view.position]
    out["erases"] = [{"generation": view.generation, "request_id": (view.requests.get(r) or {}).get("request"),
                      "request_seq": r, "final_seq": f} for r, f in sorted(view.finals.items())
                     if (view.requests.get(r) or {}).get("what") in ("erase", "removal")]
    return out


def day_entries(db, view: View, day) -> List[tuple]:
    """(start, end, count, root_s, root_c, ids_digest, salted) of every hour of ``day`` the chain covers, one
    entry an hour (a run of empty hours expanded), from the view's root seals read again."""
    start = datetime(day.year, day.month, day.day)
    first = view.first_hour()
    out = []
    cache: Dict[int, Seal] = {}
    for i in range(24):
        h = start + i * HOUR
        if first is not None and h < first:
            continue
        if view.newest_hour_end is None or h >= view.newest_hour_end:
            break
        entry = view.entry_for(h)
        if entry is None:
            continue
        seq = entry.root.seq
        seal = cache.get(seq) or read_authenticated(db, view, seq)
        cache[seq] = seal
        figures = seal_figures(seal, h)
        if figures is None:
            continue
        count, _nb, rs, rc, idd = figures
        out.append((h, h + HOUR, count, rs, rc, idd))
    return out


def day_digest_of(db, view: View, day) -> dict:
    """The digests of ``day`` the head record keeps once its hour summaries are dropped: over every hour's
    count, roots and ids digest, and over the same without the personal values' root (``stable``), with
    whether any hour of it has a salt (rows written without a nonce: their personal values cannot be
    compared once the salt is lost)."""
    from app.core.models import AuditSeal as S
    entries = day_entries(db, view, day)
    start = datetime(day.year, day.month, day.day)
    salted = db.query(func.count()).select_from(S).filter(
        S.kind.in_(("hour", "late")), S.period_start >= start, S.period_start < start + timedelta(days=1),
        S.legacy_salt.isnot(None)).scalar() or 0
    return {"full": fmt.day_digest(entries).hex(),
            "stable": fmt.day_digest([(a, b, c, rs, None, idd) for a, b, c, rs, _rc, idd in entries]).hex(),
            "hours": len(entries), "salted": bool(salted), "generation": view.generation}


DAY_DIGESTS_PER_WRITE = 31


def day_digests(db, view: View, record: dict, now: datetime, seals: List[Seal]) -> None:
    """Keep a digest per day older than the hour summaries: computed when a day ages past them (a few days per
    record write, so a long backlog spreads the work), and again when a later seal re-roots one of its
    hours."""
    from app.core.audit_head_record import SUMMARY_DAYS
    if view.newest_hour_end is None or view.first_hour() is None:
        return
    cutoff = (now - timedelta(days=SUMMARY_DAYS)).date()
    sealed_through = (view.newest_hour_end - HOUR).date()
    last_full = min(cutoff - timedelta(days=1), sealed_through - timedelta(days=1))
    days = record.setdefault("days", {})
    through = record.get("days_through")
    day = (fmt.parse_time_text(through).date() + timedelta(days=1)) if through else view.first_hour().date()
    done = 0
    while day <= last_full and done < DAY_DIGESTS_PER_WRITE:
        days[day.isoformat()] = day_digest_of(db, view, day)
        record["days_through"] = fmt.time_text(datetime(day.year, day.month, day.day))
        day += timedelta(days=1)
        done += 1
    through = record.get("days_through")
    if not through:
        return
    through_day = fmt.parse_time_text(through).date()
    touched = set()
    for seal in seals:
        if seal.kind not in ("late", "prune", "rewrite"):
            continue
        if seal.kind == "late":
            hours = [fmt.parse_time_text(seal.detail["hour"])] if isinstance(seal.detail, dict) else []
        else:
            hours = [fmt.parse_time_text(h[0]) for h in (seal.detail or {}).get("hours") or []]
        for h in hours:
            if h.date() <= through_day:
                touched.add(h.date())
    for d in sorted(touched):
        days[d.isoformat()] = day_digest_of(db, view, d)


def _summarise(record: dict, view: View, seal: Seal) -> None:
    """Hour summaries for a seal that sets roots. A summary keeps its hour's salt (rows without a nonce of their
    own) only while the hour is unchanged, as the database does: a prune or rewrite replaces it with none, and
    an erase, which sets no roots, drops it; kept beside the erase's earlier commitments, it would let erased
    low-entropy values be tested."""
    hours = record.setdefault("hours", {})
    if seal.kind == "erase":
        entry = hours.get(str((seal.detail or {}).get("hour")))
        if entry is not None:
            entry["salt"] = None
        return
    entries = []
    if seal.kind in ("hour", "late"):
        start = seal.period_start
        if seal.kind == "late":
            start = fmt.parse_time_text(seal.detail["hour"])
        entries.append((start, seal.period_end if seal.kind == "hour" else start + HOUR, seal.row_count,
                        seal.root_s, seal.root_c, seal.ids_digest))
    elif seal.kind in ("prune", "rewrite"):
        for h in (seal.detail or {}).get("hours") or []:
            start = fmt.parse_time_text(h[0])
            entries.append((start, start + HOUR, int(h[2]), bytes.fromhex(h[4]), bytes.fromhex(h[5]),
                            bytes.fromhex(h[6])))
    for start, end, count, rs, rc, idd in entries:
        salt = seal.salt if seal.kind in ("hour", "late") else None
        hours[fmt.hour_text(start)] = {"end": fmt.hour_text(end), "seq": seal.seq,
                                       "link": view.link_at(seal.seq).hex(), "sealed_at": fmt.time_text(seal.sealed_at),
                                       "count": count, "root_s": _b(rs).hex() if rs else None,
                                       "root_c": _b(rc).hex() if rc else None,
                                       "ids_digest": _b(idd).hex() if idd else None,
                                       "salt": salt.hex() if salt else None, "unsealed": False,
                                       "generation": view.generation}


def _mac_ok(key: bytes, link: bytes, mac: bytes) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(fmt.mac(key, link), bytes(mac or b""))


def _proof_ok(old_key: bytes, prev_link: bytes, new_key_id: str, proof_hex: str) -> bool:
    import hmac as _hmac
    try:
        given = bytes.fromhex(proof_hex)
    except (TypeError, ValueError):
        return False
    return _hmac.compare_digest(fmt.old_key_proof(old_key, prev_link, new_key_id), given)


def _record_lists(record: dict, generation: int, seq: int, link: bytes) -> bool:
    for e in record.get("after_record") or []:
        if e.get("generation") == generation and e.get("seq") == seq and e.get("link") == link.hex():
            return True
    for e in record.get("unverified_keys") or []:
        if e.get("generation") == generation and e.get("seq") == seq:
            return True
    return False


def _ever_in_force(record: dict, key_id: str) -> bool:
    return any(k.get("key_id") == key_id for k in (record or {}).get("keys") or [])


def is_host_kind(seal: Seal) -> bool:
    d = seal.detail if isinstance(seal.detail, dict) else {}
    if seal.kind == "restore":
        return True
    if seal.kind == "genesis" and d.get("replaces"):
        return True
    if seal.kind == "archive" and d.get("cause") == "unarchive":
        return True
    if seal.kind == "key" and d.get("accepted_unverified"):
        return True
    return d.get("by") == "host"


def key_sequence_problem(view: View, seal: Seal) -> Optional[str]:
    """Why ``seal`` breaks the key sequence at its position, or None."""
    if seal.seq == 1:
        if seal.kind != "genesis":
            return "seal 1 is not genesis"
        return None
    in_force = view.key_in_force()
    if seal.kind == "key":
        d = seal.detail if isinstance(seal.detail, dict) else {}
        if d.get("old_key_id") != in_force or d.get("new_key_id") != seal.key_id or seal.key_id == in_force:
            return f"key seal {seal.seq} does not move on from the key in force ({in_force})"
        return None
    if seal.key_id != in_force:
        return f"seal {seal.seq} is under {seal.key_id}, not the key in force ({in_force})"
    return None


def face_problem(view: View, seal: Seal, now: datetime, *, first_acceptance: bool = False,
                 record: Optional[dict] = None) -> Optional[str]:
    """Why a seal another writer appended is refused on its face, judged by the chain up to it, or None."""
    if seal.kind not in KINDS:
        return f"unknown kind {seal.kind!r}"
    if seal.kind == "genesis":
        return "a genesis that is not seal 1"
    if seal.format != fmt.FORMAT:
        return f"format {seal.format}"
    prev_at = view.newest_at()
    tol = timedelta(seconds=fmt.BACKWARDS_TOLERANCE_SECONDS)
    if prev_at is not None and seal.sealed_at < prev_at - tol:
        return "its sealed_at steps back more than five minutes"
    if first_acceptance and seal.sealed_at > now + tol:
        return "its sealed_at is ahead of the server's clock"
    if seal.kind == "hour":
        expected = view.newest_hour_end or view.first_hour()
        if seal.period_start != expected:
            return f"an hour seal starting at {seal.period_start}, not {expected}"
        if seal.period_end is None or seal.period_end <= seal.period_start:
            return "an hour seal with no period"
        if seal.period_end - seal.period_start > HOUR and seal.row_count:
            return "a run of hours with rows"
    if seal.kind in UNCHECKED_KINDS:
        return f"a {seal.kind} seal, which this release neither writes nor checks"
    # Every rule audit verify applies to the seal's kind (a late seal's root, a prune's policy seal, an
    # erase's request and delay, a cancel's pending request, a policy seal's justification).
    from app.core import audit_chain_verify
    return audit_chain_verify.justification_problem(view, seal, record)


# --------------------------------------------------------------------------- reading an hour's rows

ROW_FIELDS = fmt.STABLE_COLUMNS + fmt.COMMITTED_COLUMNS


def _row_columns(dialect: str):
    from app.core.models import AuditLog as A
    from app.core.audit_retention import _row_bytes
    cols = []
    for name in ROW_FIELDS:
        col = getattr(A, name)
        cols.append(cast(col, Text) if name in ("recorded", "details") else col)
    cols.append(A.seal_nonce)
    cols.append(_row_bytes(A, dialect))
    return cols


def iter_rows(db, start: Optional[datetime], end: Optional[datetime]) -> Iterator[dict]:
    """The rows of [start, end) (or with no timestamp, when both are None), with the chained columns and each
    row's stored size, in (timestamp, id) order, streamed."""
    from app.core.models import AuditLog as A
    dialect = db.get_bind().dialect.name
    q = db.query(*_row_columns(dialect))
    if start is None and end is None:
        q = q.filter(A.timestamp.is_(None))
    else:
        q = q.filter(A.timestamp >= start, A.timestamp < end)
    for r in q.order_by(A.timestamp, A.id).yield_per(2000):
        row = dict(zip(ROW_FIELDS, r[:len(ROW_FIELDS)]))
        if row["id"] is not None and not hasattr(row["id"], "bytes"):
            row["id"] = fmt.as_uuid(row["id"])
        row["seal_nonce"] = _b(r[len(ROW_FIELDS)])
        row["_bytes"] = int(r[len(ROW_FIELDS) + 1] or 0)
        yield row


@dataclass
class HourFigures:
    count: int = 0
    bytes: int = 0
    root_s: bytes = fmt.EMPTY_ROOT
    root_c: bytes = fmt.EMPTY_ROOT
    ids_digest: bytes = fmt.ids_digest([])
    ids: bytes = b""
    nonceless: int = 0
    missing_nonce: List = field(default_factory=list)
    unwritable: List = field(default_factory=list)


def row_nonce(row: dict, salt: Optional[bytes]) -> Optional[bytes]:
    if row.get("seal_nonce") is not None:
        return row["seal_nonce"]
    if salt is not None:
        return fmt.legacy_nonce(salt, row["id"])
    return None


def hour_figures(rows, salt: Optional[bytes] = None, c_prev: Optional[Dict] = None,
                 exclude: Optional[set] = None) -> HourFigures:
    """The figures of an hour over ``rows``: count, bytes, both roots and the ids. A row with no nonce takes
    one from ``salt``; with neither it is listed in ``missing_nonce`` (and committed under a NULL nonce). A
    row ``c_prev`` names uses that commitment (an erase newer than the hour's root seal)."""
    out = HourFigures()
    ts, tc = fmt.TreeBuilder(), fmt.TreeBuilder()
    ids = bytearray()
    for row in rows:
        if exclude and row["id"] in exclude:
            continue
        out.count += 1
        out.bytes += row.get("_bytes", 0)
        rid = row["id"]
        if c_prev and rid in c_prev:
            c = c_prev[rid]
        else:
            nonce = row_nonce(row, salt)
            if row.get("seal_nonce") is None:
                out.nonceless += 1
                if nonce is None:
                    out.missing_nonce.append(rid)
            c = fmt.commitment(nonce, row)
        for col in ("recorded", "details"):
            if not fmt.json_text_writable(row.get(col)):
                out.unwritable.append(rid)
                break
        ts.push(fmt.leaf_s(row))
        tc.push(fmt.leaf_c(rid, c))
        ids += rid.bytes
    out.root_s, out.root_c = ts.root(), tc.root()
    out.ids = bytes(ids)
    out.ids_digest = fmt.ids_digest_of_blob(out.ids)
    return out


def read_authenticated(db, view: View, seq: int) -> Seal:
    """Seal ``seq`` read again, used only when its link, recomputed from the body just read and the view's link
    for the seal before it, is the view's link for it. Raises ChainStopped (link-broken) otherwise: a seal
    changed after the view accepted it is never acted on."""
    seal = read_seal(db, seq)
    if seal is None or fmt.link(view.link_at(seq - 1), seal.body()) != view.link_at(seq):
        raise ChainStopped("link-broken", f"seal {seq} changed or went after this process accepted it", seq)
    return seal


def seal_figures(seal: Seal, hour: Optional[datetime]) -> Optional[tuple]:
    """(count, bytes, root_s, root_c, ids_digest) a seal records for ``hour`` (None: the undated rows of
    genesis), or None when it records none for it."""
    kind = seal.kind
    if hour is None:
        if kind != "genesis":
            return None
        return (seal.row_count, seal.row_bytes, _b(seal.root_s), _b(seal.root_c), _b(seal.ids_digest))
    if kind == "hour":
        if seal.period_start is None or seal.period_end is None or not (seal.period_start <= hour < seal.period_end):
            return None
        if seal.period_end - seal.period_start > HOUR:
            return (0, 0, fmt.EMPTY_ROOT, fmt.EMPTY_ROOT, fmt.ids_digest([]))
        return (seal.row_count, seal.row_bytes, _b(seal.root_s), _b(seal.root_c), _b(seal.ids_digest))
    if kind == "late":
        d = seal.detail if isinstance(seal.detail, dict) else {}
        if d.get("hour") != fmt.hour_text(hour):
            return None
        return (seal.row_count, seal.row_bytes, _b(seal.root_s), _b(seal.root_c), _b(seal.ids_digest))
    if kind in ("prune", "rewrite"):
        d = seal.detail if isinstance(seal.detail, dict) else {}
        for h in d.get("hours") or []:
            if h and h[0] == fmt.hour_text(hour):
                return (int(h[2]), int(h[3]), bytes.fromhex(h[4]), bytes.fromhex(h[5]), bytes.fromhex(h[6]))
    return None


def hour_root(db, view: View, hour: datetime) -> Optional[RootEntry]:
    """The newest seal that set ``hour``'s roots, with the roots: from the view when it keeps them, and
    otherwise read again from the seal and used only when its link is the view's (read_authenticated). None
    for an hour the view does not hold. Raises ChainStopped (link-broken)."""
    entry = view.entry_for(hour)
    if entry is None:
        return None
    root = entry.root
    if root.root_s is not None:
        return root
    seal = read_authenticated(db, view, root.seq)
    figures = seal_figures(seal, hour)
    if figures is None:
        raise ChainStopped("link-broken", f"seal {root.seq} holds no figures for {fmt.hour_text(hour)}", root.seq)
    _count, _bytes, root.root_s, root.root_c, root.ids_digest = figures
    return root


def working_row(db, hour: datetime):
    """The seal row that keeps ``hour``'s working data (row_ids, legacy_salt): its first hour or late seal whose
    period is that one hour."""
    from app.core.models import AuditSeal as S
    return (db.query(S).filter(S.kind.in_(("hour", "late")), S.period_start == hour, S.period_end == hour + HOUR)
            .order_by(S.seq).first())


def erase_c_prev(db, view: View, entry: HourEntry) -> Dict:
    """For each row an erase changed after the hour's root seal: its commitment before (``c_prev``)."""
    out: Dict = {}
    for seq in entry.erases:
        seal = read_authenticated(db, view, seq)
        for rid, c_prev, _c_next in (seal.detail or {}).get("rows") or []:
            out.setdefault(fmt.as_uuid(rid), bytes.fromhex(c_prev))
    return out


# --------------------------------------------------------------------------- when an hour may be sealed

def oldest_open_transaction(db) -> Optional[datetime]:
    """The start of the oldest transaction another client has open, as UTC without zone, or None."""
    if not _is_pg(db.get_bind()):
        return None
    t = db.execute(text(
        "SELECT min(xact_start) FROM pg_stat_activity WHERE backend_type = 'client backend' "
        "AND pid <> pg_backend_pid() AND xact_start IS NOT NULL AND datname = current_database()")).scalar()
    if t is None:
        return None
    if t.tzinfo is not None:
        t = t.astimezone(timezone.utc).replace(tzinfo=None)
    return t


def may_seal(hour_end: datetime, now: datetime, open_since: Optional[datetime]) -> tuple:
    """(may it be sealed now, open_since to record when the wait was passed)."""
    if now < hour_end + lag():
        return False, None
    if open_since is not None and open_since < hour_end:
        if now - hour_end < OPEN_TRANSACTION_WAIT:
            return False, None
        return True, open_since
    return True, None


def newest_sealable_end(now: datetime, open_since: Optional[datetime]) -> datetime:
    """The end of the newest hour that may be sealed now: an hour ending at E waits for the lag, and for a
    transaction open since before E, for at most 6 hours (may_seal, for every hour up to it at once)."""
    end = hour_floor(now - lag())
    if open_since is not None:
        end = min(end, hour_floor(max(open_since, now - OPEN_TRANSACTION_WAIT)))
    return end


def next_row_time(db, after: datetime) -> Optional[datetime]:
    from app.core.models import AuditLog as A
    return db.query(func.min(A.timestamp)).filter(A.timestamp >= after).scalar()


# --------------------------------------------------------------------------- genesis

NAME_PURGE_MARKER = "audit_name_redaction_purged"


def _genesis_ready(db) -> Optional[str]:
    """Why genesis must wait, or None."""
    from app.core.models import SystemSetting
    if db.get(SystemSetting, NAME_PURGE_MARKER) is None:
        return "the one-time name purge of old audit rows has not run yet"
    return None


def write_genesis(w: ChainWriter, now: datetime, *, replaces: Optional[str] = None,
                  grace_days: Optional[int] = None) -> Seal:
    """Seal 1. The host's genesis on a database that lost every seal names the lost head (``replaces``) and
    carries a grace of ``grace_days`` from its own time, as a restore seal does."""
    from app.core.models import AuditLog as A
    db = w.db
    first = db.query(func.min(A.timestamp)).scalar()
    open_since = oldest_open_transaction(db)
    through = hour_floor(now - lag()) - HOUR
    while through >= (hour_floor(first) if first else through) and not may_seal(through + HOUR, now, open_since)[0]:
        through -= HOUR
    backlog_rows = int(db.query(func.count()).select_from(A).filter(A.timestamp < through + HOUR).scalar() or 0)
    salt = secrets.token_bytes(32)
    fig = hour_figures(iter_rows(db, None, None), salt)
    salt = salt if fig.nonceless else None
    detail = {"format": fmt.FORMAT, "release": _release(), "first_row_hour": fmt.hour_text(hour_floor(first)) if first else None,
              "backlog_through": fmt.hour_text(through), "backlog_rows": backlog_rows, "undated_rows": fig.count,
              "replaces": replaces, "grace_until": None}

    def at_its_time(seq, sealed_at):
        if grace_days is not None:
            return {**detail, "grace_until": fmt.time_text(sealed_at + timedelta(days=grace_days))}
        return detail
    return w.append("genesis", row_count=fig.count, row_bytes=fig.bytes, root_s=fig.root_s, root_c=fig.root_c,
                    ids_dig=fig.ids_digest, detail=at_its_time, row_ids=fig.ids, legacy_salt=salt)


# --------------------------------------------------------------------------- sealing

@dataclass
class PassResult:
    sealed: int = 0
    rows: int = 0
    late: int = 0
    stopped: Optional[str] = None
    backlog: bool = False


def _engine_of(session_factory):
    db = session_factory()
    try:
        return db.get_bind()
    finally:
        db.close()


def seal_hour(w: ChainWriter, start: datetime, now: datetime, open_since: Optional[datetime]) -> Optional[Seal]:
    """Seal the hour (or run of empty hours) that starts at ``start``, if it may be sealed now."""
    db = w.db
    ok, open_mark = may_seal(start + HOUR, now, open_since)
    if not ok:
        return None
    nxt = next_row_time(db, start)
    if nxt is None or hour_floor(nxt) > start:
        # A run of empty hours, up to the next row's hour or the newest hour that may be sealed now.
        end = hour_floor(nxt) if nxt is not None else None
        newest_end = newest_sealable_end(now, open_since)
        end = max(start + HOUR, min(end, newest_end) if end is not None else newest_end)
        if open_since is not None and open_since < end:
            open_mark = open_since
        detail = {"open_since": fmt.time_text(open_mark)} if open_mark else {}
        return w.append("hour", period_start=start, period_end=end, row_count=0, row_bytes=0,
                        root_s=fmt.EMPTY_ROOT, root_c=fmt.EMPTY_ROOT, ids_dig=fmt.ids_digest([]), detail=detail,
                        row_ids=b"" if end - start == HOUR else None)
    # Streamed: a salt is drawn first, and kept only when a row of the hour has no nonce of its own.
    salt = secrets.token_bytes(32)
    fig = hour_figures(iter_rows(db, start, start + HOUR), salt)
    salt = salt if fig.nonceless else None
    detail = {"open_since": fmt.time_text(open_mark)} if open_mark else {}
    return w.append("hour", period_start=start, period_end=start + HOUR, row_count=fig.count, row_bytes=fig.bytes,
                    root_s=fig.root_s, root_c=fig.root_c, ids_dig=fig.ids_digest, detail=detail, row_ids=fig.ids,
                    legacy_salt=salt)


def _late_candidates(view: View, now: datetime) -> List[HourEntry]:
    """Hours whose root seal was written within the last 6 hours, and the hours inside such a run."""
    return view.recent_units(now - LATE_WINDOW)


def check_late(w: ChainWriter, entry: HourEntry, hour: datetime, now: datetime) -> Optional[Seal]:
    """A late seal for rows that arrived in ``hour`` after its root seal, if the rows already sealed are
    unchanged. None when nothing arrived or something else changed (the verifier reports that)."""
    from app.core.models import AuditLog as A
    db, view = w.db, w.st.view
    own = view.own_entry(hour)
    count = int(db.query(func.count()).select_from(A).filter(A.timestamp >= hour, A.timestamp < hour + HOUR).scalar() or 0)
    if count <= view.entry_for(hour).root.count:
        return None
    root = hour_root(db, view, hour)
    wr = working_row(db, hour)
    # The rows the hour's root seal holds, by its working data: a row it lists is never taken for one added, and
    # a list changed in the database is caught by the rows it then gives, which must still give the root.
    sealed_ids = bytes(wr.row_ids or b"") if wr is not None else b""
    sealed = {sealed_ids[i:i + 16] for i in range(0, len(sealed_ids), 16)}
    added, nonceless = [], False
    for r in iter_rows(db, hour, hour + HOUR):       # streamed: only the added rows' ids are kept
        if r["id"].bytes not in sealed:
            added.append(r["id"])
            nonceless = nonceless or r["seal_nonce"] is None
    salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
    c_prev = erase_c_prev(db, view, own) if own is not None and own.erases else {}
    before = hour_figures(iter_rows(db, hour, hour + HOUR), salt, c_prev, exclude=set(added))
    if (before.count, before.root_s, before.root_c, before.ids_digest) != (root.count, root.root_s, root.root_c,
                                                                          root.ids_digest):
        return None
    new_salt = secrets.token_bytes(32) if salt is None and nonceless else None
    use_salt = salt or new_salt
    # The new roots are over the rows as they are now, erased ones included: the late seal ends the hour's erase
    # entries, so the next check compares the rows with it alone.
    after = hour_figures(iter_rows(db, hour, hour + HOUR), use_salt)
    detail = {"hour": fmt.hour_text(hour), "prev_seq": root.seq, "added": [str(a) for a in added], "by": "sealer"}
    seal = w.append("late", period_start=hour, period_end=hour + HOUR, row_count=after.count, row_bytes=after.bytes,
                    root_s=after.root_s, root_c=after.root_c, ids_dig=after.ids_digest, detail=detail,
                    row_ids=after.ids if wr is None else None, legacy_salt=new_salt if wr is None else None)
    seal.salt = use_salt
    if wr is not None:
        wr.row_ids = after.ids
        if new_salt is not None:
            wr.legacy_salt = new_salt
    return seal


def seal_pass(session_factory, *, engine=None, st: Optional[ChainState] = None, now: Optional[datetime] = None,
              budget_seconds: float = PASS_SECONDS, time_left: Optional[Callable[[], bool]] = None) -> PassResult:
    """One pass of the sealer: genesis when there is no chain yet, then every hour that may be sealed, in order,
    then the late rows of the hours sealed in the last 6 hours, then the cheap checks. Never raises."""
    st = st or state()
    result = PassResult()
    deadline = time.monotonic() + budget_seconds
    left = time_left or (lambda: time.monotonic() < deadline)
    try:
        engine = engine or _engine_of(session_factory)
        clock_now = lambda: now or st.clock()  # noqa: E731
        from app.core import audit_chain_policy_seals as ps
        # Genesis, then the first policy seal right after it (and the first start's request).
        with ChainWriter(engine, st) as w:
            if w.st.view.position == 0:
                why = _genesis_ready(w.db)
                if why:
                    _say(f"The audit chain's first seal waits: {why}")
                    return result
                write_genesis(w, clock_now())
        ps.write_genesis_policy(engine, st, clock_now())
        if st.view.newest_policy() is None:
            return result
        # An .env change is sealed before anything is done under it.
        ps.seal_env_change(engine, st, clock_now())
        st.started = True
        # Hours, in order.
        rows_done = 0
        while left() and rows_done < ROW_BUDGET:
            with ChainWriter(engine, st) as w:
                if w.key_move is not None:
                    write_key_move(w)
                    result.sealed += 1
                    continue
                view = w.st.view
                start = view.newest_hour_end or view.first_hour()
                seal = seal_hour(w, start, clock_now(), oldest_open_transaction(w.db))
                if seal is None:
                    break
                result.sealed += 1
                rows_done += seal.row_count
                result.rows += seal.row_count
        genesis = st.view.genesis or {}
        through = genesis.get("backlog_through")
        next_hour = st.view.newest_hour_end or st.view.first_hour()
        if through and next_hour is not None and next_hour <= fmt.parse_time_text(through):
            result.backlog = True
        st.backlog = result.backlog
        # Late rows.
        for entry in _late_candidates(st.view, clock_now()):
            if not left():
                break
            hours = [entry.start] if entry.end - entry.start == HOUR else \
                _hours_with_rows(session_factory, entry.start, entry.end)
            for hour in hours:
                with ChainWriter(engine, st) as w:
                    current = w.st.view.entry_for(hour)
                    if current is None:
                        continue
                    seal = check_late(w, current, hour, clock_now())
                if seal is not None:
                    result.late += 1
                    _announce_late(session_factory, seal)
        st.stopped = None
        _clear_stop_warnings(st)
    except ChainStopped as stop:
        st.stopped = stop
        result.stopped = stop.kind
        if stop.kind == "key-change-waiting":
            _key_waiting(st, session_factory, stop)
        else:
            report_failures(st, session_factory, {stop.kind: str(stop)})
        try:
            summarise_stopped(session_factory, st, now or st.clock(), left)
        except Exception as exc:  # noqa: BLE001 -- the next pass tries again
            _say(f"Warning: the audit hours were not summarised while sealing is stopped ({type(exc).__name__})")
    except ChainBusy:
        result.stopped = "busy"
    except Exception as exc:  # noqa: BLE001 -- the next pass tries again
        _say(f"Warning: the audit chain's sealer failed ({type(exc).__name__}: {exc})")
        result.stopped = "error"
    try:
        every_pass_checks(session_factory, st, now or st.clock())
    except Exception as exc:  # noqa: BLE001
        _say(f"Warning: the audit chain's checks failed ({type(exc).__name__})")
    return result


def summarise_stopped(session_factory, st: ChainState, now: datetime, time_left=None) -> int:
    """While sealing is stopped: read each hour that closes (under the same two conditions as sealing, in
    order) and write its count, roots and ids digest into the head record's hour summaries, marked unsealed.
    A cut of one seal then opens no unwatched window: the host's acceptance compares these hours too. Rows
    without a nonce are committed with none (no salt is drawn while nothing is sealed). Returns the hours
    summarised."""
    from app.core import audit_head_record as hr
    record = st.head_store().memory or {}
    starts = []
    for key, entry in (record.get("hours") or {}).items():
        try:
            starts.append(fmt.parse_time_text(entry.get("end") or key))
        except (TypeError, ValueError):
            continue
    if record.get("newest_hour_end"):
        starts.append(fmt.parse_time_text(record["newest_hour_end"]))
    if not starts:
        return 0
    start = max(starts)
    floor = hour_floor(now) - timedelta(days=hr.SUMMARY_DAYS)
    start = max(start, floor)
    db = session_factory()
    found = []
    rows = 0
    try:
        open_since = oldest_open_transaction(db)
        end = newest_sealable_end(now, open_since)
        h = start
        while h < end and rows < ROW_BUDGET and (time_left is None or time_left()):
            fig = hour_figures(iter_rows(db, h, h + HOUR), None)
            rows += fig.count
            found.append((h, fig))
            h += HOUR
    finally:
        db.close()
    if not found:
        return 0

    def change(rec):
        hours = rec.setdefault("hours", {})
        for h, fig in found:
            key = fmt.hour_text(h)
            if key in hours and not hours[key].get("unsealed"):
                continue
            hours[key] = {"end": fmt.hour_text(h + HOUR), "seq": None, "link": None, "sealed_at": None,
                          "count": fig.count, "root_s": fig.root_s.hex(), "root_c": fig.root_c.hex(),
                          "ids_digest": fig.ids_digest.hex(), "salt": None, "unsealed": True,
                          "summarised_at": fmt.time_text(now)}
        return rec

    st.head_store().write(change, now)
    return len(found)


def _clear_stop_warnings(st: ChainState) -> None:
    rec = st.head_store().memory or {}
    waiting = (rec.get("warnings") or {}).get("key-change-waiting")
    if waiting and not waiting.get("resolved_at"):
        now = st.clock()

        def change(record):
            w = (record.get("warnings") or {}).get("key-change-waiting")
            if w:
                w["resolved_at"] = fmt.time_text(now)
            return record
        st.head_store().write(change, now)


def _key_waiting(st: ChainState, session_factory, stop: ChainStopped) -> None:
    rec = st.head_store().memory or {}
    w = (rec.get("warnings") or {}).get("key-change-waiting") or {}
    first = w.get("first_seen")
    if first and not w.get("resolved_at") and st.clock() - fmt.parse_time_text(first) > KEY_WAIT_GRACE:
        report_failures(st, session_factory, {"key-change-waiting": str(stop)})
    else:
        report_failures(st, session_factory, {}, {"key-change-waiting": str(stop)})


def _hours_with_rows(session_factory, start: datetime, end: datetime) -> List[datetime]:
    from app.core.models import AuditLog as A
    db = session_factory()
    try:
        times = [r[0] for r in db.query(A.timestamp).filter(A.timestamp >= start, A.timestamp < end).all()]
    finally:
        db.close()
    return sorted({hour_floor(t) for t in times if t is not None})


def _announce_late(session_factory, seal: Seal) -> None:
    try:
        from app.services.audit_logger import AuditLogger
        db = session_factory()
        try:
            d = seal.detail or {}
            db.add(AuditLogger(db).build_row(action=LATE_ACTION, status="success", resource_type="audit_log",
                                             resource_id=str(seal.seq),
                                             details={"seq": seal.seq, "hour": d.get("hour"),
                                                      "added": len(d.get("added") or [])}))
            db.commit()
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001
        _say(f"Warning: a late seal was not announced ({type(exc).__name__})")


def write_key_move(w: ChainWriter) -> Seal:
    """The forward move of the chain to the current key: a key seal from the key in force, with its proof."""
    old, new = w.key_move
    view = w.st.view
    prev = view.link_at(view.position)
    proof = fmt.old_key_proof(old.key, prev, new.key_id)
    seal = w.append("key", detail={"old_key_id": old.key_id, "new_key_id": new.key_id, "old_key_proof": proof.hex(),
                                   "accepted_unverified": False, "by": "sealer"}, key=new)
    w.key_move = None
    return seal


# --------------------------------------------------------------------------- the checks every pass runs

def every_pass_checks(session_factory, st: ChainState, now: datetime) -> Dict[str, str]:
    """future-dated rows, rows before the chain's first hour, undated rows, and hooks on the audit tables."""
    from app.core.models import AuditLog as A
    found: Dict[str, str] = {}
    db = session_factory()
    try:
        future = db.query(func.count()).select_from(A).filter(A.timestamp > now + FUTURE_SLACK).scalar() or 0
        if future:
            found["future-dated"] = f"{future} audit rows are dated more than an hour ahead"
        first = st.view.first_hour()
        if first is not None:
            before = db.query(func.count()).select_from(A).filter(A.timestamp < first).scalar() or 0
            if before:
                found["row-before-genesis"] = f"{before} audit rows are dated before the chain's first hour"
            undated = db.query(func.count()).select_from(A).filter(A.timestamp.is_(None)).scalar() or 0
            if undated != int((st.view.genesis or {}).get("undated_rows") or 0):
                found["undated-row"] = f"{undated} audit rows have no timestamp"
        from app.core import audit_chain_verify
        hooks = audit_chain_verify.db_hooks(db)
        if hooks:
            found["db-hooks"] = "; ".join(hooks)
    finally:
        db.close()
    if found:
        report_failures(st, session_factory, found)
    return found


# --------------------------------------------------------------------------- the status the pages show

def status(st: Optional[ChainState] = None) -> dict:
    """The integrity status for the Activity page and the exports: the head, the last check, and every open
    failure and warning. Read from the head record and the verified view, never from audit rows."""
    st = st or state()
    try:
        st.head_store().load()
    except ValueError:
        pass
    record = st.known_record()
    view = st.view
    out = {"head": None, "head_at": None, "key_id": None, "sealed_through": None, "check": {}, "failures": {},
           "warnings": {}, "outcome": "not-started", "key_shared": False}
    if record:
        # Findings are shown whatever else the record holds: one kept with no head (the record was lost and
        # sealing stopped) is still a finding.
        out["failures"] = open_failures(record)
        out["warnings"] = open_warnings(record)
    if record and record.get("link"):
        out["head"] = fmt.head(int(record["seq"]), bytes.fromhex(record["link"]))
        out["key_id"] = record.get("key_id")
        out["sealed_through"] = record.get("newest_hour_end")
        out["check"] = record.get("check") or {}
        if unacknowledged_foreign(view, record):
            out["warnings"].setdefault("after-record", {"message": "seals another writer appended after the "
                                                                   "head record wait for the host"})
        # This process reads the chain at the pruner's first pass after it starts; until then, the warnings
        # from the seals are the ones the last writer recorded.
        seqs = view_warning_seqs(view, record) if view.position else (record.get("view_warnings") or {})
        late = list(seqs.get("late") or [])
        if late:
            out["warnings"]["late"] = {"message": f"{len(late)} late seals wait to be acknowledged",
                                       "seqs": late}
        vetoes = list(seqs.get("veto-from-database") or [])
        if vetoes:
            out["warnings"]["veto-from-database"] = {
                "message": f"{len(vetoes)} seals hold back a deletion from the database's values (a value that "
                           "keeps more, or a waiting change it no longer shows); acknowledge them once seen",
                "seqs": vetoes}
        out["outcome"] = (record.get("status") or {}).get("outcome") or "clean"
        try:
            out["key_shared"] = keys.current(st.cfg()).source == "encryption"
        except Exception:  # noqa: BLE001
            pass
        if st.head_store().unwritable:
            out["warnings"]["head-record-unwritable"] = {"message": st.head_store().unwritable}
    mark = st.restore_mark()
    if mark is not None:
        out["warnings"]["restore-pending"] = {
            "message": "a restore of a backup is not finished: nothing is deleted until the host operator runs "
                       "dockvault.py audit accept-restore", "first_seen": mark.get("at")}
    if out["failures"]:
        out["outcome"] = "failed"
    if st.stopped is not None:
        out["stopped"] = {"kind": st.stopped.kind, "message": str(st.stopped)}
        out["outcome"] = "failed" if out["failures"] else "stopped"
    return out


def head_for_export(st: Optional[ChainState] = None) -> Optional[str]:
    """The head to write into an export, or None before the chain has a seal."""
    try:
        return status(st).get("head")
    except Exception:  # noqa: BLE001
        return None


def main(argv=None) -> int:
    from app.core import audit_chain_verify
    return audit_chain_verify.main(argv)
