"""Removing the values recorded under earlier recording levels: once a level has been tightened, the audit rows
written before keep only what the levels in force record (app/core/audit_rewrite.py says what each row keeps).

Asking. An administrator previews what a removal would change now (preview(): for each kind of personal data whose
level is below full, how many rows hold a value above it, counted within a time budget, and how many archived days
it reads), then asks for it with the step-up (the password every time, ``admin.audit_privacy.write``). In one
transaction, under the audit chain's lock (request()):

- the ``audit_value_removals`` row: the levels in force (the lower of the stored level and the .env limit, for each
  kind) and ``before``, the end of the hour it is asked in: the rows written before then are its scope, so a row
  written later, at whatever level is in force then, is never in it;
- the chain's ``request`` seal (``what: removal``): ``new`` is the scope (``{"levels": ..., "before": ...}``), with
  ``not_before``, its own time plus the reduction delay;
- the ``audit_values_removal_requested`` audit row.

Every administrator is told, in the app and by email. The removal waits the reduction delay
(RETENTION_REDUCTION_DELAY_DAYS); any administrator can cancel it until it begins (cancel(): a ``cancel`` seal).
Once it has begun it is not stopped: it completes. One removal waits or runs at a time.

Running is the pruner's ``audit_value_removal`` job (run_job()). A removal is due when its request seal is pending
and its delay has run, timed as a setting's request is (the gaps in sealing move it on, and a request another
writer appended waits for the host's acknowledgment). It takes its levels and its scope from the request seal only:
a row whose copies differ is ``unjustified-input`` and nothing runs; a request whose row the database no longer
shows waiting (removed, or cancelled while sealing was stopped) is ended by a ``cancel`` seal ``by: database``, a
veto the host acknowledges like the others. It waits while a rule registered with person_erase.register_wait says
so (legal holds, open cases), and the hold switch holds it. A unit that does not check out (rows dated before the
chain's first hour among them) is reported, and the removal waits there; its row says a finding holds it.

Each transaction rewrites one unit, oldest first (audit_rewrite.step: an archived day, or hours of rows of one day),
with a ``rewrite`` seal of reason ``levels`` naming the request seal and its scope (``through``, the last hour of
the scope, the same in every seal of the run). When no unit is left, a last ``rewrite`` seal with no hour and
``final: true``, in the transaction that marks the row completed with its counts and writes the
``audit_values_removed`` audit row; then a plain VACUUM of the tables it changed, within a time budget, so the old
values leave the live tables' pages sooner (backups keep them).

Rows a compliance case keeps as they are (retention.register_keep_as_is) are left by every unit. While any in the
scope would change, the last seal waits: at the end of the scope the removal stays running and says so on its row,
and once the case lets them go (rows as they are now, an archived day read again once a pass) it goes back to the
first of them, changes them, and completes.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from app.core import audit_chain_format as fmt
from app.core import audit_rewrite as rw
from app.core import settings_registry as registry

PENDING = "pending"
RUNNING = "running"
COMPLETED = "completed"
CANCELLED = "cancelled"

REQUESTED_ACTION = "audit_values_removal_requested"
CANCELLED_ACTION = "audit_values_removal_cancelled"
REMOVED_ACTION = "audit_values_removed"
RESOURCE_TYPE = "value_removal"

# The email every administrator gets (app/core/email_actions.py); the in-app notice is a records notice.
EMAIL_ACTION = "recorded_values_removal"

HOUR = timedelta(hours=1)
# How long a preview may read rows: past it, its counts are what it had counted ("at least").
PREVIEW_SECONDS = 20.0
WAIT, STOP, DONE, REWRITTEN, SCANNED = "wait", "stop", "done", "rewritten", "scanned"
_EPOCH = datetime(1970, 1, 1)
VACUUM_TABLES = ("audit_seals", "audit_archive_blocks", "audit_logs", "audit_value_removals")


class Refused(Exception):
    """A request the removal will not take, in plain words."""


class LevelsChanged(Refused):
    """The levels in force are no longer the ones the preview showed."""


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _ap():
    from app.core import audit_privacy
    return audit_privacy


def in_force(db) -> Dict[str, str]:
    """The levels in force now, for each kind: the lower of the newest stored level and the .env limit."""
    ap = _ap()
    latest = ap.read_latest(db) or ap.DEFAULT_POLICY
    return dict(ap.effective(latest.levels))


def below_full(levels: Dict[str, str]) -> Dict[str, str]:
    ap = _ap()
    return {k: v for k, v in levels.items() if v != ap.FULL}


def scope_end(now: datetime) -> datetime:
    """The end of the hour ``now`` is in: a removal asked for now covers the rows written before it."""
    return _ai().hour_floor(now) + HOUR


def delay_days(view, st) -> int:
    from app.core import person_erase as pe
    return pe.delay_days(view, st)


# --------------------------------------------------------------------------- the preview

def _hot_rows(db, levels, before: datetime, now: Optional[datetime] = None):
    from sqlalchemy import Text, cast
    from app.core import retention
    from app.core.models import AuditLog as A
    # Not a compliance case's rows, which a removal leaves as they are (retention.register_keep_as_is).
    q = db.query(A.id, A.action, A.user_id, A.temp_credential_id, A.username, A.ip_address, A.user_agent,
                 cast(A.recorded, Text), cast(A.details, Text)).filter(
        *retention.changeable(A, now or _ai().state().clock(), *rw.prefilter(A, levels)),
        A.timestamp.isnot(None), A.timestamp < before)
    for r in q.yield_per(2000):
        yield {"id": r[0], "action": r[1], "user_id": r[2], "temp_credential_id": r[3], "username": r[4],
               "ip_address": r[5], "user_agent": r[6], "recorded": r[7], "details": r[8]}


def count_changes(db, view, levels: Dict[str, str], before: datetime, ctx: "rw.Context", *,
                  budget: Optional[float] = None) -> dict:
    """{"rows": n, "kinds": {kind: n}, "counted": bool}: the rows (not archived, with a time, before ``before``, not
    erased) whose values above ``levels`` a removal changes, in all and for each kind below full. ``counted`` is
    False when ``budget`` seconds ran out first: the numbers are then what had been counted."""
    lowered = below_full(levels)
    full = {k: _ap().FULL for k in _ap().POLICY_KEYS}
    out = {"rows": 0, "kinds": {k: 0 for k in lowered}, "counted": True}
    if not lowered:
        return out
    deadline = time.monotonic() + budget if budget is not None else None
    for i, row in enumerate(_hot_rows(db, levels, before)):
        if deadline is not None and i % 500 == 0 and time.monotonic() > deadline:
            out["counted"] = False
            break
        if str(row["id"]) in view.erased_rows or rw.reduced(row, levels, ctx) is None:
            continue
        out["rows"] += 1
        for kind, level in lowered.items():
            if rw.reduced(row, dict(full, **{kind: level}), ctx) is not None:
                out["kinds"][kind] += 1
    return out


def later_format_days(db, view, before: datetime) -> List[str]:
    """The archived days a removal before ``before`` would reach whose blocks the database marks with a later
    release's block format (after a rollback from a release that writes one): this release neither checks nor
    changes such a day, so a removal reaching one could not complete here. Their row says so; the run checks the
    block itself (audit_rewrite.step)."""
    from app.core import audit_archive as arc
    from app.core import audit_archive_format as af
    from app.core.models import AuditArchiveBlock as B
    days = [d for d, e in view.archives.items() if e.parts and arc.day_start(d) < before]
    if not days:
        return []
    found = db.query(B.day).filter(B.day.in_(days), B.format > af.FORMAT).distinct().all()
    return sorted({(d if not isinstance(d, datetime) else d.date()).isoformat() for (d,) in found})


def _later_format_words(days: List[str]) -> str:
    return (f"The archived days {', '.join(days)} hold blocks of a later release's block format, which this release "
            "neither checks nor changes, so a removal reaching them could not complete here. Ask for it with the "
            "release that wrote them.")


def preview(db, st, now: datetime) -> dict:
    """What a removal asked for now would change, and what it leaves."""
    from sqlalchemy import func
    from app.core import audit_archive as arc
    from app.core.models import AuditLog as A
    ap = _ap()
    view = st.view
    levels = in_force(db)
    before = scope_end(now)
    counted = {"rows": 0, "kinds": {}, "counted": True}
    if below_full(levels):
        try:
            with db.begin_nested():
                counted = count_changes(db, view, levels, before, rw.Context.load(db), budget=PREVIEW_SECONDS)
        except Exception:  # noqa: BLE001 -- too slow to count in a request: the removal counts them as it runs
            counted = {"rows": None, "kinds": {}, "counted": False}
    undated = int(db.query(func.count()).select_from(A).filter(A.timestamp.is_(None)).scalar() or 0)
    not_reached = ["exports and backups made before it",
                   "the server's logs and the log-access file",
                   "audit rows an erase has changed (they keep no personal value)",
                   "values the levels do not govern: account usernames, ids, error types and the error text "
                   "earlier releases recorded, route templates",
                   "the security record of failed sign-ins and the security alerts, which keep addresses for "
                   "their own window"]
    if undated:
        not_reached.append(f"{undated} audit rows with no time")
    return {
        "levels": levels,
        "kinds": [{"key": k, "label": ap.LABELS[k], "level": levels[k], "rows": counted["kinds"].get(k)}
                  for k in ap.POLICY_KEYS if levels[k] != ap.FULL],
        "rows": counted["rows"],
        "counted": counted["counted"],
        "before": fmt.time_text(before),
        "archived_days": sum(1 for d, e in view.archives.items() if e.parts and arc.day_start(d) < before),
        "later_format_days": later_format_days(db, view, before),
        "undated_rows": undated,
        "delay_days": delay_days(view, st),
        "waiting": waiting(view) is not None,
        "not_reached": not_reached,
    }


# --------------------------------------------------------------------------- asking, cancelling, listing

def held_request(view, request_id) -> int:
    """The seq of the removal request the chain holds for ``request_id``. Raises LookupError when it holds none."""
    wanted = str(request_id)
    for seq, d in view.requests.items():
        if d.get("what") == "removal" and d.get("request") == wanted:
            return seq
    raise LookupError(request_id)


def waiting(view) -> Optional[str]:
    """The id of the removal the chain holds waiting or running, or None. A row the database shows waiting with no
    pending request in the chain is not one: nothing runs it (the job reads the chain), the page cannot cancel it,
    and the server's daily check reports it."""
    for seq, d in view.pending_requests().items():
        if d.get("what") == "removal":
            return str(d.get("request"))
    return None


def request(w, actor, *, now: Optional[datetime] = None, expected: Optional[Dict[str, str]] = None) -> dict:
    """Ask for a removal in the chain writer ``w``'s transaction: the row, the request seal and the audit row.
    ``expected``: the levels the preview showed; when the levels in force are others now (another administrator
    changed one meanwhile) nothing is asked for. Raises Refused (LevelsChanged for that)."""
    from app.core.models import AuditValueRemoval
    from app.services.audit_logger import AuditLogger
    st, db = w.st, w.db
    view = st.view
    now = now or st.clock()
    levels = in_force(db)
    if expected is not None and dict(expected) != levels:
        raise LevelsChanged("The recording levels changed since the preview: preview again, then ask.")
    if not below_full(levels):
        raise Refused("Every kind of personal data is recorded in full now, so there is nothing to remove. Choose a "
                      "lower level first.")
    if waiting(view) is not None:
        raise Refused("A removal is already waiting or running: cancel it first, or let it complete.")
    later = later_format_days(db, view, scope_end(now))
    if later:
        # Once begun, a removal cannot be cancelled, and one that waits for good holds every new removal back.
        raise Refused(_later_format_words(later))
    request_id = uuid.uuid4()
    delay = timedelta(days=delay_days(view, st))
    audit = AuditLogger(db).build_row(
        action=REQUESTED_ACTION, status="success", user=actor, resource_type=RESOURCE_TYPE,
        resource_id=str(request_id),
        details={"request_id": str(request_id), "levels": levels, "effective_at": fmt.time_text(now + delay)})
    db.add(audit)
    row = AuditValueRemoval(id=request_id, status=PENDING, levels=levels, before=scope_end(now),
                            requested_by=getattr(actor, "id", None), requested_by_name=getattr(actor, "username", None),
                            requested_at=now, effective_at=now + delay)
    db.add(row)
    db.flush()
    user_id = str(actor.id) if getattr(actor, "id", None) is not None else None
    seal = w.append("request", detail=lambda seq, sealed_at: {
        "what": "removal", "request": str(request_id), "setting": None, "old": None,
        "new": {"levels": levels, "before": fmt.hour_text(scope_end(sealed_at))}, "subject": None,
        "placeholder": None, "not_before": fmt.time_text(sealed_at + delay), "audit_row": str(audit.id),
        "by": "admin", "user_id": user_id})
    row.request_seq = seal.seq
    row.before = fmt.parse_time_text(seal.detail["new"]["before"])
    row.effective_at = fmt.parse_time_text(seal.detail["not_before"])
    return entry_of(row, view, extra_seal=seal)


def ended_as(view, seq: int) -> str:
    if seq in view.cancels:
        return "cancelled"
    if seq in view.finals:
        return "completed"
    return "ended"


def _end_row(db, row, request_id, actor, now):
    from app.services.audit_logger import AuditLogger
    if row is not None:
        row.status = CANCELLED
        row.decided_by = getattr(actor, "id", None)
        row.decided_by_name = getattr(actor, "username", None)
        row.decided_at = now
        row.waiting = None
    audit = AuditLogger(db).build_row(
        action=CANCELLED_ACTION, status="success", user=actor, resource_type=RESOURCE_TYPE,
        resource_id=str(request_id), details={"request_id": str(request_id)})
    db.add(audit)
    return audit


def _cancellable(view, request_id) -> int:
    seq = held_request(view, request_id)
    if seq not in view.pending_requests():
        raise Refused(f"This removal is no longer waiting: it was {ended_as(view, seq)}.")
    if seq in view.rewrite_through:
        raise Refused("This removal has begun: it completes, and cannot be cancelled now.")
    return seq


def cancel(w, request_id, actor) -> dict:
    """An administrator's cancel of a removal that has not begun, in ``w``'s transaction: the cancel seal, the row
    ended and the audit row. Raises LookupError (no such removal in the chain) and Refused (no longer waiting, or
    begun)."""
    from app.core.models import AuditValueRemoval
    view = w.st.view
    seq = _cancellable(view, request_id)
    row = w.db.get(AuditValueRemoval, fmt.as_uuid(request_id))
    audit = _end_row(w.db, row, request_id, actor, w.st.clock())
    user_id = str(actor.id) if getattr(actor, "id", None) is not None else None
    w.append("cancel", detail={"cancels": seq, "request": str(request_id), "audit_row": str(audit.id), "by": "admin",
                               "user_id": user_id})
    return entry_of(row, w.st.view) if row is not None else {"id": str(request_id), "status": CANCELLED}


def cancel_while_stopped(db, request_id, actor, st=None) -> dict:
    """A cancel while sealing is stopped, in ``db``'s transaction: the removal must be one this process's view holds
    waiting and not begun; its row is ended (so it never runs: the job vetoes a request whose row does not wait),
    and the next pass seals the cancel from the database. Raises LookupError and Refused as cancel() does."""
    from app.core.models import AuditValueRemoval
    st = st or _ai().state()
    _cancellable(st.view, request_id)
    row = db.get(AuditValueRemoval, fmt.as_uuid(request_id))
    _end_row(db, row, request_id, actor, st.clock())
    return entry_of(row, st.view) if row is not None else {"id": str(request_id), "status": CANCELLED}


def _iso(v) -> Optional[str]:
    return v.isoformat() + "Z" if v else None


def entry_of(row, view, extra_seal=None) -> dict:
    """A removal as the page lists it: its state from the chain (pending, running, completed, cancelled), with the
    levels and the scope its request seal holds, and the row's copies beside them."""
    seq = None
    if extra_seal is not None:
        seq = extra_seal.seq
    elif row is not None:
        try:
            seq = held_request(view, row.id)
        except LookupError:
            seq = None
    if seq is None:
        status = "not recorded"
    elif seq in view.cancels:
        status = CANCELLED
    elif seq in view.finals:
        status = COMPLETED
    elif seq in view.rewrite_through:
        status = RUNNING
    else:
        status = PENDING
    if status == PENDING and row is not None and row.status == CANCELLED:
        # Cancelled in the database while sealing was stopped: the chain records the cancel once sealing runs.
        status = CANCELLED
    chain = (view.requests.get(seq) or {}) if seq is not None else {}
    if extra_seal is not None:
        chain = extra_seal.detail
    scope = chain.get("new") if isinstance(chain.get("new"), dict) else {}
    return {
        "id": str(row.id) if row is not None else chain.get("request"),
        "status": status,
        "request_seq": seq,
        "levels": scope.get("levels") or (row.levels if row is not None else None),
        "before": scope.get("before") or (_iso(row.before) if row is not None else None),
        "requested_by": row.requested_by_name if row is not None else None,
        "requested_at": _iso(row.requested_at) if row is not None else None,
        "effective_at": chain.get("not_before") or (_iso(row.effective_at) if row is not None else None),
        "started_at": _iso(row.started_at) if row is not None else None,
        "completed_at": _iso(row.completed_at) if row is not None else None,
        "decided_by": row.decided_by_name if row is not None else None,
        "decided_at": _iso(row.decided_at) if row is not None else None,
        "waiting": row.waiting if row is not None and status in (PENDING, RUNNING) else None,
        "counts": row.counts if row is not None else None,
        "cancellable": status == PENDING,
    }


def listing(db, st=None) -> list:
    """Every removal, newest first, as the chain holds it; a row the chain holds no request of says so."""
    from app.core.models import AuditValueRemoval
    st = st or _ai().state()
    rows = db.query(AuditValueRemoval).order_by(AuditValueRemoval.requested_at.desc()).limit(100).all()
    return [entry_of(r, st.view) for r in rows]


# --------------------------------------------------------------------------- telling the administrators

def _date(text) -> str:
    from app.core import person_erase as pe
    return pe._date(text)


def _levels_words(levels) -> str:
    ap = _ap()
    from app.api.recording_levels_router import LEVEL_WORDS
    parts = [f"{ap.LABELS[k].lower()}: {LEVEL_WORDS.get(v, v).lower()}" for k, v in (levels or {}).items()
             if k in ap.LABELS and v != ap.FULL]
    return "; ".join(parts) or "every kind in full"


def notice_words(event: str, facts: dict, by: Optional[str] = None) -> tuple:
    """(title, body) of the notice every administrator gets."""
    by = by or "An administrator"
    if event == "asked":
        return ("A removal of recorded values is waiting",
                f"{by} asked for the audit rows written before {_date(facts.get('before'))} to keep only what the "
                f"recording levels in force record ({_levels_words(facts.get('levels'))}). It runs on "
                f"{_date(facts.get('effective_at'))} unless an administrator cancels it on the Settings page.")
    if event == "cancelled":
        return ("A waiting removal of recorded values was cancelled",
                f"{by} cancelled the removal of values recorded before {_date(facts.get('before'))}. Nothing "
                "changes.")
    return ("A removal of recorded values is complete",
            f"{facts.get('rows', 0)} audit rows written before {_date(facts.get('before'))} now keep only what the "
            f"recording levels record ({_levels_words(facts.get('levels'))}).")


def tell_administrators(event: str, facts: dict, by: Optional[str] = None) -> None:
    """Tell every active administrator, in the app and by email, after the commit. Never raises."""
    try:
        from app.api import api_server as api
        from app.core.database import get_db_context
        from app.core.models import RoleEnum, User
        from app.core.person_erase import NOTICE_TYPE
        title, body = notice_words(event, facts, by)
        with get_db_context() as db:
            admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
            recipients = [(a.email, a.username) for a in admins]
            api._notify_users([str(a.id) for a in admins], NOTICE_TYPE, title=title, body=body, target="#settings")
            api._fire_action_email_bulk(db, EMAIL_ACTION, recipients,
                                        {"change": body, "by": by or "", "when": api._change_time_text()})
    except Exception as exc:  # noqa: BLE001
        registry._say(f"Warning: the administrators were not told of a removal of recorded values "
                      f"({type(exc).__name__})")


# --------------------------------------------------------------------------- running it

class InputProblem(Exception):
    pass


def due(view, record: Optional[dict], now: datetime) -> List[int]:
    """The pending removals whose delay has run, oldest first, timed as a setting's request is; one that has begun
    goes on. Nothing while a gap in sealing is open."""
    from app.core import audit_chain_honour as honour
    from app.core import audit_chain_times as times
    out = []
    if not view.position:
        return out
    if any(tl.open_gap(times.us(now)) for tl in times.timelines(view, record)):
        return out
    foreign = _ai().foreign_entries(view, record)
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "removal":
            continue
        if seq in view.rewrite_through:
            out.append(seq)
            continue
        try:
            fmt.parse_time_text(d.get("not_before"))
        except (TypeError, ValueError):
            continue
        if seq in foreign and honour.ack_time(view, record, seq) is None:
            continue
        if now < honour.effective_not_before(view, record, seq, now):
            continue
        out.append(seq)
    return out


def row_of(db, view, seq: int):
    """The audit_value_removals row of the removal request ``seq``, or None when the database holds it back (no row,
    or a row that no longer waits): a veto. Raises InputProblem (unjustified-input) for a row whose copies of the
    levels or the scope differ from the request seal's."""
    from app.core.models import AuditValueRemoval
    d = view.requests[seq]
    try:
        rid = fmt.as_uuid(d.get("request"))
    except (TypeError, ValueError):
        raise InputProblem(f"removal request seal {seq} names no request") from None
    row = db.get(AuditValueRemoval, rid)
    if row is None or row.status not in (PENDING, RUNNING):
        return None
    try:
        levels, before = rw.removal_scope(d)
    except (TypeError, ValueError):
        raise InputProblem(f"removal request seal {seq} is not well formed; it is not acted on") from None
    if dict(row.levels or {}) != levels or row.before != before:
        raise InputProblem(f"audit_value_removals holds other levels or another scope for the removal of request "
                           f"seal {seq}; it is not acted on")
    return row


def pending_input_problems(db, view) -> List[str]:
    """Each pending removal whose row contradicts its request seal, and each waiting row the chain holds no request
    of (verify step 4, on the server)."""
    from app.core.models import AuditValueRemoval
    out = []
    held = {str(d.get("request")) for d in view.requests.values() if d.get("what") == "removal"}
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "removal":
            continue
        try:
            row_of(db, view, seq)
        except InputProblem as exc:
            out.append(str(exc))
    for row in db.query(AuditValueRemoval).filter(AuditValueRemoval.status.in_((PENDING, RUNNING))).all():
        if str(row.id) not in held:
            out.append("a removal waiting in the database has no request seal; it is ignored")
    return out


def vetoed(st, session_factory) -> List[int]:
    """The pending removals not begun whose row the database no longer shows waiting: each is ended by a cancel seal
    from the database without waiting for its delay."""
    from app.core.models import AuditValueRemoval
    out = []
    pending = {seq: d for seq, d in st.view.pending_requests().items()
               if d.get("what") == "removal" and seq not in st.view.rewrite_through}
    if not pending:
        return out
    db = session_factory()
    try:
        for seq, d in sorted(pending.items()):
            try:
                row = db.get(AuditValueRemoval, fmt.as_uuid(d.get("request")))
            except (TypeError, ValueError):
                row = None
            if row is None or row.status not in (PENDING, RUNNING):
                out.append(seq)
    finally:
        db.close()
    return out


_cursors: Dict[tuple, datetime] = {}
# Per removal (_cursor_key), the rows its run left because a compliance case keeps them as they are: {id: time} of
# rows, and {day: how many} of archived days. Kept in this process only: after a restart the run reads its scope
# again from the start, as it does anyway.
_kept_rows: Dict[tuple, Dict] = {}
_kept_days: Dict[tuple, Dict] = {}


def _cursor_key(st, seq: int) -> tuple:
    return (id(st), st.view.generation, seq)


KEPT_WAIT = ("It waits: {n} rows in its scope are kept as they are for a compliance case. It changes them, and "
             "completes, once the case lets them go.")


def kept_to_change(db, levels, before: datetime, ctx, now: datetime) -> Dict:
    """{id: time} of the rows of audit_logs before ``before`` whose values the removal would change but which a
    compliance case keeps as they are (retention.kept_as_is)."""
    from app.core import retention
    from app.core.models import AuditLog
    clause = retention.kept_as_is(AuditLog, now)
    if clause is None:
        return {}
    out = {}
    for row in db.query(AuditLog).filter(*rw.prefilter(AuditLog, levels), AuditLog.timestamp.isnot(None),
                                         AuditLog.timestamp < before, clause):
        values = {c.key: getattr(row, c.key) for c in AuditLog.__table__.columns}
        if rw.reduced(values, levels, ctx) is not None:
            out[row.id] = row.timestamp
    return out


def _finished_or_waiting(w, key, scope: "rw.Scope", levels, before: datetime, ctx, now: datetime, cursor: datetime,
                         cache: dict) -> Optional[tuple]:
    """At the end of the scope: None when nothing a case keeps is left (the removal completes), else what step
    returns: SCANNED with the cursor moved back to rows a case has let go since, or WAIT while it keeps them."""
    ai = _ai()
    db = w.db
    rows_now = kept_to_change(db, levels, before, ctx, now)
    left = _kept_rows.get(key) or {}
    gone = [t for i, t in left.items() if i not in rows_now]
    days = _kept_days.get(key) or {}
    if days and not cache.get("days_read"):
        # Archived days holding rows a case keeps are read again once a pass: the case may have let them go.
        cache["days_read"] = True
        for day, n in sorted(days.items()):
            still = rw.kept_in_archived_day(w, day, scope.change, now=now, before=before)
            if still < n:
                gone.append(arc_day_start(day))
            days[day] = still
    if gone:
        back = ai.hour_floor(min(gone))
        if back < cursor:
            _kept_rows.pop(key, None)
            return SCANNED, 0, back, None, None
    _kept_rows[key] = rows_now
    kept = len(rows_now) + sum(days.values())
    if kept:
        return WAIT, 0, cursor, None, KEPT_WAIT.format(n=kept)
    return None


def arc_day_start(day) -> datetime:
    from app.core import audit_archive as arc
    return arc.day_start(day)


def _progress(row, now: datetime, changed: int, unit: Optional[str]) -> None:
    if row is None:
        return
    if row.status == PENDING:
        row.status = RUNNING
        row.started_at = now
    counts = dict(row.counts or {})
    key = "archived_rows" if unit == "day" else "rows"
    counts[key] = int(counts.get(key, 0)) + int(changed)
    row.counts = counts
    row.waiting = None


def finish(w, row, seq: int, d: dict, now: datetime) -> dict:
    """In the last transaction: the row completed with its counts, and the audit_values_removed audit row. Returns
    what the notice says."""
    from app.services.audit_logger import AuditLogger
    counts = dict((row.counts or {}) if row is not None else {})
    total = int(counts.get("rows", 0)) + int(counts.get("archived_rows", 0))
    scope = d.get("new") or {}
    if row is not None:
        row.status = COMPLETED
        row.completed_at = now
        row.waiting = None
        row.counts = {"rows": int(counts.get("rows", 0)), "archived_rows": int(counts.get("archived_rows", 0))}
    w.db.add(AuditLogger(w.db).build_row(
        action=REMOVED_ACTION, status="success", resource_type=RESOURCE_TYPE, resource_id=d.get("request"),
        details={"request_id": d.get("request"), "rows": total, "levels": scope.get("levels")}))
    return {"rows": total, "before": scope.get("before"), "levels": scope.get("levels")}


def step(p, w, seq: int, findings: Dict[str, str], cache: Optional[dict] = None) -> tuple:
    """One transaction of the removal of request ``seq``: (outcome, rows changed, the new cursor, the notice's facts
    when it completed, the reason it waits, or what holds it when it stops on a finding). Writes nothing unless it
    returns REWRITTEN (or DONE after a veto). ``cache`` lasts one pass of the job."""
    from app.core import audit_chain_policy_seals as ps
    from app.core import audit_retention as ar
    from app.core import person_erase as pe
    from app.core.models import AuditLog
    st, db = w.st, w.db
    view = st.view
    now = p.now
    cursor = _cursors.get(_cursor_key(st, seq), _EPOCH)
    if seq not in view.pending_requests():
        return DONE, 0, cursor, None, None
    if st.holds_deletion():
        return STOP, 0, cursor, None, None
    d = view.requests[seq]
    try:
        row = row_of(db, view, seq)
    except InputProblem as exc:
        findings["unjustified-input"] = str(exc)
        return STOP, 0, cursor, None, held_by("unjustified-input")
    if row is None:
        if seq not in view.rewrite_through and ps._veto_allowed_today(view, now):
            w.append("cancel", detail={"cancels": seq, "request": d.get("request"), "audit_row": None,
                                       "by": "database", "user_id": None})
            return DONE, 0, cursor, None, None
        if seq in view.rewrite_through:
            findings["unjustified-input"] = (f"the removal of request seal {seq} has begun, and its row no longer "
                                             "shows it running; it waits")
            return STOP, 0, cursor, None, held_by("unjustified-input")
        return STOP, 0, cursor, None, None
    why = pe.rule_waits(db, now)
    if why:
        return WAIT, 0, cursor, None, f"It waits: {why}."
    chain = ar.chain_numbers()
    if chain is None:
        return STOP, 0, cursor, None, None
    if chain[2]:
        return WAIT, 0, cursor, None, "It waits while the hold switch is on."
    levels, before = rw.removal_scope(d)
    if view.newest_hour_end is None or view.newest_hour_end < before:
        return WAIT, 0, cursor, None, "It waits until every hour it covers is sealed."
    ctx = rw.Context.load(db)
    # A compliance case's rows stay as they are (retention.register_keep_as_is).
    from app.core import retention
    scope = rw.Scope(rw.LEVELS, before, lambda r: rw.reduced(r, levels, ctx),
                     retention.changeable(AuditLog, now, *rw.prefilter(AuditLog, levels)),
                     request_seq=seq, through=fmt.hour_text(before - HOUR))
    key = _cursor_key(st, seq)
    try:
        outcome, cursor, changed, _oldest, _newest, unit = rw.step(p, w, scope, cursor)
        days = _kept_days.setdefault(key, {})
        days.update(scope.kept_archived)
        for day in [d for d, n in days.items() if not n]:
            del days[day]
        if outcome == rw.FINISHED:
            waiting = _finished_or_waiting(w, key, scope, levels, before, ctx, now, cursor,
                                           cache if cache is not None else {})
            if waiting is not None:
                return waiting
    except rw.NotRewritten as nr:
        if nr.kind:
            # A unit that does not check out (rows dated before the chain's first hour among them): reported, and the
            # removal waits there, since it must reach every row it covers. Rows before the first hour hold it until
            # they are gone: the next pass finds them again, acknowledged or not.
            until = ""
            if nr.kind == "row-before-genesis":
                until = (f" until {'the row is' if nr.rows == 1 else 'those rows are'} removed from audit_logs (an "
                         "acknowledgment of this finding does not release it)")
            findings[nr.kind] = f"{nr}; the removal of request seal {seq} waits{until}"
            return STOP, 0, cursor, None, held_by(nr.kind)
        if nr.later_format:
            return WAIT, 0, cursor, None, f"It waits: {nr}, so this release cannot complete it."
        return WAIT, 0, cursor, None, f"It waits: {nr}."
    if outcome == rw.CHANGED:
        _progress(row, now, changed, unit)
        return REWRITTEN, changed, cursor, None, None
    if outcome == rw.CLEAN:
        return SCANNED, 0, cursor, None, None
    newest = view.newest_policy()
    w.append("rewrite", detail=scope.detail(newest[0], [], final=True))
    _progress(row, now, 0, None)
    _kept_rows.pop(key, None)
    _kept_days.pop(key, None)
    return REWRITTEN, 0, cursor, finish(w, row, seq, d, now), None


def held_by(kind: str) -> str:
    """What the request says while a finding of the audit log's check holds it: a reason given before the finding
    would no longer be true."""
    return (f"It is held: the audit log's check found a fault ({kind}) where it would change rows, and it waits "
            "until that is resolved.")


def _note_waiting(session_factory, request_id, why: Optional[str]) -> None:
    """Say on the request why it waits (a transaction of its own: a wait writes nothing in the chain's)."""
    from app.core.models import AuditValueRemoval
    db = session_factory()
    try:
        row = db.get(AuditValueRemoval, fmt.as_uuid(request_id))
        if row is not None and row.status in (PENDING, RUNNING) and row.waiting != (why or None):
            row.waiting = why[:255] if why else None
            db.commit()
    except Exception:  # noqa: BLE001 -- the next pass says it again
        db.rollback()
    finally:
        db.close()


def run_job(p):
    """The pruner's audit_value_removal job. Returns a retention.JobResult (the rows changed, as cleared)."""
    from app.core import audit_chain_erase
    from app.core import retention
    ai = _ai()
    st = ai.state()
    result = retention.JobResult()
    if st.stopped is not None or not st.view.position or st.view.newest_policy() is None:
        return result
    engine = ai._engine_of(p.session_factory)
    findings: Dict[str, str] = {}
    finished = []
    for seq in sorted(set(due(st.view, st.known_record(), p.now)) | set(vetoed(st, p.session_factory))):
        cache: dict = {}
        while p.time_left() and not p.held_now():
            outcome, changed, cursor, done, why = STOP, 0, None, None, None
            with ai.ChainWriter(engine, st) as w:
                outcome, changed, cursor, done, why = step(p, w, seq, findings, cache)
                if outcome not in (REWRITTEN, DONE) and w.written:
                    # Only a rewrite or a veto commits: anything else leaves the transaction as it found it.
                    w.written = []
                    w.db.rollback()
            if outcome in (REWRITTEN, SCANNED) and cursor is not None:
                _cursors[_cursor_key(st, seq)] = cursor
            result.cleared += changed
            if outcome == WAIT or (outcome == STOP and why):
                _note_waiting(p.session_factory, st.view.requests[seq].get("request"), why)
                break
            if outcome in (REWRITTEN, SCANNED) and done is None:
                continue
            if done is not None:
                finished.append(done)
            break
        if seq not in st.view.pending_requests():
            for kept in (_cursors, _kept_rows, _kept_days):
                kept.pop(_cursor_key(st, seq), None)
    if findings:
        ai.report_failures(st, p.session_factory, findings)
    for done in finished:
        tell_administrators("completed", done)
    if finished:
        audit_chain_erase.vacuum(engine, tables=VACUUM_TABLES)
    return result
