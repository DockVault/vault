"""The audit log's integrity status, for the Activity page, and an administrator's acknowledgment of its warnings
(app/core/audit_integrity.py).

    GET  /activity/integrity                    the chain's head (the line to keep somewhere else), how far the
                                                hours are sealed, the last check's time and outcome, every
                                                failure and warning not yet acknowledged, and the archive:
                                                when it starts, the row window, and the days held in
                                                compressed blocks
    GET  /settings/audit-integrity/warnings     the warnings an administrator may acknowledge: each late seal with
                                                the rows it added (time, action, account, resource), and each seal
                                                the pruner wrote from the database's values; and the archive, as
                                                for the Activity page
    POST /settings/audit-integrity/acknowledge  acknowledge some of them, with the step-up the "password always"
                                                policy asks for, in an ``ack`` seal by that administrator

The status is read from the head record and the verified view, never from the audit rows that announce a
failure: those land in hours not yet sealed, where whoever caused the failure could delete them. The rows a
late seal added are read through its ``added`` ids as the verified view holds the seal (its link checked), so
an administrator acknowledges what they have seen, not a count. The acknowledgment writes its seal under the
chain lock, in the transaction of its audit row, never through a queue in a table: a database row cannot ask
for one. An administrator acknowledges warnings only; failures, and seals another writer appended after the
head record, are the host operator's (``dockvault.py audit acknowledge``). Only an interactive administrator
reaches these routes.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import audit_chain_format as fmt
from app.core import audit_archive, audit_integrity
from app.core import fixed_step_up
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Audit log integrity"])

# What the page says the chain does, and does not, give.
CLAIM = ("Tamper-evident against changes made in the database without the server's key; not against the "
         "server's operator.")

STEP_UP_ACTION = "admin.audit_integrity.acknowledge"
_step_up = fixed_step_up.guard(STEP_UP_ACTION)

MAX_ROWS_SHOWN = 200
ACKNOWLEDGED_ACTION = "audit_integrity_acknowledged"


# What a refusal while this process cannot read the chain tells the client to wait before it asks again (Retry-After).
UNREAD_RETRY_SECONDS = 60


def require_chain_read(db, what: str) -> None:
    """For a route whose answer comes from this process's view of the chain: read the chain first when this process
    has not read it through (audit_integrity.read_view), and refuse with 503 (and Retry-After) when it still is not,
    rather than answer ``what`` from an empty or partial view."""
    st = audit_integrity.state()
    if audit_integrity.read_view(db.get_bind(), st):
        return
    raise _unread(st, what)


def _unread(st, what: str) -> HTTPException:
    retry = "" if (st.stopped is not None or st.read_stopped) else " Try again in a minute."
    return HTTPException(status_code=503, detail=f"{what} cannot be told yet: {audit_integrity.unread_reason(st)}."
                                                 f"{retry}", headers={"Retry-After": str(UNREAD_RETRY_SECONDS)})


def answer_from_view(db, what: str, answer):
    """``answer()``, for a route whose answer comes from this process's view: the chain read first (require_chain_read),
    and the answer given only when the view stayed read through while it was computed (ChainState.trusted); else 503
    as require_chain_read refuses."""
    require_chain_read(db, what)
    st = audit_integrity.state()
    try:
        return st.trusted(lambda _view: answer())
    except audit_integrity.ViewUnread:
        raise _unread(st, what)


def _entries(table: dict) -> list:
    return [{"kind": kind, "message": e.get("message", ""), "first_seen": e.get("first_seen"),
             "last_seen": e.get("last_seen")} for kind, e in sorted((table or {}).items())]


@router.get("/activity/integrity")
def get_integrity(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """The integrity status of the audit log. The chain is read first when this process has not read it through
    (the archive's summary is from the view; until it is read, it says so: ``read`` false)."""
    audit_integrity.read_view(db.get_bind())
    status = audit_integrity.status()
    return {"head": status.get("head"), "sealed_through": status.get("sealed_through"),
            "key_id": status.get("key_id"), "key_shared": bool(status.get("key_shared")),
            "outcome": status.get("outcome"), "checked_at": (status.get("check") or {}).get("daily_at"),
            "failures": _entries(status.get("failures")), "warnings": _entries(status.get("warnings")),
            "stopped": status.get("stopped"), "claim": CLAIM,
            "archive": audit_archive.summary()}


def admin_warnings(view, record) -> dict:
    """The seals an administrator may acknowledge: late seals and seals written from the database's values that
    no acknowledgment that counts names, and that another writer did not append."""
    ai = audit_integrity
    done = ai.acknowledged(view, record)
    foreign = set(ai.foreign_entries(view, record))
    return {"late": [s for s in view.late_seqs if s not in done and s not in foreign],
            "veto": [s for s in ai.database_seqs(view) if s not in done and s not in foreign]}


def _rows(db, ids: List[str]) -> list:
    from app.core.models import AuditLog as A
    wanted = [fmt.as_uuid(i) for i in ids[:MAX_ROWS_SHOWN]]
    rows = db.query(A.id, A.timestamp, A.action, A.username, A.resource_type, A.resource_id).filter(
        A.id.in_(wanted)).order_by(A.timestamp).all()
    return [{"id": str(r[0]), "timestamp": r[1].isoformat() + "Z" if r[1] else None, "action": r[2],
             "account": r[3], "resource": " ".join(x for x in (r[4], r[5]) if x)} for r in rows]


def current_view(db):
    """The verified view and the head record with every seal written since this process last read the chain,
    read under the chain lock (a short wait): what another process wrote meanwhile (the host's commands, a pass
    run by hand) is shown at once, not after the pruner's next pass. Busy, stopped or failing: the view as this
    process holds it (its reader trusts it only while it is read through, ChainState.view_read)."""
    ai = audit_integrity
    st = ai.state()
    try:
        with ai.ChainWriter(db.get_bind(), st, wait=2.0, writer="admin") as w:
            return w.st.view, w.record
    except Exception:  # noqa: BLE001 -- the view as it stands; the acknowledgment checks again under the lock
        return st.view, st.known_record()


@router.get("/settings/audit-integrity/warnings")
def get_warnings(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """The warnings an administrator may acknowledge, with what each is. ``read`` false (and no warning listed)
    while this process has not read the chain through, or a check cleared its view while they were read: which seals
    wait is then not known."""
    st = audit_integrity.state()
    _view, record = current_view(db)
    try:
        out = st.trusted(lambda view: _warnings(db, view, record))
    except audit_integrity.ViewUnread:
        return {"warnings": [], "read": False, "archive": audit_archive.summary()}
    return {"warnings": out, "read": True, "archive": audit_archive.summary()}


def _warnings(db, view, record) -> list:
    found = admin_warnings(view, record)
    out = []
    for seq in found["late"]:
        try:
            seal = audit_integrity.read_authenticated(db, view, seq)
        except audit_integrity.ChainStopped:
            continue          # a seal changed after it was accepted: the status shows that failure
        d = seal.detail if isinstance(seal.detail, dict) else {}
        added = [str(a) for a in d.get("added") or []]
        out.append({"seq": seq, "kind": "late", "hour": d.get("hour"), "sealed_at": fmt.time_text(seal.sealed_at),
                    "added": len(added), "rows": _rows(db, added)})
    for seq in found["veto"]:
        try:
            seal = audit_integrity.read_authenticated(db, view, seq)
        except audit_integrity.ChainStopped:
            continue
        d = seal.detail if isinstance(seal.detail, dict) else {}
        if seal.kind == "cancel":
            what = f"a waiting change (request seal {d.get('cancels')}) the database no longer shows was ended"
        else:
            changed = [f"{name} = {e.get('value')!r}" for name, e in sorted((d.get("state") or {}).items())
                       if e.get("set_by") == seq]
            what = "kept longer, as the database holds: " + ", ".join(changed)
        out.append({"seq": seq, "kind": "veto-from-database", "sealed_at": fmt.time_text(seal.sealed_at),
                    "what": what})
    return out


class AcknowledgeBody(BaseModel):
    seqs: List[int] = Field(..., min_length=1, max_length=200)


@router.post("/settings/audit-integrity/acknowledge")
def acknowledge_warnings(body: AcknowledgeBody, request: Request,
                         current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Acknowledge late seals and seals written from the database's values, once seen: an ``ack`` seal by this
    administrator, with its audit row in the same transaction."""
    _step_up(db, current_user, request)
    db.commit()
    seqs = sorted(set(body.seqs))
    ai = audit_integrity
    try:
        with ai.ChainWriter(db.get_bind(), wait=5.0, writer="admin") as w:
            found = admin_warnings(w.st.view, w.record)
            allowed = set(found["late"]) | set(found["veto"])
            unknown = [s for s in seqs if s not in allowed]
            if unknown:
                raise HTTPException(status_code=409, detail=(
                    "Not a warning an administrator can acknowledge (any more): seals "
                    + ", ".join(map(str, unknown)) + ". Failures, and seals another writer appended, are the host "
                    "operator's: dockvault.py audit acknowledge."))
            from app.services.audit_logger import AuditLogger
            row = AuditLogger(w.db).build_row(action=ACKNOWLEDGED_ACTION, status="success", user=current_user,
                                              resource_type="audit_log", details={"acknowledges": seqs})
            w.db.add(row)
            w.append("ack", detail={"acknowledges": seqs, "failures": [], "rows": [], "discarded": [],
                                    "by": "admin", "user_id": str(current_user.id), "request": str(row.id)})
    except ai.ChainBusy:
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except ai.ChainStopped as stop:
        raise HTTPException(status_code=409, detail=f"The audit log's integrity chain is not sealing just now "
                                                    f"({stop.kind}); nothing was acknowledged.")
    return {"acknowledged": seqs}
