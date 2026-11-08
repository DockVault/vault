"""The changes waiting before they apply, as the audit log's integrity chain holds them: the retention screen's list.

What the screen lists comes from this process's verified view and its head record (app/core/audit_chain_view.py,
app/core/audit_integrity.py), never from the database's rows:

- every ``request`` seal of a setting that no ``cancel`` seal names and no later seal supersedes, with the values
  it sealed (the value in force when it was asked for, and the setting asked for, resolved as the pruner will
  apply it), when it was sealed and by whom, and the date it applies: its effective ``not_before``, which every
  gap in sealing moves on. A request another writer appended after the head record waits, besides, for the host's
  acknowledgment (``dockvault.py audit acknowledge``), and is marked so;
- every request another writer's ``applies`` seal applied whose value does not count yet: it is shown as applied
  by that seal, which waits for the host, with the date its value counts from (or its due date while the host has
  not acknowledged it). It can no longer be cancelled; the way back is a change back to the value in force.

The pruner acts on the same view, so the list shows what it will do. A row of ``managed_setting_changes`` can
neither add an entry, nor hide one, nor change what an entry says or when it applies. The table is read only to
say, beside an entry, that the database no longer shows it waiting: a cancel saved while sealing was stopped (the
chain records it at its next pass), or an edit; while the database says so the change does not apply, and an
administrator may cancel it on the screen to record the cancel in the chain now. While sealing is stopped such an
entry cannot be cancelled (a cancel then is saved on the row, which already does not show it waiting): its end
is recorded once sealing runs again.

A cancel is addressed to the request the chain holds (``held``): a change the chain holds no waiting request of
is refused, whatever the table says.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from app.core import settings_registry as registry

# What an entry's ``status`` says: waiting, or applied by another writer's seal whose value does not count yet.
WAITING = "pending"
APPLIED_WAITING = "applied-waiting-for-host"


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _iso(t: Optional[datetime]) -> Optional[str]:
    return t.isoformat() + "Z" if t is not None else None


def _uuid(text) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(text))
    except (TypeError, ValueError):
        return None


def held(view, change_id) -> Optional[int]:
    """The seq of the waiting ``request`` seal of change ``change_id`` the chain holds, or None."""
    from app.core import audit_chain_policy_seals as ps
    req = ps.request_seq_for(view, change_id)
    if req is None or req not in view.pending_requests():
        return None
    return req


def ended_as(view, req: int) -> str:
    """How request ``req``, no longer waiting, ended in the chain: cancelled, applied, completed or superseded."""
    if req in view.cancels:
        return "cancelled"
    if req in view.applied:
        return "applied"
    if req in view.finals:
        return "completed"
    return "superseded"


def _names(db, details: List[dict]) -> Dict[str, str]:
    """The usernames of the accounts the seals name, by account id (the seal holds the id; the name is shown)."""
    from app.core.models import User
    ids = {u for u in (_uuid(d.get("user_id")) for d in details if d.get("by") == "admin") if u is not None}
    if not ids or db is None:
        return {}
    return {str(u.id): u.username for u in db.query(User).filter(User.id.in_(ids)).all()}


def _who(d: dict, names: Dict[str, str]) -> str:
    from app.core import audit_chain_policy_seals as ps
    by = d.get("by")
    if by == "server":
        return ps.SERVER_NAME
    if by == "admin":
        return names.get(str(d.get("user_id"))) or "an administrator whose account no longer exists"
    return str(by or "an unnamed writer")


def _row_statuses(db, ids: List[str]) -> Dict[str, str]:
    from app.core.models import ManagedSettingChange as Change
    wanted = [u for u in (_uuid(i) for i in ids) if u is not None]
    if not wanted or db is None:
        return {}
    return {str(c.id): c.status for c in db.query(Change).filter(Change.id.in_(wanted)).all()}


def _resolved(view, d: dict, req: int):
    """What request ``d`` sets its setting to when it applies, as the pruner resolves it (the newest policy seal's
    bounds), or the sealed setting itself when the chain holds no policy seal or the registry no such setting."""
    from app.core import audit_chain_policy as pol
    from app.core import audit_chain_policy_seals as ps
    spec = registry.spec_for(d.get("setting") or "")
    newest = view.newest_policy()
    if spec is None or newest is None:
        return d.get("new")
    inputs = newest[1].get("inputs") or {}
    return ps.setting_fields(spec, d.get("new"), pol.settings_from_inputs(inputs), inputs, req)["value"]


def _entry(view, record, req: int, d: dict, now: datetime, names: Dict[str, str], foreign: dict) -> dict:
    from app.core import audit_chain_honour as honour
    key = d.get("setting") or ""
    spec = registry.spec_for(key)
    return {"id": str(d.get("request")), "request_seq": req, "key": key,
            "label": (spec.label if spec else "") or key, "setting": d.get("new"), "old": d.get("old"),
            "new": _resolved(view, d, req), "status": WAITING, "requested_by": _who(d, names),
            "requested_at": _iso(view.at(req)) if 1 <= req <= view.position else None,
            "effective_at": _iso(honour.effective_not_before(view, record, req, now)),
            "another_writer": req in foreign,
            "waits_for_host": req in foreign and honour.ack_time(view, record, req) is None,
            "applied_by": None, "counts_from": None, "cancellable": True, "database": None,
            "decided_by": None, "decided_at": None, "reason": None}


def entries(db, st=None, now: Optional[datetime] = None) -> List[dict]:
    """The changes waiting, oldest request first (the module's docstring says what each holds). None of them while
    this process has not read the chain through (ChainState.view_read): a view a check stopped in part way holds
    seals the head record's link has not verified, and chain_state() then says the list is not read."""
    return listed(db, st, now)[0]


def listed(db, st=None, now: Optional[datetime] = None) -> tuple:
    """(entries, chain_state) read together: the entries from a view read through and still read through once they
    are listed, else none and ``read`` false, so that the list and what is said of it never disagree."""
    ai = _ai()
    st = st or ai.state()
    try:
        out = st.trusted(lambda view: _entries(db, st, now))
    except ai.ViewUnread:
        return [], chain_state(st, read=False)
    return out, chain_state(st, read=True)


def _entries(db, st, now: Optional[datetime]) -> List[dict]:
    from app.core import audit_chain_honour as honour
    ai = _ai()
    view = st.view
    if not view.position:
        return []
    record = st.known_record()
    now = now or st.clock()
    foreign = ai.foreign_entries(view, record)
    waiting = [(req, d) for req, d in sorted(view.pending_requests().items()) if d.get("what") == "setting"]
    applied = []
    for req, by in sorted(view.applied.items()):
        d = view.requests.get(req)
        if d is None or d.get("what") != "setting" or by not in foreign:
            continue
        since = honour.counts_from(view, record, by, now)
        if since is None or since > now:
            applied.append((req, d, by, since))
    names = _names(db, [d for _r, d in waiting] + [d for _r, d, _b, _s in applied])
    out = [_entry(view, record, req, d, now, names, foreign) for req, d in waiting]
    for req, d, by, since in applied:
        e = _entry(view, record, req, d, now, names, foreign)
        e.update(status=APPLIED_WAITING, applied_by=by, cancellable=False,
                 effective_at=_iso(since if since is not None else honour.request_due(view, record, req, now)),
                 counts_from=_iso(since), waits_for_host=since is None)
        out.append(e)
    out.sort(key=lambda e: e["request_seq"])
    statuses = _row_statuses(db, [e["id"] for e in out if e["status"] == WAITING])
    stopped = st.stopped is not None
    for e in out:
        if e["status"] == WAITING:
            status = statuses.get(e["id"], "missing")
            e["database"] = None if status == WAITING else status
            if stopped and e["database"] is not None:
                # While sealing is stopped a cancel is saved on the change's row, which no longer shows it
                # waiting: the change already does not apply, and its end is sealed once sealing runs again.
                e["cancellable"] = False
    return out


def entry(db, view, record, req: int, now: datetime) -> dict:
    """The one entry of waiting request ``req`` (for a cancel's answer and its audit row)."""
    ai = _ai()
    d = view.requests[req]
    return _entry(view, record, req, d, now, _names(db, [d]), ai.foreign_entries(view, record))



def chain_state(st=None, *, read: Optional[bool] = None) -> dict:
    """Beside the list: whether this process has read the chain through (ChainState.view_read; before that, nothing
    is listed and nothing applies), and the kind of stop while sealing is stopped, or while the chain does not check
    out for a read (nothing applies until it does). ``read``: as listed() found it."""
    st = st or _ai().state()
    stopped = st.stopped.kind if st.stopped is not None else st.read_stopped
    return {"read": st.view_read if read is None else read, "stopped": stopped}
