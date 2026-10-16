"""Running a per-person erase: the pruner's ``person_erase`` job (app/core/retention.py; the request side is
app/core/person_erase.py).

An erase is due when its ``request`` seal is pending and its delay has run, timed as a setting's request is (the
gaps in sealing move it on, and a request another writer appended waits for the host's acknowledgment). The job is
held by the hold switch, and nothing runs while a restore is not finished or its grace runs. Before it changes
anything it takes the name from erase_requests, only once the token opens under ENCRYPTION_KEY and gives the
``subject`` the request seal carries (so nobody, a holder of ENCRYPTION_KEY included, can swap the name of a
waiting erase), and it writes the placeholder the seal names, never erase_requests' copy (a copy that differs is
``unjustified-input``, and nothing is erased). A request whose row the database no longer shows waiting (removed,
cancelled, its token gone) is ended by a ``cancel`` seal ``by: database``: a veto, which the host acknowledges like
the others.

It waits, and says why on the request, while an account, a temporary credential or a waiting invitation has the
name, while a rule registered with person_erase.register_wait says so (legal holds and open cases), and, with
ERASE_BLOCKED_BY_PROTECTED_MINIMUM=true, before it begins, while any audit row it would change is younger than the
protected minimum for its kind.

The rows of the name are those whose username is exactly the name, and those of a name typed at a failed sign-in
recorded at the fingerprint level (no username, and the name's fingerprint under the key in use in ``recorded``).

The run covers the hours sealed when it begins (``through``, the same in every seal of the run), one unit per
transaction:

- an archived day: the blocks are first read, a day per transaction and nothing written, to find the days that
  hold the name (a day whose ``archive`` seal changes is read again); then each part holding a row of the name is
  written anew, the changed hours' nonces materialised and their salts dropped, and checked as stored; one
  ``erase`` seal per changed hour, then the day's ``archive`` seal of cause ``rewrite`` after the last of them;
- an hour of rows: its rows checked against its seal first (an hour that does not check out is reported and left
  as it is), its nonces materialised and its salt deleted, the rows changed, one ``erase`` seal.

Each changed row: the username becomes the placeholder; the address, the browser description, the temporary
credential's name, ``recorded`` and the error text (but an exception's type) are cleared; the endpoint is kept only
when it is one of the app's route templates; ``details`` keep only the keys the recording levels classify as always
recorded, counts and exception types, and nothing whose value holds the name; the nonce becomes sixteen 00 bytes.
The seal lists [id, c_prev, c_next] of each row, and the hour's roots, which do not change, prove that nothing
else did. Rows with no time are not reached (no hour holds them).

The last unit's transaction carries ``final: true``: it also gives the placeholder to every other store
(person_erase.STORES), deletes the sealed name, marks the row completed with its counts, and writes the
``person_erased`` audit row (the placeholder and the counts, never the name). Then a plain VACUUM of the tables it
changes, within a time budget, so the old values leave the live tables' pages sooner (backups keep them). An erase that finds no row writes
one ``erase`` seal with no hour; so does a run whose remaining rows went meanwhile (pruned).

Each unit and the final stores are changed only after person_erase.rule_waits has said nothing holds erases back:
the interface legal holds and open cases register with.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from app.core import audit_chain_format as fmt
from app.core import person_erase as pe

HOUR = timedelta(hours=1)
WAIT, STOP, DONE, SCANNED, ERASED = "wait", "stop", "done", "scanned", "erased"
_TYPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,99}")


def _ai():
    from app.core import audit_integrity
    return audit_integrity


# --------------------------------------------------------------------------- what an erased row keeps

def route_templates() -> frozenset:
    """The route templates of the running web app (an endpoint an erased row may keep), or none outside it."""
    module = sys.modules.get("app.api.api_server")
    app = getattr(module, "app", None) if module is not None else None
    if app is None:
        return frozenset()
    return frozenset(getattr(r, "path", None) for r in getattr(app, "routes", []) if getattr(r, "path", None))


def holds(value, name: str) -> bool:
    """Whether ``value`` (decoded JSON, or a text) is ``name`` or holds it (a name of one character only whole)."""
    if isinstance(value, str):
        return value == name or (len(name) >= 2 and name in value)
    if isinstance(value, list):
        return any(holds(v, name) for v in value)
    if isinstance(value, dict):
        return any(holds(k, name) or holds(v, name) for k, v in value.items())
    return False


def scrub_details(value, name: str, prefix: str = ""):
    """What an erased row keeps of its details: the keys classified as always recorded (identifiers), counts and
    exception types, and nested sets of keys classified the same way; nothing whose key or value holds the name,
    nothing of a personal kind, a secret or a key nothing classifies. None when nothing is left."""
    from app.core import audit_privacy as ap
    if not isinstance(value, dict):
        return None
    out = {}
    for key, v in value.items():
        path = prefix + str(key)
        if holds(key, name):
            continue
        kind = ap.kind_of(path)
        if kind == ap.NESTED and isinstance(v, dict):
            inner = scrub_details(v, name, path + ".")
            if inner:
                out[key] = inner
        elif holds(v, name):
            continue
        elif kind == ap.IDENTIFIER:
            out[key] = v
        elif kind == ap.COUNT and isinstance(v, int) and not isinstance(v, bool):
            out[key] = v
        elif kind == ap.ERROR and isinstance(v, str) and _TYPE_NAME.fullmatch(v):
            out[key] = v
    return out or None


def erased_values(row: dict, name: str, placeholder: str, templates: frozenset) -> dict:
    """The committed columns of an erased row. ``row`` is as read (JSON columns as their stored text); so are the
    values returned."""
    endpoint = row.get("endpoint")
    if not (isinstance(endpoint, str) and endpoint in templates and not holds(endpoint, name)):
        endpoint = None
    error = row.get("error_message")
    if not (isinstance(error, str) and _TYPE_NAME.fullmatch(error) and not holds(error, name)):
        error = None
    details = None
    if row.get("details") is not None:
        try:
            details = scrub_details(json.loads(row["details"]), name)
        except (TypeError, ValueError):
            details = None
    return {"username": placeholder, "ip_address": None, "user_agent": None, "endpoint": endpoint,
            "temp_credential_name": None, "error_message": error, "recorded": None,
            "details": json.dumps(details) if details is not None else None}


# --------------------------------------------------------------------------- when an erase is due

def due(view, record: Optional[dict], now: datetime) -> List[int]:
    """The pending erase requests whose delay has run, oldest first, timed as a setting's request is
    (audit_chain_policy_seals.due_requests); one that has begun goes on. Nothing while a gap is open."""
    from app.core import audit_chain_honour as honour
    from app.core import audit_chain_times as times
    out = []
    if not view.position:
        return out
    if any(tl.open_gap(times.us(now)) for tl in times.timelines(view, record)):
        return out
    foreign = _ai().foreign_entries(view, record)
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "erase":
            continue
        if seq in view.erase_through:
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


# --------------------------------------------------------------------------- the database's counterpart

class InputProblem(Exception):
    pass


def name_of(db, cfg, view, seq: int):
    """(row, name) for the erase request ``seq``: the token opened and checked against the request seal's subject,
    the placeholder copy compared with the seal's. (row, None) when the database holds it back (no row, a row
    ended, no token): a veto. Raises InputProblem (unjustified-input) for a row that contradicts the seal."""
    from app.core.models import EraseRequest
    d = view.requests[seq]
    try:
        rid = fmt.as_uuid(d.get("request"))
    except (TypeError, ValueError):
        raise InputProblem(f"erase request seal {seq} names no request") from None
    row = db.get(EraseRequest, rid)
    if row is None or row.status in (pe.CANCELLED, pe.COMPLETED) or not row.name_token:
        return row, None
    if row.placeholder != d.get("placeholder"):
        raise InputProblem(f"erase_requests holds another placeholder for the erase of request seal {seq}; it is not "
                           "acted on")
    try:
        r, name = pe.open_name(cfg, rid, row.name_token)
    except ValueError:
        raise InputProblem(f"the name of the erase of request seal {seq} does not open; it is not acted on") from None
    if pe.subject_of(rid, r, name).hex() != d.get("subject") or pe.name_problem(name):
        raise InputProblem(f"the name of the erase of request seal {seq} is not the one its request seal commits to; "
                           "it is not acted on")
    return row, name


def pending_input_problems(db, view, cfg) -> List[str]:
    """Each pending erase whose row contradicts its request seal (verify step 4, on the server: it holds
    ENCRYPTION_KEY), and each erase_requests row still waiting that the chain holds no request of."""
    from app.core.models import EraseRequest
    out = []
    held = {str(d.get("request")) for d in view.requests.values() if d.get("what") == "erase"}
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "erase":
            continue
        try:
            name_of(db, cfg, view, seq)
        except InputProblem as exc:
            out.append(str(exc))
    for row in db.query(EraseRequest).filter(EraseRequest.status.in_((pe.PENDING, pe.RUNNING))).all():
        if str(row.id) not in held:
            out.append("an erase waiting in the database has no request seal; it is ignored")
    return out


# --------------------------------------------------------------------------- finding the rows of the name

def _hot_rows(db, name: str, fp: Optional[str], scope_end: datetime):
    """(id, time, action) of the rows of ``name`` before ``scope_end`` (with a time), as row_matches decides."""
    from app.core.models import AuditLog as A
    found = db.query(A.id, A.timestamp, A.action, A.username, A.recorded).filter(
        pe.audit_matches(A, name, fp), A.timestamp.isnot(None), A.timestamp < scope_end).all()
    return [(i, t, a) for i, t, a, u, r in found if pe.row_matches({"username": u, "recorded": r}, name, fp)]


def hot_hours(db, view, name: str, scope_end: datetime, fp: Optional[str] = None) -> List[datetime]:
    """The sealed hours before ``scope_end`` that hold rows of ``name`` as rows (not archived), oldest first."""
    ai = _ai()
    out = set()
    for _i, t, _a in _hot_rows(db, name, fp, scope_end):
        h = ai.hour_floor(t)
        if view.entry_for(h) is None or view.archived_part(h) is not None:
            continue
        out.add(h)
    return sorted(out)


def _hot_newest(db, name: str, fp: Optional[str], scope_end: datetime, protected: frozenset) -> tuple:
    rows = _hot_rows(db, name, fp, scope_end)
    newest = max((t for _i, t, _a in rows), default=None)
    newest_p = max((t for _i, t, a in rows if a in protected), default=None)
    return newest, newest_p


def scan_day(w, day, name: str, fp: Optional[str] = None) -> tuple:
    """(rows of ``name``, newest of them, newest protected one) in ``day``'s blocks, each part read and checked.
    Raises NotVerified."""
    from app.core import audit_archive as arc
    ai = _ai()
    db, view = w.db, w.st.view
    entry = view.archives.get(day)
    count, newest, newest_p = 0, None, None
    if entry is None:
        return count, newest, newest_p
    arc._check_day_blocks(db, entry, day)
    protected = ai.protected_names()
    for part in sorted(entry.parts, key=lambda p: p.first_hour):
        reader = arc.PartReader(db, view, day, part)
        for row in reader.rows():
            if pe.row_matches(row, name, fp) and row["id"] not in view.erased_rows:
                count += 1
                t = row["timestamp"]
                newest = t if newest is None or t > newest else newest
                if row.get("action") in protected:
                    newest_p = t if newest_p is None or t > newest_p else newest_p
        reader.finish()
    return count, newest, newest_p


# --------------------------------------------------------------------------- one unit

class NotErased(Exception):
    """A unit that cannot be erased now: ``kind`` is a finding (reported), or None (it waits)."""

    def __init__(self, message: str, kind: Optional[str] = None):
        super().__init__(message)
        self.kind = kind


def _detail(hour: Optional[datetime], seq: int, d: dict, policy_seq: int, through: str, final: bool, rows: list,
            nbytes: int) -> dict:
    return {"hour": fmt.hour_text(hour) if hour is not None else None, "request_seq": seq,
            "request_id": d.get("request"), "placeholder": d.get("placeholder"), "policy_seq": policy_seq,
            "bytes_now": int(nbytes), "through": through, "final": bool(final), "rows": rows}


def erase_hour(w, seq: int, d: dict, name: str, hour: datetime, *, policy_seq: int, through: str,
               final: bool, templates: frozenset, fp: Optional[str] = None) -> int:
    """Erase the rows of ``name`` in the sealed ``hour`` in ``w``'s transaction, with its erase seal. Returns how
    many rows it changed. Raises NotErased."""
    from sqlalchemy import null
    from app.core import audit_chain_prune as prune_mod
    from app.core.models import AuditLog as A
    ai = _ai()
    db, view = w.db, w.st.view
    held = ai.hour_held(view, w.record, hour)
    if held is not None:
        raise NotErased(f"{fmt.hour_text(hour)}'s seal {held} was appended by another writer and waits for the host "
                        "operator")
    try:
        root, wr, salt, c_prev_old = prune_mod._verify_hour(w, hour)
    except prune_mod.HourNotVerified:
        raise NotErased(f"the rows of {fmt.hour_text(hour)} no longer give its seal; nothing in it was erased",
                        "rows-altered") from None
    rows = [r for r in ai.iter_rows(db, hour, hour + HOUR) if pe.row_matches(r, name, fp)]
    if not rows or any(r["id"] in view.erased_rows for r in rows):
        raise NotErased(f"rows of {fmt.hour_text(hour)} that hold the name are listed as erased already",
                        "unjustified")
    prune_mod._materialise(w, hour, salt, wr)
    db.flush()
    c_prev = {}
    for r in ai.iter_rows(db, hour, hour + HOUR):
        if not pe.row_matches(r, name, fp):
            continue
        c_prev[r["id"]] = fmt.commitment(r["seal_nonce"], r)
        new = erased_values(r, name, d["placeholder"], templates)
        db.query(A).filter(A.id == r["id"]).update({
            A.username: new["username"], A.ip_address: None, A.user_agent: None, A.endpoint: new["endpoint"],
            A.temp_credential_name: None, A.error_message: new["error_message"], A.recorded: null(),
            A.details: json.loads(new["details"]) if new["details"] is not None else null(),
            A.seal_nonce: fmt.ZERO_NONCE}, synchronize_session=False)
    db.flush()
    entries = []
    for r in ai.iter_rows(db, hour, hour + HOUR):
        if r["id"] in c_prev:
            if r["username"] != d["placeholder"] or r["seal_nonce"] != fmt.ZERO_NONCE:
                raise NotErased(f"a row of {fmt.hour_text(hour)} did not take its erased values", "unjustified")
            entries.append([str(r["id"]), c_prev[r["id"]].hex(), fmt.commitment(fmt.ZERO_NONCE, r).hex()])
    fig = ai.hour_figures(ai.iter_rows(db, hour, hour + HOUR), None, {**c_prev_old, **c_prev})
    if (fig.count, fig.root_s, fig.root_c, fig.ids_digest) != (root.count, root.root_s, root.root_c,
                                                               root.ids_digest) or fig.missing_nonce:
        raise NotErased(f"the erased rows of {fmt.hour_text(hour)} would not give its seal; nothing was erased",
                        "rows-altered")
    w.append("erase", detail=_detail(hour, seq, d, policy_seq, through, final, entries, fig.bytes))
    return len(entries)


def erase_day(w, seq: int, d: dict, name: str, day, *, policy_seq: int, through: str, final: bool,
              templates: frozenset, now: datetime, fp: Optional[str] = None) -> int:
    """Erase the rows of ``name`` in ``day``'s blocks in ``w``'s transaction: each part holding one written anew,
    streamed and checked as stored; an erase seal per changed hour, then the day's archive seal of cause rewrite.
    Returns how many rows it changed (0: none there, nothing written). Raises NotErased."""
    from app.core import audit_archive as arc
    from app.core import audit_archive_format as af
    from app.core.models import AuditArchiveBlock as B
    ai = _ai()
    db, view = w.db, w.st.view
    entry = view.archives.get(day)
    if entry is None or not entry.parts:
        return 0
    placeholder = d["placeholder"]
    try:
        arc._check_day_blocks(db, entry, day)
        picked = {}
        for part in sorted(entry.parts, key=lambda p: p.first_hour):
            reader = arc.PartReader(db, view, day, part)
            touched = {r["id"]: r["timestamp"] for r in reader.rows()
                       if pe.row_matches(r, name, fp) and r["id"] not in view.erased_rows}
            reader.finish()
            if touched:
                picked[part.part] = touched
        for touched in picked.values():
            for h in sorted({ai.hour_floor(t) for t in touched.values()}):
                held = ai.hour_held(view, w.record, h)
                if held is not None:
                    raise NotErased(f"{fmt.hour_text(h)}'s seal {held} was appended by another writer and waits for "
                                    "the host operator")
        new_parts = []
        by_hour: Dict[datetime, list] = {}
        figs: Dict[datetime, object] = {}
        for part in sorted(entry.parts, key=lambda p: p.first_hour):
            touched = picked.get(part.part)
            if not touched:
                new_parts.append(part)
                continue
            changed = sorted({ai.hour_floor(t) for t in touched.values()})
            again = arc.PartReader(db, view, day, part)
            salts = again.salts
            c_prev = {h: dict(again.c_prev.get(h) or {}) for h in again.hours}
            erased = {h: dict(again.erased.get(h) or {}) for h in again.hours}
            bw = af.BlockWriter(day, part.part, {h: s for h, s in salts.items() if h not in changed})
            builders = {h: ai.FiguresBuilder(None, c_prev[h]) for h in changed}
            for row in again.rows():
                h = ai.hour_floor(row["timestamp"])
                if h in builders and row.get("seal_nonce") is None and h in salts:
                    row = dict(row, seal_nonce=fmt.legacy_nonce(salts[h], row["id"]))
                if row["id"] in touched:
                    cp = fmt.commitment(row["seal_nonce"], row)
                    row = dict(row)
                    row.update(erased_values(row, name, placeholder, templates))
                    row["seal_nonce"] = fmt.ZERO_NONCE
                    cn = fmt.commitment(fmt.ZERO_NONCE, row)
                    c_prev[h][row["id"]] = cp
                    erased[h][row["id"]] = (cn, placeholder)
                    by_hour.setdefault(h, []).append([str(row["id"]), cp.hex(), cn.hex()])
                if h in builders:
                    builders[h].add(row)
                bw.add(row)
            again.finish()
            for h in changed:
                figs[h] = builders[h].result()
            payload = bw.finish()
            new = arc.ArchivePart(part.part, part.first_hour, part.last_hour, bw.rows, len(payload),
                                  af.digest(payload))
            db.query(B).filter(B.day == day, B.part == part.part).update(
                {B.payload: payload, B.row_count: bw.rows, B.raw_bytes: bw.raw_bytes, B.aggregates: bw.aggregates,
                 B.rewritten_at: now}, synchronize_session=False)
            db.flush()
            arc._check_stored(db, view, day, new, bw, c_prev=c_prev, erased=erased)
            new_parts.append(new)
    except arc.NotVerified as nv:
        if nv.kind == arc.LATER_FORMAT:
            raise NotErased(f"{day.isoformat()} is archived in a later release's block format, which this release does "
                            "not change") from None
        raise NotErased(f"{nv}; nothing in {day.isoformat()} was erased", nv.kind) from None
    except arc.NotArchivable as why:
        raise NotErased(str(why)) from None
    if not by_hour:
        return 0
    hours = sorted(by_hour)
    last = None
    for h in hours:
        root = arc._root(db, view, h)
        f = figs[h]
        if root is None or (f.count, f.root_s, f.root_c, f.ids_digest) != (root.count, root.root_s, root.root_c,
                                                                           root.ids_digest):
            raise NotErased(f"the erased rows of {fmt.hour_text(h)} would not give its seal; nothing was erased",
                            "rows-altered")
        last = w.append("erase", detail=_detail(h, seq, d, policy_seq, through, final and h == hours[-1],
                                                by_hour[h], f.bytes))
    arc.seal_rewrite(w, day, last.seq, arc.Rewritten(parts=new_parts), now)
    return sum(len(v) for v in by_hour.values())


# --------------------------------------------------------------------------- the end of a run

def finish(w, row, seq: int, d: dict, name: str, now: datetime, fp: Optional[str] = None) -> dict:
    """In the final unit's transaction: every other store, the row completed, the sealed name deleted, and the
    person_erased audit row. Returns what the notice says (never the name)."""
    from app.services.audit_logger import AuditLogger
    db = w.db
    placeholder = d["placeholder"]
    counts = {}
    for store in pe.STORES:
        counts[store.key] = int(store.erase(db, name, placeholder, (fp,) if fp else (), now) or 0)
    audit_rows = int((row.counts or {}).get("audit_rows", 0)) if row is not None else 0
    if row is not None:
        row.status = pe.COMPLETED
        row.completed_at = now
        row.name_token = None
        row.waiting = None
        row.counts = {"audit_rows": audit_rows, "stores": counts}
    db.add(AuditLogger(db).build_row(
        action="person_erased", status="success", resource_type=pe.RESOURCE_TYPE, resource_id=d.get("request"),
        details={"request_id": d.get("request"), "placeholder": placeholder, "rows": audit_rows, "stores": counts}))
    return {"placeholder": placeholder, "audit_rows": audit_rows, "other_rows": sum(counts.values())}


def _progress(row, through: str, now: datetime, changed: int) -> None:
    """The row's copies as the run goes: running from its first seal, with the scope and the rows changed so far."""
    if row is None:
        return
    if row.status == pe.PENDING:
        row.status = pe.RUNNING
        row.started_at = now
        row.through = fmt.parse_time_text(through)
    counts = dict(row.counts or {})
    counts["audit_rows"] = int(counts.get("audit_rows", 0)) + int(changed)
    row.counts = counts
    row.waiting = None


# --------------------------------------------------------------------------- the job

def step(p, w, seq: int, findings: Dict[str, str], tried: set) -> tuple:
    """One transaction of the erase of request ``seq``: (outcome, rows changed, the notice's details when it
    completed, the reason it waits). Writes nothing unless it returns ERASED (or DONE after a veto)."""
    from app.core import audit_archive as arc
    from app.core import audit_chain_policy_seals as ps
    from app.core import audit_retention as ar
    ai = _ai()
    st, db = w.st, w.db
    view = st.view
    now = p.now
    if seq not in view.pending_requests():
        return DONE, 0, None, None
    if st.holds_deletion():
        return STOP, 0, None, None
    d = view.requests[seq]
    try:
        row, name = name_of(db, st.cfg(), view, seq)
    except InputProblem as exc:
        findings["unjustified-input"] = str(exc)
        return STOP, 0, None, None
    if name is None:
        # The database holds it back (removed, ended, or its name gone): a veto, sealed as a cancel by the database
        # (at most once a day, as every veto), which the host acknowledges.
        if ps._veto_allowed_today(view, now):
            w.append("cancel", detail={"cancels": seq, "request": d.get("request"), "audit_row": None,
                                       "by": "database", "user_id": None})
            if row is not None and row.status != pe.COMPLETED:
                row.status = pe.CANCELLED
                row.name_token = None
        return DONE, 0, None, None
    why = pe.holder(db, name, now) or pe.rule_waits(db, now)
    if why:
        return WAIT, 0, None, f"It waits: {why}."
    chain = ar.chain_numbers()
    if chain is None:
        return STOP, 0, None, None
    numbers, _delay, hold = chain
    if hold:
        return WAIT, 0, None, "It waits while the hold switch is on."
    if view.newest_hour_end is None:
        return STOP, 0, None, None
    started = seq in view.erase_through
    fp = pe.signin_fingerprint(name, st.cfg())
    through = view.erase_through.get(seq) or fmt.hour_text(view.newest_hour_end - HOUR)
    scope_end = fmt.parse_time_text(through) + HOUR
    # The archived days are read first, a day per transaction, nothing written.
    days = [day for day, e in sorted(view.archives.items()) if e.parts and arc.day_start(day) < scope_end]
    for day in days:
        key = (seq, day)
        scan = st.erase_scans.get(key)
        if scan is None or scan[0] != view.archives[day].seq:
            try:
                st.erase_scans[key] = (view.archives[day].seq,) + scan_day(w, day, name, fp)
            except arc.NotVerified as nv:
                if nv.kind == arc.LATER_FORMAT:
                    return WAIT, 0, None, (f"It waits: {day.isoformat()} is archived in a later release's block "
                                           "format, which this release does not change.")
                findings[nv.kind] = f"{nv}; the erase of request seal {seq} waits"
                return STOP, 0, None, None
            return SCANNED, 0, None, None
    with_rows = [day for day in days if st.erase_scans[(seq, day)][1]]
    hours = hot_hours(db, view, name, scope_end, fp)
    if not started and pe.protected_minimum():
        newest, newest_p = _hot_newest(db, name, fp, scope_end, ai.protected_names())
        for day in with_rows:
            _s, _n, t, tp = st.erase_scans[(seq, day)]
            newest = max([x for x in (newest, t) if x is not None], default=None)
            newest_p = max([x for x in (newest_p, tp) if x is not None], default=None)
        if (numbers.min_days > 0 and newest is not None and newest > now - timedelta(days=numbers.min_days)) or (
                numbers.admin_min_days > 0 and newest_p is not None
                and newest_p > now - timedelta(days=numbers.admin_min_days)):
            return WAIT, 0, None, ("It waits until the rows it would change are older than the protected minimum "
                                   "(ERASE_BLOCKED_BY_PROTECTED_MINIMUM).")
    units = [("day", day) for day in with_rows] + [("hour", h) for h in hours]
    policy_seq = view.newest_policy()[0]
    changed = 0
    if not units:
        w.append("erase", detail=_detail(None, seq, d, policy_seq, through, True, [], 0))
    else:
        kind, unit = units[0]
        if (kind, unit) in tried:
            findings["unjustified"] = (f"the erase of request seal {seq} found nothing to change where it found the "
                                       f"name ({unit}); it waits")
            return STOP, 0, None, None
        tried.add((kind, unit))
        final = len(units) == 1
        templates = route_templates()
        try:
            if kind == "hour":
                changed = erase_hour(w, seq, d, name, unit, policy_seq=policy_seq, through=through, final=final,
                                     templates=templates, fp=fp)
            else:
                changed = erase_day(w, seq, d, name, unit, policy_seq=policy_seq, through=through, final=final,
                                    templates=templates, now=now, fp=fp)
        except NotErased as ne:
            if ne.kind:
                findings[ne.kind] = str(ne)
                return STOP, 0, None, None
            return WAIT, 0, None, f"It waits: {ne}."
        if not changed:
            # Nothing of the name was left in that archived day: it is read again.
            st.erase_scans.pop((seq, unit), None)
            return SCANNED, 0, None, None
        _progress(row, through, now, changed)
        if not final:
            return ERASED, changed, None, None
    _progress(row, through, now, 0)
    return ERASED, changed, finish(w, row, seq, d, name, now, fp), None


def _note_waiting(session_factory, request_id, why: Optional[str]) -> None:
    """Say on the request why it waits (a transaction of its own: a wait writes nothing in the chain's)."""
    from app.core.models import EraseRequest
    db = session_factory()
    try:
        row = db.get(EraseRequest, fmt.as_uuid(request_id))
        if row is not None and row.status in (pe.PENDING, pe.RUNNING) and row.waiting != (why or None):
            row.waiting = why[:255] if why else None
            db.commit()
    except Exception:  # noqa: BLE001 -- the next pass says it again
        db.rollback()
    finally:
        db.close()


def run_job(p):
    """The pruner's person_erase job. Returns a retention.JobResult (what it changed, as cleared)."""
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
        tried: set = set()
        while p.time_left():
            outcome, changed, done, why = STOP, 0, None, None
            with ai.ChainWriter(engine, st) as w:
                outcome, changed, done, why = step(p, w, seq, findings, tried)
                if outcome not in (ERASED, DONE) and w.written:
                    # Only an erase or a veto commits: anything else leaves the transaction as it found it.
                    w.written = []
                    w.db.rollback()
            result.cleared += changed
            if outcome == WAIT:
                _note_waiting(p.session_factory, st.view.requests[seq].get("request"), why)
                break
            if outcome == ERASED and done is None:
                continue
            if outcome == SCANNED:
                continue
            if done is not None:
                finished.append(done)
            break
        if seq not in st.view.pending_requests():
            for key in [k for k in st.erase_scans if k[0] == seq]:
                del st.erase_scans[key]
    if findings:
        ai.report_failures(st, p.session_factory, findings)
    for done in finished:
        result.cleared += done["other_rows"]
        pe.tell_administrators("completed", done)
    if finished:
        vacuum(engine)
    return result


def vetoed(st, session_factory) -> List[int]:
    """The pending erases not begun whose row the database no longer shows waiting (removed, ended, its name gone):
    each is ended by a cancel seal from the database without waiting for its delay."""
    from app.core.models import EraseRequest
    out = []
    pending = {seq: d for seq, d in st.view.pending_requests().items()
               if d.get("what") == "erase" and seq not in st.view.erase_through}
    if not pending:
        return out
    db = session_factory()
    try:
        for seq, d in sorted(pending.items()):
            try:
                row = db.get(EraseRequest, fmt.as_uuid(d.get("request")))
            except (TypeError, ValueError):
                row = None
            if row is None or row.status in (pe.CANCELLED, pe.COMPLETED) or not row.name_token:
                out.append(seq)
    finally:
        db.close()
    return out


# The small tables first: audit_seals holds the erase's earlier commitments' neighbours, the stores the name.
VACUUM_TABLES = ("audit_seals",) + tuple(s.key for s in pe.STORES) + ("audit_archive_blocks", "audit_logs")
# How long the VACUUMs after an erase may take together, so they never hold the pruner long.
VACUUM_BUDGET_SECONDS = 300.0


def vacuum(engine, budget: float = VACUUM_BUDGET_SECONDS) -> List[str]:
    """A plain VACUUM of the tables an erase changes (Postgres; elsewhere nothing), within ``budget`` seconds in
    all: the space of the old values is marked for reuse sooner. Returns the tables vacuumed. Never raises:
    autovacuum follows anyway."""
    import time
    from sqlalchemy import text
    done: List[str] = []
    if engine is None or engine.dialect.name != "postgresql":
        return done
    deadline = time.monotonic() + budget
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            for table in VACUUM_TABLES:
                left = deadline - time.monotonic()
                if left <= 1:
                    _ai()._say("Warning: the VACUUM after an erase stopped at its time budget; autovacuum follows")
                    break
                try:
                    conn.execute(text(f"SET statement_timeout = {int(left * 1000)}"))
                    conn.execute(text(f"VACUUM {table}"))
                    done.append(table)
                except Exception as exc:  # noqa: BLE001
                    _ai()._say(f"Warning: VACUUM {table} after an erase did not run ({type(exc).__name__})")
    except Exception as exc:  # noqa: BLE001
        _ai()._say(f"Warning: the tables were not vacuumed after an erase ({type(exc).__name__})")
    return done
