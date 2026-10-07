"""What the server's operator does to the audit chain from the host (``dockvault.py audit``).

Every host command that writes a seal runs in two phases, because dockvault.py asks its questions on the host,
between two separate ``docker compose exec`` calls:

- the **read phase** (``--read``) builds its view of the chain, says what it would write, and prints the state
  it saw as a token (``dvstate1:...``): the head, the head record's generation and discard count, a digest of
  the key history, the seals listed after the head record, what the command acts on, and, for a command that
  seals over rows, a digest of those rows as it read them;
- the **write phase** (``--expect <token>``) takes the chain lock, builds the same state again (the rows read in
  one snapshot), and refuses, writing nothing, unless it is the state the operator saw. Someone with database
  access therefore cannot change the chain, or the rows, between what the operator saw and what the host
  writes over it.

Both record the host operator. The commands here:

    acknowledge --seqs 12,15           warnings about seals: late seals, seals written from the database's
                                       values, seals another writer appended after the head record (it first
                                       says what acknowledging each starts)
    acknowledge --failures             every failure, and every warning kept by kind, not yet acknowledged
    acknowledge --rows <id,...>        rows holding a value no release writes, once looked at: verify then
                                       reports them as information
    acknowledge --late-rows <hour>     rows added to a sealed hour more than 6 hours after its seal: a late
                                       seal by the host, which counts as acknowledged

The restore and key commands are app/core/audit_chain_recovery.py; the acknowledgment of a removal made by
a release without the chain is app/core/audit_chain_external.py.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from app.core import audit_chain_format as fmt

STATE_PREFIX = "dvstate1:"
ACKNOWLEDGED_ACTION = "audit_integrity_acknowledged"


class Refused(Exception):
    """The command was refused; the message says why."""


def _ai():
    from app.core import audit_integrity
    return audit_integrity


# Warnings an acknowledgment does not clear: they end when what they wait for happens.
NOT_ACKNOWLEDGED = frozenset({"key-change-waiting", "head-record-unwritable", "restore-pending"})


# --------------------------------------------------------------------------- the two phases

def digest(value) -> str:
    return hashlib.sha256(fmt.canonical_json(value)).hexdigest()


def chain_state(view, record: Optional[dict]) -> dict:
    """The part of every command's state that is the chain: the head, the head record's generation and discard
    count, a digest of its key history, and the seals it lists after it."""
    record = record or {}
    return {"head": fmt.head(view.position, view.link_at(view.position)) if view.position else None,
            "generation": int(record.get("generation") or 1), "discards": int(record.get("discards") or 0),
            "keys": digest([record.get("keys") or [], record.get("unverified_keys") or []]),
            "after_record": sorted([int(e.get("generation") or 0), int(e.get("seq") or 0), e.get("link"),
                                    bool(e.get("acknowledged")), bool(e.get("discarded"))]
                                   for e in record.get("after_record") or [])}


def token(state: dict) -> str:
    return STATE_PREFIX + digest(state)


def check_expected(state: dict, expect: Optional[str]) -> None:
    """Refuse unless ``state`` is the one the operator saw."""
    if not expect or not expect.startswith(STATE_PREFIX):
        raise Refused("--expect is not a state the read phase printed (dvstate1:...)")
    if token(state) != expect:
        raise Refused("the chain, or the rows, changed since you looked: run the command again and check what "
                      "it shows now; nothing was written")


def host_audit_row(db, action: str, details: dict, status: str = "success"):
    from app.core.credential_changes import HOST_OPERATOR
    from app.services.audit_logger import AuditLogger
    row = AuditLogger(db).build_row(action=action, status=status, username=HOST_OPERATOR, resource_type="audit_log",
                                    details=details)
    db.add(row)
    return row


# --------------------------------------------------------------------------- what is waiting

def warning_seqs(view, record: Optional[dict]) -> List[int]:
    """The seals that are warnings until acknowledged: late seals, the seals written from the database's values,
    and seals another writer appended after the head record."""
    ai = _ai()
    done = ai.acknowledged(view, record)
    out = [s for s in view.late_seqs if s not in done]
    out += [s for s in ai.database_seqs(view) if s not in done]
    out += list(ai.unacknowledged_foreign(view, record))
    return sorted(set(out))


def open_findings(record: Optional[dict]) -> List[list]:
    """[table, kind, first_seen, last_seen] of every failure, and every warning kept by kind, not yet
    acknowledged."""
    ai = _ai()
    out = [["failures", kind, e.get("first_seen"), e.get("last_seen")]
           for kind, e in sorted(ai.open_failures(record).items())]
    out += [["warnings", kind, e.get("first_seen"), e.get("last_seen")]
            for kind, e in sorted(ai.open_warnings(record).items()) if kind not in NOT_ACKNOWLEDGED]
    return out


def _with_acknowledged(record: Optional[dict], view, seqs, now: datetime) -> dict:
    import copy
    out = copy.deepcopy(record or {})
    stamp = fmt.time_text(now)
    for e in out.get("after_record") or []:
        if e.get("generation") == view.generation and int(e.get("seq", 0)) in seqs:
            e["acknowledged"] = True
            e.setdefault("acknowledged_at", stamp)
    return out


def honoured_difference(view, record: Optional[dict], seqs, now: datetime) -> List[str]:
    """What acknowledging ``seqs`` changes in the honoured state: each entry whose honoured setting or value
    differs with the acknowledgment and without it, both taken as of the latest due date among the applies it
    acknowledges (now, when there is none)."""
    from app.core import audit_chain_honour as honour
    after = _with_acknowledged(record, view, seqs, now)
    at = now
    for seq in seqs:
        detail = next((d for s, d in view.policies if s == seq), None)
        if detail and detail.get("cause") == "applies" and detail.get("request_seq") in view.requests:
            at = max(at, honour.request_due(view, after, detail["request_seq"], now))
    without = honour.honoured_state(view, record, at)
    with_ack = honour.honoured_state(view, after, at)
    lines = []
    for name in sorted(set(without) | set(with_ack)):
        a, b = without.get(name) or {}, with_ack.get(name) or {}
        if (a.get("value"), a.get("setting")) != (b.get("value"), b.get("setting")):
            lines.append(f"  {name}: {a.get('value')!r} (setting {a.get('setting')!r}) -> {b.get('value')!r} "
                         f"(setting {b.get('setting')!r}), from {fmt.time_text(at)}")
    return lines


def describe_seal(view, record: Optional[dict], seq: int, now: datetime) -> List[str]:
    """What seal ``seq`` is, and what acknowledging it would start (the acknowledge printout)."""
    from app.core import audit_chain_honour as honour
    from app.core import audit_chain_policy as pol
    ai = _ai()
    foreign = ai.foreign_entries(view, record)
    entry = foreign.get(seq)
    kind = view.kind_of(seq)
    head = f"seal {seq} ({kind}), sealed_at {fmt.time_text(view.at(seq))}"
    if entry is not None:
        head += f", first accepted {entry.get('accepted_at')} ({entry.get('where')}), appended by another writer"
    lines = [head]
    if kind == "policy":
        detail = next((d for s, d in view.policies if s == seq), None) or {}
        lines.append(f"  a policy seal of cause {detail.get('cause')} by {detail.get('by')}")
        for name, e in sorted((detail.get("state") or {}).items()):
            if e.get("set_by") == seq:
                lines.append(f"  sets {name} to {e.get('value')!r} (setting {e.get('setting')!r}, "
                             f"source {e.get('source')})")
        if detail.get("cause") == "env" and (detail.get("inputs") or {}) != pol.raw_inputs():
            lines.append("  its .env inputs are not the ones this server's .env gives")
        if detail.get("cause") == "applies" and detail.get("request_seq") in view.requests:
            req = detail["request_seq"]
            after = _with_acknowledged(record, view, {seq}, now)
            due = honour.request_due(view, after, req, now)
            lines.append(f"  applies request {req}; that request was due {fmt.time_text(due)}; the value counts "
                         f"from the later of this acknowledgment and that date")
            if req in foreign and not foreign[req].get("acknowledged"):
                lines.append(f"  request {req} is another writer's too and is not acknowledged: the value waits "
                             "for its acknowledgment as well")
    elif kind == "request":
        d = view.requests.get(seq) or {}
        after = _with_acknowledged(record, view, {seq}, now)
        lines.append(f"  asks for {d.get('what')} {d.get('setting') or ''} {d.get('old')!r} -> {d.get('new')!r}; "
                     f"once acknowledged it applies from "
                     f"{fmt.time_text(honour.effective_not_before(view, after, seq, now))}")
    elif kind == "cancel":
        cancelled = next((r for r, c in view.cancels.items() if c == seq), None)
        lines.append(f"  cancels request {cancelled}")
    elif kind == "late":
        entry_h = None
        for start, _end, last in view.units():
            if any(s == seq for s, _a, _b in view.entry_chain(last)):
                entry_h = start
                break
        if entry_h is not None:
            prev = [r for r in view.entry_for(entry_h).roots if r.seq < seq]
            if prev:
                window_end = prev[-1].sealed_at + ai.LATE_WINDOW
                lines.append(f"  re-roots {fmt.hour_text(entry_h)}; its hour's previous seal was sealed "
                             f"{fmt.time_text(prev[-1].sealed_at)}, so the window ended {fmt.time_text(window_end)}")
                if entry is not None and fmt.parse_time_text(entry["accepted_at"]) > window_end:
                    lines.append("  the server first accepted it after that window: only its own sealed_at keeps "
                                 "it inside")
    elif kind in ("prune", "rewrite", "erase"):
        lines.append("  changes rows; the pruner leaves the hours it re-roots alone until it is acknowledged")
    elif kind == "ack":
        named = [s for s, by in view.acked.items() if seq in by]
        lines.append(f"  acknowledges {named or 'nothing'}: acknowledging this seal acknowledges only it; list "
                     "those seals too to acknowledge them")
    return lines


# --------------------------------------------------------------------------- acknowledge

def _rows_described(db, ids: List[str]) -> List[dict]:
    from app.core.models import AuditLog as A
    out = []
    for rid in ids:
        row = db.query(A.id, A.timestamp, A.action, A.username, A.resource_type, A.resource_id).filter(
            A.id == fmt.as_uuid(rid)).first()
        if row is not None:
            out.append({"id": str(row[0]), "timestamp": fmt.time_text(row[1]) if row[1] else None,
                        "action": row[2], "username": row[3], "resource": f"{row[4] or ''} {row[5] or ''}".strip()})
    return out


def unwritable_rows(db, view, ids: List[str]) -> Dict[str, bool]:
    """{id: whether the row holds a value no release writes}, for the given rows in sealed hours."""
    ai = _ai()
    from app.core.models import AuditLog as A
    out = {}
    for rid in ids:
        uid = fmt.as_uuid(rid)
        t = db.query(A.timestamp).filter(A.id == uid).scalar()
        if t is None or view.entry_for(ai.hour_floor(t)) is None:
            out[str(uid)] = False
            continue
        rows = [r for r in ai.iter_rows(db, ai.hour_floor(t), ai.hour_floor(t) + ai.HOUR) if r["id"] == uid]
        out[str(uid)] = bool(rows) and bool(ai.hour_figures(rows).unwritable)
    return out


def acknowledge_plan(db, view, record: Optional[dict], *, seqs: List[int], failures: bool, rows: List[str],
                     now: datetime) -> dict:
    """The read phase of ``acknowledge``: what it would acknowledge, what that starts, and the state."""
    allowed = set(warning_seqs(view, record))
    unknown = [s for s in seqs if s not in allowed]
    if unknown:
        raise Refused(f"not a warning waiting to be acknowledged: {', '.join(map(str, unknown))}")
    findings = open_findings(record) if failures else []
    rows = sorted({str(fmt.as_uuid(r)) for r in rows})
    if rows:
        acked = set(view.acked_rows)
        bad = [r for r, is_unwritable in unwritable_rows(db, view, rows).items() if not is_unwritable or r in acked]
        if bad:
            raise Refused(f"not a row holding a value no release writes, waiting to be acknowledged: "
                          f"{', '.join(bad)}")
    if not seqs and not findings and not rows:
        raise Refused("nothing to acknowledge")
    lines = []
    for seq in sorted(seqs):
        lines += describe_seal(view, record, seq, now)
    diff = honoured_difference(view, record, set(seqs), now)
    if diff:
        lines.append("What the pruner acts on changes:")
        lines += diff
    for table, kind, first, last in findings:
        lines.append(f"{table[:-1]} {kind}: first seen {first}, last seen {last}")
    described = _rows_described(db, rows)
    for r in described:
        lines.append(f"row {r['id']}: {r['timestamp']} {r['action']} {r['username'] or ''} {r['resource']}")
    state = {"chain": chain_state(view, record), "command": "acknowledge", "seqs": sorted(seqs),
             "findings": findings, "rows": rows, "rows_digest": digest(described)}
    return {"state": state, "lines": lines, "seqs": sorted(seqs), "findings": findings, "rows": rows}


def acknowledge(engine, st, *, seqs: List[int], failures: bool, expect: Optional[str] = None,
                rows: Optional[List[str]] = None, read: bool = False) -> dict:
    """``acknowledge`` in either phase: the read phase returns what it would do and the state; the write phase
    writes the host's ``ack`` seal, refusing unless the state is the one ``expect`` names. Raises Refused."""
    ai = _ai()
    rows = rows or []
    with ai.ChainWriter(engine, st, wait=30, writer="host", snapshot=True) as w:
        view, record = w.st.view, w.record or {}
        plan = acknowledge_plan(w.db, view, record, seqs=seqs, failures=failures, rows=rows, now=w.st.clock())
        if read:
            return {"state": token(plan["state"]), "lines": plan["lines"]}
        check_expected(plan["state"], expect)
        listed = [[kind, first, last] for _table, kind, first, last in plan["findings"]]
        row = host_audit_row(w.db, ACKNOWLEDGED_ACTION, {"acknowledges": plan["seqs"],
                                                            "failures": [k for k, _f, _l in listed],
                                                            "rows": plan["rows"]})
        w.append("ack", detail={"acknowledges": plan["seqs"], "failures": listed, "rows": plan["rows"],
                                "discarded": [], "by": "host", "user_id": None, "request": str(row.id)})
        w.after_record_change = marker(view, set(plan["seqs"]), plan["findings"], bool(listed), w.st.clock())
    return {"acknowledged": plan["seqs"], "failures": [k for k, _f, _l in listed], "rows": plan["rows"]}


def marker(view, acked: set, findings: List[list], any_failures: bool, now: datetime):
    """The head record change of an acknowledgment: the seals it names marked acknowledged, the findings it
    lists marked as of their last sighting, and a failed outcome turned to acknowledged."""
    def mark(rec):
        stamp = fmt.time_text(now)
        for e in rec.get("after_record") or []:
            if e.get("generation") == view.generation and int(e.get("seq", 0)) in acked:
                e["acknowledged"] = True
                e.setdefault("acknowledged_at", stamp)
        for table, kind, _f, last in findings:
            entry = (rec.get(table) or {}).get(kind)
            if entry is not None and (entry.get("last_seen") or "") <= (last or ""):
                entry["acknowledged_at"] = stamp
        status = rec.get("status") or {}
        if any_failures and status.get("outcome") == "failed":
            rec["status"] = {"outcome": "acknowledged", "at": stamp, "kinds": []}
        return rec
    return mark


# --------------------------------------------------------------------------- rows added after the window

def late_rows_plan(db, view, record: Optional[dict], hour: datetime) -> dict:
    """The read phase of ``acknowledge --late-rows``: the rows added to ``hour`` that its seal does not hold,
    once the rest still give the hour's root seal, and the figures a late seal would record."""
    ai = _ai()
    import secrets
    if view.entry_for(hour) is None:
        raise Refused(f"{fmt.hour_text(hour)} is not a sealed hour")
    root = ai.hour_root(db, view, hour)
    own = view.has_own(hour)
    wr = ai.working_row(db, hour) if own else None
    sealed_ids = bytes(wr.row_ids or b"") if wr is not None else b""
    if wr is not None and fmt.ids_digest_of_blob(sealed_ids) != root.ids_digest:
        raise Refused(f"the list of rows sealed for {fmt.hour_text(hour)} no longer matches its seal: run audit "
                      "verify")
    sealed = {sealed_ids[i:i + 16] for i in range(0, len(sealed_ids), 16)}
    added = [r["id"] for r in ai.iter_rows(db, hour, hour + ai.HOUR) if r["id"].bytes not in sealed]
    if not added:
        raise Refused(f"{fmt.hour_text(hour)} has no row its seal does not hold")
    salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
    entry = view.own_entry(hour)
    c_prev = ai.erase_c_prev(db, view, entry) if entry is not None and entry.erases else {}
    before = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), salt, c_prev, exclude=set(added))
    if (before.count, before.root_s, before.root_c, before.ids_digest) != (root.count, root.root_s, root.root_c,
                                                                          root.ids_digest):
        raise Refused(f"the rows {fmt.hour_text(hour)}'s seal holds changed too: this is not a late arrival, and it "
                      "is not sealed over")
    added_set = set(added)
    nonceless = any(r["seal_nonce"] is None for r in ai.iter_rows(db, hour, hour + ai.HOUR) if r["id"] in added_set)
    after = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), salt)
    described = _rows_described(db, [str(a) for a in added])
    lines = [f"{len(added)} rows in {fmt.hour_text(hour)} that its seal ({root.seq}) does not hold:"]
    lines += [f"  {r['timestamp']} {r['action']} {r['username'] or ''} {r['resource']}  ({r['id']})" for r in described]
    state = {"chain": chain_state(view, record), "command": "late-rows", "hour": fmt.hour_text(hour),
             "added": [str(a) for a in added], "count": after.count, "root_s": after.root_s.hex(),
             "ids_digest": after.ids_digest.hex(), "rows_digest": digest(described)}
    return {"state": state, "lines": lines, "root": root, "added": added, "salt": salt, "wr": wr,
            "new_salt": secrets.token_bytes(32) if salt is None and nonceless else None}


def seal_late_rows(engine, st, hour: datetime, *, expect: Optional[str] = None, read: bool = False) -> dict:
    """``acknowledge --late-rows <hour>`` in either phase: the write phase writes a late seal by the host over
    the hour's rows as they are now, which counts as acknowledged. Raises Refused."""
    ai = _ai()
    with ai.ChainWriter(engine, st, wait=30, writer="host", snapshot=True) as w:
        view, record = w.st.view, w.record or {}
        plan = late_rows_plan(w.db, view, record, hour)
        if read:
            return {"state": token(plan["state"]), "lines": plan["lines"]}
        check_expected(plan["state"], expect)
        use_salt = plan["salt"] or plan["new_salt"]
        after = ai.hour_figures(ai.iter_rows(w.db, hour, hour + ai.HOUR), use_salt)
        wr = plan["wr"]
        host_audit_row(w.db, ACKNOWLEDGED_ACTION, {"late_rows": fmt.hour_text(hour), "added": len(plan["added"])})
        seal = w.append("late", period_start=hour, period_end=hour + ai.HOUR, row_count=after.count,
                        row_bytes=after.bytes, root_s=after.root_s, root_c=after.root_c, ids_dig=after.ids_digest,
                        detail={"hour": fmt.hour_text(hour), "prev_seq": plan["root"].seq,
                                "added": [str(a) for a in plan["added"]], "by": "host"},
                        row_ids=after.ids if wr is None else None,
                        legacy_salt=plan["new_salt"] if wr is None else None)
        seal.salt = use_salt
        if wr is not None:
            wr.row_ids = after.ids
            if plan["new_salt"] is not None:
                wr.legacy_salt = plan["new_salt"]
    return {"sealed": seal.seq, "hour": fmt.hour_text(hour), "added": len(plan["added"])}
