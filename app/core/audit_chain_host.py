"""What the server's operator does to the audit chain from the host (``dockvault.py audit``).

    python -m app.core.audit_integrity acknowledge --seqs 12,15 --expect dvchain1:...
    python -m app.core.audit_integrity acknowledge --failures --expect dvchain1:...

``acknowledge`` writes an ``ack`` seal by the host: for warnings about seals (late seals, the seals the pruner
wrote from the database's values, seals another writer appended after the head record) it names the seals;
with ``--failures`` it lists every failure, and every warning kept by kind (a step back of ``sealed_at`` the
daily check found, for one), not yet acknowledged, with when each was first and last seen. A failure stays
on the integrity status until the host acknowledges it, so the acknowledgment is itself a chain event. A
warning that waits on something else (a key change waiting for its key) is not acknowledged this way. The write
refuses unless the chain's head is still the one the operator saw (``--expect``, the head ``audit verify``
printed): nothing appended in between is acknowledged unseen. The ``audit_integrity_acknowledged`` row is in
the seal's transaction, recorded as the host operator.
"""
from __future__ import annotations

from typing import List, Optional

from app.core import audit_chain_format as fmt


class Refused(Exception):
    """The command was refused; the message says why."""


def _ai():
    from app.core import audit_integrity
    return audit_integrity


# Warnings an acknowledgment does not clear: they end when what they wait for happens.
NOT_ACKNOWLEDGED = frozenset({"key-change-waiting", "head-record-unwritable"})


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


def acknowledge(engine, st, *, seqs: List[int], failures: bool, expect: str) -> dict:
    """Write the host's ``ack`` seal. Returns what it acknowledged. Raises Refused."""
    from app.core.credential_changes import HOST_OPERATOR
    from app.services.audit_logger import AuditLogger
    ai = _ai()
    try:
        expected_seq, expected_link = fmt.parse_head(expect)
    except ValueError:
        raise Refused("--expect is not a chain head (dvchain1:...)")
    with ai.ChainWriter(engine, st, wait=30, writer="host") as w:
        view, record = w.st.view, w.record or {}
        if (view.position, view.link_at(view.position)) != (expected_seq, expected_link):
            raise Refused("the chain has moved since you looked: run audit verify again, and acknowledge what it "
                          "shows now")
        allowed = set(warning_seqs(view, record))
        unknown = [s for s in seqs if s not in allowed]
        if unknown:
            raise Refused(f"not a warning waiting to be acknowledged: {', '.join(map(str, unknown))}")
        findings = open_findings(record) if failures else []
        if not seqs and not findings:
            raise Refused("nothing to acknowledge")
        listed = [[kind, first, last] for _table, kind, first, last in findings]
        row = AuditLogger(w.db).build_row(
            action="audit_integrity_acknowledged", status="success", username=HOST_OPERATOR, resource_type="audit_log",
            details={"acknowledges": sorted(seqs), "failures": [k for k, _f, _l in listed]})
        w.db.add(row)
        w.append("ack", detail={"acknowledges": sorted(seqs), "failures": listed, "rows": [], "discarded": [],
                                "by": "host", "user_id": None, "request": str(row.id)})
        now = w.st.clock()
        acked = set(seqs)

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
            if listed and status.get("outcome") == "failed":
                rec["status"] = {"outcome": "acknowledged", "at": stamp, "kinds": []}
            return rec

        w.after_record_change = mark
    return {"acknowledged": sorted(seqs), "failures": [k for k, _f, _l in listed]}
