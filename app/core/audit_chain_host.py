"""What the server's operator does to the audit chain from the host (``dockvault.py audit``).

    python -m app.core.audit_integrity acknowledge --seqs 12,15 --expect dvchain1:...
    python -m app.core.audit_integrity acknowledge --failures --expect dvchain1:...

``acknowledge`` writes an ``ack`` seal by the host: for warnings (late seals, vetoes the pruner sealed from
the database, seals another writer appended after the head record) it names the seals; with ``--failures`` it
lists every failure kind not yet acknowledged, with when it was first and last seen. A failure stays on the
integrity status until the host acknowledges it, so the acknowledgment is itself a chain event. The write
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


def warning_seqs(view, record: Optional[dict]) -> List[int]:
    """The seals that are warnings until acknowledged: late seals, database vetoes, and seals another writer
    appended after the head record."""
    out = [s for s in view.late_seqs if s not in view.acked]
    for seq, detail in view.policies:
        if detail.get("cause") == "database" and seq not in view.acked:
            out.append(seq)
    for e in (record or {}).get("after_record") or []:
        if e.get("generation") == view.generation and not e.get("acknowledged") and not e.get("discarded"):
            out.append(int(e["seq"]))
    return sorted(set(out))


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
        open_failures = ai.open_failures(record) if failures else {}
        if not seqs and not open_failures:
            raise Refused("nothing to acknowledge")
        listed = [[kind, e.get("first_seen"), e.get("last_seen")] for kind, e in sorted(open_failures.items())]
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
            for kind, _f, last in listed:
                entry = (rec.get("failures") or {}).get(kind)
                if entry is not None and (entry.get("last_seen") or "") <= (last or ""):
                    entry["acknowledged_at"] = stamp
            status = rec.get("status") or {}
            if listed and status.get("outcome") == "failed":
                rec["status"] = {"outcome": "acknowledged", "at": stamp, "kinds": []}
            return rec

        w.after_record_change = mark
    return {"acknowledged": sorted(seqs), "failures": [k for k, _f, _l in listed]}
