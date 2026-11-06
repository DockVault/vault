"""What the pruner keeps for compliance access: a case's audit rows and the compliance rows of the audit log.

Two row-keep rules on audit_logs (app/core/retention.py, register_keep), which every job over the table reads,
the maximum age and the size cap alike:

- A row written under a case (``case_id`` set) is kept while the case is open (not yet closed, whatever its
  state: pending, active, keeping a hold, suspended), while any legal hold of the case stands (placed and
  neither released nor lapsed), and until both COMPLIANCE_RECORD_MIN_DAYS have passed since the case closed
  and the case's own ``records_kept_until`` (the floor in force at its approval, the stricter one) has passed,
  and until the counts of its rows are kept on the case (cases.keep_counts, 30 days after it closed: the
  Compliance page reads them there once the rows are archived or pruned). A row whose case cannot be found is kept.
- A row of the compliance category (app/core/audit_catalog.py) is kept COMPLIANCE_RECORD_MIN_DAYS after it was
  written, case or not (an auditor grant, a reveal of a name, a refused request).

After that the rows follow the audit log's retention like any other. The floor is enforced here, by the
pruner's filters, rather than by a trigger on the busiest table: the pruner is the only thing that deletes
audit rows.

A case's rows are also kept as they are, where they are (retention.register_keep_as_is): the audit archive leaves
a day that holds one as rows, and a per-person erase, a removal of earlier values or the shortening of addresses
leaves them unchanged.

What every such path waits for (person_erase.register_wait): while a confirmed legal hold stands or a case is open
(a case holding only a hold nobody has confirmed yet aside), an erase, a removal of earlier values, the shortening
of addresses, and the deletion of ended invitations, ended one-time proofs, old notifications and the sealed name of
an erase that ended wait (holds_back), checked in the transaction that would change or delete, in its turn with the
holds and cases (legal_holds.take_turn).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import and_, exists, not_, or_

from app.core import person_erase
from app.core import retention


def floor_days() -> int:
    """COMPLIANCE_RECORD_MIN_DAYS, as in force now."""
    from app.core import compliance_settings as cs
    return int(cs.current(cs.RECORD_MIN_DAYS))


def case_rows_kept(model, now: datetime):
    """The rows of ``model`` (audit_logs) written under a case whose records must stay."""
    from app.core.models import ComplianceCase, LegalHoldVault
    floor = now - timedelta(days=floor_days())
    holding = exists().where(LegalHoldVault.case_id == model.case_id, LegalHoldVault.released_at.is_(None),
                             LegalHoldVault.lapsed_at.is_(None))
    # An open case has no closed_at, which is never before the floor. A case whose counts are not yet kept on it
    # (cases.keep_counts) keeps its rows until they are.
    released = exists().where(ComplianceCase.id == model.case_id, ComplianceCase.closed_at < floor,
                              or_(ComplianceCase.records_kept_until.is_(None),
                                  ComplianceCase.records_kept_until < now),
                              ComplianceCase.counts_kept_at.isnot(None))
    return and_(model.case_id.isnot(None), or_(not_(released), holding))


def case_rows_released_since(db, case, now: datetime) -> Optional[datetime]:
    """When ``case``'s audit rows stopped being kept (case_rows_kept, read for one case): the later of
    COMPLIANCE_RECORD_MIN_DAYS after its close and its own ``records_kept_until``, once both have passed, its counts
    are kept on it and no legal hold of it stands; None while they are kept. From then they follow the audit log's
    retention (archived, or pruned), so a list read from them may no longer be whole."""
    from app.core.models import LegalHoldVault
    if case.closed_at is None or case.counts_kept_at is None:
        return None
    since = case.closed_at + timedelta(days=floor_days())
    if case.records_kept_until is not None and case.records_kept_until > since:
        since = case.records_kept_until
    if since >= now:
        return None
    holding = (db.query(LegalHoldVault.vault_id)
               .filter(LegalHoldVault.case_id == case.id, LegalHoldVault.released_at.is_(None),
                       LegalHoldVault.lapsed_at.is_(None)).first())
    return None if holding is not None else since


def compliance_rows_kept(model, now: datetime):
    """The rows of ``model`` (audit_logs) of the compliance category younger than the floor."""
    from app.core import audit_catalog
    return and_(model.action.in_(audit_catalog.stored_names(["compliance"])),
                model.timestamp >= now - timedelta(days=floor_days()))


# How many case numbers a reason names before it says how many more there are.
NAMED_CASES = 3


def _cases(numbers: list, unnumbered: int) -> str:
    """"case C-2026-0001", "cases C-2026-0001 and C-2026-0002", "cases C-..., C-..., C-... and 2 more": the
    numbered cases first, at most NAMED_CASES of them, then how many more (a case not yet approved has no number)."""
    shown = numbers[:NAMED_CASES]
    more = len(numbers) - len(shown) + unnumbered
    if len(shown) == 1 and not more:
        return f"case {shown[0]}"
    if more:
        return "cases " + ", ".join(shown) + f" and {more} more"
    return "cases " + ", ".join(shown[:-1]) + " and " + shown[-1]


def _numbered(rows) -> tuple:
    """(the case numbers, sorted, and how many cases have none) of distinct (case id, number) rows."""
    numbers = sorted({n for _cid, n in rows if n})
    unnumbered = len({cid for cid, n in rows if not n})
    return numbers, unnumbered


def holds_back(db, now: datetime) -> Optional[str]:
    """Why every path that changes or deletes what a hold or a case may need waits now, or None: a confirmed legal
    hold stands (placed, confirmed by a second person, neither released nor lapsed), a case is open (not closed,
    whatever its state, but one that holds only a hold nobody has confirmed yet), or a step that would place a hold,
    confirm one or open a case gave up waiting for its turn a moment ago (legal_holds.want_turn). Any such hold and
    any such case, not only those of the rows a path would touch: an audit row of what was done in a held vault need
    not carry the case. In the caller's transaction, after taking the turn of holds and deletions shared, so a hold,
    a confirmation or a case committed before this check is seen, and one made meanwhile waits until the caller's
    transaction ends.

    A hold nobody has confirmed holds nothing back here: one person places it alone, and every erase in the
    deployment would wait for it until it lapses. It keeps what is deleted from its vaults all the same
    (app/core/kept_tables.py), and from its confirmation on it holds back as any other.

    The reason names the cases (at most NAMED_CASES, then how many more): an erase, a removal of earlier values and
    the other paths that wait show it to the administrators, who see the cases, so they know which one to wait
    for."""
    from app.core import case_rules
    from app.core import legal_holds
    from app.core.models import ComplianceCase, LegalHoldVault
    legal_holds.take_turn(db, shared=True)
    if legal_holds.turn_wanted(db):
        return "a legal hold or a compliance case is being asked for"
    held = (db.query(LegalHoldVault.case_id, ComplianceCase.number)
            .outerjoin(ComplianceCase, ComplianceCase.id == LegalHoldVault.case_id)
            .filter(LegalHoldVault.released_at.is_(None), LegalHoldVault.lapsed_at.is_(None),
                    LegalHoldVault.confirmed_at.isnot(None)).distinct().all())
    if held:
        numbers, unnumbered = _numbered(held)
        if not numbers:
            return "a legal hold stands" if unnumbered == 1 else "legal holds stand"
        if len(numbers) == 1 and not unnumbered:
            return f"the legal hold of case {numbers[0]} stands"
        return f"the legal holds of {_cases(numbers, unnumbered)} stand"
    # A hold-only case is open while its hold stands: once confirmed, that hold is counted above.
    open_cases = db.query(ComplianceCase.id, ComplianceCase.number).filter(
        ComplianceCase.closed_at.is_(None), ComplianceCase.status != case_rules.HOLD_ONLY).all()
    if open_cases:
        numbers, unnumbered = _numbered(open_cases)
        if not numbers:
            return "a compliance case is open" if unnumbered == 1 else "compliance cases are open"
        if len(numbers) == 1 and not unnumbered:
            return f"case {numbers[0]} is open"
        return f"{_cases(numbers, unnumbered)} are open"
    return None


retention.register_keep_as_is("audit_logs", case_rows_kept)
retention.register_keep("audit_logs", compliance_rows_kept)
person_erase.register_wait(holds_back)
