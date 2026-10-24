"""What a legal hold refuses, beside the deletions it keeps (app/core/kept_tables.py): deleting a vault it keeps
anything of. The refusal answers 409 with a sentence that names the case, and records ``hold_blocked_delete``
under it (audit_logs.case_id).

A hold keeps a vault while it stands (a row of ``legal_hold_vaults`` with ``released_at`` NULL: a lapse sets it
too), and after its release while files or folders it kept still wait for their purge: until then the release
can be undone, and the kept files must still open. The vault's directory holds the kept blobs, and the database
refuses the vault's delete on its own (the ``vaults`` trigger). The route asks first, so the answer says why,
and takes the trigger's refusal (a hold placed in between) for the same answer (is_trigger_refusal).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

ACTION = "hold_blocked_delete"
# What a refusal kept from happening (the audit row's ``kind``).
VAULT = "vault"
KINDS = (VAULT,)


@dataclass
class Keeping:
    """What keeps a vault or an account: the cases whose holds stand, and those released whose kept rows still wait
    for their purge (with the latest time a purge may start). A kept row whose hold row is gone names no case."""
    standing: List[Tuple[uuid.UUID, Optional[str]]] = field(default_factory=list)
    waiting: List[Tuple[uuid.UUID, Optional[str]]] = field(default_factory=list)
    purge_after: Optional[datetime] = None

    def cases(self) -> List[Tuple[uuid.UUID, Optional[str]]]:
        seen, out = set(), []
        for case_id, number in self.standing + self.waiting:
            if case_id not in seen:
                seen.add(case_id)
                out.append((case_id, number))
        return out


def _numbers(db, case_ids) -> dict:
    from app.core.models import ComplianceCase
    ids = sorted({c for c in case_ids if c is not None}, key=str)
    if not ids:
        return {}
    return {cid: number for cid, number in db.query(ComplianceCase.id, ComplianceCase.number)
            .filter(ComplianceCase.id.in_(ids)).all()}


def vault_keeping(db, vault_id) -> Optional[Keeping]:
    """What keeps ``vault_id``, or None when nothing does. Nothing on a database without the kept tables; on
    Postgres a read that fails is raised, so the caller's step fails with nothing done."""
    from app.core import kept_tables
    from app.core.models import LegalHoldVault
    if not kept_tables.vault_keeps(db, vault_id):
        return None
    vid = uuid.UUID(str(vault_id))
    rows = (db.query(LegalHoldVault.case_id, LegalHoldVault.released_at, LegalHoldVault.purge_after)
            .filter(LegalHoldVault.vault_id == vid).all())
    numbers = _numbers(db, [r[0] for r in rows])
    keeping = Keeping()
    standing = sorted((r for r in rows if r[1] is None), key=lambda r: str(numbers.get(r[0]) or ""))
    keeping.standing = [(r[0], numbers.get(r[0])) for r in standing]
    if not keeping.standing:
        # Released: the kept rows wait for the purge after the latest release (the others' purge has run, or
        # waits as long).
        released = sorted((r for r in rows if r[1] is not None), key=lambda r: r[1], reverse=True)
        if released:
            latest = released[0][1]
            keeping.waiting = [(r[0], numbers.get(r[0])) for r in released if r[1] == latest]
            purges = [r[2] for r in released if r[1] == latest and r[2] is not None]
            keeping.purge_after = max(purges) if purges else None
    return keeping


# --------------------------------------------------------------------------- what the refusal says

def _cases_text(cases) -> str:
    numbers = [n for _cid, n in cases if n]
    if not numbers:
        return "a case"
    if len(numbers) == 1:
        return f"case {numbers[0]}"
    return "cases " + ", ".join(numbers[:-1]) + " and " + numbers[-1]


def _until(keeping: Keeping) -> str:
    when = f" after {keeping.purge_after:%Y-%m-%d}" if keeping.purge_after is not None else ""
    return f"until they are purged{when}"


def vault_text(keeping: Keeping) -> str:
    if keeping.standing:
        return (f"This vault is under a legal hold until {_cases_text(keeping.standing)} ends: it cannot be deleted "
                "while it is. Your administrator can tell you more.")
    return (f"This vault keeps files a legal hold of {_cases_text(keeping.waiting)} kept, {_until(keeping)}: it can "
            "be deleted then. Your administrator can tell you more.")


# --------------------------------------------------------------------------- recording it

def record(db, actor, kind: str, keeping: Optional[Keeping], *, vault_id=None) -> None:
    """Record the refusal: ``db``'s work is rolled back first, then one ``hold_blocked_delete`` row per case that
    keeps it (one with no case when none is named), committed on its own. Never raises: the refusal stands whether
    or not its row is written."""
    from app.core.case_context import acting_for
    from app.services.audit_logger import AuditLogger
    if kind not in KINDS:
        raise ValueError(f"not a refusal under a hold: {kind!r}")
    try:
        db.rollback()
        cases = keeping.cases() if keeping is not None else []
        details = {"kind": kind}
        if vault_id is not None:
            details["vault_id"] = str(vault_id)
        if keeping is not None and not keeping.standing and keeping.purge_after is not None:
            details["purge_after"] = keeping.purge_after.isoformat()
        logger = AuditLogger(db)
        for case_id, number in cases or [(None, None)]:
            with acting_for(case_id):
                db.add(logger.build_row(
                    action=ACTION, status="failure", user=actor,
                    resource_type="vault", resource_id=str(vault_id) if vault_id is not None else None,
                    details={**details, **({"case_number": number} if number else {})}))
        db.commit()
    except Exception:  # noqa: BLE001
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass


def is_trigger_refusal(exc) -> bool:
    """Whether ``exc`` is the database refusing to delete a vault a legal hold keeps (the ``vaults`` trigger raises
    with kept_tables.HOLD_HINT as its hint)."""
    from app.core import kept_tables
    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    return getattr(diag, "message_hint", None) == kept_tables.HOLD_HINT
