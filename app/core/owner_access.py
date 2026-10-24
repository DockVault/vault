"""What a vault's owner sees of compliance access to their own vaults, and what a vault's members see.

"Access to my vaults" (GET /me/compliance-access): every case that has told the owner about one of their vaults
(an investigation once approved, a hold-only case once placed): its number, status, purpose and legal basis, its
auditor and its approver, the auditor's note to the owner, its dates, and for each of the owner's vaults in it
what it covers, whether a hold stands and how many files the hold kept; the exports of the case; and the files
opened in the owner's vaults under it, as they happen; and the names an auditor revealed outside a case from the
activity log's events on the owner's vaults (when, by whom, the reason's category; never the reason's text or the
names). Never the justification, the people named, or anything of another owner's vaults. File names are read when the page is shown, and only where the owner could read them in
the vault itself: a Standard vault's at once, a password-protected vault's once its password is given on the page
(a receipt good for 15 minutes, app/core/vault_unlock_receipts.py, on the vault-password throttle every check of
that vault's password by the owner counts in), a zero-knowledge vault's never (the server does not have them).

The banner after sign-in (static/js/notice-banner.js, the one the recording notice uses): while a notice to the
owner (each one has an outbox row, app/core/owner_notices.py) is unread, the banner says so and links the page.
"I've read it" marks them read (``seen_at``) and records that they were seen; the notices and the page stay.

Members (the vault-detail route, never VaultService.get_vault): everyone who opens a vault an active case covers
sees a neutral banner, "This vault is part of an authorised review until ...", and, while a legal hold stands on
it, that what is deleted there is kept until it ends. No case number, purpose, auditor or person concerned: the
members are told that it is read, not what its owner is suspected of.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Mapping, Optional

from app.core import case_rules as rules

# A notice of access someone else gave (app/core/access_notices.py) is the bell's, not this banner's: the banner is
# about compliance access (investigations, holds, revealed names).
_ACCESS_GRANTED = "access_granted"
# The most files opened the page lists per case, newest first.
OPENED_SHOWN = 200
# The most revealed names the page lists, newest first.
REVEALS_SHOWN = 200
NAME_HIDDEN_PASSWORD = "password"
NAME_HIDDEN_ZERO_KNOWLEDGE = "zero_knowledge"
NAME_HIDDEN_GONE = "gone"
NAME_HIDDEN_NOT_OWNER = "not_owner"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


def _who(name: Optional[str]) -> Optional[str]:
    return "the server's operator" if name == "operator@host" else name


# --------------------------------------------------------------------------- the owner's page

def owner_rows(db, user) -> list:
    """The owner's vaults in cases that told them: (case, [its rows of this owner's vaults]), newest case first."""
    from app.core.models import ComplianceCase, ComplianceCaseVault
    rows = (db.query(ComplianceCaseVault).filter(ComplianceCaseVault.owner_id_at_approval == user.id,
                                                 ComplianceCaseVault.notice_written_at.isnot(None)).all())
    by_case = {}
    for row in rows:
        by_case.setdefault(row.case_id, []).append(row)
    cases = (db.query(ComplianceCase).filter(ComplianceCase.id.in_(list(by_case)))
             .order_by(ComplianceCase.requested_at.desc()).all()) if by_case else []
    return [(c, sorted(by_case[c.id], key=lambda r: str(r.vault_id))) for c in cases]


def _kept(db, case_id, vault_id) -> int:
    """Files a hold of this case kept on this vault (rows kept while its hold stood)."""
    from sqlalchemy import and_, func, or_
    from app.core.models import HeldFile, LegalHoldVault
    holds = db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id, LegalHoldVault.vault_id == vault_id).all()
    if not holds:
        return 0
    clause = or_(*[and_(HeldFile.kept_at >= h.placed_at,
                        *([HeldFile.kept_at <= h.released_at] if h.released_at is not None else [])) for h in holds])
    return int(db.query(func.count(HeldFile.id)).filter(HeldFile.vault_id == vault_id, clause).scalar() or 0)


def _vault_facts(db, vault_id):
    """(id, type, password hash, owner) of the vault now, or None when it is gone."""
    from app.core.models import Vault
    return db.query(Vault.id, Vault.type, Vault.password_hash, Vault.owner_id).filter(Vault.id == vault_id).first()


def _file_name(db, file_id, vault, *, unlocked: bool, owner_id) -> tuple:
    """(name, why it is hidden) of a file opened under a case, read now as the owner ``owner_id`` could read it in
    the vault: never once the vault is no longer theirs."""
    from app.core.models import File, HeldFile
    if vault is None:
        return None, NAME_HIDDEN_GONE
    if str(vault[3]) != str(owner_id):
        return None, NAME_HIDDEN_NOT_OWNER
    if (vault[1] or "standard") == "zero_knowledge":
        return None, NAME_HIDDEN_ZERO_KNOWLEDGE
    if vault[2] is not None and not unlocked:
        return None, NAME_HIDDEN_PASSWORD
    fid = rules.as_id(file_id)
    row = db.get(File, fid) if fid is not None else None
    if row is None and fid is not None:
        row = db.get(HeldFile, fid)
    if row is None or row.vault_id != vault[0]:
        return None, NAME_HIDDEN_GONE
    return row.name, None


def opened(db, case, vault_ids, *, unlocked: set, owner_id) -> list:
    """Files opened under ``case`` in ``vault_ids`` (its audit rows), newest first, each name read as the owner
    ``owner_id`` could read it now."""
    from app.core.models import AuditLog
    wanted = {str(v) for v in vault_ids}
    if not wanted:
        return []
    rows = (db.query(AuditLog).filter(AuditLog.case_id == case.id, AuditLog.action == "case_file_viewed",
                                      AuditLog.status == "success",
                                      AuditLog.details["vault_id"].as_string().in_(sorted(wanted)))
            .order_by(AuditLog.timestamp.desc()).limit(OPENED_SHOWN).all())
    facts = {}
    out = []
    for row in rows:
        vid = str((row.details or {}).get("vault_id") or "")
        if vid not in facts:
            facts[vid] = _vault_facts(db, rules.as_id(vid))
        name, hidden = _file_name(db, row.resource_id, facts[vid], unlocked=vid in unlocked, owner_id=owner_id)
        out.append({"at": _iso(row.timestamp), "vault_id": vid, "file_id": row.resource_id, "name": name,
                    "name_hidden": hidden})
        if len(out) >= OPENED_SHOWN:
            break
    return out


def _exports(db, case) -> int:
    """The case's completed exports: the count kept on it once it has been closed long enough (cases.keep_counts),
    its audit rows until then."""
    from sqlalchemy import func
    from app.core.models import AuditLog
    if getattr(case, "counts_kept_at", None) is not None:
        return int(case.exports_count or 0)
    return int(db.query(func.count(AuditLog.id)).filter(AuditLog.case_id == case.id,
                                                        AuditLog.action == "case_export_completed",
                                                        AuditLog.status == "success").scalar() or 0)


def case_for_owner(db, case, rows, *, unlocked: set, now: datetime, owner_id) -> dict:
    from app.core import cases as case_steps
    from app.core import compliance_retention
    from app.core import legal_holds
    from app.core.security import is_case_sealed, open_case_field
    standing = {h.vault_id for h in legal_holds.standing(db, case.id)}
    note = None
    if is_case_sealed(case.owner_note_enc):
        try:
            note = open_case_field(case.id, case.owner_note_enc, "owner_note")
        except Exception:  # noqa: BLE001 -- a note that does not open is left out, never shown as stored
            note = None
    vaults = []
    for row in rows:
        facts = _vault_facts(db, row.vault_id)
        vaults.append({"vault_id": str(row.vault_id), "type": row.vault_type_at_approval,
                       "covers": "whole" if row.folder_ids is None else (
                           "nothing" if row.folder_ids == [] else "folders"),
                       "has_password": bool(facts is not None and facts[2] is not None),
                       "exists": facts is not None, "told_at": _iso(row.notice_written_at),
                       "hold": row.vault_id in standing, "kept_files": _kept(db, case.id, row.vault_id)})
    return {
        "id": str(case.id), "number": case.number,
        "status": case_steps.effective_status(db, case, now), "purpose": case.purpose,
        "legal_basis": case.legal_basis, "hold_only": (case.access_days or 0) == 0,
        "auditor": case.auditor_username if (case.access_days or 0) > 0 else None,
        "placed_by": case.auditor_username if (case.access_days or 0) == 0 else None,
        "approved_by": _who(case.approved_by_username), "approved_at": _iso(case.approved_at),
        "access_ends_at": _iso(case.access_ends_at), "closed_at": _iso(case.closed_at),
        "can_export": bool(case.can_export), "password_override": bool(case.password_override),
        "note": note, "vaults": vaults, "exports": _exports(db, case),
        "opened": opened(db, case, [r.vault_id for r in rows], unlocked=unlocked, owner_id=owner_id),
        # Once the case's records are no longer kept, its audit rows follow the audit log's retention: the files
        # opened are listed from those rows, so the list may no longer be whole (compliance.js says so).
        "opened_kept_until": _iso(compliance_retention.case_rows_released_since(db, case, now)),
    }


def unseen(db, user) -> list:
    """The notices to the owner not yet read: one per step and owner (their outbox rows), newest first."""
    from app.core.models import ComplianceCase, ComplianceNoticeOutbox as O
    rows = (db.query(O, ComplianceCase.number).outerjoin(ComplianceCase, ComplianceCase.id == O.case_id)
            .filter(O.user_id == user.id, O.seen_at.is_(None), O.kind != _ACCESS_GRANTED)
            .order_by(O.created_at.desc()).limit(100).all())
    return [{"case_id": str(r.case_id) if r.case_id else None, "number": number, "kind": r.kind,
             "at": _iso(r.created_at)} for r, number in rows]


def reveals(db, user) -> dict:
    """The names revealed outside a case from events on vaults the user owns now, newest first: when, by which
    auditor, the reason's category and the vault. Never the reason's text (sealed for the record) or the names."""
    from app.core.models import ComplianceReveal as R, Vault
    rows = (db.query(R.created_at, R.auditor_username, R.reason_category, R.vault_id)
            .join(Vault, Vault.id == R.vault_id).filter(Vault.owner_id == user.id)
            .order_by(R.created_at.desc(), R.id.desc()).limit(REVEALS_SHOWN + 1).all())
    return {"reveals": [{"at": _iso(at), "auditor": _who(by), "reason_category": category, "vault_id": str(vid)}
                        for at, by, category, vid in rows[:REVEALS_SHOWN]],
            "reveals_more": len(rows) > REVEALS_SHOWN}


def page(db, user, *, unlocked: Optional[set] = None, now: Optional[datetime] = None) -> dict:
    now = now or utcnow()
    unlocked = unlocked or set()
    return {"cases": [case_for_owner(db, c, rows, unlocked=unlocked, now=now, owner_id=user.id)
                      for c, rows in owner_rows(db, user)],
            **reveals(db, user),
            "unseen": unseen(db, user)}


def mark_seen(db, user, *, through: Optional[datetime] = None, now: Optional[datetime] = None) -> int:
    """Mark the owner's notices up to ``through`` read, with the audit row that says they were seen, in the caller's
    transaction. Returns how many."""
    from app.core.models import ComplianceNoticeOutbox as O
    from app.services.audit_logger import AuditLogger
    now = now or utcnow()
    q = db.query(O).filter(O.user_id == user.id, O.seen_at.is_(None), O.kind != _ACCESS_GRANTED,
                           O.created_at <= (through or now))
    rows = q.all()
    for row in rows:
        row.seen_at = now
    if rows:
        db.add(AuditLogger(db).build_row(action="owner_notice_seen", status="success", user=user,
                                         resource_type="user", resource_id=str(user.id),
                                         details={"count": len(rows)}))
    return len(rows)


def unlock_problem(db, user, vault) -> Optional[tuple]:
    """(status, words) when the owner may not unlock ``vault``'s names on their page, else None."""
    if vault is None or vault.owner_id != user.id:
        return 404, "No such vault of yours."
    if vault.type == "zero_knowledge":
        return 409, "The server never has a zero-knowledge vault's names."
    if not vault.password_hash:
        return 400, "This vault has no vault password: its names are shown already."
    return None


def unlocked_vaults(db, user, session_hash: Optional[str], given: Mapping[str, str]) -> set:
    """The owner's vaults whose names their receipts unlock now ({vault id: receipt} given with the request)."""
    from app.core import vault_unlock_receipts as receipts
    from app.core.models import Vault
    out = set()
    for vid, receipt in (given or {}).items():
        vault_id = rules.as_id(vid)
        vault = db.get(Vault, vault_id) if vault_id is not None else None
        if vault is None or vault.owner_id != user.id:
            continue
        if receipts.verify(receipt, purpose=receipts.PURPOSE_OWNER, session_hash=session_hash, vault_id=vault.id,
                           user_id=user.id, credential=receipts.credential_digest(vault.password_hash)):
            out.add(str(vault.id))
    return out


# --------------------------------------------------------------------------- members

def member_review(db, vault_id, now: Optional[datetime] = None) -> Optional[dict]:
    """The neutral banner of a vault an active case covers now, or None: until when, and whether a hold keeps
    what is deleted there. No number, purpose, auditor or person concerned."""
    from app.core import legal_holds
    from app.core.models import ComplianceCase, ComplianceCaseVault
    now = now or utcnow()
    ends = [c.access_ends_at for row, c in (
        db.query(ComplianceCaseVault, ComplianceCase).join(ComplianceCase, ComplianceCase.id == ComplianceCaseVault.case_id)
        .filter(ComplianceCaseVault.vault_id == vault_id, ComplianceCase.status == rules.ACTIVE).all())
        if row.folder_ids != [] and rules.access_open(c.access_starts_at, c.access_ends_at, now)]
    if not ends:
        return None
    return {"until": _iso(max(ends)), "hold": uuid.UUID(str(vault_id)) in legal_holds.held_vault_ids(db)}


def member_review_shown(db, vault_id) -> Optional[dict]:
    """member_review for the vault-detail route: a failure to read it never fails opening the vault (the banner is
    then not shown, and the failure is said in the log)."""
    try:
        return member_review(db, vault_id)
    except Exception as exc:  # noqa: BLE001 -- opening the vault goes on
        print(f"Warning: whether a review covers a vault could not be read ({type(exc).__name__})")
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None
