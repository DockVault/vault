"""Compliance cases with access: asking for one, approving and turning it down, withdrawing, extending, narrowing,
recording an objection, closing, and the clock that expires unapproved cases and ends access. The rules are in
app/core/case_rules.py; the routes in app/api/compliance_router.py; the server's operator approves and turns down
on the host (app/core/host_compliance.py) only when no administrator can.

Asking. An auditor whose right is in force asks for a case with the compliance step-up: what it is for and on
what basis, a justification of at least 30 characters (sealed; read only by the auditor, the administrators who
could approve it and the host), a note to the owners (sealed), the vaults, folders and custodians it covers
(resolved now into the list the approver sees and the owners it concerns), the people it names, a time range of
files, the days of access, and whether it may export, open password-protected vaults without their password, and
hold. An auditor the case concerns is refused, as is a sixth open case, a scope over COMPLIANCE_MAX_CASE_VAULTS,
and a password-protected vault while the deployment refuses them. Nothing is readable yet and the owners are not
told: the administrators who could approve it are, in the app.

Approving. An administrator independent of the auditor (app/core/case_eligibility.py), with the step-up and the
case's version (If-Match), approves it; in one transaction: the status, the number (the year's counter, locked),
the settings in force (a case never widens when .env changes later), the access period from now, the hold rows
(placed at the auditor's request, confirmed by the approval), each owner's notice in the app, its email outbox row
and its audit row (app/core/owner_notices.py), and the approval's audit row. A failure in any of them fails the
approval: nothing becomes readable without the owner's notice. The owners and the approver's eligibility are read
again at the approval, under the case's lock: a vault that changed hands tells its new owner, and an approver who
became a person concerned is refused.

The rest. Turning down takes the same eligibility and a reason the auditor sees. The auditor withdraws while it
waits. An independent administrator extends active access within the period and total ceilings, and the owners
are told. The scope narrows with no approval (by the auditor, or an independent administrator); a vault left out
covers nothing from then on and its owner is told; a legal hold on it stays until it is released. An objection by
an owner (or recorded for one by an administrator) is kept sealed and shown to whoever extends the case. Closing,
by the auditor or an independent administrator with a reason, releases the case's holds (their purge waits as for
any release) and tells the owners with a summary.

The clock (the pruner's job ``compliance_cases``, app/core/retention.py): a case unapproved after 7 days expires;
at the end of its access a case closes, or keeps only its legal hold (``hold_only``) while one stands, and the
owners are told with a summary of the files opened and the exports.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from app.core import after_commit
from app.core import case_rules as rules
from app.core import compliance_settings as cs
from app.core import owner_notices
from app.core.case_context import acting_for

HOST_OPERATOR = "operator@host"
SYSTEM = "system"
NOTICE_TYPE = "compliance_case"
TARGET = "#compliance"
OBJECTION_MAX = 4000

# Why a step is refused, beyond the case rules' own reasons.
NOT_ALLOWED = "not_allowed"
EXPIRED = "expired_unapproved"
VERSION_MISMATCH = "version_mismatch"
NO_REASON = "no_reason"
NOT_INDEPENDENT_HOST = "independent_admin"
NO_OBJECTION = "no_objection"
SFTP_VERSION = "sftp_version"

TEXTS = {
    rules.NOT_NOW: "the case is not in a state that allows this",
    rules.ACCESS_OFF: "compliance access is turned off on this deployment (COMPLIANCE_ACCESS=disabled)",
    rules.AUDITOR_NOT_LIVE: "the auditor's right is not in force now",
    rules.ACCESS_ENDED: "the case's access has ended",
    rules.NOT_STARTED: "the case's access has not started",
    rules.NOT_ACTIVE: "the case is not active",
    rules.BAD_PURPOSE: "choose what the case is for",
    rules.BAD_BASIS: "choose the case's legal basis",
    rules.NO_LIA_REFERENCE: "legitimate interests need the reference of the balancing test",
    rules.SHORT_JUSTIFICATION: f"the justification needs at least {rules.JUSTIFICATION_MIN} characters",
    rules.NO_OWNER_NOTE: "write the note the vaults' owners read",
    rules.NO_ART9_CONDITION: "special-category data needs the condition of Art. 9(2) the case rests on",
    rules.BAD_ART9_CONDITION: "that is not a condition of Art. 9(2) a case may rest on",
    rules.NO_SCOPE: "say which vaults, folders or people the case covers",
    rules.BAD_SCOPE_KIND: "a case covers vaults, folders and custodians only",
    rules.NO_SUCH_VAULT: "one of those vaults does not exist",
    rules.NO_SUCH_FOLDER: "one of those folders does not exist",
    rules.NO_SUCH_PERSON: "one of those people does not exist",
    rules.NO_VAULTS: "the case covers no vault",
    rules.TOO_MANY_VAULTS: "that is more vaults than one case may cover (COMPLIANCE_MAX_CASE_VAULTS)",
    rules.TOO_MANY_CASES: f"an auditor may have at most {rules.MAX_OPEN_CASES} cases open at a time",
    rules.AUDITOR_CONCERNED: "the case concerns you: an auditor does not investigate themselves",
    rules.BAD_DAYS: "say for how many days access is needed",
    rules.TOO_LONG: "that is longer than a case may give (COMPLIANCE_MAX_ACCESS_DAYS, COMPLIANCE_MAX_TOTAL_DAYS)",
    rules.BAD_RANGE: "the range of files ends before it starts",
    rules.PASSWORD_VAULT_REFUSED: "this deployment keeps vaults with a password out of cases",
    rules.OVERRIDE_NOT_ALLOWED: "this deployment does not let a case open vaults without their password",
    rules.EXPORT_OFF: "exports are turned off on this deployment (COMPLIANCE_EXPORT=disabled)",
    rules.WIDENS: "that covers more than the case does: a wider scope needs a new case and its approval",
    NOT_ALLOWED: "you may not do this for this case",
    EXPIRED: "nobody approved the case in time: it expired",
    VERSION_MISMATCH: "the case changed since you read it: read it again first",
    NO_REASON: "say why",
    NOT_INDEPENDENT_HOST: ("an independent administrator can decide this case, so the server's operator may not: the "
                           "host operator has no account the independence rule could check"),
    NO_OBJECTION: "write the objection",
    SFTP_VERSION: "an SFTP server of another version may be running: a hold cannot be placed now",
}


class CaseRefused(Exception):
    """A step refused: ``reason`` (a code of TEXTS, or of the independence rule), the HTTP status, details."""

    def __init__(self, reason: str, *, code: int = 409, detail: Optional[str] = None):
        super().__init__(reason)
        self.reason, self.code, self.detail = reason, code, detail


def text(reason: Optional[str]) -> str:
    if reason in TEXTS:
        return TEXTS[reason]
    from app.core import legal_holds
    return legal_holds.text(reason)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


def access_enabled() -> bool:
    from app.core import auditor_rights
    return auditor_rights.access_enabled()


def _days(key: str, case) -> int:
    return int(cs.case_value(key, case.settings_at_approval if case is not None else None))


# --------------------------------------------------------------------------- reading

def open_count(db, auditor_id) -> int:
    """The auditor's cases that give or wait to give access."""
    from app.core.models import ComplianceCase
    return (db.query(ComplianceCase).filter(ComplianceCase.auditor_id == auditor_id,
                                            ComplianceCase.status.in_(rules.OPEN)).count())


def vault_rows(db, case, *, covering_only: bool = False) -> list:
    from app.core.models import ComplianceCaseVault
    rows = (db.query(ComplianceCaseVault).filter(ComplianceCaseVault.case_id == case.id)
            .order_by(ComplianceCaseVault.vault_id).all())
    return [r for r in rows if r.folder_ids != []] if covering_only else rows


def scope_map(rows) -> dict:
    """{vault id: None (the whole vault) or a frozenset of folder ids} of a case's vault rows."""
    return {r.vault_id: (None if r.folder_ids is None else frozenset(uuid.UUID(str(f)) for f in r.folder_ids))
            for r in rows}


def _facts(db, vault_id) -> Optional[rules.VaultFacts]:
    from app.core.models import Vault
    row = db.query(Vault.id, Vault.owner_id, Vault.type, Vault.password_hash).filter(Vault.id == vault_id).first()
    if row is None:
        return None
    return rules.VaultFacts(row[0], row[1], row[2] or "standard", row[3] is not None)


def resolve(db, items) -> rules.Resolution:
    """What ``items`` cover, read from the database now."""
    from app.core.models import Folder, User, Vault
    return rules.resolve_scope(
        items, vault=lambda vid: _facts(db, vid),
        folder_vault=lambda fid: db.query(Folder.vault_id).filter(Folder.id == fid).scalar(),
        owned_by=lambda person: [rules.VaultFacts(r[0], r[1], r[2] or "standard", r[3] is not None)
                                 for r in db.query(Vault.id, Vault.owner_id, Vault.type, Vault.password_hash)
                                 .filter(Vault.owner_id == person).order_by(Vault.created_at, Vault.id)],
        person_exists=lambda person: db.query(User.id).filter(User.id == person).first() is not None)


def ancestry(db, folder_id) -> list:
    """A folder's parents toward its vault's root (without itself)."""
    from app.core.models import Folder
    chain, seen = [], set()
    cur = db.query(Folder.parent_folder_id).filter(Folder.id == folder_id).scalar()
    while cur is not None and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = db.query(Folder.parent_folder_id).filter(Folder.id == cur).scalar()
    return chain


def is_admin(user) -> bool:
    from app.core.models import RoleEnum
    return getattr(user, "role", None) == RoleEnum.ADMIN


def is_auditor_of(case, person) -> bool:
    return person is not None and str(getattr(person, "id", "")) == str(case.auditor_id)


def auditor_standing(db, case, now: Optional[datetime] = None):
    """The case's auditor's right as it stands now (auditor_rights.auditor_live), and whether it is still the grant
    the case was asked under."""
    from app.core import auditor_rights
    from app.core.models import User
    auditor = db.get(User, case.auditor_id)
    standing = auditor_rights.auditor_live(db, auditor, now) if auditor is not None else None
    live = bool(standing is not None and standing.live and standing.grant is not None
                and case.grant_id is not None and str(standing.grant.id) == str(case.grant_id))
    return live, standing


def effective_status(db, case, now: Optional[datetime] = None) -> str:
    live, _ = auditor_standing(db, case, now) if case.status == rules.ACTIVE else (True, None)
    return rules.effective_status(case.status, access_enabled=access_enabled(), auditor_live=live)


def approver_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why the administrator ``person`` may not approve, turn down, extend or close ``case`` as the independent
    second person, or None (app/core/case_eligibility.py)."""
    from app.core import case_eligibility
    if not is_admin(person):
        return NOT_ALLOWED
    return case_eligibility.approver_refusal(db, case, person, now)


def independent_approvers(db, case, now: Optional[datetime] = None) -> list:
    from app.core import case_eligibility
    return case_eligibility.independent_approvers(db, case, now)


# --------------------------------------------------------------------------- recording and telling

def _audit(db, action: str, case, *, actor=None, actor_name: Optional[str] = None, status: str = "success",
           details: Optional[dict] = None) -> None:
    """The step's audit row, in the caller's transaction, under the case."""
    from app.services.audit_logger import AuditLogger
    with acting_for(case.id):
        db.add(AuditLogger(db).build_row(
            action=action, status=status, user=actor, username=None if actor is not None else actor_name,
            resource_type="case", resource_id=str(case.id),
            details={"case_number": case.number, **(details or {})}))


def record_refusal(db, action: str, case, *, actor, reason: str) -> None:
    """Record a refused step on its own (its work rolled back first). Never raises."""
    from app.core import legal_holds
    legal_holds.record_refusal(db, action, case, actor=actor, reason=reason)


_NOTICES = "compliance_case_notices"


def _tell(db, people: Iterable, title: str, body: str) -> None:
    """Tell ``people`` (ids) in the app once the transaction commits; nothing when it rolls back. Never the
    justification, a vault, file or folder name, or a person named."""
    ids = [str(p) for p in dict.fromkeys(str(x) for x in people if x)]
    if ids:
        after_commit.later(db, _NOTICES, {"people": ids, "title": title, "body": body})


def _deliver(notices) -> None:
    try:
        from app.api import api_server as api
        for notice in notices:
            api._notify_users(notice["people"], NOTICE_TYPE, title=notice["title"], body=notice["body"], target=TARGET)
    except Exception as exc:  # noqa: BLE001 -- a notice never undoes the step
        print(f"Warning: a compliance case notice was not sent ({type(exc).__name__})")


after_commit.handler(_NOTICES, _deliver)


def _admins(db) -> list:
    from app.core.models import RoleEnum, User
    return [r[0] for r in db.query(User.id).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True))]


def reference(case) -> str:
    return case.number or str(case.id).replace("-", "")[:8]


def _who(name: Optional[str]) -> str:
    return "the server's operator" if name == HOST_OPERATOR else (name or "an administrator")


# --------------------------------------------------------------------------- asking

def _clean(value) -> str:
    return (value or "").strip() if isinstance(value, str) else ""


def _as_ids(values, reason: str) -> list:
    out = []
    for v in values or ():
        vid = rules.as_id(v)
        if vid is None:
            raise CaseRefused(reason, code=404)
        if vid not in out:
            out.append(vid)
    return out


def request_case(db, auditor, *, purpose, legal_basis, justification, owner_note, scope, lia_reference=None,
                 special_category: bool = False, art9_condition=None, criminal_offence: bool = False,
                 named_user_ids=(), files_from: Optional[datetime] = None, files_to: Optional[datetime] = None,
                 access_days: Optional[int] = None, can_export: bool = False, password_override: bool = False,
                 hold: Optional[bool] = None, now: Optional[datetime] = None):
    """Ask for a case as ``auditor`` (whose right the caller found in force), in the caller's transaction. Returns
    the pending case. Raises CaseRefused."""
    from app.core import auditor_rights
    from app.core.models import (ComplianceCase, ComplianceCasePerson, ComplianceCaseScope, ComplianceCaseVault,
                                 User)
    from app.core.security import seal_case_field
    now = now or utcnow()
    if not access_enabled():
        raise CaseRefused(rules.ACCESS_OFF)
    standing = auditor_rights.auditor_live(db, auditor, now)
    if not standing.live:
        raise CaseRefused(rules.AUDITOR_NOT_LIVE, code=403)
    problems = rules.text_problems(purpose=purpose, legal_basis=legal_basis, lia_reference=lia_reference,
                                   justification=justification, owner_note=owner_note,
                                   special_category=bool(special_category), art9_condition=art9_condition)
    if problems:
        raise CaseRefused(problems[0], code=422)
    why = rules.range_refusal(files_from, files_to)
    if why:
        raise CaseRefused(why, code=422)
    days = rules.DEFAULT_ACCESS_DAYS if access_days is None else access_days
    why = rules.access_days_refusal(days, int(cs.current(cs.MAX_ACCESS_DAYS)))
    if why:
        raise CaseRefused(why, code=422)
    for why in (rules.export_refusal(bool(can_export), cs.current(cs.EXPORT)),
                rules.override_refusal(bool(password_override), cs.current(cs.PASSWORD_VAULTS))):
        if why:
            raise CaseRefused(why, code=409)
    why = rules.open_cases_refusal(open_count(db, auditor.id))
    if why:
        raise CaseRefused(why, code=409)
    try:
        items = rules.parse_scope(scope)
        resolution = resolve(db, items)
    except rules.CaseRuleRefused as refused:
        code = 404 if refused.reason in (rules.NO_SUCH_VAULT, rules.NO_SUCH_FOLDER, rules.NO_SUCH_PERSON) else 422
        raise CaseRefused(refused.reason, code=code)
    why = rules.vault_count_refusal(len(resolution.vaults), int(cs.current(cs.MAX_CASE_VAULTS)))
    if why:
        raise CaseRefused(why, code=422)
    named = _as_ids(named_user_ids, rules.NO_SUCH_PERSON)
    for person in named:
        if db.query(User.id).filter(User.id == person).first() is None:
            raise CaseRefused(rules.NO_SUCH_PERSON, code=404)
    concerned = rules.persons_concerned(resolution, named)
    why = rules.auditor_refusal(auditor.id, concerned)
    if why:
        raise CaseRefused(why, code=403)
    policy = rules.password_policy(None, cs.current(cs.PASSWORD_VAULTS), override_requested=bool(password_override))
    for vid in resolution.vaults:
        why = rules.password_vault_refusal(policy, resolution.facts[vid].has_password)
        if why:
            raise CaseRefused(why, code=409)

    case = ComplianceCase(
        id=uuid.uuid4(), status=rules.PENDING, purpose=purpose, legal_basis=legal_basis,
        lia_reference=_clean(lia_reference)[:255] or None, special_category=bool(special_category),
        art9_condition=(art9_condition or None) if special_category else None,
        criminal_offence=bool(criminal_offence), justification_enc="", owner_note_enc="", auditor_id=auditor.id,
        auditor_username=auditor.username, grant_id=standing.grant.id, requested_at=now, access_days=days,
        hold_requested=rules.hold_by_default(purpose) if hold is None else bool(hold), can_export=bool(can_export),
        password_override=bool(password_override), files_from=files_from, files_to=files_to, created_at=now,
        updated_at=now, version=1)
    case.justification_enc = seal_case_field(case.id, _clean(justification)[:rules.TEXT_MAX], "justification")
    case.owner_note_enc = seal_case_field(case.id, _clean(owner_note)[:rules.TEXT_MAX], "owner_note")
    db.add(case)
    db.flush()
    for item in items:
        db.add(ComplianceCaseScope(case_id=case.id, kind=item.kind, target_id=item.target_id))
    for vid, folders in resolution.vaults.items():
        facts = resolution.facts[vid]
        db.add(ComplianceCaseVault(case_id=case.id, vault_id=vid, vault_type_at_approval=facts.type,
                                   folder_ids=None if folders is None else sorted(str(f) for f in folders),
                                   owner_id_at_approval=facts.owner_id))
    for person, why_concerned in concerned.items():
        db.add(ComplianceCasePerson(case_id=case.id, user_id=person, why=why_concerned))
    db.flush()
    _audit(db, "case_requested", case, actor=auditor,
           details={"purpose": purpose, "vaults": len(resolution.vaults), "days": days,
                    "hold": case.hold_requested})
    approvers = [a.id for a in independent_approvers(db, case, now)]
    _tell(db, approvers or _admins(db), "A case waits for approval",
          f"{auditor.username} asked for case {reference(case)} ({len(resolution.vaults)} vault"
          f"{'' if len(resolution.vaults) == 1 else 's'}, {days} days). "
          + ("An independent administrator approves or turns it down on the Compliance page."
             if approvers else "No administrator can approve it: the server's operator decides on the host."))
    return case


# --------------------------------------------------------------------------- approving and turning down

def check_version(case, if_match) -> None:
    """Refuse (412) a step on a case that changed since the caller read it: ``if_match`` is the version it read."""
    if if_match is None or str(if_match).strip() == "":
        raise CaseRefused(VERSION_MISMATCH, code=428)
    digits = "".join(ch for ch in str(if_match) if ch.isdigit())
    if not digits or int(digits) != int(case.version or 1):
        raise CaseRefused(VERSION_MISMATCH, code=412)


def decision_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``person`` (None: the server's operator) may not approve or turn down ``case`` now, or None."""
    now = now or utcnow()
    if rules.step_refusal(case.status, rules.APPROVE):
        return rules.NOT_NOW
    if rules.pending_expired(case.requested_at, now):
        return EXPIRED
    if person is None:
        return NOT_INDEPENDENT_HOST if independent_approvers(db, case, now) else None
    return approver_refusal(db, case, person, now)


def _refresh_owners(db, case) -> None:
    """Read each vault's owner again at the approval: a vault that changed hands concerns its new owner. A vault
    gone since the request covers nothing."""
    from app.core.models import ComplianceCasePerson
    people = {str(p.user_id) for p in db.query(ComplianceCasePerson).filter(ComplianceCasePerson.case_id == case.id)}
    for row in vault_rows(db, case, covering_only=True):
        facts = _facts(db, row.vault_id)
        if facts is None:
            row.folder_ids = []
            continue
        row.owner_id_at_approval, row.vault_type_at_approval = facts.owner_id, facts.type
        if facts.owner_id is not None and str(facts.owner_id) not in people:
            db.add(ComplianceCasePerson(case_id=case.id, user_id=facts.owner_id, why="owner"))
            people.add(str(facts.owner_id))
    db.flush()


def _owner_counts(db, case, rows, *, hold: bool) -> dict:
    """{owner: {vaults, zero_knowledge, with_password, hold}} of ``rows``."""
    out = {}
    for row in rows:
        if row.owner_id_at_approval is None:
            continue
        facts = _facts(db, row.vault_id)
        c = out.setdefault(str(row.owner_id_at_approval), {"vaults": 0, "zero_knowledge": 0, "with_password": 0,
                                                           "hold": hold})
        c["vaults"] += 1
        c["zero_knowledge"] += 1 if row.vault_type_at_approval == "zero_knowledge" else 0
        c["with_password"] += 1 if facts is not None and facts.has_password else 0
    return out


def approve(db, case, *, approver=None, now: Optional[datetime] = None):
    """Approve ``case`` as ``approver`` (None: the server's operator), in the caller's transaction, the case locked
    by the caller. Everything the approval gives, and every owner's notice of it, is written here or nothing is.
    Raises CaseRefused."""
    from app.core import case_numbers, legal_holds
    from app.core.models import LegalHoldVault
    now = now or utcnow()
    if not access_enabled():
        raise CaseRefused(rules.ACCESS_OFF)
    why = decision_refusal(db, case, approver, now)
    if why:
        raise CaseRefused(why, code=403 if why not in (rules.NOT_NOW, EXPIRED, NOT_INDEPENDENT_HOST) else 409)
    live, _standing = auditor_standing(db, case, now)
    if not live:
        raise CaseRefused(rules.AUDITOR_NOT_LIVE)
    if case.hold_requested:
        # The holds must cover every deletion that commits after them: wait for a deletion that holds a vault's
        # row (every deleting path takes it FOR NO KEY UPDATE), each row in id order as placing a hold does. The
        # owners are read below, after the wait; a vault deleted meanwhile is gone there and covers nothing.
        legal_holds._lock_vaults(db, [row.vault_id for row in vault_rows(db, case, covering_only=True)],
                                 missing_ok=True)
    _refresh_owners(db, case)
    if approver is not None:
        why = approver_refusal(db, case, approver, now)   # again, now that the owners are read afresh
        if why:
            raise CaseRefused(why, code=403)
    rows = vault_rows(db, case, covering_only=True)
    why = rules.vault_count_refusal(len(rows), int(cs.current(cs.MAX_CASE_VAULTS)))
    if why:
        raise CaseRefused(why)
    current_policy = cs.current(cs.PASSWORD_VAULTS)
    for why in (rules.override_refusal(case.password_override, current_policy),
                rules.export_refusal(case.can_export, cs.current(cs.EXPORT)),
                rules.access_days_refusal(case.access_days, int(cs.current(cs.MAX_ACCESS_DAYS)))):
        if why:
            raise CaseRefused(why)
    policy = rules.password_policy(None, current_policy, override_requested=case.password_override)
    for row in rows:
        facts = _facts(db, row.vault_id)
        why = rules.password_vault_refusal(policy, bool(facts and facts.has_password))
        if why:
            raise CaseRefused(why)
    if case.hold_requested:
        try:
            legal_holds.sftp_guard(db)
        except legal_holds.HoldRefused as refused:
            raise CaseRefused(SFTP_VERSION, detail=refused.detail)

    name = approver.username if approver is not None else HOST_OPERATOR
    case.number = case_numbers.allocate(db, now)
    case.status = rules.ACTIVE
    case.approved_by = approver.id if approver is not None else None
    case.approved_by_username, case.approved_by_operator, case.approved_at = name, approver is None, now
    case.settings_at_approval = cs.snapshot()
    case.password_policy = policy
    case.access_starts_at, case.access_ends_at = rules.access_window(now, case.access_days)
    case.total_access_days = case.access_days
    case.version = (case.version or 1) + 1
    case.updated_at = now
    db.flush()
    _audit(db, "case_approved", case, actor=approver, actor_name=name,
           details={"vaults": len(rows), "days": case.access_days, "hold": case.hold_requested,
                    "by_operator": approver is None})
    if case.hold_requested:
        for row in rows:
            db.add(LegalHoldVault(case_id=case.id, vault_id=row.vault_id, placed_by=case.auditor_id,
                                  placed_by_username=case.auditor_username, placed_at=now,
                                  confirmed_by=case.approved_by, confirmed_by_username=name, confirmed_at=now))
            legal_holds._audit(db, "hold_placed", case, actor_name=case.auditor_username, vault_id=row.vault_id,
                               details={"by_approval": True})
            legal_holds._audit(db, "hold_confirmed", case, actor=approver, actor_name=name, vault_id=row.vault_id,
                               details={"by_approval": True})
        db.flush()
        legal_holds._sync_marker(db)
    for row in rows:
        row.notice_written_at = now
    owner_notices.tell_owners(db, case, owner_notices.ACTIVATION, _owner_counts(db, case, rows,
                                                                               hold=case.hold_requested), now=now)
    case.notice_written_at = now
    _tell(db, [case.auditor_id] + _admins(db), "Case approved",
          f"{_who(name)} approved case {case.number}: {case.auditor_username} can open {len(rows)} vault"
          f"{'' if len(rows) == 1 else 's'} until {case.access_ends_at:%Y-%m-%d %H:%M} UTC. Their owners were told.")
    return case


def reject(db, case, *, by=None, reason: str, now: Optional[datetime] = None):
    """Turn ``case`` down as ``by`` (None: the server's operator), with ``reason`` (the auditor reads it), in the
    caller's transaction. Raises CaseRefused."""
    from app.core.security import seal_case_field
    now = now or utcnow()
    if not _clean(reason):
        raise CaseRefused(NO_REASON, code=422)
    why = decision_refusal(db, case, by, now)
    if why:
        raise CaseRefused(why, code=403 if why not in (rules.NOT_NOW, EXPIRED, NOT_INDEPENDENT_HOST) else 409)
    name = by.username if by is not None else HOST_OPERATOR
    case.status = rules.REJECTED
    case.rejected_by, case.rejected_by_username = getattr(by, "id", None), name
    case.reject_reason_enc = seal_case_field(case.id, _clean(reason)[:rules.TEXT_MAX], "reject_reason")
    _finish(case, now, by=by, name=name)
    _audit(db, "case_rejected", case, actor=by, actor_name=name)
    _tell(db, [case.auditor_id], "Case turned down",
          f"{_who(name)} turned down case {reference(case)}. The reason is on the Compliance page.")
    return case


def _finish(case, now: datetime, *, by=None, name: Optional[str] = None) -> None:
    """A case reaching a final state: when, by whom, and until when its records are kept."""
    case.closed_at = now
    case.closed_by = getattr(by, "id", None)
    case.closed_by_username = name
    case.records_kept_until = now + timedelta(days=_days(cs.RECORD_MIN_DAYS, case))
    case.version = (case.version or 1) + 1
    case.updated_at = now


def withdraw(db, case, *, by, now: Optional[datetime] = None):
    """The auditor withdraws ``case`` while it waits. Raises CaseRefused."""
    now = now or utcnow()
    if not is_auditor_of(case, by):
        raise CaseRefused(NOT_ALLOWED, code=403)
    if rules.step_refusal(case.status, rules.WITHDRAW):
        raise CaseRefused(rules.NOT_NOW)
    case.status = rules.WITHDRAWN
    _finish(case, now, by=by, name=by.username)
    _audit(db, "case_withdrawn", case, actor=by)
    return case


# --------------------------------------------------------------------------- extending

def extend_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    now = now or utcnow()
    if rules.step_refusal(case.status, rules.EXTEND):
        return rules.NOT_NOW
    if not access_enabled():
        return rules.ACCESS_OFF
    if not rules.access_open(case.access_starts_at, case.access_ends_at, now):
        return rules.ACCESS_ENDED
    return approver_refusal(db, case, person, now)


def extend(db, case, *, by, days, now: Optional[datetime] = None):
    """Extend ``case``'s access by ``days`` as the independent administrator ``by``, in the caller's transaction
    (the case locked by the caller): within the period and total ceilings, the stricter of the values at its
    approval and now. The owners are told in the same transaction. Raises CaseRefused."""
    now = now or utcnow()
    why = extend_refusal(db, case, by, now)
    if why:
        raise CaseRefused(why, code=403 if why not in (rules.NOT_NOW, rules.ACCESS_OFF, rules.ACCESS_ENDED) else 409)
    live, _ = auditor_standing(db, case, now)
    if not live:
        raise CaseRefused(rules.AUDITOR_NOT_LIVE)
    try:
        new_end, total = rules.extension(case.access_starts_at, case.access_ends_at, days, now=now,
                                         max_access_days=_days(cs.MAX_ACCESS_DAYS, case),
                                         max_total_days=_days(cs.MAX_TOTAL_DAYS, case))
    except rules.CaseRuleRefused as refused:
        raise CaseRefused(refused.reason, code=422 if refused.reason in (rules.BAD_DAYS, rules.TOO_LONG) else 409)
    case.access_ends_at, case.total_access_days = new_end, total
    case.version = (case.version or 1) + 1
    case.updated_at = now
    _audit(db, "case_extended", case, actor=by, details={"days": days, "ends_at": _iso(new_end)})
    rows = vault_rows(db, case, covering_only=True)
    owner_notices.tell_owners(db, case, owner_notices.EXTENSION, _owner_counts(db, case, rows, hold=False),
                              now=now, details={"by": by.username, "ends_at": new_end})
    _tell(db, [case.auditor_id], "Case extended",
          f"{by.username} extended case {case.number} until {new_end:%Y-%m-%d %H:%M} UTC.")
    return case


# --------------------------------------------------------------------------- narrowing

def narrow_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    if rules.step_refusal(case.status, rules.NARROW):
        return rules.NOT_NOW
    if is_auditor_of(case, person):
        return None
    return approver_refusal(db, case, person, now)


def narrow(db, case, *, by, scope, files_from=None, files_to=None, keep_range: bool = True,
           now: Optional[datetime] = None):
    """Narrow ``case`` to ``scope`` (and the time range), with no approval, as its auditor or an independent
    administrator, in the caller's transaction (the case locked). Anything wider is refused (WIDENS). A vault left
    out covers nothing from then on and, once the case is active, its owner is told; a hold on it stays. Raises
    CaseRefused."""
    from app.core.models import ComplianceCaseScope
    now = now or utcnow()
    why = narrow_refusal(db, case, by, now)
    if why:
        raise CaseRefused(why, code=409 if why == rules.NOT_NOW else 403)
    try:
        items = rules.parse_scope(scope)
        new = resolve(db, items).vaults
    except rules.CaseRuleRefused as refused:
        code = 404 if refused.reason in (rules.NO_SUCH_VAULT, rules.NO_SUCH_FOLDER, rules.NO_SUCH_PERSON) else 422
        raise CaseRefused(refused.reason, code=code)
    rows = vault_rows(db, case)
    old = scope_map(rows)
    why = rules.narrowing_refusal(old, new, ancestry=lambda f: ancestry(db, f))
    if why:
        raise CaseRefused(why)
    if keep_range:
        files_from, files_to = case.files_from, case.files_to
    why = rules.time_narrowing_refusal(case.files_from, case.files_to, files_from, files_to)
    if why:
        raise CaseRefused(why, code=409 if why == rules.WIDENS else 422)
    after = rules.narrowed(old, new)
    removed = []
    for row in rows:
        covers = after[row.vault_id]
        before = row.folder_ids
        row.folder_ids = None if covers is None else sorted(str(f) for f in covers)
        if before != [] and row.folder_ids == []:
            removed.append(row)
    case.files_from, case.files_to = files_from, files_to
    db.query(ComplianceCaseScope).filter(ComplianceCaseScope.case_id == case.id).delete(synchronize_session=False)
    for item in items:
        db.add(ComplianceCaseScope(case_id=case.id, kind=item.kind, target_id=item.target_id))
    case.version = (case.version or 1) + 1
    case.updated_at = now
    db.flush()
    _audit(db, "case_scope_narrowed", case, actor=by,
           details={"vaults": sum(1 for r in rows if r.folder_ids != []), "removed": len(removed)})
    if removed and case.status != rules.PENDING:
        owner_notices.tell_owners(db, case, owner_notices.SCOPE_REMOVED,
                                  _owner_counts(db, case, removed, hold=False), now=now)
    return case


# --------------------------------------------------------------------------- objections

def owns_a_vault_in(db, case, person) -> bool:
    """Whether ``person`` owns a vault of ``case`` and was told of it: a case nobody approved yet, or that told
    others only, does not exist for them."""
    from app.core.models import ComplianceCaseVault
    return db.query(ComplianceCaseVault).filter(ComplianceCaseVault.case_id == case.id,
                                                ComplianceCaseVault.owner_id_at_approval == person.id,
                                                ComplianceCaseVault.notice_written_at.isnot(None)).first() is not None


def objection_refusal(db, case, person) -> Optional[str]:
    """Why ``person`` may not record an objection on ``case``, or None: an owner of one of its vaults, or an
    administrator recording one for an owner."""
    if rules.step_refusal(case.status, rules.OBJECTION):
        return rules.NOT_NOW
    if is_admin(person) or owns_a_vault_in(db, case, person):
        return None
    return NOT_ALLOWED


def objections(case) -> list:
    """The objections recorded on ``case``, opened: [{by, as, at, text}]."""
    from app.core.security import is_case_sealed, open_case_field
    if not is_case_sealed(case.objection_enc):
        return []
    try:
        entries = json.loads(open_case_field(case.id, case.objection_enc, "objection"))
    except Exception:  # noqa: BLE001 -- a record that does not open is shown as such, never as text
        return [{"by": None, "as": None, "at": None, "text": None, "unreadable": True}]
    return entries if isinstance(entries, list) else []


def record_objection(db, case, *, by, text_: str, now: Optional[datetime] = None):
    """Record an owner's objection on ``case`` (by the owner, or by an administrator for them), sealed with the case.
    Whoever extends the case reads it. Raises CaseRefused."""
    from app.core.security import seal_case_field
    now = now or utcnow()
    why = objection_refusal(db, case, by)
    if why:
        raise CaseRefused(why, code=409 if why == rules.NOT_NOW else 403)
    body = _clean(text_)
    if not body:
        raise CaseRefused(NO_OBJECTION, code=422)
    entries = [e for e in objections(case) if not e.get("unreadable")]
    as_owner = owns_a_vault_in(db, case, by)
    entries.append({"by": by.username, "as": "owner" if as_owner else "administrator", "at": _iso(now),
                    "text": body[:OBJECTION_MAX]})
    case.objection_enc = seal_case_field(case.id, json.dumps(entries), "objection")
    case.version = (case.version or 1) + 1
    case.updated_at = now
    _audit(db, "case_objection_recorded", case, actor=by, details={"by_owner": as_owner})
    _tell(db, [a for a in _admins(db) if str(a) != str(by.id)] + [case.auditor_id], "Objection recorded",
          f"An objection was recorded on case {reference(case)}. Whoever extends the case reads it first.")
    return case


# --------------------------------------------------------------------------- closing and the clock

def close_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``person`` may not close ``case`` now, or None: its auditor (while they stand as they did, when a hold
    stands: closing releases it), or an independent administrator."""
    from app.core import legal_holds
    now = now or utcnow()
    if rules.step_refusal(case.status, rules.CLOSE):
        return rules.NOT_NOW
    if is_auditor_of(case, person):
        return legal_holds.starter_refusal(db, case, person, now) if legal_holds.standing(db, case.id) else None
    return approver_refusal(db, case, person, now)


def _counts_since_approval(db, case) -> tuple:
    """(files opened, exports) under the case: its audit rows of each kind."""
    from sqlalchemy import func
    from app.core.models import AuditLog
    opened = (db.query(func.count(func.distinct(AuditLog.resource_id)))
              .filter(AuditLog.case_id == case.id, AuditLog.action == "case_file_viewed",
                      AuditLog.status == "success").scalar() or 0)
    exports = (db.query(func.count(AuditLog.id))
               .filter(AuditLog.case_id == case.id, AuditLog.action == "case_export_completed",
                       AuditLog.status == "success").scalar() or 0)
    return int(opened), int(exports)


def _summary_counts(db, case, *, held: set) -> dict:
    opened, exports = _counts_since_approval(db, case)
    rows = vault_rows(db, case)
    counts = {}
    for row in rows:
        if row.owner_id_at_approval is None or row.notice_written_at is None:
            continue
        c = counts.setdefault(str(row.owner_id_at_approval), {"vaults": 0, "hold": False, "files_opened": opened,
                                                              "exports": exports})
        c["vaults"] += 1
        c["hold"] = c["hold"] or row.vault_id in held
    return counts


def close(db, case, *, by, reason: str, now: Optional[datetime] = None):
    """Close ``case`` as ``by`` with ``reason``, in the caller's transaction (the case locked): its holds are
    released (their purge waits as for any release) and the owners are told with a summary. A case that only
    holds is closed by releasing its hold. Raises CaseRefused."""
    from app.core import legal_holds
    from app.core.security import seal_case_field
    now = now or utcnow()
    if not _clean(reason):
        raise CaseRefused(NO_REASON, code=422)
    why = close_refusal(db, case, by, now)
    if why:
        raise CaseRefused(why, code=409 if why == rules.NOT_NOW else 403)
    if case.status == rules.HOLD_ONLY:
        legal_holds.release(db, case, by=by, reason=_clean(reason), now=now)
        return case
    if legal_holds.standing(db, case.id):
        legal_holds.release(db, case, by=by, reason=_clean(reason), now=now, tell_owners=False)
    case.status = rules.CLOSED
    case.close_reason_enc = seal_case_field(case.id, _clean(reason)[:rules.TEXT_MAX], "close_reason")
    _finish(case, now, by=by, name=by.username)
    _audit(db, "case_closed", case, actor=by)
    owner_notices.tell_owners(db, case, owner_notices.CLOSED, _summary_counts(db, case, held=set()), now=now,
                              details={"by": by.username})
    _tell(db, [case.auditor_id] + _admins(db), "Case closed", f"{by.username} closed case {reference(case)}.")
    return case


def expire_pending(db, now: Optional[datetime] = None) -> int:
    """Cases nobody approved within PENDING_DAYS expire. Returns how many."""
    from app.core.models import ComplianceCase
    now = now or utcnow()
    count = 0
    for case in (db.query(ComplianceCase).filter(ComplianceCase.status == rules.PENDING)
                 .with_for_update(skip_locked=True).all()):
        if not rules.pending_expired(case.requested_at, now):
            continue
        case.status = rules.EXPIRED_UNAPPROVED
        _finish(case, now, name=SYSTEM)
        _audit(db, "case_expired_unapproved", case, actor_name=SYSTEM)
        _tell(db, [case.auditor_id], "Case expired",
              f"Nobody approved case {reference(case)} within {rules.PENDING_DAYS} days, so it expired.")
        count += 1
    return count


def end_due(db, now: Optional[datetime] = None) -> int:
    """Access that reached its end: the case closes, or keeps only its legal hold while one stands; the owners are
    told with a summary. Returns how many cases."""
    from app.core import legal_holds
    from app.core.models import ComplianceCase
    now = now or utcnow()
    count = 0
    for case in (db.query(ComplianceCase).filter(ComplianceCase.status.in_((rules.ACTIVE, rules.SUSPENDED)),
                                                 ComplianceCase.access_ends_at <= now)
                 .with_for_update(skip_locked=True).all()):
        held = {h.vault_id for h in legal_holds.standing(db, case.id)}
        after = rules.next_status(case.status, rules.END_ACCESS, hold_stands=bool(held))
        _audit(db, "case_access_ended", case, actor_name=SYSTEM, details={"hold_only": after == rules.HOLD_ONLY})
        if after == rules.HOLD_ONLY:
            case.status = rules.HOLD_ONLY
            case.version = (case.version or 1) + 1
            case.updated_at = now
        else:
            case.status = rules.CLOSED
            _finish(case, now, name=SYSTEM)
            _audit(db, "case_closed", case, actor_name=SYSTEM, details={"access_ended": True})
        owner_notices.tell_owners(db, case, owner_notices.ACCESS_ENDED, _summary_counts(db, case, held=held), now=now)
        _tell(db, [case.auditor_id], "Case access ended",
              f"Access under case {case.number} ended" + (": its legal hold stands until it is released."
                                                           if held else "; the case is closed."))
        count += 1
    return count


# --------------------------------------------------------------------------- what a viewer sees

def may_see(case, viewer) -> bool:
    return is_admin(viewer) or is_auditor_of(case, viewer)


def _open(case, column: str, field: str) -> Optional[str]:
    from app.core.security import is_case_sealed, open_case_field
    value = getattr(case, column, None)
    if not is_case_sealed(value):
        return None
    try:
        return open_case_field(case.id, value, field)
    except Exception:  # noqa: BLE001 -- a sealed value that does not open is shown as such, never as text
        return None


def case_view(db, case, viewer, *, now: Optional[datetime] = None, detail: bool = False, light: bool = False) -> dict:
    """``case`` as ``viewer`` (its auditor or an administrator) may see it. The justification only for the auditor
    and an administrator who could approve it; the people named, the reasons it was turned down or closed and the
    owners' objections only for those the case does not concern. Never a vault, file or folder name. ``light`` (a
    list of cases): only what the list shows, without the texts, what each step would allow and the vaults'
    figures, which the case's own page reads."""
    from app.core import auditor_rights as rights
    from app.core import legal_holds
    from app.core.models import ComplianceCasePerson, User
    now = now or utcnow()
    admin = is_admin(viewer)
    own = is_auditor_of(case, viewer)
    eligible = admin and not light and approver_refusal(db, case, viewer, now) is None
    people = db.query(ComplianceCasePerson).filter(ComplianceCasePerson.case_id == case.id).all()
    concerned = any(str(p.user_id) == str(viewer.id) for p in people)
    names = {}
    ids = {p.user_id for p in people} | {r.owner_id_at_approval for r in vault_rows(db, case)}
    for uid, username in db.query(User.id, User.username).filter(User.id.in_([i for i in ids if i is not None])):
        names[uid] = username

    def may(refusal):
        why = refusal(db, case, viewer, now)
        return {"may": why is None, "why_not": None if why is None else {"reason": why, "text": text(why)}}

    vaults = []
    for row in vault_rows(db, case):
        facts = _facts(db, row.vault_id)
        entry = {"vault_id": str(row.vault_id), "type": row.vault_type_at_approval,
                 "covers": "whole" if row.folder_ids is None else ("nothing" if row.folder_ids == [] else "folders"),
                 "folders": len(row.folder_ids or []), "owner": names.get(row.owner_id_at_approval),
                 "exists": facts is not None, "has_password": bool(facts and facts.has_password),
                 "owner_told_at": _iso(row.notice_written_at)}
        if admin and facts is not None and not light:
            entry.update(_vault_numbers(db, row.vault_id))
            entry["you_are_member"] = _is_member(db, viewer, row.vault_id, facts.owner_id)
        vaults.append(entry)
    out = {
        "id": str(case.id), "reference": reference(case), "number": case.number, "status": case.status,
        "effective_status": effective_status(db, case, now), "version": case.version,
        "purpose": case.purpose, "legal_basis": case.legal_basis, "lia_reference": case.lia_reference,
        "special_category": case.special_category, "art9_condition": case.art9_condition,
        "criminal_offence": case.criminal_offence, "auditor": case.auditor_username,
        "requested_at": _iso(case.requested_at),
        "pending_until": _iso(rules.pending_until(case.requested_at)) if case.status == rules.PENDING else None,
        "access_days": case.access_days, "can_export": case.can_export, "password_override": case.password_override,
        "password_policy": case.password_policy, "hold": case.hold_requested,
        "approved_by": case.approved_by_username, "approved_by_operator": case.approved_by_operator,
        "approved_at": _iso(case.approved_at), "access_starts_at": _iso(case.access_starts_at),
        "access_ends_at": _iso(case.access_ends_at), "total_access_days": case.total_access_days,
        "files_from": _iso(case.files_from), "files_to": _iso(case.files_to),
        "owners_told": {"at": _iso(case.notice_written_at), "email": case.notice_email_status},
        "closed_at": _iso(case.closed_at), "closed_by": case.closed_by_username, "vaults": vaults,
        "holds_standing": len(legal_holds.standing(db, case.id)),
    }
    if light:
        return out
    out["you_may"] = {"approve": may(lambda d, c, p, n: decision_refusal(d, c, p, n) if admin else NOT_ALLOWED),
                    "reject": may(lambda d, c, p, n: decision_refusal(d, c, p, n) if admin else NOT_ALLOWED),
                    "extend": may(extend_refusal), "narrow": may(narrow_refusal), "close": may(close_refusal),
                    "withdraw": may(lambda d, c, p, n: (None if is_auditor_of(c, p) and c.status == rules.PENDING
                                                        else NOT_ALLOWED)),
                    "objection": may(lambda d, c, p, n: objection_refusal(d, c, p))}
    if own or eligible:
        out["justification"] = _open(case, "justification_enc", "justification")
    if own or admin:
        out["owner_note"] = _open(case, "owner_note_enc", "owner_note")
    # The people named, and free text that may name whom the case is about: never to an administrator the case
    # concerns, who sees it only as an owner does.
    if own or (admin and not concerned):
        out["reject_reason"] = _open(case, "reject_reason_enc", "reject_reason")
        out["close_reason"] = _open(case, "close_reason_enc", "close_reason")
        out["objections"] = objections(case)
        out["people"] = [{"user_id": str(p.user_id), "username": names.get(p.user_id), "why": p.why}
                         for p in sorted(people, key=lambda p: (p.why, str(p.user_id)))]
    if admin and detail:
        auditor = db.get(User, case.auditor_id)
        out["auditor_provenance"] = rights.provenance(db, auditor)
        grant = rights.grant_by_id(db, case.grant_id) if case.grant_id is not None else None
        out["grant"] = ({"id": str(grant.id), "proposed_by": grant.proposed_by_username,
                         "approved_by": grant.approved_by_username, "approved_at": _iso(grant.approved_at)}
                        if grant is not None else None)
        out["auditor_open_cases"] = open_count(db, case.auditor_id)
        out["independent_approvers"] = [a.username for a in independent_approvers(db, case, now)] \
            if case.status == rules.PENDING else []
    return out


def _vault_numbers(db, vault_id) -> dict:
    from app.core.models import Vault
    row = db.query(Vault.file_count, Vault.total_size_bytes, Vault.created_at).filter(Vault.id == vault_id).first()
    return {"file_count": int(row[0] or 0), "bytes": int(row[1] or 0), "created_at": _iso(row[2])} if row else {}


def _is_member(db, person, vault_id, owner_id) -> bool:
    """Whether ``person`` can open the vault themselves: an approver is told when they can open a vault of the case themselves."""
    from app.core.authorization import PermissionService
    if owner_id is not None and str(owner_id) == str(person.id):
        return True
    try:
        return PermissionService(db).get_vault_permissions(person, vault_id) is not None
    except Exception:  # noqa: BLE001 -- unknown membership is said as none
        return False


# --------------------------------------------------------------------------- the host

def _host_approve(db, case, *, reason=None):
    """dockvault.py cases approve: the server's operator approves, only when no administrator could."""
    from app.core.host_operator import _refuse
    try:
        approve(db, case, approver=None)
    except CaseRefused as refused:
        record_refusal(db, "case_approved", case, actor=None, reason=refused.reason)
        return _refuse(text(refused.reason).capitalize() + "." + (f" {refused.detail}" if refused.detail else ""))
    return {"id": str(case.id), "number": case.number, "status": case.status,
            "access_ends_at": _iso(case.access_ends_at)}


def _host_reject(db, case, *, reason=None):
    """dockvault.py cases reject: the server's operator turns the case down, only when no administrator could."""
    from app.core.host_operator import _refuse
    try:
        reject(db, case, by=None, reason=reason or "")
    except CaseRefused as refused:
        record_refusal(db, "case_rejected", case, actor=None, reason=refused.reason)
        return _refuse(text(refused.reason).capitalize() + ".")
    return {"id": str(case.id), "status": case.status}


def _register_host_steps() -> None:
    from app.core import host_compliance
    host_compliance.register_case_step("approve", _host_approve)
    host_compliance.register_case_step("reject", _host_reject)


_register_host_steps()
