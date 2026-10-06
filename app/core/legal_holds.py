"""Legal holds: placing one, its confirmation by a second person, the lapse of one nobody confirmed, the review
prompt, releasing it and undoing a release, and the purge of what a released hold kept.

A hold keeps what is deleted from a vault: while a row of ``legal_hold_vaults`` stands for the vault (placed,
neither released nor lapsed), the database copies every file and folder row deleted from it into the kept tables
and the blob stays on disk (app/core/kept_tables.py). A hold preserves; it does not freeze use: members keep
reading, uploading and deleting, and for them a deletion is done.

Placing. A hold-only case (no content, no names: counts and sizes only) is placed by a live auditor or an
administrator who is not a person the case concerns (an owner of one of its vaults), with the compliance
step-up, and takes effect at once: each vault's row is locked FOR UPDATE first, which waits for a deletion that
holds the vault's row lock, so the hold covers every deletion that commits after it. It is refused while an SFTP
server of another version may run (sftp_guard): an older SFTP server's own delete would destroy the blob the
trigger keeps the row of. The owner of each vault is told in the placing transaction; the administrators after it.

Confirming. A different person, independent of the one who placed it by the one rule every two-person step uses
(app/core/independence.py), confirms it within COMPLIANCE_HOLD_CONFIRM_DAYS, or the server's operator does on the
host. Unconfirmed, it lapses: it keeps nothing more, what it kept follows the release path, and the person who
placed it cannot place another unconfirmed hold on any of those vaults for PLACE_BLOCK_DAYS (another person can).
So one person cannot keep deleted data for ever with rolling holds.

Reviewing. Every COMPLIANCE_HOLD_REVIEW_DAYS the case's auditor and the administrators are asked whether the hold
is still needed; answering records ``hold_reviewed``. Nothing is released by the clock: that would destroy evidence.

Releasing. The case's auditor or an independent administrator releases a case's holds, with a reason. What they
kept is purged COMPLIANCE_HOLD_PURGE_DELAY_DAYS later; until then an independent administrator can undo the
release, which restores the same holds with their confirmation. A hold-only case closes when its holds end, and
reopens when the release is undone. A kept file is purged only when no hold stands on its vault and no release of
one waits for its purge; the purge secure-deletes the blob and records ``held_file_purged``.

The timers (the lapse, the review prompt, the purge) run as the pruner's job ``legal_holds``
(app/core/retention.py): off the event loop, one runner at a time.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, List, Optional

from app.core import after_commit
from app.core import compliance_settings as cs
from app.core import independence as ind
from app.core.case_context import acting_for

HOST_OPERATOR = "operator@host"
SYSTEM = "system"
NOTICE_TYPE = "legal_hold"
TARGET = "#compliance"
# After a lapse, the person who placed the hold cannot place another unconfirmed one on its vaults this long.
PLACE_BLOCK_DAYS = 30
JUSTIFICATION_MIN = 30
TEXT_MAX = 4000

# What a hold-only case is for and on what basis. The case rules (cases with access) use the same lists.
PURPOSES = ("internal_investigation", "litigation_hold", "regulator_request", "data_subject_request",
            "security_incident", "other")
LEGAL_BASES = ("legal_obligation", "public_task", "legitimate_interests")

# Why a step is refused.
ACCESS_OFF = "compliance_disabled"
NOT_ALLOWED = "not_allowed"
NO_VAULTS = "no_vaults"
TOO_MANY_VAULTS = "too_many_vaults"
NO_SUCH_VAULT = "no_such_vault"
PLACER_CONCERNED = "placer_concerned"
PLACE_BLOCKED = "place_blocked"
SFTP_VERSION = "sftp_version"
BAD_PURPOSE = "bad_purpose"
BAD_BASIS = "bad_basis"
NO_LIA_REFERENCE = "no_lia_reference"
SHORT_JUSTIFICATION = "short_justification"
NO_OWNER_NOTE = "no_owner_note"
NOTHING_TO_CONFIRM = "nothing_to_confirm"
CONFIRM_TOO_LATE = "confirm_too_late"
INDEPENDENT_ADMIN = "independent_admin"
NOTHING_TO_RELEASE = "nothing_to_release"
NOTHING_TO_REVIEW = "nothing_to_review"
NOTHING_TO_UNDO = "nothing_to_undo"
UNDO_TOO_LATE = "undo_too_late"
PLACER = "placer"
STARTER_CHANGED = "starter_changed"

TEXTS = {
    ACCESS_OFF: "compliance access is turned off on this deployment (COMPLIANCE_ACCESS=disabled)",
    NOT_ALLOWED: "only an auditor whose right is in force, or an administrator, can place a legal hold",
    NO_VAULTS: "name at least one vault",
    TOO_MANY_VAULTS: "that is more vaults than one case may hold (COMPLIANCE_MAX_CASE_VAULTS)",
    NO_SUCH_VAULT: "one of those vaults does not exist",
    PLACER_CONCERNED: "you own one of those vaults: a hold on it must be placed by someone it does not concern",
    PLACE_BLOCKED: (f"a hold you placed on one of those vaults ended unconfirmed (it lapsed, or it was released) "
                    f"less than {PLACE_BLOCK_DAYS} days ago: another person must place the next one"),
    SFTP_VERSION: "an SFTP server of another version may be running",
    BAD_PURPOSE: "choose what the case is for",
    BAD_BASIS: "choose the case's legal basis",
    NO_LIA_REFERENCE: "legitimate interests need the reference of the balancing test",
    SHORT_JUSTIFICATION: f"the justification needs at least {JUSTIFICATION_MIN} characters",
    NO_OWNER_NOTE: "write the note the vault's owner reads",
    NOTHING_TO_CONFIRM: "no hold of this case waits for confirmation",
    CONFIRM_TOO_LATE: "the time to confirm this hold has passed: it lapses",
    INDEPENDENT_ADMIN: ("an independent administrator can confirm this hold, so the server's operator may not: the "
                        "host operator has no account the independence rule could check"),
    NOTHING_TO_RELEASE: "no hold of this case stands",
    NOTHING_TO_REVIEW: "no hold of this case stands",
    NOTHING_TO_UNDO: "no release of this case can be undone",
    UNDO_TOO_LATE: "the purge after that release has begun: it can no longer be undone",
    PLACER: "the person who placed the hold cannot confirm it",
    STARTER_CHANGED: ("someone else changed your sign-in details, or added an SSH key to your account, since the "
                      "case started: an independent administrator must do this"),
    # The independence rule's reasons, said of a case (whoever started it: its auditor, or the administrator who
    # placed a hold-only case).
    "not_able": "only an active administrator who is not locked can do this",
    "no_grant": "the auditor's grant is no longer recorded, so nobody can be shown to be independent of it",
    ind.ASKED: "you started the case",
    ind.OWN_ACCOUNT: "you started the case",
    ind.MADE_BY_REQUESTER: "the person who started the case made you an administrator",
    ind.MADE_REQUESTER: "you made the person who started the case an administrator",
    ind.CHANGED_ACCOUNT: "you changed the sign-in details of the person who started the case recently",
    ind.BECAME_ADMIN_AFTER: "you became an administrator after the case started",
    ind.NEW_ADMIN: "you had been an administrator for less than 14 days when the case started",
    ind.PASSWORD_NOT_OWN: "your own password was set by someone else",
    ind.MADE_BY_SUBJECT: "the person who started the case made you an administrator",
    ind.MADE_SUBJECT: "you made the person who started the case an administrator",
    ind.CREATED_SUBJECT: "you created the account of the person who started the case",
    ind.CHANGED_SUBJECT: "you changed the auditor's sign-in details while their right stood",
    ind.CONCERNED: "the case concerns you",
    ind.PROPOSED: "you proposed the auditor's right",
}


class HoldRefused(Exception):
    """A step refused, with its reason (a code above, or one of the independence rule's), its HTTP status and,
    for the SFTP guard, the explanation."""

    def __init__(self, reason: str, *, code: int = 409, detail: Optional[str] = None):
        super().__init__(reason)
        self.reason, self.code, self.detail = reason, code, detail


def text(reason: Optional[str]) -> str:
    """A reason in plain words."""
    if reason in TEXTS:
        return TEXTS[reason]
    from app.core import auditor_rights
    return auditor_rights.text(reason)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


def _days(key: str, case) -> int:
    """A hold setting for ``case``: the stricter of the value at its start and the current one."""
    return int(cs.case_value(key, case.settings_at_approval if case is not None else None))


def access_enabled() -> bool:
    from app.core import auditor_rights
    return auditor_rights.access_enabled()


# --------------------------------------------------------------------------- reading

def standing(db, case_id) -> list:
    """The case's holds that stand (neither released nor lapsed)."""
    from app.core.models import LegalHoldVault
    return (db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id,
                                            LegalHoldVault.released_at.is_(None))
            .order_by(LegalHoldVault.vault_id).all())


def held_vault_ids(db) -> set:
    """Every vault a hold stands on."""
    from app.core.models import LegalHoldVault
    return {r[0] for r in db.query(LegalHoldVault.vault_id).filter(LegalHoldVault.released_at.is_(None)).distinct()}


def confirm_deadline(hold, case) -> datetime:
    """When an unconfirmed hold lapses: its recorded deadline, or sooner when COMPLIANCE_HOLD_CONFIRM_DAYS was
    lowered since."""
    by_setting = hold.placed_at + timedelta(days=_days(cs.HOLD_CONFIRM_DAYS, case))
    return min(hold.confirm_by_deadline, by_setting) if hold.confirm_by_deadline is not None else by_setting


def concerned(db, case) -> set:
    from app.core.case_eligibility import concerned as _concerned
    return {str(p) for p in _concerned(db, case)}


# --------------------------------------------------------------------------- who may decide

def decider_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why the administrator ``person`` may not confirm, release, review or undo the release of ``case``'s holds as
    the independent second person, or None. The one rule (app/core/independence.py) with whoever started the case
    (its auditor, or the administrator who placed a hold-only case) as the one who asked and the account it is
    about; for a case of an auditor's grant, the grant's exclusions too (case_eligibility)."""
    from app.core import admin_grants, credential_changes as cc, password_origin
    from app.core.models import User
    now = now or utcnow()
    if case.grant_id is not None:
        from app.core import case_eligibility
        return case_eligibility.approver_refusal(db, case, person, now)
    if not cc.can_approve(person):
        return "not_able"
    starter = db.get(User, case.auditor_id)
    records = admin_grants.of(db, [person.id, case.auditor_id])
    requested_at = case.requested_at or now
    return ind.compliance_refusal_reason(
        person.id, requester_id=case.auditor_id, subject_id=case.auditor_id,
        approver_grant=records.get(person.id), requester_grant=records.get(case.auditor_id),
        subject_grant=records.get(case.auditor_id),
        changed=cc.changers(db, case.auditor_id, min(requested_at, now) - cc.WINDOW), requested_at=requested_at,
        approver_password_set_by_other=password_origin.is_set_by_other(person),
        subject_created_by=starter.created_by if starter is not None else None,
        credential_changers=[], concerned=concerned(db, case), proposer_id=None)


def is_case_auditor(case, person) -> bool:
    return person is not None and str(getattr(person, "id", "")) == str(case.auditor_id)


def starter_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``person``, who started ``case`` (its auditor, or the administrator who placed a hold-only case), may
    not review or release its holds on their own now, or None. They may while they still stand as they did: an
    auditor whose right is in force (auditor_rights.auditor_live), or an administrator able to act
    (credential_changes.can_approve) whose password is their own and whose sign-in details nobody else has changed
    since the case started. A starter who lost that standing, or whoever took over their account, does not end a
    hold alone: an independent administrator does (decider_refusal)."""
    from app.core import auditor_rights, credential_changes as cc, password_origin
    now = now or utcnow()
    standing_now = auditor_rights.auditor_live(db, person, now)
    if standing_now.live:
        return None
    if not cc.can_approve(person):
        return standing_now.reason if case.grant_id is not None else "not_able"
    if password_origin.is_set_by_other(person):
        return ind.PASSWORD_NOT_OWN
    if auditor_rights._changed_since(db, person, case.requested_at) is not None:
        return STARTER_CHANGED
    return None


# --------------------------------------------------------------------------- the SFTP guard

def sftp_guard(db) -> None:
    """Refuse a step that makes a hold stand while an SFTP server of another version may run: an SFTP
    server older than the triggers' release deletes a held file's blob even though the trigger keeps its row."""
    from app.core.sftp_versions import sftp_same_version
    check = sftp_same_version(db)
    if not check.ok:
        raise HoldRefused(SFTP_VERSION, detail=check.explain())


# --------------------------------------------------------------------------- recording and telling

def _audit(db, action: str, case, *, actor=None, actor_name: Optional[str] = None, vault_id=None,
           status: str = "success", details: Optional[dict] = None):
    """The step's audit row, in the caller's transaction, under the case (audit_logs.case_id)."""
    from app.services.audit_logger import AuditLogger
    with acting_for(case.id):
        db.add(AuditLogger(db).build_row(
            action=action, status=status, user=actor, username=None if actor is not None else actor_name,
            resource_type="vault" if vault_id is not None else "case",
            resource_id=str(vault_id) if vault_id is not None else str(case.id),
            details={"case_number": case.number, **({"vault_id": str(vault_id)} if vault_id is not None else {}),
                     **(details or {})}))


def record_refusal(db, action: str, case, *, actor, reason: str) -> None:
    """Record a refused step on its own (its work is rolled back first). Never raises."""
    from app.services.audit_logger import AuditLogger
    try:
        db.rollback()
        with acting_for(case.id if case is not None else None):
            db.add(AuditLogger(db).build_row(
                action=action, status="failure", user=actor if getattr(actor, "id", None) is not None else None,
                username=None if getattr(actor, "id", None) is not None else HOST_OPERATOR,
                resource_type="case", resource_id=str(case.id) if case is not None else None,
                details={"reason": reason, **({"case_number": case.number} if case is not None else {})}))
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


# What is told after a commit goes through the one after-commit dispatcher (app/core/after_commit.py): a listener
# this module added on its first import broke the commit whenever that import happened inside another commit.
_NOTICES = "legal_hold_notices"


def _owner_notices(db, case, vault_owner_pairs, title: str, body: str) -> None:
    """The owners' in-app notices, in the caller's transaction: they exist exactly when the step does."""
    from app.core.models import Notification
    by_owner = {}
    for vault_id, owner_id in vault_owner_pairs:
        if owner_id is not None:
            by_owner.setdefault(str(owner_id), []).append(vault_id)
    for owner_id, vaults in by_owner.items():
        db.add(Notification(user_id=uuid.UUID(owner_id), type=NOTICE_TYPE, title=title,
                            body=body.format(n=len(vaults), s="" if len(vaults) == 1 else "s"), target=TARGET))


def queue(db, notice: dict) -> None:
    """Tell the administrators (and the case's auditor) once the caller's transaction commits; nothing when it
    rolls back."""
    after_commit.later(db, _NOTICES, notice)


def _deliver_notices(notices) -> None:
    try:
        deliver(notices)
    except Exception as exc:  # noqa: BLE001 -- a notice never undoes the step
        print(f"Warning: a legal hold notice was not sent ({type(exc).__name__})")


def deliver(notices: Iterable[dict]) -> None:
    """Every active administrator and the case's auditor, in the app, after the commit. Never a vault, file or
    folder name, the justification or a person named."""
    from app.api import api_server as api
    from app.core.database import get_db_context
    from app.core.models import RoleEnum, User
    with get_db_context() as db:
        admins = [str(a[0]) for a in db.query(User.id).filter(User.role == RoleEnum.ADMIN,
                                                                User.is_active.is_(True)).all()]
    for notice in notices:
        people = admins + ([str(notice["auditor_id"])] if notice.get("auditor_id") else [])
        api._notify_users(people, NOTICE_TYPE, title=notice["title"], body=notice["body"], target=TARGET)


def _tell(db, case, title: str, body: str) -> None:
    queue(db, {"title": title, "body": body, "auditor_id": str(case.auditor_id)})


after_commit.handler(_NOTICES, _deliver_notices)


# --------------------------------------------------------------------------- placing

def _clean(value: Optional[str]) -> str:
    return (value or "").strip()


def check_case_text(purpose, legal_basis, lia_reference, justification, owner_note) -> None:
    if purpose not in PURPOSES:
        raise HoldRefused(BAD_PURPOSE, code=422)
    if legal_basis not in LEGAL_BASES:
        raise HoldRefused(BAD_BASIS, code=422)
    if legal_basis == "legitimate_interests" and not _clean(lia_reference):
        raise HoldRefused(NO_LIA_REFERENCE, code=422)
    if len(_clean(justification)) < JUSTIFICATION_MIN:
        raise HoldRefused(SHORT_JUSTIFICATION, code=422)
    if not _clean(owner_note):
        raise HoldRefused(NO_OWNER_NOTE, code=422)


def may_place(db, person) -> Optional[str]:
    """Why ``person`` may not place a hold at all, or None: a live auditor or an active administrator."""
    from app.core import auditor_rights
    from app.core import credential_changes as cc
    if not access_enabled():
        return ACCESS_OFF
    if cc.can_approve(person):
        return None
    return None if auditor_rights.auditor_live(db, person).live else NOT_ALLOWED


def _lock_vaults(db, vault_ids: List[uuid.UUID]) -> list:
    """Each vault's (id, owner, type), its row locked FOR UPDATE, in id order: the lock waits for a deletion
    holding the row (every deleting path takes it FOR NO KEY UPDATE), so a hold covers every deletion that
    commits after it."""
    from app.core.models import Vault
    rows = []
    for vid in sorted(vault_ids, key=str):
        row = (db.query(Vault.id, Vault.owner_id, Vault.type).filter(Vault.id == vid)
               .with_for_update().first())
        if row is None:
            raise HoldRefused(NO_SUCH_VAULT, code=404)
        rows.append(row)
    return rows


def _check_block(db, placer, vault_ids, now: datetime) -> None:
    """Refuse a placing by whoever placed a hold on one of ``vault_ids`` that ended unconfirmed (it lapsed, or it
    was released before anyone confirmed it) less than PLACE_BLOCK_DAYS ago. Releasing one's own unconfirmed hold
    and placing another would otherwise keep deleted data for good with no second person ever agreeing."""
    from app.core.models import LegalHoldVault
    since = now - timedelta(days=PLACE_BLOCK_DAYS)
    blocked = (db.query(LegalHoldVault.vault_id)
               .filter(LegalHoldVault.vault_id.in_(vault_ids), LegalHoldVault.placed_by == placer.id,
                       LegalHoldVault.confirmed_at.is_(None), LegalHoldVault.released_at.isnot(None),
                       LegalHoldVault.released_at > since).first())
    if blocked is not None:
        raise HoldRefused(PLACE_BLOCKED)


def place_hold_only(db, placer, vault_ids: Iterable, *, purpose: str, legal_basis: str, justification: str,
                    owner_note: str, lia_reference: Optional[str] = None, now: Optional[datetime] = None):
    """Open a hold-only case holding ``vault_ids`` at once, placed by ``placer``, in the caller's transaction (the
    caller commits). Raises HoldRefused."""
    from app.core import auditor_rights, case_numbers
    from app.core.models import (ComplianceCase, ComplianceCasePerson, ComplianceCaseScope, ComplianceCaseVault,
                                 LegalHoldVault)
    from app.core.security import seal_case_field
    now = now or utcnow()
    why = may_place(db, placer)
    if why is not None:
        raise HoldRefused(why, code=403 if why == NOT_ALLOWED else 409)
    check_case_text(purpose, legal_basis, lia_reference, justification, owner_note)
    ids = []
    for value in vault_ids or ():
        try:
            vid = uuid.UUID(str(value))
        except (TypeError, ValueError):
            raise HoldRefused(NO_SUCH_VAULT, code=404)
        if vid not in ids:
            ids.append(vid)
    if not ids:
        raise HoldRefused(NO_VAULTS, code=422)
    if len(ids) > int(cs.current(cs.MAX_CASE_VAULTS)):
        raise HoldRefused(TOO_MANY_VAULTS, code=422)
    vaults = _lock_vaults(db, ids)
    owners = {str(v.owner_id) for v in vaults if v.owner_id is not None}
    if str(placer.id) in owners:
        raise HoldRefused(PLACER_CONCERNED, code=403)
    sftp_guard(db)
    _check_block(db, placer, ids, now)

    standing_grant = auditor_rights.auditor_live(db, placer)
    case = ComplianceCase(id=uuid.uuid4(), status="hold_only", purpose=purpose, legal_basis=legal_basis,
                          lia_reference=_clean(lia_reference)[:255] or None, auditor_id=placer.id,
                          auditor_username=placer.username, justification_enc="", owner_note_enc="",
                          grant_id=standing_grant.grant.id if standing_grant.live else None,
                          requested_at=now, hold_requested=True, access_days=0,
                          settings_at_approval=cs.snapshot(), created_at=now, updated_at=now)
    case.justification_enc = seal_case_field(case.id, _clean(justification)[:TEXT_MAX], "justification")
    case.owner_note_enc = seal_case_field(case.id, _clean(owner_note)[:TEXT_MAX], "owner_note")
    # The number now: a hold-only case is in force from its start, and the owner's notice cites it.
    case.number = case_numbers.allocate(db, now)
    db.add(case)
    db.flush()
    deadline = now + timedelta(days=_days(cs.HOLD_CONFIRM_DAYS, case))
    for v in vaults:
        db.add(ComplianceCaseScope(case_id=case.id, kind="vault", target_id=v.id))
        db.add(ComplianceCaseVault(case_id=case.id, vault_id=v.id, vault_type_at_approval=v.type or "standard",
                                   owner_id_at_approval=v.owner_id, notice_written_at=now))
        db.add(LegalHoldVault(case_id=case.id, vault_id=v.id, placed_by=placer.id,
                              placed_by_username=placer.username, placed_at=now, confirm_by_deadline=deadline))
        _audit(db, "hold_placed", case, actor=placer, vault_id=v.id,
               details={"confirm_by": _iso(deadline), "hold_only": True})
    for owner in owners:
        db.add(ComplianceCasePerson(case_id=case.id, user_id=uuid.UUID(owner), why="owner"))
    _owner_notices(db, case, [(v.id, v.owner_id) for v in vaults], "Legal hold on your vaults",
                   f"A legal hold under case {case.number} keeps what is deleted from {{n}} vault{{s}} you own, "
                   "until it is released. You can go on using them as before. See Access to my vaults.")
    _tell(db, case, "Legal hold placed",
          f"{placer.username} placed a legal hold under case {case.number} on {len(vaults)} vault"
          f"{'' if len(vaults) == 1 else 's'}. Another administrator must confirm it by {deadline:%Y-%m-%d}, "
          "or it lapses.")
    _sync_marker(db)
    return case


# --------------------------------------------------------------------------- confirming

def confirmable(db, case, now: Optional[datetime] = None) -> list:
    """``case``'s holds that stand unconfirmed and may still be confirmed: before their confirm deadline (past it a
    hold lapses, whether or not the periodic job has run yet)."""
    now = now or utcnow()
    return [h for h in standing(db, case.id) if h.confirmed_at is None and now < confirm_deadline(h, case)]


def confirm_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``person`` may not confirm ``case``'s holds, or None."""
    now = now or utcnow()
    unconfirmed = [h for h in standing(db, case.id) if h.confirmed_at is None]
    if not unconfirmed:
        return NOTHING_TO_CONFIRM
    if not confirmable(db, case, now):
        return CONFIRM_TOO_LATE
    if any(str(h.placed_by) == str(person.id) for h in standing(db, case.id)):
        return PLACER
    return decider_refusal(db, case, person, now)


def independent_confirmers(db, case, now: Optional[datetime] = None) -> list:
    """The administrators who could confirm ``case``'s holds now: able to act, independent of whoever placed them,
    and with an authenticator set up (the confirmation asks for its code). None of them: the server's operator
    confirms on the host."""
    from app.core.auditor_rights import active_totp
    from app.core.models import RoleEnum, User
    now = now or utcnow()
    admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
    return [a for a in admins if active_totp(db, a.id) is not None and confirm_refusal(db, case, a, now) is None]


def confirm(db, case, *, by=None, now: Optional[datetime] = None) -> int:
    """Confirm every hold of ``case`` that stands unconfirmed and may still be confirmed, as ``by`` (None: the
    server's operator on the host), in the caller's transaction. Returns how many."""
    now = now or utcnow()
    name = by.username if by is not None else HOST_OPERATOR
    count = 0
    for hold in confirmable(db, case, now):
        hold.confirmed_at, hold.confirmed_by_username = now, name
        hold.confirmed_by = by.id if by is not None else None
        _audit(db, "hold_confirmed", case, actor=by, actor_name=name, vault_id=hold.vault_id)
        count += 1
    if count:
        _tell(db, case, "Legal hold confirmed",
              f"{name} confirmed the legal hold of case {case.number}. It stands until it is released.")
    return count


# --------------------------------------------------------------------------- reviewing

def review_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``person`` may not say that ``case``'s hold is still needed, or None: as for a release."""
    if not standing(db, case.id):
        return NOTHING_TO_REVIEW
    if is_case_auditor(case, person):
        return starter_refusal(db, case, person, now)
    return decider_refusal(db, case, person, now)


def review(db, case, *, by, now: Optional[datetime] = None) -> int:
    """Record that the hold is still needed (``hold_reviewed``). Returns how many holds."""
    now = now or utcnow()
    holds = standing(db, case.id)
    for hold in holds:
        hold.last_reviewed_at = now
        hold.review_prompted_at = None
        _audit(db, "hold_reviewed", case, actor=by, vault_id=hold.vault_id)
    return len(holds)


def review_base(hold) -> datetime:
    return hold.last_reviewed_at or hold.confirmed_at or hold.placed_at


def prompt_reviews(db, now: Optional[datetime] = None) -> int:
    """Ask the case's auditor and the administrators about each hold whose review is due, once per period.
    Releases nothing."""
    from app.core.models import ComplianceCase, LegalHoldVault
    now = now or utcnow()
    asked = 0
    by_case = {}
    for hold in db.query(LegalHoldVault).filter(LegalHoldVault.released_at.is_(None)).all():
        case = by_case.get(hold.case_id) or db.get(ComplianceCase, hold.case_id)
        by_case[hold.case_id] = case
        due = review_base(hold) + timedelta(days=_days(cs.HOLD_REVIEW_DAYS, case))
        if now < due or (hold.review_prompted_at is not None and hold.review_prompted_at >= due):
            continue
        hold.review_prompted_at = now
        asked += 1
    for case_id, case in by_case.items():
        if any(h.review_prompted_at == now for h in standing(db, case_id)):
            _tell(db, case, "Legal hold review",
                  f"The legal hold of case {case.number} has stood {_days(cs.HOLD_REVIEW_DAYS, case)} days since "
                  "it was last reviewed. Say whether it is still needed; nothing is released by the clock.")
    return asked


# --------------------------------------------------------------------------- releasing and undoing

def release_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``person`` may not release ``case``'s holds, or None: the case's starter while they stand as they did
    (starter_refusal), or an independent administrator (decider_refusal)."""
    if not standing(db, case.id):
        return NOTHING_TO_RELEASE
    if is_case_auditor(case, person):
        return starter_refusal(db, case, person, now)
    return decider_refusal(db, case, person, now)


def _close_hold_only(db, case, *, by, by_name: str, reason: Optional[str], now: datetime) -> None:
    from app.core.security import seal_case_field
    if case.status != "hold_only" or standing(db, case.id):
        return
    case.status = "closed"
    case.closed_at, case.closed_by, case.closed_by_username = now, getattr(by, "id", None), by_name
    case.close_reason_enc = seal_case_field(case.id, reason, "close_reason") if reason else None
    case.records_kept_until = now + timedelta(days=_days(cs.RECORD_MIN_DAYS, case))
    case.version = (case.version or 1) + 1
    case.updated_at = now
    _audit(db, "case_closed", case, actor=by, actor_name=by_name, details={"by_release": True})


def _set_kept_purge(db, vault_ids, when: Optional[datetime]) -> None:
    """Show on the kept rows of vaults no hold stands on when they will be purged (or None: not, after an undo)."""
    from app.core.models import HeldFile, HeldFolder
    for vid in vault_ids:
        for model in (HeldFile, HeldFolder):
            db.query(model).filter(model.vault_id == vid).update({model.purge_after: when},
                                                                 synchronize_session=False)


def release(db, case, *, by=None, reason: str, now: Optional[datetime] = None) -> int:
    """Release every hold of ``case`` that stands, as ``by`` (None: the server's operator), with ``reason``, in
    the caller's transaction. What they kept is purged COMPLIANCE_HOLD_PURGE_DELAY_DAYS later, unless the release
    is undone first. Returns how many holds."""
    from app.core.security import seal_case_field
    now = now or utcnow()
    name = by.username if by is not None else HOST_OPERATOR
    purge_at = now + timedelta(days=_days(cs.HOLD_PURGE_DELAY_DAYS, case))
    holds = standing(db, case.id)
    for hold in holds:
        hold.released_at, hold.released_by, hold.released_by_username = now, getattr(by, "id", None), name
        hold.release_reason_enc = seal_case_field(case.id, reason, "release_reason", item_id=hold.vault_id)
        hold.purge_after = purge_at
        _audit(db, "hold_released", case, actor=by, actor_name=name, vault_id=hold.vault_id,
               details={"purge_after": _iso(purge_at)})
    db.flush()
    still_held = held_vault_ids(db)
    _set_kept_purge(db, [h.vault_id for h in holds if h.vault_id not in still_held], purge_at)
    _close_hold_only(db, case, by=by, by_name=name, reason=reason, now=now)
    if holds:
        _owner_notices(db, case, _owners(db, case, holds), "Legal hold released",
                       f"The legal hold under case {case.number} on {{n}} vault{{s}} you own was released. What it "
                       f"kept is deleted after {purge_at:%Y-%m-%d}.")
        _tell(db, case, "Legal hold released",
              f"{name} released the legal hold of case {case.number}. What it kept is purged after "
              f"{purge_at:%Y-%m-%d}, unless an administrator undoes the release first.")
    _sync_marker(db)
    return len(holds)


def _owners(db, case, holds) -> list:
    from app.core.models import ComplianceCaseVault
    owners = dict(db.query(ComplianceCaseVault.vault_id, ComplianceCaseVault.owner_id_at_approval)
                  .filter(ComplianceCaseVault.case_id == case.id).all())
    return [(h.vault_id, owners.get(h.vault_id)) for h in holds]


def last_release(db, case_id) -> list:
    """The holds of the case's last release (not a lapse), when they still wait for their purge."""
    from app.core.models import LegalHoldVault
    rows = (db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id,
                                            LegalHoldVault.released_at.isnot(None),
                                            LegalHoldVault.lapsed_at.is_(None)).all())
    if not rows:
        return []
    last = max(r.released_at for r in rows)
    return [r for r in rows if r.released_at == last]


def undo_refusal(db, case, person, now: Optional[datetime] = None) -> Optional[str]:
    now = now or utcnow()
    holds = last_release(db, case.id)
    if not holds or standing(db, case.id):
        return NOTHING_TO_UNDO
    if any(h.purge_after is None or h.purge_after <= now for h in holds):
        return UNDO_TOO_LATE
    return decider_refusal(db, case, person, now)


def undo_release(db, case, *, by, now: Optional[datetime] = None) -> int:
    """Restore the holds of the case's last release, with their confirmation, in the caller's transaction (the
    caller has checked undo_refusal and the SFTP guard). A hold-only case the release closed opens again."""
    now = now or utcnow()
    holds = last_release(db, case.id)
    for hold in holds:
        hold.released_at = hold.released_by = hold.released_by_username = None
        hold.release_reason_enc = hold.purge_after = None
        _audit(db, "hold_release_undone", case, actor=by, vault_id=hold.vault_id)
    db.flush()
    _set_kept_purge(db, [h.vault_id for h in holds], None)
    if holds and case.status == "closed" and case.closed_at is not None and case.hold_requested \
            and (case.access_days or 0) == 0:
        case.status = "hold_only"
        case.closed_at = case.closed_by = case.closed_by_username = case.close_reason_enc = None
        case.records_kept_until = None
        case.version = (case.version or 1) + 1
        case.updated_at = now
    if holds:
        _owner_notices(db, case, _owners(db, case, holds), "Legal hold restored",
                       f"The release of the legal hold under case {case.number} on {{n}} vault{{s}} you own was "
                       "undone: the hold stands again.")
        _tell(db, case, "Legal hold restored",
              f"{by.username} undid the release of the legal hold of case {case.number}: it stands again.")
    _sync_marker(db)
    return len(holds)


# --------------------------------------------------------------------------- the clock

def lapse_due(db, now: Optional[datetime] = None) -> int:
    """Holds nobody confirmed in time lapse: they keep nothing more, and what they kept follows the release path.
    Returns how many."""
    from app.core.models import ComplianceCase, LegalHoldVault
    now = now or utcnow()
    count = 0
    touched = {}
    for hold in (db.query(LegalHoldVault).filter(LegalHoldVault.released_at.is_(None),
                                                 LegalHoldVault.confirmed_at.is_(None))
                 .with_for_update(skip_locked=True).all()):
        case = touched.get(hold.case_id) or db.get(ComplianceCase, hold.case_id)
        if now < confirm_deadline(hold, case):
            continue
        purge_at = now + timedelta(days=_days(cs.HOLD_PURGE_DELAY_DAYS, case))
        hold.lapsed_at = hold.released_at = now
        hold.released_by_username = SYSTEM
        hold.purge_after = purge_at
        touched[hold.case_id] = case
        _audit(db, "hold_lapsed", case, actor_name=SYSTEM, vault_id=hold.vault_id,
               details={"purge_after": _iso(purge_at)})
        count += 1
    db.flush()
    still_held = held_vault_ids(db)
    for case_id, case in touched.items():
        lapsed = [h for h in db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id,
                                                              LegalHoldVault.lapsed_at == now).all()]
        _set_kept_purge(db, [h.vault_id for h in lapsed if h.vault_id not in still_held], lapsed[0].purge_after)
        _close_hold_only(db, case, by=None, by_name=SYSTEM, reason=None, now=now)
        _owner_notices(db, case, _owners(db, case, lapsed), "Legal hold lapsed",
                       f"The legal hold under case {case.number} on {{n}} vault{{s}} you own lapsed: nobody "
                       "confirmed it in time.")
        _tell(db, case, "Legal hold lapsed",
              f"Nobody confirmed the legal hold of case {case.number} in time, so it lapsed. Its placer cannot "
              f"place another unconfirmed hold on those vaults for {PLACE_BLOCK_DAYS} days.")
    if count:
        _sync_marker(db)
    return count


def purgeable_vaults_clause(model, now: datetime):
    """Rows of the kept table ``model`` that may be purged: no hold stands on their vault and no release of one
    waits for its purge."""
    from sqlalchemy import and_, exists, not_, or_
    from app.core.models import LegalHoldVault
    standing_or_waiting = exists().where(
        LegalHoldVault.vault_id == model.vault_id,
        or_(LegalHoldVault.released_at.is_(None), LegalHoldVault.purge_after.is_(None),
            LegalHoldVault.purge_after > now))
    return and_(not_(standing_or_waiting))


def purge(session_factory, *, now: Optional[datetime] = None, batch: int = 200,
          time_left: Callable[[], bool] = lambda: True, record: Optional[Callable] = None,
          destroy: Optional[Callable] = None, limit_statements: Optional[Callable] = None) -> int:
    """Delete the kept rows whose holds are all released and past their delay, a batch per transaction (each
    file's ``held_file_purged`` row in it), then destroy their blobs, and the kept folders and old names of
    vaults with nothing left to purge. Returns how many files."""
    from sqlalchemy import select
    from app.core.models import HeldFile, HeldFolder, HeldNameHistory, Vault
    from app.services.audit_logger import AuditLogger
    now = now or utcnow()
    destroy = destroy or _destroy_blobs
    done = 0
    while time_left():
        db = session_factory()
        try:
            if limit_statements:
                limit_statements(db)
            candidates = [r[0] for r in db.query(HeldFile.vault_id).filter(purgeable_vaults_clause(HeldFile, now))
                          .distinct().limit(batch).all()]
            # The vaults' rows first, as every deleting path takes them: a hold placed meanwhile waits, or is seen.
            for vid in sorted(candidates, key=str):
                db.query(Vault.id).filter(Vault.id == vid).with_for_update(key_share=True, skip_locked=True).first()
            rows = (db.query(HeldFile.id, HeldFile.vault_id, HeldFile.storage_path, HeldFile.kept_reason,
                             HeldFile.kept_at)
                    .filter(HeldFile.vault_id.in_(candidates), purgeable_vaults_clause(HeldFile, now))
                    .order_by(HeldFile.kept_at, HeldFile.id).limit(batch)
                    .with_for_update(of=HeldFile, skip_locked=True).all()) if candidates else []
            if rows:
                db.query(HeldFile).filter(HeldFile.id.in_([r.id for r in rows])).delete(synchronize_session=False)
                audit = AuditLogger(db)
                for r in rows:
                    db.add(audit.build_row(action="held_file_purged", status="success", resource_type="file",
                                           resource_id=str(r.id),
                                           details={"vault_id": str(r.vault_id), "kept_reason": r.kept_reason,
                                                    "kept_at": _iso(r.kept_at)}))
                if record:
                    record(db, len(rows), HeldFile.__tablename__)
            db.commit()
        except BaseException:
            db.rollback()
            db.close()
            raise
        db.close()
        if rows:
            destroy([r.storage_path for r in rows])
            done += len(rows)
        if len(rows) < batch:
            break
    # Folders and old names go with the last of their vault's files.
    db = session_factory()
    try:
        if limit_statements:
            limit_statements(db)
        for model in (HeldFolder, HeldNameHistory):
            gone = (db.query(model).filter(purgeable_vaults_clause(model, now),
                                           ~model.vault_id.in_(select(HeldFile.vault_id)))
                    .delete(synchronize_session=False))
            if gone and record:
                record(db, gone, model.__tablename__)
        _sync_marker(db)
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()
    return done


def _destroy_blobs(paths) -> None:
    """Destroy purged blobs through the one gate every committed blob's destruction passes (it finds no kept row
    for them now)."""
    from app.core.authorization import PermissionService
    from app.core.database import get_db_context
    from app.services.vault_service import VaultService
    with get_db_context() as db:
        VaultService(db, PermissionService(db))._destroy_blobs(paths)


def _sync_marker(db) -> None:
    from app.core import legal_hold_marker
    legal_hold_marker.sync(db)


# --------------------------------------------------------------------------- the host

def _host_confirm(db, case, *, reason=None):
    """dockvault.py cases confirm-hold: the server's operator confirms the case's holds, only when no
    administrator could (independent_confirmers): the confirmation is the hold's second person, and the operator
    has no account the independence rule could check. A refusal for that reason is recorded."""
    from app.core.host_operator import _refuse
    now = utcnow()
    if not any(h.confirmed_at is None for h in standing(db, case.id)):
        return _refuse(text(NOTHING_TO_CONFIRM).capitalize() + ".")
    if not confirmable(db, case, now):
        return _refuse(text(CONFIRM_TOO_LATE).capitalize() + ".")
    others = independent_confirmers(db, case, now)
    if others:
        record_refusal(db, "hold_confirmed", case, actor=None, reason=INDEPENDENT_ADMIN)
        return _refuse(f"An independent administrator can confirm this hold "
                       f"({', '.join(sorted(a.username for a in others))}), so the server's operator may not: the "
                       "host operator has no account the independence rule could check.")
    count = confirm(db, case, by=None, now=now)
    return {"id": str(case.id), "number": case.number, "confirmed": count}


def _register_host_step() -> None:
    from app.core import host_compliance
    host_compliance.register_case_step("confirm-hold", _host_confirm)


_register_host_step()
