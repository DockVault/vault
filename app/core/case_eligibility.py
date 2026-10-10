"""Who may approve a compliance case, or confirm its legal hold, as the independent second person.

The one rule every two-person approval uses (app/core/independence.py, compliance_refusal_reason), with the
auditor as both the one who asked and the account the case is about. Besides the rule's own refusals (the
auditor, an administrator in the auditor's lineage either way, anyone who changed the auditor's sign-in details
in the 14 days before the request or since, an administrator of less than 14 days, one whose password someone
else set), it refuses whoever created the auditor's account and an administrator in that creator's lineage either
way (one the creator made, one who made the creator: read now and as the grant's proposal kept it), whoever
changed the auditor's sign-in details while the auditor's grant stood (the grant's own list), a person the case
concerns, whoever proposed the auditor's grant and an administrator in the proposer's lineage either way (read now
and as the grant kept it when it was proposed). A case whose grant is no longer recorded refuses everyone: the grant's list could not be read.

independent_approvers() is who could approve now: administrators who can act, with an authenticator set up (the
approval asks for its code), refused by nothing. When there is none, the server's operator approves on the host
(app/core/host_compliance.py), and only then: the host operator has no account the exclusions could apply to.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.core import credential_changes as cc
from app.core import independence as ind

NOT_ABLE = "not_able"
NO_GRANT = "no_grant"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def concerned(db, case) -> list:
    """The ids of the people the case concerns: the owners of its vaults (as recorded, and whoever owns one now: a
    vault that changed hands concerns its new owner at once, before the approval reads the owners again),
    custodians, and people named."""
    from app.core.models import ComplianceCasePerson, ComplianceCaseVault, Vault
    people = [row[0] for row in db.query(ComplianceCasePerson.user_id).filter(ComplianceCasePerson.case_id == case.id)]
    owners = [row[0] for row in db.query(Vault.owner_id)
              .join(ComplianceCaseVault, ComplianceCaseVault.vault_id == Vault.id)
              .filter(ComplianceCaseVault.case_id == case.id, Vault.owner_id.isnot(None))]
    return list(dict.fromkeys(people + owners))


def approver_refusal(db, case, approver, now: Optional[datetime] = None) -> Optional[str]:
    """Why ``approver`` (an account) may not approve ``case`` or confirm its hold, or None when they may."""
    from app.core import admin_grants, password_origin
    from app.core.models import AuditorGrant, User
    now = now or utcnow()
    if not cc.can_approve(approver):
        return NOT_ABLE
    grant = db.get(AuditorGrant, case.grant_id) if case.grant_id is not None else None
    if grant is None:
        return NO_GRANT
    from app.core.auditor_rights import creator_of
    auditor = db.get(User, case.auditor_id)
    records = admin_grants.of(db, [approver.id, case.auditor_id, grant.proposed_by])
    requested_at = case.requested_at or now
    creator, creator_grant = creator_of(db, auditor)
    kept = grant.proposal_snapshot or {}
    return ind.compliance_refusal_reason(
        approver.id, requester_id=case.auditor_id, subject_id=case.auditor_id,
        approver_grant=records.get(approver.id), requester_grant=records.get(case.auditor_id),
        subject_grant=records.get(case.auditor_id),
        changed=cc.changers(db, case.auditor_id, min(requested_at, now) - cc.WINDOW), requested_at=requested_at,
        approver_password_set_by_other=password_origin.is_set_by_other(approver),
        subject_created_by=creator, creator_grant=creator_grant, kept_creator=kept.get("creator"),
        kept_creator_lineage=kept.get("creator_lineage") or [],
        credential_changers=grant.credential_changers or [], concerned=concerned(db, case),
        proposer_id=grant.proposed_by, proposer_grant=records.get(grant.proposed_by),
        kept_proposer=kept.get("requester"), kept_proposer_lineage=kept.get("lineage") or [])


def independent_approvers(db, case, now: Optional[datetime] = None) -> list:
    """The administrators who could approve ``case`` now (the module docstring)."""
    from app.core.auditor_rights import active_totp
    from app.core.models import RoleEnum, User
    now = now or utcnow()
    admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
    return [a for a in admins if active_totp(db, a.id) is not None and approver_refusal(db, case, a, now) is None]
