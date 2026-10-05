"""Who is independent enough to approve what someone else asked for: one rule for every two-person approval.

The rule came with the approval of an administrator's second change to someone's sign-in details within 14
days (app/core/credential_changes.py has that flow, its records and the reasons in the module docstring). It
refuses, in this order:
  * the one who asked (ASKED);
  * the person the request is about (OWN_ACCOUNT);
  * an administrator the one who asked made one, directly or through administrators they made, and the one who
    made the one who asked (MADE_BY_REQUESTER, MADE_REQUESTER);
  * anyone who made a change to that account's sign-in details in the 14 days before the request, or since
    (CHANGED_ACCOUNT);
  * an administrator for less than 14 days when the request was made, or since it was made (NEW_ADMIN,
    BECAME_ADMIN_AFTER);
  * an administrator whose password someone else set (PASSWORD_NOT_OWN).
refusal_reason() is that rule, pure: the caller reads the records it needs.

Compliance access applies the same rule to approving an auditor grant, approving or extending a case, and
confirming or releasing a legal hold, with the auditor as the account the request is about (the subject), and
refuses besides (compliance_refusal_reason):
  * an administrator in the subject's lineage, either way, when the subject is not the one who asked (an auditor
    grant someone else proposed): an administrator the auditor made, or who made the auditor one
    (MADE_BY_SUBJECT, MADE_SUBJECT);
  * whoever created the auditor's account (CREATED_SUBJECT): they knew its first password;
  * anyone who changed the auditor's sign-in details while the grant stood (CHANGED_SUBJECT), read from the
    grant's own list, which outlives the records of credential changes (pruned 14 days after they apply);
  * a person the case concerns (CONCERNED): an owner of a vault in it, a custodian, someone named;
  * whoever proposed the auditor's grant (PROPOSED).
Two paths would otherwise let one person read a vault: a stand-in administrator (A makes B an administrator,
then B approves A's grant and A's case) and a stand-in account (A creates U, someone grants U the right, and A
approves U's case).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable, Optional, Set

# How long an approver must have been an administrator before the request was made.
TENURE = timedelta(days=14)

# Why someone may not approve, in the order the rule checks. Each is said in plain words where it is shown
# (app/api/api_server.py for a credential change).
ASKED = "asked"                  # the administrator who asked
OWN_ACCOUNT = "own"              # the change is to their own account
REQUESTER_GONE = "gone"          # the administrator who asked is no longer an active one (a held change)
MADE_BY_REQUESTER = "made"       # the one who asked made them an administrator
MADE_REQUESTER = "maker"         # they made the one who asked an administrator
CHANGED_ACCOUNT = "changed"      # they made or approved a change to that account
BECAME_ADMIN_AFTER = "after"     # they became an administrator after the request was made
NEW_ADMIN = "new"                # they had been one for less than TENURE when it was made
PASSWORD_NOT_OWN = "password"    # their current password was set by someone else

# The refusals compliance access adds.
MADE_BY_SUBJECT = "made_by_subject"      # the auditor made them an administrator
MADE_SUBJECT = "made_subject"            # they made the auditor an administrator
CREATED_SUBJECT = "created_subject"      # they created the auditor's account
CHANGED_SUBJECT = "changed_subject"      # they changed the auditor's sign-in details while the grant stood
CONCERNED = "concerned"                  # the case concerns them
PROPOSED = "proposed"                    # they proposed the auditor's grant


def refusal_reason(approver_id, *, requester_id, approver_grant, requester_grant, changed: Set,
                   requested_at: datetime, target_id=None,
                   approver_password_set_by_other: bool = False) -> Optional[str]:
    """Why ``approver_id`` may not approve a change to ``target_id`` that ``requester_id`` asked for at
    ``requested_at``, or None when they may (the module docstring has the rules). ``approver_grant``
    and ``requester_grant`` are their admin_grants records (None: none); ``changed`` is
    credential_changes.changers() for the account since 14 days before the request; ``approver_password_set_by_other`` whether the
    approver's current password was set by someone else (password_origin.is_set_by_other)."""
    from app.core import admin_grants
    if approver_id == requester_id:
        return ASKED
    if target_id is not None and approver_id == target_id:
        return OWN_ACCOUNT
    if admin_grants.made_by(approver_grant, requester_id):
        return MADE_BY_REQUESTER
    if admin_grants.made_by(requester_grant, approver_id):
        return MADE_REQUESTER
    if approver_id in changed:
        return CHANGED_ACCOUNT
    if admin_grants.granted_after(approver_grant, requested_at):
        return BECAME_ADMIN_AFTER
    if admin_grants.granted_after(approver_grant, requested_at - TENURE):
        return NEW_ADMIN
    if approver_password_set_by_other:
        return PASSWORD_NOT_OWN
    return None


def changer_ids(entries: Iterable) -> Set[str]:
    """The account ids in an auditor grant's list of credential changers ({"id": ..., ...} entries, or bare
    ids), as text. The host operator, who has no account, has no id."""
    out = set()
    for entry in entries or ():
        value = entry.get("id") if isinstance(entry, dict) else entry
        if value is not None:
            out.add(str(value))
    return out


def compliance_refusal_reason(approver_id, *, requester_id, subject_id, approver_grant, requester_grant,
                              subject_grant, changed: Set, requested_at: datetime,
                              approver_password_set_by_other: bool = False, subject_created_by=None,
                              credential_changers: Iterable = (), concerned: Iterable = (),
                              proposer_id=None) -> Optional[str]:
    """Why ``approver_id`` may not approve a compliance step about the auditor ``subject_id`` that
    ``requester_id`` asked for at ``requested_at`` (the auditor, for a case; the proposer, for a grant), or None.
    refusal_reason() first, with the auditor as the account it is about, then the refusals compliance adds (the
    module docstring). ``subject_grant`` is the auditor's admin_grants record (None: none), ``subject_created_by``
    who created the auditor's account, ``credential_changers`` the grant's list, ``concerned`` the persons the
    case concerns, ``proposer_id`` who proposed the grant."""
    from app.core import admin_grants
    reason = refusal_reason(approver_id, requester_id=requester_id, approver_grant=approver_grant,
                            requester_grant=requester_grant, changed=changed, requested_at=requested_at,
                            target_id=subject_id, approver_password_set_by_other=approver_password_set_by_other)
    if reason is not None:
        return reason
    # The auditor's lineage, either way (when the auditor asked, the rule above has read it already).
    if admin_grants.made_by(approver_grant, subject_id):
        return MADE_BY_SUBJECT
    if admin_grants.made_by(subject_grant, approver_id):
        return MADE_SUBJECT
    who = str(approver_id)
    if subject_created_by is not None and str(subject_created_by) == who:
        return CREATED_SUBJECT
    if who in changer_ids(credential_changers):
        return CHANGED_SUBJECT
    if who in {str(person) for person in concerned or ()}:
        return CONCERNED
    if proposer_id is not None and str(proposer_id) == who:
        return PROPOSED
    return None
