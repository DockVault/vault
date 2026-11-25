"""Groups from the provider into departments and roles, at each sign-in through it.

At a sign-in (purpose ``sign_in`` or ``app``) every mapping of the provider (``sso_group_mappings``) is applied: the
person joins the mapped department when the group is in the token and leaves it when it is not; departments no
mapping names are never touched. A token with **no group information** (the claim absent, or Entra's marker for
too many groups) changes nothing: a server warning, and an administrator notice once a day per provider. A role
of ``user`` or ``external`` applies at once (an administrator is never demoted by it). ``admin`` is never granted
by a sign-in: with the provider's ``sso_admin_mapping`` on, a **held request** (``sso_admin_requests``) is opened
for another administrator to approve, under the approver rules of the credential changes with no requester, and
on approval the promotion path records the grant with the approver as the grantor. An administrator made that way
is demoted at the next sign-in through the provider whose token names no group mapped to the administrator role,
while the group they were approved through is still mapped to it; never the last administrator able to act. Once
that group's mapping is removed or changed, the role is nobody's to take back through the provider: it stays, as
the removal says, and a mapping added later demotes nobody it did not approve. Nothing here commits:
:func:`apply` writes in the caller's transaction, :func:`tell` records and notifies after the commit.
"""
from __future__ import annotations

import logging
import types
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

from app.core import sso_policy

log = logging.getLogger("dockvault.sso")

REQUEST_DAYS = 7
GRANT_MATCH_SECONDS = 2              # an approval's grant record is written with the decision, at its moment
HELD, APPROVED, DENIED, EXPIRED, DEMOTED = "held", "approved", "denied", "expired", "demoted"
# Why a held request can no longer be approved that is neither the person's doing nor the approver's: the provider
# is gone or off, it raises no requests any more, or its group is mapped to the role no more. Such a request can
# still be denied (a denial asks nothing the mapping vouches for), so the list never holds a row nobody can act on.
NO_LONGER_GRANTABLE = frozenset({"provider_gone", "mapping_off", "mapping_gone"})
MAPPING_GONE = "mapping_gone"

# What the owners of vaults a department reaches are told about a join made by a sign-in (the access notices
# want a granter with an id and a name; nobody's own account made this change).
SSO_ACTOR = types.SimpleNamespace(id=uuid.UUID(int=0), username="single sign-on")
BY_NAME = "single sign-on"

# Why an administrator may not decide a request, in words (app/core/independence.py's reasons, with no requester).
REFUSAL_TEXTS = {
    "cannot_act": "You cannot approve while your account is locked.",
    "own": "This request is about your own account.",
    "changed": "You made or approved a change to this account's sign-in details in the last 14 days.",
    "after": "You became an administrator after this request was made.",
    "new": "You have been an administrator for less than 14 days.",
    "password": "Your current password was set by someone else; set one of your own first.",
}


class Conflict(Exception):
    """A decision that cannot be taken now (code, words)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _api():
    from app.api import api_server
    return api_server


@dataclass
class Applied:
    """What a sign-in's mappings did, for the records and notices written after the commit."""
    joined: List[str] = field(default_factory=list)       # department names
    left: List[str] = field(default_factory=list)
    joined_ids: List[str] = field(default_factory=list)
    left_ids: List[str] = field(default_factory=list)
    role_change: Optional[tuple] = None                    # (old, new) when the role changed
    permissions_removed: list = field(default_factory=list)
    request: object = None                                 # the held administrator request opened now
    ended_requests: list = field(default_factory=list)     # held ones whose group is mapped to the role no more
    demoted: bool = False
    kept_last_admin: bool = False                          # a demotion the last-administrator rule stopped
    lost: object = None                                    # what _account_lost_standing did, told after the commit
    no_groups: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.joined or self.left or self.role_change or self.request is not None or self.demoted)


# --------------------------------------------------------------------------- at the sign-in

def apply(db, row, user, answer) -> Applied:
    """Apply the provider's mappings to ``user`` for this token, in the caller's transaction."""
    from app.core.models import RoleEnum, SsoGroupMapping
    applied = Applied()
    mappings = db.query(SsoGroupMapping).filter(SsoGroupMapping.provider_id == row.id).all()
    if not mappings:
        return applied
    if answer.groups is None or answer.groups_overage:
        applied.no_groups = True            # a missing claim never means "member of nothing"
        log.warning("sso provider %s sent no group information for a sign-in; the mappings were not applied%s",
                    row.id, " (overage marker)" if answer.groups_overage else "")
        return applied
    present = {str(g) for g in answer.groups}
    policy = sso_policy.effective(getattr(row, "policy", None))
    # A department is wanted when any of the groups mapped to it is in the token.
    wanted_by_department = {}
    for m in mappings:
        if m.department_id is not None:
            wanted_by_department[m.department_id] = wanted_by_department.get(m.department_id, False) or (m.provider_group in present)
    joins, leaves = [], []
    for department_id, wanted in wanted_by_department.items():
        member = any(str(g.id) == str(department_id) for g in (user.groups or []))
        if wanted and not member:
            joins.append(department_id)
        elif not wanted and member:
            leaves.append(department_id)
    if joins:
        _join(db, row, user, joins, applied)
    if leaves:
        _leave(db, user, leaves, applied)
    roles = {m.role for m in mappings if m.role and m.provider_group in present}
    admin_groups = {m.provider_group for m in mappings if m.role == "admin"}
    # The groups of the token that are mapped to the role, in one order always: which of them a request names does
    # not depend on the order the mappings were read in.
    admin_present = sorted(m.provider_group for m in mappings if m.role == "admin" and m.provider_group in present)
    admin_group = admin_present[0] if admin_present else None
    if getattr(user, "role", None) == RoleEnum.ADMIN:
        # Demoted only through the group the person was approved through, while it is still mapped to the role.
        # Asked of any administrator mapping at all, removing one of two mappings demoted the people approved
        # through it at their next sign-in, and so did a mapping added months after theirs was removed, while the
        # removal had said that a role it gave stays.
        if admin_group is None and approved_through(db, user, row) in admin_groups:
            _demote(db, row, user, roles, applied)
        return applied
    if admin_group is not None and policy["sso_admin_mapping"] and not _providers_without_passwords(db, user):
        # An account that a provider whose people hold no password holds to none could never type the password an
        # administrator needs for the fixed step-ups: no request is raised for it (that provider's password
        # sign-in comes first). An account that signs in only through its provider because it was made at its
        # first sign-in is another matter: the approval is an administrator's word for the person, ends that for
        # the account and hands over a link to choose a password (app/api/api_server.py, _record_admin_grant).
        applied.request = _request_admin(db, user, row, admin_present, admin_groups, applied)
    lesser = "user" if "user" in roles else ("external" if "external" in roles else None)
    if lesser is not None and getattr(user.role, "value", user.role) != lesser:
        old = getattr(user.role, "value", user.role)
        applied.permissions_removed = _api()._set_role(db, user, RoleEnum(lesser), actor=None)
        applied.role_change = (old, lesser)
    return applied


def _providers_without_passwords(db, user) -> list:
    """The providers ``user`` is linked to whose people hold no password (their names): they hold the account to
    none. None for an account that signs in only through its provider because it was made at its first sign-in
    there. Asked of the links, not of the account's flag, which follows them."""
    from app.core import sso_only
    return sso_only.password_less_providers_of(db, user)


def _join(db, row, user, group_ids, applied: Applied) -> None:
    """Add ``user`` to the departments, telling the owners of the vaults and shared items each department reaches
    (as an administrator's add does), in the caller's transaction."""
    from app.core import access_notices
    from app.core.models import Group, Vault
    reach = access_notices.Reach(db, SSO_ACTOR)
    groups = []
    for gid in group_ids:
        group = db.query(Group).filter(Group.id == gid).first()
        if group is None:
            continue
        vault_ids, shares = _reach_of(db, gid)
        for vid in vault_ids:
            reach.watch(db.query(Vault).filter(Vault.id == vid).first(), [user.id],
                        via=access_notices.JOINED, department=group.name)
        for share in shares:
            reach.watch_share(share, db.query(Vault).filter(Vault.id == share.vault_id).first(), [user.id],
                              department=group.name)
        groups.append(group)
    # User.groups is read-only (the association is written through the groups routes), so the rows are written
    # here as those routes write them; a membership written meanwhile by an administrator is left as it is.
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from app.core.models import user_groups
    now = datetime.utcnow()
    for group in groups:
        db.execute(pg_insert(user_groups).values(user_id=user.id, group_id=group.id, group_role="member",
                                                  added_at=now, added_by=None).on_conflict_do_nothing())
        applied.joined.append(group.name)
        applied.joined_ids.append(str(group.id))
    db.flush()
    db.expire(user, ["groups"])
    reach.tell()


def _reach_of(db, group_id):
    """What a department reaches, for the owners' notices: the vaults granted to it, and the active shares addressed
    to it (the same reads as an administrator's add)."""
    from app.core.models import Share, vault_group_access
    vault_ids = [vid for vid, _perm in db.query(vault_group_access.c.vault_id, vault_group_access.c.permission).filter(
        vault_group_access.c.group_id == group_id).all()]
    shares = db.query(Share).filter(Share.claim_audience == "departments", Share.status == "active",
                                    Share.expires_at > datetime.utcnow(),
                                    Share.audience_department_ids.contains([str(group_id)])).all()
    return vault_ids, shares


def _leave(db, user, group_ids, applied: Applied) -> None:
    from app.core.models import user_groups
    wanted = {str(g) for g in group_ids}
    for group in list(user.groups or []):
        if str(group.id) in wanted:
            result = db.execute(user_groups.delete().where((user_groups.c.user_id == user.id)
                                                           & (user_groups.c.group_id == group.id)))
            if getattr(result, "rowcount", 1) == 0:
                continue                     # removed meanwhile by an administrator: nothing to record
            applied.left.append(group.name)
            applied.left_ids.append(str(group.id))
    if applied.left_ids:
        db.flush()
        db.expire(user, ["groups"])


def _demote(db, row, user, roles, applied: Applied) -> None:
    """An administrator made so by an approved request who left the mapped group: the demotion the Users page
    would make, by nobody (the host-operator reading of ``actor=None``), unless they are the last administrator
    able to act."""
    from app.core import admin_grants
    from app.core.models import RoleEnum
    api = _api()
    if api.removes_last_admin(db, user):
        applied.kept_last_admin = True
        return
    applied.lost = api._account_lost_standing(db, user, actor=None, because="demoted")
    admin_grants.forget(db, user.id)
    new_role = RoleEnum.EXTERNAL if ("external" in roles and "user" not in roles) else RoleEnum.USER
    applied.permissions_removed = api._set_role(db, user, new_role, actor=None)
    applied.role_change = ("admin", new_role.value)
    applied.demoted = True
    for request in _approvals_of(db, user, row):
        request.state = DEMOTED                 # the approval is spent: a later role is somebody else's doing


def _request_admin(db, user, row, groups, admin_groups, applied: Applied):
    """The request for ``user`` on this provider: None while one is waiting, else a new one (seven days) for the
    first of ``groups`` (the token's groups that are mapped to the role) that was not denied lately.

    A held request whose group is mapped to the role no more (``admin_groups`` are the groups that are) can never
    be approved. It waited for nothing while it stopped a new request for seven days: after a mapping's group was
    renamed, the person could not be made an administrator through the provider at all. It is ended here, and
    the sign-in goes on to a request for a group that is mapped.

    A denial holds off a new request through the group it denied, for as long as a request would have waited. It
    says nothing of another group: one whose mapping was removed since is in no token's ``groups``."""
    from app.core.models import SsoAdminRequest
    now = datetime.utcnow()
    rows = db.query(SsoAdminRequest).filter(SsoAdminRequest.user_id == user.id,
                                            SsoAdminRequest.provider_id == row.id).all()
    for r in rows:
        if r.state == HELD and r.expires_at > now:
            if r.provider_group in admin_groups:
                return None                  # already waiting: nothing new to tell
            r.state, r.decided_at = EXPIRED, now
            applied.ended_requests.append(r)
    denied_lately = {r.provider_group for r in rows if r.state == DENIED and r.decided_at is not None
                     and r.decided_at > now - timedelta(days=REQUEST_DAYS)}
    for group in groups:
        if group in denied_lately:
            continue                         # a denial holds for as long as a request would have waited
        request = SsoAdminRequest(id=uuid.uuid4(), user_id=user.id, provider_id=row.id, provider_group=str(group)[:255],
                                  requested_at=now, expires_at=now + timedelta(days=REQUEST_DAYS), state=HELD)
        db.add(request)
        return request
    return None


def end_requests_of_group(db, row, group: str, *, now: Optional[datetime] = None) -> list:
    """End the held requests ``group`` of ``row`` opened, because the group is mapped to the administrator role no
    more (its mapping was removed, or given another group or role): marked expired, in the caller's transaction.
    Each is read locked and as it stands, so a decision landing this second is not overwritten. Returns them, for
    the caller's records and notices."""
    from app.core.models import SsoAdminRequest
    now = now or datetime.utcnow()
    held = (db.query(SsoAdminRequest).filter(SsoAdminRequest.provider_id == row.id,
                                            SsoAdminRequest.provider_group == group, SsoAdminRequest.state == HELD)
            .populate_existing().with_for_update().all())
    for request in held:
        request.state, request.decided_at = EXPIRED, now
    return held


def _approvals_of(db, user, row) -> list:
    from app.core.models import SsoAdminRequest
    return db.query(SsoAdminRequest).filter(SsoAdminRequest.user_id == user.id, SsoAdminRequest.provider_id == row.id,
                                            SsoAdminRequest.state == APPROVED).all()


def approved_through(db, user, row) -> Optional[str]:
    """The provider's group ``user`` was approved through, when the account's administrator role is the one an
    approved request of this provider's mapping granted: the approval stands, and the account's current grant
    record is that approval's (made by its approver, at the decision). None otherwise: a role made by hand
    since, or by another provider's mapping, is not this provider's to take back."""
    from app.core import admin_grants
    approvals = _approvals_of(db, user, row)
    if not approvals:
        return None
    grant = admin_grants.of(db, [user.id]).get(user.id)
    if grant is None:
        return None
    for r in approvals:
        if r.decided_by is None or r.decided_at is None or grant.granted_at is None:
            continue
        since = abs((grant.granted_at - r.decided_at).total_seconds())
        # The approval records the grant at the decision's moment; a grant made by hand later, even by the same
        # administrator, is another decision and keeps the role.
        if str(getattr(grant, "granted_by_id", None)) == str(r.decided_by) and since <= GRANT_MATCH_SECONDS:
            return r.provider_group
    return None


def kept_by_the_end_of_a_mapping(db, row, group: str) -> int:
    """How many administrators hold the role by an approval that came through ``group`` of ``row``, now that no
    mapping of the provider gives that group the role. Each keeps the role, and from here on no sign-in through
    the provider takes it from them: :func:`apply` demotes only through a group that is still mapped to it. Until
    the mapping changed, leaving the group at the provider demoted them at their next sign-in. 0 while a mapping
    still gives the group the role.

    Said to the administrators with the change, because nothing else shows it: an organisation that renames its
    administrators' group and renames the mapping to match has, from that save on, administrators the provider's
    groups no longer govern. A count that cannot be made says nothing, and holds up nothing."""
    from app.core.models import RoleEnum, SsoAdminRequest, User
    try:
        from app.services import sso_group_mappings
        if any(m.role == "admin" and m.provider_group == group for m in sso_group_mappings.of(db, row, fresh=True)):
            return 0
        approved = {r.user_id for r in db.query(SsoAdminRequest).filter(
            SsoAdminRequest.provider_id == row.id, SsoAdminRequest.provider_group == group,
            SsoAdminRequest.state == APPROVED).all()}
        kept = 0
        for user_id in approved:
            user = db.query(User).filter(User.id == user_id).first()
            if (user is not None and getattr(user, "role", None) == RoleEnum.ADMIN
                    and approved_through(db, user, row) == group):
                kept += 1
        return kept
    except Exception:  # noqa: BLE001
        db.rollback()
        return 0


def made_administrator_through(db, user, row) -> bool:
    """Whether ``user``'s administrator role is the one an approved request of this provider's mapping granted."""
    return approved_through(db, user, row) is not None


# --------------------------------------------------------------------------- whom a change of the mappings may move

def linked_members(db, row, department_id) -> int:
    """How many accounts that can sign in (active) are linked to ``row`` and in the department now. One count."""
    from sqlalchemy import func, select
    from app.core.models import ExternalIdentity, User, user_groups
    linked = (select(ExternalIdentity.user_id).join(User, User.id == ExternalIdentity.user_id)
              .where(ExternalIdentity.provider_id == row.id, User.is_active.is_(True)))
    counted = select(func.count()).select_from(user_groups).where(
        user_groups.c.group_id == department_id, user_groups.c.user_id.in_(linked))
    return int(db.execute(counted).scalar() or 0)


def may_leave(db, row, department_ids) -> list:
    """For the departments a write touched: those a mapping of ``row`` names now, with how many linked accounts are
    in each, as ``[{"department": {"id", "name"}, "accounts": n}]``. Each of those accounts leaves the department
    at its next sign-in through the provider unless that sign-in names a group mapped to it. A department no
    mapping names any more is left out (a sign-in no longer touches it), and so is one with nobody linked in it.
    Read as the mappings are committed. A count that cannot be made says nothing, and holds up nothing."""
    from app.core.models import Group
    try:
        from app.services import sso_group_mappings
        named = {m.department_id for m in sso_group_mappings.of(db, row, fresh=True)
                 if m.department_id is not None}
        out = []
        for department_id in dict.fromkeys(d for d in department_ids if d is not None):
            if department_id not in named:
                continue
            accounts = linked_members(db, row, department_id)
            department = db.query(Group).filter(Group.id == department_id).first()
            if accounts and department is not None:
                out.append({"department": {"id": str(department.id), "name": department.name}, "accounts": accounts})
        return out
    except Exception:  # noqa: BLE001
        db.rollback()
        return []


# --------------------------------------------------------------------------- after the commit

def tell(db, row, user, applied: Applied, *, client_ip) -> None:
    """The audit rows and notices for what :func:`apply` did. Best effort, like every notice."""
    api = _api()
    label = (getattr(row, "label", None) or getattr(row, "name", None) or "single sign-on")
    pid = str(row.id)
    if applied.no_groups:
        _audit(db, "sso_groups_missing", user=user, ip=client_ip, status_="failure",
               details={"provider_id": pid, "username": user.username})
        try:
            admins = [str(a.id) for a in api._active_admins(db)]
            api._notify_users(admins, "sso_groups_missing", title="A provider sent no group information",
                              body=(f"{label} signed {user.username} in without the groups claim (or with the marker for "
                                    "too many groups), so its group mappings were not applied. Nobody was removed from a "
                                    "department. Check the provider's token configuration."),
                              target="#users", dedup_prefix=f"sso_groups_missing:{pid}:{datetime.utcnow():%Y-%m-%d}")
        except Exception as exc:  # noqa: BLE001
            log.info("sso groups-missing notice skipped: %s", type(exc).__name__)
        return
    # Recorded under the account that signed in: its own sign-in moved it, by the provider's word (``via``,
    # ``provider_id``). With nobody named the Activity page showed the change as made by nobody, and whoever
    # looked for the person did not find it.
    for gid in applied.joined_ids:
        api._audit_access_change(db, user, "group_members_added", "group", gid,
                                 {"user_ids": [str(user.id)], "added": 1, "via": "single_sign_on", "provider_id": pid})
    for gid in applied.left_ids:
        api._audit_access_change(db, user, "group_member_removed", "group", gid,
                                 {"user_id": str(user.id), "via": "single_sign_on", "provider_id": pid})
    if applied.role_change is not None:
        _audit(db, "sso_role_changed", user=user, ip=client_ip,
               details={"provider_id": pid, "from_role": applied.role_change[0], "to_role": applied.role_change[1],
                        "demoted": applied.demoted})
        try:
            api._notify_account_status_changes(db, user, by_name=BY_NAME, role=applied.role_change,
                                               permissions_removed=applied.permissions_removed)
        except Exception as exc:  # noqa: BLE001
            log.info("sso role notice skipped: %s", type(exc).__name__)
    if applied.lost is not None:
        try:
            api._announce_lost_standing(db, applied.lost, None)
        except Exception as exc:  # noqa: BLE001
            log.info("sso lost-standing notice skipped: %s", type(exc).__name__)
    if applied.kept_last_admin:
        _audit(db, "sso_role_changed", user=user, ip=client_ip, status_="failure",
               details={"provider_id": pid, "from_role": "admin", "to_role": "admin", "reason": "last_administrator"})
        try:
            admins = [str(a.id) for a in api._active_admins(db)]
            api._notify_users(admins, "sso_role_kept", title="An administrator kept the role",
                              body=(f"{user.username} left the group {label} maps to the administrator role, but is the "
                                    "last administrator able to act, so the role was kept. Make another administrator "
                                    "before this one is demoted."),
                              target="#users", dedup_prefix=f"sso_role_kept:{user.id}:{datetime.utcnow():%Y-%m-%d}")
        except Exception as exc:  # noqa: BLE001
            log.info("sso last-administrator notice skipped: %s", type(exc).__name__)
    for ended in applied.ended_requests:
        _audit(db, "sso_admin_expired", ip=None, resource_type="sso_admin_request", resource_id=str(ended.id),
               details={"provider_id": pid, "user_id": str(user.id), "reason": MAPPING_GONE})
    if applied.request is not None:
        _audit(db, "sso_admin_requested", user=user, ip=client_ip, resource_type="sso_admin_request",
               resource_id=str(applied.request.id), details={"provider_id": pid, "provider_group": applied.request.provider_group})
        try:
            admins = [str(a.id) for a in api._active_admins(db)]
            api._notify_users(admins, "sso_admin_request", title="An administrator request is waiting",
                              body=(f"{user.username} signed in through {label} in a group mapped to the administrator "
                                    f"role. The role is granted only when another administrator approves, within "
                                    f"{REQUEST_DAYS} days, on the Users page."),
                              target="#users", dedup_prefix=f"sso_admin_request:{applied.request.id}")
            api._notify_users([str(user.id)], "sso_admin_request", title="Your administrator role waits for approval",
                              body=(f"Your organisation's sign-in through {label} puts you in a group mapped to the "
                                    "administrator role. An administrator must approve before the role is granted."),
                              target="#profile", dedup_prefix=f"sso_admin_request_own:{applied.request.id}")
        except Exception as exc:  # noqa: BLE001
            log.info("sso admin-request notice skipped: %s", type(exc).__name__)


def _audit(db, action: str, *, user=None, ip, details: dict, status_: str = "success", resource_type=None,
           resource_id=None) -> None:
    try:
        from app.services.audit_logger import AuditLogger
        AuditLogger(db).log_action(action=action, status=status_, user=user, ip_address=ip, details=details,
                                   resource_type=resource_type, resource_id=resource_id)
    except Exception:      # noqa: BLE001 -- the change stands without its row
        pass


# --------------------------------------------------------------------------- the held requests

def requests(db, *, now: Optional[datetime] = None):
    """(held, decided) requests, newest first; a held one past its time is marked expired here, with its row."""
    from app.core.models import SsoAdminRequest
    now = now or datetime.utcnow()
    rows = sorted(db.query(SsoAdminRequest).all(), key=lambda r: r.requested_at or now, reverse=True)
    held, decided = [], []
    for r in rows:
        if r.state == HELD and r.expires_at <= now:
            # Guarded by the row's state as the database holds it: a decision landing this second is not overwritten.
            expired = db.query(SsoAdminRequest).filter(SsoAdminRequest.id == r.id, SsoAdminRequest.state == HELD,
                                                       SsoAdminRequest.expires_at <= now).update(
                {"state": EXPIRED, "decided_at": now}, synchronize_session=False)
            if expired:
                r.state, r.decided_at = EXPIRED, now
                _audit(db, "sso_admin_expired", ip=None, resource_type="sso_admin_request", resource_id=str(r.id),
                       details={"provider_id": str(r.provider_id), "user_id": str(r.user_id)})
        (held if r.state == HELD else decided).append(r)
    return held, decided


def approver_refusal(db, approver, request) -> Optional[str]:
    """Why ``approver`` may not decide ``request``, as a reason code, or None: the approver rules of the credential
    changes with no requester (a sign-in asked), and the account must be able to act."""
    from app.core import admin_grants, independence
    from app.core import credential_changes as cc
    from app.core.password_origin import is_set_by_other
    if not cc.can_approve(approver):
        return "cannot_act"
    grants = admin_grants.of(db, [approver.id])
    changed = cc.changers(db, request.user_id, request.requested_at - cc.WINDOW)
    return independence.refusal_reason(approver.id, requester_id=None, approver_grant=grants.get(approver.id),
                                       requester_grant=None, changed=changed, requested_at=request.requested_at,
                                       target_id=request.user_id, approver_password_set_by_other=is_set_by_other(approver))


def decision_refusal(db, request, approver, *, now: Optional[datetime] = None) -> Optional[Conflict]:
    """Why ``request`` cannot be decided by ``approver`` now, or None."""
    from app.core.models import RoleEnum, SsoGroupMapping, SsoProvider, User
    from app.services.sso_sign_in import account_usable
    now = now or datetime.utcnow()
    if request.state != HELD:
        return Conflict("decided", f"This request was already {request.state}.")
    if request.expires_at <= now:
        return Conflict("expired", "This request has expired; the person signs in again to raise a new one.")
    provider = db.query(SsoProvider).filter(SsoProvider.id == request.provider_id).first()
    if provider is None or getattr(provider, "state", None) != "enabled":
        return Conflict("provider_gone", "The provider this request came from is gone or disabled.")
    if not sso_policy.effective(getattr(provider, "policy", None))["sso_admin_mapping"]:
        return Conflict("mapping_off", "The provider no longer maps a group to the administrator role.")
    if db.query(SsoGroupMapping).filter(SsoGroupMapping.provider_id == request.provider_id,
                                        SsoGroupMapping.provider_group == request.provider_group,
                                        SsoGroupMapping.role == "admin").first() is None:
        return Conflict("mapping_gone", "The group this request came from is no longer mapped to the administrator role.")
    user = db.query(User).filter(User.id == request.user_id).first()
    if user is None or not account_usable(user):
        return Conflict("account_unusable", "The account this request is about cannot sign in.")
    if getattr(user, "role", None) == RoleEnum.ADMIN:
        return Conflict("already_admin", "The account is an administrator already.")
    without = _providers_without_passwords(db, user)
    if without:
        named = " and ".join(without)
        return Conflict("sso_only", (
            f"The account is linked to {named}, whose people hold no password, and an administrator needs one. "
            f"Allow password sign-in for {named} (its Access settings) before granting the administrator role."))
    from app.core import auditor_rights
    held_by_rule = auditor_rights.promotion_refusal(db, user)
    if held_by_rule:
        return Conflict("auditor_right", held_by_rule)
    why = approver_refusal(db, approver, request)
    if why is not None:
        return Conflict(why, REFUSAL_TEXTS.get(why, "You may not decide this request."))
    return None


def denial_refusal(db, request, approver, *, now: Optional[datetime] = None) -> Optional[Conflict]:
    """Why ``request`` cannot be denied by ``approver`` now, or None. As for an approval, except that a request
    which can no longer be approved (:data:`NO_LONGER_GRANTABLE`) can still be denied by an administrator who may
    decide it: refused for both, it stayed in the list for its seven days with nothing anybody could do to it."""
    conflict = decision_refusal(db, request, approver, now=now)
    if conflict is None or conflict.code not in NO_LONGER_GRANTABLE:
        return conflict
    why = approver_refusal(db, approver, request)
    return Conflict(why, REFUSAL_TEXTS.get(why, "You may not decide this request.")) if why is not None else None


def approve(db, request, approver, *, http_request=None) -> dict:
    """Grant the role the request asks for, through the promotion path: the grant recorded with the approver as the
    grantor, a password set by someone else taken back, the permissions reset to the role's defaults; then the
    announcements. The caller checked :func:`decision_refusal` first."""
    from app.core.models import RoleEnum, User
    api = _api()
    user = db.query(User).filter(User.id == request.user_id).first()
    now = datetime.utcnow()
    old_role = getattr(user.role, "value", user.role)
    api._record_admin_grant(db, user, by=approver)
    taken = api._take_back_password_at_promotion(db, user, by=approver)
    removed = api._set_role(db, user, RoleEnum.ADMIN, actor=approver)
    from app.core import admin_grants
    grant = admin_grants.of(db, [user.id]).get(user.id)
    request.state = APPROVED
    request.decided_by = approver.id
    request.decided_by_name = approver.username
    # The decision's moment is the grant record's, so the two match exactly when the demotion rule asks.
    request.decided_at = getattr(grant, "granted_at", None) or now
    db.commit()
    try:
        api._announce_admin_granted(db, user, by_name=approver.username, how="promoted")
        api._notify_account_status_changes(db, user, by_name=approver.username, role=(old_role, "admin"),
                                           permissions_removed=removed)
    except Exception as exc:  # noqa: BLE001
        log.info("sso approval notices skipped: %s", type(exc).__name__)
    handed = api._hand_over_promotion_reset(db, taken, by=approver, request=http_request)
    return {"username": user.username, "handed_over": handed}


def deny(db, request, approver) -> None:
    """Refuse the request; the person is told. The caller checked :func:`decision_refusal` first."""
    from app.core.models import User
    api = _api()
    request.state = DENIED
    request.decided_by = approver.id
    request.decided_by_name = approver.username
    request.decided_at = datetime.utcnow()
    db.commit()
    user = db.query(User).filter(User.id == request.user_id).first()
    if user is not None:
        try:
            api._notify_users([str(user.id)], "sso_admin_request", title="Your administrator role was not granted",
                              body=("An administrator decided not to grant the administrator role your organisation's "
                                    "sign-in asked for. Your account is unchanged."),
                              target="#profile", dedup_prefix=f"sso_admin_denied:{request.id}")
        except Exception as exc:  # noqa: BLE001
            log.info("sso denial notice skipped: %s", type(exc).__name__)
