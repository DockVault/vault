"""Groups from the provider into departments and roles, at each sign-in through it.

At a sign-in (purpose ``sign_in`` or ``app``) every mapping of the provider (``sso_group_mappings``) is applied: the
person joins the mapped department when the group is in the token and leaves it when it is not; departments no
mapping names are never touched. A token with **no group information** (the claim absent, or Entra's marker for
too many groups) changes nothing: a server warning, and an administrator notice once a day per provider. A role
of ``user`` or ``external`` applies at once (an administrator is never demoted by it). ``admin`` is never granted
by a sign-in: with the provider's ``sso_admin_mapping`` on, a **held request** (``sso_admin_requests``) is opened
for another administrator to approve, under the approver rules of the credential changes with no requester, and
on approval the promotion path records the grant with the approver as the grantor. An administrator made that way
who leaves the mapped group is demoted at the next sign-in through the provider, except the last administrator
able to act. Nothing here commits: :func:`apply` writes in the caller's transaction, :func:`tell` records and
notifies after the commit.
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
HELD, APPROVED, DENIED, EXPIRED = "held", "approved", "denied", "expired"

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
    role: Optional[tuple] = None                           # (old, new) when the role changed
    permissions_removed: list = field(default_factory=list)
    request: object = None                                 # the held administrator request opened now
    demoted: bool = False
    kept_last_admin: bool = False                          # a demotion the last-administrator rule stopped
    lost: object = None                                    # what _account_lost_standing did, told after the commit
    no_groups: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.joined or self.left or self.role or self.request is not None or self.demoted)


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
    admin_group = next((m.provider_group for m in mappings if m.role == "admin" and m.provider_group in present), None)
    maps_admin = any(m.role == "admin" for m in mappings)
    if getattr(user, "role", None) == RoleEnum.ADMIN:
        if maps_admin and admin_group is None and made_administrator_through(db, user, row):
            _demote(db, user, roles, applied)
        return applied
    if admin_group is not None and policy["sso_admin_mapping"]:
        applied.request = _request_admin(db, user, row, admin_group)
    lesser = "user" if "user" in roles else ("external" if "external" in roles else None)
    if lesser is not None and getattr(user.role, "value", user.role) != lesser:
        old = getattr(user.role, "value", user.role)
        applied.permissions_removed = _api()._set_role(db, user, RoleEnum(lesser), actor=None)
        applied.role = (old, lesser)
    return applied


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
    for group in groups:
        user.groups.append(group)
        applied.joined.append(group.name)
        applied.joined_ids.append(str(group.id))
    db.flush()
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
    wanted = {str(g) for g in group_ids}
    for group in list(user.groups or []):
        if str(group.id) in wanted:
            user.groups.remove(group)
            applied.left.append(group.name)
            applied.left_ids.append(str(group.id))


def _demote(db, user, roles, applied: Applied) -> None:
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
    applied.role = ("admin", new_role.value)
    applied.demoted = True


def _request_admin(db, user, row, group: str):
    """The held request for ``user`` on this provider: the one still held, or a new one (seven days)."""
    from app.core.models import SsoAdminRequest
    now = datetime.utcnow()
    for r in db.query(SsoAdminRequest).filter(SsoAdminRequest.user_id == user.id,
                                              SsoAdminRequest.provider_id == row.id).all():
        if r.state == HELD and r.expires_at > now:
            return None                      # already waiting: nothing new to tell
    request = SsoAdminRequest(id=uuid.uuid4(), user_id=user.id, provider_id=row.id, provider_group=str(group)[:255],
                              requested_at=now, expires_at=now + timedelta(days=REQUEST_DAYS), state=HELD)
    db.add(request)
    return request


def made_administrator_through(db, user, row) -> bool:
    """Whether ``user`` became an administrator by an approved request of this provider's mapping (the only
    administrators a mapping may take the role from; one made by hand keeps it)."""
    from app.core.models import SsoAdminRequest
    return db.query(SsoAdminRequest).filter(SsoAdminRequest.user_id == user.id, SsoAdminRequest.provider_id == row.id,
                                            SsoAdminRequest.state == APPROVED).first() is not None


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
    for gid in applied.joined_ids:
        api._audit_access_change(db, None, "group_members_added", "group", gid,
                                 {"user_ids": [str(user.id)], "added": 1, "via": "single_sign_on", "provider_id": pid})
    for gid in applied.left_ids:
        api._audit_access_change(db, None, "group_member_removed", "group", gid,
                                 {"user_id": str(user.id), "via": "single_sign_on", "provider_id": pid})
    if applied.role is not None:
        _audit(db, "sso_role_changed", user=user, ip=client_ip,
               details={"provider_id": pid, "from": applied.role[0], "to": applied.role[1], "demoted": applied.demoted})
        try:
            api._notify_account_status_changes(db, user, by_name=BY_NAME, role=applied.role,
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
               details={"provider_id": pid, "from": "admin", "to": "admin", "reason": "last_administrator"})
        try:
            admins = [str(a.id) for a in api._active_admins(db)]
            api._notify_users(admins, "sso_role_kept", title="An administrator kept the role",
                              body=(f"{user.username} left the group {label} maps to the administrator role, but is the "
                                    "last administrator able to act, so the role was kept. Make another administrator "
                                    "before this one is demoted."),
                              target="#users", dedup_prefix=f"sso_role_kept:{user.id}:{datetime.utcnow():%Y-%m-%d}")
        except Exception as exc:  # noqa: BLE001
            log.info("sso last-administrator notice skipped: %s", type(exc).__name__)
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
            r.state = EXPIRED
            r.decided_at = now
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
    from app.core.models import RoleEnum, User
    from app.services.sso_sign_in import account_usable
    now = now or datetime.utcnow()
    if request.state != HELD:
        return Conflict("decided", f"This request was already {request.state}.")
    if request.expires_at <= now:
        return Conflict("expired", "This request has expired; the person signs in again to raise a new one.")
    user = db.query(User).filter(User.id == request.user_id).first()
    if user is None or not account_usable(user):
        return Conflict("account_unusable", "The account this request is about cannot sign in.")
    if getattr(user, "role", None) == RoleEnum.ADMIN:
        return Conflict("already_admin", "The account is an administrator already.")
    why = approver_refusal(db, approver, request)
    if why is not None:
        return Conflict(why, REFUSAL_TEXTS.get(why, "You may not decide this request."))
    return None


def approve(db, request, approver, *, http_request=None) -> dict:
    """Grant the role the request asks for, through the promotion path: the grant recorded with the approver as the
    grantor, a password set by someone else taken back, the permissions reset to the role's defaults; then the
    announcements. The caller checked :func:`decision_refusal` first."""
    from app.core.models import RoleEnum, User
    api = _api()
    user = db.query(User).filter(User.id == request.user_id).first()
    now = datetime.utcnow()
    api._record_admin_grant(db, user, by=approver)
    taken = api._take_back_password_at_promotion(db, user, by=approver)
    removed = api._set_role(db, user, RoleEnum.ADMIN, actor=approver)
    request.state = APPROVED
    request.decided_by = approver.id
    request.decided_by_name = approver.username
    request.decided_at = now
    db.commit()
    try:
        api._announce_admin_granted(db, user, by_name=approver.username, how="promoted")
        api._notify_account_status_changes(db, user, by_name=approver.username, role=("user", "admin"),
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
