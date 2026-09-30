"""
Endpoint Permission System for granular access control.
This module provides decorators and utilities for checking endpoint-level permissions.
Uses app/core/api_catalog.py for comprehensive endpoint definitions.
"""
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, List, Optional, Set
import uuid as uuid_module

from fastapi import HTTPException, status
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.api_catalog import (
    GRANTABLE_API_CATALOG,
    dependency_closure,
    dependent_closure,
)
from app.core.models import RoleEnum, User, UserEndpointPermission


# Populated when route modules apply @require_endpoint_permission. api_server
# validates this registry once all routers and monolithic routes are loaded.
GUARDED_ENDPOINT_GROUPS: Set[str] = set()


def validate_endpoint_permission_contract() -> None:
    """Fail startup unless guarded and grantable group names match exactly."""
    grantable = set(GRANTABLE_API_CATALOG)
    missing_guards = sorted(grantable - GUARDED_ENDPOINT_GROUPS)
    unknown_guards = sorted(GUARDED_ENDPOINT_GROUPS - grantable)
    if missing_guards or unknown_guards:
        details = []
        if missing_guards:
            details.append(f"grantable groups without a route guard: {', '.join(missing_guards)}")
        if unknown_guards:
            details.append(f"route guards absent from the grantable catalog: {', '.join(unknown_guards)}")
        raise RuntimeError("Endpoint-permission contract mismatch: " + "; ".join(details))


def _required_groups(group_name: str) -> Set[str]:
    return {group_name, *dependency_closure(group_name)}


def _user_has_required_groups(db: Session, user_id, group_name: str) -> bool:
    required = _required_groups(group_name)
    held = {
        row[0]
        for row in db.query(UserEndpointPermission.endpoint_group).filter(
            UserEndpointPermission.user_id == user_id,
            UserEndpointPermission.endpoint_group.in_(required),
        ).all()
    }
    return required <= held


def _audit_endpoint_denial(db, user, group_name: str, reason: str) -> None:
    """Record an endpoint-permission denial in the audit log. The deployment audited authorised
    actions but not refused ones, so a defender reviewing the log after an incident saw who got in,
    never who was turned away at a permission gate -- the higher-signal half. This runs only on the
    denial path (the happy path is untouched) and only after the read-only permission checks, so the
    request session carries no pending writes. Best-effort by contract: a failure here must never
    turn the 403 the caller is already getting into a 500, so everything is swallowed."""
    try:
        from app.services.audit_logger import AuditLogger
        from app.core.net_utils import current_client_ip
        # ClientIPMiddleware stamps the trusted-proxy client IP per request into a contextvar, so it
        # is available even on endpoints that declare no `request` parameter.
        ip = current_client_ip()
        AuditLogger(db).log_action(
            action="endpoint_permission_denied",
            status="failure",
            user=user,
            resource_type="endpoint_group",
            resource_id=str(group_name),
            ip_address=ip,
            details={"required_group": str(group_name), "reason": reason},
        )
    except Exception:  # noqa: BLE001 — a lost audit row must never mask the 403
        pass


def require_endpoint_permission(group_name: str):
    """Require a grantable endpoint group and all of its dependencies."""
    if group_name not in GRANTABLE_API_CATALOG:
        raise ValueError(f"Unknown grantable endpoint group: {group_name}")

    def decorator(func: Callable):
        GUARDED_ENDPOINT_GROUPS.add(group_name)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            check_endpoint_permission(kwargs.get("db"), kwargs.get("current_user"),
                                      group_name, kwargs)
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def check_endpoint_permission(db, current_user, group_name: str, kwargs=None) -> None:
    """Raise unless `current_user` may use `group_name` right now. The decorator's whole decision,
    named so it can be asked AGAIN -- a long request (a chunk upload streaming a body) is judged
    once before the body and must be judged once more before it publishes, against permissions that
    may have been withdrawn while the bytes were arriving. One implementation, so the second ask
    cannot drift from the first."""
    kwargs = kwargs or {}
    if not current_user or db is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    reason = endpoint_permission_denial(db, current_user, group_name, kwargs)
    if reason is None:
        return
    _audit_endpoint_denial(db, current_user, group_name, reason)
    if reason == "temp_credential_scope":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Temporary credential scope does not permit this action ({group_name})",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "You do not have permission to access this resource. "
            f"Required permission: {group_name}"
        ),
    )


def endpoint_permission_denial(db, current_user, group_name: str, kwargs=None) -> Optional[str]:
    """Why `current_user` may not use `group_name` right now ("temp_credential_scope" or
    "missing_required_group"), or None when they may. The decision and nothing else: no audit row
    and no exception, so a caller that only needs to KNOW -- whether to show a vault's member count
    in a list, say -- can ask once per row without logging a denial per row. check_endpoint_permission
    is this decision plus the audit row and the 403, so the two cannot drift apart."""
    kwargs = kwargs or {}
    # Temporary-credential sessions are gated by their OWN scope and never
    # inherit the admin bypass. A temp credential minted by an admin can use
    # ordinary scoped groups because its creator has every group by role.
    if getattr(current_user, "_is_temp_session", False):
        from app.core.temp_scope import temp_session_allows_group

        if not temp_session_allows_group(current_user, group_name, kwargs):
            return "temp_credential_scope"
        if current_user.role != RoleEnum.ADMIN and not _user_has_required_groups(
            db, current_user.id, group_name
        ):
            return "missing_required_group"
        return None

    if current_user.role == RoleEnum.ADMIN:
        return None

    if not _user_has_required_groups(db, current_user.id, group_name):
        return "missing_required_group"
    return None


def _ordered_with_dependencies(group_names: List[str]) -> List[str]:
    ordered = []
    seen = set()
    for group_name in group_names:
        if group_name not in GRANTABLE_API_CATALOG:
            raise ValueError(f"Unknown grantable endpoint group: {group_name}")
        for candidate in [*dependency_closure(group_name), group_name]:
            if candidate not in seen:
                ordered.append(candidate)
                seen.add(candidate)
    return ordered


def _insert_permission_groups(
    user_id: uuid_module.UUID,
    group_names: List[str],
    db: Session,
    granted_by: Optional[uuid_module.UUID],
) -> None:
    if not group_names:
        return
    now = datetime.now(timezone.utc)
    values = [
        {
            "id": uuid_module.uuid4(),
            "user_id": user_id,
            "endpoint_group": group_name,
            "granted_at": now,
            "granted_by": granted_by,
        }
        for group_name in group_names
    ]
    if db.get_bind().dialect.name == "sqlite":
        # The offline tests' database. The same statement: a row the account already holds stays as it is.
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        statement = sqlite_insert(UserEndpointPermission).values(values).on_conflict_do_nothing(
            index_elements=["user_id", "endpoint_group"])
    else:
        statement = pg_insert(UserEndpointPermission).values(values).on_conflict_do_nothing(
            constraint="uq_user_endpoint")
    db.execute(statement)


def grant_endpoint_permission(
    user_id: str,
    endpoint_group: str,
    db: Session,
    granted_by: Optional[str] = None,
    commit: bool = True,
) -> List[str]:
    """Atomically grant a group and every transitive prerequisite."""
    groups = _ordered_with_dependencies([endpoint_group])
    target_id = uuid_module.UUID(user_id)
    granter_id = uuid_module.UUID(granted_by) if granted_by else None
    try:
        _insert_permission_groups(target_id, groups, db, granter_id)
        if commit:
            db.commit()
    except Exception:
        db.rollback()
        raise
    return groups


# The revision of the role defaults that every release before revisions existed granted: those releases
# granted each account its role's defaults again at every start, so an account they left behind (its
# users.permission_defaults_revision NULL) holds them, apart from those revoked since.
BASELINE_DEFAULTS_REVISION = 1

# Written for each default a start gives an account (grant_newer_role_defaults).
DEFAULT_GRANTED_ACTION = "permission_default_granted"


def current_defaults_revision() -> int:
    """The newest revision of the role defaults: the highest ``default_since`` of any default."""
    return max([group.default_since for group in GRANTABLE_API_CATALOG.values() if group.default_for_roles]
               + [BASELINE_DEFAULTS_REVISION])


def role_default_groups(role, since: Optional[int] = None) -> List[str]:
    """The groups ``role`` (a RoleEnum or its text) has by default, with their prerequisites, in
    dependency-first order. With ``since``, only the defaults added after that revision, with their
    prerequisites."""
    role_str = str(getattr(role, "value", role)).lower().replace("roleenum.", "").replace("role.", "")
    return _ordered_with_dependencies([
        group_name
        for group_name, group in GRANTABLE_API_CATALOG.items()
        if role_str in [item.lower() for item in group.default_for_roles]
        and (since is None or group.default_since > since)
    ])


def _record_defaults_revision(db: Session, user_id) -> None:
    """The account ``user_id`` now holds every default of its role: record the current revision, in the
    caller's transaction."""
    account = db.get(User, uuid_module.UUID(str(user_id)))
    if account is not None:
        account.permission_defaults_revision = current_defaults_revision()


def reset_to_role_defaults(user_id, role, db: Session) -> dict:
    """``user_id``'s role has just changed to ``role``: bring the permissions stored for the account to
    that role's defaults, in the caller's transaction (nothing is committed), and say what changed:
    ``{"removed": [...], "added": [...], "kept": [...]}``, group names, ``kept`` being the grants that
    stayed although the role does not have them by default.

    Each role's defaults are stored as rows when an account is created (POST /users, an invitation,
    sign-up), with no granter; a permission an administrator grants records who granted it. An account
    created as an administrator therefore holds the permissions to view and to manage users as rows, and
    before this a change of role left them there: an administrator made a user kept the permission to
    manage users, which nobody had granted to a user, and with it made password reset links for other
    people's accounts.

    What stays: the new role's defaults, and each permission another account granted this one (its
    granter is recorded and is not the account itself), with what it depends on, because an
    administrator may give that to anyone. What goes: every other row, that is the old role's defaults,
    and a permission the account granted itself while it was an administrator, which changed nothing
    then and must not outlast its own demotion. A grant whose granter's account was deleted since has
    lost its granter (the column is set to NULL), cannot be told from a default, and goes too; an
    administrator can grant it again. Rows naming a group outside the catalogue are left alone: nothing
    requires them."""
    target = uuid_module.UUID(str(user_id))
    defaults = role_default_groups(role)
    rows = db.query(UserEndpointPermission).filter(
        UserEndpointPermission.user_id == target,
        UserEndpointPermission.endpoint_group.in_(GRANTABLE_API_CATALOG),
    ).all()
    held = {row.endpoint_group for row in rows}
    granted = {row.endpoint_group for row in rows
               if row.granted_by is not None and row.granted_by != target}
    keep = set(defaults) | granted | {dep for group in granted for dep in dependency_closure(group)}
    removed = sorted(held - keep)
    if removed:
        db.query(UserEndpointPermission).filter(
            UserEndpointPermission.user_id == target,
            UserEndpointPermission.endpoint_group.in_(removed),
        ).delete(synchronize_session=False)
    added = [group for group in defaults if group not in held]
    _insert_permission_groups(target, added, db, None)
    _record_defaults_revision(db, target)
    return {"removed": removed, "added": sorted(added), "kept": sorted((keep & held) - set(defaults))}


def grant_default_permissions_for_role(
    user_id: str,
    role: str,
    db: Session,
    commit: bool = True,
) -> List[str]:
    """Atomically grant every grantable role default and its prerequisites.

    `commit=False` lets a caller fold the grant into a surrounding transaction (e.g. invitation
    acceptance, which claims the invite and creates the user in one commit); the default keeps the
    self-committing behaviour every existing caller relies on. The account is recorded as holding the
    current revision of the defaults (users.permission_defaults_revision)."""
    groups = role_default_groups(role)
    try:
        _insert_permission_groups(uuid_module.UUID(user_id), groups, db, None)
        _record_defaults_revision(db, user_id)
        if commit:
            db.commit()
    except Exception:
        db.rollback()
        raise
    return groups


def grant_newer_role_defaults(db: Session) -> dict:
    """At start: give each account that is not an administrator the defaults of its role that are newer
    than the revision it has been given, once, and record the current revision on it. Returns
    ``{"accounts": n, "grants": m}``, how many accounts were brought up to date and how many
    permissions were granted. Commits.

    A default an administrator revoked is not given back: only a default added in a later revision is
    granted, with what it depends on, and each grant is recorded as ``permission_default_granted`` in
    the same commit. An account no revision was recorded for (every account an earlier release left
    behind) counts as holding revision 1, whose defaults those releases granted at every start; a start
    therefore grants it nothing of revision 1, only what came after. Administrators are skipped: they
    hold every group, and a change of role records the revision."""
    from sqlalchemy import or_
    from app.services.audit_logger import AuditLogger

    current = current_defaults_revision()
    accounts = db.query(User).filter(
        User.role != RoleEnum.ADMIN,
        or_(User.permission_defaults_revision.is_(None), User.permission_defaults_revision < current),
    ).all()
    grants = 0
    for account in accounts:
        since = account.permission_defaults_revision or BASELINE_DEFAULTS_REVISION
        held = {row[0] for row in db.query(UserEndpointPermission.endpoint_group).filter(
            UserEndpointPermission.user_id == account.id).all()}
        new = [group for group in role_default_groups(account.role, since=since) if group not in held]
        _insert_permission_groups(account.id, new, db, None)
        for group in new:
            db.add(AuditLogger(db).build_row(
                action=DEFAULT_GRANTED_ACTION, status="success", resource_type="user",
                resource_id=str(account.id),
                details={"endpoint_group": group, "target_user": account.username,
                         "role": getattr(account.role, "value", account.role),
                         "from_revision": since, "to_revision": current}))
        grants += len(new)
        account.permission_defaults_revision = current
    db.commit()
    return {"accounts": len(accounts), "grants": grants}


def revoke_endpoint_permission(
    user_id: str,
    endpoint_group: str,
    db: Session,
    commit: bool = True,
) -> List[str]:
    """Atomically revoke a group and all groups that transitively require it."""
    if endpoint_group not in GRANTABLE_API_CATALOG:
        raise ValueError(f"Unknown grantable endpoint group: {endpoint_group}")
    groups = [endpoint_group, *dependent_closure(endpoint_group)]
    try:
        db.query(UserEndpointPermission).filter(
            UserEndpointPermission.user_id == uuid_module.UUID(user_id),
            UserEndpointPermission.endpoint_group.in_(groups),
        ).delete(synchronize_session=False)
        if commit:
            db.commit()
    except Exception:
        db.rollback()
        raise
    return groups


def get_user_permissions(user_id: str, db: Session) -> List[dict]:
    """Return endpoint details for the user's grantable permission rows."""
    permissions = db.query(UserEndpointPermission).filter(
        UserEndpointPermission.user_id == uuid_module.UUID(user_id),
        UserEndpointPermission.endpoint_group.in_(GRANTABLE_API_CATALOG),
    ).all()

    results = []
    for permission in permissions:
        endpoint_group = permission.endpoint_group
        group = GRANTABLE_API_CATALOG.get(endpoint_group)
        if not group:
            continue
        for endpoint in group.endpoints:
            results.append({
                "endpoint_group": endpoint_group,
                "endpoint_pattern": endpoint.path,
                "method": endpoint.method,
                "is_allowed": True,
                "granted_at": (
                    permission.granted_at.isoformat()
                    if permission.granted_at is not None
                    else None
                ),
                "granted_by": (
                    str(permission.granted_by)
                    if permission.granted_by is not None
                    else None
                ),
            })

    return results
