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
from app.core.models import RoleEnum, UserEndpointPermission


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


def require_endpoint_permission(group_name: str):
    """Require a grantable endpoint group and all of its dependencies."""
    if group_name not in GRANTABLE_API_CATALOG:
        raise ValueError(f"Unknown grantable endpoint group: {group_name}")

    def decorator(func: Callable):
        GUARDED_ENDPOINT_GROUPS.add(group_name)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")
            db = kwargs.get("db")

            if not current_user or not db:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            # Temporary-credential sessions are gated by their OWN scope and never
            # inherit the admin bypass. A temp credential minted by an admin can use
            # ordinary scoped groups because its creator has every group by role.
            if getattr(current_user, "_is_temp_session", False):
                from app.core.temp_scope import temp_session_allows_group

                if not temp_session_allows_group(current_user, group_name, kwargs):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Temporary credential scope does not permit this action ({group_name})",
                    )
                if current_user.role != RoleEnum.ADMIN and not _user_has_required_groups(
                    db, current_user.id, group_name
                ):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=(
                            "You do not have permission to access this resource. "
                            f"Required permission: {group_name}"
                        ),
                    )
                return await func(*args, **kwargs)

            if current_user.role == RoleEnum.ADMIN:
                return await func(*args, **kwargs)

            if not _user_has_required_groups(db, current_user.id, group_name):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "You do not have permission to access this resource. "
                        f"Required permission: {group_name}"
                    ),
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


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
    statement = pg_insert(UserEndpointPermission).values([
        {
            "id": uuid_module.uuid4(),
            "user_id": user_id,
            "endpoint_group": group_name,
            "granted_at": now,
            "granted_by": granted_by,
        }
        for group_name in group_names
    ]).on_conflict_do_nothing(constraint="uq_user_endpoint")
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


def grant_default_permissions_for_role(
    user_id: str,
    role: str,
    db: Session,
) -> List[str]:
    """Atomically grant every grantable role default and its prerequisites."""
    role_str = str(role).lower().replace("roleenum.", "").replace("role.", "")
    defaults = [
        group_name
        for group_name, group in GRANTABLE_API_CATALOG.items()
        if role_str in [item.lower() for item in group.default_for_roles]
    ]
    groups = _ordered_with_dependencies(defaults)
    try:
        _insert_permission_groups(uuid_module.UUID(user_id), groups, db, None)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return groups


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
