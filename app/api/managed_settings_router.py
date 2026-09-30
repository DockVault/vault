"""The settings the panel manages through the settings registry (app/core/settings_registry.py).

    GET  /settings/managed         every managed setting: the value in force, where it came from (the
                                   default, .env, an administrator, or locked by the deployment), its
                                   bounds, and the .env lines that set them.
    PUT  /settings/managed/{key}   an administrator's value for one setting; ``{"value": null}`` goes back
                                   to the deployment's value.

Both are plain ``def`` routes, so they run on the thread pool, and every statement they send is bounded by a
statement timeout. Only an interactive administrator reaches them (a temporary credential is refused).

A change is written with its audit row in one transaction: the row names the setting and the values in
force before and after, and when the row cannot be written the change is not made either.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import settings_registry as registry
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Managed settings"])

# How long any statement of these routes may run.
STATEMENT_TIMEOUT_MS = 5000


def limit_statements(db: Session) -> None:
    """Bound every statement of the transaction ``db`` is in (Postgres; another database has no such
    setting). Call it again after anything that commits."""
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


class ManagedValue(BaseModel):
    value: Any = None


@router.get("/settings/managed")
def get_managed_settings(current_user: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    """Every managed setting, from this process's copy (no table is read for the values)."""
    limit_statements(db)
    return {"settings": registry.describe(), "locked": sorted(registry.locked_tokens())}


def spec_or_404(key: str) -> registry.SettingSpec:
    spec = registry.spec_for(key)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"{key} is not a managed setting")
    return spec


def in_force(spec: registry.SettingSpec) -> dict:
    """The one describe() row of ``spec``."""
    return registry.describe([spec.key])[0]


def refusal(spec: registry.SettingSpec, value) -> str | None:
    """Why the panel may not set ``spec`` to ``value``, or None. ``None`` (back to the deployment's
    value) is always allowed where the panel may set the setting at all."""
    if spec.editable != registry.ADMIN:
        return f"{spec.key} is set by the deployment, not in the panel"
    if registry.is_locked(spec):
        return f"{spec.key} is locked by the deployment (SETTINGS_LOCKED_KEYS)"
    if value is None:
        return None
    return registry.check_value(spec, value) or registry.check_bounds(spec, value)


@router.put("/settings/managed/{key}")
def put_managed_setting(key: str, body: ManagedValue, request: Request,
                        current_user: User = Depends(require_interactive_admin),
                        db: Session = Depends(get_db)):
    """Store an administrator's value for ``key``, with its audit row in the same transaction."""
    limit_statements(db)
    spec = spec_or_404(key)
    why = refusal(spec, body.value)
    if why:
        raise HTTPException(status_code=400, detail=why)
    before = in_force(spec)
    if body.value == before["stored"] and (body.value is not None or before["stored"] is None):
        return {"status": "unchanged", "setting": before}
    from app.services.audit_logger import AuditLogger
    try:
        registry.store(db, key, body.value, by_id=current_user.id, by_name=current_user.username)
        db.add(AuditLogger(db).build_row(
            action="setting_changed", status="success", user=current_user,
            resource_type="setting", resource_id=key,
            details={"key": key, "old": before["value"], "new": _value_after(spec, body.value),
                     "setting": body.value}))
        db.commit()
    except registry.SettingRefused as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:  # noqa: BLE001 -- no change without its audit row
        db.rollback()
        raise HTTPException(status_code=503, detail="The change was not saved: its audit record could not be "
                                                    "written. Nothing was changed.")
    registry.refresh()
    return {"status": "applied", "setting": in_force(spec)}


def _value_after(spec: registry.SettingSpec, setting):
    """The value in force once ``setting`` is stored (None: the deployment's value), as resolve() will
    give it after the refresh."""
    deployment, _source = registry.deployment_value(spec)
    floor, ceiling = registry.bounds(spec)
    return registry.clamp(spec, deployment if setting is None else setting, floor, ceiling)
