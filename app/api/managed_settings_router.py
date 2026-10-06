"""The settings the panel manages through the settings registry (app/core/settings_registry.py).

    GET  /settings/managed/audit/preview               what the audit job would delete now under three
                                                       numbers of an administrator's choosing.
    GET  /settings/managed                             every managed setting (the value in force, where it
                                                       came from: the default, .env, an administrator, or
                                                       locked by the deployment; its bounds, and the .env
                                                       lines that set them), and the changes waiting.
    PUT  /settings/managed/{key}                       an administrator's value for one setting;
                                                       ``{"value": null}`` goes back to the deployment's value.
    POST /settings/managed/changes/{change_id}/cancel  cancel a waiting change, by any administrator.

A change that deletes data sooner waits before it applies, and any administrator may cancel it meanwhile
(app/core/setting_changes.py); every administrator is told of every change. Changing a value asks for the
password every time, plus any second factor the account has enrolled (the fixed step-up
``admin.retention.write``), which no setting of the step-up matrix weakens.

Every route is a plain ``def``, so it runs on the thread pool, and every statement it sends is bounded by a
statement timeout. Only an interactive administrator reaches them (a temporary credential is refused). A
change is written with its audit row in one transaction: when the row cannot be written, the change is not
made either.

Each change and each cancel also writes its seal in the audit log's integrity chain, in the same transaction
(app/core/audit_chain_policy_seals.py): the pruner acts on those seals, never on the database's values alone.
Another writer of seals holding the chain's lock gives 409 (busy, retry). While sealing is stopped, or before
the chain's first seal, a change that deletes sooner is refused with the reason; a change that keeps data
longer, and a cancel, are saved and sealed from the database once sealing runs again.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import audit_chain_policy_seals as chain_seals
from app.core import audit_integrity
from app.core import fixed_step_up
from app.core import setting_changes
from app.core import settings_registry as registry
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Managed settings"])

# How long any statement of these routes may run.
STATEMENT_TIMEOUT_MS = 5000

# The fixed step-up every change asks for.
STEP_UP_ACTION = "admin.retention.write"
_step_up = fixed_step_up.guard(STEP_UP_ACTION)

def limit_statements(db: Session, timeout_ms: int = STATEMENT_TIMEOUT_MS) -> None:
    """Bound every statement of the transaction ``db`` is in (Postgres; another database has no such
    setting). Call it again after anything that commits."""
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {int(timeout_ms)}"))


class ManagedValue(BaseModel):
    value: Any = None


def change_dict(change) -> Optional[dict]:
    if change is None:
        return None
    spec = registry.spec_for(change.key)
    iso = (lambda v: v.isoformat() + "Z" if v else None)
    return {"id": str(change.id), "key": change.key, "label": (spec.label if spec else "") or change.key,
            "setting": change.setting, "old": change.old_value, "new": change.new_value,
            "status": change.status, "requested_by": change.requested_by_name,
            "requested_at": iso(change.requested_at), "effective_at": iso(change.effective_at),
            "decided_by": change.decided_by_name, "decided_at": iso(change.decided_at), "reason": change.reason}


@router.get("/settings/managed")
def get_managed_settings(current_user: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    """Every managed setting, from this process's copy, and the changes waiting (read from the table)."""
    limit_statements(db)
    return {"settings": with_chain(registry.describe()), "locked": sorted(registry.locked_tokens()),
            "reduction_delay_days": registry.resolve(setting_changes.DELAY_KEY),
            "pending": [change_dict(c) for c in setting_changes.pending_for(db)]}


def spec_or_404(key: str) -> registry.SettingSpec:
    spec = registry.spec_for(key)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"{key} is not a managed setting")
    return spec


# Where the chain's entry came from, as the panel names where a value came from.
_CHAIN_SOURCE = {"setting": registry.SOURCE_ADMIN, "clamped": registry.SOURCE_ADMIN, "held": registry.SOURCE_ADMIN,
                 "env": registry.SOURCE_ENV, "default": registry.SOURCE_DEFAULT}


def with_chain(rows: list) -> list:
    """Each row of a setting the audit chain records shows what the pruner acts on (the chain's honoured
    entry): its value, where it came from, the administrator's setting behind it, and the entry itself beside
    them. The database's stored value alone decides nothing, so a value written into the database without the
    chain's key is never shown as in force; it is shown apart, as ``database_stored``."""
    entries = chain_seals.honoured_entries()
    for row in rows:
        entry = entries.get(row["key"])
        if entry is None:
            continue
        row["database_stored"] = row.get("stored")
        row["value"] = entry.get("value")
        if row.get("source") != registry.SOURCE_LOCKED:
            row["source"] = _CHAIN_SOURCE.get(entry.get("source"), row.get("source"))
        row["stored"] = entry.get("setting") if row["source"] == registry.SOURCE_ADMIN else None
        row["clamped"] = entry.get("source") == "clamped"
        row["chain"] = {"value": entry.get("value"), "setting": entry.get("setting"), "source": entry.get("source")}
    return rows


def in_force(spec: registry.SettingSpec) -> dict:
    """The one describe() row of ``spec``."""
    return with_chain(registry.describe([spec.key]))[0]


def refusal(spec: registry.SettingSpec, value) -> Optional[str]:
    """Why the panel may not set ``spec`` to ``value``, or None. ``None`` (back to the deployment's
    value) is always allowed where the panel may set the setting at all."""
    if spec.editable != registry.ADMIN:
        return f"{spec.key} is set by the deployment, not in the panel"
    if registry.is_locked(spec):
        return f"{spec.key} is locked by the deployment (SETTINGS_LOCKED_KEYS)"
    if value is not None:
        why = registry.check_value(spec, value) or registry.check_bounds(spec, value)
        if why:
            return why
    for check in setting_changes.CROSS_CHECKS:
        why = check(spec, value)
        if why:
            return why
    return None


@router.put("/settings/managed/{key}")
def put_managed_setting(key: str, body: ManagedValue, request: Request,
                        current_user: User = Depends(require_interactive_admin),
                        db: Session = Depends(get_db)):
    """Change ``key``: at once, or after the delay when it deletes data sooner, with its audit row in the
    same transaction; every administrator is told."""
    limit_statements(db)
    spec = spec_or_404(key)
    why = refusal(spec, body.value)
    if why:
        raise HTTPException(status_code=400, detail=why)
    _step_up(db, current_user, request)       # may commit (a receipt is used once): bound the rest again
    limit_statements(db)
    try:
        try:
            with chain_seals.change_transaction(db.get_bind()) as w:
                limit_statements(w.db)
                outcome = chain_seals.change(w, key, body.value, current_user)
                change = change_dict(outcome.change)
        except audit_integrity.ChainStopped as stopped:
            # No seal can be written: a change that deletes sooner waits for sealing; any other is saved, and
            # sealed from the database once sealing runs again.
            if chain_seals.refuses_while_stopped(db, key, body.value):
                db.rollback()
                raise HTTPException(status_code=409, detail=(
                    "This change deletes records sooner, and the audit log's integrity chain is not sealing "
                    f"just now ({stopped.kind}), so it cannot be recorded. Nothing was changed; try again later."))
            outcome = setting_changes.request(db, key, body.value, actor=current_user,
                                              judge=chain_seals.judge_now(key))
            change = change_dict(outcome.change)
            db.commit()
    except audit_integrity.ChainBusy:
        db.rollback()
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except HTTPException:
        raise
    except registry.SettingRefused as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no change without its audit row
        db.rollback()
        registry._say(f"Warning: a change of {key} was not saved ({type(exc).__name__}: {exc})")
        raise HTTPException(status_code=503, detail="The change was not saved: its audit record could not be "
                                                    "written. Nothing was changed.")
    if outcome.status == "applied":
        registry.refresh()
    setting_changes.announce_outcome(outcome, current_user.username)
    return {"status": outcome.status, "setting": in_force(spec), "change": change}


@router.post("/settings/managed/changes/{change_id}/cancel")
def cancel_managed_setting_change(change_id: uuid.UUID,
                                  current_user: User = Depends(require_interactive_admin),
                                  db: Session = Depends(get_db)):
    """Cancel a waiting change, with its audit row in the same transaction; every administrator is told."""
    limit_statements(db)
    try:
        try:
            with chain_seals.change_transaction(db.get_bind()) as w:
                limit_statements(w.db)
                change = setting_changes.cancel(w.db, change_id, actor=current_user)
                chain_seals.seal_cancel(w, change, current_user)
                details = {"key": change.key, "old": change.old_value, "new": change.new_value,
                           "requested_by": change.requested_by_name}
                out = change_dict(change)
        except audit_integrity.ChainStopped:
            # Saved now, honoured at once (it keeps data longer), sealed from the database once sealing runs.
            change = setting_changes.cancel(db, change_id, actor=current_user)
            details = {"key": change.key, "old": change.old_value, "new": change.new_value,
                       "requested_by": change.requested_by_name}
            out = change_dict(change)
            db.commit()
    except audit_integrity.ChainBusy:
        db.rollback()
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="No such change")
    except registry.SettingRefused as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no cancel without its audit row
        db.rollback()
        registry._say(f"Warning: a cancel of a waiting change was not saved ({type(exc).__name__}: {exc})")
        raise HTTPException(status_code=503, detail="The change was not cancelled: its audit record could not "
                                                    "be written. It is still waiting.")
    setting_changes.announce(setting_changes.CANCELLED_BY_ADMIN, details, current_user.username)
    return {"status": "cancelled", "change": out}


# A preview counts over the whole audit table, so it may take longer than a change.
PREVIEW_STATEMENT_TIMEOUT_MS = 30000


@router.get("/settings/managed/audit/preview")
def preview_audit_retention(max_days: Optional[int] = None, min_days: Optional[int] = None,
                            admin_min_days: Optional[int] = None, max_mb: Optional[int] = None,
                            current_user: User = Depends(require_interactive_admin),
                            db: Session = Depends(get_db)):
    """What the audit job would delete now if the three numbers were these (each left out: the value in
    force): rows and bytes by age and by size, by the same conditions the job uses."""
    limit_statements(db, PREVIEW_STATEMENT_TIMEOUT_MS)
    from app.core import audit_retention as ar
    numbers = ar.current()
    asked = {}
    for key, value in ((ar.MAX_DAYS, max_days), (ar.MIN_DAYS, min_days), (ar.ADMIN_MIN_DAYS, admin_min_days),
                       (ar.MAX_MB, max_mb)):
        if value is None:
            continue
        spec = registry.spec_for(key)
        why = registry.check_value(spec, value) or registry.check_bounds(spec, value)
        if why:
            raise HTTPException(status_code=400, detail=why)
        asked[key] = value
    numbers = ar.Numbers(asked.get(ar.MAX_DAYS, numbers.max_days), asked.get(ar.MIN_DAYS, numbers.min_days),
                         asked.get(ar.ADMIN_MIN_DAYS, numbers.admin_min_days), asked.get(ar.MAX_MB, numbers.max_mb))
    out = ar.preview(db, setting_changes.utcnow(), numbers)
    out["numbers"] = {ar.MAX_DAYS: numbers.max_days, ar.MIN_DAYS: numbers.min_days,
                      ar.ADMIN_MIN_DAYS: numbers.admin_min_days, ar.MAX_MB: numbers.max_mb}
    return out
