"""Settings → Sign-in: the passkey settings an administrator tunes, under the fixed step-up
``admin.auth_policy.write`` (the password every time, plus the account's second factor when it has one).

``GET /settings/sign-in`` lists the settings with their values in force, the deployment's lock on each, and the
readiness of the public address passkeys are bound to; ``PUT /settings/sign-in/{key}`` changes one, after the
registry's own checks and the passkey guards (app/core/webauthn_settings.save_refusal), with its audit row in
the same transaction; every administrator is told. A change applies at once (none of these settings deletes
records). Removing a signature algorithm is remembered, so existing keys of it stay usable for 30 days.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.managed_settings_router import limit_statements, refusal
from app.api.user_management_api import require_interactive_admin
from app.core import fixed_step_up
from app.core import setting_changes
from app.core import settings_registry as registry
from app.core import webauthn_settings as ws_settings
from app.core.database import get_db
from app.core.models import User
from app.core.safe_log import log_failure

router = APIRouter(tags=["Sign-in settings"])
_step_up = fixed_step_up.guard(ws_settings.STEP_UP_ACTION)


class SignInValue(BaseModel):
    value: Any = None


def _spec_or_404(key: str) -> registry.SettingSpec:
    spec = registry.spec_for(key)
    if spec is None or spec.group != ws_settings.GROUP:
        raise HTTPException(status_code=404, detail="Unknown sign-in setting.")
    return spec


@router.get("/settings/sign-in")
def get_sign_in_settings(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """The passkey settings as the page shows them: each with its value in force, where it comes from and whether
    the deployment locked it; the public address's readiness (passkeys need one); whether trust anchors exist."""
    from app.core.public_url import readiness
    return {"settings": registry.describe(ws_settings.KEYS), "readiness": readiness(),
            "trust_anchors": len(ws_settings.trust_anchors()), "step_up": ws_settings.STEP_UP_ACTION}


@router.put("/settings/sign-in/{key}")
def put_sign_in_setting(key: str, body: SignInValue, request: Request,
                        current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Change one passkey setting: the registry's bounds and the deployment's lock, then the passkey guards (never
    'admin' among the passwordless roles; a requirement needs a usable public address; direct attestation needs
    anchors; no requirement that leaves no administrator able to sign in), then the step-up, then the change with
    its audit row. ``null`` returns the setting to the deployment's value."""
    limit_statements(db)
    spec = _spec_or_404(key)
    why = refusal(spec, body.value) or ws_settings.save_refusal(db, key, body.value)
    if why:
        raise HTTPException(status_code=400, detail=why)
    _step_up(db, current_user, request)       # may commit (a receipt is used once): bound the rest again
    limit_statements(db)
    old_algs = ws_settings.allowed_alg_names() if key == ws_settings.ALLOWED_ALGS else None
    try:
        outcome = setting_changes.request(db, key, body.value, actor=current_user)
        if key == ws_settings.ALLOWED_ALGS and outcome.status == "applied":
            new_algs = body.value if body.value is not None else spec.default
            ws_settings.record_algorithm_change(db, old_algs, new_algs)
        db.commit()
    except HTTPException:
        raise
    except registry.SettingRefused as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no change without its audit row
        db.rollback()
        error_id = log_failure(f"a change of {spec.key} was not saved", exc)
        raise HTTPException(status_code=503, detail="The change was not saved: its audit record could not be "
                                                    f"written. Nothing was changed (error {error_id}).")
    if outcome.status == "applied":
        registry.refresh()
    setting_changes.announce_outcome(outcome, current_user.username)
    return {"status": outcome.status, "setting": registry.describe([key])[0]}
