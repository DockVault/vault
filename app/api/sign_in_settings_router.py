"""Settings → Sign-in: the passkey settings an administrator tunes, under the fixed step-up
``admin.auth_policy.write`` (the password every time, plus the account's second factor when it has one).

``GET /settings/sign-in`` lists the settings with their values in force, the deployment's lock on each, and the
readiness of the public address passkeys are bound to; ``PUT /settings/sign-in/{setting}`` changes one, after the
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
    the deployment locked it; the public address's readiness (passkeys need one) and, when no passkey can be made at
    it, what to change, in words, and whether a requirement on some role waits because of it; whether trust anchors
    exist, and under direct attestation how many passkeys in use were added without it; how many passkeys in use
    never verified the person, and how many accounts hold no other (with the rule on, the ones that no longer
    count; with it off, the ones that would stop counting if it were turned on); how many accounts, and how many
    administrators among them, hold a passkey as their only second factor (the ones that set an authenticator app
    up at their next sign-in if passkeys are turned off); and the accounts the server's operator lifted a role's
    requirement for."""
    from app.core.public_url import readiness, why_no_passkeys
    never = ws_settings.never_verified(db)
    only = ws_settings.only_a_passkey(db)
    return {"settings": registry.describe(ws_settings.KEYS), "readiness": readiness(), "why_not": why_no_passkeys(),
            "requirement_paused": ws_settings.requirement_paused(),
            "unattested_passkeys": ws_settings.unattested_count(db),
            "passkeys_without_verification": never["passkeys"],
            "accounts_with_only_such_passkeys": never["accounts_with_no_other"],
            "requirement_lifted_for": ws_settings.lifted_for(db),
            "accounts_with_only_a_passkey": only["accounts"],
            "administrators_with_only_a_passkey": only["administrators"],
            "trust_anchors": len(ws_settings.trust_anchors()), "step_up": ws_settings.STEP_UP_ACTION}


@router.put("/settings/sign-in/{setting}")
def put_sign_in_setting(setting: str, body: SignInValue, request: Request,
                        current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Change one passkey setting: the registry's bounds and the deployment's lock, then the passkey guards (never
    'admin' among the passwordless roles; a requirement needs a usable public address; direct attestation needs
    anchors; no requirement that leaves no administrator able to sign in), then the step-up, then the change with
    its audit row. ``null`` returns the setting to the deployment's value.

    The path names the setting (``webauthn_mode``): a name, not a secret, so its parameter is not called a key (a
    path parameter named so is taken to hold a secret and masked in every log)."""
    key = setting
    limit_statements(db)
    spec = _spec_or_404(key)
    why = refusal(spec, body.value) or ws_settings.save_refusal(db, key, body.value)
    if why:
        raise HTTPException(status_code=400, detail=why)
    _step_up(db, current_user, request)       # may commit (a receipt is used once): bound the rest again
    limit_statements(db)
    old_algs = ws_settings.allowed_alg_names() if key == ws_settings.ALLOWED_ALGS else None
    verified_before = ws_settings.require_uv()
    passkeys_before = ws_settings.enabled()
    removed_algs = []
    try:
        outcome = setting_changes.request(db, key, body.value, actor=current_user)
        if key == ws_settings.ALLOWED_ALGS and outcome.status == "applied":
            new_algs = body.value if body.value is not None else spec.default
            ws_settings.record_algorithm_change(db, old_algs, new_algs)
            removed_algs = [name for name in old_algs or () if name not in set(new_algs or ())]
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
        if key == ws_settings.REQUIRE_UV and ws_settings.require_uv() and not verified_before:
            _tell_the_owners_of_keys_that_never_verified(db)
        if key == ws_settings.MODE and passkeys_before and not ws_settings.enabled():
            _tell_the_accounts_with_only_a_passkey(db)
        if removed_algs:
            _tell_the_owners_of_keys_of_a_removed_algorithm(db, removed_algs)
    setting_changes.announce_outcome(outcome, current_user.username)
    return {"status": outcome.status, "setting": registry.describe([key])[0]}


def _tell_the_owners_of_keys_of_a_removed_algorithm(db, removed_algs) -> None:
    """A signature algorithm was just removed: whoever holds a passkey of it is told now that the key is accepted
    for 30 more days and until when. The setting promised a notice to the owners; it was sent only where the key
    was used within those days, so an owner who signed in with a password and an authenticator code meanwhile met
    the refusal on the day after with no word before it. Best effort: the change is saved, and the key says the
    same when it is used."""
    try:
        from datetime import datetime, timedelta
        from app.api import api_server as api
        owners = [str(owner) for owner in ws_settings.owners_of_keys_of(db, removed_algs)]
        if owners:
            until = (datetime.utcnow() + timedelta(days=ws_settings.ALG_GRACE_DAYS)).date().isoformat()
            api._notify_users(owners, "security", title="One of your passkeys needs replacing",
                              body=("The signature algorithm one of your passkeys uses is no longer accepted by "
                                    f"this vault. That passkey still works until {until}; register a new passkey "
                                    "before then. Your list of passkeys shows which one."),
                              target="#profile",
                              dedup_prefix=f"passkey_alg_removed:{','.join(sorted(removed_algs))}:{until}")
    except Exception as exc:  # noqa: BLE001 -- the change is saved; nothing here may undo it
        log_failure("owners of passkeys of a removed algorithm were not told", exc)


def _tell_the_accounts_with_only_a_passkey(db) -> None:
    """Passkeys were just turned off: whoever held a passkey as their only second factor is told that they set an
    authenticator app up at their next sign-in. Best effort: the change is saved, and the sign-in says the same."""
    try:
        from datetime import datetime
        from app.api import api_server as api
        owners = [str(owner) for owner in ws_settings.only_a_passkey(db)["owners"]]
        if owners:
            api._notify_users(owners, "security", title="Passkeys were turned off on this vault",
                              body=("Your passkey was your only second factor here, and passkeys are no longer "
                                    "accepted. At your next sign-in you set an authenticator app up, after your "
                                    "password. Your passkeys are kept, and count again if passkeys are turned "
                                    "back on."),
                              target="#profile",
                              dedup_prefix=f"passkeys_turned_off:{datetime.utcnow().date().isoformat()}")
    except Exception as exc:  # noqa: BLE001 -- the change is saved; nothing here may undo it
        log_failure("accounts with only a passkey were not told that passkeys were turned off", exc)


def _tell_the_owners_of_keys_that_never_verified(db) -> None:
    """The rule that the authenticator verify the person was just turned on: whoever holds a passkey that never
    did is told that it no longer counts, and what to do. Best effort: the change is saved, and the sign-in page
    says the same to an account left with only such keys."""
    try:
        from datetime import datetime
        from app.api import api_server as api
        owners = [str(owner) for owner in ws_settings.never_verified(db)["owners"]]
        if owners:
            api._notify_users(owners, "security", title="One of your passkeys no longer counts here",
                              body=("This vault now asks every passkey to check a PIN, a fingerprint or a face. A "
                                    "passkey of yours has never done so, and is refused until it does: set a PIN "
                                    "on it and sign in with it, or add another passkey or an authenticator app. "
                                    "If it was your only second factor, you set one up again at your next "
                                    "sign-in."),
                              target="#profile",
                              dedup_prefix=f"passkey_never_verified:{datetime.utcnow().date().isoformat()}")
    except Exception as exc:  # noqa: BLE001 -- the change is saved; nothing here may undo it
        log_failure("owners of passkeys that never verified the person were not told", exc)
