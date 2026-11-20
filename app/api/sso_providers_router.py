"""Settings → Sign-in: the single sign-on providers, for administrators.

``GET /admin/sso/providers`` lists them with the wizard's presets and whether the vault has an address a provider can
send a browser back to; ``POST`` makes a draft (so its two addresses exist before the provider's own console is
touched); ``PATCH`` changes one; ``POST .../state`` turns it on or off; ``DELETE`` removes it. The rules are in
app/services/sso_providers.py. A test sign-in starts and finishes in app/api/sso_router.py.

Every write is refused while the deployment has locked single sign-on (app/core/sso_settings.py), is judged before
anything is asked of the administrator, then asks the fixed step-up every sign-in setting is written under, then
judges again on the row as it stands, writes, and records what changed (the names of the fields, never a value: an
issuer is not a secret, but a row that never holds a secret cannot leak one). The other administrators are told.
The client secret is taken, encrypted and never answered.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import fixed_step_up, sso_presets, sso_settings
from app.core.database import get_db
from app.core.models import SsoProvider, User
from app.services import sso_providers as providers

router = APIRouter(tags=["Single sign-on administration"])
log = logging.getLogger("dockvault.sso")

STEP_UP_ACTION = "admin.auth_policy.write"
_step_up = fixed_step_up.guard(STEP_UP_ACTION)


class ProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    preset: Optional[str] = Field(default=None, max_length=40)


class ProviderState(BaseModel):
    state: str = Field(min_length=1, max_length=16)


def _api():
    from app.api import api_server
    return api_server


def _audit(db, action: str, *, user, ip, row_id, details: dict) -> None:
    try:
        from app.services.audit_logger import AuditLogger
        AuditLogger(db).log_action(action=action, status="success", user=user, ip_address=ip, details=details,
                                   resource_type="sso_provider", resource_id=str(row_id))
    except Exception as exc:      # noqa: BLE001 -- the change stands; the missing row is said
        log.warning("sso provider audit row not written: %s", type(exc).__name__)


def _tell_administrators(by: str, title: str, body: str) -> None:
    """Tell every active administrator of a change to the providers, in the app and by email, after the commit, as a
    change of a managed setting is told. Never raises."""
    try:
        from app.core import setting_changes
        from app.core.database import get_db_context
        from app.core.models import RoleEnum
        api = _api()
        with get_db_context() as db:
            admins = db.query(User).filter(User.role == RoleEnum.ADMIN, User.is_active.is_(True)).all()
            api._notify_users([str(a.id) for a in admins], setting_changes.NOTICE_TYPE, title=title, body=body,
                              target="#settings")
            api._fire_action_email_bulk(db, setting_changes.EMAIL_ACTION, [(a.email, a.username) for a in admins],
                                        {"change": body, "by": by or "", "when": api._change_time_text()})
    except Exception as exc:  # noqa: BLE001
        log.info("sso provider notice skipped: %s", type(exc).__name__)


def _refuse_locked() -> None:
    if sso_settings.locked():
        raise HTTPException(status_code=409, detail={"reason": "locked", "message": sso_settings.LOCKED_TEXT})


def _row_or_404(db, provider_id, *, lock: bool = False) -> SsoProvider:
    try:
        pid = uuid.UUID(str(provider_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    query = db.query(SsoProvider).filter(SsoProvider.id == pid)
    if lock:
        query = query.populate_existing().with_for_update()      # one change at a time, on the row as it stands
    row = query.first()
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    return row


def _tell_accounts(users, title: str, change: str) -> None:
    """Tell each of ``users`` of a change an administrator made to how their account signs in: in the app, and by
    email when the account has an address and email is configured. After the commit; never raises."""
    api = _api()
    try:
        from app.core.database import get_db_context
        with get_db_context() as db:
            for user_id, username, email in users:
                try:
                    api._notify_users([str(user_id)], "account_changed", title=title, body=change, target="#profile")
                    if (email or "").strip():
                        api._fire_action_email(db, "sign_in_method_changed", email=email, username=username,
                                               action_context={"change": change, "when": api._change_time_text()})
                except Exception as exc:  # noqa: BLE001 -- one notice that fails does not stop the others
                    log.info("sso account notice skipped: %s", type(exc).__name__)
    except Exception as exc:  # noqa: BLE001
        log.info("sso account notices skipped: %s", type(exc).__name__)


def _end_sessions_of(db, provider_id) -> int:
    """End every session that came through the provider, once it is off (no new sign-in and no renewal goes through
    it any more): each account's turn at its sessions first, as a provider's own logout ends them. Returns how
    many ended; a failure ends none and is logged, and the provider stays off."""
    from app.api import sso_router
    from app.core.models import SsoSession
    api = _api()
    try:
        query = db.query(SsoSession).filter(SsoSession.provider_id == provider_id)
        named = [s.session_id for s in query.all()]
        if not named:
            return 0
        for owner in sso_router._owners_of(db, named):
            api._sessions_turn(db, owner)
        session_ids = [s.session_id for s in query.all()]
        ended = api._revoke_sessions(db, session_ids=session_ids, actor_username="provider turned off",
                                     durable=True) if session_ids else 0
        db.commit()
        return int(ended or 0)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.warning("sso sessions of a provider turned off were not ended: %s", type(exc).__name__)
        return 0


def _accounts_named(db, usernames) -> list:
    """(id, username, email) of the accounts ``usernames`` names, for a notice sent after the commit."""
    names = list(usernames or [])
    if not names:
        return []
    return [(u.id, u.username, u.email) for u in db.query(User).filter(User.username.in_(names)).all()]


SET_A_PASSWORD = ("Your account has no password yet: set one with \"Forgot password\" on the sign-in page, or ask an "
                  "administrator for a reset link.")


def _refused(exc) -> HTTPException:
    if isinstance(exc, providers.Invalid):
        return HTTPException(status_code=400, detail={"reason": "invalid", "field": exc.field, "message": exc.said})
    return HTTPException(status_code=409, detail={"reason": exc.reason, "message": str(exc)})


def _address() -> dict:
    """Whether the vault has an address a provider can send a browser back to, and what to change when not."""
    from app.core import public_url
    from app.services import sso_sign_in
    why = sso_sign_in.address_refusal()
    return {"usable": why is None, "base": public_url.public_base_url() or None, "why_not": why}


@router.get("/admin/sso/providers")
def list_providers(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """The providers in the sign-in page's order, the wizard's presets, the vault's address as a provider needs it,
    and whether the deployment locked single sign-on."""
    rows = sorted(db.query(SsoProvider).all(),
                  key=lambda r: (r.sort_order or 0, (r.label or r.name or "").lower(), str(r.id)))
    return {"providers": [providers.public(db, row) for row in rows], "presets": sso_presets.public(),
            "icons": list(providers.ICONS), "limit": providers.MAX_PROVIDERS, "address": _address(),
            "locked": sso_settings.locked(), "step_up": STEP_UP_ACTION}


@router.get("/admin/sso/providers/{provider_id}")
def get_provider(provider_id: str, current_user: User = Depends(require_interactive_admin),
                 db: Session = Depends(get_db)):
    return {"provider": providers.public(db, _row_or_404(db, provider_id))}


@router.post("/admin/sso/providers", status_code=201)
def create_provider(body: ProviderCreate, request: Request, current_user: User = Depends(require_interactive_admin),
                    db: Session = Depends(get_db)):
    """Make a draft provider, filled in from a preset when one is named. It is off, shows nothing on the sign-in
    page and can sign nobody in; it exists so that its redirect address can be given to the provider."""
    api = _api()
    _refuse_locked()
    try:
        providers.new(db, name=body.name, preset_id=body.preset)
    except (providers.Invalid, providers.Conflict) as exc:
        raise _refused(exc)
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    try:
        row = providers.create(db, name=body.name, preset_id=body.preset, by=current_user)
        db.commit()
    except (providers.Invalid, providers.Conflict) as exc:
        db.rollback()
        raise _refused(exc)
    _audit(db, "sso_provider_created", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
           details={"provider_id": str(row.id), "name": row.name, "preset": body.preset or ""})
    _tell_administrators(current_user.username, "A single sign-on provider was added",
                         f"{current_user.username} added the single sign-on provider {row.name}. It is off until it "
                         "is tested and turned on.")
    return {"provider": providers.public(db, row)}


@router.patch("/admin/sso/providers/{provider_id}")
def update_provider(provider_id: str, body: Dict[str, Any], request: Request,
                    current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Change a provider: its name, button and order, its connection (issuer, client id and secret, scopes, claim
    names), its policy. A change to the connection leaves the last test sign-in speaking for something else: a
    provider that is off must be tested again before it is turned on, and one that is on is turned off by the
    change, with its sessions ended, until a test sign-in passes again (an untested connection signs nobody in).
    Pointing the provider somewhere else (the issuer, the discovery address, the private-network switch) without
    a new client secret drops the stored one: it is never sent to an address it was not entered for.
    Turning password sign-in off for the provider makes its linked accounts sign in only through it (refused while
    one of them must keep a password); allowing it again lets each hold a password again, and mints nothing."""
    api = _api()
    _refuse_locked()
    row = _row_or_404(db, provider_id)
    try:
        changes = providers.clean(body, row=row)
        providers.check(db, row, changes, account_policy=api._account_policy(db))
    except (providers.Invalid, providers.Conflict) as exc:
        raise _refused(exc)
    if not changes:
        return {"provider": providers.public(db, row), "changed": [], "connection_changed": False,
                "made_sso_only": [], "restored": []}
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    row = _row_or_404(db, provider_id, lock=True)
    try:
        changes = providers.clean(body, row=row)
        stored_policy = providers.check(db, row, changes, account_policy=api._account_policy(db))
        outcome = providers.apply(db, row, changes, stored_policy)
        made, restored = _accounts_named(db, outcome["made_sso_only"]), _accounts_named(db, outcome["restored"])
        turned_off = outcome["connection_changed"] and row.state == providers.ENABLED
        held = providers.hold_lapsed(db, row) if turned_off else 0
        if turned_off:
            row.state = providers.DISABLED
        db.commit()
    except (providers.Invalid, providers.Conflict) as exc:
        db.rollback()
        raise _refused(exc)
    ended = _end_sessions_of(db, row.id) if turned_off else 0
    outcome = {**outcome, "turned_off": bool(turned_off), "sessions_ended": ended, "held": held}
    label = row.label or row.name
    # A change another person made to how an account signs in is told to its owner.
    _tell_accounts(made, "Your password no longer works on this vault", (
        f"An administrator turned password sign-in off for {label}. Your account now signs in only through {label}: "
        "its password and its SFTP password sign-in no longer work."))
    _tell_accounts(restored, "You can set a password again", (
        f"An administrator allowed password sign-in again for accounts linked to {label}. {SET_A_PASSWORD} You can "
        f"still sign in through {label}."))
    if outcome["changed"]:
        _audit(db, "sso_provider_updated", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
               details={"provider_id": str(row.id), "name": row.name, "changed": outcome["changed"],
                        "made_sso_only": len(outcome["made_sso_only"]), "restored": len(outcome["restored"])})
        said = f"{current_user.username} changed the single sign-on provider {row.name} ({', '.join(outcome['changed'])})."
        if outcome["made_sso_only"]:
            said += f" {len(outcome['made_sso_only'])} linked account(s) now sign in only through it."
        if outcome["restored"]:
            said += f" {len(outcome['restored'])} linked account(s) may hold a password again."
        if outcome["secret_cleared"]:
            said += " It was pointed somewhere else, so its stored client secret was dropped and must be entered again."
        if turned_off:
            said += (" Its connection changed, so it was turned off until a test sign-in passes again"
                     + (f", and {ended} session(s) that came through it were ended." if ended else "."))
        _tell_administrators(current_user.username, "A single sign-on provider was changed", said)
    return {"provider": providers.public(db, row), **outcome}


@router.post("/admin/sso/providers/{provider_id}/state")
def set_provider_state(provider_id: str, body: ProviderState, request: Request,
                       current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Turn a provider on or off. On: only with an address the provider can send a browser back to, the connection
    filled in, and a test sign-in passed with it as it is now. Off: never refused (an incident may need it at
    once); the sessions that came through it are ended, and an account whose sign-in there had already lapsed stays
    held, so that turning it off hands nobody their keys back. The answer says how many accounts sign in only
    through a provider and are linked to this one, since they cannot sign in while it is off."""
    api = _api()
    _refuse_locked()
    if body.state not in (providers.ENABLED, providers.DISABLED):
        raise HTTPException(status_code=400, detail={"reason": "invalid", "field": "state",
                                                     "message": "One of: enabled, disabled."})
    row = _row_or_404(db, provider_id)
    if row.state == body.state:
        return {"provider": providers.public(db, row), "changed": False}
    if body.state == providers.ENABLED:
        refusal = providers.enable_refusal(db, row)
        if refusal is not None:
            raise _refused(refusal)
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    row = _row_or_404(db, provider_id, lock=True)
    if body.state == providers.ENABLED:
        refusal = providers.enable_refusal(db, row)
        if refusal is not None:
            db.rollback()
            raise _refused(refusal)
    off = body.state == providers.DISABLED
    held = providers.hold_lapsed(db, row) if off else 0        # while the row still reads as on
    row.state = body.state
    db.commit()
    ended = _end_sessions_of(db, row.id) if off else 0
    _audit(db, "sso_provider_updated", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
           details={"provider_id": str(row.id), "name": row.name, "changed": ["state"], "state": row.state,
                    **({"sessions": ended, "identities": held} if off else {})})
    turned = "on" if row.state == providers.ENABLED else "off"
    said = f"{current_user.username} turned the single sign-on provider {row.name} {turned}."
    if off and ended:
        said += f" {ended} session(s) that came through it were ended."
    if off and held:
        said += (f" {held} account(s) whose sign-in there had lapsed stay held: lift each under Identities when it "
                 "should have its keys back.")
    _tell_administrators(current_user.username, f"A single sign-on provider was turned {turned}", said)
    answer = {"provider": providers.public(db, row), "changed": True}
    if off:
        answer.update(sessions_ended=ended, held=held)
    return answer


@router.delete("/admin/sso/providers/{provider_id}")
def remove_provider(provider_id: str, request: Request, current_user: User = Depends(require_interactive_admin),
                    db: Session = Depends(get_db)):
    """Remove a provider with its links, its group mappings and its held requests. Refused while it is on, while an
    account still signs in only through a provider and is linked to it, and while a refusal it recorded is in force."""
    api = _api()
    _refuse_locked()
    row = _row_or_404(db, provider_id)
    if row.state != providers.ENABLED and providers.hold_lapsed(db, row):
        # People whose days ran out while the provider was off: held now, so the removal does not lift the pause
        # unseen. The holds stand whatever becomes of this request.
        db.commit()
        row = _row_or_404(db, provider_id)
    refusal = providers.remove_refusal(db, row)
    if refusal is not None:
        raise _refused(refusal)
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    row = _row_or_404(db, provider_id, lock=True)
    refusal = providers.remove_refusal(db, row)
    if refusal is not None:
        db.rollback()
        raise _refused(refusal)
    from app.core import sso_only
    from app.core.models import ExternalIdentity
    gone = {"provider_id": str(row.id), "name": row.name, "identities": providers.public(db, row)["identities"]}
    label = row.label or row.name
    # Each account linked to it loses a way to sign in, and its flag follows the providers it is still linked to
    # (one held to no password by this provider alone may hold a password again; nothing is minted).
    kept, may_set = [], []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all():
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is None:
            continue
        settled = sso_only.settle(db, user, without=identity)
        (may_set if settled == sso_only.RESTORED else kept).append((user.id, user.username, user.email))
    db.delete(row)
    db.commit()
    removed = f"An administrator removed {label} from this vault: your account can no longer sign in through it."
    _tell_accounts(kept, "A sign-in method was removed from your account", removed)
    _tell_accounts(may_set, "A sign-in method was removed from your account", f"{removed} {SET_A_PASSWORD}")
    _audit(db, "sso_provider_deleted", user=current_user, ip=api.get_client_ip(request), row_id=gone["provider_id"],
           details={"provider_id": gone["provider_id"], "name": gone["name"], "identities": gone["identities"]})
    _tell_administrators(current_user.username, "A single sign-on provider was removed",
                         f"{current_user.username} removed the single sign-on provider {gone['name']}"
                         + (f", with the links of {gone['identities']} account(s) to it." if gone["identities"] else "."))
    return JSONResponse(status_code=200, content={"removed": True})
