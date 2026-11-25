"""Settings → Sign-in: the single sign-on providers, for administrators.

``GET /admin/sso/providers`` lists them with the wizard's presets and whether the vault has an address a provider can
send a browser back to; ``POST`` makes a draft (so its two addresses exist before the provider's own console is
touched); ``PATCH`` changes one; ``POST .../state`` turns it on or off; ``DELETE`` removes it. The rules are in
app/services/sso_providers.py. A test sign-in starts and finishes in app/api/sso_router.py.

``/admin/sso/providers/{id}/group-mappings`` (``GET``, ``POST``, ``PATCH .../{mapping}``, ``DELETE .../{mapping}``)
keeps the provider's groups mapped to departments and roles (app/services/sso_group_mappings.py), under the same
order as every other write here.

Every write is refused while the deployment has locked single sign-on (app/core/sso_settings.py), is judged before
anything is asked of the administrator, then asks the fixed step-up every sign-in setting is written under, then
judges again on the row as it stands, writes, and records what changed in the transaction that changes it: the
names of the fields and what each was and is, as a save of any other setting is recorded (no change without its
record). Of the client secret the record says only that one was set, replaced or dropped. The other administrators
are told. The client secret is taken, encrypted and never answered.
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
from app.services import sso_group_mappings as mappings
from app.services import sso_groups
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


def _record(db, action: str, *, user, ip, row_id, details: dict, resource_type: str = "sso_provider") -> None:
    """Add the record of a change to the transaction that makes it, before its commit: the two are written
    together or not at all. Written after the commit, a record that failed left a provider added, changed or
    removed with nothing in the audit log to say who did it. A record that cannot be built refuses the change."""
    from app.core.safe_log import log_failure
    try:
        from app.services.audit_logger import AuditLogger
        db.add(AuditLogger(db).build_row(action=action, status="success", user=user, ip_address=ip, details=details,
                                         resource_type=resource_type, resource_id=str(row_id)))
    except Exception as exc:      # noqa: BLE001 -- no change without its record
        db.rollback()
        error_id = log_failure("a change of a single sign-on provider was not saved", exc)
        raise HTTPException(status_code=503, detail="The change was not saved: its audit record could not be "
                                                    f"written. Nothing was changed (error {error_id}).")


def _recorded_changes(before: dict, row, changed) -> dict:
    """What a save changed, as the audit log keeps it: a long value by its digest, as any setting's is."""
    return providers.recorded_changes(before, row, changed, shorten=_api()._settings_value_for_audit)


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
        # One change at a time, on the row as it stands, and none while a sign-in through the provider is being
        # written (it holds the row shared). The row's key is left free: a row that only refers to the provider
        # (the record of a session that "Stay signed in" moves, written in the account's turn) waits for nothing.
        # Taken with its key, the row and that turn were asked for in both orders: a save settles accounts in
        # their turns while it holds the row.
        query = query.populate_existing().with_for_update(key_share=True)
    row = query.first()
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    return row


def _tell_accounts(users, title: str, change: str, *, once_for: Optional[str] = None) -> None:
    """Tell each of ``users`` of a change an administrator made to how their account signs in: in the app, and by
    email when the account has an address and email is configured. After the commit; never raises.

    ``once_for``: what this telling is about, when it must reach an account once however often it is asked for
    (a key for the notice's ledger). An account already told of it is told nothing more, in the app or by
    email."""
    api = _api()
    try:
        from app.core.database import get_db_context
        with get_db_context() as db:
            for user_id, username, email in users:
                try:
                    if once_for:
                        if not api._notify_users([str(user_id)], "account_changed", title=title, body=change,
                                                 target="#profile", dedup_prefix=once_for, once=True):
                            continue
                    else:
                        api._notify_users([str(user_id)], "account_changed", title=title, body=change,
                                          target="#profile")
                    if (email or "").strip():
                        api._fire_action_email(db, "sign_in_method_changed", email=email, username=username,
                                               action_context={"change": change, "when": api._change_time_text()})
                except Exception as exc:  # noqa: BLE001 -- one notice that fails does not stop the others
                    log.info("sso account notice skipped: %s", type(exc).__name__)
    except Exception as exc:  # noqa: BLE001
        log.info("sso account notices skipped: %s", type(exc).__name__)


def _end_sessions_of(db, provider_id, *, by=None, ip=None, name=None) -> int:
    """End every session that came through the provider, once it is off (no new sign-in and no renewal goes through
    it any more): each account's turn at its sessions first, as a provider's own logout ends them. Returns how
    many ended; a failure ends none and is logged, and the provider stays off. How many ended is recorded with
    their ending, in its transaction, as the administrator's (``by``): the change that turned the provider off
    was committed before, and could not know the number."""
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
        ended = int(api._revoke_sessions(db, session_ids=session_ids, actor_username="provider turned off",
                                         durable=True) or 0) if session_ids else 0
        if ended and by is not None:
            _record(db, "sso_provider_updated", user=by, ip=ip, row_id=provider_id,
                    details={"provider_id": str(provider_id), "name": name, "changed": [], "sessions": ended,
                             "reason": "sessions_ended"})
        db.commit()
        return ended
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.warning("sso sessions of a provider turned off were not ended: %s", type(exc).__name__)
        return 0


def _still_works(session, now) -> bool:
    """Whether a session's token is still taken: it is until the session is ended (``revoked``) or its time is
    over. Not whether it was used lately: the periodic cleanup marks a session inactive once it sat idle, a new
    password sign-in does the same to the account's earlier ones, and neither refuses the token (ending the
    account's sessions ends those rows too, for that reason)."""
    if getattr(session, "revoked", False):
        return False
    over = getattr(session, "expires_at", None)
    return over is None or over.replace(tzinfo=None) > now


def _sessions_standing(db, provider_id) -> Optional[int]:
    """How many sessions that came through the provider still stand (their token still works), or None when
    that could not be counted. Asked after a provider is turned off: its sessions are ended in a transaction of
    their own, after the one that turned it off, and a failure there (an owner's turn held for longer than the
    wait) ended none and was told to nobody. Turned off in an incident, the provider then signed nobody in while
    every session through it stood until it ran out.

    Counted as the sessions in use lately, the ones older than about an hour were left out, though they work as
    long: a turn-off that ended none said nothing of them, and asked again it found nothing to end."""
    from datetime import datetime
    from app.core.models import ActiveSession, SsoSession
    try:
        named = [s.session_id for s in db.query(SsoSession).filter(SsoSession.provider_id == provider_id).all()]
        if not named:
            return 0
        now = datetime.utcnow()
        rows = db.query(ActiveSession).filter(ActiveSession.id.in_(named)).all()
        return sum(1 for row in rows if _still_works(row, now))
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.warning("sso sessions of a provider turned off were not counted: %s", type(exc).__name__)
        return None


SESSIONS_STANDING = "sessions_standing"


def _sessions_refusal(db, row) -> Optional[providers.Conflict]:
    """Why ``row`` may not be removed for the sessions that came through it, or None. A turn-off ends them; where
    that failed, its answer and its notice say how many still stand and that turning the provider off again ends
    them. Removed meanwhile, the provider took with it what names those sessions: they went on working until they
    ran out, turning it off again answered that there is no such provider, and nothing said which accounts to
    sign out. The removal waits until none stands, and when they cannot be counted."""
    standing = _sessions_standing(db, row.id)
    if standing == 0:
        return None
    many = "Sessions" if standing is None else f"{standing} session(s)"
    return providers.Conflict(SESSIONS_STANDING, (
        f"{many} that came through this provider still stand. Turn it off again to end its sessions first: "
        "removed now, nothing would name them any more."))


def _said_of_sessions_standing(standing: Optional[int]) -> str:
    """The sentence of the administrators' notice for sessions that still stand after a turn-off, or ""."""
    if standing == 0:
        return ""
    many = "Sessions" if standing is None else f"{standing} session(s)"
    return (f" {many} that came through it could not be ended and stand until they run out: turn it off again "
            "to end them, or sign those accounts out.")


def _held_after(db, row, *, by, ip, held_before) -> tuple:
    """The accounts ``row`` holds to a provider's sign-in after a change of what its days hold was committed, and
    the record of it, in a transaction of its own (the change's own record was written with the change, before
    this could be counted). Returns (every account held, the ids of those held by its days): the rest are held by
    a refusal or hold on record. The record says how many of each, and how many are held since this change. A
    count that cannot be made holds up nothing: the change stands, nobody is said to be held, and the failure is
    logged."""
    try:
        held = providers.held_through(db, row)
        by_days = {user.id for user in providers.held_by_its_days(db, row)}
        newly = sum(1 for user in held if user.id not in held_before)
        if newly:
            _record(db, "sso_provider_updated", user=by, ip=ip, row_id=row.id,
                    details={"provider_id": str(row.id), "name": row.name, "changed": [],
                             "reason": "held_by_its_days", "held_by_its_days": len(by_days),
                             "held_by_a_refusal": len(held) - len(by_days), "newly_held": newly})
            db.commit()
        return held, by_days
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.warning("the accounts a provider holds were not counted: %s", type(exc).__name__)
        return [], set()


def _accounts_named(db, usernames) -> list:
    """(id, username, email) of the accounts ``usernames`` names, for a notice sent after the commit."""
    names = list(usernames or [])
    if not names:
        return []
    return [(u.id, u.username, u.email) for u in db.query(User).filter(User.username.in_(names)).all()]


def _accounts_linked(db, row, *, but=None) -> list:
    """(id, username, email) of the active accounts linked to ``row``, without the account ``but`` names, for a
    notice sent after the commit."""
    from app.core.models import ExternalIdentity
    ids = {identity.user_id for identity in
           db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all()}
    ids.discard(but)
    if not ids:
        return []
    return [(u.id, u.username, u.email) for u in db.query(User).filter(User.id.in_(ids)).all() if u.is_active]


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
        db.flush()                                 # the row has its id: the record names it
        _record(db, "sso_provider_created", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
                details={"provider_id": str(row.id), "name": row.name, "preset": body.preset or ""})
        db.commit()
    except (providers.Invalid, providers.Conflict) as exc:
        db.rollback()
        raise _refused(exc)
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
    one of them must keep a password); allowing it again lets each hold a password again, and mints nothing. The
    setting for the accounts the provider made at a first sign-in does the same for those of them that have no
    password of their own."""
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
    # A change of the policy may replace the password of every linked account. The one hash for them is made
    # here, before the row is taken: sign-ins through the provider wait for that row, and hashing is slow.
    from app.core import sso_only
    unknown_hash = sso_only.a_password_nobody_knows() if "policy" in changes else None
    # Whom the provider's days hold to a sign-in through it, before the change: a save that shortens the days, or
    # turns on that they end sign-in, holds more accounts from the moment it is committed. Counted here and
    # after the commit, never while the provider's row is held: it reads every linked account.
    held_before = {u.id for u in providers.held_through(db, row)} if "policy" in changes else set()
    row = _row_or_404(db, provider_id, lock=True)
    try:
        changes = providers.clean(body, row=row)
        stored_policy = providers.check(db, row, changes, account_policy=api._account_policy(db))
        before = providers.recorded_values(row)
        outcome = providers.apply(db, row, changes, stored_policy, unknown_hash=unknown_hash)
        made, restored = _accounts_named(db, outcome["made_sso_only"]), _accounts_named(db, outcome["restored"])
        turned_off = outcome["connection_changed"] and row.state == providers.ENABLED
        # Where the provider is found says who a linked account's sign-in is vouched for by. A change of it is one
        # administrator's word: the people linked to it are told, whether it was on or off when it was changed
        # (turning it off first hides nothing), beside the other administrators.
        pointed_elsewhere = any(field in outcome["changed"] for field in providers.WHERE_IT_IS)
        owners = _accounts_linked(db, row, but=current_user.id) if pointed_elsewhere else []
        held = providers.hold_lapsed(db, row) if turned_off else 0
        if turned_off:
            row.state = providers.DISABLED
        if outcome["changed"]:
            # With the change, in its transaction: the fields, what each was and is, and what the change did to
            # the provider and to the accounts linked to it. (The sessions it ends are ended after the commit,
            # and recorded there.)
            details = {"provider_id": str(row.id), "name": row.name, "changed": outcome["changed"],
                       "changes": _recorded_changes(before, row, outcome["changed"]),
                       "made_sso_only": len(outcome["made_sso_only"]), "restored": len(outcome["restored"]),
                       "secret_cleared": bool(outcome["secret_cleared"]), "owners_told": len(owners)}
            if turned_off:
                details.update(state=providers.DISABLED, identities=held)
            _record(db, "sso_provider_updated", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
                    details=details)
        db.commit()
    except (providers.Invalid, providers.Conflict) as exc:
        db.rollback()
        raise _refused(exc)
    ended = (_end_sessions_of(db, row.id, by=current_user, ip=api.get_client_ip(request), name=row.name)
             if turned_off else 0)
    standing = _sessions_standing(db, row.id) if turned_off else 0
    # Whom its days hold now that the change is committed, where one of the two settings changed. A provider that
    # is off holds nobody by its days (one this change turned off among them): the count is given when it is
    # turned on again.
    days_changed = any(field in outcome["changed"] for field in providers.WHAT_ITS_DAYS_HOLD)
    held_now, by_days = (_held_after(db, row, by=current_user, ip=api.get_client_ip(request), held_before=held_before)
                         if days_changed else ([], set()))
    newly_held = [(u.id, u.username, u.email) for u in held_now if u.id not in held_before]
    newly_by_days = [one for one in newly_held if one[0] in by_days]
    newly_by_a_refusal = [one for one in newly_held if one[0] not in by_days]
    outcome = {**outcome, "turned_off": bool(turned_off), "sessions_ended": ended, "sessions_not_ended": standing,
               "held": held, "owners_told": len(owners), "held_by_its_days": len(by_days),
               "held_by_a_refusal": len(held_now) - len(by_days), "newly_held": len(newly_held)}
    label = row.label or row.name
    # The people the change holds from this moment had no warning of it (the warning counts five days down to the
    # days as they were): each is told now, in the app and by email, what stopped and what brings it back.
    # Said as what was changed: the days themselves, or what running out of them stops (with the days as they
    # were, "changed how often it must have seen you" was not true).
    what_changed = (f"An administrator changed how often {label} must have seen you."
                    if "policy.sso_freshness_days" in outcome["changed"] else
                    f"An administrator changed what stops when {label} has not seen you within its days: your "
                    "password and passkeys now stop as well as your keys.")
    # Once a day for a provider, whatever the saves: the accounts held before a save are read before the
    # provider's row is taken, so of two saves made at about the same time the second counts the people the
    # first has just held as its own, and told them again, in the app and by email.
    from datetime import datetime
    today = f"sso_newly_held:{row.id}:{datetime.utcnow():%Y-%m-%d}"
    _tell_accounts(newly_by_days, f"Sign in through {label} to keep signing in here", (
        f"{what_changed} Your last sign-in through {label} is older than that: your password and passkeys do not "
        f"sign you in to this vault until you have signed in through {label} again."), once_for=today)
    _tell_accounts(newly_by_a_refusal, f"Sign in through {label} to keep signing in here", (
        f"An administrator changed what a sign-in that {label} did not admit stops. Your account is held to a "
        f"sign-in through {label}: its password and passkeys do not sign it in to this vault until {label} has "
        "admitted it again. If it does not, ask your administrator."), once_for=today)
    _tell_accounts(owners, f"{label} was pointed somewhere else", (
        f"An administrator changed where this vault finds {label}, a sign-in your account is linked to. Nobody signs "
        f"in through {label} until an administrator has tested it again and turned it on. If the sign-in you meet "
        "there next does not look like the one you know, stop and tell an administrator."))
    # A change another person made to how an account signs in is told to its owner.
    # Said as it is for the account that reads it: a provider that is off signs nobody in.
    is_on = row.state == providers.ENABLED
    while_off = f" {label} is turned off at the moment: ask an administrator."
    if "policy.sso_password_login" in outcome["changed"]:
        _tell_accounts(made, "Your password no longer works on this vault", (
            f"An administrator turned password sign-in off for {label}. Your account now signs in only through {label}: "
            "its password and its SFTP password sign-in no longer work." + ("" if is_on else while_off)))
        _tell_accounts(restored, "You can set a password again", (
            f"An administrator allowed password sign-in again for accounts linked to {label}. {SET_A_PASSWORD}"
            + (f" You can still sign in through {label}." if is_on else while_off)))
    else:
        # The rule for the accounts the provider made at a first sign-in changed, and nothing else that settles.
        _tell_accounts(made, f"Your account signs in only through {label}", (
            f"An administrator no longer lets accounts made at their first sign-in through {label} set a password. "
            f"Your account has none of its own, and signs in only through {label}." + ("" if is_on else while_off)))
        _tell_accounts(restored, "You can set a password", (
            f"An administrator now lets accounts made at their first sign-in through {label} set a password. "
            f"{SET_A_PASSWORD}" + (f" You can still sign in through {label}." if is_on else while_off)))
    if outcome["changed"]:
        said = f"{current_user.username} changed the single sign-on provider {row.name} ({', '.join(outcome['changed'])})."
        if outcome["made_sso_only"]:
            said += f" {len(outcome['made_sso_only'])} linked account(s) now sign in only through it."
        if outcome["restored"]:
            said += f" {len(outcome['restored'])} linked account(s) may hold a password again."
        if pointed_elsewhere:
            said += " It was pointed somewhere else" + (
                ", so its stored client secret was dropped and must be entered again." if outcome["secret_cleared"]
                else ".")
            if owners:
                said += f" The {len(owners)} account(s) linked to it were told."
        if newly_by_days:
            said += (f" {len(newly_by_days)} more linked account(s) have not signed in through it within its days as "
                     "they are now: their password and passkeys do not sign them in until they have. They were "
                     "told.")
        if newly_by_a_refusal:
            said += (f" {len(newly_by_a_refusal)} more linked account(s) that it had not admitted are held to a "
                     "sign-in through it now: their password and passkeys do not sign them in until it admits them. "
                     "They were told.")
        if newly_held:
            said += f" {len(held_now)} account(s) are held so in all."
        if turned_off:
            said += (" Its connection changed, so it was turned off until a test sign-in passes again"
                     + (f", and {ended} session(s) that came through it were ended." if ended else "."))
            said += _said_of_sessions_standing(standing)
        _tell_administrators(current_user.username, "A single sign-on provider was changed", said)
    return {"provider": providers.public(db, row), **outcome}


@router.post("/admin/sso/providers/{provider_id}/state")
def set_provider_state(provider_id: str, body: ProviderState, request: Request,
                       current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Turn a provider on or off. On: only with an address the provider can send a browser back to, the connection
    filled in, and a test sign-in passed with it as it is now. Off: never refused (an incident may need it at
    once); the sessions that came through it are ended, and an account whose sign-in there had already lapsed stays
    held, so that turning it off hands nobody their keys back. The answer says for how many linked accounts this
    provider is the only way in (no password they can type, no other provider that lets them in), since nothing
    signs them in while it is off; the administrators' notice of the change says so too."""
    api = _api()
    _refuse_locked()
    if body.state not in (providers.ENABLED, providers.DISABLED):
        raise HTTPException(status_code=400, detail={"reason": "invalid", "field": "state",
                                                     "message": "One of: enabled, disabled."})
    row = _row_or_404(db, provider_id)
    if row.state == body.state:
        # Off already. Where sessions that came through it still stand (they could not be ended when it was
        # turned off), asking again ends them: behind the same proof as the turn-off, and nothing else changes.
        left = _sessions_standing(db, row.id) if body.state == providers.DISABLED else 0
        if left == 0:
            return {"provider": providers.public(db, row), "changed": False}
        _step_up(db, current_user, request)
        ended = _end_sessions_of(db, row.id, by=current_user, ip=api.get_client_ip(request), name=row.name)
        standing = _sessions_standing(db, row.id)
        _tell_administrators(current_user.username, "Sessions of a single sign-on provider were ended", (
            f"{current_user.username} asked again to end the sessions that came through the single sign-on provider "
            f"{row.name}, which is turned off. {ended} session(s) were ended." + _said_of_sessions_standing(standing)))
        return {"provider": providers.public(db, row), "changed": False, "sessions_ended": ended,
                "sessions_not_ended": standing}
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
    state_change = dict(old=row.state, new=body.state)
    row.state = body.state
    _record(db, "sso_provider_updated", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
            details={"provider_id": str(row.id), "name": row.name, "changed": ["state"], "state": row.state,
                     "changes": {"state": state_change}, **({"identities": held} if off else {})})
    db.commit()
    ended = (_end_sessions_of(db, row.id, by=current_user, ip=api.get_client_ip(request), name=row.name)
             if off else 0)
    standing = _sessions_standing(db, row.id) if off else 0
    turned = "on" if row.state == providers.ENABLED else "off"
    said = f"{current_user.username} turned the single sign-on provider {row.name} {turned}."
    if off and ended:
        said += f" {ended} session(s) that came through it were ended."
    said += _said_of_sessions_standing(standing)
    if off and providers.sso_policy.effective(row.policy)["sso_lapse_ends_sign_in"]:
        said += (" While it is off, its days stop no password: only an account that was held before (a refusal, or "
                 "days already run out) stays held to this provider's sign-in, until it is lifted under Identities.")
    shown = providers.public(db, row)
    if off and shown["only_way_in_accounts"]:
        said += (f" {shown['only_way_in_accounts']} account(s) linked to it have no other way to sign in: nothing "
                 "signs them in while it is off.")
    if off and held:
        said += (f" {held} account(s) whose sign-in there had lapsed stay held: lift each under Identities when it "
                 "should have its keys back.")
    due = providers.due_at_turn_on(db, row) if not off else 0
    if due:
        said += (f" {due} linked account(s) have not signed in through it within its days: their password and "
                 "passkeys do not sign them in until they have.")
    _tell_administrators(current_user.username, f"A single sign-on provider was turned {turned}", said)
    answer = {"provider": providers.public(db, row), "changed": True}
    if off:
        answer.update(sessions_ended=ended, sessions_not_ended=standing, held=held)
    else:
        answer.update(due=due)
    return answer


@router.delete("/admin/sso/providers/{provider_id}")
def remove_provider(provider_id: str, request: Request, current_user: User = Depends(require_interactive_admin),
                    db: Session = Depends(get_db)):
    """Remove a provider with its links, its group mappings and its held requests. Refused while it is on, while an
    account still signs in only through a provider and is linked to it, while a refusal it recorded is in force,
    and while a session that came through it still stands (409 ``sessions_standing``: turned off again, it ends
    them)."""
    api = _api()
    _refuse_locked()
    row = _row_or_404(db, provider_id)
    # Reads only: nothing is changed before the step-up.
    refusal = providers.remove_refusal(db, row) or _sessions_refusal(db, row)
    if refusal is not None:
        raise _refused(refusal)
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    from app.core import sso_only
    from app.core.models import ExternalIdentity
    # Made before the row is taken, as at a save: the linked accounts are settled while it is held.
    unknown_hash = sso_only.a_password_nobody_knows()
    row = _row_or_404(db, provider_id, lock=True)
    refusal = providers.remove_refusal(db, row) or _sessions_refusal(db, row)
    if refusal is not None:
        db.rollback()
        raise _refused(refusal)
    # People whose days ran out while the provider was off: held now, so the removal does not lift the pause
    # unseen. After the step-up, never before it: a click that goes no further changes no account. The hold is
    # recorded in the transaction that writes it, the administrators and the people it holds are told, and the
    # removal waits until each is cleared. None is written where a hold would also end the person's password (a
    # provider that closes the other ways in after its days: remove_refusal answered above).
    held_ids = []
    if row.state != providers.ENABLED and providers.hold_lapsed(db, row, into=held_ids):
        held = len(held_ids)
        _record(db, "sso_provider_updated", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
                details={"provider_id": str(row.id), "name": row.name, "changed": [], "identities": held,
                         "reason": "held_before_removal"})
        # The hold is written for every one of them. Told are the accounts that can sign in: one that is turned
        # off signs in nowhere, and its stored address is often a former employee's own.
        people = [(u.id, u.username, u.email) for u in db.query(User).filter(User.id.in_(held_ids)).all()
                  if u.is_active]
        turned_off = held - len(people)
        name, shown = row.name, row.label or row.name
        db.commit()
        _tell_administrators(current_user.username, "Accounts were held before a provider's removal", (
            f"{current_user.username} began to remove the single sign-on provider {name}. {held} account(s) had not "
            "signed in through it within its days and are held now, so that the removal does not give them their "
            "SSH keys, temporary credentials and devices back unseen. Lift each under Identities when it should "
            "have them back; the provider can be removed then."
            + (f" {turned_off} of them are turned off: held as the others are, and not told." if turned_off else "")))
        _tell_accounts(people, "Your keys stay paused on this vault", (
            f"You have not signed in through {shown} within the time your organisation allows, and {shown} is being "
            "removed from this vault. Your SSH keys, temporary credentials and devices stay paused until an "
            "administrator lifts that. Your password signs you in as before."))
        raise _refused(providers.held_by_the_removal(held))
    gone = {"provider_id": str(row.id), "name": row.name, "identities": providers.public(db, row)["identities"]}
    label = row.label or row.name
    # Each account linked to it loses a way to sign in, and its flag follows the providers it is still linked to
    # (one held to no password by this provider alone may hold a password again; nothing is minted).
    kept, may_set, to_ask = [], [], []
    # In the one order every route takes several accounts' turns in (sso_router._owners_of): by the account's id.
    for identity in sorted(db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all(),
                           key=lambda linked: str(linked.user_id)):
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is None:
            continue
        settled = sso_only.settle(db, user, without=identity, unknown_hash=unknown_hash)
        # Told how to get a password: an account that may hold one again, and one that has none it can type and
        # no other provider that is on (its passkey signs in after a provider only: nothing else would sign it in).
        # Not one that another provider still holds to no password, though that provider is off: a reset link is
        # refused for it, so it is told who can help and not to do what would be refused.
        from app.services import sign_in
        stranded = (not sign_in.has_a_password_it_can_type(user)
                    and not sso_only.another_way_in(db, user, without=identity))
        told = (user.id, user.username, user.email)
        if settled == sso_only.RESTORED or (stranded and not getattr(user, "sso_only", False)):
            may_set.append(told)
        elif stranded:
            to_ask.append(told)
        else:
            kept.append(told)
    _record(db, "sso_provider_deleted", user=current_user, ip=api.get_client_ip(request), row_id=gone["provider_id"],
            details={"provider_id": gone["provider_id"], "name": gone["name"], "identities": gone["identities"]})
    db.delete(row)
    db.commit()
    removed = f"An administrator removed {label} from this vault: your account can no longer sign in through it."
    _tell_accounts(kept, "A sign-in method was removed from your account", removed)
    _tell_accounts(may_set, "A sign-in method was removed from your account", f"{removed} {SET_A_PASSWORD}")
    _tell_accounts(to_ask, "A sign-in method was removed from your account", f"{removed} {sso_only.NO_PROVIDER_ON}")
    _tell_administrators(current_user.username, "A single sign-on provider was removed",
                         f"{current_user.username} removed the single sign-on provider {gone['name']}"
                         + (f", with the links of {gone['identities']} account(s) to it." if gone["identities"] else "."))
    return JSONResponse(status_code=200, content={"removed": True})
# --------------------------------------------------------------------------- a provider's group mappings

def _mapping_or_404(db, row, mapping_id):
    mapping = mappings.one(db, row, mapping_id)
    if mapping is None:
        raise HTTPException(status_code=404, detail="Unknown group mapping.")
    return mapping


def _mapping_record(row, shown: dict, **more) -> dict:
    """What the audit log keeps of a mapping: the provider, the mapping, the group as the provider sends it, the
    department (its id and its name) and the role."""
    department = shown["department"] or {}
    return {"provider_id": str(row.id), "name": row.name, "mapping_id": shown["id"],
            "provider_group": shown["provider_group"], "group_id": department.get("id"),
            "department": department.get("name"), "role": shown["role"], **more}


def _end_the_requests_of(db, row, group, *, user, ip) -> list:
    """End the held requests for the administrator role that ``group`` of ``row`` opened, in the transaction of
    the change that takes the role from the group's mapping, each with its record. Returns (request id, account
    id) for each, for what is told after the commit."""
    ended = sso_groups.end_requests_of_group(db, row, group)
    for one in ended:
        _record(db, "sso_admin_expired", user=user, ip=ip, row_id=one.id, resource_type="sso_admin_request",
                details={"provider_id": str(row.id), "user_id": str(one.user_id), "reason": sso_groups.MAPPING_GONE})
    return [(str(one.id), str(one.user_id)) for one in ended]


def _tell_of_requests_ended(ended: list, row) -> str:
    """Tell each person whose request ended with its group's mapping, and give the sentence of the administrators'
    notice for them ("" for none). Best effort."""
    if not ended:
        return ""
    label = row.label or row.name
    try:
        api = _api()
        for request_id, account_id in ended:
            api._notify_users([account_id], "sso_admin_request", title="Your request for the administrator role ended",
                              body=(f"The group of {label} your request came through is no longer mapped to the "
                                    "administrator role, so the request was ended with nothing decided. Your "
                                    "account is unchanged. If another group of yours is mapped to the role, your "
                                    "next sign-in through it asks again."),
                              target="#profile", dedup_prefix=f"sso_admin_ended:{request_id}")
    except Exception as exc:  # noqa: BLE001
        log.info("sso request-ended notice skipped: %s", type(exc).__name__)
    return (f" {len(ended)} request(s) for the administrator role that the group had opened were ended with nothing "
            "decided, and the people told.")


def _said_of_who_may_leave(leaving: list, row) -> str:
    """The sentence of a mapping's notice for the people a sign-in may now take out of a department, or ""."""
    said = ""
    for one in leaving:
        said += (f" {one['accounts']} account(s) linked to {row.name} are in the department "
                 f"{one['department']['name']} now: each leaves it at its next sign-in through the provider unless "
                 "that sign-in names a group mapped to it.")
    return said


def _mapping_words(shown: dict) -> str:
    """What a mapping gives, in words, for the administrators' notice."""
    gives = []
    if shown["department"]:
        gives.append(f"the department {shown['department']['name']}")
    if shown["role"] == "admin":
        gives.append("a request for the administrator role, which another administrator decides")
    elif shown["role"]:
        gives.append(f"the role {shown['role']}")
    return " and ".join(gives)


@router.get("/admin/sso/providers/{provider_id}/group-mappings")
def list_group_mappings(provider_id: str, current_user: User = Depends(require_interactive_admin),
                        db: Session = Depends(get_db)):
    """The provider's groups mapped to departments and roles, with what the page needs to add one: the departments,
    the roles, whether the administrator role can be mapped as the provider stands (and why not), the claim the
    groups are read from and the groups the last test sign-in carried."""
    row = _row_or_404(db, provider_id)
    return {"provider": {"id": str(row.id), "name": row.name, "label": row.label, "state": row.state},
            **mappings.listing(db, row), "locked": sso_settings.locked(), "step_up": STEP_UP_ACTION}


@router.post("/admin/sso/providers/{provider_id}/group-mappings", status_code=201)
def add_group_mapping(provider_id: str, body: Dict[str, Any], request: Request,
                      current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Map a group of the provider, named exactly as the provider sends it, to a department, a role, or both. It
    applies from the next sign-in through the provider. The administrator role is mapped only while the provider
    may raise administrator requests and its people can hold a password.

    A department that has members already follows the provider's groups from now on: a linked account in it
    leaves it at its next sign-in through the provider unless that sign-in names a group mapped to it. The answer
    (``may_leave``) and the administrators' notice say how many such accounts there are. An administrator mapping
    demotes nobody it did not approve."""
    api = _api()
    _refuse_locked()
    row = _row_or_404(db, provider_id)
    try:
        fields = mappings.fields_of(body, new=True)
        mappings.judge(db, row, **fields)          # reads only: nothing is changed before the step-up
    except (providers.Invalid, providers.Conflict) as exc:
        raise _refused(exc)
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    # The provider's row is held as a save of it holds it: one change at a time, and none while a sign-in through
    # the provider applies its mappings.
    row = _row_or_404(db, provider_id, lock=True)
    try:
        mapping = mappings.create(db, row, fresh=True, **fields)
        db.flush()                                 # the row has its id: the record names it
        shown = mappings.public(db, row, mapping)
        _record(db, "sso_group_mapping_added", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
                details=_mapping_record(row, shown))
        touched = [mapping.department_id]
        db.commit()
    except (providers.Invalid, providers.Conflict) as exc:
        db.rollback()
        raise _refused(exc)
    leaving = sso_groups.may_leave(db, row, touched)
    _tell_administrators(current_user.username, "A single sign-on group was mapped", (
        f"{current_user.username} mapped the group {shown['provider_group']} of the single sign-on provider "
        f"{row.name} to {_mapping_words(shown)}. It applies from each person's next sign-in through the provider."
        + _said_of_who_may_leave(leaving, row)))
    return {"mapping": shown, "may_leave": leaving}


@router.patch("/admin/sso/providers/{provider_id}/group-mappings/{mapping_id}")
def change_group_mapping(provider_id: str, mapping_id: str, body: Dict[str, Any], request: Request,
                         current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Change a mapping: its group, its department, its role. A department or a role sent as null is taken away;
    a mapping keeps at least one of the two. Nobody is moved by the change itself: the next sign-in of each person
    applies the mappings as they are then. A linked account in a department that a mapping still names leaves it
    at that sign-in unless the token names a group mapped to it; the answer (``may_leave``) and the notice say how
    many such accounts there are, for the department the mapping had and for the one it has now. An administrator
    approved through the group the mapping had keeps the role."""
    api = _api()
    _refuse_locked()
    row = _row_or_404(db, provider_id)
    mapping = _mapping_or_404(db, row, mapping_id)
    try:
        fields = mappings.fields_of(body, new=False)
        would, _values = mappings.differences(db, row, mapping, fields)      # reads only
    except (providers.Invalid, providers.Conflict) as exc:
        raise _refused(exc)
    if not would:
        return {"mapping": mappings.public(db, row, mapping), "changed": []}
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    row = _row_or_404(db, provider_id, lock=True)
    mapping = mappings.one(db, row, mapping_id, fresh=True)
    if mapping is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="Unknown group mapping.")
    try:
        touched = [mapping.department_id]
        was_group, was_role = mapping.provider_group, mapping.role
        changes = mappings.change(db, row, mapping, fields, fresh=True)
        touched.append(mapping.department_id)
        shown = mappings.public(db, row, mapping)
        ended = []
        if changes:
            _record(db, "sso_group_mapping_changed", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
                    details=_mapping_record(row, shown, changed=sorted(changes), changes=changes))
            # The group it had is mapped to the administrator role no more: the requests that group opened end.
            if was_role == "admin" and (mapping.role != "admin" or mapping.provider_group != was_group):
                ended = _end_the_requests_of(db, row, was_group, user=current_user, ip=api.get_client_ip(request))
        db.commit()
    except (providers.Invalid, providers.Conflict) as exc:
        db.rollback()
        raise _refused(exc)
    leaving = sso_groups.may_leave(db, row, touched)
    if changes:
        _tell_administrators(current_user.username, "A single sign-on group mapping was changed", (
            f"{current_user.username} changed how the group {shown['provider_group']} of the single sign-on provider "
            f"{row.name} is mapped: it now gives {_mapping_words(shown)}. It applies from each person's next "
            "sign-in through the provider." + _said_of_who_may_leave(leaving, row)
            + _tell_of_requests_ended(ended, row)))
    return {"mapping": shown, "changed": sorted(changes), "may_leave": leaving, "requests_ended": len(ended)}


@router.delete("/admin/sso/providers/{provider_id}/group-mappings/{mapping_id}")
def remove_group_mapping(provider_id: str, mapping_id: str, request: Request,
                         current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """Remove a mapping. Nobody is changed by the removal itself, and a role it gave stays: an administrator
    approved through its group keeps the role. A department no other mapping of the provider names is no longer
    touched by a sign-in, and its members stay until an administrator takes them out. One that another mapping
    still names goes on following the provider's groups: a linked account in it leaves it at its next sign-in
    unless the token names a group still mapped to it, and the answer (``may_leave``) and the notice say how many
    such accounts there are. The requests for the administrator role its group opened are ended with it
    (``requests_ended``), each with its record, and the people told: a request nobody could approve any more
    stood in the list, and kept the person from asking again through a group that is still mapped."""
    api = _api()
    _refuse_locked()
    row = _row_or_404(db, provider_id)
    _mapping_or_404(db, row, mapping_id)
    _step_up(db, current_user, request)        # may commit (a receipt is used once)
    row = _row_or_404(db, provider_id, lock=True)
    mapping = mappings.one(db, row, mapping_id, fresh=True)
    if mapping is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="Unknown group mapping.")
    shown = mappings.public(db, row, mapping)
    _record(db, "sso_group_mapping_removed", user=current_user, ip=api.get_client_ip(request), row_id=row.id,
            details=_mapping_record(row, shown))
    touched = [mapping.department_id]
    ended = (_end_the_requests_of(db, row, mapping.provider_group, user=current_user, ip=api.get_client_ip(request))
             if mapping.role == "admin" else [])
    db.delete(mapping)
    db.commit()
    leaving = sso_groups.may_leave(db, row, touched)
    _tell_administrators(current_user.username, "A single sign-on group mapping was removed", (
        f"{current_user.username} removed the mapping of the group {shown['provider_group']} of the single sign-on "
        f"provider {row.name} (it gave {_mapping_words(shown)}). Nobody's department or role was changed by that."
        + _tell_of_requests_ended(ended, row)
        + (" Another group is still mapped to the department." + _said_of_who_may_leave(leaving, row)
           if leaving else "")))
    return {"removed": True, "mapping": shown, "may_leave": leaving, "requests_ended": len(ended)}
