"""Finishing a sign-in: one way, whatever proved who the person is.

Three routes used to finish a sign-in each on their own, building the session and the token inline:
the password route, the second-factor route and the forced-enrollment route. They agreed on most
things and differed in small ones (only the password route told the live monitor and sent the
sign-in alert; only the other two wrote ``amr``). Passkeys and single sign-on add more ways to prove
who the person is, so the finishing moves here and every route calls it:

* :func:`second_factor_due` is the one table that says what, if anything, follows a proof: nothing,
  the vault's second factor, its enrollment, or the account password. An administrator always types
  the password (a passkey or a provider adds to it, never replaces it). A passkey without user
  verification is one possession factor, so the knowledge factor, the password, must follow it,
  never an authenticator code (a second possession factor is not a second kind).
* :func:`begin_pending` holds the sign-in in a pending login until that step is done, behind a
  five-minute pre-authentication token that carries the stage (``second_factor`` or ``password``) and
  the proofs so far, and nothing a request could use as a session.
* :func:`complete_sign_in` makes the session and the token, with ``amr`` (RFC 8176 values where the
  RFC has a word, the vault's own ``totp`` and ``recovery`` where it has not) and ``auth_time`` on
  every token, ``mfa_at`` when two kinds of factor were present, and makes the same records for every
  method: the audit row, the live-monitor event, the sign-in alert, the owner's notice of a
  temporary credential's sign-in.
* :func:`renew` keeps a finished sign-in going ("Stay signed in"): a new session and token in place of
  the old, by the renewal rules, in an order that leaves no moment without one of the two.

The route decides how it answers (the shapes the web app knows are unchanged); this module decides
what a sign-in is.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Sequence

from fastapi import HTTPException

from app.core.models import PendingLogin, RoleEnum
from app.core.security import create_access_token
from app.core.session_hash_utils import hash_session_token

# ``amr`` values. RFC 8176 names the kinds; the vault has written ``totp`` for the authenticator code
# since the second factor shipped, and ``recovery`` for a recovery code used in its place, so those stay.
PASSWORD = "pwd"
TOTP = "totp"
RECOVERY = "recovery"
HARDWARE_KEY = "hwk"      # a passkey bound to one device
SOFTWARE_KEY = "swk"      # a synced passkey
PASSKEYS = frozenset({HARDWARE_KEY, SOFTWARE_KEY})
# The vault's own codes.
CODES = frozenset({TOTP, RECOVERY})
# What counts as a second kind of factor beside the password.
SECOND_KINDS = CODES | PASSKEYS

# What a pending login waits for. The pre-authentication token carries the value in ``stage``.
STAGE_SECOND_FACTOR = "second_factor"
STAGE_PASSWORD = "password"
STAGES = (STAGE_SECOND_FACTOR, STAGE_PASSWORD)
# The other two answers of second_factor_due: nothing follows; the person must enroll a factor first.
DONE = "done"
ENROLL = "enroll"

# A pending login lives this long, and takes this many wrong answers before it must be started again
# (the durable cap that holds through a cache outage).
PRE_AUTH_TTL_MINUTES = 5
MAX_PENDING_ATTEMPTS = 5
# A session row's absolute lifetime: a margin above the longest session timeout (30 days), so the row
# outlives any token it backs and still ages out once nothing renews it.
SESSION_ROW_LIFETIME = timedelta(days=31)
# What the person may enroll when the policy requires a factor they do not have.
ENROLLMENT_METHODS = ("totp",)


@dataclass
class SignInResult:
    """A proof of who the person is, on its way to becoming a session.

    ``methods`` are the proofs so far, as ``amr`` values, in the order they were given. ``session_token``
    is set when the proof already made a session (the password check does); otherwise one is made.
    ``pending`` is the pending login this result continues or completes, when there is one.
    """
    user: object
    methods: List[str]
    client_ip: Optional[str]
    session_token: Optional[str] = None
    is_temporary: bool = False
    temp_username: Optional[str] = None
    pending: Optional[PendingLogin] = None
    # Single sign-on: the provider's id (the token's ``idp`` claim) and whether its own MFA is trusted and
    # was present in this sign-in.
    provider_id: Optional[str] = None
    provider_mfa_trusted: bool = False
    # A passkey: whether the authenticator verified the person (the UV flag), and whether the policy lets
    # this person sign in with a user-verified passkey alone.
    user_verified: bool = False
    passwordless_allowed: bool = False
    auth_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    channel: str = "web"


@dataclass
class SignedIn:
    """A finished sign-in: the token the route answers with, and who signed in."""
    access_token: str
    user: object
    is_temporary: bool = False


@dataclass
class PendingStep:
    """A sign-in held for one more step; ``body`` is the answer the route returns as it is."""
    stage: str
    body: dict


class NoFirstProof(ValueError):
    """A sign-in with no first proof (no password, no passkey, no identity provider) asked what follows: a
    programming error, never a sign-in."""


class ProviderOnly(HTTPException):
    """The account signs in only through its organisation's identity provider and this sign-in did not come through
    it: 403 with a message naming what to use instead. Raised by :func:`finish` after the proof was checked, so a
    route that finishes a sign-in can recognise it: the proof was good, nothing of it counts as a failed attempt."""

    def __init__(self, message: str):
        super().__init__(status_code=403, detail=message)


def second_factor_due(user, methods: Iterable[str], *, factor_in_effect: bool, enrollment_pending: bool,
                      passwordless_allowed: bool = False, user_verified: bool = False,
                      provider_mfa_trusted: bool = False, provider_id: Optional[str] = None,
                      is_temporary: bool = False) -> str:
    """What follows the proofs in ``methods``: DONE, STAGE_PASSWORD, STAGE_SECOND_FACTOR or ENROLL.

    ``factor_in_effect`` and ``enrollment_pending`` are the account's second-factor state as the password
    route has always read it: the login switch, the policy, the enrollment, an administrator's reset.
    ``provider_id`` says the person came through an identity provider. A sign-in must have a first proof:
    the password, a passkey or a provider; without one this raises :class:`NoFirstProof` (a code alone
    proves nothing about who the person is). The table, in the order the rows are checked:

    * a temporary credential: done (it has its own validity window and no factor);
    * no password yet, and the person is an administrator: the password, always;
    * no password yet, an identity provider: done when the provider's MFA is trusted and was present, or
      when the vault's own second factor (an authenticator or recovery code, or a passkey) was already given
      after the provider, which proved who the person is; otherwise the vault's own rule below;
    * no password yet, a passkey as the first proof (no provider): done when the authenticator verified the
      person and the policy allows a passkey alone for them; otherwise the password (a possession factor
      needs a knowledge factor, never a second possession factor);
    * the password and a second kind (a code, a recovery code, a passkey), or the password and a trusted
      provider MFA: done;
    * the password alone: the vault's rule, as today: nothing when no factor is in effect, enrollment
      when one is required but not set up, else the second factor.
    """
    methods = set(methods)
    if is_temporary:
        return DONE
    has_password = PASSWORD in methods
    has_passkey = bool(methods & PASSKEYS)
    if not (has_password or has_passkey or provider_id):
        raise NoFirstProof("a sign-in needs a first proof: the password, a passkey or an identity provider")
    if not has_password:
        if getattr(user, "role", None) == RoleEnum.ADMIN:
            return STAGE_PASSWORD
        if provider_id:
            # The provider proved who the person is; a code or a passkey given after it is the second kind.
            if provider_mfa_trusted or (methods & SECOND_KINDS):
                return DONE
        elif has_passkey:
            return DONE if (user_verified and passwordless_allowed) else STAGE_PASSWORD
    elif (methods & SECOND_KINDS) or (provider_id and provider_mfa_trusted):
        return DONE
    if not factor_in_effect:
        return DONE
    return ENROLL if enrollment_pending else STAGE_SECOND_FACTOR


def second_kind_present(result: SignInResult) -> bool:
    """Whether two kinds of factor were present: the password and a second kind, a user-verified passkey
    (the authenticator checked the person as well as the device), or a trusted provider's MFA."""
    methods = set(result.methods)
    if PASSWORD in methods and methods & SECOND_KINDS:
        return True
    if (methods & PASSKEYS) and result.user_verified:
        return True
    return bool(result.provider_mfa_trusted)


def check_second_factor_stage(methods_so_far: Iterable[str]) -> None:
    """Refuse a second-factor stage that a passkey reached without the password: the second step would
    be a code, a second possession factor, where the rule wants the password. begin_pending never makes
    such a pending login; this guards every reader of the token as well."""
    methods = set(methods_so_far)
    if (methods & PASSKEYS) and PASSWORD not in methods:
        raise HTTPException(status_code=401, detail="A valid pre-authentication token is required.")


def read_pre_auth(payload: dict, pending: PendingLogin) -> None:
    """Note on ``pending`` what the pre-authentication token says about the sign-in it holds: the stage,
    the proofs so far (a token from before this field counts as a password proof, which is all a
    pending login could hold then; an empty list is a single sign-on with nothing of the vault's own yet),
    the provider, and whether the provider's trusted MFA was present. The values ride in the signed
    token, not in the row; a request cannot change them. A second-factor stage a passkey reached without
    the password is refused here, whatever route reads the token."""
    methods = payload.get("methods_so_far")
    if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
        methods = [PASSWORD]
    stage = payload.get("stage")
    if stage == STAGE_SECOND_FACTOR:
        check_second_factor_stage(methods)
    pending._stage = stage
    pending._methods_so_far = tuple(methods)
    provider = payload.get("idp")
    pending._provider_id = provider if isinstance(provider, str) else None
    pending._provider_mfa_trusted = payload.get("provider_mfa") is True


def methods_so_far(pending: Optional[PendingLogin]) -> List[str]:
    """The proofs a pending login holds, as :func:`read_pre_auth` read them (an empty list is a real answer:
    a single sign-on with nothing of the vault's own yet); the password alone for a pending login nothing
    read (a token from before the field). No pending login, as at the sign-in form: nothing yet."""
    if pending is None:
        return []
    read = getattr(pending, "_methods_so_far", None)
    return [PASSWORD] if read is None else list(read)


def provider_of(pending: Optional[PendingLogin]) -> Optional[str]:
    return getattr(pending, "_provider_id", None)


def provider_mfa_of(pending: Optional[PendingLogin]) -> bool:
    """Whether the pending login's provider sign-in carried the provider's trusted MFA (read from the token)."""
    return bool(getattr(pending, "_provider_mfa_trusted", False))


def delete_session_by_token(db, session_token: Optional[str]) -> None:
    """Delete the session the password check just made, so a sign-in with a step still to go leaves no
    usable session behind. The stored value is the token's SHA-256 hash."""
    if not session_token:
        return
    from app.core.models import ActiveSession
    db.query(ActiveSession).filter(
        ActiveSession.session_token == hash_session_token(session_token)).delete(synchronize_session=False)
    db.commit()


def consume_pending(db, pending: PendingLogin) -> None:
    """Spend a pending login, one winner only: a second completion of the same step is refused."""
    done = db.query(PendingLogin).filter(
        PendingLogin.id == pending.id, PendingLogin.consumed_at.is_(None)).update(
        {"consumed_at": datetime.now(timezone.utc)}, synchronize_session=False)
    db.commit()
    if done != 1:
        raise HTTPException(status_code=401, detail="This login attempt was already completed.")


def too_many_attempts(db, pending: PendingLogin) -> None:
    """Refuse a pending login that has taken its share of wrong answers, and spend it."""
    if (pending.attempts or 0) >= MAX_PENDING_ATTEMPTS:
        pending.consumed_at = datetime.now(timezone.utc)
        db.commit()
        raise HTTPException(status_code=401, detail="Too many attempts on this login; start again.")


def count_failed_attempt(db, pending: PendingLogin) -> None:
    """One wrong answer to a pending login's step; the last allowed one spends the login."""
    pending.attempts = (pending.attempts or 0) + 1
    if pending.attempts >= MAX_PENDING_ATTEMPTS:
        pending.consumed_at = datetime.now(timezone.utc)
    db.commit()


def begin_pending(db, result: SignInResult, stage: str, *, enrollment_required: bool = False) -> PendingStep:
    """Hold ``result`` for one more step. The pre-authentication token carries ``stage``, the pending
    login's id, the proofs so far and the provider; it has no ``session_token``, which is the confinement
    (the session dependency, the monitor handshake and the sign-out route each refuse a token without
    one). A pending login this result was continuing is spent first.

    The body is the pending answer the web app knows (``second_factor_required`` means a step follows),
    plus ``stage`` and, for an enrollment, what may be enrolled. The password stage names the account so
    the page can ask for the password alone.
    """
    from app.api import api_server as api
    if stage not in STAGES:
        raise ValueError(f"not a pending stage: {stage!r}")
    user = result.user
    if result.pending is not None:
        consume_pending(db, result.pending)
    pending = PendingLogin(user_id=user.id, client_ip=result.client_ip, enrollment_required=enrollment_required,
                           expires_at=datetime.now(timezone.utc) + timedelta(minutes=PRE_AUTH_TTL_MINUTES))
    db.add(pending)
    db.commit()
    claims = {"sub": str(user.id), "username": user.username, "stage": stage, "pre_auth": str(pending.id),
              "methods_so_far": list(result.methods)}
    if result.provider_id:
        claims["idp"] = result.provider_id
    if result.provider_mfa_trusted:
        # The trusted provider MFA counts at the end of the sign-in too (an administrator's password stage
        # after it), so the fact travels with the stage.
        claims["provider_mfa"] = True
    token = create_access_token(data=claims, expires_delta=timedelta(minutes=PRE_AUTH_TTL_MINUTES))
    if stage == STAGE_PASSWORD:
        methods = ["password"]
    else:
        methods = [] if enrollment_required else api._sf_login_methods(db, user)
    body = {
        "access_token": None, "second_factor_required": True, "stage": stage,
        "enrollment_required": enrollment_required,
        "methods": methods,
        "enrollment_methods": list(ENROLLMENT_METHODS) if enrollment_required else [],
        "pre_auth_token": token,
    }
    if stage == STAGE_PASSWORD:
        body["username"] = user.username
    return PendingStep(stage=stage, body=body)


def finish(db, result: SignInResult):
    """Finish a sign-in or hold it for its next step: a :class:`SignedIn` or a :class:`PendingStep`.

    A step that follows deletes the session the proof made (none may exist before the sign-in is
    whole) and records that the password was accepted when it was one of the proofs.
    """
    from app.api import api_server as api
    user = result.user
    if result.is_temporary:
        stage = DONE
    else:
        refuse_unless_the_account_may_sign_in(db, user, result.client_ip)
        in_effect = api._login_second_factor_in_effect(db, user)
        enrollment_pending = bool(in_effect) and api._second_factor_effective(db, user)["state"] == "pending"
        try:
            stage = second_factor_due(user, result.methods, factor_in_effect=bool(in_effect),
                                      enrollment_pending=enrollment_pending,
                                      passwordless_allowed=result.passwordless_allowed,
                                      user_verified=result.user_verified,
                                      provider_mfa_trusted=result.provider_mfa_trusted,
                                      provider_id=result.provider_id)
        except NoFirstProof:
            raise HTTPException(status_code=401, detail="This sign-in cannot be completed; start again.")
    if stage == DONE:
        return complete_sign_in(db, result)
    if result.session_token:
        delete_session_by_token(db, result.session_token)
        result.session_token = None
    if PASSWORD in result.methods:
        try:
            api.AuditLogger(db).log_action(action="login_password_ok", status="success", user=user,
                                           ip_address=result.client_ip, details={})
        except Exception:  # noqa: BLE001 -- the hold stands without its row
            pass
    if stage == ENROLL:
        return begin_pending(db, result, STAGE_SECOND_FACTOR, enrollment_required=True)
    return begin_pending(db, result, stage)


def refuse_unless_the_account_may_sign_in(db, user, client_ip: Optional[str]) -> None:
    """The account-state checks the password check makes, for every other way in: an inactive account is
    refused like an unknown one; a locked account (an administrator's lock, a timed one) and an automatic
    sign-in lock from this address or account-wide are refused with the lock's own answer, as at the form.
    A proof made moments before a lock does not finish a sign-in after it."""
    from app.api import api_server as api
    from app.core import sign_in_lockout
    from app.services.auth_service import AccountLockedError, account_locked
    if not getattr(user, "is_active", True):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if account_locked(user):
        raise api._sign_in_lock_refusal(AccountLockedError(
            "Account is locked", locked_until=user.locked_until,
            scope="administrator" if user.locked_until is None else "timed"))
    lock = sign_in_lockout.lock_in_force(db, user.id, client_ip)
    if lock is not None:
        raise api._sign_in_lock_refusal(AccountLockedError(
            "Account is locked", locked_until=lock.locked_until, scope=lock.scope))


def complete_sign_in(db, result: SignInResult) -> SignedIn:
    """Make the session and the token, and the records every sign-in makes.

    The token carries what it always did (``sub``, ``username``, ``session_token``, ``is_temporary``) plus
    ``amr`` (the proofs), ``auth_time``, ``mfa_at`` when two kinds of factor were present, and ``idp`` for
    a single sign-on. Every sign-in gets a ``sign_in_id`` of its own, made here and never taken from a
    provider: a renewal keeps it, so a page can tell a renewal of its own sign-in from another sign-in of the
    same person even when both share one time (a provider's session gives two sign-ins one ``auth_time``).
    A regular session honours the session-timeout setting; a temporary credential keeps the default token
    life, its own validity window being enforced separately.
    """
    from app.api import api_server as api
    from app.services.auth_service import AuthService
    user = result.user
    if result.pending is not None:
        consume_pending(db, result.pending)
    session_token = result.session_token
    if not session_token:
        auth = AuthService(db)
        session_token = auth._create_session(
            user, None, result.client_ip, expires_at=datetime.now(timezone.utc) + SESSION_ROW_LIFETIME,
            channel=auth.WEB)
    now = datetime.now(timezone.utc)
    # The account's last sign-in, the one the Users page shows and a dormant-account rule reads: every door stamps
    # it here (the password door stamped it before any second factor; a passkey or a provider sign-in has no other
    # place). Never a reason to refuse a sign-in that is whole.
    try:
        user.last_login = now
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    claims = {
        "sub": str(user.id), "username": user.username, "session_token": session_token,
        "is_temporary": result.is_temporary, "amr": list(result.methods),
        "auth_time": int(result.auth_time.timestamp()),
        "sign_in_id": api._new_sign_in_id(),
    }
    if second_kind_present(result):
        claims["mfa_at"] = int(now.timestamp())
    if result.provider_id:
        claims["idp"] = result.provider_id
    expires = None
    if not result.is_temporary:
        expires = timedelta(minutes=api._setting_int(db, "session_timeout", api.settings.jwt_access_token_expire_minutes))
    access_token = create_access_token(data=claims, expires_delta=expires)
    _record(db, result, api)
    return SignedIn(access_token=access_token, user=user, is_temporary=result.is_temporary)


def _record(db, result: SignInResult, api) -> None:
    """The records of a finished sign-in, the same for every method. Each is best-effort: a sign-in
    that is whole must not fail on its own telemetry."""
    user = result.user
    client_ip = result.client_ip
    try:
        api.AuditLogger(db).log_login_success(user, client_ip, is_temporary=result.is_temporary,
                                              methods=list(result.methods))
    except Exception:  # noqa: BLE001
        pass
    # The live monitor. A temporary credential's event is tagged with the owning account so its session
    # is told and only it receives the event (the monitor's filter). Fire-and-forget, off the loop: a
    # sign-in never waits on its telemetry, and a cache outage must not stall it. include_metrics=False:
    # a sign-in event does not need the six COUNT queries metrics enrichment runs.
    login_event = {
        "type": "login",
        "title": "User logged in",
        "description": f"{user.username} logged in" + (" (temporary)" if result.is_temporary else ""),
        "user": user.username,
        "ip": client_ip,
        "is_temporary": result.is_temporary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if result.is_temporary:
        login_event["temp_username"] = result.temp_username
        login_event["owner_user_id"] = str(user.id)
    api._fire_offloop(api.broadcast_event, {"event": login_event}, include_metrics=False)
    if result.is_temporary:
        # The owner's durable notice of a temporary credential's sign-in: written inline on its own
        # database session (the row must exist within the answer), its live nudge off the loop.
        api._notify_users(
            [str(user.id)], "temp_login",
            title="Temporary credential signed in",
            body=f"{result.temp_username} signed in" + (f" from {client_ip}" if client_ip else ""),
            target="#temp-creds",
        )
    else:
        # The opt-in "New sign-in alert" email to the account (the default template uses the current
        # time, so no action context is required).
        api._fire_action_email(db, "login_alert", email=user.email, username=user.username)


# How long the session row a renewal makes lives until the renewal has won: time enough for the few statements between
# making it and ending the old session, and short enough that a row left by a crash in between ends on its own.
RENEWAL_HOLD = timedelta(minutes=2)


@dataclass
class Renewed:
    """A renewed sign-in: the new token, and when it runs out."""
    access_token: str
    expires_at: datetime


def renew(db, user, old: dict, *, client_ip: Optional[str], now: Optional[datetime] = None) -> Renewed:
    """Keep a sign-in going ("Stay signed in"): a new session and a new token for the same account, and the session
    behind the old token ended at once.

    ``old`` is the verified payload of the token the request carried. Whether a sign-in may be renewed, and until
    when, is the renewal rules' answer (``_renewal_terms`` in app/api/api_server.py: the limit counted from the
    sign-in, a second factor the account now needs); the one helper that mints (``_renewed_token``) carries how the
    person signed in. This function owns the order:

    1. A refusal comes before anything changes: the session is left as it was, to run out on its own.
    2. The new session row is made first, with what the old one carried, and lives only minutes
       (``RENEWAL_HOLD``) until the renewal has won. So whatever looks for the account's sessions meanwhile (a
       sign-out everywhere, an identity provider's logout) finds it, at no moment is the old session ended with
       the new one not yet there, and a row left by a crash at this point ends on its own. Its token exists only
       inside this call.
    3. The old session is ended by one conditional update, and only the call that ended it goes on. Of two
       requests with the same token one wins; the other, like a renewal whose session was ended meanwhile, deletes
       the row it made and is refused, so a replay carries a dead token and leaves nothing.
    4. The winner's row gets its full life, the old token is refused for the rest of its own, the new token is
       minted and the renewal is recorded (``session_extended``).
    """
    import time
    from app.api import api_server as api
    from app.core.models import ActiveSession
    from app.services.auth_service import AuthService, denylist_token
    now = now or datetime.now(timezone.utc)
    old_session = old.get("session_token")
    if not old_session or old.get("is_temporary") or getattr(user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="This session cannot be extended; sign in again when it ends.")
    auth_time, expires_at = api._renewal_terms(db, user, old, now)
    ended_already = HTTPException(status_code=401, detail="This session has already ended.")
    old_row = db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(old_session)).first()
    if old_row is None or str(old_row.user_id) != str(user.id) or old_row.revoked:
        raise ended_already
    auth = AuthService(db)
    new_session = auth._create_session(user, None, client_ip, expires_at=now + RENEWAL_HOLD, channel=auth.WEB)
    try:
        api._carry_session_marks(db, old_row, new_session)
        _row, ended = api._end_web_session(db, old_session, user_id=user.id)
    except BaseException:
        _drop_unwon_session(db, new_session)
        raise
    if not ended:
        _drop_unwon_session(db, new_session)
        raise ended_already
    db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(new_session)).update(
        {ActiveSession.expires_at: now + SESSION_ROW_LIFETIME}, synchronize_session=False)
    db.commit()
    ttl = int(old.get("exp", 0) - time.time())
    denylist_token(old_session, ttl if ttl > 0 else 1800)
    access_token = api._renewed_token(user, old, new_session, auth_time, expires_at, now)
    try:
        api.AuditLogger(db).log_action(action="session_extended", status="success", user=user, ip_address=client_ip,
                                       details={
                                           "ended_session": hash_session_token(old_session)[:8],
                                           "new_session": hash_session_token(new_session)[:8],
                                           "signed_in_at": datetime.fromtimestamp(auth_time, tz=timezone.utc)
                                           .replace(microsecond=0).isoformat().replace("+00:00", "Z")})
    except Exception:  # noqa: BLE001 -- the renewal stands without its row
        pass
    return Renewed(access_token=access_token, expires_at=expires_at)


def _drop_unwon_session(db, session_token: str) -> None:
    """A renewal that did not win leaves nothing: the row it made is deleted (its token never left the call that
    made it) and its cache entry with it."""
    from app.services import auth_service
    try:
        db.rollback()
        delete_session_by_token(db, session_token)
    except Exception:  # noqa: BLE001 -- the row ends on its own (RENEWAL_HOLD) when it cannot be deleted now
        db.rollback()
    auth_service._best_effort_cache(
        "session.cache-delete.skipped",
        lambda: auth_service.redis_client.delete(f"session:{hash_session_token(session_token)}"))


def read_password_stage(payload: Optional[dict], db):
    """The pending login a password-stage token names, with its proofs read, or None when ``payload``
    is not such a token. Refuses an expired or spent pending login as the second-factor stage does."""
    if not payload or payload.get("stage") != STAGE_PASSWORD or not payload.get("pre_auth"):
        return None
    try:
        pending_id = uuid.UUID(str(payload["pre_auth"]))
    except ValueError:
        raise HTTPException(status_code=401, detail="A valid pre-authentication token is required.")
    pending = db.query(PendingLogin).filter(PendingLogin.id == pending_id).first()
    exp = pending.expires_at if pending else None
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if not pending or pending.consumed_at is not None or (exp is not None and exp < datetime.now(timezone.utc)):
        raise HTTPException(status_code=401, detail="This login attempt has expired; start again.")
    read_pre_auth(payload, pending)
    return pending
