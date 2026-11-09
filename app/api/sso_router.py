"""Single sign-on routes: starting a sign-in or a link, the provider's callback, and a person's own identities.

Public: ``POST /auth/sso/{provider_id}/start`` answers the authorization URL the web app navigates to (a POST
answering a URL rather than a redirecting GET: the vault is bearer-only, so the session-bound variants could never
be browser navigations, and one shape serves all); ``GET /auth/sso/{provider_id}/callback`` is where the provider
sends the browser back, and it ends in a redirect to the web app with a one-time code in the fragment
(``/#sso=<code>``), or a reason (``/#sso-error=<reason>``); the web app redeems the code at ``POST /auth/finish``.
Signed in: a person's identities, a start that links a new one (under the account.second_factor step-up, in a
session that proved the password and, when the account has a factor, the second factor), and the unlink.

Every start counts in the sign-in budget for its address, and the state store caps abandoned starts per address;
the callback is public and an error answer there is unsigned, so a refusal never has a consequence for any account.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.user_management_api import get_current_user, require_interactive_admin
from app.core import sso_state
from app.core.database import get_db
from app.core.models import ExternalIdentity, SsoProvider, User
from app.services import oidc_client as oc
from app.services import sso_groups
from app.services import sso_sign_in as sso

router = APIRouter(tags=["Single sign-on"])
log = logging.getLogger("dockvault.sso")

START_LIMIT = 30                     # starts per address per START_WINDOW, beside the state store's abandoned cap
START_WINDOW = 300
LOGOUT_LIMIT = 600                 # back-channel logouts per provider per source address and window: a provider
                                   # signing out many people at once is machine-to-machine, not a person

FINISH_LIMIT = 30                    # handover claims per address per FINISH_WINDOW
FINISH_WINDOW = 300


class SsoStartRequest(BaseModel):
    verifier_hash: Optional[str] = Field(default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    code_challenge: Optional[str] = Field(default=None, min_length=43, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    return_to: Optional[str] = Field(default=None, max_length=40)
    # An invitation being accepted through the provider: the invited account is made at the callback.
    invitation: Optional[str] = Field(default=None, min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class SsoLinkStartRequest(BaseModel):
    # The tab's verifier, hashed: the finish is accepted only from the tab that started the link.
    verifier_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class SsoHandoverFinishRequest(BaseModel):
    code: str = Field(min_length=1, max_length=128)
    verifier: str = Field(min_length=1, max_length=256)


class SsoReauthStartRequest(BaseModel):
    verifier_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    action: str = Field(min_length=1, max_length=80)


def _api():
    from app.api import api_server
    return api_server


def _provider(db, provider_id) -> Optional[SsoProvider]:
    try:
        pid = uuid.UUID(str(provider_id))
    except ValueError:
        return None
    return db.query(SsoProvider).filter(SsoProvider.id == pid).first()


def _limit_start(client_ip: str) -> None:
    from app.core import sign_in_lockout
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable, retry_after_seconds
    try:
        allowed, _, reset = _rl.check_rate_limit(identifier=sign_in_lockout.source_of(client_ip), limit=START_LIMIT,
                                                 window=START_WINDOW, prefix="sso_start", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many sign-in starts. Try again later.",
                            headers={"Retry-After": str(retry_after_seconds(reset, START_WINDOW))})


def _refused_start(exc) -> HTTPException:
    if isinstance(exc, sso.Refusal):
        code = exc.code
    elif isinstance(exc, oc.OidcError):
        code = exc.code
    elif isinstance(exc, sso_state.TooManyAbandoned):
        return HTTPException(status_code=429, detail="Too many unfinished sign-ins from your network. Try again later.")
    elif isinstance(exc, sso_state.Unavailable):
        return HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
    else:
        code = oc.PROVIDER_ERROR
    log.info("sso start refused: %s", exc)
    http = 404 if code == sso.PROVIDER_DISABLED else 503 if code == oc.TEMPORARILY_UNAVAILABLE else 409
    return HTTPException(status_code=http, detail={"reason": code, "message": sso.reason_text(code)})


def _audit(db, action: str, *, user=None, ip, details: dict, status_: str = "success", resource_type=None,
           resource_id=None) -> None:
    try:
        from app.services.audit_logger import AuditLogger
        AuditLogger(db).log_action(action=action, status=status_, user=user, ip_address=ip, details=details,
                                   resource_type=resource_type, resource_id=resource_id)
    except Exception:      # noqa: BLE001 -- a refusal or a link stands without its row
        pass


def _redirect(fragment: str) -> RedirectResponse:
    return RedirectResponse(url="/#" + fragment, status_code=302)


def _invitation_for_start(db, token: str, client_ip: str):
    """The pending invitation a token names, for a sign-in that accepts it through a provider: looked up as the
    password acceptance looks it up (the same limiter per token prefix, the same checks, the same generic
    refusal, the same audit row), so a guessed token learns nothing more here than there."""
    api = _api()
    from app.core import invitations
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable, retry_after_seconds
    prefix = invitations.token_prefix(token)
    try:
        allowed, _, reset = _rl.check_rate_limit(identifier=prefix, limit=5, window=60, prefix="invite_accept_prefix",
                                                 fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests.",
                            headers={"Retry-After": str(retry_after_seconds(reset, 60))})
    if not invitations.pepper_ok(api._invite_pepper()):
        raise HTTPException(status_code=503,
                            detail="Invitations are unavailable: the invite-token secret is not configured.")
    inv = api._resolve_valid_invite(db, token)
    if inv is None or not api._invitation_inviter_can_act(db, inv) or api._username_kept(inv.username):
        api._audit_accept_failure(db, prefix, client_ip, reason="sso_start_unresolved")
        raise HTTPException(status_code=404, detail={"reason": sso.INVITATION_UNUSABLE,
                                                     "message": sso.reason_text(sso.INVITATION_UNUSABLE)})
    return inv


def _invitation_prefix(db, invitation_id) -> str:
    from app.core.models import AccountInvitation
    try:
        row = db.query(AccountInvitation).filter(AccountInvitation.id == uuid.UUID(str(invitation_id))).first()
    except ValueError:
        return ""
    return getattr(row, "token_prefix", None) or ""


# --------------------------------------------------------------------------- public

@router.post("/auth/sso/{provider_id}/start")
async def start_sign_in(
    provider_id: str,
    body: SsoStartRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Start a single sign-on: the login state is made and the provider's authorization URL answered. The body
    carries the hash of the verifier the tab made (the web app) or a PKCE challenge (the desktop app); the sign-in
    cannot be finished without the matching verifier. ``return_to`` is one of the app's own views."""
    api = _api()
    client_ip = api.get_client_ip(request)
    _limit_start(client_ip)
    if bool(body.verifier_hash) == bool(body.code_challenge):
        raise HTTPException(status_code=400, detail="The start needs the tab's verifier hash or an app's code challenge, one of the two.")
    row = _provider(db, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": sso.reason_text(sso.PROVIDER_DISABLED)})
    purpose = sso_state.APP if body.code_challenge and not body.verifier_hash else sso_state.SIGN_IN
    why = sso.usable_for(row, purpose)
    if why is not None:
        raise _refused_start(sso.Refusal(why))      # before any invitation is looked up for a provider that cannot serve
    extras = None
    if body.invitation:
        if body.code_challenge:
            raise HTTPException(status_code=400, detail="An invitation is accepted in the browser, not in an app.")
        extras = {"invitation_id": str(_invitation_for_start(db, body.invitation, client_ip).id)}
    from app.core import sign_in_lockout
    try:
        url = sso.start(row, purpose=purpose,
                        source=sign_in_lockout.source_of(client_ip), client_ip=client_ip,
                        verifier_hash=body.verifier_hash, code_challenge=body.code_challenge, return_to=body.return_to,
                        extras=extras)
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


@router.get("/auth/sso/reasons")
async def sign_in_reasons():
    """PUBLIC: every reason the callback can send the sign-in page in its ``#sso-error=<reason>`` fragment, with
    the words the page shows for it. The page shows these and never a provider's own text."""
    return {"reasons": dict(sso.REASON_TEXTS)}


@router.get("/auth/sso/{provider_id}/callback")
async def sign_in_callback(
    provider_id: str,
    request: Request,
    state: Optional[str] = None,
    code: Optional[str] = None,
    iss: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Where the provider sends the browser back. The state is spent first (one use, whatever follows); the
    provider in the path must be the state's; an ``iss`` parameter, when present, must be the provider's issuer;
    a provider ``error`` is a refusal with no consequence for any account. Then the code exchange, the token
    checks and the purpose's own step. The answer is always a redirect into the web app: a one-time code for a
    sign-in, a confirmation for a link, a reason otherwise."""
    api = _api()
    client_ip = api.get_client_ip(request)
    try:
        login = sso_state.take(state)
    except sso_state.Unavailable:
        return _redirect("sso-error=" + oc.TEMPORARILY_UNAVAILABLE)
    if login is None:
        log.info("sso callback with an unknown or spent state from %s", client_ip)
        return _redirect("sso-error=" + sso.STATE_UNKNOWN)
    row = _provider(db, provider_id)
    if row is None or str(row.id) != login.provider_id:
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure",
               details={"provider_id": login.provider_id, "reason": sso.PROVIDER_MIX_UP, "purpose": login.purpose})
        return _redirect("sso-error=" + sso.PROVIDER_MIX_UP)
    details = {"provider_id": login.provider_id, "purpose": login.purpose}
    if error is not None or not code:
        # Unsigned: anyone can send it. A reason, a row, and nothing else.
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": oc.PROVIDER_ERROR})
        log.info("sso callback error for provider %s: %s", login.provider_id, (error or "no code")[:64])
        return _redirect("sso-error=" + oc.PROVIDER_ERROR)
    why = sso.usable_for(row, login.purpose)
    if why is not None:
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": why})
        return _redirect("sso-error=" + why)
    # RFC 9207: a provider that advertises the iss parameter must send it, and it must be the issuer; one that
    # does not advertise it is held to it whenever it does send it.
    try:
        discovery = oc.discover(sso.provider_config(row))
    except (sso.Refusal, oc.OidcError) as exc:
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": exc.code})
        return _redirect("sso-error=" + exc.code)
    if (iss is not None and iss != row.issuer) or (iss is None and discovery.iss_in_callback):
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": oc.ISSUER_MISMATCH})
        return _redirect("sso-error=" + oc.ISSUER_MISMATCH)
    try:
        answer = sso.verified_answer(row, login, code=code)
    except (sso.Refusal, oc.OidcError) as exc:
        log.info("sso callback refused for provider %s: %s", login.provider_id, exc)
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": exc.code})
        return _redirect("sso-error=" + exc.code)
    # The provider's restriction (tenant, domain, group, the sign-up domain list) is judged before who the person
    # is, known identity included; a test reports it instead of refusing.
    if login.purpose != sso_state.TEST:
        try:
            sso.restriction_refusal(db, row, answer)
        except sso.Refusal as exc:
            _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": exc.code})
            return _redirect("sso-error=" + exc.code)

    if login.purpose in (sso_state.SIGN_IN, sso_state.APP):
        invitation_id = login.extras.get("invitation_id") if isinstance(login.extras, dict) else None
        try:
            found = sso.resolve_account(db, row, answer, login=login)
        except sso.Refusal as exc:
            db.rollback()          # nothing of a refused resolution may ride on the audit row's commit
            _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure",
                   details={**details, "reason": exc.code, **({"detail": exc.detail} if exc.detail else {})})
            if invitation_id:
                api._audit_accept_failure(db, _invitation_prefix(db, invitation_id), client_ip,
                                          reason=exc.detail or exc.code)
            return _redirect("sso-error=" + exc.code)
        user = found.user
        # The provider's groups into departments and roles, for this token (a held request for the administrator
        # role, never the role itself).
        applied = sso_groups.apply(db, row, user, answer)
        if found.created or found.linked_now or applied.changed:
            # The account, its identity, the claimed invitation and the memberships stand before any code is handed
            # out: a store that fails afterwards costs the person one more sign-in, never an account without its
            # identity.
            from sqlalchemy.exc import IntegrityError
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                code_ = sso.INVITATION_UNUSABLE if found.invitation is not None else sso.NO_ACCOUNT
                _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": code_})
                if invitation_id:
                    api._audit_accept_failure(db, _invitation_prefix(db, invitation_id), client_ip, reason="commit_conflict")
                return _redirect("sso-error=" + code_)
            if found.created or found.linked_now:
                _record_resolution(db, row, found, client_ip=client_ip, details=details)
        sso_groups.tell(db, row, user, applied, client_ip=client_ip)
        from app.core import sign_in_codes
        result = sso.pipeline_result(db, row, user, answer, provider_id=login.provider_id, client_ip=client_ip)
        try:
            handover_code = sign_in_codes.store(sign_in_codes.from_result(
                result, verifier_hash=login.verifier_hash, code_challenge=login.code_challenge,
                purpose="app" if login.purpose == sso_state.APP else "sign_in"))
        except sign_in_codes.Unavailable:
            return _redirect("sso-error=" + oc.TEMPORARILY_UNAVAILABLE)
        db.commit()        # a tenant learnt at this sign-in; the identity's last sign-in is stamped by the finish
        fragment = f"sso={handover_code}"
        if login.return_to and login.return_to != sso_state.DEFAULT_RETURN_TO:
            fragment += "&return_to=" + login.return_to.lstrip("#")
        return _redirect(fragment)

    # A link and a test belong to the signed-in account and tab that started them. The browser that reaches this
    # callback proves nothing about that (a start URL can be handed to anyone), so nothing is linked or written
    # here: what the provider said waits under a one-time code, and the tab that started the flow claims it with
    # its session and its verifier (POST /users/me/identities/finish, POST /admin/sso/providers/{id}/test/finish).
    user = db.query(User).filter(User.id == uuid.UUID(login.user_id)).first() if login.user_id else None
    if not sso.account_usable(user):
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": sso.ACCOUNT_DISABLED})
        return _redirect("sso-error=" + sso.ACCOUNT_DISABLED)
    if login.purpose not in (sso_state.LINK, sso_state.TEST, sso_state.STEP_UP) or not login.verifier_hash \
            or not login.session_hash:
        _audit(db, "sso_sign_in_refused", user=user, ip=client_ip, status_="failure",
               details={**details, "reason": sso.PURPOSE_NOT_READY})
        return _redirect("sso-error=" + sso.PURPOSE_NOT_READY)
    if login.purpose == sso_state.STEP_UP:
        # A fresh sign-in of the account's own identity, within the minute, with the provider's MFA when trusted.
        try:
            sso.reauth_refusal(db, row, user, answer)
        except sso.Refusal as exc:
            _audit(db, "sso_sign_in_refused", user=user, ip=client_ip, status_="failure",
                   details={**details, "reason": exc.code, "step_up": login.step_up_action})
            return _redirect("sso-error=" + exc.code)
        if not login.step_up_action:
            return _redirect("sso-error=" + sso.PURPOSE_NOT_READY)
    if login.purpose == sso_state.LINK:
        # Refusals that need no claim are given now, so the person is told at once.
        try:
            sso.link_refusal(db, row, user, answer)
        except sso.Refusal as exc:
            _audit(db, "sso_sign_in_refused", user=user, ip=client_ip, status_="failure",
                   details={**details, "reason": exc.code})
            return _redirect("sso-error=" + exc.code)
    record = {"purpose": login.purpose, "provider_id": login.provider_id, "user_id": login.user_id,
              "session_hash": login.session_hash, "verifier_hash": login.verifier_hash, **sso.answer_record(answer)}
    if login.purpose == sso_state.TEST:
        record["summary"] = sso.test_summary(db, row, answer, user)
    if login.purpose == sso_state.STEP_UP:
        record["step_up_action"] = login.step_up_action
    try:
        handover = sso_state.store_handover(record)
    except sso_state.Unavailable:
        return _redirect("sso-error=" + oc.TEMPORARILY_UNAVAILABLE)
    fragment = {sso_state.LINK: "sso-linked=", sso_state.TEST: "sso-test=", sso_state.STEP_UP: "sso-stepup="}[login.purpose]
    return _redirect(fragment + handover)


@router.post("/auth/sso/{provider_id}/backchannel-logout")
async def backchannel_logout(provider_id: str, request: Request, db: Session = Depends(get_db)):
    """Where the provider says a person signed out of it (OpenID Connect back-channel logout, a form with
    ``logout_token``): the token is verified as an ID token with the logout event, honoured once by its id, and the
    vault sessions it names (by the provider's session id, else by the subject) are ended, those and no others.
    200 on success; 400 with ``{"error": "invalid_request"}`` for a token that is not valid, never a body that says
    why; 501 with ``{"error": "logout_failed"}`` when the vault could not act on a token (the limiter, the store, the
    provider's keys unreachable), the code the specification gives a failed logout, so the provider may try again."""
    api = _api()
    client_ip = api.get_client_ip(request)
    from app.core import sign_in_lockout
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    invalid = JSONResponse(status_code=400, content={"error": "invalid_request"})
    failed = JSONResponse(status_code=501, content={"error": "logout_failed"})
    try:
        # One bucket per source, whatever the address names: a path with a new provider id each time gets no bucket
        # of its own.
        allowed, _, _reset = _rl.check_rate_limit(
            identifier=sign_in_lockout.source_of(client_ip), limit=LOGOUT_LIMIT,
            window=START_WINDOW, prefix="sso_backchannel", fail_open=False)
    except RateLimiterUnavailable:
        allowed = False
    if not allowed:
        return failed
    try:
        form = await request.form()
        token = form.get("logout_token")
    except Exception:  # noqa: BLE001
        token = None
    row = _provider(db, provider_id)
    if row is None:
        return invalid                     # no provider by that id: nothing to record (the address is anyone's to type)
    scope = str(row.id)
    if getattr(row, "kind", None) != "oidc" or not isinstance(token, str) or not token \
            or not sso.policy_of(row)["sso_backchannel_logout"]:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "not_accepted"})
        return invalid
    try:
        provider = sso.provider_config(row)

        def verify():
            # The provider's discovery and keys are fetched over the network: off the event loop.
            discovery = oc.discover(provider, fetch=oc.fetch_json)
            return oc.verify_logout_token(provider, discovery, token, fetch=oc.fetch_json,
                                          seen_jti=lambda jti, ttl: sso_state.seen_logout_jti(jti, ttl, scope=scope))
        from starlette.concurrency import run_in_threadpool
        claims = await run_in_threadpool(verify)
    except sso_state.Unavailable:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "store_unavailable"})
        return failed
    except (sso.Refusal, oc.OidcError) as exc:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": exc.code})
        return failed if exc.code == oc.TEMPORARILY_UNAVAILABLE else invalid
    from app.core.models import SsoSession
    sid, sub = claims.get("sid"), claims.get("sub")
    query = db.query(SsoSession).filter(SsoSession.provider_id == row.id)
    if isinstance(sid, str) and sid:
        query, by = query.filter(SsoSession.idp_sid == sid), "sid"
    elif isinstance(sub, str) and sub:
        query, by = query.filter(SsoSession.idp_sub == sub), "sub"
    else:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "no_identifier"})
        return invalid
    try:
        session_ids = [s.session_id for s in query.all()]
        ended = api._revoke_sessions(db, session_ids=session_ids, actor_username="provider logout",
                                     durable=True) if session_ids else 0
        db.commit()
    except Exception as exc:  # noqa: BLE001 -- the logout failed: the token is not spent, so the provider's retry works
        db.rollback()
        sso_state.forget_logout_jti(claims.get("jti"), scope=scope)
        log.warning("sso back-channel logout not applied: %s", type(exc).__name__)
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "revocation_failed"})
        return failed
    _audit(db, "sso_backchannel_logout", ip=client_ip, details={"provider_id": scope, "by": by, "sessions": ended})
    return JSONResponse(status_code=200, content={})


@router.post("/users/me/identities/{provider_id}/reauth")
async def start_reauth(
    provider_id: str,
    body: SsoReauthStartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start a fresh sign-in at a linked provider to meet the password part of a step-up for ``action``: the
    provider is told to authenticate again (``prompt=login``, ``max_age=0``); the callback hands the answer to this
    tab, which stages it (``POST /users/me/identities/reauth/finish``) and then calls the step-up route with the
    method ``idp_reauth``. Offered only for a provider whose test sign-in carried ``auth_time``."""
    from app.core import second_factor_actions as acts
    api = _api()
    _refuse_temp(current_user)
    if not acts.is_step_up_action(body.action):
        raise HTTPException(status_code=404, detail="Unknown action.")
    client_ip = api.get_client_ip(request)
    _limit_start(client_ip)
    row = _provider(db, provider_id)
    if row is None or not sso.reauth_offered(row):
        raise HTTPException(status_code=404, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": "This provider cannot confirm you for a step-up."})
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id,
                                                 ExternalIdentity.user_id == current_user.id).first()
    if identity is None:
        raise HTTPException(status_code=404, detail="Your account has no identity on this provider.")
    from app.core import sign_in_lockout
    try:
        url = sso.start(row, purpose=sso_state.STEP_UP, source=sign_in_lockout.source_of(client_ip), client_ip=client_ip,
                        verifier_hash=body.verifier_hash, user_id=current_user.id, session_hash=api._current_session_hash(request),
                        step_up_action=body.action, reauthenticate=True, login_hint=identity.email_at_link or None)
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


@router.post("/users/me/identities/reauth/finish")
async def finish_reauth(
    body: SsoHandoverFinishRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The tab that started a provider re-authentication stages its answer for the step-up route (one use, two
    minutes, this session and this action only)."""
    _refuse_temp(current_user)
    api = _api()
    record = _claim_handover(db, request, current_user, body, purpose=sso_state.STEP_UP)
    action = record.get("step_up_action")
    if not isinstance(action, str) or not action:
        raise HTTPException(status_code=401, detail="This code is not valid for this tab; start again.")
    try:
        sso_state.stage_reauth(record["session_hash"], action)
    except sso_state.Unavailable:
        raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
    _audit(db, "step_up_idp_reauth", user=current_user, ip=api.get_client_ip(request),
           details={"provider_id": record["provider_id"], "step_up": action})
    return {"staged": True, "action": action, "expires_in": sso_state.REAUTH_TTL_SECONDS}


def _record_resolution(db, row, found, *, client_ip, details: dict) -> None:
    """After the commit: the audit rows and notices for an account made from an invitation or linked by its
    verified email at this sign-in. Best effort, like every notice."""
    api = _api()
    user = found.user
    label = (row.label or row.name) if row is not None else "single sign-on"
    if found.invitation is not None:
        inv = found.invitation
        _audit(db, "account_invitation_accepted", user=user, ip=client_ip, resource_type="account_invitation",
               resource_id=str(inv.id), details={"username": user.username, "role": str(user.role),
                                                 "token_prefix": inv.token_prefix, "method": "sso",
                                                 "provider_id": details.get("provider_id")})
        try:
            from app.core.models import RoleEnum
            if user.role == RoleEnum.ADMIN:
                api._announce_admin_granted(db, user, by_name=found.inviter_name, how="invited")
            api._fire_action_email(db, "account_welcome", email=user.email, username=user.username)
        except Exception as exc:  # noqa: BLE001
            log.info("sso invitation notices skipped: %s", type(exc).__name__)
    if found.linked_by == "jit":
        _audit(db, "sso_account_created", user=user, ip=client_ip, resource_type="user", resource_id=str(user.id),
               details={"username": user.username, "role": str(user.role), "provider_id": details.get("provider_id")})
        try:
            admins = [str(a.id) for a in api._active_admins(db)]
            api._notify_users(admins, "account_created", title="An account was created by single sign-on",
                              body=(f"{user.username} signed in through {label} for the first time and an account was made "
                                    f"for them with the role {getattr(user.role, 'value', user.role)}. Check the Users page "
                                    "if you did not expect this."),
                              target="#users")
            api._fire_action_email(db, "account_welcome", email=user.email, username=user.username)
        except Exception as exc:  # noqa: BLE001
            log.info("sso account-created notices skipped: %s", type(exc).__name__)
    _audit(db, "sso_identity_linked", user=user, ip=client_ip,
           details={"provider_id": details.get("provider_id"), "linked_by": found.linked_by})
    if found.linked_by == "self":
        _tell_owner(db, user, row, "A sign-in method was added",
                    f"Single sign-on with {label} was linked to your account by a sign-in with your verified email address.")


def _claim_handover(db, request, current_user, body: SsoHandoverFinishRequest, *, purpose: str):
    """The record a handover code stands for, when this tab and session may claim it: the code is spent whatever
    follows; the verifier must hash to the one the start kept; the account and the session must be the ones
    that started it. One refusal for every miss."""
    api = _api()
    client_ip = api.get_client_ip(request)
    from app.core import sign_in_lockout
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable, retry_after_seconds
    try:
        allowed, _, reset = _rl.check_rate_limit(identifier=sign_in_lockout.source_of(client_ip), limit=FINISH_LIMIT,
                                                 window=FINISH_WINDOW, prefix="sso_finish", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.",
                            headers={"Retry-After": str(retry_after_seconds(reset, FINISH_WINDOW))})
    try:
        record = sso_state.take_handover(body.code)
    except sso_state.Unavailable:
        raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
    import hashlib
    import hmac
    refused = HTTPException(status_code=401, detail="This code is not valid for this tab; start again.")
    if record is None or record.get("purpose") != purpose or not sso.account_usable(current_user):
        raise refused
    if not hmac.compare_digest(hashlib.sha256(body.verifier.encode("utf-8")).hexdigest(), record["verifier_hash"]):
        _audit(db, "sso_sign_in_refused", user=current_user, ip=client_ip, status_="failure",
               details={"provider_id": record["provider_id"], "purpose": purpose, "reason": "verifier_mismatch"})
        raise refused
    if record["user_id"] != str(current_user.id) or record["session_hash"] != api._current_session_hash(request):
        _audit(db, "sso_sign_in_refused", user=current_user, ip=client_ip, status_="failure",
               details={"provider_id": record["provider_id"], "purpose": purpose, "reason": sso.NOT_THIS_ACCOUNT})
        raise refused
    return record


@router.post("/users/me/identities/finish")
async def finish_link(
    body: SsoHandoverFinishRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Claim a finished link: the identity the provider confirmed is linked to the caller's account, when the
    code came back to the tab and session that started the link."""
    api = _api()
    _refuse_temp(current_user)
    client_ip = api.get_client_ip(request)
    record = _claim_handover(db, request, current_user, body, purpose=sso_state.LINK)
    row = _provider(db, record["provider_id"])
    if row is None or sso.usable_for(row, sso_state.LINK) is not None:
        raise HTTPException(status_code=409, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": sso.reason_text(sso.PROVIDER_DISABLED)})
    answer = sso.answer_from_record(record)
    from sqlalchemy.exc import IntegrityError
    try:
        identity = sso.link_identity(db, row, current_user, answer, linked_by="self")
        db.commit()
    except (sso.Refusal, IntegrityError) as exc:
        db.rollback()
        code = exc.code if isinstance(exc, sso.Refusal) else sso.ALREADY_LINKED      # a second writer got there first
        _audit(db, "sso_sign_in_refused", user=current_user, ip=client_ip, status_="failure",
               details={"provider_id": str(row.id), "purpose": sso_state.LINK, "reason": code})
        raise HTTPException(status_code=409, detail={"reason": code, "message": sso.reason_text(code)})
    _audit(db, "sso_identity_linked", user=current_user, ip=client_ip,
           details={"provider_id": str(row.id), "purpose": sso_state.LINK, "identity_id": str(identity.id), "linked_by": "self"})
    _tell_owner(db, current_user, row, "A sign-in method was added to your account",
                f"You linked your account to {row.label or row.name}: it can now sign in through it.")
    return {"linked": True, "identity": _identity_public(identity, row)}


@router.post("/admin/sso/providers/{provider_id}/test/finish")
async def finish_test(
    provider_id: str,
    body: SsoHandoverFinishRequest,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Claim a finished test sign-in: the summary of what the provider sent and what the vault would do is written
    on the provider's row and answered, for the administrator whose tab and session started the test."""
    api = _api()
    client_ip = api.get_client_ip(request)
    record = _claim_handover(db, request, current_user, body, purpose=sso_state.TEST)
    row = _provider(db, provider_id)
    if row is None or str(row.id) != record["provider_id"]:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    row.last_test = record.get("summary") or {}
    db.commit()
    _audit(db, "sso_provider_tested", user=current_user, ip=client_ip,
           details={"provider_id": str(row.id), "purpose": sso_state.TEST, "outcome": "ok"})
    return {"tested": True, "summary": row.last_test}


# --------------------------------------------------------------------------- the person's own identities

def _refuse_temp(user) -> None:
    if getattr(user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="Temporary credentials cannot manage sign-in methods.")


def _identity_public(identity: ExternalIdentity, row: Optional[SsoProvider]) -> dict:
    def _t(value):
        return value.isoformat() + "Z" if value else None
    return {"id": str(identity.id), "provider_id": str(identity.provider_id),
            "provider": (row.label or row.name) if row is not None else "a removed provider",
            "linked_at": _t(identity.linked_at), "linked_by": identity.linked_by,
            "last_sign_in_at": _t(identity.last_sign_in_at)}


def _tell_owner(db, user, row, title: str, change: str) -> None:
    api = _api()
    try:
        api._notify_users([str(user.id)], "account_changed", title=title,
                          body=f"{change} If you did not do this, remove it and change your password.", target="#profile")
    except Exception as exc:  # noqa: BLE001
        log.info("sso owner notice skipped: %s", type(exc).__name__)
    try:
        if (user.email or "").strip():
            api._fire_action_email(db, "sign_in_method_changed", email=user.email, username=user.username,
                                   action_context={"change": change, "when": api._change_time_text()})
    except Exception as exc:  # noqa: BLE001
        log.info("sso owner email skipped: %s", type(exc).__name__)


@router.get("/users/me/identities")
async def list_my_identities(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The caller's linked organisation identities: the provider's label, when linked and by what, the last sign-in."""
    _refuse_temp(current_user)
    rows = db.query(ExternalIdentity).filter(ExternalIdentity.user_id == current_user.id).all()
    providers = {str(p.id): p for p in db.query(SsoProvider).all()} if rows else {}
    return {"identities": [_identity_public(i, providers.get(str(i.provider_id))) for i in rows]}


@router.post("/users/me/identities/{provider_id}/start")
async def start_link(
    provider_id: str,
    body: SsoLinkStartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start linking the caller's account to a provider. The session must have proved the password (its ``amr``
    carries ``pwd``) and, when the account has a factor, the second factor (``mfa_at`` set), and the link is made
    under the account.second_factor step-up: a provider identity is a new way into the account."""
    api = _api()
    _refuse_temp(current_user)
    client_ip = api.get_client_ip(request)
    _limit_start(client_ip)
    claims = _session_claims(request)
    if "pwd" not in (claims.get("amr") or []):
        raise HTTPException(status_code=403, detail={
            "reason": "password_proof_required",
            "message": "Sign in with your password before adding a sign-in method."})
    from app.core.active_factors import active_factors
    if active_factors(db, current_user.id).any and not claims.get("mfa_at"):
        raise HTTPException(status_code=403, detail={
            "reason": "second_factor_proof_required",
            "message": "Sign in with your second factor before adding a sign-in method."})
    api._enforce_step_up(db, current_user, request, "account.second_factor")
    row = _provider(db, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": sso.reason_text(sso.PROVIDER_DISABLED)})
    if db.query(ExternalIdentity.id).filter(ExternalIdentity.provider_id == row.id,
                                            ExternalIdentity.user_id == current_user.id).first() is not None:
        raise HTTPException(status_code=409, detail={"reason": sso.NOT_THIS_ACCOUNT,
                                                     "message": "Your account is already linked to this provider."})
    from app.core import sign_in_lockout
    try:
        url = sso.start(row, purpose=sso_state.LINK, source=sign_in_lockout.source_of(client_ip), client_ip=client_ip,
                        verifier_hash=body.verifier_hash, user_id=current_user.id,
                        session_hash=api._current_session_hash(request))
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


def _session_claims(request) -> dict:
    """The current session's token claims (``amr``, ``mfa_at``), or an empty dict."""
    from app.core.security import verify_access_token
    try:
        auth = request.headers.get("Authorization") or ""
        if not auth.lower().startswith("bearer "):
            return {}
        return verify_access_token(auth.split(None, 1)[1].strip()) or {}
    except Exception:      # noqa: BLE001
        return {}


@router.delete("/users/me/identities/{identity_id}")
async def unlink_my_identity(
    identity_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove one of the caller's identities, under the account.second_factor step-up. Refused when the account
    signs in only through single sign-on and this is its last identity (it would lose its only way in)."""
    api = _api()
    _refuse_temp(current_user)
    api._enforce_step_up(db, current_user, request, "account.second_factor")
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.id == identity_id,
                                                 ExternalIdentity.user_id == current_user.id).first()
    if identity is None:
        raise HTTPException(status_code=404, detail="That identity was not found.")
    others = db.query(ExternalIdentity.id).filter(ExternalIdentity.user_id == current_user.id,
                                                  ExternalIdentity.id != identity.id).count()
    if getattr(current_user, "sso_only", False) and others == 0:
        raise HTTPException(status_code=409, detail=(
            "Your account signs in only through single sign-on, and this is its only identity. Ask an "
            "administrator for a password first."))
    row = _provider(db, identity.provider_id)
    provider_id = str(identity.provider_id)
    db.delete(identity)
    db.commit()
    _audit(db, "sso_identity_unlinked", user=current_user, ip=api.get_client_ip(request),
           details={"provider_id": provider_id, "identity_id": str(identity_id), "linked_by": "self"})
    label = (row.label or row.name) if row is not None else "an organisation provider"
    _tell_owner(db, current_user, row, "A sign-in method was removed from your account",
                f"You unlinked your account from {label}: it can no longer sign in through it.")
    return {"removed": True}
