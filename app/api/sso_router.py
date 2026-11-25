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

import asyncio
import contextvars
import logging
import threading
import types
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import text as sa_text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api.user_management_api import get_current_user, require_interactive_admin
from app.core import sso_state
from app.core.database import get_db
from app.core.models import ExternalIdentity, SsoProvider, User
from app.core import sso_only
from app.core import sso_policy
from app.services import oidc_client as oc
from app.services import sso_freshness
from app.services import sso_groups
from app.services import sign_in as _sign_in
from app.services import sso_sign_in as sso

router = APIRouter(tags=["Single sign-on"])
log = logging.getLogger("dockvault.sso")

START_LIMIT = 30                     # starts per address per START_WINDOW, beside the state store's abandoned cap
START_WINDOW = 300
LOGOUT_LIMIT = 600                 # back-channel logouts per source address and window, for each provider (and one
                                   # bucket for every id with no provider): signing many people out is not a person
BACKCHANNEL_CONCURRENCY = 4         # back-channel logouts in flight at once, per process: each from its
                                    # verification to the end of what it writes
BACKCHANNEL_WAIT_SECONDS = 5.0      # how long a logout waits for one of them before it is answered as failed (the
                                    # provider may send it again; the refusal is recorded)
_BACKCHANNEL_SLOTS = asyncio.Semaphore(BACKCHANNEL_CONCURRENCY)
# Every refused logout is answered 400, as the specification gives it (Back-Channel Logout 1.0: 2.6 for a token that
# fails validation, 2.8 for a logout that failed). The body tells the two apart, and never says why.
# These are the refusals that say the token itself is not valid (``invalid_request``): its signature, claims or
# issuer, or a signing key too short to trust, which verifies nothing however often the token is sent. A failure
# to reach the provider's discovery or keys, of the state store or of the vault is a failed logout
# (``logout_failed``): the token is not spent, and sent again it may end the sessions then.
LOGOUT_REFUSED = 400
TOKEN_REFUSALS = frozenset({oc.TOKEN_INVALID, oc.ISSUER_MISMATCH, oc.SIGNING_KEY_TOO_SHORT})


STEP_BUSY = "The vault is busy with this right now. Start it again in a moment."


def _start_the_step_again() -> HTTPException:
    """The busy answer of a route that claims a finished provider step (a link, a test, a confirmation): its
    one-time code is spent, so there is nothing to send again and no wait to count down."""
    return HTTPException(status_code=503, detail={"reason": sso.BUSY, "message": STEP_BUSY})


def _back_to_the_sign_in_page_as_busy():
    """The busy answer where the browser has come back from the provider: a navigation, so the sign-in page with
    the reason, never a page of JSON. The sign-in's state is spent: the person starts again there."""
    return _redirect("sso-error=" + sso.BUSY)


class _ProviderUnusable(Exception):
    """The provider's discovery could not be used: the logout failed, whatever the token says."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

FINISH_LIMIT = 30                    # handover claims per address per FINISH_WINDOW
FINISH_WINDOW = 300

# The provider's part of a start or a callback (discovery, the code exchange, the ID token's keys) runs off the event
# loop, in a pool of its own, so a provider that hangs holds neither the loop nor anything password sign-in uses. Before
# it waits, the request ends its database transaction (the wait holds no connection) and hands the worker a plain view
# of the provider row (a row of the request's session read from another thread would load through that session).
PROVIDER_WAIT_SECONDS = 20.0          # the longest a person waits for the provider's part of one request; past it the
                                      # answer is temporarily unavailable
PROVIDER_THREADS = 8                  # provider calls running at once, per process; beyond, temporarily unavailable
_provider_pool = ThreadPoolExecutor(max_workers=PROVIDER_THREADS, thread_name_prefix="sso-provider")
_provider_threads = threading.BoundedSemaphore(PROVIDER_THREADS)


def _provider_place_free() -> bool:
    """Whether a provider call could start now (a place taken and given back at once). The callback asks before it
    spends the login state, so a full pool answers with the state unspent; a place taken in between answers
    temporarily unavailable as any call does."""
    if not _provider_threads.acquire(blocking=False):
        return False
    _provider_threads.release()
    return True


async def _provider_call(fn, *args, deadline: float, **kwargs):
    """Run ``fn(*args, **kwargs)``, work that reaches the provider, in the provider pool, off the event loop; once
    ``deadline`` (the loop's clock) passes, :class:`oc.OidcError` ``temporarily_unavailable``. The call's place is
    given back when its work ends, or when it is cancelled before a thread took it up, never when the request stops
    waiting: a call that ran out of time is not stopped (a thread cannot be), so it keeps its place until its fetches
    end, and calls that outlive their request never queue the next ones. With every place taken, or no time left, the
    answer is immediate."""
    loop = asyncio.get_running_loop()
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "no time was left for the provider")
    places = _provider_threads
    if not places.acquire(blocking=False):
        log.warning("sso: every provider call is in use; answered temporarily unavailable")
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "every provider call is in use")
    ctx = contextvars.copy_context()
    try:
        work = _provider_pool.submit(ctx.run, fn, *args, **kwargs)
    except BaseException:
        places.release()
        raise
    work.add_done_callback(lambda _done: places.release())
    try:
        return await asyncio.wait_for(asyncio.wrap_future(work), timeout=remaining)
    except asyncio.TimeoutError:
        log.warning("sso: the provider did not answer within %s s; answered temporarily unavailable",
                    PROVIDER_WAIT_SECONDS)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "the provider did not answer in time") from None


def _provider_deadline() -> float:
    return asyncio.get_running_loop().time() + PROVIDER_WAIT_SECONDS


def _provider_view(row):
    """The provider row's columns as plain values, for the work that runs off the loop."""
    return types.SimpleNamespace(**{c.key: getattr(row, c.key, None) for c in SsoProvider.__mapper__.column_attrs})


def _release_database(db) -> None:
    """End the request's read transaction before it waits on the provider, so the wait holds no database connection
    (as the back-channel logout does): nothing is written before this point in these routes (the step-up receipt a
    link start consumes commits on its own), and the session takes a connection again for its next statement."""
    db.rollback()


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


def _provider_as_it_stands(db, provider_id) -> Optional[SsoProvider]:
    """The provider row as it is in the database now, held against a change until this request's transaction ends.

    A link is made after the provider's round trip: the person was away at the provider, or the callback waited
    for the provider's answer. What the row said before is not what a link is made on. An administrator who
    meanwhile turned the provider off, or changed whether its people hold a password, changed it for this link
    too; and a save that comes while the link is being made waits for it (the save, the state change and the
    removal take the row for themselves), so it settles this account with the others. What this session has
    pending is written first: the row is read again whole.

    A save of this provider that is under way holds the row, and settles every linked account before it commits.
    This read waits for it a short time only (PROVIDER_ROW_WAIT_MS, in place of the connection's own, longer
    wait): the routes that call it are answered on the server's one loop, and a wait here is a wait for every
    request. Still held after that, :class:`ProviderRowBusy`: nothing was written, and the person tries again.
    The transaction gets the wait it had back afterwards (read before), as sign_in.with_a_short_wait gives it."""
    try:
        pid = uuid.UUID(str(provider_id))
    except ValueError:
        return None
    db.flush()
    waits = _on_postgres(db)
    if waits:
        own = db.execute(sa_text("SELECT current_setting('lock_timeout')")).scalar()
        db.execute(sa_text("SELECT set_config('lock_timeout', :wait, true)"),
                   {"wait": f"{int(PROVIDER_ROW_WAIT_MS)}ms"})
    try:
        row = (db.query(SsoProvider).filter(SsoProvider.id == pid)
               .populate_existing().with_for_update(read=True).first())
    except OperationalError as held:
        if getattr(getattr(held, "orig", None), "pgcode", None) != LOCK_NOT_AVAILABLE:
            raise
        db.rollback()
        raise ProviderRowBusy() from None
    if waits:
        db.execute(sa_text("SELECT set_config('lock_timeout', :own, true)"), {"own": own})
    return row


# How long a link waits for a provider's row that a save of that provider holds, and the database's word for
# "still held" (lock_not_available).
PROVIDER_ROW_WAIT_MS = 500
LOCK_NOT_AVAILABLE = "55P03"


class ProviderRowBusy(Exception):
    """The provider's row was still held by a save of that provider after the short wait: the transaction was
    rolled back, nothing was linked."""


def _on_postgres(db) -> bool:
    try:
        return db.get_bind().dialect.name == "postgresql"
    except Exception:  # noqa: BLE001 -- a stand-in session of a test, or SQLite: no such setting there
        return False


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
    http = 404 if code == sso.PROVIDER_DISABLED else 503 if code in (oc.TEMPORARILY_UNAVAILABLE, sso.BUSY) else 409
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


def _refused_at_the_callback(db, login, row, code: str) -> RedirectResponse:
    """Where a refusal leaves the callback. A person's sign-in, link or confirmation goes back to the page with
    the reason. An administrator's test sign-in that did not pass goes back as a test's answer: what did not
    pass waits under a one-time code, as a test that passed does, for the tab that started it to claim. Claimed,
    it is written on the provider and recorded, and the administrator reads it where the test was run, in words
    for the one who can change the settings. With the reason alone the page showed a person's sentence
    ("contact your administrator") and the provider went on showing its last test."""
    if login is None or login.purpose != sso_state.TEST or row is None or not login.user_id:
        return _redirect("sso-error=" + code)
    try:
        tester = db.query(User).filter(User.id == uuid.UUID(str(login.user_id))).first()
        record = {"purpose": sso_state.TEST, "provider_id": login.provider_id, "user_id": login.user_id,
                  "session_hash": login.session_hash, "verifier_hash": login.verifier_hash,
                  # No identity answered: the record names the provider's issuer, and nobody.
                  "subject": "-", "issuer": (getattr(row, "issuer", None) or "-"),
                  "summary": sso.failed_test_summary(row, getattr(tester, "username", None) or "", code)}
        return _redirect("sso-test=" + sso_state.store_handover(record))
    except Exception as exc:  # noqa: BLE001 -- the refusal stands as a reason
        log.info("a failed test sign-in was not handed to its tab: %s", type(exc).__name__)
        return _redirect("sso-error=" + code)


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
    if not sso.invitation_takes_a_provider(inv):
        # Said before the person is sent to the provider: an administrator's invitation is accepted with the form.
        raise HTTPException(status_code=409, detail={"reason": sso.ADMINISTRATOR_INVITATION,
                                                     "message": sso.reason_text(sso.ADMINISTRATOR_INVITATION)})
    return inv


def _sign_in_fragment(handover_code: str, login) -> str:
    """What a sign-in's callback sends the browser back with: the one-time code, and where the page goes after."""
    fragment = f"sso={handover_code}"
    if login.return_to and login.return_to != sso_state.DEFAULT_RETURN_TO:
        fragment += "&return_to=" + login.return_to.lstrip("#")
    return fragment


def finish_invitation(db, handover, *, client_ip) -> None:
    """Accept the invitation a one-time sign-in code holds, now that the tab that started the sign-in has
    redeemed the code with its verifier (POST /auth/finish): the account made, its identity linked, the
    provider's groups applied and the invitation claimed, in one transaction; then what was done is recorded and
    told. ``handover`` then names the account, and is finished as any provider's sign-in.

    Nothing of this is written at the provider's callback: whoever reaches the callback may be anybody the
    starter sent the address to. The provider's row is read again as it stands and held, as at the callback: a
    provider turned off in the minute between makes no account. A refusal is raised as the route's answer, with
    the reason's sentence, and leaves nothing behind."""
    from sqlalchemy.exc import IntegrityError
    from app.core import sign_in_lockout
    from app.services import sign_in
    api = _api()
    invitation_id = handover.invitation["invitation_id"]
    purpose = sso_state.APP if handover.purpose == "app" else sso_state.SIGN_IN
    details = {"provider_id": handover.provider_id, "purpose": purpose}

    def refused(code: str, detail: str = "") -> HTTPException:
        db.rollback()
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure",
               details={**details, "reason": code, **({"refused_because": detail} if detail else {})})
        api._audit_accept_failure(db, _invitation_prefix(db, invitation_id), client_ip, reason=detail or code)
        return HTTPException(status_code=409, detail={"reason": code, "message": sso.reason_text(code)})
    try:
        row = _provider_as_it_stands(db, handover.provider_id)
    except ProviderRowBusy:
        raise HTTPException(status_code=503, headers={"Retry-After": str(sign_in_lockout.BUSY_RETRY_SECONDS)}, detail={
            "reason": oc.TEMPORARILY_UNAVAILABLE,
            "message": "This provider's settings are being saved. Open the invitation again in a moment."})
    why = sso.usable_for(row, purpose) if row is not None else sso.PROVIDER_DISABLED
    if why is not None:
        raise refused(why)
    answer = sso.answer_of_an_invitation(handover.invitation)
    try:
        found = sso.accept_invitation(db, row, answer, invitation_id)
        applied = sso_groups.apply(db, row, found.user, answer)
        db.commit()
    except sso.Refusal as exc:
        raise refused(exc.code, exc.detail)
    except IntegrityError:
        raise refused(sso.INVITATION_UNUSABLE, "commit_conflict")
    _record_resolution(db, row, found, client_ip=client_ip, details=details)
    sso_groups.tell(db, row, found.user, applied, client_ip=client_ip)
    handover.user_id, handover.ended, handover.invitation = str(found.user.id), sign_in.as_read(found.user), None


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
    view = _provider_view(row)
    _release_database(db)
    try:
        url = await _provider_call(sso.start, view, purpose=purpose,
                                   source=sign_in_lockout.source_of(client_ip), client_ip=client_ip,
                                   verifier_hash=body.verifier_hash, code_challenge=body.code_challenge,
                                   return_to=body.return_to, extras=extras, deadline=_provider_deadline())
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


@router.get("/auth/sso/reasons")
async def sign_in_reasons():
    """PUBLIC: every reason the callback can send the sign-in page in its ``#sso-error=<reason>`` fragment, with
    the words the page shows for it. The page shows these and never a provider's own text."""
    return {"reasons": dict(sso.REASON_TEXTS)}


def _logged_error(error) -> str:
    """What the callback's ``error`` parameter is logged as. Anyone can send it (the callback has no session), so
    only a value shaped like an error code of the protocol (``access_denied``, ``login_required``) is written;
    anything else is named, never copied, and no text a caller chose reaches a log line."""
    import re
    if error is None:
        return "no code"
    return error if isinstance(error, str) and re.fullmatch(r"[a-z_]{1,40}", error) else "unrecognised"


@router.get("/auth/sso/{provider_id}/callback")
@_sign_in.after_a_spent_code_busy_is(_back_to_the_sign_in_page_as_busy)
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
    if not _provider_place_free():
        return _redirect("sso-error=" + oc.TEMPORARILY_UNAVAILABLE)       # the state is not spent: a reload may finish
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
        log.info("sso callback error for provider %s: %s", login.provider_id, _logged_error(error))
        return _refused_at_the_callback(db, login, row, oc.PROVIDER_ERROR)
    why = sso.usable_for(row, login.purpose)
    if why is not None:
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": why})
        return _refused_at_the_callback(db, login, row, why)
    # RFC 9207: a provider that advertises the iss parameter must send it, and it must be the issuer; one that
    # does not advertise it is held to it whenever it does send it.
    # The provider's part, off the event loop, bounded together.
    view = _provider_view(row)
    _release_database(db)
    deadline = _provider_deadline()
    try:
        discovery = await _provider_call(lambda: oc.discover(sso.provider_config(view)), deadline=deadline)
    except (sso.Refusal, oc.OidcError) as exc:
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": exc.code})
        return _refused_at_the_callback(db, login, row, exc.code)
    if (iss is not None and iss != view.issuer) or (iss is None and discovery.iss_in_callback):
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": oc.ISSUER_MISMATCH})
        return _refused_at_the_callback(db, login, row, oc.ISSUER_MISMATCH)
    try:
        answer = await _provider_call(sso.verified_answer, view, login, code=code, deadline=deadline)
    except (sso.Refusal, oc.OidcError) as exc:
        log.info("sso callback refused for provider %s: %s", login.provider_id, exc)
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": exc.code})
        return _refused_at_the_callback(db, login, row, exc.code)
    # The provider's answer took its time (up to the whole wait). The row is read again as it stands, and held:
    # a provider turned off meanwhile, by an administrator or by a change to its connection, links nobody, makes
    # no account and applies no password rule on the strength of an answer it gave before.
    try:
        row = _provider_as_it_stands(db, login.provider_id)
    except ProviderRowBusy:
        # A save of this provider is under way and holds its row: nothing was written, the person starts again.
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure",
               details={**details, "reason": oc.TEMPORARILY_UNAVAILABLE})
        return _refused_at_the_callback(db, login, row, oc.TEMPORARILY_UNAVAILABLE)
    why = sso.usable_for(row, login.purpose) if row is not None else sso.PROVIDER_DISABLED
    if why is not None:
        db.rollback()
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": why})
        return _refused_at_the_callback(db, login, row, why)
    # The provider's restriction (tenant, domain, group, the sign-up domain list) is judged before who the person
    # is, known identity included; a test reports it instead of refusing.
    if login.purpose != sso_state.TEST:
        try:
            sso.restriction_refusal(db, row, answer)
        except sso.Refusal as exc:
            if exc.code == sso_policy.RESTRICTED:
                # Proof from the provider (a verified token whose claim leaves the person out), never a missing claim
                # or an overage marker: a known identity's access ends when the provider's policy says so.
                try:
                    sso_freshness.end_access_on_refusal(db, row, answer, client_ip=client_ip)
                except Exception as end_exc:  # noqa: BLE001 -- the refusal stands; the failure is said
                    db.rollback()
                    log.error("sso refusal could not end access for provider %s: %s", login.provider_id,
                              type(end_exc).__name__)
            _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": exc.code})
            return _refused_at_the_callback(db, login, row, exc.code)

    if login.purpose in (sso_state.SIGN_IN, sso_state.APP):
        invitation_id = login.extras.get("invitation_id") if isinstance(login.extras, dict) else None
        # An invitation is the choice of whoever started this sign-in, and the browser that reaches this callback
        # proves nothing about who that was (a start URL can be handed to anyone). So for an invitation nothing
        # is written here: it is judged, and what the provider said waits under the one-time code until the tab
        # that started the sign-in redeems it with its verifier. Written here, the account an invited person
        # named was bound to whoever at the provider opened that person's start address, with that colleague's
        # departments. A person the vault already knows signs in as themselves, the invitation untouched.
        holds_invitation = bool(invitation_id) and sso.known_identity(db, row, answer) is None
        try:
            if holds_invitation:
                sso.judge_invitation(db, row, answer, invitation_id)
                found = None
            else:
                found = sso.resolve_account(db, row, answer)
        except sso.Refusal as exc:
            db.rollback()          # nothing of a refused resolution may ride on the audit row's commit
            # A refusal that met an account of the vault (a linked identity whose account is turned off, an
            # address that is an account's) is that account's failed sign-in, and is recorded under it, as a
            # wrong password for it is: an administrator who looks for the person finds who tried to come in as
            # them. One that met nobody (no account, an address nobody holds) names nobody.
            _audit(db, "sso_sign_in_refused", user=exc.about, ip=client_ip, status_="failure",
                   details={**details, "reason": exc.code,
                            **({"refused_because": exc.detail} if exc.detail else {})})
            if invitation_id:
                api._audit_accept_failure(db, _invitation_prefix(db, invitation_id), client_ip,
                                          reason=exc.detail or exc.code)
            _tell_of_a_sign_in_kept_out(db, row, exc)
            return _refused_at_the_callback(db, login, row, exc.code)
        from app.core import sign_in_codes
        if holds_invitation:
            try:
                handover_code = sign_in_codes.store(sso.held_invitation(
                    row, answer, invitation_id=invitation_id, provider_id=login.provider_id, client_ip=client_ip,
                    began_at=sso_state.began_at(login), verifier_hash=login.verifier_hash,
                    code_challenge=login.code_challenge,
                    purpose="app" if login.purpose == sso_state.APP else "sign_in"))
            except sign_in_codes.Unavailable:
                return _refused_at_the_callback(db, login, row, oc.TEMPORARILY_UNAVAILABLE)
            db.rollback()          # nothing was written, and nothing is until the code is redeemed
            return _redirect(_sign_in_fragment(handover_code, login))
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
                return _refused_at_the_callback(db, login, row, code_)
            if found.created or found.linked_now:
                _record_resolution(db, row, found, client_ip=client_ip, details=details)
        sso_groups.tell(db, row, user, applied, client_ip=client_ip)
        result = sso.pipeline_result(db, row, user, answer, provider_id=login.provider_id, client_ip=client_ip,
                                     identity=found.identity, began_at=sso_state.began_at(login))
        try:
            handover_code = sign_in_codes.store(sign_in_codes.from_result(
                result, verifier_hash=login.verifier_hash, code_challenge=login.code_challenge,
                purpose="app" if login.purpose == sso_state.APP else "sign_in"))
        except sign_in_codes.Unavailable:
            return _refused_at_the_callback(db, login, row, oc.TEMPORARILY_UNAVAILABLE)
        db.commit()        # a tenant learnt at this sign-in; the identity's last sign-in is stamped by the finish
        return _redirect(_sign_in_fragment(handover_code, login))

    # A link and a test belong to the signed-in account and tab that started them. The browser that reaches this
    # callback proves nothing about that (a start URL can be handed to anyone), so nothing is linked or written
    # here: what the provider said waits under a one-time code, and the tab that started the flow claims it with
    # its session and its verifier (POST /users/me/identities/finish, POST /admin/sso/providers/{id}/test/finish).
    user = db.query(User).filter(User.id == uuid.UUID(login.user_id)).first() if login.user_id else None
    if not sso.account_usable(user):
        _audit(db, "sso_sign_in_refused", ip=client_ip, status_="failure", details={**details, "reason": sso.ACCOUNT_DISABLED})
        return _refused_at_the_callback(db, login, row, sso.ACCOUNT_DISABLED)
    if login.purpose not in (sso_state.LINK, sso_state.TEST, sso_state.STEP_UP) or not login.verifier_hash \
            or not login.session_hash:
        _audit(db, "sso_sign_in_refused", user=user, ip=client_ip, status_="failure",
               details={**details, "reason": sso.PURPOSE_NOT_READY})
        return _refused_at_the_callback(db, login, row, sso.PURPOSE_NOT_READY)
    if login.purpose == sso_state.STEP_UP:
        # A fresh sign-in of the account's own identity, within the minute, with the provider's MFA when trusted.
        try:
            sso.reauth_refusal(db, row, user, answer)
        except sso.Refusal as exc:
            _audit(db, "sso_sign_in_refused", user=user, ip=client_ip, status_="failure",
                   details={**details, "reason": exc.code, "step_up": login.step_up_action})
            # Where it was to confirm an unlink, the person is told what to do when the provider cannot confirm
            # them at all (the record keeps the refusal's own reason).
            shown = (sso.said_for_an_unlink(exc.code) if login.step_up_action == sso.UNLINK_CONFIRMATION
                     else exc.code)
            return _refused_at_the_callback(db, login, row, shown)
        if not login.step_up_action:
            return _refused_at_the_callback(db, login, row, sso.PURPOSE_NOT_READY)
    if login.purpose == sso_state.LINK:
        # Refusals that need no claim are given now, so the person is told at once. First that the provider did
        # sign the person in for this link, where it says when it did.
        try:
            sso.link_freshness_refusal(row, answer)
            sso.link_refusal(db, row, user, answer)
        except sso.Refusal as exc:
            _audit(db, "sso_sign_in_refused", user=user, ip=client_ip, status_="failure",
                   details={**details, "reason": exc.code})
            return _refused_at_the_callback(db, login, row, exc.code)
    record = {"purpose": login.purpose, "provider_id": login.provider_id, "user_id": login.user_id,
              "session_hash": login.session_hash, "verifier_hash": login.verifier_hash, **sso.answer_record(answer)}
    if login.purpose == sso_state.TEST:
        record["summary"] = sso.test_summary(db, row, answer, user, tested=view)
    if login.purpose == sso_state.STEP_UP:
        record["step_up_action"] = login.step_up_action
    try:
        handover = sso_state.store_handover(record)
    except sso_state.Unavailable:
        return _refused_at_the_callback(db, login, row, oc.TEMPORARILY_UNAVAILABLE)
    fragment = {sso_state.LINK: "sso-linked=", sso_state.TEST: "sso-test=", sso_state.STEP_UP: "sso-stepup="}[login.purpose]
    return _redirect(fragment + handover)


def _note_refused_logout(db, scope: str, source: str, client_ip, *, reason: str) -> None:
    """A known provider's logout refused before it was verified (the limiter, every slot busy) is recorded at most
    once per window for each provider and source address, so a dropped logout leaves a trace (another source's flood
    does not use it up) without letting a flood write a row per request. Nothing is written when the limiter that
    counts these cannot be asked."""
    from app.core.rate_limiter import rate_limiter as _rl
    try:
        allowed, _, _reset = _rl.check_rate_limit(identifier=f"{scope}:{source}", limit=1, window=START_WINDOW,
                                                  prefix="sso_backchannel_refused", fail_open=False)
    except Exception:  # noqa: BLE001
        return
    if allowed:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": reason})


def _a_session_is_live(db, session_ids) -> bool:
    """Whether a session among ``session_ids`` is still not revoked (True when that cannot be read)."""
    from app.core.models import ActiveSession
    try:
        return db.query(ActiveSession.id).filter(ActiveSession.id.in_(list(session_ids)),
                                                 ActiveSession.revoked == False).first() is not None  # noqa: E712
    except Exception:  # noqa: BLE001
        db.rollback()
        return True


def _end_what_came_through(db, account, identity) -> int:
    """End the sessions that came through ``identity`` (its provider and its subject) and spend the sign-ins of
    ``account`` under way, in the caller's transaction. Returns how many sessions ended. Raises when it cannot:
    the unlink then fails as a whole, and nothing stays signed in through an identity that is gone."""
    from app.core.models import PendingLogin, SsoSession
    api = _api()
    query = db.query(SsoSession).filter(SsoSession.provider_id == identity.provider_id,
                                        SsoSession.idp_sub == identity.subject)
    named = [s.session_id for s in query.all()]
    ended = 0
    if named:
        for owner in _owners_of(db, named):
            api._sessions_turn(db, owner)
        session_ids = [s.session_id for s in query.all()]
        if session_ids:
            ended = int(api._revoke_sessions(db, session_ids=session_ids, actor_username=account.username,
                                             durable=True) or 0)
    from app.services import sign_in
    sign_in.spend_sign_ins_under_way(db, account.id)      # and a set-up begun at one of them, left half-way
    return ended


def _sessions_by_owner(db, session_ids, owners) -> dict:
    """How many of ``session_ids`` are each account's and not ended yet (what the logout is about to end), as
    ``{account id: count}``; every account in ``owners`` is there, with 0 when the token named the person and none
    of their sessions was open. A session a renewal has replaced is ended already, and is not counted."""
    counts = {str(owner): 0 for owner in owners}
    if session_ids:
        from app.core.models import ActiveSession
        for row in db.query(ActiveSession).filter(ActiveSession.id.in_(list(session_ids))).all():
            counts.setdefault(str(row.user_id), 0)
            if not getattr(row, "revoked", False):
                counts[str(row.user_id)] += 1
    return counts


def _owners_of(db, session_ids) -> list:
    """The accounts the given sessions belong to, in one order always (two logouts that name the same accounts take
    their turns the same way round)."""
    if not session_ids:
        return []
    from app.core.models import ActiveSession
    rows = db.query(ActiveSession).filter(ActiveSession.id.in_(list(session_ids))).all()
    return sorted({str(row.user_id) for row in rows})


def _end_what_a_logout_names(db, row_id, scope, claims, client_ip):
    """The database's part of a provider's logout, once its token is verified: the provider's row taken, what the
    token names remembered as logged out, each named account's turn taken, the sessions ended and the commit; and
    the route's answer. A function of its own, called in the thread pool (it waits for locks)."""
    api = _api()
    from app.core.models import SsoSession
    invalid = JSONResponse(status_code=LOGOUT_REFUSED, content={"error": "invalid_request"})
    failed = JSONResponse(status_code=LOGOUT_REFUSED, content={"error": "logout_failed"})
    # The session id in the form the sign-in kept it in (a long one as its hash), so the two meet.
    sid, sub = sso.kept_sid(claims.get("sid")), claims.get("sub")
    query = db.query(SsoSession).filter(SsoSession.provider_id == row_id)
    if isinstance(sid, str) and sid:
        query, by = query.filter(SsoSession.idp_sid == sid), "sid"
    elif isinstance(sub, str) and sub:
        query, by = query.filter(SsoSession.idp_sub == sub), "sub"
    else:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "no_identifier"})
        return invalid
    session_ids = []
    try:
        # The provider's row for this logout, first (it stands before the accounts' turns in the order of the
        # locks, app/services/sign_in.py). A sign-in through this provider that is being written holds the row
        # shared until it commits: the logout comes wholly after it, and ends the session it wrote, or wholly
        # before it, and the sign-in finds the provider's session logged out. The key is left free, so a row that
        # only refers to the provider waits for nothing.
        if db.query(SsoProvider).filter(SsoProvider.id == row_id).with_for_update(key_share=True).first() is None:
            db.rollback()
            return invalid                 # removed since the token came in: its sessions went with it
        # A sign-in held for a further step, or waiting in its handover code, carries the provider's session
        # and the person, and would record them on a new vault session that no later logout names. What the
        # token names (the session, else the person) is remembered as logged out now, for as long as such a
        # sign-in can last: one begun before this moment is refused where it is written, and
        # one it answers after is a new sign-in.
        if by == "sid":
            sso_state.note_logged_out(scope=scope, sid=sid)
        else:
            sso_state.note_logged_out(scope=scope, sub=sub)
        # Whose sessions the token names, then, under each of those accounts' turn at its sessions, which sessions.
        # A renewal ("Stay signed in") moves the provider's session to its new session row under the same turn, so
        # the read made under it sees a renewal wholly done or not begun: the live session is among those ended.
        # The person the token names takes a turn too, with or without a session yet.
        named = [s.session_id for s in query.all()]
        owners = set(_owners_of(db, named))
        person = None
        if isinstance(sub, str) and sub:
            person = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row_id,
                                                       ExternalIdentity.subject == sub).first()
            if person is not None:
                owners.add(str(person.user_id))
        for owner in sorted(owners):
            api._sessions_turn(db, owner)
        session_ids = [s.session_id for s in query.all()]
        # Whose each of them is, for the record: read while the turns are held, like the sessions themselves.
        sessions_of = _sessions_by_owner(db, session_ids, owners)
        ended = api._revoke_sessions(db, session_ids=session_ids, actor_username="provider logout",
                                     durable=True) if session_ids else 0
    except Exception as exc:  # noqa: BLE001 -- nothing was applied: the token is not spent, so the provider's retry works
        db.rollback()
        sso_state.forget_logout_jti(claims.get("jti"), scope=scope)
        log.warning("sso back-channel logout not applied: %s", type(exc).__name__)
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "revocation_failed"})
        return failed
    try:
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        # A failed commit may still have reached the database. The token is forgotten (so the provider's retry is
        # honoured) when a session it named is still live, or when that cannot be read: ending sessions is the safer
        # side, though a retry naming only a subject could then also end a session opened after this logout.
        if session_ids and _a_session_is_live(db, session_ids):
            sso_state.forget_logout_jti(claims.get("jti"), scope=scope)
        log.warning("sso back-channel logout commit failed: %s", type(exc).__name__)
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "revocation_failed"})
        return failed
    # Recorded for each account the token named, with how many of its sessions ended: an administrator who looks
    # for the person finds that their provider signed them out. One row said only how many sessions ended, of
    # nobody's. A token that named nobody here leaves that one row.
    accounts = {str(u.id): u for u in db.query(User).filter(User.id.in_([uuid.UUID(o) for o in sessions_of])).all()} \
        if sessions_of else {}
    for owner, count in sorted(sessions_of.items()):
        if owner in accounts:
            _audit(db, "sso_backchannel_logout", user=accounts[owner], ip=client_ip,
                   details={"provider_id": scope, "by": by, "sessions": count})
    if not accounts:
        _audit(db, "sso_backchannel_logout", ip=client_ip, details={"provider_id": scope, "by": by, "sessions": ended})
    return JSONResponse(status_code=200, content={})


@router.post("/auth/sso/{provider_id}/backchannel-logout")
async def backchannel_logout(provider_id: str, request: Request, db: Session = Depends(get_db)):
    """Where the provider says a person signed out of it (OpenID Connect back-channel logout, a form with
    ``logout_token``): the token is verified as an ID token with the logout event, honoured once by its id, and the
    vault sessions it names (by the provider's session id, else by the subject) are ended, those and no others.
    200 on success. Every refusal is 400, as the specification gives it (Back-Channel Logout 1.0: 2.6 for a token
    that fails validation, 2.8 for a logout that failed; it names no other status for either), with a body that
    tells the two apart and never says why: ``{"error": "invalid_request"}`` for a token that is not valid, and
    ``{"error": "logout_failed"}`` when the vault could not act on a token (the limiter, the store, the provider's
    discovery or keys out of reach, the sessions not ended). A token the vault could not act on is not spent: sent
    again, it ends the sessions then. Why a logout was refused is in its record (the reason), for an
    administrator. Every answer carries ``Cache-Control: no-store``, as the specification asks: the server sets it
    on every answer of the API, and the route's tests hold each of its answers to it."""
    api = _api()
    client_ip = api.get_client_ip(request)
    from app.core import sign_in_lockout
    from app.core.models import SsoSession
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    invalid = JSONResponse(status_code=LOGOUT_REFUSED, content={"error": "invalid_request"})
    failed = JSONResponse(status_code=LOGOUT_REFUSED, content={"error": "logout_failed"})
    source = sign_in_lockout.source_of(client_ip)
    # Everything this route needs from the provider's row, read at once; the connection then goes back to the pool,
    # before the body is read or anything waits, and the rest of the request takes another.
    row = _provider(db, provider_id)
    scope = str(row.id) if row is not None else None
    row_id = row.id if row is not None else None
    usable = row is not None and getattr(row, "kind", None) == "oidc" and sso.policy_of(row)["sso_backchannel_logout"]
    provider, unreadable = None, None
    if usable:
        try:
            provider = sso.provider_config(row)
        except sso.Refusal as exc:
            unreadable = exc.code
    db.rollback()
    try:
        # A bucket per source for each provider, and one per source for every id with no provider behind it: a stream
        # of made-up ids gets no buckets of its own and does not spend a real provider's.
        allowed, _, _reset = _rl.check_rate_limit(
            identifier=f"{source}:{scope or 'unknown'}", limit=LOGOUT_LIMIT,
            window=START_WINDOW, prefix="sso_backchannel", fail_open=False)
    except RateLimiterUnavailable:
        allowed = False
    if not allowed:
        if scope is not None:
            _note_refused_logout(db, scope, source, client_ip, reason="rate_limited")
        return failed
    if row_id is None:
        return invalid                     # no provider by that id: nothing to record (the address is anyone's to type)
    try:
        form = await request.form()
        token = form.get("logout_token")
    except Exception:  # noqa: BLE001
        token = None
    if not usable or not isinstance(token, str) or not token:
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": "not_accepted"})
        return invalid
    if unreadable is not None:
        # The vault cannot read its own configuration of the provider: the logout failed, not the token.
        _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
               details={"provider_id": scope, "reason": unreadable})
        return failed
    try:
        await asyncio.wait_for(_BACKCHANNEL_SLOTS.acquire(), timeout=BACKCHANNEL_WAIT_SECONDS)
    except asyncio.TimeoutError:
        _note_refused_logout(db, scope, source, client_ip, reason="busy")
        return failed

    def verify():
        # The provider's discovery and keys are fetched over the network: in the thread pool, not on the event loop.
        try:
            discovery = oc.discover(provider, fetch=oc.fetch_json)
        except oc.OidcError as exc:
            raise _ProviderUnusable(exc.code) from exc
        return oc.verify_logout_token(provider, discovery, token, fetch=oc.fetch_json,
                                      seen_jti=lambda jti, ttl: sso_state.seen_logout_jti(jti, ttl, scope=scope))
    from starlette.concurrency import run_in_threadpool
    try:
        try:
            claims = await run_in_threadpool(verify)
        except _ProviderUnusable as exc:
            _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
                   details={"provider_id": scope, "reason": exc.code})
            return failed
        except sso_state.Unavailable:
            _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
                   details={"provider_id": scope, "reason": "store_unavailable"})
            return failed
        except oc.OidcError as exc:
            _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
                   details={"provider_id": scope, "reason": exc.code})
            return invalid if exc.code in TOKEN_REFUSALS else failed
        except Exception as exc:  # noqa: BLE001 -- anything else (a key the library cannot read): the logout failed
            log.warning("sso back-channel logout not verified: %s", type(exc).__name__)
            _audit(db, "sso_backchannel_logout", ip=client_ip, status_="failure",
                   details={"provider_id": scope, "reason": "verification_error"})
            return failed
        # What the token names is ended off the server's loop, and still in the slot. Each account's turn,
        # and the provider's row, are waited for as long as the connection waits for any lock: a provider
        # rarely sends a logout twice, so this is never answered as busy for a wait of its own. The logouts of
        # one provider take its row one after another, each holding a thread and a connection while it
        # waits. Given the slot back before this part, a burst of them behind a row that a save held took
        # every thread the server answers its other requests with, and those stood still until the burst
        # had drained. In the slot, no more of them wait at once than BACKCHANNEL_CONCURRENCY; the rest wait
        # for a slot on the loop, holding nothing, and are answered as a failed logout when none comes.
        return await run_in_threadpool(_end_what_a_logout_names, db, row_id, scope, claims, client_ip)
    finally:
        _BACKCHANNEL_SLOTS.release()


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
    # The confirmation of an unlink is staged the same way and stands in for no password: any account with an
    # identity on the provider may give it.
    confirms_unlink = body.action == sso.UNLINK_CONFIRMATION
    if not confirms_unlink and not acts.is_step_up_action(body.action):
        raise HTTPException(status_code=404, detail="Unknown action.")
    client_ip = api.get_client_ip(request)
    _limit_start(client_ip)
    if not confirms_unlink and not sso.reauth_permitted(db, current_user, body.action):
        # Nothing is started and no state is made for a step this account answers with its own password.
        raise HTTPException(status_code=403, detail={"reason": "password_required", "message": sso.REAUTH_NOT_FOR_THIS})
    row = _provider(db, provider_id)
    if row is None or not sso.reauth_offered(row):
        raise HTTPException(status_code=404, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": "This provider cannot confirm you for a step-up."})
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id,
                                                 ExternalIdentity.user_id == current_user.id).first()
    if identity is None:
        raise HTTPException(status_code=404, detail="Your account has no identity on this provider.")
    from app.core import sign_in_lockout
    view, user_id, login_hint = _provider_view(row), current_user.id, identity.email_at_link or None
    session_hash = api._current_session_hash(request)
    _release_database(db)
    try:
        url = await _provider_call(
            sso.start, view, purpose=sso_state.STEP_UP, source=sign_in_lockout.source_of(client_ip), client_ip=client_ip,
            verifier_hash=body.verifier_hash, user_id=user_id, session_hash=session_hash,
            step_up_action=body.action, reauthenticate=True, login_hint=login_hint, deadline=_provider_deadline())
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


@router.post("/users/me/identities/reauth/finish")
@_sign_in.after_a_spent_code_busy_is(_start_the_step_again)
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
        raise _code_refused()
    if action != sso.UNLINK_CONFIRMATION and not sso.reauth_permitted(db, current_user, action):
        raise HTTPException(status_code=403, detail={"reason": "password_required", "message": sso.REAUTH_NOT_FOR_THIS})
    if not sso.reauth_stands(db, current_user, record["provider_id"], record.get("subject")):
        # Turned off, or the account unlinked from it, while the person was at the provider.
        raise HTTPException(status_code=409, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": sso.reason_text(sso.PROVIDER_DISABLED)})
    try:
        sso_state.stage_reauth(record["session_hash"], action, record["provider_id"], record.get("subject"))
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
           details={"provider_id": details.get("provider_id"), "linked_by": found.linked_by,
                    "identity_id": str(getattr(found.identity, "id", "") or ""),
                    "made_sso_only": bool(found.password_stopped)})
    if found.linked_by == sso.LINKED_BY_EMAIL:
        _tell_owner(db, user, row, "A sign-in method was added",
                    f"Single sign-on with {label} was linked to your account by a sign-in with your verified email address."
                    + (PASSWORD_STOPPED.format(label=label) if found.password_stopped else ""))
        # A link nobody at the vault asked for: the administrators are told of each, as of an account made at a
        # first sign-in.
        try:
            admins = [str(a.id) for a in api._active_admins(db)]
            api._notify_users(admins, "account_changed", title="An account was linked to single sign-on by its email address",
                              body=(f"{user.username} was linked to {label} by a sign-in there with the account's email "
                                    "address. From now on that identity signs in to the account. Check the Users page if "
                                    "you did not expect this."),
                              target="#users")
        except Exception as exc:  # noqa: BLE001
            log.info("sso link-by-email notices skipped: %s", type(exc).__name__)


# What an owner is told when a link made their account sign in only through the provider.
PASSWORD_STOPPED = (" {label} signs its people in without a vault password, so your password and SFTP password "
                    "sign-in no longer work: you sign in through {label} from now on.")


CODE_REFUSED = "code_refused"
CODE_REFUSED_WORDS = "This did not come back to the tab and session that started it. Start again."


def _code_refused() -> HTTPException:
    """The one refusal of a code a signed-in page claims (a link, a test sign-in, a confirmation). Answered 409
    with its reason, never 401: the page takes a 401 for the end of its session and signs the person out, and
    this says nothing about the session. A session renewed while the person was at the provider, or a code that
    ran out on a slow load, is refused here, and the person, who is signed in, starts the link again."""
    return HTTPException(status_code=409, detail={"reason": CODE_REFUSED, "message": CODE_REFUSED_WORDS})


def _claim_handover(db, request, current_user, body: SsoHandoverFinishRequest, *, purpose: str):
    """The record a handover code stands for, when this tab and session may claim it: the code is spent whatever
    follows; the verifier must hash to the one the start kept; the account and the session must be the ones
    that started it. One refusal for every miss (:func:`_code_refused`)."""
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
    refused = _code_refused()
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
@_sign_in.after_a_spent_code_busy_is(_start_the_step_again)
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
    # An account held to its provider's sign-in adds no other way in: from a session a password made before the
    # hold, a link to another provider would let the person back in without the provider that asks for them.
    due = sso_freshness.held_to_a_provider(db, current_user)
    if due is not None:
        raise HTTPException(status_code=409, detail={"reason": "sso_sign_in_due",
                                                     "message": sso_freshness.way_in_text(db, due)})
    client_ip = api.get_client_ip(request)
    record = _claim_handover(db, request, current_user, body, purpose=sso_state.LINK)
    try:
        row = _provider_as_it_stands(db, record["provider_id"])  # as it stands now, held until the link is written
    except ProviderRowBusy:
        raise HTTPException(status_code=503, detail={
            "reason": oc.TEMPORARILY_UNAVAILABLE,
            "message": "This provider's settings are being saved. Start the link again in a moment."})
    if row is None or sso.usable_for(row, sso_state.LINK) is not None:
        raise HTTPException(status_code=409, detail={"reason": sso.PROVIDER_DISABLED,
                                                     "message": sso.reason_text(sso.PROVIDER_DISABLED)})
    answer = sso.answer_from_record(record)
    from sqlalchemy.exc import IntegrityError
    # The account as this transaction holds it: the link may also end its password (a provider whose people hold
    # none), and that is written with the link or not at all.
    account = db.query(User).filter(User.id == current_user.id).first() or current_user
    try:
        # The account's turn before its flag is read: what the link ends is told from the flag as it is committed.
        sso.decide_in_the_accounts_turn(db, account)
        had_password = not getattr(account, "sso_only", False)
        # Where the link ends the account's password, the sessions the password made end with it; not this one,
        # in which the person has just proved themselves at the provider.
        from app.core.models import ActiveSession
        from app.core.session_hash_utils import hash_session_token
        named = _session_claims(request).get("session_token")
        this_session = (db.query(ActiveSession.id).filter(
            ActiveSession.session_token == hash_session_token(named)).scalar() if named else None)
        identity = sso.link_identity(db, row, account, answer, linked_by="self", keep_session=this_session)
        password_stopped = had_password and bool(getattr(account, "sso_only", False))
        db.commit()
    except (sso.Refusal, IntegrityError) as exc:
        db.rollback()
        code = exc.code if isinstance(exc, sso.Refusal) else sso.ALREADY_LINKED      # a second writer got there first
        _audit(db, "sso_sign_in_refused", user=current_user, ip=client_ip, status_="failure",
               details={"provider_id": str(row.id), "purpose": sso_state.LINK, "reason": code})
        if code == sso.BUSY:
            # The account's turn was held: a change of the account was being written. Nothing was linked. The
            # one-time code this request came with is spent, so no Retry-After is sent: sending the same request
            # again could not work, and the sentence says to start the link again.
            raise HTTPException(status_code=503, detail={"reason": code, "message": (
                "Your account is being changed right now. Start the link again in a moment.")})
        raise HTTPException(status_code=409, detail={"reason": code, "message": sso.reason_text(code)})
    _audit(db, "sso_identity_linked", user=current_user, ip=client_ip,
           details={"provider_id": str(row.id), "purpose": sso_state.LINK, "identity_id": str(identity.id),
                    "linked_by": "self", "made_sso_only": bool(password_stopped)})
    label = row.label or row.name
    who = sso.identity_shown(identity)
    _tell_owner(db, current_user, row, "A sign-in method was added to your account",
                f"You linked your account to {label}{' as ' + who if who else ''}: it can now sign in through it."
                + (PASSWORD_STOPPED.format(label=label) if password_stopped else ""))
    answer = {"linked": True, "identity": _identity_public(identity, row)}
    if password_stopped:
        answer["password_stopped"] = True
    return answer


@router.post("/admin/sso/providers/{provider_id}/test/start")
async def start_test(
    provider_id: str,
    body: SsoLinkStartRequest,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Start a test sign-in at a provider whose connection is filled in, whatever its state: the administrator signs
    in at the provider in this browser, and the callback hands what the provider sent to the tab that started it
    (``POST .../test/finish``). Nobody is signed in or linked, and nothing changes but the summary on the provider's
    row. Asks no step-up: a test is how an administrator finds out, before anything is turned on."""
    from app.services import sso_providers
    api = _api()
    client_ip = api.get_client_ip(request)
    _limit_start(client_ip)
    row = _provider(db, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Unknown provider.")
    if not sso_providers.configured(row):
        raise HTTPException(status_code=409, detail={
            "reason": sso_providers.NOT_CONFIGURED,
            "message": "Enter the issuer, the client id and the client secret first."})
    why = sso.usable_for(row, sso_state.TEST)
    if why is not None:
        raise _refused_start(sso.Refusal(why))
    from app.core import sign_in_lockout
    view, user_id, session_hash = _provider_view(row), current_user.id, api._current_session_hash(request)
    _release_database(db)
    try:
        url = await _provider_call(sso.start, view, purpose=sso_state.TEST, source=sign_in_lockout.source_of(client_ip),
                                   client_ip=client_ip, verifier_hash=body.verifier_hash, user_id=user_id,
                                   session_hash=session_hash, deadline=_provider_deadline())
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


@router.post("/admin/sso/providers/{provider_id}/test/finish")
@_sign_in.after_a_spent_code_busy_is(_start_the_step_again)
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
    row.last_test = sso.keeping_what_a_passing_test_established(record.get("summary") or {}, row.last_test)
    db.commit()
    outcome = str((row.last_test or {}).get("outcome") or "")
    passed = outcome == "ok"
    # A test that did not pass is recorded as one: who ran it, and the reason.
    _audit(db, "sso_provider_tested", user=current_user, ip=client_ip, status_="success" if passed else "failure",
           details={"provider_id": str(row.id), "purpose": sso_state.TEST, "outcome": outcome or "unknown"})
    shown = {key: value for key, value in (row.last_test or {}).items() if key != "config"}
    return {"tested": passed, "summary": shown if not passed else row.last_test}


# --------------------------------------------------------------------------- the person's own identities

def _refuse_temp(user) -> None:
    if getattr(user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="Temporary credentials cannot manage sign-in methods.")


def _identity_public(identity: ExternalIdentity, row: Optional[SsoProvider]) -> dict:
    def _t(value):
        return value.isoformat() + "Z" if value else None
    # Who the identity is at the provider, as the provider said when it was linked: the owner sees which identity
    # stands on their account, and a wrong one shows.
    return {"id": str(identity.id), "provider_id": str(identity.provider_id),
            "provider": (row.label or row.name) if row is not None else "a removed provider",
            "email": getattr(identity, "email_at_link", None), "display_name": getattr(identity, "display_name", None),
            "linked_at": _t(identity.linked_at), "linked_by": identity.linked_by,
            "last_sign_in_at": _t(identity.last_sign_in_at)}


def _tell_of_a_held_account_kept_out(db, row, user, label: str, key: str) -> None:
    """A sign-in at ``row`` carried the address of ``user``, whose account is held to another provider's sign-in:
    the owner is told what works (the holding provider first, in the words its own doors use), and the
    administrators are told once a day for the account. Called inside the caller's guard."""
    from app.core import setting_changes
    from app.core.models import RoleEnum
    api = _api()
    held = sso_freshness.held_to_a_provider(db, user)
    holding = held.provider_name if held is not None else "the provider it already uses"
    first = (sso_freshness.way_in_text(db, held) if held is not None else
             "Your account signs in only through the sign-in it already uses, until it has signed in there again.")
    # "You can link it under Your account" is said to an account that can: a link is started with the account's
    # password, so one that has none it can type (it signs in only through its provider) never could.
    from app.services import sign_in as _sign_in
    can_link = (f" Once your account has signed in there, you can link {label} under Your account."
                if _sign_in.has_a_password_it_can_type(user) else "")
    api._notify_users([str(user.id)], "account_changed",
                      title=f"A sign-in through {label} with your address was kept out",
                      body=(f"Someone signed in through {label} with your email address. Nobody was signed in to your "
                            f"account and nothing was linked. {first}{can_link} If it was not you, your address at "
                            f"{label} may be in someone else's hands: tell an administrator."),
                      target="#profile", dedup_prefix=key, once=True)
    # (The held account is never one of them: an administrator is not held.)
    admins = [str(a.id) for a in db.query(User).filter(User.role == RoleEnum.ADMIN).all() if a.is_active]
    if admins:
        api._notify_users(admins, setting_changes.NOTICE_TYPE,
                          title=f"A sign-in through {label} tried to reach {user.username}'s account",
                          body=(f"A sign-in through {label} carried the email address of {user.username}, whose "
                                f"account signs in only through {holding} until it has signed in there again (its "
                                f"days there ran out, or {holding} did not admit the person). Nobody was signed in "
                                f"and nothing was linked. A person who can no longer sign in through {holding} and "
                                "tries another provider looks like this: check the account on the Users page."),
                          target="#users", dedup_prefix=f"{key}:{user.id}:held", once=True)


def _tell_of_a_sign_in_kept_out(db, row, refusal) -> None:
    """A sign-in at the provider carried the verified address of an account that is never linked by its address
    (it set up a second factor of its own, or it is privileged). Whoever holds that address at the provider
    learns little from the answer; the account's owner would learn nothing at all, and an address taken over at
    the provider shows here first. So the owner is told, in the app, at most once a day for a provider; for a
    privileged account the other administrators are told as well. No email: the notice is not something a
    stranger at the provider may send at will. Never raises."""
    user = getattr(refusal, "about", None)
    if user is None:
        return
    api = _api()
    label = (getattr(row, "label", None) or getattr(row, "name", None) or "a provider").strip()
    key = f"sso_kept_out:{row.id}:{datetime.utcnow():%Y-%m-%d}"
    try:
        detail = getattr(refusal, "detail", "") or ""
        if detail == sso.HELD_ACCOUNT:
            # The account is held to the sign-in of a provider it is linked to. "Link it under Your account" is
            # refused for it, and so is its password: what works is said instead, and the administrators are
            # told, for a person who can no longer sign in through one provider trying another is what a leaver
            # does.
            _tell_of_a_held_account_kept_out(db, row, user, label, key)
            return
        api._notify_users([str(user.id)], "account_changed", title=f"A sign-in through {label} with your address was kept out",
                          body=(f"Someone signed in through {label} with your email address. Nobody was signed in to your "
                                f"account and nothing was linked: your account is linked to {label} only by you, under "
                                f"Your account. If that was you, link it there. If it was not, your address at {label} "
                                "may be in someone else's hands: tell an administrator."),
                          target="#profile", dedup_prefix=key, once=True)
        if detail == sso.ADDRESS_ON_AN_UNCONFIRMED_ACCOUNT:
            # A first sign-in that made no account: its verified address is written on an account that never
            # confirmed it. Either that account is this person's, and they link the provider there; or the
            # address on it is wrong, and until an administrator corrects it this person gets no account.
            from app.core import setting_changes
            from app.core.models import RoleEnum
            admins = [str(a.id) for a in db.query(User).filter(User.role == RoleEnum.ADMIN).all() if a.is_active]
            if admins:
                api._notify_users(admins, setting_changes.NOTICE_TYPE,
                                  title=f"A first sign-in through {label} made no account",
                                  body=(f"Someone signed in through {label} for the first time with an email address "
                                        f"that is written on {user.username}'s account, which never confirmed it. No "
                                        f"second account was made. If the person is {user.username}, they sign in to "
                                        f"that account and link {label} under Your account. If not, the address on "
                                        f"{user.username}'s account is wrong: correct it on the Users page, and the "
                                        "person can sign in again."),
                                  target="#users", dedup_prefix=f"{key}:{user.id}:unconfirmed", once=True)
        if detail.startswith(sso.PRIVILEGED_ACCOUNT):
            from app.core import setting_changes
            from app.core.models import RoleEnum
            others = [str(a.id) for a in db.query(User).filter(User.role == RoleEnum.ADMIN).all()
                      if a.is_active and a.id != user.id]
            if others:
                api._notify_users(others, setting_changes.NOTICE_TYPE,
                                  title=f"A sign-in through {label} tried to reach {user.username}'s account",
                                  body=(f"A sign-in through {label} carried the email address of {user.username}, an "
                                        "account that is never linked to a provider by its address. Nobody was signed "
                                        f"in. If {user.username} did not try this, the address may be in someone else's "
                                        f"hands at {label}."),
                                  target="#users", dedup_prefix=f"{key}:{user.id}", once=True)
    except Exception as exc:  # noqa: BLE001
        log.info("sso kept-out notice skipped: %s", type(exc).__name__)


# Why an owner's unlink is refused before anything is asked of the provider (the reasons of owners_unlink_refusal).
UNLINK_NO_WAY_IN, UNLINK_MADE_HERE, UNLINK_LAPSED = "no_way_in_left", "made_here", "sso_freshness_lapsed"


def owners_unlink_refusal(db, account, identity, row, *, now: Optional[datetime] = None):
    """Why ``account``'s owner may not unlink ``identity`` (of provider ``row``) now, whatever the provider would
    say: ``(reason, sentence)``, or None. Asked by the unlink itself, in the account's turn, and by the list of
    the caller's identities for each of them.

    - The account holds no password anybody can type, and no other identity on a provider that is on would sign
      it in: without this one nothing would. One that is off, or not finished, is no way in.
    - The identity is the one the account was made with at its first sign-in, while that provider holds such
      accounts to no password: only an administrator's act ends that hold. Unlinked by its owner, who had linked
      another provider meanwhile, the account could set itself the password the provider that made it says it
      may not have.
    - The provider refused the person, or its days have run out: unlinking would end the provider's say over the
      account's keys and credentials."""
    from app.services import sign_in
    now = now or datetime.utcnow()
    if not sign_in.has_a_password_it_can_type(account) and not sso_only.another_way_in(db, account, without=identity):
        return (UNLINK_NO_WAY_IN, (
            "Your account signs in only through single sign-on, and no other identity on a provider that is "
            "on can sign you in now. Ask an administrator for a password first."
            if getattr(account, "sso_only", False) else
            "Your account has no password of its own, and no other identity on a provider that is on can sign "
            "you in now: without this one nothing would sign you in. Set a password first (\"Forgot password\" "
            "on the sign-in page, or ask an administrator for a reset link), then unlink."))
    linked_by = getattr(identity, "linked_by", None)
    if row is not None and linked_by in sso_only.MADE_THROUGH_THE_PROVIDER \
            and sso_only.holds_to_no_password(row, account, linked_by):
        return (UNLINK_MADE_HERE, (
            f"Your account was made at its first sign-in through {row.label or row.name}, which stays its way in: "
            "it is not unlinked here. Ask an administrator."))
    standing = sso_freshness.deadline_of(identity, row)
    if standing is not None and (standing.refused or standing.due <= now):
        return (UNLINK_LAPSED, _what_unblocks_an_unlink(standing, now))
    return None


def _what_unblocks_an_unlink(standing, now: datetime) -> str:
    """What the owner is told when their provider's hold, or its days, stand in the way of an unlink: what would
    let the unlink through, and nothing that would not.

    - The provider is turned off: nobody signs in through it, so "sign in there again" led nowhere (it has no
      button), and after an administrator lifted a hold the next try was refused for the days. Only an
      administrator's unlink works: said as that.
    - It is on, and a hold is on record: a sign-in it admits lifts the hold and gives new days. An
      administrator's lift helps only while the days have not run out as well; where they have, it is not named.
    - It is on and the days have run out: a sign-in through it."""
    name = standing.provider_name
    if not standing.provider_on:
        return (f"{name} is turned off on this vault, so you cannot sign in through it, and it is not unlinked "
                "here. Ask an administrator to unlink it for you.")
    days_ran_out = standing.window_days > 0 and standing.due <= now
    if standing.refused and days_ran_out:
        return (f"Your account is held to a sign-in through {name}: sign in there again before you unlink it. If "
                f"{name} does not admit you, ask an administrator to unlink it for you.")
    if standing.refused:
        # True of both holds a row can carry: the provider's refusal, and the vault's own. A sign-in the provider
        # admits lifts either.
        return (f"Your account is held to a sign-in through {name}: sign in there again, or ask an "
                "administrator to lift the hold, before you unlink it.")
    return f"Sign in through {name} again before you unlink it."


def owners_unlink_text(username: str, label: str, *, asked: bool, linked_by, standing, policy, reached: bool,
                       now: datetime, warned_for=None) -> str:
    """What the administrators are told when an owner unlinks an identity: whether the provider confirmed it, and
    if not, why none was asked; the day a sign-in there was due, when one was; and what really stops waiting for
    the provider, by the provider's own rules. ``standing``: the identity's deadline (or None); ``policy``: the
    provider's; ``reached``: whether the provider's hold reaches this account (sso_freshness.may_be_held);
    ``warned_for``: the deadline the account was warned about, as the daily pass wrote it on the identity.

    "The account had been warned" is said when it was: the warning for this deadline is on record. Judged by the
    clock alone, it was said of accounts no warning had gone to (the pass warns nobody while the provider is off,
    no account that is turned off, and nobody before its next run): then the notice says that the warning days
    had begun, which is what the clock shows."""
    said = f"{username} removed {label} from the ways their account signs in"
    if asked:
        said += f", after a fresh sign-in through {label}."
    elif linked_by == sso.LINKED_BY_EMAIL:
        said += (f". {label} had put the identity on the account by its email address, so no fresh sign-in "
                 f"through {label} was asked.")
    else:
        said += "."
    if standing is not None and standing.due is not None and not standing.refused:
        said += f" A sign-in through {label} was due by {standing.due:%Y-%m-%d}"
        if warned_for is not None and warned_for == standing.due:
            said += ", and the account had been warned of it"
        elif now >= standing.due - sso_freshness.warning_lead(standing.window_days):
            said += ", and the warning days had begun"
        said += "."
    watches = bool(policy) and (policy["sso_freshness_days"] > 0 or policy["sso_refusal_ends_access"])
    if watches and policy["sso_lapse_ends_sign_in"] and reached:
        said += (f" From now on {label} says nothing about this account: what signs it in without {label} (a "
                 "password, passkeys) and its SSH keys no longer wait for a sign-in there.")
    elif watches:
        said += (f" From now on {label} says nothing about this account: its SSH keys, temporary credentials and "
                 "devices no longer wait for a sign-in there.")
    else:
        said += f" {label} asked nothing of this account's other ways in, so nothing else changes."
    return said + " Check the Users page if you did not expect this."


# What an account's owner is advised when an administrator, not the owner, changed how the account signs in.
BY_AN_ADMINISTRATOR = "If you did not expect this, ask an administrator."


def _tell_owner(db, user, row, title: str, change: str, *, advice: Optional[str] = None) -> None:
    """Tell ``user`` of a change to how their account signs in, in the app and by email. ``advice``: what to do
    about it, when the change was not the owner's own (the default speaks to the one who may have been
    impersonated: it was done from their own account)."""
    api = _api()
    try:
        if advice is None:
            advice = ("If you did not do this, tell an administrator at once." if getattr(user, "sso_only", False)
                      else "If you did not do this, remove it and change your password.")
        api._notify_users([str(user.id)], "account_changed", title=title, body=f"{change} {advice}", target="#profile")
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
    """The caller's linked organisation identities (the provider's label, when linked and by what, the last
    sign-in), and the providers the account is linked to or could link: each one that is on and can serve a sign-in
    now, whether the sign-in page shows its button or not, in the sign-in page's order, with whether it is linked
    and whether it can confirm the person afresh. The button is about the sign-in page: the texts that send a
    person here to link a provider are true only if every provider that can be linked is offered here."""
    _refuse_temp(current_user)
    rows = db.query(ExternalIdentity).filter(ExternalIdentity.user_id == current_user.id).all()
    providers = {str(p.id): p for p in db.query(SsoProvider).all()}
    linked = {str(i.provider_id) for i in rows}
    offered = [p for p in providers.values() if sso.usable_for(p, sso_state.LINK) is None]
    offered.sort(key=lambda p: (p.sort_order or 0, (p.label or p.name or "").lower(), str(p.id)))
    may_confirm = sso.reauth_allowed(db, current_user)        # a provider confirms only an account with no password

    def shown(identity):
        row = providers.get(str(identity.provider_id))
        out = _identity_public(identity, row)
        # Whether unlinking it asks for a fresh sign-in there first, and whether the provider can give one now.
        out["unlink_asks_provider"] = sso.unlink_asks_the_provider(db, current_user, identity, row)
        out["provider_can_confirm"] = row is not None and sso.reauth_offered(row)
        # Why its unlink would be refused whatever the provider says, or None: shown in place of the unlink, so
        # that nobody is sent to the provider for nothing.
        refusal = owners_unlink_refusal(db, current_user, identity, row)
        out["unlink_refusal"] = {"reason": refusal[0], "message": refusal[1]} if refusal is not None else None
        return out
    return {"identities": [shown(i) for i in rows],
            "providers": [{"id": str(p.id), "label": p.label or p.name, "icon": p.icon or "generic",
                           "linked": str(p.id) in linked,
                           # Linking it ends the account's password: the page says so before it starts the link.
                           "ends_password": (str(p.id) not in linked and sso_only.password_less(p)
                                             and not getattr(current_user, "sso_only", False)),
                           "reauth": may_confirm and str(p.id) in linked and sso.reauth_offered(p)} for p in offered],
            # The account's address, when confirming it would let a provider's sign-in find the account: the
            # page then offers the code (or says who can confirm it, where the vault sends no email).
            "email": ({"address": current_user.email, "can_send_code": bool(_api()._smtp_configured(db)),
                       # Whether the account can set a second factor up under Your account: an authenticator
                       # asks for the password again, and one with none it can type is left the passkey.
                       "factor_here": _a_factor_can_be_set_up_here(current_user)}
                      if sso.confirmed_address_wanted(db, current_user) else None)}


def _a_factor_can_be_set_up_here(user) -> bool:
    """Whether the account can set a second factor up under Your account, which the page's hint goes by: an
    authenticator app asks for the password again, and a passkey needs passkeys turned on and an address one can
    be made at. Turned off, a passkey's registration is refused whatever the address is: the hint must not send
    an account with no password it can type to a set-up that will refuse it."""
    from app.core import webauthn_settings
    from app.services import sign_in
    return sign_in.has_a_password_it_can_type(user) or (
        webauthn_settings.enabled() and webauthn_settings.passkeys_can_be_made())


@router.post("/users/me/identities/{provider_id}/start")
async def start_link(
    provider_id: str,
    body: SsoLinkStartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start linking the caller's account to a provider. The session must have proved the password (its ``amr``
    carries ``pwd``; a session from before tokens named their proofs began with the password) and, when the
    account has a factor, the second factor: at its sign-in (``mfa_at`` set) or afresh in the
    account.second_factor step-up the link is made under (:func:`_the_factor_is_given_for_a_link`). A provider
    identity is a new way into the account."""
    api = _api()
    _refuse_temp(current_user)
    # An account held to its provider's sign-in adds no other way in: from a session a password made before the
    # hold, a link to another provider would let the person back in without the provider that asks for them.
    due = sso_freshness.held_to_a_provider(db, current_user)
    if due is not None:
        raise HTTPException(status_code=409, detail={"reason": "sso_sign_in_due",
                                                     "message": sso_freshness.way_in_text(db, due)})
    client_ip = api.get_client_ip(request)
    _limit_start(client_ip)
    claims = _session_claims(request)
    from app.services import sign_in
    # No token read is no proof; a token that names no proofs is from before they were named, and a password's.
    if not claims or sign_in.PASSWORD not in sign_in.proofs_of(claims):
        raise HTTPException(status_code=403, detail={
            "reason": "password_proof_required",
            "message": "Sign in with your password before adding a sign-in method."})
    from app.core.active_factors import active_factors
    if (active_factors(db, current_user.id).any and not claims.get("mfa_at")
            and not _the_factor_is_given_for_a_link(api, db, current_user)):
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
    view, user_id, session_hash = _provider_view(row), current_user.id, api._current_session_hash(request)
    _release_database(db)
    try:
        # The provider is asked to sign the person in again: what is linked is to be the identity of whoever is
        # here now, not of whoever was still signed in at the provider in this browser.
        url = await _provider_call(sso.start, view, purpose=sso_state.LINK, source=sign_in_lockout.source_of(client_ip),
                                   client_ip=client_ip, verifier_hash=body.verifier_hash, user_id=user_id,
                                   session_hash=session_hash, reauthenticate=True, deadline=_provider_deadline())
    except (sso.Refusal, oc.OidcError, sso_state.TooManyAbandoned, sso_state.Unavailable) as exc:
        raise _refused_start(exc)
    return {"authorization_url": url, "expires_in": sso_state.STATE_TTL_SECONDS}


def _the_factor_is_given_for_a_link(api, db, user) -> bool:
    """For an account that holds a second factor and whose session did not give it: whether the link may go on
    all the same.

    It may where the step-up the link is made under asks for the factor: its receipt is a fresh proof of it,
    given for this very act. And it may where no sign-in asks for the factor either (the administrator turned
    the sign-in's second step off): no session could then have given it, and telling the person to sign in with
    it asked for what nothing would let them do. The link is refused only where the step-up does not ask for the
    factor and a sign-in would: signing in again gives it."""
    requirement, _has_one = api._sf_requirement_for(db, user, "account.second_factor")
    if requirement.get("otp"):
        return True
    sign_in_asks, _password = api._sf_action_toggles(db, "login")
    return not sign_in_asks


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
    """Remove one of the caller's identities, under the account.second_factor step-up. Refused when this is the
    last identity, on a provider that is on, of an account that has no password it can type (one that signs in
    only through single sign-on, or whose password nobody knows): it would lose its only way in. A passkey of
    such an account signs in after its provider only, so it is no other way."""
    api = _api()
    _refuse_temp(current_user)
    api._enforce_step_up(db, current_user, request, "account.second_factor")
    # The account's turn before its identities are read: two unlinks sent at once would each count the other's
    # identity as the way in that is left, and both would go through. Waited for as a link waits (the short wait
    # of where a sign-in is written): this route runs on the server's one loop, and a change that settles the
    # account holds its turn until it commits. A turn still held is answered as busy. Nothing was changed; the
    # step-up the request came with is used, so the person gives it again with the next try.
    from sqlalchemy.exc import OperationalError
    from app.services import sign_in as _sign_in
    try:
        _sign_in.with_a_short_wait(db, lambda: api._sessions_turn(db, current_user.id))
    except OperationalError as waited:
        if getattr(getattr(waited, "orig", None), "pgcode", None) != LOCK_NOT_AVAILABLE:
            raise
        db.rollback()
        from app.core import sign_in_lockout
        raise HTTPException(status_code=503, headers={"Retry-After": str(sign_in_lockout.BUSY_RETRY_SECONDS)},
                            detail={"reason": sso.BUSY, "message": (
                                "Your account is being changed right now. Try again in a moment.")}) from None
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.id == identity_id,
                                                 ExternalIdentity.user_id == current_user.id).first()
    if identity is None:
        raise HTTPException(status_code=404, detail="That identity was not found.")
    # The account as it is committed, read in the turn: the one the request was checked with was loaded before
    # it, and a setting that makes the account sign in only through its provider may have been saved since.
    account = db.query(User).filter(User.id == current_user.id).populate_existing().first() or current_user
    row = _provider(db, identity.provider_id)
    # What refuses the unlink before anything is asked of the provider (owners_unlink_refusal: no way in left,
    # the identity the account was made with, a refusal or days run out). The list of the caller's identities
    # says the same for each, so that the page does not send a person to the provider for an unlink that is
    # refused on their return.
    refusal = owners_unlink_refusal(db, account, identity, row)
    if refusal is not None:
        reason, message = refusal
        raise HTTPException(status_code=409, detail=({"reason": reason, "message": message}
                                                     if reason == UNLINK_LAPSED else message))
    standing = sso_freshness.deadline_of(identity, row)
    # Where the provider closes the account's other ways in, the unlink is confirmed by a fresh sign-in through
    # it, staged by this session a moment ago (sso.unlink_asks_the_provider). Asked last, so that a confirmation
    # is not spent on an unlink that is refused for another reason.
    asked = sso.unlink_asks_the_provider(db, account, identity, row)
    if asked:
        label = row.label or row.name
        try:
            staged = sso_state.take_reauth(api._current_session_hash(request), sso.UNLINK_CONFIRMATION)
        except sso_state.Unavailable:
            raise HTTPException(status_code=503, detail="Sign-in is temporarily unavailable. Try again in a moment.")
        if not (staged and str(staged[0]) == str(identity.provider_id) and sso.reauth_stands(db, account, *staged)):
            if sso.reauth_offered(row):
                raise HTTPException(status_code=403, detail={
                    "reason": "provider_confirmation_required", "action": sso.UNLINK_CONFIRMATION,
                    "provider": {"id": str(row.id), "label": label},
                    "message": f"Sign in through {label} once more to confirm it is you, then unlink it."})
            raise HTTPException(status_code=409, detail={
                "reason": "provider_cannot_confirm", "provider": {"id": str(row.id), "label": label},
                "message": f"{label} cannot confirm you right now, so it is not unlinked here. Ask an administrator."})
    provider_id = str(identity.provider_id)
    # Kept for the record and the notice, before the identity goes: how it was linked, and what its provider
    # still asked of the account (a deadline that was running).
    linked_by = getattr(identity, "linked_by", None)
    # Whether this provider could hold the account to its own sign-in: where it could, the unlink takes the
    # account out of that for good, and the administrators are told by email too (below).
    could_hold = sso.provider_can_hold(db, account, row)
    told = owners_unlink_text(current_user.username, (row.label or row.name) if row is not None else
                              "an organisation provider", asked=bool(asked), linked_by=linked_by,
                              standing=standing, policy=sso.policy_of(row) if row is not None else None,
                              reached=sso_freshness.may_be_held(db, account), now=datetime.utcnow(),
                              warned_for=getattr(identity, "freshness_warned_for", None))
    # The flag follows the providers the account is still linked to: unlinking the one that held it to no password
    # lets it hold one again (nothing is minted), in the same transaction as the unlink.
    settled = sso_only.settle(db, account, without=identity)
    # What came through the identity ends with it, in the same transaction: the sessions made by a sign-in through
    # it, and the sign-ins of the account under way. An unlink is the owner's answer to a link they did not make;
    # whoever was signed in through it must not stay signed in, least of all once the owner links their own
    # identity on the same provider.
    ended = _end_what_came_through(db, account, identity)
    db.delete(identity)
    db.commit()
    # How the identity was linked is recorded as it was (an identity its provider put on the account by an
    # address is unlinked in one step: the record must tell it from one the owner linked), with who unlinked it
    # and the day a sign-in there was due.
    _audit(db, "sso_identity_unlinked", user=current_user, ip=api.get_client_ip(request),
           details={"provider_id": provider_id, "identity_id": str(identity_id), "linked_by": linked_by,
                    "unlinked_by": "owner", "sessions": ended, "confirmed_at_provider": bool(asked),
                    "due": standing.due.isoformat() + "Z" if standing is not None and standing.due else None,
                    "restored": settled == sso_only.RESTORED})
    label = (row.label or row.name) if row is not None else "an organisation provider"
    may_set_password = settled == sso_only.RESTORED
    # Every unlink by its owner is told to the administrators in the app: from now on the provider says nothing
    # about the account. By email as well only where the provider could hold the account to its own sign-in:
    # there the unlink is what a person does whom the provider is about to stop signing in, and an identity
    # linked by an address is unlinked there with no confirmation at all. Everywhere else an email for every
    # unlink would be noise in a large organisation. The owner who is an administrator reads their own notice
    # as the owner, and not a second one that says somebody unlinked.
    try:
        admins = [a for a in api._active_admins(db) if str(a.id) != str(current_user.id)]
        api._notify_users([str(a.id) for a in admins], "account_changed",
                          title=f"{current_user.username} unlinked {label}", body=told, target="#users")
        if could_hold:
            from app.core import setting_changes
            api._fire_action_email_bulk(db, setting_changes.EMAIL_ACTION, [(a.email, a.username) for a in admins],
                                        {"change": told, "by": current_user.username,
                                         "when": api._change_time_text()})
    except Exception as exc:  # noqa: BLE001 -- the unlink stands without its notice
        log.info("sso unlink notice to administrators skipped: %s", type(exc).__name__)
    _tell_owner(db, current_user, row, "A sign-in method was removed from your account",
                f"You unlinked your account from {label}: it can no longer sign in through it."
                + (" Your account may hold a password again and has none yet: set one with \"Forgot password\" on the "
                   "sign-in page, or ask an administrator for a reset link." if may_set_password else ""))
    answer = {"removed": True, "sessions_ended": ended}
    if may_set_password:
        answer["may_set_password"] = True
    return answer
