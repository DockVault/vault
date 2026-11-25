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
  the old, by the renewal rules, the two changed in one transaction under the account's turn at its sessions.

The route decides how it answers (the shapes the web app knows are unchanged); this module decides
what a sign-in is.
"""
from __future__ import annotations

import functools
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

# What a held sign-in is told once its account's sessions were ended, and where its time ran out.
BUSY = "Signing in is busy right now. Try again in a moment."
# The same, where what carried the sign-in was spent by the try (a one-time sign-in code): there is nothing to
# send again, so the answer says what works and gives no wait.
BUSY_START_AGAIN = "Signing in is busy right now. Start the sign-in again in a moment."
PROVIDER_BUSY = "Signing in through your organisation is busy right now. Try again in a moment."


def provider_busy() -> HTTPException:
    """The refusal of a provider sign-in that could not be judged now and can be a moment later (the provider's
    row held by a save, the memory of the provider's logouts out of reach): 503 with the wait, as every busy
    answer carries it. One answer for all of them, so that none goes without the wait."""
    from app.core import sign_in_lockout
    return HTTPException(status_code=503, detail=PROVIDER_BUSY,
                         headers={"Retry-After": str(sign_in_lockout.BUSY_RETRY_SECONDS)})
EXPIRED = "This login attempt has expired; start again."

# The order of the locks.
#
# A sign-in, and a change to how an account signs in, take these in this order, and never one of them after one
# that stands later in the list:
#
#   1. the account's turn at signing in (app/core/sign_in_lockout.py take_turn; the password door alone);
#   2. a provider's row (sso_providers), read under a lock or written;
#   3. the account's turn at its sessions (take_sessions_turn there; api_server._sessions_turn);
#   4. the account's row (users), read under a lock or written;
#   5. a row of credential_changes or of auditor_grants, read under a lock or written (an account that loses
#      its standing has its open requests and its auditor right locked: after its turn, on every route).
#
# Any of them may be skipped, and one already held may be taken again. The turns are an account's own: another
# account's row may be held when a turn is taken. A lock the application takes on an account's row under a turn
# leaves the row's key free (FOR NO KEY UPDATE), so the rows that name the account (a session, a held sign-in, a
# passkey, an audit row) are written without waiting for it. Two transactions that keep to the order cannot wait
# for each other in a ring. tests/_lock_order_recorder.py watches a test stack for a transaction that does not.
#
# What is written in the account's turn at its sessions: a session, a sign-in held for a further step, and a
# factor set up at a held sign-in, each in one transaction with a check that its proof still stands
# (in_the_accounts_turn), committed once. What ends an account's sessions takes the same turn, so each of the two
# comes wholly before the other. The deletion of an account is one of them: it takes the turn after the vault rows
# it locks and before it removes the account's row (the database then removes the account's held sign-ins and
# sessions, which a sign-in under way would otherwise be writing).


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
    # What a provider session remembers for the provider's logouts: the provider's session id and subject, and
    # the ID token (plain here, encrypted at rest) when the provider logout option wants it.
    provider_sid: Optional[str] = None
    provider_sub: Optional[str] = None
    # The moment this sign-in counts from for the provider's logouts (seconds since the epoch): when the vault
    # began it, before the person was sent to the provider (app/core/sso_state.began_at). A logout the vault
    # takes later ends the sign-ins under way that were begun before it, and not one begun after.
    provider_answered_at: Optional[float] = None
    # The ID token, for the provider's own logout; only when wanted. Never in the result's text form.
    provider_logout_hint: Optional[str] = field(default=None, repr=False)
    # When the provider says the person authenticated there (its own session, which may be days old). Kept with the
    # provider's session as a record of it: no rule reads it (an identity's freshness counts from the vault's own
    # stamp of its last sign-in), and it is never the token's ``auth_time``, which is the moment the vault's own
    # sign-in completed, for every door (complete_sign_in).
    provider_auth_time: Optional[datetime] = None
    # A passkey: whether the authenticator verified the person (the UV flag), and whether the policy lets
    # this person sign in with a user-verified passkey alone.
    user_verified: bool = False
    passwordless_allowed: bool = False
    # What this sign-in does to the day the account's passkey requirement began: GRACE_BEGINS (the first sign-in
    # under the requirement) or GRACE_ENDS (the requirement waits, or is met again). Noted where the sign-in is
    # judged and written where it is written, in the account's turn, on the account as it is read again there:
    # written on the account before that, it was lost when the account was read again.
    passkey_grace: Optional[str] = None
    channel: str = "web"
    # How many times the account's sessions had been ended when the first proof of this sign-in read the account
    # (:func:`as_read`; a held sign-in carries it in its token, :func:`ended_of`). A door passes what it read
    # with the account, before it checked anything; left out, it is read off ``user`` as it stands here.
    sessions_ended: Optional[int] = None

    def __post_init__(self):
        if self.sessions_ended is None:
            self.sessions_ended = as_read(self.user)


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
    ended = payload.get("ended")
    pending._sessions_ended = ended if isinstance(ended, int) and not isinstance(ended, bool) else None
    sid, sub = payload.get("idp_sid"), payload.get("idp_sub")
    pending._provider_sid = sid if isinstance(sid, str) else None
    pending._provider_sub = sub if isinstance(sub, str) else None
    # When the vault began the sign-in at the provider (the field keeps an older name: it is not the moment of
    # the provider's answer).
    answered = payload.get("idp_at")
    pending._provider_answered_at = (float(answered) if isinstance(answered, (int, float))
                                     and not isinstance(answered, bool) else None)
    at = payload.get("idp_auth_time")
    pending._provider_auth_time = (datetime.fromtimestamp(at, tz=timezone.utc)
                                   if isinstance(at, int) and not isinstance(at, bool) and 0 <= at < 2 ** 33 else None)


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


def as_read(user) -> int:
    """How many times the account's sessions had been ended as a whole when ``user`` was read
    (``users.sessions_ended``). A door takes it right after it loads the account, before it checks anything."""
    return int(getattr(user, "sessions_ended", 0) or 0)


def ended_of(pending: Optional[PendingLogin]) -> int:
    """The count a held sign-in carries from its first proof (read from its token). A token that carries none
    was made before the count was kept: it matches no account, so that sign-in starts again."""
    read = getattr(pending, "_sessions_ended", None)
    return read if isinstance(read, int) else -1


# How long a sign-in waits for a lock at the point where it is written. The routes that finish a sign-in are
# answered on the server's one loop, where a wait is a wait for every request of every person; the connection's own
# wait (app/core/database.py, five seconds) is for work that runs off that loop. A lock still held after this is
# answered as busy, with nothing written, and the person tries again.
WRITE_WAIT_MS = 500


def _on_postgres(db) -> bool:
    try:
        return db.get_bind().dialect.name == "postgresql"
    except Exception:  # noqa: BLE001 -- a stand-in session of a test, or SQLite: no such setting there
        return False


def with_a_short_wait(db, take):
    """Run ``take``, which takes a lock, with the wait for it bounded by :data:`WRITE_WAIT_MS`, and give the
    transaction its own wait back afterwards: the one it had, read before, not the connection's usual one (a
    caller that had set a wait of its own keeps it). A lock still held raises what the database raises
    (lock_not_available), with the transaction as the database leaves it: the caller rolls back and answers."""
    from sqlalchemy import text
    bounded = _on_postgres(db)
    if bounded:
        own = db.execute(text("SELECT current_setting('lock_timeout')")).scalar()
        db.execute(text("SELECT set_config('lock_timeout', :wait, true)"), {"wait": f"{int(WRITE_WAIT_MS)}ms"})
    taken = take()
    if bounded:
        db.execute(text("SELECT set_config('lock_timeout', :own, true)"), {"own": own})
    return taken


def busy() -> HTTPException:
    """The refusal of a sign-in that could not be written now and can be a moment later: 503 with the wait."""
    from app.core import sign_in_lockout
    return HTTPException(status_code=503, detail=BUSY,
                         headers={"Retry-After": str(sign_in_lockout.BUSY_RETRY_SECONDS)})


def start_again() -> HTTPException:
    """The busy answer of a route whose one-time code is spent: 503, the words that say to start again, and no
    wait to count down (sent again, the code is no code)."""
    return HTTPException(status_code=503, detail=BUSY_START_AGAIN)


def after_a_spent_code_busy_is(answer):
    """For an async route that has spent a one-time code or state by the time it works (the exchange of a sign-in
    code, the provider's answer coming back, the claim of a finished link or test): a lock wait that ran out
    anywhere in it is answered by ``answer()``, which returns the route's answer or raises it.

    Left to the application's own answer for a lock wait, such a route said "Try again in a moment" with a wait
    to count down. What carried the request was spent by the first try, so the try made after the wait was told
    the code is not valid, and where the browser had come back from a provider, a page of JSON stood where the
    sign-in page should. The transaction is rolled back before the answer is made. Any other error of the
    database passes as it is."""
    def wrap(route):
        @functools.wraps(route)
        async def guarded(*args, **kwargs):
            from sqlalchemy.exc import OperationalError
            try:
                return await route(*args, **kwargs)
            except OperationalError as waited:
                if getattr(getattr(waited, "orig", None), "pgcode", None) != "55P03":      # lock_not_available
                    raise
                db = kwargs.get("db")
                if db is not None:
                    db.rollback()
                made = answer()
                if isinstance(made, BaseException):
                    raise made from None
                return made
        return guarded
    return wrap


def a_refusal_leaves_no_session(step):
    """For a step of the pipeline that takes ``(db, result, ...)``: a refusal it raises leaves no session of the
    sign-in's proof behind. The password door writes its session in its own turn and commits it before the
    pipeline judges the sign-in. Refused there for something other than the count or a busy turn (the account
    locked or turned off meanwhile, a held sign-in already spent, whatever a later step of the pipeline
    refuses), the sign-in got no token, and its session stayed: of no use to anyone, shown among the account's
    sessions and counted with them. With a proof's session to drop, what the refused sign-in had written and not
    committed is rolled back first, so that the drop's commit keeps none of it; without one nothing is touched.

    A lock that stayed held for longer than the step waited is such a refusal, wherever in the step it was
    waited for: the account's turn at its sessions, held by a change that settles many accounts at once, or a
    row a later statement writes. Nothing of the step was written, the session of the proof goes, and the answer
    is the busy one. Left to pass, it was an error to the caller with the session left behind, and where a
    one-time sign-in code had carried the sign-in, the answer told the page to send again a code that was spent.
    Any other error of the database is not a refusal, and passes as it is."""
    @functools.wraps(step)
    def guarded(db, result, *args, **kwargs):
        from sqlalchemy.exc import OperationalError
        try:
            return step(db, result, *args, **kwargs)
        except HTTPException:
            if getattr(result, "session_token", None):
                db.rollback()
                drop_the_session_the_proof_made(db, result)
            raise
        except OperationalError as waited:
            if getattr(getattr(waited, "orig", None), "pgcode", None) != "55P03":      # lock_not_available
                raise
            db.rollback()
            drop_the_session_the_proof_made(db, result)
            raise busy() from None
    return guarded


@a_refusal_leaves_no_session
def in_the_accounts_turn(db, result: "SignInResult") -> None:
    """Before a session or a held sign-in is written for ``result``: take the account's turn at its sessions and
    judge the sign-in again in it, on the account as it is committed.

    What ends an account's sessions (a new password, a reset link used, a second-factor reset, a sign-out
    everywhere, a lock) takes that turn, counts itself on the account, and ends the sessions and the held
    sign-ins it finds. A sign-in whose proof was read before such a change and that writes after it would leave
    a session, or a held sign-in, the change never saw. So the writer takes the turn, reads the account again and
    compares the count with the one the sign-in's first proof read: a sign-in from before the change is refused,
    and one that passes commits before the next change can begin, which then finds what it wrote. The account's
    state is judged again on the same read (locked, turned off). The caller writes and commits once, without
    another commit in between: the commit is what lets the turn go.

    A temporary credential's sign-in is not the account's own and is left as it is."""
    if result.is_temporary:
        return
    from sqlalchemy.exc import InvalidRequestError
    from app.api import api_server as api
    user = result.user
    # A sign-in that came through a provider: the provider's row first, under a share lock (it stands before the
    # turn in the order of the locks). A turn-off, a save or a removal of the provider takes the row for itself,
    # so it comes wholly before this write, which then finds the provider as it left it, or wholly after, and
    # ends what was written.
    hold_the_providers_row(db, result)
    # A turn held for longer than a sign-in waits where it is written (a change that settles many accounts at
    # once) refuses the sign-in as busy, with nothing written and no session of its proof left: the guard of
    # this step answers a lock wait that ran out, here and in whatever it writes below.
    with_a_short_wait(db, lambda: api._sessions_turn(db, user.id))
    refresh = getattr(db, "refresh", None)
    if refresh is not None:
        try:
            refresh(user)                          # as committed: everything below reads this
        except InvalidRequestError:
            # The account is no longer there (deleted while the sign-in waited): refused as from before a change.
            db.rollback()
            drop_the_session_the_proof_made(db, result)
            raise HTTPException(status_code=401, detail=EXPIRED) from None
    if as_read(user) != result.sessions_ended:
        drop_the_session_the_proof_made(db, result)
        raise HTTPException(status_code=401, detail=EXPIRED)
    if a_passkey_alone(result) and not api._passkey_passwordless_allowed(db, user):
        # A passkey by itself, taken when the account's role let one in alone. The account as it stands now does
        # not (made an administrator meanwhile, or given the auditor right): refused as from before a change,
        # and the person signs in again with what the account now owes.
        drop_the_session_the_proof_made(db, result)
        raise HTTPException(status_code=401, detail=EXPIRED)
    refuse_unless_the_account_may_sign_in(db, user, result.client_ip)
    refuse_without_the_provider(db, result)
    refuse_unless_the_provider_stands(db, result)
    write_the_passkey_grace(result)


def proofs_of(claims) -> set:
    """The proofs a session's token names, as a set. A token that names none at all (no ``amr``) was made by a
    release in which every session began with the password, and is carried on by the renewals of that session:
    it is a password's. One that names them is what it names."""
    proofs = (claims or {}).get("amr")
    if proofs is None:
        return {PASSWORD}
    return {m for m in proofs if isinstance(m, str)} if isinstance(proofs, (list, tuple)) else set()


def a_passkey_alone(result: "SignInResult") -> bool:
    """Whether ``result`` is a sign-in that a passkey made by itself: no password, no provider, and the account's
    role let a user-verified passkey be the whole of it when the passkey was taken."""
    return (bool(result.passwordless_allowed) and not result.provider_id and PASSWORD not in result.methods
            and bool(set(result.methods) & PASSKEYS))


GRACE_BEGINS, GRACE_ENDS = "begins", "ends"


def write_the_passkey_grace(result: "SignInResult") -> None:
    """Write what the sign-in does to the day the account's passkey requirement began, on the account as it was
    read again in its turn, for the commit that writes the sign-in: the day begins only where none is set, and
    ends only where one is. The account object holds nothing unwritten before the turn, so nothing of it is lost
    when it is read again there."""
    from app.api import api_server as api
    if result.passkey_grace == GRACE_BEGINS:
        api._passkey_mark_required(result.user)
    elif result.passkey_grace == GRACE_ENDS:
        api._passkey_pause_grace(result.user)


def drop_the_session_the_proof_made(db, result: "SignInResult") -> None:
    """A sign-in that is refused where it would be written leaves no session behind: the one its proof made (the
    password door writes its own, in its turn) is deleted with it."""
    made, result.session_token = result.session_token, None
    if made:
        delete_session_by_token(db, made)


def provider_session_of(pending: Optional[PendingLogin]) -> dict:
    """What the pending login's provider sign-in remembers for the provider's logouts, as result fields: the
    provider's session id, subject and authentication time from the pre-authentication token, and the logout hint
    staged for it (read back encrypted from the store, opened here; nothing when the store or the key has none)."""
    fields = {"provider_sid": getattr(pending, "_provider_sid", None), "provider_sub": getattr(pending, "_provider_sub", None),
              "provider_answered_at": getattr(pending, "_provider_answered_at", None),
              "provider_auth_time": getattr(pending, "_provider_auth_time", None), "provider_logout_hint": None}
    if pending is not None and getattr(pending, "_provider_id", None) and getattr(pending, "id", None) is not None:
        try:
            from app.core import sso_state
            from app.core.security import decrypt_secret
            staged = sso_state.read_logout_hint(str(pending.id))
            fields["provider_logout_hint"] = decrypt_secret(staged) if staged else None
        except Exception:  # noqa: BLE001 -- the hint is a convenience for the provider's logout, never a refusal
            fields["provider_logout_hint"] = None
    return fields


def delete_session_by_token(db, session_token: Optional[str]) -> None:
    """Delete the session the password check just made, so a sign-in with a step still to go leaves no
    usable session behind. The stored value is the token's SHA-256 hash."""
    if not session_token:
        return
    from app.core.models import ActiveSession
    db.query(ActiveSession).filter(
        ActiveSession.session_token == hash_session_token(session_token)).delete(synchronize_session=False)
    db.commit()


def spend_sign_ins_under_way(db, user_id) -> int:
    """Spend every sign-in of the account that is held for a further step (its second factor, its password, an
    enrollment), in the caller's transaction; returns how many. Called where the account's sessions are ended
    because something about how it signs in changed, or because it is to be signed out everywhere: a held sign-in
    was proved by what the account had before (the old password, say), lives five minutes, and would otherwise
    go on to a session, or set a passkey up, after the change that was meant to end it. An authenticator app the
    account had begun to set up and not finished goes with them (:func:`_drop_a_set_up_left_half_way`). A
    database built with only the tables a test needs may hold no sign-ins at all: nothing to spend there."""
    from app.core.table_presence import has_table
    _drop_a_set_up_left_half_way(db, user_id)
    if not has_table(db, PendingLogin.__tablename__):
        return 0
    return int(db.query(PendingLogin).filter(
        PendingLogin.user_id == user_id, PendingLogin.consumed_at.is_(None)).update(
        {PendingLogin.consumed_at: datetime.now(timezone.utc)}, synchronize_session=False) or 0)


def _drop_a_set_up_left_half_way(db, user_id) -> None:
    """Remove the authenticator app the account began to set up and did not finish, with the recovery codes made
    for it, in the caller's transaction. Whoever began it, at a sign-in now spent or in a session now ended, knows
    its secret and its codes, and the last step of the set-up, sent later from any session of the account, would
    have made that secret the account's second factor. An account holds one enrollment, so one that is not
    finished means no authenticator is active and the codes are that set-up's own."""
    from app.core.models import SecondFactorEnrollment, SecondFactorRecoveryCode
    from app.core.table_presence import has_table
    if not has_table(db, SecondFactorEnrollment.__tablename__):
        return
    dropped = db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.user_id == user_id, SecondFactorEnrollment.status == "unconfirmed").delete(
        synchronize_session=False)
    if dropped and has_table(db, SecondFactorRecoveryCode.__tablename__):
        db.query(SecondFactorRecoveryCode).filter(SecondFactorRecoveryCode.user_id == user_id).delete(
            synchronize_session=False)


def consume_pending(db, pending: PendingLogin, *, commit: bool = True) -> None:
    """Spend a pending login, one winner only: a second completion of the same step is refused. ``commit=False``
    leaves the commit to the caller, who writes what the pending login becomes in the same transaction."""
    done = db.query(PendingLogin).filter(
        PendingLogin.id == pending.id, PendingLogin.consumed_at.is_(None)).update(
        {"consumed_at": datetime.now(timezone.utc)}, synchronize_session=False)
    if commit:
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


def begin_pending(db, result: SignInResult, stage: str, *, enrollment_required: bool = False,
                  enrollment_methods=None, passkey_required: Optional[bool] = None) -> PendingStep:
    """Hold ``result`` for one more step. The pre-authentication token carries ``stage``, the pending
    login's id, the proofs so far and the provider; it has no ``session_token``, which is the confinement
    (the session dependency, the monitor handshake and the sign-out route each refuse a token without
    one). A pending login this result was continuing is spent first.

    The body is the pending answer the web app knows (``second_factor_required`` means a step follows),
    plus ``stage`` and, for an enrollment, what may be enrolled. The password stage names the account so
    the page can ask for the password alone. ``passkey_required``, for an enrollment that offers a passkey: whether
    the account's role must hold one (True), or the passkey is one way to meet the second factor asked for (False).
    """
    from app.api import api_server as api
    if stage not in STAGES:
        raise ValueError(f"not a pending stage: {stage!r}")
    user = result.user
    # In the account's turn, in one transaction: the sign-in judged again, the pending login it continued spent,
    # the new one written.
    in_the_accounts_turn(db, result)
    if result.pending is not None:
        consume_pending(db, result.pending, commit=False)
    pending = PendingLogin(user_id=user.id, client_ip=result.client_ip, enrollment_required=enrollment_required,
                           expires_at=datetime.now(timezone.utc) + timedelta(minutes=PRE_AUTH_TTL_MINUTES))
    db.add(pending)
    db.commit()
    claims = {"sub": str(user.id), "username": user.username, "stage": stage, "pre_auth": str(pending.id),
              "methods_so_far": list(result.methods), "ended": result.sessions_ended}
    if result.provider_id:
        claims["idp"] = result.provider_id
        if result.provider_sid:
            claims["idp_sid"] = result.provider_sid
        if result.provider_sub:
            claims["idp_sub"] = result.provider_sub
        if result.provider_answered_at is not None:
            claims["idp_at"] = result.provider_answered_at
        if result.provider_auth_time is not None:
            claims["idp_auth_time"] = int(result.provider_auth_time.timestamp())
        if result.provider_logout_hint:
            # The provider's logout hint waits for the step that completes the sign-in, encrypted, for the pending
            # login's life; a store that cannot take it costs the provider's own logout, nothing else.
            try:
                from app.core import sso_state
                from app.core.security import encrypt_secret
                sso_state.stage_logout_hint(str(pending.id), encrypt_secret(result.provider_logout_hint),
                                            PRE_AUTH_TTL_MINUTES * 60)
            except Exception:  # noqa: BLE001
                pass
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
        "enrollment_methods": (list(enrollment_methods) if enrollment_methods is not None
                               else list(ENROLLMENT_METHODS)) if enrollment_required else [],
        "pre_auth_token": token,
    }
    if stage == STAGE_PASSWORD:
        body["username"] = user.username
    if enrollment_required:
        # An account that holds passkeys and sets a factor up all the same is told why.
        why = api._why_a_factor_is_set_up_again(db, user)
        if why:
            body["set_up_again"] = why
    if passkey_required is not None:
        body["passkey_required"] = bool(passkey_required)
    return PendingStep(stage=stage, body=body)


# The reason an account that signs in only through its identity provider is refused at a door that is not the
# provider: the password door (app/services/auth_service.py) and every other first proof here record the same text.
PROVIDER_ONLY_REASON = "Account signs in only through its identity provider"
# The audit's reason for a provider sign-in that was not finished because its provider was turned off, or the
# account unlinked from it, while the sign-in was under way.
PROVIDER_GONE_REASON = "The identity provider was turned off or unlinked before the sign-in finished"
PROVIDER_LOGGED_OUT_REASON = "The identity provider logged the person out before the sign-in finished"
LOGOUT_MEMORY_REASON = ("The sign-in began before the vault's memory of the provider's logouts does (the store was "
                        "emptied meanwhile)")
# The audit's reason for a passkey used by itself on an account whose password nobody knows: the key was set up on
# the provider's sign-in alone and confirms the person after it.
KEY_AFTER_THE_PROVIDER_REASON = "Passkey of an account without a password of its own, used without its identity provider"
# The audit's reason for a good proof refused because the account's sign-in through its provider has lapsed, or the
# provider refused the person, and the provider closes the other ways in then (app/services/sso_freshness.py).
PROVIDER_DUE_REASON = "A sign-in through the identity provider is due; nothing else signs the account in until then"


def refuse_without_the_provider(db, result: SignInResult) -> None:
    """Refuse a sign-in that did not come through a provider for an account whose way in is its provider: one audit
    row, nothing counted (the proof was good), and :class:`ProviderOnly`. A sign-in that came through the provider
    carries it in ``provider_id`` (also at the second step, from the pending login), so the account's passkey still
    serves as its second factor there.

    Three kinds of account. One that signs in only through its provider (``users.sso_only``): whatever the proof.
    One whose sign-in through its provider has lapsed, or that the provider refused, where the provider closes the
    other ways in then (app/services/sso_freshness.py held_to_a_provider): whatever the proof, until it has signed
    in through the provider again. And one whose password nobody knows (made at a first provider sign-in, say: app/core/password_origin.py), when
    a passkey is the proof (no password can be among its proofs). Such an account can type no password, so nothing
    but its provider's sign-in stood behind the key when it was set up (Your account asks it for a fresh sign-in
    there, and so does the enrollment at a sign-in). A key set up on the provider's word alone does not outlive
    that word: by itself it would sign in after the provider refused the person, after the time without a sign-in
    there ran out, and after the provider was turned off, none of which a passkey's own sign-in looks at. A
    password of the account's own (set with a reset link) ends the mark, and the key signs in by itself as
    anybody's does."""
    user = result.user
    if result.is_temporary or result.provider_id:
        return
    from app.core import password_origin
    methods = set(result.methods)
    passkey = bool(methods & PASSKEYS)
    provider_only = bool(getattr(user, "sso_only", False))
    key_alone = passkey and password_origin.nobody_knows(user)
    due = None
    if not (provider_only or key_alone):
        from app.services import sso_freshness
        due = sso_freshness.held_to_a_provider(db, user)
        if due is None:
            return
    from app.api import api_server as api
    from app.core import sso_only
    if due is not None:
        message, reason = sso_freshness.way_in_text(db, due), PROVIDER_DUE_REASON
    elif provider_only:
        message, reason = sso_only.provider_only_message(db, user), PROVIDER_ONLY_REASON
    else:
        message, reason = sso_only.passkey_after_the_provider_message(db, user), KEY_AFTER_THE_PROVIDER_REASON
    try:
        api.AuditLogger(db).log_login_failure(
            user.username, result.client_ip, reason,
            account=user, login_identifier="passkey" if passkey else "username")
    except Exception:  # noqa: BLE001 -- the refusal stands without its row
        db.rollback()
    # A session the proof made (the password door writes its own) does not outlive the refusal.
    drop_the_session_the_proof_made(db, result)
    raise ProviderOnly(message)


def hold_the_providers_row(db, result: "SignInResult") -> None:
    """Read the row of the provider ``result`` came through again, under a share lock kept until the transaction
    ends: the second of the locks in their order, before the account's turn at its sessions. Nothing for a
    sign-in that came through none. A row another transaction holds for itself longer than a sign-in waits where
    it is written (:func:`with_a_short_wait`; a save that settles many accounts) refuses the sign-in as busy, with
    nothing written."""
    if result.is_temporary or not result.provider_id:
        return
    import uuid
    from sqlalchemy.exc import OperationalError
    from app.core.models import SsoProvider
    from app.core.table_presence import has_table
    try:
        provider_id = uuid.UUID(str(result.provider_id))
    except ValueError:
        return                                     # not a provider's id at all: refused where the provider is judged
    if not has_table(db, SsoProvider.__tablename__):
        return
    try:
        with_a_short_wait(db, lambda: db.query(SsoProvider).filter(SsoProvider.id == provider_id)
                          .populate_existing().with_for_update(read=True).first())
    except OperationalError as held:
        if getattr(getattr(held, "orig", None), "pgcode", None) != "55P03":      # lock_not_available
            raise
        db.rollback()
        drop_the_session_the_proof_made(db, result)
        raise provider_busy() from None


def refuse_unless_the_provider_stands(db, result: SignInResult) -> None:
    """A sign-in that came through a provider is finished only while that provider is on and the account is still
    linked to it by the identity the sign-in came through (an identity unlinked meanwhile, and another linked on the
    same provider since, does not finish it). The provider's answer was taken at the callback; the handover code lives a minute after it and
    a held step (the account's second factor, an administrator's password, an enrollment) five. An administrator
    who turns the provider off in that time, or a change to its connection that does, ends the sign-ins under way
    with it: without this each would still become a session, and would stamp its identity as freshly signed in."""
    if result.is_temporary or not result.provider_id:
        return
    stands, reason = False, PROVIDER_GONE_REASON
    try:
        import uuid
        from app.core.models import ExternalIdentity, SsoProvider
        provider_id = uuid.UUID(str(result.provider_id))
        # Both as they are committed, not as this request first loaded them: the check is made again in the
        # account's turn, after a wait in which either may have changed.
        row = db.query(SsoProvider).filter(SsoProvider.id == provider_id).populate_existing().first()
        if row is not None and getattr(row, "state", None) == "enabled":
            from app.services import sso_sign_in
            identity = (db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == provider_id,
                                                          ExternalIdentity.user_id == result.user.id)
                        .populate_existing().first())
            stands = identity is not None and sso_sign_in.same_identity(identity, result.provider_sub)
            if stands and logged_out_at_the_provider(row, result):
                stands, reason = False, PROVIDER_LOGGED_OUT_REASON
            elif stands and begun_before_the_logout_memory(row, result):
                stands, reason = False, LOGOUT_MEMORY_REASON
    except ValueError:
        stands = False                  # not a provider's id at all
    if stands:
        return
    from app.api import api_server as api
    try:
        api.AuditLogger(db).log_login_failure(result.user.username, result.client_ip, reason,
                                              account=result.user, login_identifier="sso")
    except Exception:  # noqa: BLE001 -- the refusal stands without its row
        db.rollback()
    raise HTTPException(status_code=401, detail="This sign-in cannot be completed; start again.")


def logged_out_at_the_provider(row, result: SignInResult) -> bool:
    """Whether the provider has said, by a back-channel logout the vault took after this sign-in was begun, that
    the session the sign-in came through, or the person, is logged out (app/api/sso_router.py backchannel_logout).
    Finished all the same, the sign-in would record the provider's session on a new vault session, and no later
    logout would name it. A sign-in begun after the logout is a new one, whatever session id it carries (a
    provider may keep one): it is not refused. One that does not say when it was begun is taken as begun
    before. Asked only where the provider's logouts are taken. A store that cannot be reached refuses
    the sign-in as busy: whether the person was logged out cannot be told."""
    pending = result.pending
    sid = result.provider_sid or getattr(pending, "_provider_sid", None)
    sub = result.provider_sub or getattr(pending, "_provider_sub", None)
    if not (isinstance(sid, str) and sid) and not (isinstance(sub, str) and sub):
        return False
    from app.core import sso_state
    from app.services import sso_sign_in
    if not sso_sign_in.policy_of(row)["sso_backchannel_logout"]:
        return False
    try:
        since = sso_state.logged_out_since(scope=str(row.id), sid=sid, sub=sub)
    except sso_state.Unavailable:
        raise provider_busy() from None
    if since is None:
        return False
    answered = result.provider_answered_at
    if answered is None:
        answered = getattr(pending, "_provider_answered_at", None)
    if not isinstance(answered, (int, float)) or isinstance(answered, bool):
        return True
    return answered <= since


def carry_provider_session(result: SignInResult) -> None:
    """A step that finishes a provider's sign-in (the second factor, a passkey, an enrollment, the password) records
    the provider's session the pending login carries: its session id and subject (so the provider's back-channel
    logout finds the session), its authentication time and the logout hint. Filled here for every route, so none
    can forget; a field the route set itself is kept."""
    if result.pending is None or not result.provider_id:
        return
    for name, value in provider_session_of(result.pending).items():
        if getattr(result, name, None) is None and value is not None:
            setattr(result, name, value)


@a_refusal_leaves_no_session
def finish(db, result: SignInResult):
    """Finish a sign-in or hold it for its next step: a :class:`SignedIn` or a :class:`PendingStep`.

    A step that follows deletes the session the proof made (none may exist before the sign-in is
    whole) and records that the password was accepted when it was one of the proofs.
    """
    from app.api import api_server as api
    user = result.user
    carry_provider_session(result)
    enrollment_methods = []
    if result.is_temporary:
        stage = DONE
    else:
        refuse_unless_the_account_may_sign_in(db, user, result.client_ip)
        refuse_without_the_provider(db, result)
        refuse_unless_the_provider_stands(db, result)
        if result.provider_id and result.provider_mfa_trusted:
            # Taken at the provider's answer, up to a minute ago (a handover code) or five (a held step): the
            # account may hold a factor of its own since, or owe one. Judged again as the account stands now.
            from app.services import sso_sign_in
            result.provider_mfa_trusted = sso_sign_in.provider_mfa_still_counts(db, result)
        in_effect = api._login_second_factor_in_effect(db, user)
        enrollment_pending = bool(in_effect) and api._second_factor_effective(db, user)["state"] == "pending"
        # A role that must hold a passkey: the grace runs from the first sign-in under the requirement; past it the
        # sign-in stops at the enrollment (a user-verified passkey meets a pending authenticator enrollment too).
        passkey = api._passkey_requirement(db, user)
        enrollment_methods = list(ENROLLMENT_METHODS) if enrollment_pending else []
        own_factor_first = False
        passkey_required = None
        if passkey.paused:
            result.passkey_grace = GRACE_ENDS
        elif not passkey.required and getattr(user, "passkey_required_since", None) is not None:
            # The requirement is met again by a passkey the account holds (one made at an address the vault went
            # back to, or of an algorithm that is accepted again). The day the requirement began, written while it
            # was not met, ends here: should the account's last passkey leave it later, its time to set one up
            # starts over, as it does when a key is registered.
            from app.core import webauthn_settings
            if webauthn_settings.usable_passkeys(db, user.id) > 0:
                result.passkey_grace = GRACE_ENDS
        if passkey.required:
            result.passkey_grace = GRACE_BEGINS
            # A hold made for an enrollment offers the passkey the role must hold. Whenever such a hold is made the
            # registration takes it: an account that owes its password first (a provider's sign-in of an account
            # that has one it can type) is held at the password stage before any enrollment, below.
            enrollment_methods.append("passkey")
            passkey_required = True
            if passkey.overdue:
                # A passkey outlives whatever proved the sign-in it was set up at (it signs in after a provider
                # was turned off, an identity unlinked), so it is added on no less than Your account asks for the
                # same act. An account that holds a factor of its own gives that factor first, whatever the login
                # switch says, and a provider's trusted MFA does not stand in for it here. An account with none
                # enrolls after its first proof, as a required authenticator is enrolled; where that proof was a
                # provider and the account has a password it can type, the password comes first.
                in_effect = True
                if holds_a_factor(db, user):
                    own_factor_first = True
                else:
                    enrollment_pending = True
        elif a_passkey_meets_the_enrollment(user):
            # No role asks for a passkey. Where a second factor is to be set up (the list is read only then), this
            # account has nothing but its provider's sign-in to give: a passkey is offered beside the authenticator
            # (it serves after the provider's sign-in, as the authenticator's code does: refuse_without_the_provider).
            enrollment_methods.append("passkey")
            passkey_required = False
        # An account with no factor sets its first one up on the proof Your account asks for the same act. Where the
        # sign-in came through a provider and the account has a password it can type, that password comes first: the
        # authenticator's enrollment asks for it, and after the round trip to the provider the page holds none to
        # send. An account with no password it can type goes on: the provider's sign-in is its proof
        # (provider_proves_an_enrollment).
        password_first = enrollment_pending and password_owed_before_an_enrollment(
            user, result.methods, result.provider_id)
        try:
            stage = second_factor_due(user, result.methods, factor_in_effect=bool(in_effect),
                                      enrollment_pending=enrollment_pending,
                                      passwordless_allowed=result.passwordless_allowed,
                                      user_verified=result.user_verified,
                                      provider_mfa_trusted=result.provider_mfa_trusted and not own_factor_first,
                                      provider_id=result.provider_id)
        except NoFirstProof:
            raise HTTPException(status_code=401, detail="This sign-in cannot be completed; start again.")
        if passkey.overdue and stage == DONE and not (set(result.methods) & PASSKEYS):
            # The table is done (the password with a code, a provider's trusted MFA, an account with no factor): the
            # passkey the role must hold is still missing, and past the grace the sign-in stops at its enrollment
            # whatever else was proved. A step the table still asks for (an administrator's password, the
            # account's own second factor) comes first.
            stage = ENROLL
        if password_first and stage == ENROLL:
            stage = STAGE_PASSWORD
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
        return begin_pending(db, result, STAGE_SECOND_FACTOR, enrollment_required=True,
                             enrollment_methods=enrollment_methods, passkey_required=passkey_required)
    return begin_pending(db, result, stage)


def holds_a_factor(db, user) -> bool:
    """Whether the account holds a second factor of its own right now: an authenticator or a passkey."""
    from app.core.active_factors import active_factors
    return active_factors(db, user.id).any


def has_a_password_it_can_type(user) -> bool:
    """Whether somebody can type the account's password: it has one, it does not sign in only through its provider
    (such an account's password works nowhere: app/core/sso_only.py), and the password is not one nobody knows
    (random bytes set when the account was made at a provider's sign-in, say: app/core/password_origin.py)."""
    from app.core import password_origin
    return (bool(getattr(user, "password_hash", None)) and not getattr(user, "sso_only", False)
            and not password_origin.nobody_knows(user))


def password_owed_before_an_enrollment(user, methods, provider_id) -> bool:
    """Whether a sign-in that came through a provider owes the account's password before it sets a second factor
    up (a passkey, an authenticator): the password is not among its proofs, and the account has one it can type.
    An account that signs in only through its provider has none; its passkey signs nobody in without the provider,
    so the provider is proof enough. An account whose password nobody knows has none it can type either: asked
    for it, it could never answer, and would be shut out by the requirement."""
    if not provider_id or PASSWORD in set(methods or ()):
        return False
    return has_a_password_it_can_type(user)


def provider_proves_an_enrollment(user, pending) -> bool:
    """Whether a sign-in held for an enrollment is itself the proof the authenticator's enrollment asks for, in
    place of the account's password: it came through a provider, and the account has no password it can type.
    The other side of :func:`password_owed_before_an_enrollment`, for the one enrollment that asks for the
    password in its own request. The provider's sign-in is all such an account can give, and what it sets up
    serves after that sign-in only (a code is never a first proof)."""
    return pending is not None and bool(provider_of(pending)) and not has_a_password_it_can_type(user)


def a_passkey_meets_the_enrollment(user) -> bool:
    """Whether a sign-in held for the enrollment of a second factor is offered a passkey beside the authenticator
    where no role must hold one: the account has no password it can type (its sign-ins come through its provider),
    and a passkey can be made at the vault's address now. An account with a password is offered what the policy's
    enrollment has always offered it, and adds a passkey under Your account."""
    from app.core import webauthn_settings
    return (not has_a_password_it_can_type(user)
            and webauthn_settings.enabled() and webauthn_settings.passkeys_can_be_made())


def refuse_enrollment_before_the_accounts_factor(db, user, pending) -> None:
    """A held sign-in sets a passkey up only on what Your account asks for the same act: an account that holds a
    second factor gives that factor first (a provider's trusted MFA does not stand in for it: the passkey would
    outlive the provider), and an account with none, signed in through a provider, gives its password first when
    it has one it can type. The pipeline makes no enrollment hold that skips either; this refuses one at the
    registration routes all the same, whatever made the token."""
    if pending is None:
        return
    methods = set(methods_so_far(pending))
    if holds_a_factor(db, user):
        if methods & SECOND_KINDS:
            return
        raise HTTPException(status_code=401, detail="Confirm your second factor first; start the sign-in again.")
    if password_owed_before_an_enrollment(user, methods, provider_of(pending)):
        raise HTTPException(status_code=401, detail="Enter your password first; start the sign-in again.")


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


# What of the account the refusals below read: read again in the turn, where a factor is about to be written.
ACCOUNT_STATE_A_FACTOR_IS_JUDGED_ON = ("sso_only", "is_active", "is_locked", "locked_until")


def refuse_a_factor_the_sign_in_could_not_finish(db, user, pending, client_ip: Optional[str]) -> None:
    """On a held sign-in, before a factor is stored or made active for the account: refuse what :func:`finish`
    refuses. It is asked there only after the factor stands, and a factor outlives the sign-in it was set up at:
    one stored for an account that was locked or turned off while its enrollment was open would stay after the
    refusal, and so would one stored after the provider the sign-in came through was turned off, or the account
    unlinked from it (a passkey signs in by itself afterwards, without the provider). With a session there is
    nothing to ask here: the session is the account's own.

    The account's turn at its sessions is taken first, and the held sign-in is read again in it. What ends the
    account's sessions spends its sign-ins under way in that same turn (:func:`spend_sign_ins_under_way`), and a
    change of its factors takes the turn before it reads them. So the factor is written wholly before such a
    change, which then finds it (a reset retires it, a removal counts it), or not at all: without the turn, a
    change that fell between the check of the token and the write left a factor set up on a proof the change had
    just ended.

    The wait for the turn is the short one of a sign-in where it is written (:func:`with_a_short_wait`): the
    routes that set a factor up run on the server's one loop, as a sign-in does. A change that settles many
    accounts at once holds each account's turn until it commits; waited for with the connection's own wait, every
    other request stood still meanwhile, and the wait ended in an error that said nothing. A turn still held is
    answered as a sign-in is: busy, try again in a moment. Nothing was written, and the held sign-in stays."""
    if pending is None:
        return
    from sqlalchemy.exc import OperationalError
    from app.api import api_server as api
    held = SignInResult(user, methods_so_far(pending), client_ip, pending=pending, provider_id=provider_of(pending),
                        provider_mfa_trusted=provider_mfa_of(pending), sessions_ended=ended_of(pending),
                        provider_sub=getattr(pending, "_provider_sub", None))
    # The provider's row before the turn, as where the sign-in is written (the order of the locks): the session
    # that follows the factor is written in this same turn, and takes the row it already holds.
    hold_the_providers_row(db, held)
    try:
        with_a_short_wait(db, lambda: api._sessions_turn(db, user.id))
    except OperationalError as waited:
        if getattr(getattr(waited, "orig", None), "pgcode", None) != "55P03":      # lock_not_available
            raise
        db.rollback()
        from app.core import sign_in_lockout
        raise HTTPException(status_code=503, detail=BUSY,
                            headers={"Retry-After": str(sign_in_lockout.BUSY_RETRY_SECONDS)}) from None
    on_record = db.query(PendingLogin.consumed_at).filter(PendingLogin.id == pending.id).first()
    if on_record is None or on_record[0] is not None:
        raise HTTPException(status_code=401, detail="This login attempt has expired; start again.")
    # The account as it is committed, read in the turn. A lock or a turning-off spends the held sign-in, which
    # the read above sees. A provider's save that makes the account sign in only through the provider ends the
    # sessions a password made and spends no sign-in under way: judged on the account as it was loaded before
    # the turn, a factor was stored at a password's hold of an account made provider-only in that moment, and
    # stayed on it after the sign-in itself was refused.
    from app.core import sso_only
    sso_only.read_again(db, user, ACCOUNT_STATE_A_FACTOR_IS_JUDGED_ON)
    refuse_unless_the_account_may_sign_in(db, user, client_ip)
    refuse_without_the_provider(db, held)
    refuse_unless_the_provider_stands(db, held)


def begun_before_the_logout_memory(row, result: SignInResult) -> bool:
    """Whether this sign-in through ``row`` was begun before the vault's memory of the provider's logouts is whole
    (app/core/sso_state.logout_memory_reaches). The memory lives in the store's own memory: emptied (an update or
    a restart of the host makes its container anew), it has lost a logout the vault took while the sign-in was
    held at a step, and the provider does not send it again. Finished all the same, the sign-in made a session
    for the provider's session that was logged out. So a sign-in the memory does not cover from its start is
    refused, and the person starts again: the cost of a store emptied while a sign-in was under way. Asked only
    where the provider's logouts are taken, and of a sign-in that says when it was begun. A store that cannot be
    reached refuses the sign-in as busy."""
    pending = result.pending
    sid = result.provider_sid or getattr(pending, "_provider_sid", None)
    sub = result.provider_sub or getattr(pending, "_provider_sub", None)
    if not (isinstance(sid, str) and sid) and not (isinstance(sub, str) and sub):
        return False
    from app.core import sso_state
    from app.services import sso_sign_in
    if not sso_sign_in.policy_of(row)["sso_backchannel_logout"]:
        return False
    begun = result.provider_answered_at
    if begun is None:
        begun = getattr(pending, "_provider_answered_at", None)
    if not isinstance(begun, (int, float)) or isinstance(begun, bool):
        return False
    try:
        return begun < sso_state.logout_memory_reaches()
    except sso_state.Unavailable:
        raise provider_busy() from None


def complete_sign_in(db, result: SignInResult) -> SignedIn:
    """Make the session and the token, and the records every sign-in makes.

    The token carries what it always did (``sub``, ``username``, ``session_token``, ``is_temporary``) plus
    ``amr`` (the proofs), ``auth_time``, ``mfa_at`` when two kinds of factor were present, and ``idp`` for
    a single sign-on. Every sign-in gets a ``sign_in_id`` of its own, made here and never taken from a
    provider: a renewal keeps it, so a page can tell a renewal of its own sign-in from another sign-in of the
    same person even when both share one time (two sign-ins may complete in the same second). ``auth_time`` is
    the moment the sign-in completed here, never a time a provider reports: the renewal limit counts from it.
    A regular session honours the session-timeout setting; a temporary credential keeps the default token
    life, its own validity window being enforced separately.
    """
    from app.api import api_server as api
    from app.services.auth_service import AuthService
    user = result.user
    # In the account's turn, in one transaction: the sign-in judged again, its pending login spent, the session
    # written, and the account's last sign-in stamped (the one the Users page shows and a dormant-account rule
    # reads: every door stamps it here). One commit, so nothing sees a part of it.
    in_the_accounts_turn(db, result)
    if result.pending is not None:
        consume_pending(db, result.pending, commit=False)
    session_token = result.session_token
    if not session_token:
        auth = AuthService(db)
        session_token = auth._create_session(
            user, None, result.client_ip, expires_at=datetime.now(timezone.utc) + SESSION_ROW_LIFETIME,
            channel=auth.WEB, commit=False)
    now = datetime.now(timezone.utc)
    user.last_login = now
    # With the session, in the one transaction: what turns the provider off, or logs the person out at the
    # provider, waits for this commit and then finds the session by this record. Written after it, a session
    # could be live for a moment with nothing to find it by, and that moment is the one such a change wakes in.
    _record_provider_session(db, result, session_token)
    db.commit()
    claims = {
        "sub": str(user.id), "username": user.username, "session_token": session_token,
        "is_temporary": result.is_temporary, "amr": list(result.methods),
        # When this sign-in completed at the vault: what the renewal limit counts from, whichever door was used.
        "auth_time": int(now.timestamp()),
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


def _record_provider_session(db, result: SignInResult, session_token: Optional[str]) -> None:
    """A session signed in through a provider remembers the provider's session id and subject (so the provider's
    back-channel logout, and a turn-off of the provider, find it) and, when the provider logout option is on, the
    ID token encrypted. In the caller's transaction, with the session itself: the session is not there without
    the record that finds it. The logout hint is a convenience; one that cannot be sealed is left out."""
    if not result.provider_id or not session_token:
        return
    import uuid
    from app.core.models import ActiveSession, SsoSession
    try:
        provider_id = uuid.UUID(str(result.provider_id))
    except ValueError:
        return                     # not a provider's id at all: refused where the provider is judged
    flush = getattr(db, "flush", None)
    if flush is not None:
        flush()                    # the session written a moment ago, in this transaction, is read below
    row = db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(session_token)).first()
    if row is None:
        return
    at = result.provider_auth_time or datetime.now(timezone.utc)
    auth_time = at.astimezone(timezone.utc).replace(tzinfo=None) if at.tzinfo else at
    sealed = None
    if result.provider_logout_hint:
        try:
            from app.core.security import encrypt_secret
            sealed = encrypt_secret(result.provider_logout_hint)
        except Exception:  # noqa: BLE001 -- the provider's own logout is then not offered at the sign-out
            sealed = None
    db.add(SsoSession(session_id=row.id, provider_id=provider_id,
                      idp_sid=(result.provider_sid or None), idp_sub=(result.provider_sub or None),
                      auth_time=auth_time, id_token_enc=sealed))


def forget_provider_logout_hints(db, session_ids) -> int:
    """Drop the provider logout hints (the encrypted ID tokens) kept for the given sessions: a session that has
    ended has no provider logout to make, and the token's claims are personal data. In the caller's transaction;
    returns how many rows changed."""
    from sqlalchemy.sql import Select
    from app.core.models import SsoSession
    if isinstance(session_ids, Select):
        named = SsoSession.session_id.in_(session_ids)           # sessions chosen by a query, in one statement
    else:
        ids = [i for i in session_ids if i is not None]
        if not ids:
            return 0
        named = SsoSession.session_id.in_(ids)
    if not table_present(db, "sso_sessions"):
        return 0
    return db.query(SsoSession).filter(named, SsoSession.id_token_enc.isnot(None)).update(
        {SsoSession.id_token_enc: None}, synchronize_session=False)


import weakref as _weakref

_TABLES_PRESENT: "_weakref.WeakKeyDictionary" = _weakref.WeakKeyDictionary()


def table_present(db, name: str) -> bool:
    """Whether the database has the table ``name``: a database built with only the tables a test needs may not, and
    a query there would fail (and abort a real transaction). A stand-in with no engine answers for itself. Asked on
    the session's own connection (no second connection from the pool); remembered per engine, without keeping the
    engine alive, once found."""
    get_bind = getattr(db, "get_bind", None)
    if get_bind is None:
        return True
    bind = get_bind()
    engine = getattr(bind, "engine", bind)
    try:
        known = _TABLES_PRESENT.get(engine)
    except TypeError:                                  # an engine that cannot be weakly referenced: ask every time
        known = None
    if known is not None and name in known:
        return True
    from sqlalchemy import inspect
    connection = db.connection() if hasattr(db, "connection") else bind
    if inspect(connection).has_table(name):
        try:
            _TABLES_PRESENT.setdefault(engine, set()).add(name)
        except TypeError:
            pass
        return True
    return False


def _stamp_identity(db, result: SignInResult) -> None:
    """A provider sign-in that is now a session: the identity it came through records the time."""
    if not result.provider_id:
        return
    try:
        import uuid
        from app.core.models import ExternalIdentity
        provider_id = uuid.UUID(str(result.provider_id))
    except (ImportError, ValueError):
        return
    try:
        db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == provider_id,
                                          ExternalIdentity.user_id == result.user.id).update(
            {"last_sign_in_at": datetime.utcnow()}, synchronize_session=False)
        db.commit()
    except Exception:  # noqa: BLE001 -- the stamp is a record, never a refusal
        db.rollback()


def _record(db, result: SignInResult, api) -> None:
    _stamp_identity(db, result)
    """The records of a finished sign-in, the same for every method. Each is best-effort: a sign-in
    that is whole must not fail on its own telemetry."""
    user = result.user
    client_ip = result.client_ip
    try:
        # A sign-in through a provider names it, and whether its second factor counted for the vault's.
        through = ({"provider_id": str(result.provider_id), "provider_mfa": bool(result.provider_mfa_trusted)}
                   if result.provider_id else {})
        api.AuditLogger(db).log_login_success(user, client_ip, is_temporary=result.is_temporary,
                                              methods=list(result.methods), **through)
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

    1. A refusal comes before anything changes (the renewal rules, then the rules of the other ways in,
       ``refuse_renewal_by_the_sign_in_rules``): the session is left as it was, to run out on its own.
    2. The renewal takes the account's turn at its sessions (``_sessions_turn``, which every revocation of an
       account's sessions takes too) and reads the old session under it, locked. A session that has ended, or is
       not this account's, is refused here with nothing made.
    3. In that same transaction the new session row is made, what the old one remembers of an identity
       provider's sign-in moves to it (``carry_renewed_provider_session``) and the old one is ended, all committed
       together. Nothing sees the old session ended with the new one not yet there, or the new one while the old
       still stands. A revocation of the account's sessions (a password change, a sign-out everywhere) comes wholly
       before the renewal, which then finds its session ended and makes nothing, or wholly after it, and ends the
       new session. Of two requests with the same token, one takes the turn first and the other finds the session
       ended: a replay carries a dead token and leaves nothing. A crash before the commit leaves nothing either.
    4. The old token is refused for the rest of its own life, what the person proved in the old session is carried
       to the new one, the new token is minted (it exists only in this answer) and the renewal is recorded
       (``session_extended``).
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
    refuse_renewal_by_the_sign_in_rules(db, user, old)
    ended_already = HTTPException(status_code=401, detail="This session has already ended.")
    user_id = user.id
    try:
        api._sessions_turn(db, user_id)
        old_row = (db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(old_session))
                   .populate_existing().with_for_update().first())
        if old_row is None or str(old_row.user_id) != str(user_id) or old_row.revoked:
            raise ended_already
        auth = AuthService(db)
        new_session = auth._create_session(user, None, client_ip, expires_at=now + SESSION_ROW_LIFETIME,
                                           channel=auth.WEB, commit=False)
        carry_renewed_provider_session(db, old_row, new_session)
        # Ends the old session and commits: the new session and the old one's end become visible together.
        _row, ended = api._end_web_session(db, old_session, user_id=user_id)
    except BaseException:
        db.rollback()
        raise
    if not ended:
        # Not reachable while the turn and the row are held. A session is never left without its token.
        api._end_web_session(db, new_session, user_id=user_id)
        raise ended_already
    ttl = int(old.get("exp", 0) - time.time())
    denylist_token(old_session, ttl if ttl > 0 else 1800)
    api._carry_session_marks(db, old_row, new_session)
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


def refuse_renewal_by_the_sign_in_rules(db, user, old: dict) -> None:
    """A renewal keeps a sign-in going, so it is refused when signing in now would not end where that sign-in did:
    the person signs in again and meets the rule there. The renewal rules refuse an account that now needs a second
    factor its token does not show; this adds the rules of the other ways in. Raises HTTPException(403) with the
    sentence the sign-in screen shows; nothing has changed by then.

    A session made without the password (the token's ``amr`` names none): an administrator always types the
    password, so the session of an account promoted since is not renewed; and a passkey alone is the whole sign-in
    only for a person the policy lets in without the password, so a session a passkey made on its own is not renewed
    once the role left the passwordless roles or the account was given the auditor right. Nor is it for an
    account whose password nobody knows: its passkey signs in after its provider only
    (:func:`refuse_without_the_provider`), and a session the key made alone, before the account came to hold such
    a password, is not kept going past that. A token from before the proofs were written on it names none and
    was made with the password: it is read as one.

    A role that must hold a passkey, past its grace, with none on the account: the next sign-in stops at the
    enrollment, so the renewal is refused, whatever the old token shows (a passkey it was made with is gone).

    An account that signs in only through its identity provider, with a session that did not come through one
    (made before the account became provider-only): refused, with what to use instead. A session that came through
    a provider (the token's ``idp``) is renewed only while that sign-in could be made again: the identity still
    linked, the provider turned on, no refusal by the provider in force and its freshness window not run out
    (``sso_sign_in.renewal_refusal``).

    An account whose sign-in through its provider has lapsed, where the provider closes the other ways in then
    (``sso_freshness.held_to_a_provider``), with a session that came through no provider: refused, with what to
    use instead. Signing in again now would be refused the same way."""
    from app.api import api_server as api
    methods = proofs_of(old)
    if PASSWORD not in methods:
        if getattr(user, "role", None) == RoleEnum.ADMIN:
            raise HTTPException(status_code=403, detail="Administrators sign in with their password. Sign in again.")
        if (methods & PASSKEYS) and not old.get("idp") and not api._passkey_passwordless_allowed(db, user):
            raise HTTPException(status_code=403, detail=(
                "A passkey alone no longer signs you in. Sign in again with your password."))
        if (methods & PASSKEYS) and not old.get("idp"):
            from app.core import password_origin
            if password_origin.nobody_knows(user):
                from app.core import sso_only
                raise HTTPException(status_code=403, detail=sso_only.passkey_after_the_provider_message(db, user))
    if api._passkey_requirement(db, user).overdue:
        raise HTTPException(status_code=403, detail=(
            "Your role must hold a passkey now. Sign in again: you will be asked to add one."))
    provider_id = old.get("idp")
    if not provider_id:
        if getattr(user, "sso_only", False):
            from app.core import sso_only
            raise HTTPException(status_code=403, detail=sso_only.provider_only_message(db, user))
        from app.services import sso_freshness
        due = sso_freshness.held_to_a_provider(db, user)
        if due is not None:
            raise HTTPException(status_code=403, detail=sso_freshness.way_in_text(db, due))
        return
    from app.services import sso_sign_in
    sentence = sso_sign_in.renewal_refusal(db, user, provider_id, methods=old.get("amr") or (),
                                           subject=provider_subject_of_session(db, old.get("session_token")))
    if sentence:
        raise HTTPException(status_code=403, detail=sentence)


def provider_subject_of_session(db, session_token: Optional[str]) -> Optional[str]:
    """The identity a session came through at its provider (``sso_sessions.idp_sub``), or None when the session has
    no such record."""
    if not session_token or not table_present(db, "sso_sessions"):
        return None
    from app.core.models import ActiveSession, SsoSession
    row = db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(session_token)).first()
    if row is None:
        return None
    kept = db.query(SsoSession).filter(SsoSession.session_id == row.id).first()
    return (getattr(kept, "idp_sub", None) or None) if kept is not None else None


def carry_renewed_provider_session(db, old_row, new_session: str) -> None:
    """The new session of a renewal takes over what the old one remembers of the provider's sign-in: the provider's
    session id and subject (so the provider's back-channel logout finds the new session), its authentication time
    and the logout hint, which the old session gives up (once ended it makes no provider logout). Written in the
    renewal's own transaction and not committed here: the record moves with the session, so a logout that names
    the provider's session finds the live one, whichever of the two that is. Raises when the record is there and
    cannot be copied: the renewal fails as a whole and the old session stands."""
    if old_row is None or not table_present(db, "sso_sessions"):
        return
    from app.core.models import ActiveSession, SsoSession
    kept = db.query(SsoSession).filter(SsoSession.session_id == old_row.id).first()
    if kept is None:
        return
    new_row = db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(new_session)).first()
    db.add(SsoSession(session_id=new_row.id, provider_id=kept.provider_id, idp_sid=kept.idp_sid,
                      idp_sub=kept.idp_sub, auth_time=kept.auth_time, id_token_enc=kept.id_token_enc))
    kept.id_token_enc = None
    db.flush()


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
