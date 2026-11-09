"""The login state of a single sign-on that is under way, and the cap on abandoned ones.

A start writes one record under ``sso:state:<state>`` (``state`` is 32 random bytes, base64url) for ten minutes:
the provider, the purpose, the nonce and the PKCE verifier the callback must present to the provider, what the
tab or app must later prove (the verifier's hash, or a PKCE challenge), the account and session a ``link``,
``test`` or ``step_up`` purpose belongs to, where to return, when and from where it started. The callback reads it
with ``GETDEL``: one use, whatever follows.

Offices share one egress address, so the abuse cap counts **abandoned** starts, not starts: each start is filed
under its source address (``sso:started:<source>``, a sorted set by time); a callback removes its entry; what is
left older than a state's life and younger than an hour is abandoned, and above 200 of those a start is refused.
Without the store every step fails closed; nothing falls back to the database.
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

STATE_TTL_SECONDS = 600
ABANDONED_WINDOW_SECONDS = 3600
ABANDONED_LIMIT = 200
KEY_PREFIX = "sso:state:"
STARTED_PREFIX = "sso:started:"
# A finished link or test, waiting for the tab and session that started it to claim it (one use, a minute).
HANDOVER_PREFIX = "sso:handover:"
HANDOVER_TTL_SECONDS = 60
# A provider re-authentication the step-up route may spend once, within two minutes, for one action of one session.
REAUTH_PREFIX = "sso:reauth:"
REAUTH_TTL_SECONDS = 120
# A back-channel logout token's id, kept for the token's remaining life so it is honoured once.
LOGOUT_JTI_PREFIX = "sso:logout_jti:"

SIGN_IN = "sign_in"
LINK = "link"
TEST = "test"
STEP_UP = "step_up"
APP = "app"
PURPOSES = (SIGN_IN, LINK, TEST, STEP_UP, APP)

# Where the web app may be sent back to after a sign-in: its own views, never an address.
RETURN_TO = ("#vaults", "#shared", "#notes", "#profile", "#activity", "#temp-creds", "#users")
DEFAULT_RETURN_TO = "#vaults"
_MAX_STATE_LENGTH = 64


class Unavailable(Exception):
    """The state store cannot be reached: the sign-in is unavailable, never guessed."""


class TooManyAbandoned(Exception):
    """This address has left too many sign-ins unfinished in the last hour."""


def _redis(redis):
    if redis is not None:
        return redis
    from app.core.database import redis_client
    return redis_client


def _b64(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def return_to_or_default(value) -> str:
    """One of the app's own views, else the default: a return address is never an arbitrary string."""
    return value if isinstance(value, str) and value in RETURN_TO else DEFAULT_RETURN_TO


@dataclass
class LoginState:
    state: str
    provider_id: str
    purpose: str
    nonce: str
    code_verifier: str
    return_to: str = DEFAULT_RETURN_TO
    verifier_hash: Optional[str] = None          # the web app's tab verifier, hashed
    code_challenge: Optional[str] = None         # the desktop app's PKCE challenge
    user_id: Optional[str] = None                # link, test, step_up: the signed-in account
    session_hash: Optional[str] = None           # link, test, step_up: the session that started it
    step_up_action: Optional[str] = None
    client_ip: Optional[str] = None
    source: Optional[str] = None                 # the address's source key, for the abandoned count
    started_at: int = field(default_factory=lambda: int(time.time()))
    extras: dict = field(default_factory=dict)   # small, purpose-specific additions (an invitation token)

    @classmethod
    def from_payload(cls, data) -> Optional["LoginState"]:
        if not isinstance(data, dict):
            return None
        known = {f for f in cls.__dataclass_fields__}  # noqa: C416
        try:
            record = cls(**{k: v for k, v in data.items() if k in known})
        except TypeError:
            return None
        for name in ("state", "provider_id", "purpose", "nonce", "code_verifier", "return_to"):
            if not isinstance(getattr(record, name), str) or not getattr(record, name):
                return None
        if record.purpose not in PURPOSES:
            return None
        for name in ("verifier_hash", "code_challenge", "user_id", "session_hash", "step_up_action", "client_ip",
                     "source"):
            value = getattr(record, name)
            if value is not None and not isinstance(value, str):
                return None
        if not isinstance(record.extras, dict):
            return None
        if record.return_to not in RETURN_TO:
            return None
        if record.verifier_hash is None and record.code_challenge is None and record.purpose in (SIGN_IN, APP):
            return None
        return record


def _key(state: str) -> str:
    return KEY_PREFIX + state


def begin(*, provider_id: str, purpose: str, source: str, client_ip: Optional[str] = None,
          verifier_hash: Optional[str] = None, code_challenge: Optional[str] = None, return_to=None,
          user_id: Optional[str] = None, session_hash: Optional[str] = None, step_up_action: Optional[str] = None,
          extras: Optional[dict] = None, redis=None, now: Optional[float] = None) -> LoginState:
    """Make and store the state of a new sign-in; the nonce and PKCE verifier are made here too. Raises
    :class:`TooManyAbandoned` above the cap for this source, :class:`Unavailable` without the store."""
    if purpose not in PURPOSES:
        raise ValueError(f"not a sign-in purpose: {purpose!r}")
    if purpose in (SIGN_IN, APP) and not (verifier_hash or code_challenge):
        raise ValueError("a sign-in needs the tab's verifier hash or an app's PKCE challenge")
    now = time.time() if now is None else now
    client = _redis(redis)
    started_key = STARTED_PREFIX + source
    try:
        client.zremrangebyscore(started_key, "-inf", now - ABANDONED_WINDOW_SECONDS)
        abandoned = client.zcount(started_key, now - ABANDONED_WINDOW_SECONDS, now - STATE_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in state store cannot be reached") from exc
    if int(abandoned or 0) >= ABANDONED_LIMIT:
        raise TooManyAbandoned("too many unfinished sign-ins from this address")
    record = LoginState(
        state=_b64(secrets.token_bytes(32)), provider_id=str(provider_id), purpose=purpose,
        nonce=_b64(secrets.token_bytes(32)), code_verifier=_b64(secrets.token_bytes(48)),
        return_to=return_to_or_default(return_to), verifier_hash=verifier_hash, code_challenge=code_challenge,
        user_id=str(user_id) if user_id is not None else None, session_hash=session_hash,
        step_up_action=step_up_action, client_ip=client_ip, source=source, started_at=int(now),
        extras=dict(extras or {}))
    try:
        written = client.set(_key(record.state), json.dumps(asdict(record), separators=(",", ":")),
                             ex=STATE_TTL_SECONDS, nx=True)
        if written:
            client.zadd(started_key, {record.state: now})
            client.expire(started_key, ABANDONED_WINDOW_SECONDS + STATE_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in state store cannot be reached") from exc
    if not written:
        raise Unavailable("the sign-in state could not be written")
    return record


def take(state, *, redis=None) -> Optional[LoginState]:
    """Spend the state ``state`` and return it, or None for an unknown, spent, expired or malformed one. The
    start's entry in its source's abandoned count is removed: this sign-in was not abandoned."""
    if not isinstance(state, str) or not state or len(state) > _MAX_STATE_LENGTH:
        return None
    if not all(ch.isalnum() or ch in "-_" for ch in state):
        return None
    client = _redis(redis)
    try:
        raw = client.getdel(_key(state))
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in state store cannot be reached") from exc
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        record = LoginState.from_payload(json.loads(raw))
    except ValueError:
        return None
    if record is None or record.state != state:
        return None
    if record.source:
        try:
            client.zrem(STARTED_PREFIX + record.source, state)
        except Exception:  # noqa: BLE001 -- the count is advisory; the sign-in goes on
            pass
    return record


def store_handover(record: dict, *, redis=None) -> str:
    """Keep what a finished link or test found, under a fresh one-time code, for a minute: the account and
    session that started it, the tab verifier's hash, and what the provider said. Returns the code."""
    import hashlib
    code = _b64(secrets.token_bytes(32))
    key = HANDOVER_PREFIX + hashlib.sha256(code.encode("ascii")).hexdigest()
    try:
        written = _redis(redis).set(key, json.dumps(record, separators=(",", ":")), ex=HANDOVER_TTL_SECONDS, nx=True)
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in state store cannot be reached") from exc
    if not written:
        raise Unavailable("the handover could not be written")
    return code


_HANDOVER_TEXT = ("purpose", "provider_id", "user_id", "session_hash", "verifier_hash", "subject", "issuer")
_HANDOVER_OPTIONAL = ("tenant_id", "email", "display_name")


def take_handover(code, *, redis=None) -> Optional[dict]:
    """Spend a handover code and return its record, or None for an unknown, spent, expired or malformed one."""
    import hashlib
    if not isinstance(code, str) or not code or len(code) > 128 or not all(ch.isalnum() or ch in "-_" for ch in code):
        return None
    try:
        raw = _redis(redis).getdel(HANDOVER_PREFIX + hashlib.sha256(code.encode("ascii")).hexdigest())
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in state store cannot be reached") from exc
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(record, dict) or record.get("purpose") not in (LINK, TEST, STEP_UP):
        return None
    action = record.get("step_up_action")
    if record["purpose"] == STEP_UP and (not isinstance(action, str) or not action):
        return None                                  # a re-authentication is staged for one named action
    if action is not None and not isinstance(action, str):
        return None
    for name in _HANDOVER_TEXT:
        if not isinstance(record.get(name), str) or not record.get(name):
            return None
    for name in _HANDOVER_OPTIONAL:
        if record.get(name) is not None and not isinstance(record.get(name), str):
            return None
    if not isinstance(record.get("summary", {}), dict) or not isinstance(record.get("email_verified", False), bool):
        return None
    return record


def abandoned_count(source: str, *, redis=None, now: Optional[float] = None) -> int:
    """How many starts from ``source`` in the last hour were left unfinished past a state's life."""
    now = time.time() if now is None else now
    try:
        return int(_redis(redis).zcount(STARTED_PREFIX + source, now - ABANDONED_WINDOW_SECONDS,
                                        now - STATE_TTL_SECONDS) or 0)
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in state store cannot be reached") from exc


# --------------------------------------------------------------------------- staged re-authentications, logout ids

def _reauth_key(session_hash: str, action: str) -> str:
    import hashlib
    return REAUTH_PREFIX + hashlib.sha256(f"{session_hash}:{action}".encode("utf-8")).hexdigest()


def stage_reauth(session_hash: str, action: str, *, redis=None) -> None:
    """Note that this session re-authenticated at its provider for ``action``: spent by :func:`take_reauth` once,
    within :data:`REAUTH_TTL_SECONDS`. Raises :class:`Unavailable` without the store."""
    try:
        _redis(redis).set(_reauth_key(session_hash, action), "1", ex=REAUTH_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001
        raise Unavailable(str(exc)) from exc


def take_reauth(session_hash: str, action: str, *, redis=None) -> bool:
    """Spend the staged re-authentication of this session for ``action``: True once, then False."""
    try:
        return _redis(redis).getdel(_reauth_key(session_hash, action)) is not None
    except Exception as exc:  # noqa: BLE001
        raise Unavailable(str(exc)) from exc


def seen_logout_jti(jti: str, ttl_seconds: int, *, redis=None) -> bool:
    """Record a back-channel logout token's id for ``ttl_seconds`` and say whether it was already recorded (a
    replayed token). Without the store the token is treated as seen: a logout is never honoured twice, and the
    provider retries."""
    import hashlib
    key = LOGOUT_JTI_PREFIX + hashlib.sha256(str(jti).encode("utf-8")).hexdigest()
    try:
        fresh = _redis(redis).set(key, "1", nx=True, ex=max(1, int(ttl_seconds)))
    except Exception:  # noqa: BLE001
        return True
    return not bool(fresh)
