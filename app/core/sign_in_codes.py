"""One-time sign-in codes: how a sign-in that ended on another page reaches the web app or the desktop app.

A passkey ceremony and a single sign-on both end in a redirect back to the vault. A session must never
travel in a URL (a URL reaches server logs, proxies and the browser history), so the redirect carries a
**code** instead, in the URL fragment (``/#sso=<code>``), which never leaves the browser. The code is
worthless on its own:

* **Web app:** before the redirect the tab made a random **verifier**, kept it in its own session storage,
  and sent the verifier's SHA-256 with the start request; the code's record holds that hash. To finish, the
  tab posts the code and the verifier; the server spends the code and checks the hash. A code read from a
  log or a shoulder is useless without the tab's verifier.
* **Desktop app:** the same exchange with PKCE (RFC 7636, ``S256``): the record holds the app's
  ``code_challenge``; the app posts the code and its ``code_verifier``.

The record lives in Redis under the code's SHA-256 for sixty seconds and is read with ``GETDEL``, so a code
is spent by its first use, right or wrong: a stolen code gives one guess. Without Redis the exchange fails
closed (``Unavailable``); nothing falls back to the database. While Redis is known to be down it fails at once,
without a try (the shared outage guard, app/core/redis_guard.py). The record carries what the sign-in proved
(the pipeline's inputs: app/services/sign_in.py), never a session or a token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

CODE_TTL_SECONDS = 60
KEY_PREFIX = "signin:code:"
PURPOSES = ("sign_in", "app")
# RFC 7636: a code verifier is 43 to 128 characters of the unreserved set.
_PKCE_MIN, _PKCE_MAX = 43, 128
_MAX_CODE_LENGTH = 128


class Unavailable(Exception):
    """The code store cannot be reached: the exchange fails closed."""


def make_secret() -> str:
    """32 random bytes, base64url without padding: a code, a tab verifier, a PKCE verifier."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def digest(value: str) -> str:
    """SHA-256 of ``value`` as hex: the store key of a code, the stored form of a tab verifier."""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def pkce_challenge(code_verifier: str) -> str:
    """The ``S256`` challenge of a PKCE verifier (RFC 7636 §4.2). The verifier is ASCII by the RFC; anything
    else has no challenge (an empty string, which no stored challenge equals)."""
    try:
        raw = hashlib.sha256((code_verifier or "").encode("ascii")).digest()
    except UnicodeEncodeError:
        return ""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _is_pkce_verifier(value) -> bool:
    """RFC 7636 §4.1: 43 to 128 characters from the unreserved set."""
    return (isinstance(value, str) and _PKCE_MIN <= len(value) <= _PKCE_MAX
            and all(ch.isalnum() or ch in "-._~" for ch in value) and value.isascii())


def _key(code: str) -> str:
    return KEY_PREFIX + digest(code)


def _redis(redis):
    """The client a call uses: the one handed in, else the vault's own."""
    if redis is not None:
        return redis
    from app.core.database import redis_client
    return redis_client


def _run(redis, function: str, op):
    """One store call; ``op`` is given the client. On the vault's own client the call goes behind the shared outage
    guard: while Redis is known to be down the socket is not touched and the call fails at once, so an outage
    costs the server one discovery and not one timeout for every code. Any other client is called as it is."""
    from app.core import database, redis_guard
    client = _redis(redis)
    if client is not database.redis_client:
        return op(client)
    return redis_guard.required(function, lambda: op(client))


@dataclass
class Handover:
    """What a finished proof hands to the pipeline: who, how, and the proof the finisher must give."""
    user_id: str
    methods: List[str]
    client_ip: Optional[str] = None
    provider_id: Optional[str] = None
    provider_mfa_trusted: bool = False
    user_verified: bool = False
    passwordless_allowed: bool = False
    pending_id: Optional[str] = None
    purpose: str = "sign_in"
    verifier_hash: Optional[str] = None
    code_challenge: Optional[str] = None
    # When the person authenticated at the identity provider (seconds since the epoch), when it said so.
    # What the provider session remembers for the provider's logouts: its session id and subject, and the hint the
    # provider's own logout takes (the ID token), encrypted, only when the provider logout option wants it.
    provider_sid: Optional[str] = None
    provider_sub: Optional[str] = None
    provider_logout_hint_enc: Optional[str] = None
    provider_auth_time: Optional[int] = None          # when the provider said the person authenticated; None if it did not say
    created_at: int = field(default_factory=lambda: int(time.time()))
    # How many times the account's sessions had been ended when the proof read the account
    # (app/services/sign_in.py, in_the_accounts_turn). A record without it matches no account.
    ended: Optional[int] = None

    @classmethod
    def from_payload(cls, data) -> Optional["Handover"]:
        """A record read back from the store, or None when it is not one this module wrote."""
        if not isinstance(data, dict):
            return None
        known = {f for f in cls.__dataclass_fields__}  # noqa: C416
        try:
            handover = cls(**{k: v for k, v in data.items() if k in known})
        except TypeError:
            return None
        if not isinstance(handover.user_id, str) or not handover.user_id:
            return None
        if not isinstance(handover.methods, list) or not all(isinstance(m, str) for m in handover.methods):
            return None
        if handover.purpose not in PURPOSES:
            return None
        # Every proof is a plain value of its kind: a flag is a boolean (never a truthy word), a hash or an id
        # a string or absent; anything else is not a record this module wrote.
        for flag in ("provider_mfa_trusted", "user_verified", "passwordless_allowed"):
            if type(getattr(handover, flag)) is not bool:
                return None
        for text_field in ("client_ip", "provider_id", "pending_id", "verifier_hash", "code_challenge",
                           "provider_sid", "provider_sub", "provider_logout_hint_enc"):
            value = getattr(handover, text_field)
            if value is not None and not isinstance(value, str):
                return None
        if not isinstance(handover.created_at, int):
            return None
        # A sign-in needs a first proof: the password, a passkey or an identity provider.
        if not handover.methods and not handover.provider_id:
            return None
        return handover


def store(handover: Handover, *, redis=None, ttl_seconds: int = CODE_TTL_SECONDS) -> str:
    """Write the record under a fresh code and return the code. The record must name exactly one proof the
    finisher will give: a tab verifier's hash, or a PKCE challenge."""
    if bool(handover.verifier_hash) == bool(handover.code_challenge):
        raise ValueError("a sign-in code needs exactly one of a verifier hash and a PKCE challenge")
    if handover.purpose not in PURPOSES:
        raise ValueError(f"not a sign-in code purpose: {handover.purpose!r}")
    if not handover.methods and not handover.provider_id:
        raise ValueError("a sign-in code needs a first proof: a method, or an identity provider")
    code = make_secret()
    payload = json.dumps(asdict(handover), separators=(",", ":"))
    try:
        written = _run(redis, "sign_in_codes.store", lambda r: r.set(_key(code), payload, ex=int(ttl_seconds), nx=True))
    except Exception as exc:  # noqa: BLE001 -- any store failure is an outage for this exchange
        raise Unavailable("the sign-in code store cannot be reached") from exc
    if not written:
        raise Unavailable("the sign-in code could not be written")
    return code


def take(code: str, *, verifier: Optional[str] = None, code_verifier: Optional[str] = None,
         redis=None) -> Optional[Handover]:
    """Spend ``code`` and prove the caller is the tab or app that started the sign-in.

    None when the code is unknown, spent, expired or not a code at all, when the record is not one this
    module wrote, and when the proof is missing or wrong: a wrong proof spends the code too (``GETDEL``
    comes first), so a stolen code gives one guess. The tab verifier is compared by its hash, the PKCE
    verifier by its ``S256`` challenge, both in constant time.
    """
    if not isinstance(code, str) or not code or len(code) > _MAX_CODE_LENGTH:
        return None
    try:
        raw = _run(redis, "sign_in_codes.take", lambda r: r.getdel(_key(code)))
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the sign-in code store cannot be reached") from exc
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        handover = Handover.from_payload(json.loads(raw))
    except (TypeError, ValueError):
        return None
    if handover is None:
        return None
    if handover.verifier_hash:
        if not isinstance(verifier, str) or not verifier:
            return None
        if not hmac.compare_digest(digest(verifier), handover.verifier_hash):
            return None
        return handover
    if handover.code_challenge:
        if not _is_pkce_verifier(code_verifier):
            return None
        if not hmac.compare_digest(pkce_challenge(code_verifier), handover.code_challenge):
            return None
        return handover
    return None


def from_result(result, *, verifier_hash: Optional[str] = None, code_challenge: Optional[str] = None,
                purpose: str = "sign_in") -> Handover:
    """The record for a pipeline result (app/services/sign_in.SignInResult) that is about to be handed over."""
    return Handover(
        user_id=str(result.user.id), methods=list(result.methods), client_ip=result.client_ip,
        provider_id=result.provider_id, provider_mfa_trusted=bool(result.provider_mfa_trusted),
        user_verified=bool(result.user_verified), passwordless_allowed=bool(result.passwordless_allowed),
        pending_id=str(result.pending.id) if result.pending is not None else None,
        purpose=purpose, verifier_hash=verifier_hash, code_challenge=code_challenge,
        ended=result.sessions_ended,
        provider_sid=getattr(result, "provider_sid", None), provider_sub=getattr(result, "provider_sub", None),
        provider_logout_hint_enc=_encrypted(getattr(result, "provider_logout_hint", None)),
        provider_auth_time=(int(result.provider_auth_time.timestamp())
                            if getattr(result, "provider_auth_time", None) is not None else None),
    )


def _encrypted(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    from app.core.security import encrypt_secret
    return encrypt_secret(token)


def _decrypted(token_enc: Optional[str]) -> Optional[str]:
    if not token_enc:
        return None
    from app.core.security import decrypt_secret
    try:
        return decrypt_secret(token_enc)
    except Exception:  # noqa: BLE001 -- a token the key cannot open is no token
        return None


def _refused_since(db, provider_id, user_id, created_at: int) -> bool:
    """Whether the provider refused this account's identity after the handover was made: a refusal at a later
    callback ends the sign-ins under way, this one too (app/services/sso_freshness.py). The handover keeps its time in
    whole seconds, so a refusal within the same second counts as after it (fail closed)."""
    import uuid
    from datetime import datetime, timezone
    from app.services.sign_in import table_present
    if not table_present(db, "external_identities"):
        return False
    from app.core.models import ExternalIdentity
    try:
        pid = uuid.UUID(str(provider_id))
    except ValueError:
        return False
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == pid,
                                                 ExternalIdentity.user_id == user_id).first()
    refused = getattr(identity, "refused_at", None) if identity is not None else None
    made = datetime.fromtimestamp(created_at, tz=timezone.utc).replace(tzinfo=None)
    return refused is not None and refused >= made


def to_result(db, handover: Handover, *, client_ip: Optional[str] = None):
    """The pipeline result a record stands for, read back against the database: the account must still
    exist and be active, a pending login it names must still be live, and a provider's handover must not have been
    overtaken by that provider's refusal of the identity. None otherwise (the finisher then answers as for an
    unknown code)."""
    import uuid
    from datetime import datetime, timezone
    from app.core.models import PendingLogin, User
    from app.services.sign_in import SignInResult
    try:
        user_id = uuid.UUID(handover.user_id)
    except ValueError:
        return None
    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not getattr(user, "is_active", True):
        return None
    if handover.provider_id and _refused_since(db, handover.provider_id, user_id, handover.created_at):
        return None
    pending = None
    if handover.pending_id:
        try:
            pending_id = uuid.UUID(handover.pending_id)
        except ValueError:
            return None
        pending = db.query(PendingLogin).filter(PendingLogin.id == pending_id).first()
        exp = pending.expires_at if pending else None
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if (pending is None or pending.consumed_at is not None
                or (exp is not None and exp < datetime.now(timezone.utc))):
            return None
    result = SignInResult(
        user, list(handover.methods), client_ip if client_ip is not None else handover.client_ip,
        pending=pending, provider_id=handover.provider_id,
        provider_mfa_trusted=handover.provider_mfa_trusted, user_verified=handover.user_verified,
        passwordless_allowed=handover.passwordless_allowed,
        provider_sid=handover.provider_sid, provider_sub=handover.provider_sub,
        provider_logout_hint=_decrypted(handover.provider_logout_hint_enc),
        # What the proof read, not what the account says now: the code lives a minute, and a change in that
        # minute ends the sign-in it carries.
        sessions_ended=handover.ended if isinstance(handover.ended, int) else -1,
    )
    at = handover.provider_auth_time
    if isinstance(at, int) and not isinstance(at, bool) and 0 <= at < 2 ** 33:
        result.provider_auth_time = datetime.fromtimestamp(at, tz=timezone.utc)
    return result
