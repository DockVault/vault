"""The challenges a passkey ceremony signs: made once, used once, gone in five minutes.

A WebAuthn ceremony starts with the server handing the browser a random challenge and ends with the browser
returning it signed. The challenge is kept in Redis under its own id with the purpose it was made for (a
registration, a sign-in, the second factor, a step-up), the account it was bound to when there was one, and
the credential ids the browser was offered; it is read with ``GETDEL``, so the first use spends it, right or
wrong. Without Redis a ceremony fails closed (``Unavailable``); nothing falls back to the database. While Redis is
known to be down it fails at once, without a try (the shared outage guard, app/core/redis_guard.py).
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

TTL_SECONDS = 300
KEY_PREFIX = "webauthn:chal:"
REGISTER = "register"
SIGN_IN = "sign_in"
SECOND_FACTOR = "second_factor"
STEP_UP = "step_up"
PURPOSES = (REGISTER, SIGN_IN, SECOND_FACTOR, STEP_UP)
_MAX_ID_LENGTH = 64


class Unavailable(Exception):
    """The challenge store cannot be reached: the ceremony fails closed."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _redis(redis):
    """The client a call uses: the one handed in, else the vault's own."""
    if redis is not None:
        return redis
    from app.core.database import redis_client
    return redis_client


def _run(redis, function: str, op):
    """One store call; ``op`` is given the client. On the vault's own client the call goes behind the shared outage
    guard: while Redis is known to be down the socket is not touched and the call fails at once, so an outage
    costs the server one discovery and not one timeout for every ceremony. Any other client is called as it is."""
    from app.core import database, redis_guard
    client = _redis(redis)
    if client is not database.redis_client:
        return op(client)
    return redis_guard.required(function, lambda: op(client))


@dataclass
class Challenge:
    id: str
    challenge: str                       # 32 random bytes, base64url without padding
    purpose: str
    user_id: Optional[str] = None        # the account the ceremony is bound to, when one is
    allow_ids: List[str] = field(default_factory=list)   # the credential ids offered, base64url
    created_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def challenge_bytes(self) -> bytes:
        padded = self.challenge + "=" * (-len(self.challenge) % 4)
        return base64.urlsafe_b64decode(padded)

    @classmethod
    def from_payload(cls, data) -> Optional["Challenge"]:
        if not isinstance(data, dict):
            return None
        known = {f for f in cls.__dataclass_fields__}  # noqa: C416
        try:
            challenge = cls(**{k: v for k, v in data.items() if k in known})
        except TypeError:
            return None
        if not isinstance(challenge.id, str) or not isinstance(challenge.challenge, str) or not challenge.challenge:
            return None
        if challenge.purpose not in PURPOSES:
            return None
        if challenge.user_id is not None and not isinstance(challenge.user_id, str):
            return None
        if not isinstance(challenge.allow_ids, list) or not all(isinstance(i, str) for i in challenge.allow_ids):
            return None
        return challenge


def issue(purpose: str, *, user_id: Optional[str] = None, allow_ids=(), redis=None,
          ttl_seconds: int = TTL_SECONDS) -> Challenge:
    """A fresh challenge for ``purpose``, written to the store under a fresh id."""
    if purpose not in PURPOSES:
        raise ValueError(f"not a ceremony purpose: {purpose!r}")
    challenge = Challenge(id=secrets.token_hex(16), challenge=_b64(secrets.token_bytes(32)), purpose=purpose,
                          user_id=str(user_id) if user_id is not None else None, allow_ids=list(allow_ids))
    try:
        payload = json.dumps(asdict(challenge), separators=(",", ":"))
        written = _run(redis, "webauthn_challenges.issue",
                       lambda r: r.set(KEY_PREFIX + challenge.id, payload, ex=int(ttl_seconds), nx=True))
    except Exception as exc:  # noqa: BLE001 -- any store failure is an outage for this ceremony
        raise Unavailable("the challenge store cannot be reached") from exc
    if not written:
        raise Unavailable("the challenge could not be written")
    return challenge


def take(challenge_id, *, purpose: str, redis=None) -> Optional[Challenge]:
    """Spend the challenge ``challenge_id`` and return it when it was made for ``purpose``. None for an unknown,
    spent, expired or malformed id, and for a challenge made for another purpose (which is spent all the same:
    a challenge serves one ceremony)."""
    if not isinstance(challenge_id, str) or not challenge_id or len(challenge_id) > _MAX_ID_LENGTH:
        return None
    if not all(ch in "0123456789abcdef" for ch in challenge_id):
        return None
    try:
        raw = _run(redis, "webauthn_challenges.take", lambda r: r.getdel(KEY_PREFIX + challenge_id))
    except Exception as exc:  # noqa: BLE001
        raise Unavailable("the challenge store cannot be reached") from exc
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        challenge = Challenge.from_payload(json.loads(raw))
    except (TypeError, ValueError):
        return None
    if challenge is None or challenge.purpose != purpose or challenge.id != challenge_id:
        return None
    return challenge
