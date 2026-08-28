"""Generalized one-time-code (OTP) service: purpose-scoped, single-use, short-lived codes with a
3-strike lockout, stored in Redis (primary) with a durable Postgres fallback.

Design (owner-approved): Redis holds the active code for fast, auto-expiring storage; if Redis is
unavailable at issue time, the code is written to the ``otp_codes`` table instead. ``verify`` consults
BOTH stores and honours the one with the newer ``issued_at`` generation, so a stale code left in one
store by a re-issue that happened during a Redis outage can never shadow (or outlive) the current code
in the other store. A Redis-issued code lost to a restart simply forces the user to request a new one.

Security properties (OWASP "Multifactor Authentication" cheat sheet):
- **Single active code per (purpose, user):** issuing a new code invalidates any prior one — a new
  issue clears both stores, and verify always redeems the newest generation, so an older code is dead.
- **Bound to (purpose, user, destination):** the store key is ``otp:{purpose}:{user_id}``, so a code
  for one action or user can't be redeemed for another; the destination (e.g. a pending new email)
  travels with the code and is returned on success, so a code minted for address A can't confirm B.
- **Single-use:** consumed atomically on the first correct redemption — the Redis key delete and the DB
  conditional update each have a single winner, so two concurrent correct submissions can't both pass.
- **3-strike:** after ``max_attempts`` (default 3) wrong guesses the code is invalidated (on top of the
  caller's outer rate limit on issue and verify).
- **Expiry:** configurable TTL; an expired code never verifies (checked logically; the Redis key also
  auto-expires shortly after, after a small grace).
- **At rest:** only a peppered HMAC-SHA256 of the code is stored, never the plaintext; the plaintext
  reaches only the intended channel (an email) and is returned to the caller once at issue.

The crypto helpers are pure so they unit-test offline; ``issue``/``verify`` take the redis client and
db session explicitly so both stores (and their fallback interplay) are exercisable with fakes.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

# 12 lowercase-hex chars (~48 bits). Single-use, short-lived and rate-limited, so it does not need
# link-length entropy and stays short enough to read out of an email and type.
_CODE_BYTES = 6
DEFAULT_MAX_ATTEMPTS = 3
_REDIS_GRACE_SECONDS = 15   # let the Redis key outlive its logical expiry briefly; verify re-checks


# --------------------------------------------------------------------------------------------------
# Pure helpers (offline-testable)
# --------------------------------------------------------------------------------------------------
def generate_code() -> str:
    """A fresh, high-entropy, human-typeable code (lowercase hex)."""
    return secrets.token_hex(_CODE_BYTES)


def hash_code(code: str, pepper: str) -> str:
    """Peppered HMAC-SHA256 hex of a code — a read of the store alone never yields a usable code."""
    return hmac.new((pepper or "").encode(), (code or "").encode(), hashlib.sha256).hexdigest()


def _hash_matches(a_hex: str, b_hex: str) -> bool:
    """Constant-time comparison of two hex digests."""
    return hmac.compare_digest(a_hex or "", b_hex or "")


def redis_key(purpose: str, user_id) -> str:
    return f"otp:{purpose}:{user_id}"


def _utc_epoch(dt) -> int:
    """Epoch seconds for a NAIVE-UTC datetime (treat it as UTC, not local)."""
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


class OtpResult:
    """Outcome of a verify. ``ok`` True -> ``destination`` is the value the code was bound to. Failure
    ``reason`` is one of: 'not_found', 'expired', 'invalid', 'too_many'."""
    __slots__ = ("ok", "destination", "reason")

    def __init__(self, ok: bool, destination: Optional[str] = None, reason: Optional[str] = None):
        self.ok = ok
        self.destination = destination
        self.reason = reason

    def __repr__(self):  # pragma: no cover - debug aid
        return f"OtpResult(ok={self.ok!r}, destination={self.destination!r}, reason={self.reason!r})"


def _resolve_redis(redis):
    if redis is not None:
        return redis
    try:
        from app.core.database import redis_client
        return redis_client
    except Exception:
        return None


def _resolve_pepper(pepper):
    if pepper:
        return pepper
    try:
        from app.core.config import settings
        return settings.jwt_secret_key or ""
    except Exception:
        return ""


# --------------------------------------------------------------------------------------------------
# Redis store
# --------------------------------------------------------------------------------------------------
def _redis_delete(redis, purpose, user_id) -> None:
    try:
        redis.delete(redis_key(purpose, user_id))
    except Exception:
        pass


def _redis_put(redis, purpose, user_id, *, code_hash, destination, expires_at, issued_at, max_attempts) -> bool:
    """Store the active code as a hash + TTL. Returns True on success, False if Redis is unavailable.
    A partial write (a transient drop after HSET but before EXPIRE) is cleaned up so it can't orphan a
    TTL-less duplicate code alongside the DB fallback."""
    key = redis_key(purpose, user_id)
    epoch = _utc_epoch(expires_at)
    ttl = max(1, epoch - int(time.time())) + _REDIS_GRACE_SECONDS
    try:
        redis.delete(key)   # clear any prior code for this (purpose, user) first
        redis.hset(key, mapping={
            "code_hash": code_hash,
            "destination": destination or "",
            "attempts": 0,
            "max_attempts": int(max_attempts),
            "expires_at": epoch,
            "issued_at": repr(float(issued_at)),   # sub-second so two issues can't tie the generation
        })
        redis.expire(key, ttl)
        return True
    except Exception:
        try:
            redis.delete(key)   # roll back any partial write so it can't co-exist with the DB copy
        except Exception:
            pass
        return False


def _redis_load(redis, purpose, user_id):
    """Return the parsed Redis candidate dict (with int issued_at/expires_at/max_attempts) or None.
    None means the key is absent OR Redis is unreachable — verify uses issued_at to pick the winner."""
    try:
        data = redis.hgetall(redis_key(purpose, user_id))
    except Exception:
        return None
    if not data:
        return None
    try:
        return {
            "code_hash": data.get("code_hash") or "",
            "destination": data.get("destination") or None,
            "expires_at": int(data.get("expires_at") or 0),
            "max_attempts": int(data.get("max_attempts") or DEFAULT_MAX_ATTEMPTS),
            "issued_at": float(data.get("issued_at") or 0),
        }
    except (ValueError, TypeError):
        _redis_delete(redis, purpose, user_id)
        return None


def _redis_consume_verify(redis, purpose, user_id, presented_hash, cand) -> OtpResult:
    key = redis_key(purpose, user_id)
    if int(time.time()) > cand["expires_at"]:
        _redis_delete(redis, purpose, user_id)
        return OtpResult(False, reason="expired")
    if _hash_matches(cand["code_hash"], presented_hash):
        # Single-winner consume: only the caller whose DELETE actually removed the key succeeds, so two
        # concurrent correct submissions can't both pass.
        try:
            removed = int(redis.delete(key) or 0)
        except Exception:
            removed = 1
        return OtpResult(True, destination=cand["destination"]) if removed >= 1 \
            else OtpResult(False, reason="not_found")
    try:
        attempts = int(redis.hincrby(key, "attempts", 1))
    except Exception:
        attempts = cand["max_attempts"]            # if we can't count, fail closed by invalidating
    if attempts >= cand["max_attempts"]:
        _redis_delete(redis, purpose, user_id)
        return OtpResult(False, reason="too_many")
    return OtpResult(False, reason="invalid")


# --------------------------------------------------------------------------------------------------
# DB store (durable fallback)
# --------------------------------------------------------------------------------------------------
def _db_invalidate(db, purpose, user_id) -> None:
    # COMMITTED on purpose: a re-issue must durably drop any prior DB-stored code for this (purpose,
    # user), even on the Redis-primary path (which does not otherwise write the DB). Without the commit
    # a still-valid old code could survive a re-issue and later be redeemed if Redis went down.
    from app.core.models import OtpCode
    try:
        db.query(OtpCode).filter(
            OtpCode.purpose == purpose,
            OtpCode.user_id == user_id,
            OtpCode.consumed_at.is_(None),
        ).delete(synchronize_session=False)
        db.commit()
    except Exception as e:  # noqa: BLE001
        print(f"[otp] DB invalidate failed for {purpose}: {type(e).__name__}")
        try:
            db.rollback()
        except Exception:
            pass


def _db_put(db, purpose, user_id, *, code_hash, destination, expires_at, max_attempts) -> None:
    from app.core.models import OtpCode
    db.add(OtpCode(purpose=purpose, user_id=user_id, destination=destination, code_hash=code_hash,
                   attempts=0, max_attempts=int(max_attempts), expires_at=expires_at))
    db.commit()


def _db_load(db, purpose, user_id):
    from app.core.models import OtpCode
    return (db.query(OtpCode)
            .filter(OtpCode.purpose == purpose, OtpCode.user_id == user_id,
                    OtpCode.consumed_at.is_(None))
            .order_by(OtpCode.created_at.desc()).first())


def _db_consume_verify(db, row, presented_hash) -> OtpResult:
    from app.core.models import OtpCode
    now = datetime.utcnow()
    if row.expires_at is not None and row.expires_at <= now:
        row.consumed_at = now
        db.commit()
        return OtpResult(False, reason="expired")
    if _hash_matches(row.code_hash, presented_hash):
        # Atomic single-use consume: only the request whose conditional UPDATE affects the row wins.
        won = db.query(OtpCode).filter(OtpCode.id == row.id, OtpCode.consumed_at.is_(None)) \
            .update({"consumed_at": now}, synchronize_session=False)
        db.commit()
        return OtpResult(True, destination=row.destination) if won else OtpResult(False, reason="not_found")
    row.attempts = int(row.attempts or 0) + 1
    if row.attempts >= int(row.max_attempts or DEFAULT_MAX_ATTEMPTS):
        row.consumed_at = now                    # 3-strike invalidation
    db.commit()
    return OtpResult(False, reason="invalid")


# --------------------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------------------
def issue(db, *, purpose: str, user_id, destination: Optional[str], ttl_minutes: int,
          pepper: Optional[str] = None, redis=None, max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> str:
    """Mint a fresh code for (purpose, user_id), invalidating any prior code in BOTH stores. Stores it
    in Redis; if Redis is unavailable, in the DB. Returns the plaintext code (send it, then discard)."""
    redis = _resolve_redis(redis)
    pepper = _resolve_pepper(pepper)
    code = generate_code()
    code_hash = hash_code(code, pepper)
    issued_at = time.time()
    expires_at = datetime.utcnow() + timedelta(minutes=max(1, int(ttl_minutes)))

    # Invalidate any prior code for this (purpose, user) in both stores, so exactly one is ever active.
    if redis is not None:
        _redis_delete(redis, purpose, user_id)
    _db_invalidate(db, purpose, user_id)

    stored = False
    if redis is not None:
        stored = _redis_put(redis, purpose, user_id, code_hash=code_hash, destination=destination,
                            expires_at=expires_at, issued_at=issued_at, max_attempts=max_attempts)
    if not stored:
        # Redis unavailable (or absent) -> durable DB fallback.
        _db_put(db, purpose, user_id, code_hash=code_hash, destination=destination,
                expires_at=expires_at, max_attempts=max_attempts)
    return code


def verify(db, *, purpose: str, user_id, code: str, pepper: Optional[str] = None, redis=None) -> OtpResult:
    """Check a presented code for (purpose, user_id). Consumes it on success (single-use), bumps the
    strike counter on a wrong guess (invalidating at max_attempts). Both stores are consulted and the
    NEWER generation (issued_at) wins, so a stale code left by a re-issue during a Redis outage neither
    shadows nor outlives the current code."""
    redis = _resolve_redis(redis)
    pepper = _resolve_pepper(pepper)
    presented_hash = hash_code(code or "", pepper)

    redis_cand = _redis_load(redis, purpose, user_id) if redis is not None else None
    db_row = _db_load(db, purpose, user_id)

    if redis_cand is not None and db_row is not None:
        db_gen = (db_row.created_at.replace(tzinfo=timezone.utc).timestamp()
                  if db_row.created_at is not None else 0.0)
        if redis_cand["issued_at"] >= db_gen:
            return _redis_consume_verify(redis, purpose, user_id, presented_hash, redis_cand)
        # DB code is newer -> the Redis key is stale; drop it and verify against the DB.
        _redis_delete(redis, purpose, user_id)
        return _db_consume_verify(db, db_row, presented_hash)
    if redis_cand is not None:
        return _redis_consume_verify(redis, purpose, user_id, presented_hash, redis_cand)
    if db_row is not None:
        return _db_consume_verify(db, db_row, presented_hash)
    return OtpResult(False, reason="not_found")


def invalidate(db, *, purpose: str, user_id, redis=None) -> None:
    """Drop any active code for (purpose, user_id) from both stores (e.g. after the flow completes).
    _db_invalidate already commits its delete."""
    redis = _resolve_redis(redis)
    if redis is not None:
        _redis_delete(redis, purpose, user_id)
    _db_invalidate(db, purpose, user_id)
