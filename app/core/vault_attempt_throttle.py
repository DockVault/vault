"""Fail-closed, failure-only attempt throttle for the vault-password / passcode gate.

The gate counts WRONG attempts per (vault, account) in a fixed window and refuses once the limit is
reached. It runs synchronously on the event loop, so a bare Redis touch pays the socket timeout on
the loop during an outage -- and it must NOT skip: skipping would leave vault-password guessing
unthrottled for the whole outage (a HIGH). So it mirrors the login throttle: Redis while the guard is
closed, the durable RateLimitRecord DB fallback while the guard (the limiter's breaker or the shared
private memory) is open or on a Redis error, and fail-closed (refuse) if the DB is unreachable too.

Failure-only semantics are preserved by splitting the count into a read-only CHECK (``over_limit``)
and an increment-only BURN (``burn``) -- only a wrong attempt burns, exactly as the Redis path does.
The three call sites (the vault-access gate, the device-grant proof, the temp-credential mint proof)
share this one helper. It reads the shared guard but, like every read-through consumer, records a
failure only to the guard's PRIVATE memory, never the limiter's breaker.

The Redis counter and the RateLimitRecord DB counter are SEPARATE stores with independent windows, so
across an outage transition (a live Redis count, then the breaker opens and counting moves to the DB)
a guesser can accumulate up to roughly 2x the limit before being refused -- the same bound the login
throttle accepts for the same reason. The window is short and the DB account/vault backstops remain,
so this is an accepted degradation, not a bypass.
"""
import time
import uuid
from datetime import datetime, timedelta

from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.database import redis_client, get_db_context
from app.core.models import RateLimitRecord
from app.core import redis_guard

_ACTION = "vault_attempt"


def over_limit(rate_key: str, limit: int, window: int) -> bool:
    """True if (vault, account) is at or over ``limit`` wrong attempts in the window.

    Redis while the guard is closed; the DB fallback when it is open or on a Redis error. Read-only
    (never counts the check itself). Fail-closed: if the DB is also unreachable, report over-limit so
    the gate refuses rather than letting guessing run unthrottled during a double outage."""
    now = time.time()
    if not redis_guard.guard_is_open(now):
        try:
            attempts = redis_guard.timed_redis(
                "vault_attempt_throttle.over_limit", lambda: redis_client.get(rate_key))
            redis_guard.guard_record_success()
            return bool(attempts) and int(attempts) >= limit
        except Exception:  # noqa: BLE001 — record the private failure and drop to the DB fallback
            redis_guard.guard_record_failure(time.time())
    try:
        return _db_count(rate_key, window) >= limit
    except Exception:  # noqa: BLE001 — Redis AND the DB are unreachable: refuse (never unthrottle)
        return True


def burn(rate_key: str, window: int) -> None:
    """Count one WRONG attempt. Redis while the guard is closed; the DB increment when it is open or
    on a Redis error. A lost burn cannot unthrottle on its own -- ``over_limit`` fail-closes when the
    DB is unreachable -- so a DB burn error is swallowed."""
    now = time.time()
    if not redis_guard.guard_is_open(now):
        try:
            def _op():
                pipe = redis_client.pipeline()
                pipe.incr(rate_key)
                pipe.expire(rate_key, window)
                pipe.execute()
            redis_guard.timed_redis("vault_attempt_throttle.burn", _op)
            redis_guard.guard_record_success()
            return
        except Exception:  # noqa: BLE001 — private failure, then the DB burn
            redis_guard.guard_record_failure(time.time())
    try:
        _db_burn(rate_key, window)
    except Exception:  # noqa: BLE001 — see the docstring: the check fail-closes on DB unavailability
        pass


def _db_count(rate_key: str, window: int) -> int:
    """Current wrong-attempt count for (rate_key, window) from RateLimitRecord; 0 if none or the
    window has expired. Naive UTC to match the TIMESTAMP WITHOUT TIME ZONE column. Raises on a DB
    error so ``over_limit`` can fail closed."""
    cutoff = datetime.utcnow() - timedelta(seconds=window)
    tbl = RateLimitRecord.__table__
    with get_db_context() as db:
        row = db.execute(
            select(tbl.c.attempt_count, tbl.c.window_start)
            .where(tbl.c.identifier == rate_key, tbl.c.action == _ACTION)
        ).first()
    if row is None:
        return 0
    count, window_start = row[0], row[1]
    if window_start is None or window_start < cutoff:
        return 0  # the window lapsed; the stale row will be restarted on the next burn
    return count or 0


def _db_burn(rate_key: str, window: int) -> None:
    """Increment the wrong-attempt count for (rate_key) in a fixed DB window, atomically. On conflict:
    restart the window if it has expired, else increment within it. One canonical row per
    (identifier, action) via the unique constraint, so concurrent burns cannot split the count."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window)
    tbl = RateLimitRecord.__table__
    expired = tbl.c.window_start < cutoff
    stmt = (
        pg_insert(tbl)
        .values(id=uuid.uuid4(), identifier=rate_key, action=_ACTION,
                attempt_count=1, window_start=now, last_attempt=now)
        .on_conflict_do_update(
            index_elements=[tbl.c.identifier, tbl.c.action],
            set_={
                "attempt_count": case((expired, 1), else_=tbl.c.attempt_count + 1),
                "window_start": case((expired, now), else_=tbl.c.window_start),
                "last_attempt": now,
            },
        )
    )
    with get_db_context() as db:
        db.execute(stmt)
