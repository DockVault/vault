"""Read-through guard and slow-op instrument for on-loop Redis touches.

Every synchronous Redis operation on the event loop is a potential multi-second stall when Redis is
down: the socket timeout (and an unbounded DNS lookup before it) is paid on the loop, freezing the
server for that request. The rate limiter's circuit breaker already turns a sustained outage into a
skip after the first discovery, but only for callers that consult it. This module is the shared way
for every other on-loop Redis touch to consult it, so during an outage the whole server pays ONE
discovery stall, not one per subsystem.

Two primitives:

* ``timed_redis`` wraps a synchronous Redis op and logs a warning naming the FUNCTION and the elapsed
  time (NEVER the key -- keys carry usernames, session-token hashes and device ids) when it runs long
  on the loop, so a paused-Redis measurement can be pinned to its path.

* the read-through guard (``guard_is_open`` / ``guard_record_failure`` / ``guard_record_success`` and
  the ``best_effort`` wrapper) skips a best-effort op while Redis looks down. It reads the limiter's
  breaker but NEVER writes it -- the breaker's fail threshold is 1 and the general-API limiter is
  fail-open, so opening it from a best-effort cache hiccup would disable rate limiting for the whole
  cooldown. A best-effort failure opens only this guard's PRIVATE memory. The auth-path cache guard
  in ``auth_service`` delegates here, so both share one private memory: the first failure anywhere in
  the cohort makes the rest skip.
"""
import logging
import time

logger = logging.getLogger(__name__)

# A synchronous Redis op that takes longer than this on the loop is almost certainly paying a socket
# timeout against a down backend; log it (by function, never key) so a measurement can pin the stall.
SLOW_REDIS_OP_SECONDS = 0.5

# Private failure memory, shared across every read-through consumer (see the module docstring). Open
# for one breaker-cooldown after a real failure; a success clears it. Distinct from the limiter's
# breaker, which this reads but never writes.
_guard_open_until = 0.0


def _cooldown() -> float:
    from app.core.rate_limiter import _CB_COOLDOWN_SECONDS
    return _CB_COOLDOWN_SECONDS


def guard_is_open(now: float) -> bool:
    """Whether a best-effort Redis touch should be skipped right now -- the limiter's breaker is open
    (a real outage the limiter already discovered) OR this guard's own private memory is inside its
    cooldown after a recent best-effort failure."""
    from app.core.rate_limiter import _cb_is_open
    return _cb_is_open(now) or now < _guard_open_until


def guard_private_open(now: float) -> bool:
    """Whether only this guard's PRIVATE memory is open (ignoring the limiter's breaker)."""
    return now < _guard_open_until


def guard_record_failure(now: float) -> None:
    """A best-effort Redis op failed: open the private memory for a cooldown so the cohort skips."""
    global _guard_open_until
    _guard_open_until = now + _cooldown()


def guard_record_success() -> None:
    """A best-effort Redis op succeeded: clear the private memory."""
    global _guard_open_until
    _guard_open_until = 0.0


def timed_redis(function: str, op):
    """Run ``op`` and, if it took longer than ``SLOW_REDIS_OP_SECONDS``, log a warning naming
    ``function`` and the elapsed seconds -- never the key. Returns op()'s result and re-raises its
    exception (timing the failing case too, since that is the socket-timeout path)."""
    start = time.monotonic()
    try:
        return op()
    finally:
        elapsed = time.monotonic() - start
        if elapsed > SLOW_REDIS_OP_SECONDS:
            logger.warning("slow on-loop Redis op in %s: %.2fs", function, elapsed)


def timed_db(function: str, op):
    """Like ``timed_redis`` but for the durable DB fallback path (RateLimitRecord). Same elapsed-only
    warning (function + seconds, never the query), so a slow paused-Redis attempt that has dropped to
    the DB can be attributed to its path too. Returns op()'s result and re-raises."""
    start = time.monotonic()
    try:
        return op()
    finally:
        elapsed = time.monotonic() - start
        if elapsed > SLOW_REDIS_OP_SECONDS:
            logger.warning("slow on-loop DB fallback in %s: %.2fs", function, elapsed)


def best_effort(function: str, op, *, default=None):
    """Run a best-effort, on-loop Redis op behind the read-through guard.

    While the guard is open the socket is skipped and ``default`` is returned. Otherwise the op runs
    through ``timed_redis``; a success clears the private memory and returns the result, a failure
    opens the private memory and returns ``default`` (swallowed -- the caller treats ``default`` as
    'Redis unavailable'). Never writes the limiter's breaker."""
    now = time.time()
    if guard_is_open(now):
        return default
    try:
        result = timed_redis(function, op)
    except Exception:  # noqa: BLE001 — best-effort: the caller's fallback/default is authoritative
        guard_record_failure(time.time())
        return default
    guard_record_success()
    return result


class Skipped(Exception):
    """The guard is open: the op was not tried, and the socket was not touched."""


def _is_an_outage(error: BaseException) -> bool:
    """Whether ``error`` says Redis could not be reached: its connection, or its timeout. Anything else says nothing
    of whether Redis is there: a value the client would not write as bytes (raised before Redis is asked at all),
    or an answer Redis itself gave."""
    if isinstance(error, OSError):                  # the built-in ConnectionError and TimeoutError among them
        return True
    try:
        from redis import exceptions as redis_errors
    except Exception:  # noqa: BLE001 -- no client library: nothing more to tell them by
        return False
    return isinstance(error, (redis_errors.ConnectionError, redis_errors.TimeoutError))


def required(function: str, op):
    """Run an on-loop Redis op that its caller cannot do without (a one-time code, a ceremony's challenge, a
    login state: stores with no fallback, which fail closed) behind the read-through guard.

    While the guard is open the socket is skipped and :class:`Skipped` is raised at once, so an outage costs the
    server one discovery and not one socket timeout for every request that reaches such a store. Otherwise the
    op runs through ``timed_redis``: a success clears the private memory and returns the result; a failure is
    raised as it is, and opens the private memory when it says Redis could not be reached. A failure of another
    kind opens nothing: these stores are reached by anyone, and one request whose value could not be written must
    not make every such store answer "unavailable" for the next while. Never writes the limiter's breaker."""
    if guard_is_open(time.time()):
        raise Skipped(function)
    try:
        result = timed_redis(function, op)
    except Exception as error:
        if _is_an_outage(error):
            guard_record_failure(time.time())
        raise
    guard_record_success()
    return result
