"""Bound the auth routes' concurrency below the database pool, and run their blocking work off the loop.

A login or a credential mint does synchronous work that, during a cache outage, blocks on a Redis
socket. Two mechanisms keep that from freezing the server:

  * a request-scoped SLOT, taken as a FastAPI dependency declared FIRST on each offloaded route —
    before ``db`` / ``current_user`` / ``principal`` — so NO database connection is checked out until
    a slot is held. Each such route therefore holds at most one connection while it owns a slot, and
    the slots cap how many run at once BELOW the pool, so an outage-time burst cannot drain the pool
    and fail every request (a plain in-flight semaphore that a route queued on AFTER already querying
    the database would not give this — the slot has to gate the whole request);
  * ``run_offloaded`` runs the blocking work in a worker thread, so one caller's stall does not hold
    the event loop and concurrent callers do not serialize behind it.

``asyncio.to_thread`` uses the event loop's default ``ThreadPoolExecutor`` (``min(32, cpu + 4)``
workers, shared with other offloaded work such as preview rendering); the slot cap, not the executor,
is what bounds these routes. This pairs with the session-cache circuit breaker rather than replacing
it: the breaker bounds each stall, the slot bounds how many requests run at once.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException, status

# Below the database pool base (10); the rest of the pool plus overflow stays free for other requests.
AUTH_OFFLOAD_LIMIT = 8
# How many best-effort background side effects (a broadcast, a notification, a failed-login record)
# may run at once. A login never waits on these; beyond this they queue as background tasks.
FIRE_OFFLOOP_LIMIT = 4

# A DEDICATED thread pool for the offloaded auth work and the background side effects, so they do not
# share the event loop's default executor with the /ws/monitor pub/sub poller (which parks ~a whole
# worker per open browser). Sized to the slot count plus the side-effect bound, so the SLOT — not an
# incidentally-starved executor — is what bounds the offloaded routes, as the module contract says.
_offload_executor = ThreadPoolExecutor(
    max_workers=AUTH_OFFLOAD_LIMIT + FIRE_OFFLOOP_LIMIT, thread_name_prefix="auth-offload")
# The longest a request waits for a slot before shedding load with 503 + Retry-After. During a cache
# outage each held slot lasts about one socket timeout, so the queue drains steadily and a normal
# request never waits this long; the cap only bites under a pathological pileup, bounding the waiters
# a fail-open outage would otherwise let grow without limit (a slow-drain queue is a memory sink and
# serves nobody once the wait exceeds any client's own timeout).
SLOT_ACQUIRE_TIMEOUT_SECONDS = 15.0
_SLOT_RETRY_AFTER_SECONDS = 5
_auth_slots = asyncio.Semaphore(AUTH_OFFLOAD_LIMIT)


async def auth_offload_slot():
    """FastAPI dependency: hold one bounded slot for the whole request. Declare it FIRST on an
    offloaded route so the slot is held before any database connection is checked out. Waits at most
    SLOT_ACQUIRE_TIMEOUT_SECONDS for a slot, then sheds load with 503 + Retry-After rather than let
    waiters queue without bound during a fail-open outage."""
    try:
        await asyncio.wait_for(_auth_slots.acquire(), timeout=SLOT_ACQUIRE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The server is busy; please retry shortly.",
            headers={"Retry-After": str(_SLOT_RETRY_AFTER_SECONDS)},
        )
    try:
        yield
    finally:
        _auth_slots.release()


async def run_offloaded(fn, *args, **kwargs):
    """Run ``fn(*args, **kwargs)`` in the dedicated offload thread pool. Concurrency is bounded by the
    ``auth_offload_slot`` dependency the route holds, not here; the dedicated pool keeps that true by
    not sharing the default executor with the WebSocket poller."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_offload_executor, lambda: fn(*args, **kwargs))
