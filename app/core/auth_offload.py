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

# Below the database pool base (10); the rest of the pool plus overflow stays free for other requests.
AUTH_OFFLOAD_LIMIT = 8
_auth_slots = asyncio.Semaphore(AUTH_OFFLOAD_LIMIT)


async def auth_offload_slot():
    """FastAPI dependency: hold one bounded slot for the whole request. Declare it FIRST on an
    offloaded route so the slot is held before any database connection is checked out."""
    async with _auth_slots:
        yield


async def run_offloaded(fn, *args, **kwargs):
    """Run ``fn(*args, **kwargs)`` in a worker thread. Concurrency is bounded by the
    ``auth_offload_slot`` dependency the route holds, not here."""
    return await asyncio.to_thread(lambda: fn(*args, **kwargs))
