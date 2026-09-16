"""The auth offload slot caps how many offloaded auth requests run at once, below the database pool.

A pure unit test of the bound itself: drive the ``auth_offload_slot`` dependency the way FastAPI does
— enter it (acquire a slot), hold it, then close it (release) — for far more concurrent "requests"
than the limit, and watch the peak number holding a slot at once. It must equal the limit; lowering
or raising the semaphore moves the peak and turns this red. No server, no Redis, no thread pool: the
semaphore inside the dependency is the only thing that can be capping concurrency here.

The slot is a request-scoped FastAPI dependency (not a wrapper around the blocking call) precisely so
it is held for the WHOLE request — before any database connection is checked out. That ordering is
what bounds the pool; this test pins the cap the ordering relies on. run_offloaded, tested for
"off the loop" behaviour by the outage tests, carries no bound of its own.
"""
import asyncio

import pytest

from app.core.auth_offload import AUTH_OFFLOAD_LIMIT, auth_offload_slot

pytestmark = pytest.mark.unit


def test_auth_offload_slot_caps_concurrency_at_the_limit():
    state = {"current": 0, "peak": 0}

    async def run():
        release = asyncio.Event()

        async def one_request():
            # FastAPI enters an async-generator dependency by advancing it once (acquiring the slot),
            # runs the request, then closes it (releasing the slot). Mirror that here.
            gen = auth_offload_slot()
            await gen.__anext__()  # acquire a slot
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
            try:
                # Hold the slot so requests pile up against the semaphore instead of passing through
                # one at a time.
                await release.wait()
            finally:
                state["current"] -= 1
                with pytest.raises(StopAsyncIteration):
                    await gen.__anext__()  # leave the async-with, releasing the slot

        tasks = [asyncio.create_task(one_request()) for _ in range(AUTH_OFFLOAD_LIMIT * 3)]
        # Give the loop time to admit as many as the semaphore allows.
        for _ in range(200):
            await asyncio.sleep(0.01)
            if state["current"] >= AUTH_OFFLOAD_LIMIT:
                break
        peak_while_held = state["peak"]
        release.set()
        await asyncio.gather(*tasks)
        return peak_while_held

    peak = asyncio.run(run())
    assert peak == AUTH_OFFLOAD_LIMIT, (
        f"peak concurrent offload slots was {peak}, expected exactly {AUTH_OFFLOAD_LIMIT} — the "
        f"slot semaphore is not bounding concurrency at its limit")
