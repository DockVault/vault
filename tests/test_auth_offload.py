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
import threading

import pytest
from fastapi import HTTPException

import app.core.auth_offload as ao
from app.core.auth_offload import AUTH_OFFLOAD_LIMIT, auth_offload_slot

pytestmark = pytest.mark.unit


def _run(coro):
    """Run an async body on a loop of its own, in a thread of its own — the repo's pattern (see
    test_transfer_admission._run). asyncio.run refuses when a loop is already running in the calling
    thread, and in the single-invocation full suite Playwright's sync API leaves one running once any
    browser-driven module sorts earlier; a unit test must not depend on that ambient state."""
    outcome = {}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            outcome["value"] = loop.run_until_complete(coro)
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller
            outcome["error"] = exc
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()

    thread = threading.Thread(target=_worker)
    thread.start()
    thread.join(timeout=60)
    assert not thread.is_alive(), "the async body did not finish"
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def _fresh_slots():
    """A new semaphore bound to the CURRENT event loop. asyncio.Semaphore binds to the loop that
    first uses it, so two asyncio.run() calls in this module would otherwise reuse one bound to the
    first test's (now closed) loop and raise. Production creates it once, under the server's single
    loop, so this reset is a test-loop artifact only."""
    ao._auth_slots = asyncio.Semaphore(AUTH_OFFLOAD_LIMIT)


def test_auth_offload_slot_caps_concurrency_at_the_limit():
    state = {"current": 0, "peak": 0}

    async def run():
        _fresh_slots()
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

    peak = _run(run())
    assert peak == AUTH_OFFLOAD_LIMIT, (
        f"peak concurrent offload slots was {peak}, expected exactly {AUTH_OFFLOAD_LIMIT} — the "
        f"slot semaphore is not bounding concurrency at its limit")


def test_the_slot_sheds_load_with_503_when_the_wait_exceeds_the_timeout(monkeypatch):
    """Beyond the slot cap, a waiter does not queue without bound: after the acquire timeout it sheds
    load with a 503 + Retry-After. With every slot held and a tiny timeout, the next request's slot
    dependency raises HTTPException(503) instead of waiting forever. Reverting the dependency to an
    unbounded acquire makes the waiter never shed, so the test's own wait times out with no
    HTTPException and it goes red."""
    import app.core.auth_offload as ao
    monkeypatch.setattr(ao, "SLOT_ACQUIRE_TIMEOUT_SECONDS", 0.1)

    async def run():
        _fresh_slots()
        holders = []
        for _ in range(AUTH_OFFLOAD_LIMIT):
            g = auth_offload_slot()
            await g.__anext__()  # take and hold every slot
            holders.append(g)
        try:
            waiter = auth_offload_slot()
            # Bound the test's own wait so an unbounded-acquire revert fails cleanly (TimeoutError,
            # not HTTPException) instead of hanging.
            with pytest.raises(HTTPException) as exc:
                await asyncio.wait_for(waiter.__anext__(), timeout=3)
            assert exc.value.status_code == 503
            assert exc.value.headers.get("Retry-After")
        finally:
            for g in holders:
                with pytest.raises(StopAsyncIteration):
                    await g.__anext__()  # release each slot

    _run(run())
