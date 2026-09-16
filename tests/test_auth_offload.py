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
import contextvars
import threading

import pytest
from fastapi import HTTPException

# The minimal env the API bootstrap requires, so this module (which imports app.api.api_server for
# the _fire_offloop tests) passes when run alone with no .env.
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.core.auth_offload as ao
from app.core.auth_offload import (
    AUTH_OFFLOAD_LIMIT, FIRE_OFFLOOP_LIMIT, auth_offload_slot, run_offloaded)

pytestmark = pytest.mark.unit

_probe = contextvars.ContextVar("offload_probe", default="unset")

# Captured at import, BEFORE the autouse fixture or _fresh_slots() can rebind ao._auth_slots: the
# SHIPPED semaphore's initial count, i.e. the real bound the routes run under. The concurrency test
# rebinds the semaphore to dodge cross-loop binding, so on its own it proves only the CAP mechanism,
# not the shipped value — a shipped Semaphore(200) with the constant left at 8 would pass it.
_SHIPPED_SLOT_INITIAL = ao._auth_slots._value


@pytest.fixture(autouse=True)
def _restore_offload_globals():
    """Tests here rebind the module-level slot semaphore onto their own loop; restore a clean one
    afterwards so a semaphore bound to a now-closed loop never leaks to another module in the same
    process."""
    yield
    ao._auth_slots = asyncio.Semaphore(AUTH_OFFLOAD_LIMIT)


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
            assert exc.value.headers.get("Retry-After") == str(ao._SLOT_RETRY_AFTER_SECONDS)
        finally:
            for g in holders:
                with pytest.raises(StopAsyncIteration):
                    await g.__anext__()  # release each slot

    _run(run())


def test_run_offloaded_preserves_contextvars_into_the_worker():
    """run_offloaded must carry the caller's contextvars into the offloaded call. loop.run_in_executor
    does NOT propagate them (asyncio.to_thread did), so without an explicit context copy the worker
    would see the default value. Reverting to a bare run_in_executor turns this red."""
    async def run():
        _probe.set("set-on-the-loop")
        return await run_offloaded(_probe.get)

    assert _run(run()) == "set-on-the-loop", (
        "the contextvar set on the loop was not visible inside the offloaded callable — "
        "run_in_executor dropped the context")


def test_run_offloaded_keeps_the_loop_free_under_a_blocking_burst():
    """The core of the login offload, without a server: N concurrent run_offloaded calls doing
    blocking (GIL-releasing) work must not freeze the loop — an unrelated heartbeat keeps ticking
    while the burst runs. This is the property the login route relies on to stay responsive under a
    burst of CPU-bound password verifies. Replacing run_offloaded's executor hop with a direct call on
    the loop freezes it and the heartbeat stalls — red."""
    import time as _time

    async def run():
        ticks = {"n": 0}
        stop = asyncio.Event()

        async def heartbeat():
            while not stop.is_set():
                ticks["n"] += 1
                await asyncio.sleep(0.005)

        def blocking():
            _time.sleep(0.3)  # releases the GIL: in a worker thread the loop runs on; on the loop it blocks

        hb = asyncio.create_task(heartbeat())
        await asyncio.sleep(0.02)
        before = ticks["n"]
        await asyncio.gather(*[run_offloaded(blocking) for _ in range(AUTH_OFFLOAD_LIMIT)])
        advanced = ticks["n"] - before
        stop.set()
        await hb
        return advanced

    advanced = _run(run())
    # ~0.3 s of loop time at a 5 ms heartbeat is dozens of ticks when the loop is free; a direct call
    # freezes it for ~8 x 0.3 s and the heartbeat barely advances. 15 sits well between the two.
    assert advanced >= 15, (
        f"the loop ticked only {advanced} times during an offloaded blocking burst — it was frozen, "
        f"so run_offloaded did not move the blocking work off the loop")


def test_the_shipped_slot_semaphore_is_sized_to_the_limit():
    # Pin the SHIPPED bound, not the rebound one the concurrency test uses. The module's own semaphore,
    # as created at import, must start at AUTH_OFFLOAD_LIMIT. A shipped Semaphore(200) with the
    # constant left at 8 reddens here even though the rebound-semaphore concurrency test stays green.
    assert _SHIPPED_SLOT_INITIAL == AUTH_OFFLOAD_LIMIT, (
        f"the shipped auth-offload semaphore starts at {_SHIPPED_SLOT_INITIAL}, not AUTH_OFFLOAD_LIMIT "
        f"({AUTH_OFFLOAD_LIMIT}) — the routes run under a different bound than the unit test proves")


def test_the_shed_constants_are_the_shipped_values():
    # Pin the shipped shed configuration so a change is a deliberate, reviewed edit — the shed test
    # patches the timeout, so without this pin a silent change to the real value would go unnoticed.
    assert ao.SLOT_ACQUIRE_TIMEOUT_SECONDS == 15.0
    assert ao._SLOT_RETRY_AFTER_SECONDS == 5


def test_run_offloaded_uses_the_dedicated_executor():
    """The offloaded work must run in the module's dedicated pool (thread name prefix 'auth-offload'),
    not the loop's default executor shared with the WebSocket poller. Reverting to asyncio.to_thread
    lands it on a default-executor thread with a different name — red."""
    async def run():
        return await run_offloaded(lambda: threading.current_thread().name)

    name = _run(run())
    assert name.startswith("auth-offload"), (
        f"offloaded work ran on thread {name!r}, not the dedicated 'auth-offload' pool")


def test_fire_offloop_caps_concurrent_side_effects_at_the_limit():
    """_fire_offloop must run at most FIRE_OFFLOOP_LIMIT side effects at once (their own DB sessions
    must not outgrow the pool). Fire far more than the limit, hold each, and watch the peak."""
    import app.api.api_server as S
    lock = threading.Lock()
    state = {"current": 0, "peak": 0}
    release = threading.Event()

    def work():
        with lock:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
        release.wait(10)
        with lock:
            state["current"] -= 1

    async def run():
        S._offloop_sem = None  # bind a fresh semaphore on THIS loop
        S._BG_TASKS.clear()
        for _ in range(FIRE_OFFLOOP_LIMIT * 3):
            S._fire_offloop(work)
        for _ in range(300):
            await asyncio.sleep(0.01)
            if state["current"] >= FIRE_OFFLOOP_LIMIT:
                break
        peak = state["peak"]
        release.set()
        for _ in range(300):
            await asyncio.sleep(0.01)
            if state["current"] == 0 and not S._BG_TASKS:
                break
        return peak

    peak = _run(run())
    assert peak == FIRE_OFFLOOP_LIMIT, (
        f"peak concurrent side effects was {peak}, expected {FIRE_OFFLOOP_LIMIT}")


def test_fire_offloop_sheds_beyond_the_queue_cap():
    """Beyond _OFFLOOP_MAX_PENDING queued side effects, _fire_offloop drops rather than growing the
    queue without bound (the failed-login path feeds it from an unauthenticated door). Removing the
    cap check schedules the work and increments nothing — red."""
    import app.api.api_server as S

    async def run():
        S._offloop_sem = None
        S._BG_TASKS.clear()
        for i in range(S._OFFLOOP_MAX_PENDING):
            S._BG_TASKS.add(("dummy", i))  # saturate the pending set with sentinels
        before = S._offloop_dropped
        fired = {"n": 0}
        S._fire_offloop(lambda: fired.__setitem__("n", fired["n"] + 1))
        delta = S._offloop_dropped - before
        S._BG_TASKS.clear()
        return delta, fired["n"]

    delta, fired = _run(run())
    assert delta == 1 and fired == 0, (
        f"side effect not shed at the queue cap: dropped_delta={delta}, fired={fired}")
