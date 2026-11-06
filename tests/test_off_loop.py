"""Blocking work on stored bytes runs off the event loop, to its end (app/core/off_loop.py), offline.

The web server answers every request from one event loop, so blocking work inside a handler held every other
request until it ended: finishing a large upload froze the server for seconds. run_to_end runs such work in a
thread of its own pool and waits for it there, so the loop answers others meanwhile; and the work always runs
to its end, whatever happens to the request, so a file and its row are written whole or not at all. Work on the
request's database session that fails is rolled back in that thread, so a row lock it took is not held while the
request handles the error. These run the helper on a real event loop (tests/_async_run.py) against work that
blocks for a set time.
"""
import asyncio
import concurrent.futures
import contextvars
import threading
import time

import anyio
import pytest

from _async_run import run_coroutine
from app.core import off_loop

pytestmark = pytest.mark.unit

BLOCK = 0.6           # how long the work blocks
TICK = 0.02           # how often the other request asks


def _blocking(seconds=BLOCK, done=None):
    time.sleep(seconds)
    if done is not None:
        done.append(threading.get_ident())
    return "stored"


async def _ticker(stop, gaps):
    """Another request on the same loop: notes the longest it waited for its next turn."""
    last = time.monotonic()
    while not stop.is_set():
        await asyncio.sleep(TICK)
        now = time.monotonic()
        gaps.append(now - last)
        last = now


def test_the_loop_answers_others_while_the_work_blocks():
    async def scenario():
        stop, gaps, done = asyncio.Event(), [], []
        ticker = asyncio.create_task(_ticker(stop, gaps))
        await asyncio.sleep(TICK * 3)
        started = time.monotonic()
        result = await off_loop.run_to_end(_blocking, BLOCK, done)
        took = time.monotonic() - started
        stop.set()
        await ticker
        return result, took, max(gaps), done, threading.get_ident()

    result, took, worst, done, loop_thread = run_coroutine(scenario())
    assert result == "stored"
    assert took >= BLOCK * 0.9, "the work did not run as long as it blocks"
    assert done and done[0] != loop_thread, "the work ran on the loop's own thread"
    assert worst < BLOCK / 3, f"another request waited {worst:.3f} s for its turn while the work ran"


def test_what_the_work_raises_comes_back_as_itself():
    class Refused(Exception):
        pass

    def refuse():
        raise Refused("no room")

    async def scenario():
        with pytest.raises(Refused, match="no room"):
            await off_loop.run_to_end(refuse)
        return await off_loop.run_to_end(lambda a, b=0: a + b, 2, b=3)

    assert run_coroutine(scenario()) == 5


def test_the_work_sees_the_requests_context_variables():
    who = contextvars.ContextVar("who", default=None)

    async def scenario():
        who.set("203.0.113.7")
        return await off_loop.run_to_end(who.get)

    assert run_coroutine(scenario()) == "203.0.113.7"


def test_a_cancelled_request_waits_for_the_work_to_end_then_is_cancelled():
    """The server stopping cancels the request's task: the work it started goes on, the request waits for its
    end (nothing it does next runs beside the work), and the cancellation is passed on after."""
    release = threading.Event()
    finished = []

    def work():
        release.wait(10)
        finished.append(time.monotonic())
        return "row committed"

    async def scenario():
        task = asyncio.create_task(off_loop.run_to_end(work))
        await asyncio.sleep(0.1)
        task.cancel()
        await asyncio.sleep(0.3)
        waiting = not task.done()
        release.set()
        try:
            await task
            outcome = "returned"
        except asyncio.CancelledError:
            outcome = "cancelled"
        return waiting, outcome, time.monotonic()

    waiting, outcome, ended = run_coroutine(scenario())
    assert waiting, "the request gave up on the work while it was still running"
    assert finished and finished[0] <= ended, "the work did not run to its end"
    assert outcome == "cancelled", "the cancellation was lost"


def test_the_frameworks_cancellation_lets_the_work_end_and_its_result_come_back():
    """The web framework cancels through a scope, which asks again at every pause until the request ends. The
    work still runs to its end, its result comes back, and the cancellation lands at the next pause after."""
    after = []

    async def scenario():
        with anyio.CancelScope() as scope:
            scope.cancel()
            result = await off_loop.run_to_end(_blocking, 0.3)
            after.append(result)
            await anyio.sleep(0)
            after.append("not reached")
        return scope.cancelled_caught

    caught = run_coroutine(scenario())
    assert after == ["stored"], after
    assert caught is True


def test_calls_more_than_the_pool_has_threads_all_run_and_the_loop_still_answers():
    n = off_loop.pool_size() + 4

    async def scenario():
        stop, gaps = asyncio.Event(), []
        ticker = asyncio.create_task(_ticker(stop, gaps))
        results = await asyncio.gather(*(off_loop.run_to_end(_blocking, 0.2) for _ in range(n)))
        stop.set()
        await ticker
        return results, max(gaps)

    results, worst = run_coroutine(scenario())
    assert results == ["stored"] * n
    assert worst < 0.2


class _Session:
    """The request's database session as the work sees it: a row lock the work takes is held until the session
    commits or rolls back."""

    def __init__(self, rollback_fails=False):
        self.row_lock = threading.Lock()
        self.rollbacks = []
        self.rollback_fails = rollback_fails

    def lock_the_row(self):
        assert self.row_lock.acquire(timeout=5)

    def rollback(self):
        self.rollbacks.append(threading.current_thread().name)
        if self.row_lock.locked():
            self.row_lock.release()
        if self.rollback_fails:
            raise RuntimeError("the connection went away")


class _StaleEpoch(Exception):
    pass


def _http_refusal():
    from fastapi import HTTPException
    return HTTPException(status_code=409, detail={"code": "stale_zk_epoch"})


def _service_refusal():
    from app.services.vault_service import StorageLimitExceeded
    return StorageLimitExceeded("no room", kind="vault", used=1, cap=1)


# What the work on a session raises after it took a lock: its own error, the HTTP refusal a completion raises
# (a key that changed meanwhile), and a refusal of the service's (no room for the file).
REFUSALS = [lambda: _StaleEpoch("the vault key changed during upload"), _http_refusal, _service_refusal]


@pytest.mark.parametrize("refusal", REFUSALS, ids=["own", "http", "service"])
def test_work_on_the_session_that_fails_has_released_its_lock_before_the_request_goes_on(refusal):
    """A completion takes the vault's row lock, then refuses the upload. Its error handling waits for the file's
    removal; another request that opens the vault must not find the lock still held meanwhile, or it waits for it
    on the loop until the lock timeout, and every request with it. Whatever the refusal is."""
    db = _Session()
    raised = refusal()

    def refuse_after_the_lock():
        db.lock_the_row()
        raise raised

    async def scenario():
        try:
            await off_loop.run_to_end_on_session(db, refuse_after_the_lock)
        except type(raised) as caught:
            assert caught is raised
            free_while_handling = db.row_lock.acquire(blocking=False)
            if free_while_handling:
                db.row_lock.release()
            # The error handling waits for other work, as the removal of the file does.
            await off_loop.run_to_end(_blocking, 0.05)
            return free_while_handling, list(db.rollbacks), threading.current_thread().name
        return None

    free, rollbacks, loop_thread = run_coroutine(scenario())
    assert free is True, "the row lock was still held while the request handled the error"
    assert len(rollbacks) == 1 and rollbacks[0] != loop_thread, rollbacks
    assert rollbacks[0].startswith("stored-bytes"), "the session was not rolled back in the pool's thread"


def test_work_on_the_session_that_succeeds_is_not_rolled_back():
    db = _Session()

    async def scenario():
        return await off_loop.run_to_end_on_session(db, lambda a, b=0: a + b, 2, b=3)

    assert run_coroutine(scenario()) == 5
    assert db.rollbacks == []


def test_a_rollback_that_fails_does_not_hide_what_the_work_raised():
    db = _Session(rollback_fails=True)

    def refuse():
        raise _StaleEpoch("refused")

    async def scenario():
        with pytest.raises(_StaleEpoch, match="refused"):
            await off_loop.run_to_end_on_session(db, refuse)
        return list(db.rollbacks)

    assert len(run_coroutine(scenario())) == 1


def test_the_work_is_not_queued_behind_the_loops_default_executor():
    """The /ws/monitor poller parks threads in the event loop's default executor for as long as it polls. Work run
    here does not wait for them: it has a pool of its own."""
    release = threading.Event()
    timer = threading.Timer(3.0, release.set)

    async def scenario():
        loop = asyncio.get_running_loop()
        parked_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(parked_pool)
        parked = loop.run_in_executor(None, release.wait, 10)
        timer.start()
        try:
            started = time.monotonic()
            result = await off_loop.run_to_end(_blocking, 0.1)
            return result, time.monotonic() - started
        finally:
            release.set()
            await parked
            parked_pool.shutdown(wait=False)

    try:
        result, took = run_coroutine(scenario())
    finally:
        release.set()
        timer.cancel()
    assert result == "stored"
    assert took < 1.5, f"the work waited {took:.2f} s for a thread the loop's default executor had parked"


def test_the_pool_has_a_thread_for_every_transfer_the_ceilings_admit_and_room_for_the_rest():
    from app.core.transfer_admission import admitted_at_most
    for limit in list(range(-1, 130)) + [256]:
        assert off_loop.workers(limit) >= off_loop.MIN_WORKERS == 32
        assert off_loop.workers(limit) - admitted_at_most(limit) >= off_loop.HEADROOM == 12, limit
    assert off_loop.workers(16) == 32, "the default ceiling's pool changed"


def test_at_a_raised_ceiling_a_chunk_sync_is_not_kept_waiting_behind_every_admitted_transfer(monkeypatch):
    """At a ceiling of 40 the two ceilings admit 50 transfers, each of which may hold a thread here for minutes (a
    folder copy). The pool had 32 threads: those took every one, and a chunk's sync, which takes milliseconds,
    waited behind them. With every admitted transfer running, a sync is still done at once."""
    from app.core.config import settings
    from app.core.transfer_admission import admitted_at_most
    monkeypatch.setattr(settings, "max_concurrent_transfers", 40)
    # A pool of its own, made at the first use below; the pool and its size are put back together afterwards.
    monkeypatch.setattr(off_loop, "_pool", None)
    monkeypatch.setattr(off_loop, "_pool_size", None)
    admitted = admitted_at_most(40)
    release = threading.Event()

    def transfer():
        assert release.wait(10)
        return "copied"

    async def scenario():
        running = [asyncio.ensure_future(off_loop.run_to_end(transfer)) for _ in range(admitted)]
        await asyncio.sleep(0.2)
        started = time.monotonic()
        try:
            synced = await asyncio.wait_for(off_loop.run_to_end(lambda: "synced"), timeout=3)
        except asyncio.TimeoutError:
            synced = None
        took = time.monotonic() - started
        release.set()
        return synced, took, await asyncio.gather(*running)

    try:
        synced, took, copied = run_coroutine(scenario())
    finally:
        release.set()
        pool = off_loop._pool
        if pool is not None:
            pool.shutdown(wait=True)
    assert off_loop.workers(40) == 62
    assert synced == "synced" and took < 1, f"the sync waited {took:.1f} s behind {admitted} transfers"
    assert copied == ["copied"] * admitted


def test_the_pool_size_reported_is_that_of_the_pool_in_use():
    """pool_size() says how many threads the pool run_to_end uses has: a test that sends more calls than that reads
    it. It stays true after the test above made a pool of its own for a raised ceiling and put the first one back."""
    assert off_loop.pool_size() == off_loop._executor()._max_workers
