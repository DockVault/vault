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
    n = off_loop.WORKERS + 4

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


def test_work_on_the_session_that_fails_has_released_its_lock_before_the_request_goes_on():
    """A completion takes the vault's row lock, then refuses the upload. Its error handling waits for the file's
    removal; another request that opens the vault must not find the lock still held meanwhile, or it waits for it
    on the loop until the lock timeout, and every request with it."""
    db = _Session()

    def refuse_after_the_lock():
        db.lock_the_row()
        raise _StaleEpoch("the vault key changed during upload")

    async def scenario():
        try:
            await off_loop.run_to_end_on_session(db, refuse_after_the_lock)
        except _StaleEpoch:
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

