"""The ONE place a test runs a coroutine, or touches an event loop at all.

``asyncio.run()`` refuses when an event loop is already running in the calling thread -- and after
the browser tests (Playwright's sync API) have run in a session, one IS: it stays behind in the main
thread for the rest of the process. So a module that sorts after ``test_ui_*`` and calls
``asyncio.run()`` passes every local lane (which deselect the browser tests) and fails only in CI's
full suite, with an error that points at asyncio rather than at ordering. And the running-loop slot
is THREAD-LOCAL: the main thread's belongs to Playwright's suspended dispatcher for the rest of the
session, and a test that set and then cleared it hung the session's ``browser.close()`` at teardown
until the job cap -- twice.

The general form: a test that manipulates process-wide or thread-local interpreter state must
confine it to state it owns. A loop this module makes lives on a thread this module makes, so the
main thread's state is never read, never written, and never depended on. Every test module uses
these entry points; none carries a loop helper of its own (tests/test_async_discipline.py holds
that structurally), so the rules above are enforced in one implementation rather than remembered
in seven.
"""
import asyncio
import threading

DEFAULT_TIMEOUT = 60.0


def run_coroutine(coro, timeout=DEFAULT_TIMEOUT):
    """Run ``coro`` to completion on a fresh loop in a thread of its own and return its result.

    An exception inside the coroutine comes back as itself, on the caller's thread. The loop's
    async generators are shut down before it closes, because abandoning one mid-iteration is
    exactly what a refusal path under test does, and its ``finally`` must run. If the coroutine has
    not finished within ``timeout`` seconds it is cancelled on its loop and ``TimeoutError`` is
    raised here: a test never blocks the run unbounded, and never leaves a thread behind.
    """
    box = {}
    started = threading.Event()

    def go():
        loop = asyncio.new_event_loop()
        box["loop"] = loop
        try:
            task = loop.create_task(coro)
            box["task"] = task
            started.set()
            box["value"] = loop.run_until_complete(task)
        except BaseException as e:  # noqa: BLE001 -- re-raised in the caller's thread below
            box["error"] = e
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            finally:
                loop.close()

    t = threading.Thread(target=go, name="test-coroutine", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        if started.wait(1) and "task" in box:
            box["loop"].call_soon_threadsafe(box["task"].cancel)
        t.join(5)
        raise TimeoutError(f"the async body did not finish within {timeout} s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def call_with_a_running_loop_in_a_worker(fn, timeout=DEFAULT_TIMEOUT):
    """Call ``fn()`` on a worker thread whose running-loop slot is set, and return its result.

    This is the state the browser tests leave in the MAIN thread for the rest of a session, made
    on purpose so a test can prove its own code copes with it -- in a thread this helper owns, so
    the main thread's slot is never touched. The slot is cleared and the loop closed before the
    thread ends; the caller may assert the main thread's slot is what it was.
    """
    box = {}

    def go():
        loop = asyncio.new_event_loop()
        asyncio.events._set_running_loop(loop)          # THIS thread's slot only
        try:
            box["value"] = fn()
        except BaseException as e:  # noqa: BLE001 -- re-raised in the caller's thread below
            box["error"] = e
        finally:
            asyncio.events._set_running_loop(None)
            loop.close()

    t = threading.Thread(target=go, name="test-running-loop-worker", daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"the worker did not finish within {timeout} s")
    if "error" in box:
        raise box["error"]
    return box["value"]
