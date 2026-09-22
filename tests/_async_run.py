"""Run a coroutine to completion from a synchronous test, whatever the main thread's loop state.

``asyncio.run()`` refuses when an event loop is already running in the calling thread -- and after
the browser tests (Playwright's sync API) have run in a session, one IS: it stays behind in the main
thread for the rest of the process. So a module that sorts after ``test_ui_*`` and calls
``asyncio.run()`` passes every local lane (which deselect the browser tests) and fails only in CI's
full suite, with an error that points at asyncio rather than at ordering. Six modules call it today
and pass only because they sort BEFORE the browser tests.

This runs the coroutine on a fresh loop in its own thread, which works either way. Use it instead.
"""
import asyncio
import threading


def run_coroutine(coro):
    box = {}

    def go():
        loop = asyncio.new_event_loop()
        try:
            box["value"] = loop.run_until_complete(coro)
        except BaseException as e:  # noqa: BLE001 -- re-raised in the caller's thread below
            box["error"] = e
        finally:
            loop.close()

    t = threading.Thread(target=go, name="test-coroutine")
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["value"]
