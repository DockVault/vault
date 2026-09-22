"""No test touches an event loop except through tests/_async_run.py, and that helper owns its loops.

Two failures this pins, both of which pass every local lane and fail only in CI's full suite:

  * ``asyncio.run()`` in a test module. After the browser tests a loop is left running in the main
    thread for the rest of the session, and ``asyncio.run()`` refuses there. A module that calls it
    passes while it happens to sort BEFORE ``test_ui_*`` and fails the day it is renamed, with an
    error that points at asyncio rather than at ordering.
  * ``asyncio.events._set_running_loop()`` on the main thread. The slot is thread-local and the main
    thread's belongs to Playwright's suspended dispatcher; a test that set and cleared it hung the
    session's ``browser.close()`` at teardown until the job cap -- it cost four capped CI runs.

The rule is structural and names no files: every loop primitive (``asyncio.run``,
``run_until_complete``, ``new_event_loop``, ``_set_running_loop``) lives in ``_async_run.py`` and
nowhere else under tests/. Seven modules used to carry a private "loop in a thread" helper each,
correct by discipline; now there is one, and the discipline is a test. The single lawful exception:
``asyncio.run(`` inside a ``with pytest.raises(`` block -- a test proving that it refuses.

The general form, worth writing beside it: a test that manipulates process-wide or thread-local
interpreter state must confine it to state it owns.
"""
import asyncio
import io
import re
import threading
import tokenize
from pathlib import Path

import pytest

from _async_run import call_with_a_running_loop_in_a_worker, run_coroutine

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parent
HELPER = TESTS / "_async_run.py"

_PRIMITIVES = re.compile(r"\basyncio\.run\(|\.run_until_complete\(|\bnew_event_loop\(|_set_running_loop\(")


def _code_lines(path: Path):
    """The file's lines with every comment and string token blanked, so a docstring that MENTIONS
    ``asyncio.run()`` (several do, to say why they avoid it) is not a call."""
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                (r0, c0), (r1, c1) = tok.start, tok.end
                for r in range(r0, r1 + 1):
                    line = lines[r - 1]
                    a = c0 if r == r0 else 0
                    b = c1 if r == r1 else len(line.rstrip("\r\n"))
                    lines[r - 1] = line[:a] + " " * (b - a) + line[b:]
    except tokenize.TokenError:
        pass
    return [ln.rstrip("\r\n") for ln in lines]


def _inside_pytest_raises(lines, idx):
    """True if line ``idx`` sits inside a ``with pytest.raises(`` block: a ``with pytest.raises(``
    line above it with smaller indentation, and nothing between them dedented to that level."""
    own = len(lines[idx]) - len(lines[idx].lstrip())
    for j in range(idx - 1, -1, -1):
        ln = lines[j]
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent >= own:
            continue                                    # a sibling or deeper: not an enclosing block
        if ln.lstrip().startswith("with ") and "pytest.raises(" in ln:
            return True
        if ln.lstrip().startswith(("def ", "class ")):
            return False
        own = indent                                    # walk out through enclosing blocks only
    return False


def _offences():
    found = []
    for path in sorted(TESTS.rglob("*.py")):
        if path == HELPER or path.name == Path(__file__).name:
            continue
        lines = _code_lines(path)
        for i, ln in enumerate(lines):
            m = _PRIMITIVES.search(ln)
            if not m:
                continue
            if m.group(0) == "asyncio.run(" and _inside_pytest_raises(lines, i):
                continue
            found.append(f"{path.relative_to(TESTS)}:{i + 1}: {ln.strip()}")
    return found


def test_no_test_touches_an_event_loop_except_through_the_one_helper():
    offences = _offences()
    assert not offences, (
        "run coroutines through tests/_async_run.py (run_coroutine / "
        "call_with_a_running_loop_in_a_worker); a private loop helper or a direct asyncio.run() "
        "passes locally and fails after the browser tests in CI:\n  " + "\n  ".join(offences)
    )


def test_the_scan_sees_a_call_but_not_a_mention_and_honours_the_one_lawful_home(tmp_path):
    # The scan's own edges, so it cannot pass by seeing nothing: a call is an offence, a docstring
    # or comment mentioning the same text is not, and asyncio.run( inside `with pytest.raises(` is
    # the one lawful home -- but not once the block has ended.
    p = tmp_path / "test_probe.py"
    p.write_text(
        '"""asyncio.run() is mentioned here."""\n'
        "import asyncio  # asyncio.run( in a comment\n"
        "def test_a():\n"
        "    with pytest.raises(RuntimeError):\n"
        "        asyncio.run(x())\n"
        "    asyncio.run(y())\n"
        "def test_b():\n"
        "    loop.run_until_complete(z())\n",
        encoding="utf-8",
    )
    lines = _code_lines(p)
    hits = [(i + 1, _PRIMITIVES.search(ln).group(0)) for i, ln in enumerate(lines) if _PRIMITIVES.search(ln)]
    assert hits == [(5, "asyncio.run("), (6, "asyncio.run("), (8, ".run_until_complete(")]
    assert _inside_pytest_raises(lines, 4) is True
    assert _inside_pytest_raises(lines, 5) is False
    assert _inside_pytest_raises(lines, 7) is False


def test_the_helper_lives_on_its_own_thread_and_never_reads_the_main_threads_slot():
    async def where():
        await asyncio.sleep(0)
        return threading.current_thread().name, threading.current_thread() is threading.main_thread()
    name, on_main = run_coroutine(where())
    assert name == "test-coroutine" and on_main is False
    # Structural: the helper's only loop primitives are on a thread it starts, and the main thread's
    # slot is never written -- the only _set_running_loop calls sit inside the worker function.
    src = HELPER.read_text(encoding="utf-8")
    assert src.count("_set_running_loop(") == 2
    worker = src[src.index("def call_with_a_running_loop_in_a_worker("):]
    inner = worker[worker.index("    def go():"):worker.index("    t = threading.Thread(")]
    assert inner.count("_set_running_loop(") == 2, "the slot may be set only inside the worker thread"
    # Every thread the helper starts is a daemon: a coroutine that outlives its timeout must not
    # keep the interpreter alive at exit. Counted against the constructions, not merely present.
    assert src.count("threading.Thread(") == 2 and src.count("daemon=True") == 2


def test_the_helper_works_while_a_loop_is_running_in_the_calling_thread():
    # The state the browser tests leave behind, made in a worker this test owns: asyncio.run()
    # refuses there (the failure the helper exists for) and run_coroutine does not. The main
    # thread's slot is untouched throughout.
    main_slot_before = asyncio.events._get_running_loop()

    async def two():
        await asyncio.sleep(0)
        return 2

    def inside():
        refused = two()
        with pytest.raises(RuntimeError, match="running event loop"):
            asyncio.run(refused)
        refused.close()                                 # never started; do not let it warn
        return run_coroutine(two())

    assert call_with_a_running_loop_in_a_worker(inside) == 2
    assert asyncio.events._get_running_loop() is main_slot_before, "the main thread's running-loop slot was touched"


def test_an_exception_comes_back_as_itself_and_async_generators_are_shut_down():
    class Teapot(Exception):
        pass

    async def boom():
        raise Teapot()

    with pytest.raises(Teapot):
        run_coroutine(boom())

    closed = []

    async def gen():
        try:
            yield 1
            yield 2
        finally:
            closed.append(True)

    async def abandon():
        async for item in gen():
            return item                                 # abandons the generator mid-iteration

    assert run_coroutine(abandon()) == 1
    assert closed == [True], "the abandoned async generator's finally never ran"


def test_a_coroutine_that_never_finishes_is_cancelled_and_reported_not_waited_for():
    cancelled = []

    async def forever():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    before = {t.name for t in threading.enumerate()}
    with pytest.raises(TimeoutError, match="did not finish"):
        run_coroutine(forever(), timeout=0.5)
    assert cancelled == [True]
    lingering = {t.name for t in threading.enumerate()} - before
    assert "test-coroutine" not in lingering, "the timed-out thread was left behind"
