"""The Redis circuit breaker closes only when a BACKGROUND probe proves Redis healthy, never on a
timer, and no foreground caller ever touches the socket while it is open.

The bug this pins: while Redis is down the breaker used to lapse after a cooldown, so the first
foreground caller to touch Redis afterwards -- typically RateLimitMiddleware's synchronous check, ON
the event loop, on every route -- paid the socket timeout again to rediscover the outage, freezing
the whole server for ~one timeout every cooldown. Now, once open, the breaker stays open; a single
daemon thread waits a cooldown, pings Redis on a short-timeout connection, and only its SUCCESS
closes the breaker. The server heals while idle, and a plain sleep is enough to wait it out. If
that thread hangs (a resolver stall no socket timeout bounds) it is REPLACED by another, within a
ceiling -- never by a foreground caller re-probing -- and staleness is judged on a monotonic clock.

Timing is pinned by threads and events, never by a sleep in an assertion path: the probe's inter-
attempt wait and its ping are seams a test replaces, and the recovery case joins the probe thread.
"""
import threading
import time

import pytest

# rate_limiter imports app.core.database (a lazy client proxy); the bare env keeps this module
# importable and runnable alone with no .env.
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import rate_limiter as R

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_breaker():
    """Every test starts and ends with a closed breaker and no tracked probe thread. A probe thread
    a test started is joined by that test; a closed breaker makes any stray one exit at its next
    wait."""
    def _clear():
        R._cb_record_success()
        with R._cb_lock:
            R._cb_probe_thread = None
            R._cb_probe_threads[:] = []
            R._cb_probe_cap_logged = False
            R._cb_last_attempt_at = R._cb_monotonic()  # fresh, so the staleness backstop stays dormant
    _clear()
    yield
    _clear()


def _raise_down():
    raise RuntimeError("redis down")


class _RecordingRedis:
    """A backend that RECORDS each script call and returns a healthy result. Recording (not raising)
    is the reliable signal: a raise from eval is swallowed by the fail-open handler, so it could not
    tell a skipped socket from a touched-then-swallowed one. The test asserts it was never touched."""

    def __init__(self):
        self.evals = 0

    def eval(self, *a, **k):
        self.evals += 1
        return [1, 4, str(int(time.time()) + 10)]  # allowed, remaining, reset_at


def test_no_foreground_caller_touches_the_socket_while_the_breaker_is_open():
    # Open the breaker directly (no probe thread needed for this check).
    with R._cb_lock:
        R._cb_open = True
    try:
        fake = _RecordingRedis()
        rl = R.RateLimiter(fake)
        # Fail-open traffic is allowed without touching the socket ...
        allowed, remaining, reset = rl._sliding_window_check("k", 5, 10, fail_open=True)
        assert allowed is True
        # ... and fail-closed (auth) traffic drops to its fallback (a raise), also no socket.
        with pytest.raises(R.RateLimiterUnavailable):
            rl._sliding_window_check("k", 5, 10, fail_open=False)
        assert fake.evals == 0, "the foreground path hit Redis while the breaker was open"
    finally:
        R._cb_record_success()


def test_a_probe_attempt_failure_keeps_the_breaker_open(monkeypatch):
    with R._cb_lock:
        R._cb_open = True
    monkeypatch.setattr(R, "_cb_ping", _raise_down)
    assert R._cb_probe_attempt() is False
    assert R._cb_open is True                       # a failed probe never closes the breaker


def test_a_probe_attempt_success_closes_the_breaker(monkeypatch):
    with R._cb_lock:
        R._cb_open = True
    monkeypatch.setattr(R, "_cb_ping", lambda: None)
    assert R._cb_probe_attempt() is True
    assert R._cb_open is False


def test_opening_starts_one_background_probe_that_closes_on_recovery(monkeypatch):
    # Drive the loop without real time (no-op inter-attempt wait), and hold the ping on an Event so
    # the probe is observably in flight. A second open must not start a second probe; when Redis
    # recovers the ping returns, the probe closes the breaker and the thread exits.
    started = threading.Event()
    release = threading.Event()
    pings = []

    def _blocking_ping():
        pings.append(threading.current_thread().name)
        started.set()
        assert release.wait(5), "probe ping was never released"
        # returning (no raise) means Redis is healthy

    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", _blocking_ping)

    R._cb_record_failure(time.time())               # opens the breaker and starts the probe
    assert R._cb_is_open(time.time()) is True
    assert started.wait(5), "the background probe never ran"
    first = R._cb_probe_thread
    assert first is not None and first.is_alive() and first.name == "redis-cb-probe"

    R._cb_record_failure(time.time())               # a second open must not start a second probe
    assert R._cb_probe_thread is first

    release.set()
    first.join(timeout=5)
    assert not first.is_alive()
    assert R._cb_open is False                       # the probe's success closed it
    assert len(pings) == 1                           # exactly one probe ran


def test_a_closed_breaker_reports_not_open():
    R._cb_record_success()
    assert R._cb_is_open(time.time()) is False
    assert R.redis_circuit_open() is False


# --- the breaker can never sit open with no working probe ----------------------------------------
# The flag has no timer and the probe is its only closer, and while open no foreground caller records
# a failure -- so "open with no working probe" would be permanent. Three ways it could arise, each
# covered below: a failure racing the probe's exit, a Thread.start() that raised, and a hung probe.


def test_a_failure_racing_a_probe_success_does_not_strand_the_breaker_open(monkeypatch):
    # Inject exactly one failure in the window between a probe recording success and the loop
    # re-checking -- the window the exit fix closes. The loop must NOT exit stuck-open: it keeps
    # looping on the SAME thread, and a later clean success closes it.
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", lambda: None)  # every ping succeeds
    once = {"fired": False}

    def _inject_failure():
        if not once["fired"]:
            once["fired"] = True
            R._cb_record_failure(time.time())  # a failure lands right after success is recorded

    monkeypatch.setattr(R, "_cb_probe_post_success", _inject_failure)

    R._cb_record_failure(time.time())  # opens and starts the probe
    thread = R._cb_probe_thread
    assert thread is not None
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert R._cb_open is False          # not stranded; the second success closed it
    assert R._cb_probe_thread is None   # same thread throughout; a clean close freed the slot


def test_a_failed_probe_start_does_not_escape_and_the_backstop_heals(monkeypatch):
    # A Thread.start() that raises (thread exhaustion) must not 500 the request, and must not wedge:
    # the breaker opens with no probe, then the staleness backstop restarts one that heals.
    real_thread = R.threading.Thread

    class _BadThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            raise RuntimeError("thread exhaustion")

    monkeypatch.setattr(R.threading, "Thread", _BadThread)
    R._cb_record_failure(time.time())            # must NOT raise
    assert R._cb_open is True and R._cb_probe_thread is None  # open, no probe started

    monkeypatch.setattr(R.threading, "Thread", real_thread)
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", lambda: None)          # healthy once a probe can start
    R._cb_last_attempt_at = R._cb_monotonic() - (R._CB_PROBE_STALE_SECONDS + 1)  # age it: go stale
    assert R._cb_is_open(time.time()) is True    # backstop restarts the probe and keeps skipping
    thread = R._cb_probe_thread
    assert thread is not None
    thread.join(timeout=5)
    assert R._cb_open is False                    # the restarted probe healed it


def test_a_dead_probe_is_restarted_by_the_staleness_backstop(monkeypatch):
    # A probe whose loop crashes leaves a DEAD thread in the slot; the backstop restarts it.
    real_loop = R._cb_probe_loop
    state = {"crashed": False}

    def _loop_dies_once():
        if not state["crashed"]:
            state["crashed"] = True
            raise RuntimeError("probe crashed on entry")
        real_loop()

    monkeypatch.setattr(R, "_cb_probe_loop", _loop_dies_once)
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", lambda: None)

    R._cb_record_failure(time.time())            # opens; probe #1 crashes on entry
    first = R._cb_probe_thread
    assert first is not None
    first.join(timeout=5)
    assert not first.is_alive()
    assert R._cb_open is True                     # a crashed probe closed nothing

    R._cb_last_attempt_at = R._cb_monotonic() - (R._CB_PROBE_STALE_SECONDS + 1)
    assert R._cb_is_open(time.time()) is True     # dead slot -> backstop restarts, stays open
    second = R._cb_probe_thread
    assert second is not None and second is not first
    second.join(timeout=5)
    assert R._cb_open is False                     # the restarted (real) probe healed it


# --- a hung probe is REPLACED; no caller ever re-probes in the foreground ------------------------
# A probe stuck in its ping (a DNS lookup the socket timeout does not bound) is ALIVE, so "restart
# if dead" cannot help. The foreground client's connect is exactly as unbounded, so letting a caller
# re-probe would be the on-loop stall the breaker exists to remove. Instead a replacement thread
# takes the slot; ownership gates the old thread's exit AND the stamp; replacements are capped.


class _Parking:
    """A ping that parks each probe thread on its own gate until the test releases it, then does
    what the test said: return (healthy) or raise (still down). Threads are keyed by identity."""

    def __init__(self):
        self.entered = {}
        self.gates = {}
        self.outcome = {}
        self.lock = threading.Lock()

    def ping(self):
        me = threading.current_thread()
        with self.lock:
            entered = self.entered.setdefault(me, threading.Event())
            gate = self.gates.setdefault(me, threading.Event())
        entered.set()
        assert gate.wait(30), "a parked probe was never released"
        if self.outcome.get(me) == "down":
            raise RuntimeError("redis down")

    def wait_entered(self, thread):
        with self.lock:
            ev = self.entered.setdefault(thread, threading.Event())
        assert ev.wait(5), "the probe never reached its ping"

    def release(self, thread, outcome="healthy"):
        with self.lock:
            self.outcome[thread] = outcome
            gate = self.gates.setdefault(thread, threading.Event())
        gate.set()


def _go_stale():
    R._cb_last_attempt_at = R._cb_monotonic() - (R._CB_PROBE_STALE_SECONDS + 1)


def _is_open_from_another_thread():
    """'No request path probes in the foreground', as a deterministic shape rather than a timing
    measurement: ask the breaker from a thread that is not the probe, and return exactly what a
    request would be told."""
    out = []
    t = threading.Thread(target=lambda: out.append(R._cb_is_open(time.time())))
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "the is-open check itself stalled -- a caller probed in the foreground"
    return out[0]


def test_a_hung_probe_is_replaced_and_no_caller_is_ever_told_to_reprobe(monkeypatch):
    park = _Parking()
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", park.ping)
    R._cb_record_failure(time.time())            # opens; the probe parks in its ping
    first = R._cb_probe_thread
    park.wait_entered(first)

    _go_stale()
    assert _is_open_from_another_thread() is True   # alive-but-stale: STILL skipping ...
    second = R._cb_probe_thread
    assert second is not None and second is not first and second.is_alive()  # ... a replacement owns the slot
    park.wait_entered(second)
    # Every later caller, in every state the slot can be in (fresh; stale with a replacement still
    # possible; stale at the ceiling), is told to skip -- never False.
    for _ in range(3):
        assert _is_open_from_another_thread() is True
        _go_stale()
        assert _is_open_from_another_thread() is True

    replacements = [t for t in R._cb_probe_threads if t is not first]
    for t in replacements:                        # the replacements find Redis back ...
        park.wait_entered(t)
        park.release(t, "healthy")
    for t in replacements:
        t.join(timeout=5)
    assert R._cb_open is False                    # ... and heal the breaker
    park.release(first, "down")                   # the stuck one finally wakes to a still-failing ping
    first.join(timeout=5)
    assert not first.is_alive() and R._cb_open is False and R._cb_probe_thread is None


def test_a_superseded_probe_neither_clears_the_slot_nor_keeps_probing(monkeypatch):
    # Ownership gates the exit and the slot write together: the stuck thread, once replaced, must
    # leave the moment it wakes -- not clear the slot its replacement holds (the exit race, from the
    # other side), and not loop on beside it while the breaker is still open.
    park = _Parking()
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", park.ping)
    R._cb_record_failure(time.time())
    first = R._cb_probe_thread
    park.wait_entered(first)
    _go_stale()
    assert R._cb_is_open(time.time()) is True
    second = R._cb_probe_thread
    assert second is not first
    park.wait_entered(second)                     # the replacement is parked too: the slot stays held

    park.release(first, "down")                   # the stuck one wakes to a failing ping, breaker still open
    first.join(timeout=5)
    assert not first.is_alive(), "a superseded probe kept looping beside its replacement"
    assert R._cb_probe_thread is second, "a superseded probe cleared a slot it no longer owned"
    assert R._cb_open is True
    park.release(second, "healthy")
    second.join(timeout=5)
    assert R._cb_open is False and R._cb_probe_thread is None


def test_a_superseded_probe_does_not_refresh_the_stamp_but_its_success_still_counts(monkeypatch):
    # The stamp is the backstop's only evidence that the OWNER is making progress. A superseded
    # thread waking once per period must not refresh it (that would hold the backstop off forever);
    # but a ping that succeeded now is current news whoever ran it, so its success closes the breaker.
    monkeypatch.setattr(R, "_cb_ping", lambda: None)
    with R._cb_lock:
        R._cb_open = True
        R._cb_probe_thread = threading.Thread(name="someone-else")  # the slot is owned by another
    stamp = R._cb_monotonic() - 5
    R._cb_last_attempt_at = stamp
    assert R._cb_probe_attempt() is True         # this thread is not the owner
    assert R._cb_last_attempt_at == stamp         # the stamp did not move
    assert R._cb_open is False                    # the success was recorded
    # The owner (or a bare call with no owner at all) does stamp.
    with R._cb_lock:
        R._cb_open = True
        R._cb_probe_thread = None
    R._cb_probe_attempt()
    assert R._cb_last_attempt_at > stamp


def test_replacements_are_capped_and_the_cap_is_logged_once(monkeypatch, caplog):
    # Each stale period that still finds the owner stuck would start another thread; under an
    # hour-long resolver hang that is an unbounded leak of threads parked in the same getaddrinfo.
    # N+2 stale periods must produce at most N live probe threads, and the ceiling is logged once.
    import logging
    park = _Parking()
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", park.ping)
    n = R._CB_MAX_PROBE_THREADS
    with caplog.at_level(logging.WARNING, logger="app.core.rate_limiter"):
        R._cb_record_failure(time.time())
        park.wait_entered(R._cb_probe_thread)
        for _ in range(n + 2):
            _go_stale()
            assert R._cb_is_open(time.time()) is True
            park.wait_entered(R._cb_probe_thread)
    threads = list(R._cb_probe_threads)
    assert len(threads) == n and all(t.is_alive() for t in threads)
    assert sum(1 for rec in caplog.records if "ceiling" in rec.getMessage()) == 1
    for t in threads:
        park.release(t, "healthy")
    for t in threads:
        t.join(timeout=5)
    assert R._cb_open is False and R._cb_probe_thread is None
    # A later open period logs the ceiling again -- once is per open period, not per process.
    with caplog.at_level(logging.WARNING, logger="app.core.rate_limiter"):
        R._cb_record_failure(time.time())
        park.wait_entered(R._cb_probe_thread)
        for _ in range(n + 1):
            _go_stale()
            assert R._cb_is_open(time.time()) is True
            park.wait_entered(R._cb_probe_thread)
    assert sum(1 for rec in caplog.records if "ceiling" in rec.getMessage()) == 2
    for t in list(R._cb_probe_threads):
        park.release(t, "healthy")
    for t in list(R._cb_probe_threads):
        t.join(timeout=5)
    assert R._cb_open is False


def test_a_failed_replacement_start_keeps_skipping_and_the_next_period_heals(monkeypatch):
    # With no foreground escape, the only closer is a thread, so "cannot wedge open" now rests on
    # being able to START one: a Thread.start() that raises on the stale path must not escape into
    # the request path, must leave the breaker skipping, and the NEXT stale period must try again
    # and heal. (The sibling above, for a start that raises at the open, still stands.)
    park = _Parking()
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", park.ping)
    R._cb_record_failure(time.time())
    first = R._cb_probe_thread
    park.wait_entered(first)                      # the owner is stuck
    real_thread = R.threading.Thread

    class _BadThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            raise RuntimeError("thread exhaustion")

    monkeypatch.setattr(R.threading, "Thread", _BadThread)
    _go_stale()
    assert R._cb_is_open(time.time()) is True    # must NOT raise, must still skip
    assert R._cb_open is True and R._cb_probe_thread is first   # nothing replaced it; nothing wedged
    assert len(R._cb_probe_threads) == 1

    monkeypatch.setattr(R.threading, "Thread", real_thread)
    _go_stale()
    assert R._cb_is_open(time.time()) is True    # the next period tries again ...
    second = R._cb_probe_thread
    assert second is not first
    park.wait_entered(second)
    park.release(second, "healthy")
    second.join(timeout=5)
    assert R._cb_open is False                    # ... and heals
    park.release(first, "down")
    first.join(timeout=5)


# --- the staleness stamp is monotonic ------------------------------------------------------------
# The callers pass a wall-clock `now` for the sliding-window arithmetic; the staleness test must not
# read it. A wall-clock step forward would otherwise fake a stale probe (and start a needless
# replacement); a step backward would hide a dead one for the length of the jump. Advancing the
# monotonic source proves nothing here (the old code passes that too); the distinguishing pair is a
# wall-clock jump in each direction with the monotonic source standing still.


def test_a_wall_clock_jump_forward_does_not_fake_a_stale_probe(monkeypatch):
    park = _Parking()
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", park.ping)
    R._cb_record_failure(time.time())
    first = R._cb_probe_thread
    park.wait_entered(first)                      # alive, and freshly stamped
    far_future = time.time() + 10 * R._CB_PROBE_STALE_SECONDS
    assert R._cb_is_open(far_future) is True
    assert R._cb_probe_thread is first, "a wall-clock step started a needless replacement"
    assert len(R._cb_probe_threads) == 1
    park.release(first, "healthy")
    first.join(timeout=5)
    assert R._cb_open is False


def test_a_wall_clock_jump_backward_does_not_hide_a_dead_probe(monkeypatch):
    real_loop = R._cb_probe_loop
    state = {"crashed": False}

    def _loop_dies_once():
        if not state["crashed"]:
            state["crashed"] = True
            raise RuntimeError("probe crashed on entry")
        real_loop()

    monkeypatch.setattr(R, "_cb_probe_loop", _loop_dies_once)
    monkeypatch.setattr(R, "_cb_probe_sleep", lambda _s: None)
    monkeypatch.setattr(R, "_cb_ping", lambda: None)
    R._cb_record_failure(time.time())
    first = R._cb_probe_thread
    first.join(timeout=5)
    assert not first.is_alive() and R._cb_open is True
    _go_stale()                                   # the monotonic stamp says: stale
    far_past = time.time() - 10 * R._CB_PROBE_STALE_SECONDS
    assert R._cb_is_open(far_past) is True       # a backward wall-clock step must not suppress the backstop
    second = R._cb_probe_thread
    assert second is not None and second is not first, "a wall-clock step hid a dead probe"
    second.join(timeout=5)
    assert R._cb_open is False


def test_every_writer_of_the_stamp_and_its_reader_share_the_monotonic_source():
    # Mixing clocks is worse than either: a monotonic stamp compared against a wall-clock reading is
    # always stale, turning the backstop into the default path. Structural: the stamp is written in
    # exactly three places, all from _cb_monotonic(), and no staleness comparison reads `now`.
    import inspect
    import re
    src = inspect.getsource(R)
    writes = [w.split("#")[0].strip() for w in re.findall(r"_cb_last_attempt_at = ([^\n]+)", src)]
    writes = [w for w in writes if not w.startswith("0.0")]      # the module-level initialiser
    assert len(writes) == 3 and all(w in ("_cb_monotonic()", "mono") for w in writes), writes
    assert "now - _cb_last_attempt_at" not in src
    assert re.search(r"def _cb_monotonic\(\).*?return time\.monotonic\(\)", src, re.S)
