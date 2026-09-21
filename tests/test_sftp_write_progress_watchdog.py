"""An upload that stops making progress is failed, so it cannot hold its resources for ever.

After authentication nothing else bounds a connection. A client that opens a file for writing and
then sends nothing keeps its thread, its transport and its connection slot until it chooses to
leave; one that sends a byte now and then keeps the same-name lock alive too, because every write
refreshes it. The watchdog watches each open write handle in windows: a window in which fewer than
the floor of bytes were accepted fails the handle. One rule covers both, the full stop and the
trickle.

WHAT IS MEASURED IS BYTES ACCEPTED, never elapsed time and never records flushed to storage. A
record is 1 MiB, so a genuinely slow link would go minutes without completing one while making
perfectly good progress; failing it would be the opposite of what this is for. Everywhere below
that asserts a handle was NOT failed does so in a sweep that failed a different handle in the same
call, because a sweep that failed nothing passes every "not failed" assertion by doing nothing.

Three things this file deliberately does, each because leaving it out made a real mutation
survive. Windows are anchored at a NON-ZERO clock, so a watchdog that never records a start time
(leaving the handle's default 0.0 against a monotonic clock in the hundred-thousands) is visible
rather than accidentally correct. The window and floor used here are NOT the shipped defaults, so
a sweep that ignores its arguments and reads the settings instead cannot pass. And both upload
shapes appear -- buffered, where the plaintext is staged to a file, and streaming, where it is
encrypted record by record -- because the discard they need is implemented differently in each.

The decision itself is driven directly, with an injected clock and hand-counted byte totals: no
thread, no socket and no waiting. What object-level tests CANNOT show -- that a real stalled
session's thread, slot and lock are genuinely released -- is not covered anywhere in this suite;
it is measured by hand against a running server.
"""
from __future__ import annotations

import io
import os
import threading
import tokenize
import types
from pathlib import Path

import paramiko
import pytest

from app.sftp import sftp_server as mod
from app.sftp.sftp_server import VaultSFTPHandle, _WriteProgressWatchdog

pytestmark = pytest.mark.unit

SRC = Path(mod.__file__)

# Deliberately NOT the shipped defaults (120 s / 65536 B): a sweep that ignores what it is handed
# and reads the settings instead must not be able to pass.
WINDOW = 90.0
FLOOR = 40_000
# Deliberately NOT zero: the handle's own default window start is 0.0, and against a real
# monotonic clock that is hours in the past. Anchoring every window at 0.0 hides a watchdog that
# never records a start time at all.
T0 = 10_000.0


def _handle(*, stream=None):
    """A write handle in the shape the open path leaves one -- minus what no watchdog code reads.

    The interface stands in for the session: the only thing the close path asks it is whether the
    session is over. Using the real 700-line class here would couple every test in this file to
    an unrelated constructor.
    """
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle._interface = types.SimpleNamespace(_session_over=False)
    handle.stream = stream
    return handle


def _watched(dog, *, at=T0, stream=None):
    handle = _handle(stream=stream)
    dog.watch(handle, now=at)
    return handle


class _FakeStream:
    """The streaming upload driver, as far as the watchdog can see it.

    `_failed` is the flag `_StreamingUpload.close()` reads to decide between committing the
    records it has already written and aborting them, so it is the whole discard on this path.
    """

    def __init__(self, result=paramiko.SFTP_OK):
        self._failed = False
        self._result = result
        self.written = []

    def write(self, offset, data):
        self.written.append((offset, len(data)))
        return self._result


def _buffered(dog, tmp_path, name="staged", *, at=T0):
    """A watched handle with a real staging file, so close() can run for real."""
    handle = _watched(dog, at=at)
    handle.writepath = str(tmp_path / name)
    handle.writefile = open(handle.writepath, "wb")
    return handle


def _quiet(monkeypatch):
    monkeypatch.setattr(mod, 'safe_event', lambda *a, **k: None)


def _source_without_comments(text: str) -> str:
    """Comments stripped, line structure kept -- so a source pin cannot be satisfied by prose."""
    lines = text.splitlines(keepends=True)
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT:
            row, col = token.start
            lines[row - 1] = lines[row - 1][:col].rstrip() + "\n"
    return "".join(lines)


# ---- the decision itself ------------------------------------------------------------------------

def test_a_window_that_has_not_closed_yet_is_never_failed():
    # Progress is judged per window, not moment to moment: a client that has sent nothing YET, one
    # second in, is not behind -- it has the rest of the window to send.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert _WriteProgressWatchdog.verdict(handle, T0 + 1.0, WINDOW, FLOOR) == 'ok'
    assert _WriteProgressWatchdog.verdict(handle, T0 + WINDOW - 0.001, WINDOW, FLOOR) == 'ok'


def test_a_window_that_closed_with_nothing_at_all_is_stalled():
    # (mutation: return 'ok' unconditionally -> red. mutation: compare > window instead of >= at
    # the boundary -> the boundary case below goes red.)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert _WriteProgressWatchdog.verdict(handle, T0 + WINDOW, WINDOW, FLOOR) == 'stalled'


def test_a_window_that_closed_above_the_floor_is_ok_and_starts_the_next_one():
    # THE DIRECTION THAT BREAKS REAL USERS. A slow client that cleared the floor is not failed,
    # and its window is restarted from now with its count zeroed -- so clearing one window does
    # not buy credit in the next.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle._progress_bytes = FLOOR + 1
    assert _WriteProgressWatchdog.verdict(handle, T0 + WINDOW, WINDOW, FLOOR) == 'ok'
    assert handle._progress_window_start == T0 + WINDOW, "the next window did not start from now"
    assert handle._progress_bytes == 0
    # ... and the next window is judged on its own: nothing in it, so it closes stalled.
    assert _WriteProgressWatchdog.verdict(handle, T0 + WINDOW * 2, WINDOW, FLOOR) == 'stalled'


def test_each_handle_is_judged_against_its_own_window():
    # The window is per handle, not a property of the clock: two uploads that began at different
    # times are two different windows. (mutation: drop the subtraction and compare `now` to the
    # window length -> red, because then every handle on a long-lived server is always stalled.)
    dog = _WriteProgressWatchdog()
    old = _watched(dog, at=T0)
    fresh = _watched(dog, at=T0 + WINDOW)
    now = T0 + WINDOW + 1.0
    assert _WriteProgressWatchdog.verdict(old, now, WINDOW, FLOOR) == 'stalled'
    assert _WriteProgressWatchdog.verdict(fresh, now, WINDOW, FLOOR) == 'ok'


def test_exactly_the_floor_clears_it_and_one_byte_short_does_not():
    # The boundary in both directions, because "at least the floor" and "more than the floor" are
    # one byte apart and only one of them is what the setting says.
    dog = _WriteProgressWatchdog()
    at_floor = _watched(dog)
    at_floor._progress_bytes = FLOOR
    assert _WriteProgressWatchdog.verdict(at_floor, T0 + WINDOW, WINDOW, FLOOR) == 'ok'

    short = _watched(dog)
    short._progress_bytes = FLOOR - 1
    assert _WriteProgressWatchdog.verdict(short, T0 + WINDOW, WINDOW, FLOOR) == 'stalled'


def test_a_trickle_below_the_floor_is_stalled_however_often_it_writes():
    # THE GHOST. A byte now and then is progress by any no-progress timer, and it refreshes the
    # same-name lock for ever. The floor is what tells it from a slow transfer.
    # (mutation: treat any non-zero count as progress -> red.)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle._progress_bytes = 1
    assert _WriteProgressWatchdog.verdict(handle, T0 + WINDOW, WINDOW, FLOOR) == 'stalled'


def test_floor_zero_means_any_byte_at_all_counts():
    # The documented meaning of 0: a pure no-progress timer, no rate requirement.
    # (mutation: drop the max(1, floor) so a zero floor passes a window with NOTHING in it -> red.)
    dog = _WriteProgressWatchdog()
    one_byte = _watched(dog)
    one_byte._progress_bytes = 1
    assert _WriteProgressWatchdog.verdict(one_byte, T0 + WINDOW, WINDOW, 0) == 'ok'

    nothing = _watched(dog)
    assert _WriteProgressWatchdog.verdict(nothing, T0 + WINDOW, WINDOW, 0) == 'stalled'


# ---- the sweep ----------------------------------------------------------------------------------

def test_a_zero_timeout_disables_the_watchdog_entirely(monkeypatch):
    # (mutation: sweep regardless of the timeout -> red.) The same handle, far past any window, is
    # failed with a positive timeout and untouched with zero -- so "returned nothing" cannot be
    # passing for the wrong reason.
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert dog.sweep(now=T0 + WINDOW * 10, window=0, floor=FLOOR) == []
    assert handle.interrupted is False
    assert dog.sweep(now=T0 + WINDOW * 10, window=WINDOW, floor=FLOOR) == [handle]


def test_the_sweep_fails_the_stalled_handle_and_leaves_the_progressing_one_alone(monkeypatch):
    # The positive and the negative in ONE sweep, which is the only way the negative means
    # anything: a sweep that failed nothing would pass the "not failed" half by doing nothing.
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    stalled = _watched(dog)
    slow = _watched(dog)
    slow._progress_bytes = FLOOR

    failed = dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)

    assert set(failed) == {stalled}, "the stalled handle was not the one failed"
    assert stalled.interrupted is True
    assert slow.interrupted is False, "a client above the floor was failed for being slow"


def test_a_client_that_keeps_clearing_the_floor_is_watched_the_whole_time(monkeypatch):
    """The real slow user: window after window, always above the floor, never failed -- and still
    being watched at the end.

    Failing a handle is not the only way to stop protecting against it. A watchdog that dropped a
    handle the first time it approved one is indistinguishable from a working one for as long as
    the client keeps sending, and defends nothing the moment it stops: send 64 KB once, then hold
    the slot for ever. Each round below carries a fresh canary so "nothing was failed" is never
    the reason the slow client survives, and the last sweep proves it was still being watched.
    """
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    slow = _watched(dog)
    now = T0
    for _ in range(3):
        canary = _watched(dog, at=now)
        slow._progress_bytes = FLOOR
        now += WINDOW
        assert set(dog.sweep(now=now, window=WINDOW, floor=FLOOR)) == {canary}, "the sweep is inert"
        assert slow.interrupted is False, "a client above the floor was failed for being slow"
    # It stops sending. It must still be watched -- and now it is the one that goes.
    # (mutation: forget a handle whose window came back 'ok' -> red here.)
    now += WINDOW
    assert set(dog.sweep(now=now, window=WINDOW, floor=FLOOR)) == {slow}


def test_a_handle_already_interrupted_is_not_failed_twice(monkeypatch):
    # close() and the watchdog can both reach a handle. The second one through must do nothing --
    # shown against a sibling that IS failed in the same sweep.
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle.mark_interrupted()
    canary = _watched(dog)
    assert set(dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)) == {canary}


def test_a_forgotten_handle_is_no_longer_swept(monkeypatch):
    # An upload the watchdog has let go of must never be failed after the fact.
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    dog.forget(handle)
    canary = _watched(dog)
    assert set(dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)) == {canary}
    assert handle.interrupted is False


def test_forgetting_a_handle_twice_does_not_raise(monkeypatch):
    # Both the watchdog and close() forget a failed handle, in that order, so the second forget is
    # the NORMAL case -- not an edge one. Raising there would propagate out of close() and take
    # the handler thread with it, leaving the staging file behind.
    # (mutation: discard -> remove in forget() -> red.)
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)
    dog.forget(handle)
    dog.forget(handle)


def test_a_failed_handle_is_dropped_from_the_watch_set(monkeypatch):
    """Both halves, and they are not the same claim.

    The BEHAVIOUR -- never failed twice -- is carried by the `interrupted` check at the top of the
    sweep, and it holds whether or not the handle is still in the set. Asserting only that would
    therefore say nothing about the drop. So the drop is asserted on the set itself, and named for
    what it is: housekeeping, so a long-lived server's watch set does not accumulate handles whose
    fate is already decided.
    """
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR) == [handle]

    assert handle not in dog._handles, "a failed handle was left in the watch set"
    canary = _watched(dog, at=T0 + WINDOW)
    assert set(dog.sweep(now=T0 + WINDOW * 2, window=WINDOW, floor=FLOOR)) == {canary}


def test_the_argument_less_sweep_reads_the_window_and_the_floor_from_the_settings(monkeypatch):
    """`sweep()` with no arguments is the ONLY call the product makes.

    Everything else in this file hands it a window and a floor, which is what makes the decision
    testable -- and also what makes the wiring between the two settings and the two parameters
    invisible. Swapping them ships a 65536-second window with a 120-byte floor, i.e. no watchdog,
    and every other test here stays green.
    """
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    monkeypatch.setattr(mod, 'settings', types.SimpleNamespace(
        sftp_write_progress_timeout_seconds=WINDOW,
        sftp_write_progress_min_bytes=FLOOR,
    ))
    monkeypatch.setattr(mod.time, 'monotonic', lambda: T0 + WINDOW)

    stalled = _watched(dog)
    slow = _watched(dog)
    slow._progress_bytes = FLOOR          # clears THIS floor, not the shipped one
    assert set(dog.sweep()) == {stalled}
    assert slow.interrupted is False

    # ... and zero there disables it, which is what the operator is told 0 means.
    mod.settings.sftp_write_progress_timeout_seconds = 0
    assert dog.sweep() == []


def test_the_watchdog_thread_sweeps_with_the_settings(monkeypatch):
    # run() is the thread body. It must call the argument-less sweep -- the one that reads the
    # settings -- and it must survive a sweep that raises, or one bad handle ends the watchdog for
    # the whole process. (mutation: `self.sweep()` -> `pass` in run() -> red.)
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    stop = threading.Event()
    calls = []
    ticks = []

    def _sweep(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            raise RuntimeError("one bad handle")
        return []

    def _sleep(_seconds):
        # The loop is ended from HERE, not from the sweep: a run() that never sweeps must still
        # terminate, or its own mutation hangs the suite instead of failing it.
        ticks.append(_seconds)
        if len(ticks) >= 2:
            stop.set()

    monkeypatch.setattr(dog, 'sweep', _sweep)
    monkeypatch.setattr(mod.time, 'sleep', _sleep)
    dog.run(stop=stop)

    assert calls == [((), {}), ((), {})], calls


# ---- the wiring ---------------------------------------------------------------------------------

def test_both_upload_branches_watch_the_handle_before_returning_it():
    """The watchdog decides correctly about handles it is given. This is what gives it any.

    open() cannot be driven from here -- it resolves a vault, authorizes the write and claims the
    same-name lock, all against a live database -- so the two upload branches are pinned in the
    source instead. Deleting either call disables the watchdog for that upload shape entirely,
    and every behavioural test in this file stays green.

    The slice is `_open_write` alone, not the module: a DOWNLOAD handle is returned too, and it is
    correctly not watched -- there is no upload to stall and nothing to discard.
    """
    import re

    src = _source_without_comments(SRC.read_text(encoding="utf-8"))
    body = src.split("def _open_write", 1)[1].split("\n    def ", 1)[0]

    returns = [line for line in body.splitlines() if line.strip() == "return handle"]
    assert len(returns) == 2, (
        f"_open_write returns an upload handle from {len(returns)} places, not 2 -- a new one "
        "needs its own watch call, and its own line here"
    )
    paired = re.findall(r"_write_progress\.watch\(handle\)\n\s*return handle\n", body)
    assert len(paired) == 2, (
        f"only {len(paired)} of the 2 upload branches watch the handle immediately before "
        "returning it"
    )


def test_the_server_starts_the_watchdog_thread_once_and_only_when_it_is_enabled():
    # The thread is what makes any of this run. Starting it unconditionally would sweep with a
    # zero window -- harmless today, but the operator was told 0 disables it -- and not starting
    # it at all is silent: nothing fails, uploads simply hang for ever again.
    src = _source_without_comments(SRC.read_text(encoding="utf-8"))
    body = src.split("def start_sftp_server", 1)[1]
    import re
    starts = re.findall(r"threading\.Thread\(target=_write_progress\.run[^\n]*\)\.start\(\)", body)
    assert len(starts) == 1, f"the watchdog thread is started {len(starts)} times, not once"
    guard = re.search(
        r"if settings\.sftp_write_progress_timeout_seconds[^\n]*\n\s*"
        r"threading\.Thread\(target=_write_progress\.run",
        body,
    )
    assert guard, "the watchdog thread is started without the enabled/positive-timeout guard"


def test_closing_a_handle_takes_it_out_of_the_watch_set(tmp_path, monkeypatch):
    """A committed upload must not be swept afterwards -- and the set must not keep it either.

    These are two claims, and after the closing-handle guard below they are carried by different
    lines. The BEHAVIOUR (never failed after the client closed it) rests on `_closing`, which
    holds whether or not the handle was dropped from the set; the drop itself is housekeeping, so
    a long-lived server's set does not fill with handles whose uploads are over. Asserting only
    the sweep would leave the drop unpinned, so the set is asserted directly and called what it
    is. The sibling proves the sweep was live.
    """
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    monkeypatch.setattr(mod, '_write_progress', dog)
    closed = _buffered(dog, tmp_path)
    canary = _watched(dog)

    closed.close()

    assert closed not in dog._handles, "a closed handle was left in the watch set"
    assert set(dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)) == {canary}
    assert closed.interrupted is False, "a handle the client closed was failed after the fact"


def test_a_handle_that_has_begun_closing_is_never_failed(tmp_path, monkeypatch):
    """THE RACE. The sweep takes its snapshot under the set's lock and then decides outside it.

    So the client's CLOSE can land between the decision and the act. close() is where an upload
    is COMMITTED; marking the handle in that gap makes close() discard a file the client finished
    sending, and paramiko answers that same CLOSE with SFTP_OK either way -- the client is told
    its upload succeeded and the file is not there. Closing the transport underneath it is the
    same story for every other handle on that connection.

    The gap is frozen here rather than raced: close() runs for real (so it really is close() that
    claims the handle) with the set's forget suppressed, leaving exactly the state the sweep would
    find mid-close. (mutation: drop the _closing check in _fail -> red on all three assertions.)
    """
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    monkeypatch.setattr(mod, '_write_progress', dog)
    closing = _buffered(dog, tmp_path)
    closing._sftp_server = _transport_holder()
    canary = _watched(dog)

    with monkeypatch.context() as frozen:
        frozen.setattr(dog, 'forget', lambda handle: None)
        closing.close()

    assert closing._closing is True, "close() did not claim the handle"
    assert set(dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)) == {canary}
    assert closing.interrupted is False, "an upload the client completed was marked for discard"
    assert closing._sftp_server.sock.transport.closed is False, \
        "the connection was closed under a client whose upload had succeeded"


# ---- the ordering the discard depends on ---------------------------------------------------------

class _Transport:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _transport_holder(order=None):
    transport = _Transport()

    class _Sock:
        def get_transport(_self):
            return transport

    sock = _Sock()
    sock.transport = transport
    if order is not None:
        real_close = transport.close

        def _traced():
            order.append('transport.close')
            real_close()

        transport.close = _traced
    return types.SimpleNamespace(sock=sock)


def test_the_handle_is_marked_interrupted_before_anything_is_closed(monkeypatch):
    """THE ORDERING THE DISCARD-ON-INTERRUPT BEHAVIOUR RESTS ON.

    close() COMMITS an upload unless it has been told not to. So a watchdog that ends a transfer by
    closing the connection, without marking the handle first, would commit the stalled upload's
    partial bytes as a complete file -- and where overwriting is allowed, replace the good file of
    that name with the truncated one. The mark must be set before the transport is touched, and
    the event must be out before it too: closing the transport is what ends the session, and an
    event emitted after it is one the operator may never get.
    """
    order = []
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle._sftp_server = _transport_holder(order)

    real_mark = handle.mark_interrupted

    def _traced():
        order.append('mark_interrupted')
        real_mark()

    monkeypatch.setattr(handle, 'mark_interrupted', _traced)
    monkeypatch.setattr(mod, 'safe_event',
                        lambda code, *a, **k: order.append(f'event:{code}'))

    dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)

    assert order == ['mark_interrupted', 'event:upload.stalled', 'transport.close'], order
    # (mutation: close the transport before marking -> the order reverses -> red.)


def test_a_stalled_streaming_upload_is_discarded_not_committed(monkeypatch):
    """The same guarantee on the other upload shape, where it is a DIFFERENT flag.

    A buffered upload is discarded because close() reads `interrupted`. A streaming one has
    already written encrypted records to storage, and its driver decides between committing them
    and aborting them on its own `_failed` -- which it reads once, at the top of close(), and
    which nothing else in the watchdog path sets. So a watchdog that marks only the handle
    commits a truncated file here while doing the right thing everywhere else.
    (mutation: drop the `stream._failed = True` line from mark_interrupted -> red.)
    """
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    stream = _FakeStream()
    handle = _watched(dog, stream=stream)
    live = _watched(dog, stream=_FakeStream())
    live._progress_bytes = FLOOR

    assert set(dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)) == {handle}

    assert stream._failed is True, "the stalled stream's records would be committed as a whole file"
    assert live.stream._failed is False, "a stream above the floor was aborted for being slow"


def test_failing_a_handle_releases_its_same_name_lock(monkeypatch):
    # The upload holding the name is dead; the lock goes now rather than whenever the handler
    # thread gets round to close(), which may be stuck in a storage write.
    removed = []

    def _remove(vault_id, folder_id, filename, token):   # the real four-argument shape
        removed.append((vault_id, folder_id, filename, token))

    monkeypatch.setattr(mod.upload_marker, 'remove', _remove)
    _quiet(monkeypatch)

    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    ref = ('11111111-2222-3333-4444-555555555555', None, 'report.pdf', 'token-abc')
    handle.upload_marker_ref = ref

    dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)

    assert removed == [ref]
    assert handle.upload_marker_ref is None, "the reference was left behind for close() to repeat"


def test_a_handle_with_no_transport_is_still_marked_for_discard(monkeypatch):
    # The transport can be gone already. Failing the handle must not depend on closing anything --
    # if the mark were skipped, whatever closes the handle next would commit its partial bytes.
    _quiet(monkeypatch)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)          # no _sftp_server at all
    assert dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR) == [handle]
    assert handle.interrupted is True


def test_the_stalled_event_carries_its_numbers_and_nothing_else(monkeypatch, tmp_path):
    """What the operator actually gets -- through the REAL emitter, not a stub.

    Every other test here suppresses `safe_event`, which is how three numbers computed at this
    call site came to be silently dropped by the field whitelist: an event can ship as a bare code
    and nothing notices. The emitter is a whitelist, so the only way to know a field survives is
    to run it. And the same line must not gain anything identifying -- the staging path, the
    filename -- which is the rule that made the emitter exist.
    """
    written = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: written.append(" ".join(map(str, a))))

    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle.writepath = str(tmp_path / "secret-merger-terms.pdf")
    handle._progress_bytes = 17

    dog.sweep(now=T0 + WINDOW, window=WINDOW, floor=FLOOR)

    stalled = [line for line in written if line.startswith("event upload.stalled")]
    assert len(stalled) == 1, written
    line = stalled[0]
    assert "accepted_bytes=17" in line, line
    assert f"window_seconds={WINDOW}" in line, line
    assert f"floor_bytes={FLOOR}" in line, line
    assert "secret" not in line and "tmp" not in line and ".pdf" not in line, line


# ---- what counts as progress ---------------------------------------------------------------------

def test_bytes_accepted_by_a_buffered_write_are_what_counts_as_progress(tmp_path):
    """Progress is counted where bytes are ACCEPTED, not where they reach permanent storage.

    On the streaming path a record is 1 MiB and is only flushed when it is full, so a client
    sending steadily at a few kilobytes a second would go many windows without completing one.
    Counting flushes would fail exactly the slow-but-honest transfers this must never touch --
    so both paths count at the same place, the moment the server takes the bytes.
    """
    handle = _handle()
    handle.writepath = str(tmp_path / "staged")
    handle.writefile = open(handle.writepath, "wb")
    try:
        assert handle.write(0, b"x" * 4096) == paramiko.SFTP_OK
        assert handle._progress_bytes == 4096
        assert handle.write(4096, b"y" * 1024) == paramiko.SFTP_OK
        assert handle._progress_bytes == 4096 + 1024, "a second write did not add to the window"
    finally:
        handle.writefile.close()


def test_a_rejected_over_limit_write_is_not_progress(tmp_path):
    # An over-limit write is refused, and refusing it costs the server nothing to keep doing. If
    # it counted, a client could hold its slot for ever by sending writes it knows will bounce --
    # the trickle again, without even the cost of storing anything.
    handle = _handle()
    handle.writepath = str(tmp_path / "staged")
    handle.writefile = open(handle.writepath, "wb")
    handle.max_bytes = 1024
    try:
        assert handle.write(0, b"x" * 4096) == paramiko.SFTP_FAILURE
        assert handle._progress_bytes == 0, "a rejected write counted as progress"
    finally:
        handle.writefile.close()


def test_only_accepted_streaming_writes_are_progress():
    # The streaming path counts in a different place, on the driver's answer, so it needs its own
    # pin in both directions. (mutation: count regardless of the result -> the failure leg goes
    # red. mutation: `pass` instead of the increment -> the accepted leg goes red.)
    ok = _handle(stream=_FakeStream(paramiko.SFTP_OK))
    assert ok.write(0, b"z" * 2048) == paramiko.SFTP_OK
    assert ok._progress_bytes == 2048

    refused = _handle(stream=_FakeStream(paramiko.SFTP_FAILURE))
    assert refused.write(0, b"z" * 2048) == paramiko.SFTP_FAILURE
    assert refused._progress_bytes == 0, "a write the driver refused counted as progress"
