"""An upload that stops making progress is failed, so it cannot hold its resources for ever.

After authentication nothing else bounds a connection. A client that opens a file for writing and
then sends nothing keeps its thread, its transport and its connection slot until it chooses to
leave; one that sends a byte now and then keeps the same-name lock alive too, because every write
refreshes it. The watchdog watches each open write handle in windows: a window in which fewer than
the floor of bytes were accepted fails the handle. One rule covers both, the full stop and the
trickle.

WHAT IS MEASURED IS BYTES ACCEPTED, never elapsed time and never records flushed to storage. A
record is 1 MiB, so a genuinely slow link would go minutes without completing one while making
perfectly good progress; failing it would be the opposite of what this is for. Everything below
therefore also pins the NOT-failed direction, which is the direction that breaks real users.

These tests drive the decision directly with an injected clock and hand-counted byte totals. They
need no thread, no socket and no waiting: `verdict` is a pure function of (handle, now, window,
floor), and `sweep` takes the clock and both settings as arguments. The live behaviour these
cannot show -- that a real stalled session's thread, slot and lock are genuinely released -- is
measured separately against a running server.
"""
from __future__ import annotations

import os

import paramiko
import pytest

from app.sftp import sftp_server as mod
from app.sftp.sftp_server import SFTPServerInterface, VaultSFTPHandle, _WriteProgressWatchdog

pytestmark = pytest.mark.unit

WINDOW = 120.0        # seconds; the shipped default
FLOOR = 65536         # bytes per window; the shipped default


def _handle(interface=None):
    """A write handle as the open path leaves one: watched, with its window started at t=0."""
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle._interface = interface or SFTPServerInterface(server=object())
    handle.writepath = "/dev/null/not-used"
    handle.writefile = object()          # only its not-None-ness matters here
    return handle


def _watched(dog, interface=None, at=0.0):
    handle = _handle(interface)
    dog.watch(handle, now=at)
    return handle


# ---- the decision itself ------------------------------------------------------------------------

def test_a_window_that_has_not_closed_yet_is_never_failed():
    # Progress is judged per window, not moment to moment: a client that has sent nothing YET, one
    # second in, is not behind -- it has the rest of the window to send.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert _WriteProgressWatchdog.verdict(handle, 1.0, WINDOW, FLOOR) == 'ok'
    assert _WriteProgressWatchdog.verdict(handle, WINDOW - 0.001, WINDOW, FLOOR) == 'ok'


def test_a_window_that_closed_with_nothing_at_all_is_stalled():
    # (mutation: return 'ok' unconditionally -> red. mutation: compare > window instead of >= at
    # the boundary -> the boundary case below goes red.)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert _WriteProgressWatchdog.verdict(handle, WINDOW, WINDOW, FLOOR) == 'stalled'


def test_a_window_that_closed_above_the_floor_is_ok_and_starts_the_next_one():
    # THE DIRECTION THAT BREAKS REAL USERS. A slow client that cleared the floor is not failed,
    # and its window is restarted from now with its count zeroed -- so clearing one window does
    # not buy credit in the next.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle._progress_bytes = FLOOR + 1
    assert _WriteProgressWatchdog.verdict(handle, WINDOW, WINDOW, FLOOR) == 'ok'
    assert handle._progress_window_start == WINDOW
    assert handle._progress_bytes == 0
    # ... and the next window is judged on its own: nothing in it, so it closes stalled.
    assert _WriteProgressWatchdog.verdict(handle, WINDOW * 2, WINDOW, FLOOR) == 'stalled'


def test_exactly_the_floor_clears_it_and_one_byte_short_does_not():
    # The boundary in both directions, because "at least the floor" and "more than the floor" are
    # one byte apart and only one of them is what the setting says.
    dog = _WriteProgressWatchdog()
    at_floor = _watched(dog)
    at_floor._progress_bytes = FLOOR
    assert _WriteProgressWatchdog.verdict(at_floor, WINDOW, WINDOW, FLOOR) == 'ok'

    short = _watched(dog)
    short._progress_bytes = FLOOR - 1
    assert _WriteProgressWatchdog.verdict(short, WINDOW, WINDOW, FLOOR) == 'stalled'


def test_a_trickle_below_the_floor_is_stalled_however_often_it_writes():
    # THE GHOST. A byte now and then is progress by any no-progress timer, and it refreshes the
    # same-name lock for ever. The floor is what tells it from a slow transfer.
    # (mutation: treat any non-zero count as progress -> red.)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle._progress_bytes = 1
    assert _WriteProgressWatchdog.verdict(handle, WINDOW, WINDOW, FLOOR) == 'stalled'


def test_floor_zero_means_any_byte_at_all_counts():
    # The documented meaning of 0: a pure no-progress timer, no rate requirement.
    # (mutation: drop the max(1, floor) so a zero floor passes a window with NOTHING in it -> red.)
    dog = _WriteProgressWatchdog()
    one_byte = _watched(dog)
    one_byte._progress_bytes = 1
    assert _WriteProgressWatchdog.verdict(one_byte, WINDOW, WINDOW, 0) == 'ok'

    nothing = _watched(dog)
    assert _WriteProgressWatchdog.verdict(nothing, WINDOW, WINDOW, 0) == 'stalled'


# ---- the sweep ----------------------------------------------------------------------------------

def test_a_zero_timeout_disables_the_watchdog_entirely():
    # (mutation: sweep regardless of the timeout -> red.) A handle far past any window is untouched.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    assert dog.sweep(now=WINDOW * 10, window=0, floor=FLOOR) == []
    assert handle.interrupted is False


def test_the_sweep_fails_the_stalled_handle_and_leaves_the_progressing_one_alone():
    # The positive and the negative in ONE sweep, which is the only way the negative means
    # anything: a sweep that failed nothing would pass the "not failed" half by doing nothing.
    dog = _WriteProgressWatchdog()
    stalled = _watched(dog)
    slow = _watched(dog)
    slow._progress_bytes = FLOOR

    failed = dog.sweep(now=WINDOW, window=WINDOW, floor=FLOOR)

    assert failed == [stalled], "the stalled handle was not the one failed"
    assert stalled.interrupted is True
    assert slow.interrupted is False, "a client above the floor was failed for being slow"


def test_a_handle_already_interrupted_is_not_failed_twice():
    # close() and the watchdog can both reach a handle. The second one through must do nothing.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle.mark_interrupted()
    assert dog.sweep(now=WINDOW, window=WINDOW, floor=FLOOR) == []


def test_a_forgotten_handle_is_no_longer_swept():
    # close() forgets the handle; a closed upload must never be failed after the fact.
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    dog.forget(handle)
    assert dog.sweep(now=WINDOW, window=WINDOW, floor=FLOOR) == []
    assert handle.interrupted is False


# ---- the ordering the discard depends on ---------------------------------------------------------

def test_the_handle_is_marked_interrupted_before_anything_is_closed(monkeypatch):
    """THE ORDERING THE DISCARD-ON-INTERRUPT BEHAVIOUR RESTS ON.

    close() COMMITS an upload unless it has been told not to. So a watchdog that ends a transfer by
    closing the connection, without marking the handle first, would commit the stalled upload's
    partial bytes as a complete file -- and where overwriting is allowed, replace the good file of
    that name with the truncated one. The mark must be set before the transport is touched.
    """
    order = []

    class _Transport:
        def close(self):
            order.append('transport.close')

    class _Sock:
        def get_transport(self):
            return _Transport()

    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle._sftp_server = type('S', (), {'sock': _Sock()})()

    real_mark = handle.mark_interrupted

    def _traced():
        order.append('mark_interrupted')
        real_mark()

    monkeypatch.setattr(handle, 'mark_interrupted', _traced)
    monkeypatch.setattr(mod, 'safe_event', lambda *a, **k: None)

    dog.sweep(now=WINDOW, window=WINDOW, floor=FLOOR)

    assert order == ['mark_interrupted', 'transport.close'], order
    # (mutation: close the transport before marking -> the order reverses -> red.)


def test_failing_a_handle_releases_its_same_name_lock(monkeypatch):
    # The upload holding the name is dead; the lock goes now rather than whenever the handler
    # thread gets round to close(), which may be stuck in a storage write.
    removed = []
    monkeypatch.setattr(mod.upload_marker, 'remove', lambda *ref: removed.append(ref))
    monkeypatch.setattr(mod, 'safe_event', lambda *a, **k: None)

    dog = _WriteProgressWatchdog()
    handle = _watched(dog)
    handle.upload_marker_ref = ('vault-1', 'report.pdf', 'token-abc')

    dog.sweep(now=WINDOW, window=WINDOW, floor=FLOOR)

    assert removed == [('vault-1', 'report.pdf', 'token-abc')]
    assert handle.upload_marker_ref is None, "the reference was left behind for close() to repeat"


def test_a_handle_with_no_transport_is_still_marked_and_its_lock_released(monkeypatch):
    # The transport can be gone already. Failing the handle must not depend on closing anything.
    monkeypatch.setattr(mod, 'safe_event', lambda *a, **k: None)
    dog = _WriteProgressWatchdog()
    handle = _watched(dog)          # no _sftp_server at all
    dog.sweep(now=WINDOW, window=WINDOW, floor=FLOOR)
    assert handle.interrupted is True


# ---- what counts as progress ---------------------------------------------------------------------

def test_bytes_accepted_by_write_are_what_counts_as_progress(tmp_path):
    """Progress is counted where bytes are ACCEPTED, not where records reach storage.

    A record is 1 MiB and is only flushed when it is full, so a client sending steadily at a few
    kilobytes a second would go many windows without completing one. Counting records would fail
    exactly the slow-but-honest transfers this must never touch.
    """
    dog = _WriteProgressWatchdog()
    handle = _handle()
    handle.writepath = str(tmp_path / "staged")
    handle.writefile = open(handle.writepath, "wb")
    dog.watch(handle, now=0.0)
    try:
        assert handle.write(0, b"x" * 4096) == paramiko.SFTP_OK
        assert handle._progress_bytes == 4096
        assert handle.write(4096, b"y" * 1024) == paramiko.SFTP_OK
        assert handle._progress_bytes == 4096 + 1024, "a second write did not add to the window"
    finally:
        handle.writefile.close()
