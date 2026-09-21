"""An SFTP upload the client never closed is DISCARDED, not committed.

SFTP carries no total size. The server cannot tell a finished upload from one that stopped halfway
by looking at the bytes: the only sign of completion there is, is the client's CLOSE. The handle's
close() is also what commits an upload -- and it is reached two ways that look alike from inside:
the client's CLOSE, and the cleanup paramiko runs over every handle still open when a connection
goes (a disconnect, an abort, a transport torn down). A client's CLOSE calls close() and THEN takes
the handle out of paramiko's table, so the cleanup only ever reaches the uploads that were NOT
finished -- and it runs on the same thread as the requests, after the last of them, so no client
CLOSE can ever be in progress once the session has been announced as over.

Those used to be finalized like any other: a dropped connection committed its partial bytes as a
complete file, and where overwriting was allowed it replaced the good file of that name with the
truncated one. paramiko announces the end of the session BEFORE it closes what is left, and that is
what now tells the two apart.
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path

import paramiko
import paramiko.server
import paramiko.sftp_server
import pytest

from app.sftp import sftp_server as mod
from app.sftp.sftp_server import SFTPServerInterface, VaultSFTPHandle, _StreamingUpload

pytestmark = pytest.mark.unit


def _interface() -> SFTPServerInterface:
    return SFTPServerInterface(server=object())


def _cleanup_as_paramiko_does(interface, handles):
    """The order paramiko's own SFTPServer.finish_subsystem uses (pinned below): the session is
    announced as ended, THEN every handle still in the table is closed."""
    interface.session_ended()
    for h in handles:
        h.close()


# ---- the buffered upload ----------------------------------------------------------------------------

def _buffered(tmp_path, interface, payload=b"half of a file"):
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle._interface = interface
    handle.writepath = str(tmp_path / "up_buffer")
    handle.writefile = open(handle.writepath, "wb")
    committed = []
    handle.finalizer = lambda path: committed.append(Path(path).read_bytes())
    assert handle.write(0, payload) == paramiko.SFTP_OK
    return handle, committed


def test_a_buffered_upload_the_client_closed_is_committed(tmp_path):
    # No false discard: a CLOSE from the client, in a live session, finalizes exactly as before.
    handle, committed = _buffered(tmp_path, _interface())
    handle.close()
    assert committed == [b"half of a file"] and handle.interrupted is False
    assert not os.path.exists(handle.writepath)


def test_a_buffered_upload_left_open_when_the_connection_goes_commits_nothing(tmp_path):
    # (mutation: session_ended records nothing -> committed -> red. mutation: close() does not look
    # at the session -> committed -> red.)
    interface = _interface()
    handle, committed = _buffered(tmp_path, interface)
    _cleanup_as_paramiko_does(interface, [handle])
    assert committed == [], "a truncated upload was committed as a complete file"
    assert handle.interrupted is True
    assert not os.path.exists(handle.writepath), "the staged bytes were left behind"


def test_a_same_name_original_survives_an_interrupted_overwrite(tmp_path):
    # What was actually being lost. The finalizer is what replaces a file of the same name; an
    # interrupted upload must never reach it, so the original is exactly as it was.
    store = {"report.pdf": b"the good original"}
    interface = _interface()
    handle, _ = _buffered(tmp_path, interface, payload=b"the first third of a new re")
    handle.finalizer = lambda path: store.__setitem__("report.pdf", Path(path).read_bytes())
    _cleanup_as_paramiko_does(interface, [handle])
    assert store == {"report.pdf": b"the good original"}


def test_the_in_flight_marker_is_released_either_way(tmp_path, monkeypatch):
    removed = []
    monkeypatch.setattr(mod.upload_marker, "remove", lambda *ref: removed.append(ref))
    interface = _interface()
    handle, _ = _buffered(tmp_path, interface)
    handle.upload_marker_ref = ("V", None, "report.pdf", "token")
    _cleanup_as_paramiko_does(interface, [handle])
    assert removed == [("V", None, "report.pdf", "token")] and handle.upload_marker_ref is None


# ---- the streaming upload ---------------------------------------------------------------------------

class _Ctx:
    """The encryptor context: a clean exit marks the blob complete, an error exit unlinks it."""
    def __init__(self):
        self.exits = []

    def __exit__(self, exc_type, exc, tb):
        self.exits.append("clean" if exc_type is None else "discard")


def _streaming(interface, monkeypatch):
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle._interface = interface
    stream = _StreamingUpload(handle=handle, interface=interface, vault_id="V", folder_id=None,
                              filename="report.pdf", can_overwrite=True, max_bytes=0, reorder_bytes=0)
    stream._ctx, stream._started = _Ctx(), True          # as after the first record
    handle.stream = stream
    took = []
    monkeypatch.setattr(stream._assembler, "finish", lambda: took.append("finish"))
    # The commit path goes on from here into the database; reaching it is what is being shown.
    monkeypatch.setattr(stream, "_ensure_started", lambda: took.append("commit-path"))
    monkeypatch.setattr(stream._ctx, "get_checksum", lambda: (_ for _ in ()).throw(RuntimeError("stop here")),
                        raising=False)
    return handle, stream, took


def test_a_streaming_upload_the_client_closed_takes_the_commit_path(monkeypatch):
    handle, stream, took = _streaming(_interface(), monkeypatch)
    handle.close()
    assert took == ["finish", "commit-path"] and handle.interrupted is False


def test_a_streaming_upload_left_open_when_the_connection_goes_is_discarded(monkeypatch):
    # (mutation: mark_interrupted does not fail the stream -> the tail is flushed and the commit
    # path is taken, with replace_same_name -> red.)
    interface = _interface()
    handle, stream, took = _streaming(interface, monkeypatch)
    ctx = stream._ctx
    _cleanup_as_paramiko_does(interface, [handle])
    assert took == [], "an interrupted upload reached the commit path"
    assert ctx.exits == ["discard"], "the uncommitted blob was not discarded"
    assert handle.interrupted is True and handle.stream is None


def test_a_caller_that_ends_a_transfer_says_so_before_it_closes_anything(monkeypatch):
    # The same rule for anything ELSE that ends a transfer (a watchdog, say): close() commits
    # unless it has been told not to, so the telling comes first.
    handle, stream, took = _streaming(_interface(), monkeypatch)       # the session is still LIVE
    ctx = stream._ctx
    handle.mark_interrupted()
    handle.close()
    assert took == [] and ctx.exits == ["discard"]


def test_a_streaming_discard_is_logged_as_an_interruption_only_when_that_is_the_cause(monkeypatch):
    codes = []
    monkeypatch.setattr(mod, "safe_event", lambda code, *a, **k: codes.append(code))
    # Cut short from outside: that IS the cause, and the log says so.
    interface = _interface()
    handle, stream, _ = _streaming(interface, monkeypatch)
    _cleanup_as_paramiko_does(interface, [handle])
    assert codes == ["upload.discarded.interrupted"]
    # One that had already failed for a reason of its own (over the size limit, here) and THEN lost
    # its connection: the real cause was logged when it happened. Calling the discard an
    # interruption would send whoever reads the log looking for a network fault.
    del codes[:]
    interface = _interface()
    handle, stream, _ = _streaming(interface, monkeypatch)
    ctx = stream._ctx
    stream._max_bytes = 4
    assert handle.write(0, b"more than four bytes") == paramiko.SFTP_FAILURE
    _cleanup_as_paramiko_does(interface, [handle])
    assert "upload.discarded.interrupted" not in codes
    assert ctx.exits == ["discard"] and handle.interrupted is True


# ---- what the above rests on ------------------------------------------------------------------------

def test_a_read_handle_is_untouched_by_the_end_of_the_session():
    interface = _interface()
    handle = VaultSFTPHandle(flags=os.O_RDONLY)
    handle._interface = interface
    _cleanup_as_paramiko_does(interface, [handle])
    assert handle.interrupted is False


def test_paramiko_announces_the_end_of_the_session_before_it_closes_what_is_left():
    # The whole fix rests on this order, and it is paramiko's, not ours: a release that closed the
    # handles first would silently turn the fix off. Read from the installed library.
    src = inspect.getsource(paramiko.sftp_server.SFTPServer.finish_subsystem)
    assert src.index("self.server.session_ended()") < src.index("for f in self.file_table.values():")
    # ... and a client's CLOSE closes the handle and THEN takes it out of that table, so the cleanup
    # never sees an upload the client finished.
    process = inspect.getsource(paramiko.sftp_server.SFTPServer._process)
    close_branch = process[process.index("CMD_CLOSE"):]
    close_branch = close_branch[:close_branch.index("CMD_READ")]
    assert close_branch.index("self.file_table[handle].close()") < close_branch.index("del self.file_table[handle]")
    # What makes a false discard impossible is not that order but the THREAD: the cleanup runs on
    # the thread that served the requests, after the request loop has returned. So while any
    # client CLOSE is inside close(), the session cannot yet have been announced as over.
    run = inspect.getsource(paramiko.server.SubsystemHandler._run)
    assert run.index("self.start_subsystem(") < run.index("self.finish_subsystem()")
    assert "Thread(" not in run and "Thread(" not in src


def test_both_places_a_write_handle_is_made_give_it_its_session():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    open_fn = src[src.index("    def open(self, path"):src.index("    def _make_upload_finalizer(")]
    code = "\n".join(ln for ln in open_fn.splitlines() if not ln.lstrip().startswith("#"))
    assert code.count("VaultSFTPHandle(flags=os.O_WRONLY)") == 2
    # (mutation: a write handle made without its session -> it can never learn the session ended
    # -> it finalizes on cleanup again -> red.)
    assert code.count("handle._interface = self") == 2
