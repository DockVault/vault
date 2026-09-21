"""The SFTP container's healthcheck reads the age of a heartbeat file, not the bound port.

A bound port says a process once called listen(). The old check (the port's hex in /proc/net/tcp)
therefore called a server healthy for as long as it existed -- through an accept loop that had
stopped turning, and through an upload whose thread was stuck in a storage write for good. Now the
server touches a file only while it is actually alive, and the check is that file's age.

Everything here runs the shipped code: the check is the command lifted out of the compose files
and run as a program; the accept loop is the real start_sftp_server() on a loopback port.
"""
from __future__ import annotations

import ast
import gc
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from app.sftp import heartbeat
from app.sftp import sftp_server as mod
from app.sftp.sftp_server import VaultSFTPHandle, _Liveness

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILES = ("deploy/docker-compose.yml", "deploy/docker-compose.secure.yml")


def _until(predicate, seconds=15.0, what="the condition"):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out waiting for " + what)


# ---- the file, and the check that reads it ----------------------------------------------------------

def test_a_beat_is_fresh_until_it_is_old_enough_to_be_stale(tmp_path):
    path = str(tmp_path / "hb")
    heartbeat.beat(path, now=1000.0)
    assert heartbeat.is_fresh(path, now=1000.0)
    assert heartbeat.is_fresh(path, now=1000.0 + heartbeat.STALE_AFTER_SECONDS - 1)
    assert not heartbeat.is_fresh(path, now=1000.0 + heartbeat.STALE_AFTER_SECONDS)
    # A second beat is what makes it fresh again -- not the first one's having happened.
    heartbeat.beat(path, now=1000.0 + heartbeat.STALE_AFTER_SECONDS)
    assert heartbeat.is_fresh(path, now=1000.0 + heartbeat.STALE_AFTER_SECONDS + 1)


def test_no_heartbeat_at_all_is_stale(tmp_path):
    assert heartbeat.age_seconds(str(tmp_path / "never-written")) is None
    assert not heartbeat.is_fresh(str(tmp_path / "never-written"))


def test_a_beat_from_the_future_does_not_pass_for_a_live_server(tmp_path):
    # A clock stepped back by an hour must not make a dead server look alive for an hour.
    path = str(tmp_path / "hb")
    heartbeat.beat(path, now=5000.0)
    assert heartbeat.is_fresh(path, now=5000.0 - 2)          # ordinary jitter
    assert not heartbeat.is_fresh(path, now=5000.0 - 3600)


def test_the_margin_covers_several_missed_beats_not_one_late_one():
    assert heartbeat.STALE_AFTER_SECONDS >= 4 * heartbeat.BEAT_SECONDS


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="no O_NOFOLLOW on this platform")
def test_a_beat_does_not_write_through_a_link_left_at_its_name(tmp_path):
    victim = tmp_path / "somebody-elses-file"
    victim.write_bytes(b"precious")
    link = tmp_path / "hb"
    os.symlink(str(victim), str(link))
    with pytest.raises(OSError):
        heartbeat.beat(str(link))
    assert victim.read_bytes() == b"precious"


def test_the_check_needs_nothing_but_the_standard_library():
    # It runs every thirty seconds in the container, as a fresh interpreter. It must never come to
    # import the application (settings, the database layer) to read one file's age.
    tree = ast.parse((ROOT / "app/sftp/heartbeat.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported == {"os", "sys", "tempfile", "time"}


def _healthcheck(compose_file):
    doc = yaml.safe_load((ROOT / compose_file).read_text(encoding="utf-8"))
    return doc["services"]["vault-sftp"]["healthcheck"]


def _run_the_check(compose_file, heartbeat_file):
    """The compose file's own command, run as the container runs it: from the application root,
    with the server's environment."""
    test = _healthcheck(compose_file)["test"]
    assert test[0] == "CMD" and test[1] == "python", test
    env = dict(os.environ, SFTP_HEARTBEAT_FILE=str(heartbeat_file))
    return subprocess.run([sys.executable] + test[2:], cwd=str(ROOT), env=env,
                          capture_output=True, timeout=60).returncode


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_the_container_check_passes_on_a_fresh_beat_and_fails_on_a_stale_or_missing_one(compose_file, tmp_path):
    hb = tmp_path / "hb"
    assert _run_the_check(compose_file, hb) == 1, "no heartbeat file, and the check passed"
    heartbeat.beat(str(hb))
    assert _run_the_check(compose_file, hb) == 0
    old = time.time() - heartbeat.STALE_AFTER_SECONDS - 5
    os.utime(str(hb), (old, old))
    assert _run_the_check(compose_file, hb) == 1, "a stale heartbeat, and the check passed"


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_the_container_check_looks_at_no_port_and_opens_no_socket(compose_file):
    test = _healthcheck(compose_file)["test"]
    assert test == ["CMD", "python", "-B", "-m", "app.sftp.heartbeat"]
    # and it still flips a wedged container within minutes: the retries are what they were
    hc = _healthcheck(compose_file)
    assert (hc["interval"], hc["retries"]) == ("30s", 5)


def test_the_server_and_the_check_agree_on_where_the_file_is(monkeypatch, tmp_path):
    monkeypatch.setenv(heartbeat.HEARTBEAT_FILE_ENV, str(tmp_path / "elsewhere"))
    assert _Liveness().pulse() is None
    assert heartbeat.is_fresh() and (tmp_path / "elsewhere").exists()


# ---- what the file stands for -----------------------------------------------------------------------

def test_a_loop_that_keeps_turning_keeps_the_server_alive():
    live = _Liveness()
    live.turning("accept-loop", now=100.0)
    assert live.fault(now=100.0 + live.SILENT_AFTER_SECONDS - 1) is None
    assert live.fault(now=100.0 + live.SILENT_AFTER_SECONDS) == "accept-loop-silent"
    live.turning("accept-loop", now=100.0 + live.SILENT_AFTER_SECONDS)
    assert live.fault(now=100.0 + live.SILENT_AFTER_SECONDS + 1) is None


def test_only_a_loop_that_was_enrolled_can_be_missed():
    # The watchdog is optional (0 disables it). A server that never started one is not at fault
    # for its silence; one that did start it, is.
    live = _Liveness()
    live.turning("accept-loop", now=0.0)
    live.turning("accept-loop", now=500.0)
    assert live.fault(now=500.0) is None
    live.turning("write-progress", now=500.0)
    live.turning("accept-loop", now=500.0 + live.SILENT_AFTER_SECONDS)
    assert live.fault(now=500.0 + live.SILENT_AFTER_SECONDS) == "write-progress-silent"


class _Upload:
    """Anything that can be held weakly stands in for a handle here."""


def test_an_upload_told_to_stop_has_a_grace_to_unwind_and_then_is_a_fault():
    live = _Liveness()
    upload = _Upload()
    live.stopping(upload, now=10.0)
    assert live.fault(now=10.0 + live.UNWIND_GRACE_SECONDS - 1) is None
    assert live.fault(now=10.0 + live.UNWIND_GRACE_SECONDS) == "upload-not-unwinding"
    # ...and it recovers by itself the moment the stuck thread comes back and the handle closes.
    live.stopped(upload)
    assert live.fault(now=10.0 + live.UNWIND_GRACE_SECONDS) is None


def test_being_told_to_stop_a_second_time_does_not_restart_the_clock():
    # A handle the watchdog failed is marked again by its own close(). If that reset the clock, a
    # close() stuck for good would look forever as though it had only just begun.
    live = _Liveness()
    upload = _Upload()
    live.stopping(upload, now=10.0)
    live.stopping(upload, now=10.0 + live.UNWIND_GRACE_SECONDS - 1)
    assert live.fault(now=10.0 + live.UNWIND_GRACE_SECONDS) == "upload-not-unwinding"


def test_an_upload_that_no_longer_exists_cannot_hold_the_server_unhealthy():
    live = _Liveness()
    upload = _Upload()
    live.stopping(upload, now=10.0)
    del upload
    gc.collect()
    assert live.fault(now=10_000.0) is None


def test_the_file_is_touched_only_while_the_server_is_alive(tmp_path, monkeypatch):
    # The pin the whole design hangs on: a fault is reported by SILENCE. The file is not marked
    # bad, it just stops being touched, and its age does the rest.
    monkeypatch.setattr(mod, "safe_event", lambda *a, **k: None)
    path = str(tmp_path / "hb")
    live = _Liveness()
    live.turning("accept-loop", now=0.0)
    assert live.pulse(now=1.0, path=path) is None
    first = os.stat(path).st_mtime_ns
    old = time.time() - 1000
    os.utime(path, (old, old))
    assert live.pulse(now=live.SILENT_AFTER_SECONDS + 1.0, path=path) == "accept-loop-silent"
    assert abs(os.stat(path).st_mtime - old) < 2, "a server at fault touched its heartbeat"
    live.turning("accept-loop", now=live.SILENT_AFTER_SECONDS + 2.0)
    assert live.pulse(now=live.SILENT_AFTER_SECONDS + 2.0, path=path) is None
    assert os.stat(path).st_mtime_ns >= first and os.stat(path).st_mtime > old + 500


def test_a_heartbeat_that_cannot_be_written_is_a_fault_and_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "safe_event", lambda *a, **k: None)
    live = _Liveness()
    assert live.pulse(path=str(tmp_path / "no-such-directory" / "hb")) == "heartbeat-unwritable"


def test_a_change_of_state_is_logged_once_not_on_every_beat(tmp_path, monkeypatch):
    codes = []
    monkeypatch.setattr(mod, "safe_event", lambda code, *a, **k: codes.append(code))
    path = str(tmp_path / "hb")
    live = _Liveness()
    live.turning("accept-loop", now=0.0)
    for t in (1.0, 2.0, 3.0):
        live.pulse(now=t, path=path)
    late = live.SILENT_AFTER_SECONDS + 5.0
    for t in (late, late + 1, late + 2):
        live.pulse(now=t, path=path)
    live.turning("accept-loop", now=late + 3)
    live.pulse(now=late + 3, path=path)
    assert codes == ["liveness.lost.accept-loop-silent", "liveness.restored"]


# ---- the handle tells it ----------------------------------------------------------------------------

@pytest.fixture()
def live(monkeypatch):
    fresh = _Liveness()
    monkeypatch.setattr(mod, "_liveness", fresh)
    return fresh


def _write_handle(tmp_path):
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle.writepath = str(tmp_path / "up_buffer")
    handle.writefile = open(handle.writepath, "wb")
    handle.finalizer = lambda path: None
    return handle


def test_an_interrupted_upload_counts_as_unwinding_until_its_close_returns(tmp_path, live):
    handle = _write_handle(tmp_path)
    assert live.fault(now=time.monotonic() + 10_000) is None        # an open upload is no fault
    handle.mark_interrupted()
    assert live.fault(now=time.monotonic() + 10_000) == "upload-not-unwinding"
    handle.close()
    assert live.fault(now=time.monotonic() + 10_000) is None


def test_a_close_that_fails_still_counts_as_gone(tmp_path, live, monkeypatch):
    # Otherwise one close() that raised would hold the container unhealthy until it restarted.
    handle = _write_handle(tmp_path)
    handle.mark_interrupted()

    def _boom(*ref):
        raise RuntimeError("something close() relies on went away")
    handle.upload_marker_ref = ("vault", "folder", "name", "token")      # the first thing close() touches
    monkeypatch.setattr(mod.upload_marker, "remove", _boom)
    with pytest.raises(RuntimeError):
        handle.close()
    handle.writefile.close()
    assert live.fault(now=time.monotonic() + 10_000) is None


# ---- the accept loop --------------------------------------------------------------------------------

def test_a_connection_does_not_inherit_the_listening_sockets_timeout():
    # The loop's wake-up interval is set on the listening socket. If accepted connections took it
    # over, every SFTP session would start with a five-second socket timeout.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(heartbeat.BEAT_SECONDS)
    client = socket.create_connection(listener.getsockname(), timeout=5)
    try:
        accepted, _ = listener.accept()
        try:
            assert accepted.gettimeout() is None
        finally:
            accepted.close()
    finally:
        client.close()
        listener.close()
    # and the wake-up is an OSError, which is why its handler has to come first in the loop
    assert issubclass(socket.timeout, OSError)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_the_heartbeat_goes_stale_while_the_accept_loop_is_blocked_and_returns_with_it(tmp_path, monkeypatch):
    # The real start_sftp_server(), on a loopback port, with only its surroundings stubbed: no
    # Redis listener, no watchdog, the signal handler captured instead of installed (it is how the
    # server is stopped at the end).
    #
    # (mutation: the listening socket gets no timeout -> an idle loop never turns -> the beats
    #  stop with nobody connected. mutation: the loop does not say it has turned -> same.
    #  mutation: the timeout is caught after the closed-socket branch -> still turns, so that one
    #  is pinned by the order test below.)
    port = _free_port()
    hb = tmp_path / "hb"
    live = _Liveness()
    live.SILENT_AFTER_SECONDS = 1.5
    beats = []
    real_beat = heartbeat.beat
    handlers = {}
    gate = threading.Event()
    entered = threading.Event()
    admit_all = {"block": False}

    def _admit(ip):
        if admit_all["block"]:
            entered.set()
            gate.wait(30)
        return False          # refused at the door: no session is ever started in this test

    monkeypatch.setenv(heartbeat.HEARTBEAT_FILE_ENV, str(hb))
    monkeypatch.setattr(heartbeat, "BEAT_SECONDS", 0.05)
    monkeypatch.setattr(heartbeat, "beat", lambda *a, **k: (real_beat(*a, **k), beats.append(1)))
    monkeypatch.setattr(mod, "_liveness", live)
    monkeypatch.setattr(mod, "safe_event", lambda *a, **k: None)
    monkeypatch.setattr(mod, "_sweep_sftp_tmp", lambda: None)
    monkeypatch.setattr(mod, "listen_for_terminations", lambda: None)
    monkeypatch.setattr(mod.signal, "signal", lambda signum, handler: handlers.setdefault(signum, handler))
    monkeypatch.setattr(mod._connection_admission, "admit", _admit)
    monkeypatch.setattr(mod.settings, "sftp_host", "127.0.0.1")
    monkeypatch.setattr(mod.settings, "sftp_port", port)
    monkeypatch.setattr(mod.settings, "sftp_host_key_path", str(tmp_path / "host_key"))
    monkeypatch.setattr(mod.settings, "sftp_write_progress_timeout_seconds", 0)

    server = threading.Thread(target=mod.start_sftp_server, daemon=True)
    server.start()
    try:
        # 1. Idle, nobody connecting: the loop still TURNS -- it is not parked in accept() -- and so,
        #    well past the point at which a silent loop would be called dead, the file is still
        #    being touched.
        turns = set()
        _until(lambda: (turns.add(live._turned.get("accept-loop")), len(turns) >= 4)[1],
               what="an idle accept loop to keep turning")
        time.sleep(live.SILENT_AFTER_SECONDS + 0.3)
        assert live.fault() is None, "an idle server was called dead"
        idle = len(beats)
        _until(lambda: len(beats) >= idle + 3, what="an idle server to go on beating")
        assert heartbeat.is_fresh(str(hb))
        # The watchdog is off in this test (0 disables it): a loop that was never started is not
        # one whose silence counts.
        assert set(live._turned) == {"accept-loop"}

        # 2. The loop blocks (here: inside the admission step). The beats STOP.
        admit_all["block"] = True
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            assert entered.wait(15), "the connection never reached the loop"
            _until(lambda: live.fault() == "accept-loop-silent", what="the blocked loop to be noticed")
            stopped_at = len(beats)
            time.sleep(0.5)                                   # ten beat intervals
            assert len(beats) == stopped_at, "the heartbeat went on while the accept loop was blocked"

            # 3. It comes back: so do the beats. Nothing had to restart.
            admit_all["block"] = False
            gate.set()
            _until(lambda: len(beats) >= stopped_at + 3, what="the beats to resume")
            assert live.fault() is None
        finally:
            client.close()
    finally:
        gate.set()
        _until(lambda: handlers, what="the server to install its signal handler")
        next(iter(handlers.values()))(15, None)
        server.join(15)
    assert not server.is_alive(), "the server did not stop"
    # 4. A server that has stopped stops beating.
    final = len(beats)
    time.sleep(0.3)
    assert len(beats) == final


def _handler_names(handler):
    t = handler.type
    if t is None:
        return []
    return [ast.unparse(e) for e in (t.elts if isinstance(t, ast.Tuple) else [t])]


def test_the_wake_up_is_handled_before_the_branch_for_a_closed_socket():
    # socket.timeout IS an OSError. Caught by the OSError branch it would still loop (that branch
    # continues unless the server is stopping) -- but the day that branch learns to do anything
    # else with an error from accept(), an idle server would start doing it every five seconds.
    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "start_sftp_server")
    loop = next(n for n in fn.body if isinstance(n, ast.While))
    tries = [n for n in loop.body if isinstance(n, ast.Try)]
    assert len(tries) == 1
    names = [name for h in tries[0].handlers for name in _handler_names(h)]
    assert names.index("socket.timeout") < names.index("OSError")
    wake = next(h for h in tries[0].handlers if _handler_names(h) == ["socket.timeout"])
    assert [type(s) for s in wake.body] == [ast.Continue]


def test_the_watchdog_loop_says_it_is_turning(monkeypatch, live):
    # It is enrolled when the server starts it; from then on its silence turns the container
    # unhealthy. So it has to actually speak, every time round. No upload is involved here.
    monkeypatch.setattr(mod.settings, "sftp_write_progress_timeout_seconds", 4)   # one turn a second
    stop = threading.Event()
    loop = threading.Thread(target=mod._WriteProgressWatchdog().run, args=(stop,), daemon=True)
    loop.start()
    try:
        _until(lambda: "write-progress" in live._turned, what="the watchdog loop to say it turned")
    finally:
        stop.set()
        loop.join(10)


def test_the_watchdog_is_enrolled_only_when_it_is_started_and_by_whoever_starts_it():
    # Enrolled unconditionally, a server with the watchdog switched off would go unhealthy for good
    # after thirty seconds. Enrolled only by the thread's own first turn, a thread that never got
    # going would never be missed -- so the starter does it, in the same block as the start.
    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "start_sftp_server")
    enrol = "_liveness.turning('write-progress')"
    at_top = [ast.unparse(s) for s in fn.body]
    assert enrol not in at_top
    guarded = [n for n in fn.body if isinstance(n, ast.If)
               and "sftp_write_progress_timeout_seconds > 0" in ast.unparse(n.test)]
    assert len(guarded) == 1
    block = [ast.unparse(s) for s in guarded[0].body]
    assert sum(1 for s in block if "_write_progress.run" in s and ".start()" in s) == 1
    assert block.count(enrol) == 1


# ---- the numbers the two ends share -----------------------------------------------------------------

def test_the_timings_leave_the_watchdog_room_to_work():
    # A loop is called silent only after several of its turns have been missed.
    assert _Liveness.SILENT_AFTER_SECONDS >= 4 * heartbeat.BEAT_SECONDS
    # The watchdog sweeps at least every five seconds (see its run()); so does the accept loop wake.
    assert heartbeat.BEAT_SECONDS <= 5
