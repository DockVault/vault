"""run_combined.py per-service log tagging.

The provisioned single-vault image runs the web/API and SFTP servers in ONE container, so
`docker logs` interleaves both. `run_combined` tags each child's lines `[web]`/`[sftp]` via a
daemon reader thread so the two halves can be told apart (and filtered per-service upstream).

The reader thread must NEVER stop draining the child's pipe while the child lives — a child
writes to a pipe with a small kernel buffer (~64 KB), so an undrained reader would hang the
child on its next write and wedge the whole container. These tests lock that in.

Pure stdlib (subprocess/threading/io) — no running vault instance required.
"""
import io
import os
import queue
import sys
import time

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import run_combined  # noqa: E402


def test_pump_tags_each_line():
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        run_combined._pump("web", iter(["hello\n", "world\n"]))
    finally:
        sys.stdout = old
    assert buf.getvalue() == "[web] hello\n[web] world\n"


def test_pump_never_dies_on_a_write_error():
    # A transient write failure must not stop the reader draining the rest — otherwise the
    # child's pipe could fill and the child would hang.
    calls = {"n": 0}

    class FlakyOut:
        def write(self, s):
            calls["n"] += 1
            if calls["n"] == 1:
                raise IOError("boom")

        def flush(self):
            pass

    old = sys.stdout
    sys.stdout = FlakyOut()
    try:
        # Must not raise, and must attempt every line (3 writes for 3 lines).
        run_combined._pump("sftp", iter(["a\n", "b\n", "c\n"]))
    finally:
        sys.stdout = old
    assert calls["n"] == 3


def test_spawn_high_volume_child_drains_without_deadlock(tmp_path):
    # THE robustness test. A child emits far more than one pipe buffer (~64 KB) of output; if
    # the reader ever stopped draining, the child would block on write and never exit. Proof
    # of no deadlock = the child exits (rc 0) within the timeout; proof of correct tagging =
    # every captured line carries the [label] prefix and stderr was merged in.
    n_out, n_err = 3000, 5
    script = tmp_path / "noisy_child.py"
    script.write_text(
        "import sys\n"
        f"for i in range({n_out}):\n"
        "    print('out %d padding-padding-padding-padding' % i)\n"
        f"for i in range({n_err}):\n"
        "    print('err %d' % i, file=sys.stderr)\n"
    )

    run_combined._PROCS.clear()
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        run_combined._spawn(str(script), "child")
        p = run_combined._PROCS[-1][1]
        # If the pipe filled and the child hung, wait() would time out here -> test fails.
        rc = p.wait(timeout=30)
        # Let the daemon reader finish draining to EOF, then settle.
        deadline = time.monotonic() + 5
        expected = n_out + n_err
        while time.monotonic() < deadline and buf.getvalue().count("[child] ") < expected:
            time.sleep(0.05)
    finally:
        sys.stdout = old
        run_combined._PROCS.clear()

    assert rc == 0, f"child did not exit cleanly (rc={rc}) — possible pipe-fill deadlock"
    out = buf.getvalue()
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == n_out + n_err, f"lost lines: {len(lines)} != {n_out + n_err}"
    assert all(ln.startswith("[child] ") for ln in lines), "an untagged line leaked"
    assert any("err " in ln for ln in lines), "stderr was not merged into the tagged stream"


# ---- The log sink (a rotating FILE the in-container API can tail, since it
#      is a SEPARATE process that cannot read this launcher's stdout). The sink write must never
#      block a pump — it only put_nowait()s onto a bounded queue that a writer thread drains. ----

def _reset_sink():
    run_combined._sink_logger = None
    # drain any residual queued records so tests do not bleed into each other
    try:
        while True:
            run_combined._SINK_QUEUE.get_nowait()
    except queue.Empty:
        pass


def test_sink_writes_tagged_lines_to_file(tmp_path):
    sink = tmp_path / "combined.log"
    orig_path, orig_logger = run_combined._SINK_PATH, run_combined._sink_logger
    try:
        run_combined._SINK_PATH = str(sink)
        _reset_sink()
        run_combined._init_sink()
        assert run_combined._sink_logger is not None, "sink should initialize on a writable dir"
        run_combined._sink_emit("web", "Uvicorn running\n")
        run_combined._sink_emit("sftp", "SFTP listening\n")
        # Drain synchronously in this thread (sentinel stops the loop).
        run_combined._SINK_QUEUE.put(None)
        run_combined._sink_writer_loop()
        content = sink.read_text(encoding="utf-8")
        assert "[web] Uvicorn running" in content, content
        assert "[sftp] SFTP listening" in content, content
        # The tag prefix is at line start (so the API can filter per-service), one line each.
        assert content.count("\n") == 2, content
    finally:
        run_combined._SINK_PATH, run_combined._sink_logger = orig_path, orig_logger
        _reset_sink()


def test_sink_disabled_when_dir_not_writable_is_a_noop(tmp_path):
    # Point the sink at a path whose parent is a FILE (mkdir must fail) -> sink stays disabled,
    # and _sink_emit is a silent no-op (a read-only-logs deployment keeps tagging stdout).
    a_file = tmp_path / "not_a_dir"
    a_file.write_text("x")
    orig_path, orig_logger = run_combined._SINK_PATH, run_combined._sink_logger
    try:
        run_combined._SINK_PATH = str(a_file / "combined.log")
        _reset_sink()
        run_combined._init_sink()
        assert run_combined._sink_logger is None, "sink must disable when its dir is unwritable"
        run_combined._sink_emit("web", "should not raise\n")  # must not raise
        assert run_combined._SINK_QUEUE.empty(), "disabled sink must not enqueue"
    finally:
        run_combined._SINK_PATH, run_combined._sink_logger = orig_path, orig_logger
        _reset_sink()


def test_sink_emit_never_blocks_when_queue_full():
    # THE deadlock guard: a slow/failed disk (full queue) must make _sink_emit DROP, never block
    # or raise — otherwise a pump stalls and the child's stdout pipe fills and wedges the container.
    orig_q, orig_logger = run_combined._SINK_QUEUE, run_combined._sink_logger
    try:
        run_combined._SINK_QUEUE = queue.Queue(maxsize=1)
        run_combined._sink_logger = object()  # truthy so _sink_emit tries to enqueue
        run_combined._SINK_QUEUE.put_nowait("prefill")  # now full
        # Many emits against a full queue: each must return immediately, dropping silently.
        for i in range(1000):
            run_combined._sink_emit("web", f"line {i}\n")
        assert run_combined._SINK_QUEUE.qsize() == 1, "full queue must drop, not grow or block"
    finally:
        run_combined._SINK_QUEUE, run_combined._sink_logger = orig_q, orig_logger


def test_sink_rotates_at_the_size_cap(tmp_path):
    # The sink is bounded: past the cap it rotates, so a chatty vault cannot fill the disk.
    sink = tmp_path / "combined.log"
    orig_path, orig_logger = run_combined._SINK_PATH, run_combined._sink_logger
    orig_max, orig_bk = run_combined._SINK_MAX_BYTES, run_combined._SINK_BACKUPS
    try:
        run_combined._SINK_PATH = str(sink)
        run_combined._SINK_MAX_BYTES = 2000  # tiny cap to force rotation quickly
        run_combined._SINK_BACKUPS = 1
        _reset_sink()
        run_combined._init_sink()
        for i in range(500):
            run_combined._sink_emit("web", f"padding-padding-padding line {i}\n")
        run_combined._SINK_QUEUE.put(None)
        run_combined._sink_writer_loop()
        # A rotation happened (the .1 backup exists) and each file is bounded by the cap.
        assert (tmp_path / "combined.log.1").exists(), "expected a rotated backup file"
        assert sink.stat().st_size <= run_combined._SINK_MAX_BYTES + 500, "active file exceeds cap"
    finally:
        (run_combined._SINK_PATH, run_combined._sink_logger,
         run_combined._SINK_MAX_BYTES, run_combined._SINK_BACKUPS) = (
            orig_path, orig_logger, orig_max, orig_bk)
        _reset_sink()
