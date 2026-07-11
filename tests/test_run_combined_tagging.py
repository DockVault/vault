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
import sys
import time

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
