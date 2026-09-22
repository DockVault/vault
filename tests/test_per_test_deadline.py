"""Every test has a deadline, and the deadline is real.

A hung test used to cost the CI job cap: tests.yml's faulthandler dump says where it hung but does
not end it, and a live module had to hand-sum a bound from every call's own timeout -- one
blocking call outside those bounds hung the run anyway. pytest-timeout gives every test, fixtures
included, a deadline from pytest.ini. This pins the three places it must be declared, and that it
FIRES: a pytest run in a subprocess, with a test that sleeps past a one-second deadline, must be
cut off before the test's last line -- an installed-but-inactive plugin would pass every other
check. Judged by what the test reached, never by the plugin's message, which is worded per platform.
"""
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def test_the_deadline_is_declared_in_the_input_the_lock_and_the_config():
    inp = (ROOT / "tests" / "requirements-test.txt").read_text(encoding="utf-8")
    lock = (ROOT / "tests" / "requirements-test.lock").read_text(encoding="utf-8")
    ini = (ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert re.search(r"^pytest-timeout>=", inp, re.M), "declare the plugin in the input file"
    assert re.search(r"^pytest-timeout==\d", lock, re.M), "re-resolve the lock; do not hand-edit it"
    m = re.search(r"^timeout\s*=\s*(\d+)\s*$", ini, re.M)
    assert m, "pytest.ini must set a default `timeout`"
    assert 300 <= int(m.group(1)) <= 1800, "generous enough for a live lane, far below the job cap"


def _run_sleeper(tmp_path, seconds, *extra):
    """Run a nested pytest on a throwaway test that sleeps ``seconds`` under a one-second deadline,
    and return (exit code, whether the sleeper reached its last line, the output).

    The verdict never reads the plugin's message: its wording differs per platform and is the
    plugin's to change in any patch release ("Timeout (>1.0s)" under the signal method on Linux, a
    "+++ Timeout +++" banner and a terminated process under the thread method on Windows). What
    the deadline MEANS is that the test was cut off before it finished, so the sleeper writes a
    file on its last line and the verdict is whether that file exists."""
    probe = tmp_path / "test_probe.py"
    reached = tmp_path / "reached-the-end"
    probe.write_text(textwrap.dedent(f"""
        import pathlib
        import time

        def test_sleeps():
            time.sleep({seconds})
            pathlib.Path({str(reached)!r}).write_text("done")
    """), encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider\n", encoding="utf-8")
    python = sys.executable if Path(sys.executable).exists() else shutil.which("python")
    done = subprocess.run(
        [python, "-m", "pytest", "-q", "--no-header", "-o", "timeout=1", *extra, str(probe)],
        cwd=tmp_path, capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
    )
    return done.returncode, reached.exists(), done.stdout + done.stderr


def test_a_test_that_sleeps_past_the_deadline_is_cut_off_before_it_finishes(tmp_path):
    # Real pytest, in a subprocess: the plugin must be ACTIVE in this environment, not merely
    # listed. The sleep is far past the one-second deadline, so a cut-off is unambiguous, and still
    # bounded, so an inactive plugin makes the probe finish (and fail here) rather than hang.
    code, reached, out = _run_sleeper(tmp_path, 10)
    assert not reached, "the sleeper reached its last line: the deadline did not cut it off\n" + out
    assert code != 0, out


def test_the_instrument_can_see_a_test_finish(tmp_path):
    # The same probe with the plugin DISABLED must let the sleeper finish -- otherwise "the file
    # was never written" could mean the probe itself is broken, and the test above would pass for
    # that reason instead. Short sleep, still past the (now inert) one-second deadline.
    code, reached, out = _run_sleeper(tmp_path, 2, "-p", "no:timeout")
    assert reached, "the probe cannot observe a finished test, so it cannot observe a cut-off\n" + out
    assert code == 0, out
