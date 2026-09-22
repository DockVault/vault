"""Every test has a deadline, and the deadline is real.

A hung test used to cost the CI job cap: tests.yml's faulthandler dump says where it hung but does
not end it, and a live module had to hand-sum a bound from every call's own timeout -- one
blocking call outside those bounds hung the run anyway. pytest-timeout gives every test, fixtures
included, a deadline from pytest.ini. This pins the three places it must be declared, and that it
FIRES: a pytest run in a subprocess, with a test that sleeps past a one-second deadline, must fail
with a timeout rather than finish -- an installed-but-inactive plugin would pass every other check.
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


def test_a_test_that_sleeps_past_the_deadline_fails_with_a_timeout(tmp_path):
    # Real pytest, in a subprocess, on a throwaway file: the plugin must be active in THIS
    # environment, not merely listed. The deadline is forced to one second on the command line so
    # the probe is quick; the sleep is bounded so an inactive plugin makes the probe finish (and
    # fail here), not hang.
    probe = tmp_path / "test_probe.py"
    probe.write_text(textwrap.dedent("""
        import time

        def test_sleeps():
            time.sleep(4)
    """), encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider\n", encoding="utf-8")
    python = sys.executable if Path(sys.executable).exists() else shutil.which("python")
    done = subprocess.run(
        [python, "-m", "pytest", "-q", "--no-header", "-o", "timeout=1", str(probe)],
        cwd=tmp_path, capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
    )
    out = done.stdout + done.stderr
    assert done.returncode != 0, out
    # Two shapes, both the deadline firing: with the signal method (Linux) the test FAILS with
    # "Timeout >1.0s" and the run goes on; with the thread method (Windows, no signals) the plugin
    # prints the "+++ Timeout +++" banner with every stack and terminates the process.
    assert ("Timeout >1.0s" in out and "1 failed" in out) or "+++ Timeout +++" in out, out
    assert "1 passed" not in out, "the sleeping test finished: the deadline is not active"
