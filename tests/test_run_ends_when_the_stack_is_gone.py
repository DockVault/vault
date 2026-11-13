"""A run against a stack ends when the stack is gone, and only then.

A run may go on past a failed test. When the stack under test has stopped, every test left fails for
that one reason, so tests/conftest.py asks the stack for its health after a live test has failed and
ends the run when the stack gives no usable answer (its section "A run against a stack ends when the
stack is gone").

Each test here runs a small suite of its own in a second pytest process that loads tests/conftest.py
as it is. No stack is involved: the health request is answered from a script, in the order the run
asks, and every request is written down, so a test can say how often the stack was asked, at which
address, and what the run did with each answer.
"""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from conftest import STACK_GONE_EXIT_STATUS

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parent
ADDRESS = "http://stack.under.test.invalid:8200"
HEALTH = f"{ADDRESS}/health timeout=5"
TESTS_FAILED = 1                                    # pytest's exit status for a run with failed tests

# Loaded into the second process with -p: answers requests.get from the script and writes each
# request down. An answer the script does not hold is written down too, and no test here expects it.
SCRIPTED_HEALTH = '''
import json
import os

import requests

_answers = json.loads(os.environ["HEALTH_ANSWERS"])
_asked = os.environ["HEALTH_ASKED"]


class _Answer:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError(f"{self.status} Server Error")

    def json(self):
        return self.body


def _get(url, timeout=None, **_):
    answer = _answers.pop(0) if _answers else "NOT SCRIPTED"
    with open(_asked, "a", encoding="utf-8") as log:
        log.write(f"{url} timeout={timeout}" + (" NOT SCRIPTED" if answer == "NOT SCRIPTED" else "") + "\\n")
    if answer == "healthy":
        return _Answer(200, {"status": "healthy", "database": "connected"})
    if answer == "no database":
        return _Answer(200, {"status": "degraded", "database": "disconnected"})
    if answer == "an error":
        return _Answer(503, {"status": "degraded", "database": "connected"})
    raise requests.ConnectionError("connection refused")      # "silent", or not scripted


requests.get = _get
'''

MARKERS = """
[pytest]
markers =
    unit: runs without a stack
    integration: needs a stack
    sftp: needs the stack's SFTP service
"""


def _run(tmp_path, suite, answers, *options):
    """Run `suite` in a pytest process of its own, with tests/conftest.py loaded and the health request
    answered by `answers` in turn. Returns the finished process and the requests it made."""
    (tmp_path / "pytest.ini").write_text(MARKERS, encoding="utf-8")
    (tmp_path / "scripted_health.py").write_text(SCRIPTED_HEALTH, encoding="utf-8")
    (tmp_path / "test_suite.py").write_text(textwrap.dedent(suite), encoding="utf-8")
    asked = tmp_path / "asked.txt"
    environment = {name: value for name, value in os.environ.items() if not name.startswith("PYTEST_")}
    environment.update(
        PYTHONPATH=os.pathsep.join([str(TESTS), str(tmp_path)]),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        VAULT_BASE_URL=ADDRESS,
        HEALTH_ANSWERS=json.dumps(answers),
        HEALTH_ASKED=str(asked),
    )
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "conftest", "-p", "scripted_health",
         "-p", "no:cacheprovider", "-v", *options, "test_suite.py"],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=300)
    return done, (asked.read_text(encoding="utf-8").splitlines() if asked.exists() else [])


def _outcomes(done):
    """{test name: outcome} from the verbose lines of the run."""
    found = {}
    for line in done.stdout.splitlines():
        if line.startswith("test_suite.py::") and " " in line:
            name, outcome = line.split()[:2]
            found[name.partition("::")[2]] = outcome
    return found


A_FAILURE_THEN_A_PASS = """
    def test_fails():
        assert False, "a failure of the test's own"

    def test_runs_after_it():
        pass
"""


def test_a_stack_that_still_answers_lets_the_run_go_on_past_a_failure(tmp_path):
    done, asked = _run(tmp_path, A_FAILURE_THEN_A_PASS, ["healthy", "healthy"], "--maxfail=25")
    assert _outcomes(done) == {"test_fails": "FAILED", "test_runs_after_it": "PASSED"}, done.stdout
    assert done.returncode == TESTS_FAILED
    # Once before the first live test, once after the failure, and not after the test that passed.
    assert asked == [HEALTH, HEALTH]
    assert "is gone" not in done.stdout + done.stderr


@pytest.mark.parametrize("answer, said", [
    ("silent", "gave no usable answer (ConnectionError: connection refused)"),
    ("an error", "gave no usable answer (HTTPError: 503 Server Error)"),
    ("no database", "answers that its database is not connected"),
])
def test_a_stack_that_is_gone_ends_the_run_at_the_first_failure(tmp_path, answer, said):
    done, asked = _run(tmp_path, A_FAILURE_THEN_A_PASS, ["healthy", answer], "--maxfail=25")
    assert _outcomes(done) == {"test_fails": "FAILED"}, done.stdout       # the test after it never ran
    assert done.returncode == STACK_GONE_EXIT_STATUS != TESTS_FAILED
    assert asked == [HEALTH, HEALTH]
    said_by_the_run = " ".join((done.stdout + done.stderr).split())
    assert f"The stack under test is gone: {ADDRESS}/health {said}" in said_by_the_run, done.stdout
    assert "asked after test_suite.py::test_fails failed" in said_by_the_run


def test_the_failed_test_is_reported_before_the_run_ends(tmp_path):
    """The run is cut short after the failed test's report is complete: its failure and its teardown
    are in the report file a later step reads."""
    done, _ = _run(tmp_path, A_FAILURE_THEN_A_PASS, ["healthy", "silent"], "--junitxml=report.xml")
    assert done.returncode == STACK_GONE_EXIT_STATUS
    report = (tmp_path / "report.xml").read_text(encoding="utf-8")
    assert 'name="test_fails"' in report and "<failure" in report and "a failure of the test" in report
    assert "test_runs_after_it" not in report


def test_the_stack_is_asked_after_the_failed_tests_fixtures_are_torn_down(tmp_path):
    """A test may take part of the stack down and bring it back in a fixture's teardown: the stack is
    judged after that, not while the test's own outage lasts."""
    done, asked = _run(tmp_path, """
        import os
        import pytest

        @pytest.fixture
        def an_outage_of_its_own():
            yield
            with open(os.environ["HEALTH_ASKED"], "a", encoding="utf-8") as log:
                log.write("the fixture's teardown\\n")

        def test_fails(an_outage_of_its_own):
            assert False

        def test_runs_after_it():
            pass
    """, ["healthy", "healthy"])
    assert asked == [HEALTH, "the fixture's teardown", HEALTH]
    assert _outcomes(done) == {"test_fails": "FAILED", "test_runs_after_it": "PASSED"}, done.stdout


@pytest.mark.parametrize("fails_in", ["setup", "teardown"])
def test_a_live_test_that_fails_in_a_fixture_counts_as_failed(tmp_path, fails_in):
    before, after = ("raise RuntimeError('no sign-in')", "") if fails_in == "setup" else ("", "raise RuntimeError('no clean-up')")
    done, asked = _run(tmp_path, f"""
        import pytest

        @pytest.fixture
        def account():
            {before}
            yield
            {after}

        def test_uses_the_stack(account):
            pass

        def test_runs_after_it():
            pass
    """, ["healthy", "silent"])
    assert done.returncode == STACK_GONE_EXIT_STATUS, done.stdout
    assert asked == [HEALTH, HEALTH]
    assert "test_runs_after_it" not in _outcomes(done)


def test_a_run_of_unit_tests_alone_never_asks(tmp_path):
    done, asked = _run(tmp_path, """
        import pytest

        pytestmark = pytest.mark.unit

        def test_fails():
            assert False

        def test_runs_after_it():
            pass
    """, [])
    assert _outcomes(done) == {"test_fails": "FAILED", "test_runs_after_it": "PASSED"}, done.stdout
    assert done.returncode == TESTS_FAILED
    assert asked == []


def test_a_unit_test_that_fails_beside_live_tests_does_not_ask(tmp_path):
    done, asked = _run(tmp_path, """
        import pytest

        def test_uses_the_stack():
            pass

        @pytest.mark.unit
        def test_a_unit_test_fails():
            assert False

        def test_uses_the_stack_after_it():
            pass
    """, ["healthy"])
    assert _outcomes(done) == {"test_uses_the_stack": "PASSED", "test_a_unit_test_fails": "FAILED",
                               "test_uses_the_stack_after_it": "PASSED"}, done.stdout
    assert done.returncode == TESTS_FAILED
    assert asked == [HEALTH]                        # the one before the first live test


def test_no_stack_at_the_start_skips_the_live_tests_as_before_and_never_asks_again(tmp_path):
    done, asked = _run(tmp_path, """
        import pytest

        def test_uses_the_stack():
            assert False, "never reached: there is no stack"

        @pytest.mark.unit
        def test_a_unit_test_fails():
            assert False

        def test_uses_the_stack_after_it():
            pass
    """, ["silent"])
    assert _outcomes(done) == {"test_uses_the_stack": "SKIPPED", "test_a_unit_test_fails": "FAILED",
                               "test_uses_the_stack_after_it": "SKIPPED"}, done.stdout
    assert done.returncode == TESTS_FAILED
    assert asked == [HEALTH]
    assert "is gone" not in done.stdout + done.stderr


def test_a_live_test_that_fails_where_no_stack_ever_answered_does_not_end_the_run(tmp_path):
    """Without a stack most live tests skip, but one whose module-scoped fixture reaches for the stack
    fails before the skip can happen. That is a run with no stack, as before, not a stack that went
    away: the tests after it still run."""
    done, asked = _run(tmp_path, """
        import pytest

        @pytest.fixture(scope="module")
        def signed_in():
            raise ConnectionError("nothing listens there")

        def test_needs_a_sign_in(signed_in):
            pass

        @pytest.mark.unit
        def test_a_unit_test_runs_after_it():
            pass

        def test_uses_the_stack_after_it():
            pass
    """, ["silent"])
    assert _outcomes(done) == {"test_needs_a_sign_in": "ERROR", "test_a_unit_test_runs_after_it": "PASSED",
                               "test_uses_the_stack_after_it": "SKIPPED"}, done.stdout
    assert done.returncode == TESTS_FAILED
    assert asked == [HEALTH]                        # by the last test, before it was skipped
    assert "is gone" not in done.stdout + done.stderr
