"""Offline checks that the workflows run the whole suite once, in lanes whose reports are joined.

The suite runs as the offline lane (preflight) and six shards on six stacks. What makes that the
same check as one job running everything:

- the offline lane and the shards select every test, and none twice;
- the shards are the ones the recorded times deal out, and none cancels another;
- every lane keeps its report under a name of its own, and one job reads them all, joins them,
  audits the result and cannot be skipped;
- the same job checks that the tests changed since the last release ran in their lanes.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_TEXT = {name: (_WORKFLOWS / f"{name}.yml").read_text(encoding="utf-8")
         for name in ("tests", "preflight", "fast-tests", "setup-matrix", "release")}
_YAML = {name: yaml.safe_load(text) for name, text in _TEXT.items()}
_JOBS = _YAML["tests"]["jobs"]
_SHARD, _REPORT = _JOBS["integration"], _JOBS["suite-report"]
_OFFLINE_LANE = _YAML["preflight"]["jobs"]["preflight"]
_FAST_LANE = _YAML["fast-tests"]["jobs"]["fast"]

_SPEC = importlib.util.spec_from_file_location("suite_shards", _ROOT / ".github" / "scripts" / "suite_shards.py")
assert _SPEC and _SPEC.loader
_SHARDS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SHARDS)
_SHARD_COUNT, _SECONDS = _SHARDS.load(_ROOT / ".github" / "suite-shards.json")

_UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
_OFFLINE = "unit and not docker"
# GitHub starts a step's script with these options on a Linux runner.
_BASH = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
_NEEDS_BASH = pytest.mark.skipif(
    os.name == "nt", reason="the step is a bash script for a Linux runner; the Linux lanes run this")


def _step(job: dict, name: str) -> dict:
    (step,) = [s for s in job["steps"] if s.get("name") == name]
    return step


def _pytest_commands(job: dict) -> list[str]:
    return [line.strip() for step in job["steps"] for line in step.get("run", "").splitlines()
            if "python -m pytest" in line]


def _expression(command: str) -> str:
    (expression,) = re.findall(r' -m "([^"]+)"', command)
    return expression


# --- every test once ---------------------------------------------------------------------------


def test_the_shards_select_what_the_offline_lane_leaves_out():
    """Preflight and the two Fast lanes run `unit and not docker`. A shard runs exactly the rest: the
    same expression, negated. Its own files only, read from the file the shard script wrote."""
    assert _step(_OFFLINE_LANE, "Run the offline fast lane")["run"] == (
        f'python -m pytest -m "{_OFFLINE}" --maxfail=1 --junitxml=offline-results.xml')
    assert _step(_FAST_LANE, "Run the offline fast lane")["run"] == (
        f'python -m pytest -m "{_OFFLINE}" --maxfail=1 --junitxml=fast-results.xml')

    (command,) = _pytest_commands(_SHARD)
    assert _expression(command) == f"not ({_OFFLINE})"
    assert command.split()[:4] == ["VAULT_SFTP_STREAMING=1", "python", "-m", "pytest"]
    assert command.split()[4] == "@shard-files.txt"
    run = _step(_SHARD, "Run this shard of the suite")["run"]
    listed = "python .github/scripts/suite_shards.py files --shard ${{ matrix.shard }} > shard-files.txt\n"
    assert run.index(listed) < run.index(command)
    # No path or keyword of its own narrows a shard further than its file list and the expression.
    assert " -k " not in command and "tests/" not in command and "--deselect" not in command


_MARKED = '''
import pytest

pytestmark = pytest.mark.{module}


def test_plain():
    pass


@pytest.mark.docker
def test_docker():
    pass


@pytest.mark.ui
def test_ui():
    pass


@pytest.mark.docker
@pytest.mark.sftp
def test_docker_and_sftp():
    pass
'''


def test_between_them_the_two_expressions_select_every_test_once(tmp_path):
    """pytest itself, on a file of unit tests and a file of the other kind, each holding a test with no
    further marker, a docker one and others: what the offline lanes' expression selects and what the
    shards' selects are every test, and no test twice. A docker test runs in a shard whichever file it
    is in."""
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n    unit\n    integration\n    docker\n    ui\n    sftp\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    for module in ("unit", "integration"):
        (tmp_path / "tests" / f"test_{module}_file.py").write_text(_MARKED.format(module=module), encoding="utf-8")
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONUTF8="1")

    def selected(*arguments: str) -> list[str]:
        done = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "--strict-markers",
             *arguments, "tests"], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stdout + done.stderr
        return [line for line in done.stdout.splitlines() if "::" in line]

    everything = selected()
    offline = selected("-m", _expression(_pytest_commands(_FAST_LANE)[0]))
    shards = selected("-m", _expression(_pytest_commands(_SHARD)[0]))

    assert len(everything) == 8
    assert sorted(offline + shards) == sorted(everything)
    assert offline == ["tests/test_unit_file.py::test_plain", "tests/test_unit_file.py::test_ui"]
    assert "tests/test_unit_file.py::test_docker" in shards
    assert "tests/test_unit_file.py::test_docker_and_sftp" in shards


def test_the_report_job_collects_with_the_lanes_expressions():
    """The names the reports are compared with are a collection of the whole suite, and the second
    list, which says what the offline lanes run, uses the offline lanes' own expression."""
    run = _step(_REPORT, "Collect the suite's test names")["run"]
    assert [line.strip() for line in run.splitlines() if "pytest" in line] == [
        "python -m pytest --collect-only -q > collected.txt",
        f'python -m pytest --collect-only -q -m "{_OFFLINE}" > collected-offline.txt',
    ]
    assert run.lstrip().startswith("set -euo pipefail\n")


# --- the shards --------------------------------------------------------------------------------


def test_the_shards_are_the_recorded_ones_and_none_cancels_another():
    assert _SHARD["strategy"] == {"fail-fast": False,
                                  "matrix": {"shard": list(range(1, _SHARD_COUNT + 1))}}
    assert _SHARD["name"] == f"Full suite, shard ${{{{ matrix.shard }}}} of {_SHARD_COUNT} (API + browser + SFTP)"
    assert "if" not in _SHARD and "needs" not in _SHARD and "continue-on-error" not in _SHARD

    (command,) = _pytest_commands(_SHARD)
    # A round shows up to 25 failures of each shard; the offline lanes still stop at their first.
    assert "--maxfail=25" in command.split()
    assert "--junitxml=suite-results.xml" in command.split()
    assert command.endswith("-o faulthandler_timeout=300")


def test_a_shards_time_limit_is_twice_what_the_recorded_times_need():
    """The limit ends a hang. It must leave about twice the recorded time, because runners differ and
    the suite grows, and stay far under the 240 minutes the single job needed."""
    rows = _SHARDS.balance(_SHARDS.suite_files(_ROOT), _SECONDS, _SHARD_COUNT)
    longest_minutes = max(row["seconds"] for row in rows) / 60
    setup_minutes = 2
    limit = _SHARD["timeout-minutes"]
    assert limit >= 2 * (longest_minutes + setup_minutes), (limit, longest_minutes)
    assert limit <= 90


def test_the_readme_runs_a_shard_with_the_shards_own_command():
    """tests/README.md shows how to run one shard against a local stack, in PowerShell. It shows the
    shard's own marker expression and failure limit, and it writes the file list with an encoding
    pytest can read: Windows PowerShell's `>` writes UTF-16 or a byte-order mark first, and pytest
    then looks for a file of that name and runs nothing."""
    readme = (_ROOT / "tests" / "README.md").read_text(encoding="utf-8")
    (command,) = _pytest_commands(_SHARD)
    (limit,) = [word for word in command.split() if word.startswith("--maxfail=")]
    assert f'python -m pytest "@shard-files.txt" -m "{_expression(command)}" {limit}\n' in readme
    assert ("python .github/scripts/suite_shards.py files --shard 3 | Out-File -Encoding ascii shard-files.txt\n"
            in readme)
    assert re.search(r"suite_shards\.py files --shard \d+ *>", readme) is None


# --- every lane's report -----------------------------------------------------------------------


def _upload_after(job: dict, pytest_step: str, upload_step: str) -> dict:
    names = [step.get("name") for step in job["steps"]]
    assert names.index(upload_step) == names.index(pytest_step) + 1
    upload = _step(job, upload_step)
    assert upload["uses"] == _UPLOAD
    return upload


def test_every_lane_keeps_its_report_under_a_name_of_its_own():
    """A report is kept after a failed run too, under a name no other job of the run takes: a second
    upload under a taken name fails its step."""
    shard = _upload_after(_SHARD, "Run this shard of the suite", "Keep the shard's report (durations + results)")
    assert shard["if"] == "always()"
    assert shard["with"]["name"] == "lane-results-shard-${{ matrix.shard }}"
    assert shard["with"]["path"] == "suite-results.xml"

    fast = _upload_after(_FAST_LANE, "Run the offline fast lane", "Keep the lane's report")
    assert fast["if"] == "always()"
    assert fast["with"]["name"] == "lane-results-fast-${{ matrix.os }}"
    assert fast["with"]["path"] == "fast-results.xml"

    offline = _upload_after(_OFFLINE_LANE, "Run the offline fast lane", "Keep the offline lane's report")
    assert offline["if"] == "${{ always() && inputs.offline_report_artifact != '' }}"
    assert offline["with"]["name"] == "${{ inputs.offline_report_artifact }}"
    assert offline["with"]["path"] == "offline-results.xml"
    declared = _YAML["preflight"][True]["workflow_call"]["inputs"]["offline_report_artifact"]
    assert declared == {"description": declared["description"], "required": False, "type": "string", "default": ""}

    # Tests asks preflight for the report. The setup scenarios call preflight too, and a release
    # runs both in one run: they must name no artifact, or the second upload would fail.
    assert _JOBS["preflight"]["with"] == {
        "expected_sha": "${{ inputs.expected_sha }}", "offline_report_artifact": "lane-results-offline"}
    assert _YAML["setup-matrix"]["jobs"]["preflight"]["with"] == {"expected_sha": "${{ inputs.expected_sha }}"}
    assert _TEXT["release"].count("uses: ./.github/workflows/tests.yml") == 1
    assert "preflight.yml" not in _TEXT["release"]


# --- the job that joins them --------------------------------------------------------------------


def test_the_suite_report_reads_every_lane_and_cannot_be_skipped():
    assert _REPORT["needs"] == ["preflight", "integration", "fast"]
    # Runs after a failed lane too, and on a tag: a job that was skipped counts as passed.
    assert _REPORT["if"] == "${{ always() }}"
    assert "continue-on-error" not in _REPORT
    assert 10 <= _REPORT["timeout-minutes"] <= 30

    assert [step.get("name", step.get("uses")) for step in _REPORT["steps"]] == [
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "Verify requested commit",
        "Set up Python 3.14",
        "Install locked test dependencies",
        "Collect the suite's test names",
        "Fetch every lane's report",
        "Show the shards' recorded balance",
        "Join the lanes' reports and check that every test ran exactly once",
        "Keep the joined report (durations + results)",
        "Audit the joined report",
        "Check that the tests changed since the last release ran in their lanes",
    ]
    checkout = _REPORT["steps"][0]["with"]
    assert checkout == {"ref": "${{ inputs.expected_sha || github.sha }}", "fetch-depth": 0,
                        "persist-credentials": False}
    assert _step(_REPORT, "Verify requested commit")["run"] == 'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"'
    # The names are collected with the packages preflight and the shards have, and with nothing
    # else: what is installed can change what a test file collects, and the names are compared
    # with those lanes' reports.
    assert _step(_REPORT, "Install locked test dependencies")["run"].splitlines() == [
        "python -m pip install -r tests/requirements-test.lock",
        "python -m pip install --force-reinstall --require-hashes -r requirements.lock",
        "python -m pip check",
    ]

    # Every lane's report, by the one prefix their artifacts share.
    fetch = _step(_REPORT, "Fetch every lane's report")
    assert re.fullmatch(r"actions/download-artifact@[0-9a-f]{40}", fetch["uses"])
    assert fetch["with"] == {"pattern": "lane-results-*", "path": "reports"}
    assert "if" not in fetch
    # Of everything a Tests run keeps, the pattern takes the lanes' reports and nothing else: not the
    # joined report of an earlier attempt, not a failure's pictures.
    lanes = {"lane-results-shard-${{ matrix.shard }}", "lane-results-fast-${{ matrix.os }}", "lane-results-offline"}
    artifacts = {step["with"]["name"] for job in (_SHARD, _JOBS["scenarios"], _REPORT, _FAST_LANE)
                 for step in job["steps"] if step.get("uses") == _UPLOAD}
    artifacts.add(_JOBS["preflight"]["with"]["offline_report_artifact"])
    assert {name for name in artifacts if fnmatch.fnmatchcase(name, fetch["with"]["pattern"])} == lanes
    assert artifacts - lanes == {
        "pytest-results", "ui-failure-screenshots-shard-${{ matrix.shard }}", "ui-failure-screenshots-scenarios"}

    # The join and the audit have no condition: each runs only if all went well before it, and its
    # failure fails the job. The audit is the one the single job's report went through.
    join = _step(_REPORT, "Join the lanes' reports and check that every test ran exactly once")
    audit = _step(_REPORT, "Audit the joined report")
    assert "if" not in join and "if" not in audit
    assert 'reports=(--report "offline=reports/lane-results-offline/offline-results.xml")' in join["run"]
    assert ('reports+=(--report "shard-${shard}=reports/lane-results-shard-${shard}/suite-results.xml")'
            in join["run"])
    assert 'shards="$(python .github/scripts/suite_shards.py count)"\n' in join["run"]
    assert 'for shard in $(seq 1 "$shards"); do\n' in join["run"]
    assert ('python .github/scripts/join_suite_reports.py --collected collected.txt "${reports[@]}" '
            "--output pytest-results.xml") in join["run"]
    assert audit["run"] == ("python .github/scripts/pytest_result_audit.py pytest-results.xml "
                            '--expected-total "${{ needs.preflight.outputs.test-count }}"')

    # The joined report is kept, failed or not, under the name the single job's report had.
    kept = _step(_REPORT, "Keep the joined report (durations + results)")
    assert kept["uses"] == _UPLOAD and kept["if"] == "always()"
    assert kept["with"]["name"] == "pytest-results" and kept["with"]["path"] == "pytest-results.xml"


def test_the_changed_test_check_reads_the_fast_lanes_whenever_they_ran():
    step = _step(_REPORT, "Check that the tests changed since the last release ran in their lanes")
    assert step["if"] == "always()"
    assert step["env"] == {"FAST_LANES": "${{ needs.fast.result }}"}
    run = step["run"]
    assert 'lanes=(--offline-lane "preflight=reports/lane-results-offline/offline-results.xml")' in run
    assert 'if [ "$FAST_LANES" != "skipped" ]; then' in run
    systems = {"ubuntu-latest": "linux", "windows-latest": "windows"}
    assert sorted(_FAST_LANE["strategy"]["matrix"]["os"]) == sorted(systems)
    for runner, lane in systems.items():
        assert f'lanes+=(--offline-lane "{lane}=reports/lane-results-fast-{runner}/fast-results.xml")' in run
    assert ('python .github/scripts/changed_tests_ran.py --collected collected.txt '
            '--offline-collected collected-offline.txt "${lanes[@]}" '
            "--stack-report reports/lane-results-shard-*/suite-results.xml") in run
    assert "--base-ref" not in run                       # the script finds the last release tag
    # The Fast lanes are part of a manual run and of a release's call, and only then.
    assert _JOBS["fast"]["if"] == "github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')"


def test_each_action_of_the_suites_workflows_is_pinned_to_a_commit_with_its_version():
    for name in ("tests", "preflight", "fast-tests"):
        used = [line.split("uses:", 1)[1].strip() for line in _TEXT[name].splitlines()
                if line.lstrip("- ").startswith("uses:")]
        assert used, name
        for action in used:
            assert action.startswith("./.github/workflows/") or re.fullmatch(
                r"[\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", action), (name, action)


# --- the report job's two scripts, run -----------------------------------------------------------


def _checkout(tmp_path: Path) -> Path:
    """The scripts and the shard data as a checkout has them, in a directory the steps can write in."""
    root = tmp_path / "checkout"
    shutil.copytree(_ROOT / ".github" / "scripts", root / ".github" / "scripts",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(_ROOT / ".github" / "suite-shards.json", root / ".github" / "suite-shards.json")
    return root


def _write_report(path: Path, *tests: str) -> None:
    cases = "".join(
        f'<testcase classname="{test.split("::")[0][:-3].replace("/", ".")}" name="{test.split("::")[1]}" time="1"/>'
        for test in tests)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'<testsuites><testsuite name="pytest" tests="{len(tests)}" skipped="0" failures="0" '
                    f'errors="0" time="1">{cases}</testsuite></testsuites>', encoding="utf-8")


def _write_lanes(root: Path) -> tuple[str, list[str]]:
    """One offline test and one stack test per shard, collected and reported as the lanes would."""
    offline = "tests/test_changed_unit.py::test_offline"
    stack = [f"tests/test_changed_live_{number}.py::test_stack" for number in range(1, _SHARD_COUNT + 1)]
    everything = [offline, *stack]
    (root / "collected.txt").write_text(
        "\n".join(everything) + f"\n\n{len(everything)} tests collected in 1.00s\n", encoding="utf-8")
    (root / "collected-offline.txt").write_text(
        f"{offline}\n\n1/{len(everything)} tests collected ({len(stack)} deselected) in 1.00s\n", encoding="utf-8")
    _write_report(root / "reports" / "lane-results-offline" / "offline-results.xml", offline)
    for number, test in enumerate(stack, start=1):
        _write_report(root / "reports" / f"lane-results-shard-{number}" / "suite-results.xml", test)
    return offline, stack


def _run_step(root: Path, name: str, **env: str) -> subprocess.CompletedProcess:
    script = root / "step.sh"
    script.write_text(_step(_REPORT, name)["run"], encoding="utf-8", newline="\n")
    path = os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])
    return subprocess.run([*_BASH, str(script)], cwd=root, env={**os.environ, "PATH": path, **env},
                          capture_output=True, text=True, timeout=120)


@_NEEDS_BASH
def test_the_join_step_passes_on_a_report_from_every_lane_and_fails_without_one(tmp_path):
    root = _checkout(tmp_path)
    _write_lanes(root)
    name = "Join the lanes' reports and check that every test ran exactly once"

    done = _run_step(root, name)
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"every one of the {_SHARD_COUNT + 1} collected tests is in exactly one report" in done.stdout
    assert (root / "pytest-results.xml").is_file()

    # Any one lane's report missing: the last shard's, the first, the offline lane's.
    for lane in (f"shard-{_SHARD_COUNT}", "shard-1", "offline"):
        report = root / "reports" / f"lane-results-{lane}"
        report.rename(root / "set-aside")
        done = _run_step(root, name)
        assert done.returncode != 0, lane
        assert f"::error::the {lane} report is missing" in done.stderr
        (root / "set-aside").rename(report)

    # A shard the data does not count is a shard nobody joins: its report is a case too many.
    extra = root / "reports" / f"lane-results-shard-{_SHARD_COUNT + 1}" / "suite-results.xml"
    _write_report(extra, "tests/test_changed_live_extra.py::test_stack")
    assert _run_step(root, name).returncode == 0
    (root / ".github" / "suite-shards.json").write_text(
        '{"shards": %d, "seconds": {}}' % (_SHARD_COUNT + 1), encoding="utf-8")
    done = _run_step(root, name)
    assert done.returncode != 0 and "1 report case(s) are not in the collection" in done.stderr


@_NEEDS_BASH
def test_the_changed_test_step_asks_for_the_fast_lanes_when_they_ran(tmp_path):
    root = _checkout(tmp_path)
    offline, stack = _write_lanes(root)
    name = "Check that the tests changed since the last release ran in their lanes"

    def git(*arguments: str) -> None:
        subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True, timeout=60)

    git("init", "-q", "-b", "main")
    for key, value in (("user.name", "Suite Lanes"), ("user.email", "suite-lanes@example.invalid"),
                       ("commit.gpgsign", "false"), ("tag.gpgsign", "false")):
        git("config", key, value)
    git("commit", "-q", "--allow-empty", "-m", "release 1.0.0")
    git("tag", "v1.0.0")
    for test in (offline, *stack):
        target = root / test.split("::")[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("changed\n", encoding="utf-8")
    git("add", "tests")
    git("commit", "-q", "-m", "tests after the release")

    # A pull request or a push: the Fast lanes are another workflow's, and this run's lanes pass.
    done = _run_step(root, name, FAST_LANES="skipped")
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"compared with v1.0.0: {_SHARD_COUNT + 1} test file(s) added or changed" in done.stdout
    assert "::notice::the Fast lanes are not part of this run" in done.stdout
    assert "preflight: 1 test(s) of the changed files: 1 ran, 0 skipped" in done.stdout
    assert f"stack: {_SHARD_COUNT} test(s) of the changed files: {_SHARD_COUNT} ran, 0 skipped" in done.stdout

    # A candidate's run or a release: they ran, whatever their result, so their reports are required.
    for result in ("success", "failure", "cancelled"):
        done = _run_step(root, name, FAST_LANES=result)
        assert done.returncode != 0, result
        assert "::error::linux: the report" in done.stderr and "::error::windows: the report" in done.stderr
    _write_report(root / "reports" / "lane-results-fast-ubuntu-latest" / "fast-results.xml", offline)
    _write_report(root / "reports" / "lane-results-fast-windows-latest" / "fast-results.xml")
    done = _run_step(root, name, FAST_LANES="success")
    assert done.returncode != 0
    assert done.stderr.strip() == ("::error::windows: 1 test(s) of changed files are not in the report: "
                                   + offline)
    _write_report(root / "reports" / "lane-results-fast-windows-latest" / "fast-results.xml", offline)
    done = _run_step(root, name, FAST_LANES="success")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "windows: 1 test(s) of the changed files: 1 ran, 0 skipped" in done.stdout

    # A shard that kept no report: its changed test is in none.
    shutil.rmtree(root / "reports" / "lane-results-shard-2")
    done = _run_step(root, name, FAST_LANES="success")
    assert done.returncode != 0 and stack[1] in done.stderr
