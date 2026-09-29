"""Offline checks for the full-suite workflow's failure semantics."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import test_api_update_settings as update_settings
import test_login_throttle as login_throttle
import test_zk_vault as zk_vault

import pytest
import yaml

from conftest import skip_for_older_deployment


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_WORKFLOW = (_ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
_FAST_WORKFLOW = (_ROOT / ".github" / "workflows" / "fast-tests.yml").read_text(
    encoding="utf-8"
)
_PREFLIGHT = (_ROOT / ".github" / "workflows" / "preflight.yml").read_text(encoding="utf-8")


def _step(name: str, next_name: str) -> str:
    return _WORKFLOW.split(f"- name: {name}", 1)[1].split(f"- name: {next_name}", 1)[0]


def _job_text(name: str, next_name: str | None) -> str:
    """One job of tests.yml as text, sliced at the next job's key (exactly once each)."""
    assert _WORKFLOW.count(f"\n  {name}:\n") == 1, name
    body = _WORKFLOW.split(f"\n  {name}:\n", 1)[1]
    if next_name is None:
        return body
    assert body.count(f"\n  {next_name}:\n") == 1, next_name
    return body.split(f"\n  {next_name}:\n", 1)[0]


# The six configuration scenarios. Each reconfigures the stack, so they run in a job of their own.
_SCENARIO_STEPS = (
    "Exercise the transfer ceiling on a deployment that refuses",
    "Exercise the log-pull endpoint with its ceiling on",
    "Exercise the vault-type allowlist against a forbidden type",
    "Exercise the general API fail-open during a Redis outage",
    "Exercise login throttling and Redis outage fallback",
    "Exercise the device-sync pre-flight states",
)
# The setup both stack jobs share, from the checkout to the browser check.
_LAST_SETUP_STEP = "Verify Chromium launches against the API"


def test_preflight_blocks_expensive_integration_work():
    caller = _WORKFLOW.split("  preflight:", 1)[1].split("  integration:", 1)[0]
    integration = _WORKFLOW.split("  integration:", 1)[1]

    assert "uses: ./.github/workflows/preflight.yml" in caller
    assert "workflow_call:" in _PREFLIGHT
    assert "needs: preflight" in integration
    assert "--collect-only -q" in _PREFLIGHT
    assert '-m "unit and not docker" --maxfail=1' in _PREFLIGHT
    assert "docker compose" not in _PREFLIGHT
    assert "playwright install" not in _PREFLIGHT


def test_the_configuration_scenarios_run_in_their_own_job_on_the_same_stack():
    """The six reconfiguring scenarios used to follow the suite in one job and one 60-minute cap,
    which the suite plus 0.33.0's new tests would have run out. They now run in a second job, beside
    the suite, on a stack of their own. What must hold for that to be the same check, not a weaker one:

    - both jobs build the stack with the same setup, step for step, so a scenario still starts
      from the stack the suite runs on;
    - every scenario is in the new job and none is left behind in the suite's;
    - both jobs need only preflight (in parallel, not one after the other) and neither can be
      skipped, because a release publishes only when every job of this workflow succeeded;
    - each job keeps its own logs, teardown and uniquely named failure pictures;
    - the suite's cap is 75 minutes.
    """
    import yaml

    jobs = yaml.safe_load(_WORKFLOW)["jobs"]
    suite, scenarios = jobs["integration"], jobs["scenarios"]

    for job in (suite, scenarios):
        assert job["needs"] == "preflight"
        assert "if" not in job                   # a skipped job counts as passed for publication
        assert job["runs-on"] == "ubuntu-latest"
    assert suite["timeout-minutes"] == 75
    assert 15 <= scenarios["timeout-minutes"] <= 45

    def names(job):
        return [step.get("name", step.get("uses", "")) for step in job["steps"]]

    suite_names, scenario_names = names(suite), names(scenarios)
    cut_suite = suite_names.index(_LAST_SETUP_STEP) + 1
    cut_scenarios = scenario_names.index(_LAST_SETUP_STEP) + 1
    # The same setup, compared as parsed steps: names, commands, pins, masks and all.
    assert cut_suite == cut_scenarios == 9
    assert suite["steps"][:cut_suite] == scenarios["steps"][:cut_scenarios]

    # The scenarios, all of them, in their old order, straight after the setup.
    assert scenario_names[cut_scenarios:cut_scenarios + len(_SCENARIO_STEPS)] == list(_SCENARIO_STEPS)
    for name in _SCENARIO_STEPS:
        assert name not in suite_names
    # The suite, its report and its count audit stay in the suite's job only.
    for name in (
        "Run the full test suite",
        "Keep the test report (durations + results)",
        "Audit the successful full report",
    ):
        assert name in suite_names and name not in scenario_names
    assert suite_names[cut_suite:cut_suite + 3] == [
        "Run the full test suite",
        "Keep the test report (durations + results)",
        "Audit the successful full report",
    ]

    # Each job ends by keeping its failure picture and logs, then tearing its own stack down.
    artifacts = []
    for job in (suite, scenarios):
        tail = job["steps"][-3:]
        assert [s["name"] for s in tail] == [
            "Keep the picture of a failed browser test",
            "Container logs",
            "Tear the stack down",
        ]
        assert tail[0]["if"] == "failure()"
        assert tail[1]["if"] == "${{ failure() || cancelled() }}"
        assert tail[2]["if"] == "always()"
        assert tail[2]["run"] == "docker compose down -v --remove-orphans"
        artifacts += [
            s["with"]["name"] for s in job["steps"]
            if s.get("uses", "").startswith("actions/upload-artifact@")
        ]
    # Artifact names are unique within a run: a second upload under a taken name fails its step.
    assert len(artifacts) == len(set(artifacts)) == 3


def test_a_candidate_or_release_tests_run_includes_the_fast_lanes():
    """The Fast lanes are the only ones with the test lock alone. A candidate's Tests run and the
    release's call must include them, on the commit under test, or a test that imports something only
    the production lock carries is first caught on main -- after the release has shipped."""
    import yaml

    tests = yaml.safe_load(_WORKFLOW)
    job = tests["jobs"]["fast"]
    assert job["uses"] == "./.github/workflows/fast-tests.yml"
    # A manual run (a candidate) and a tag (the release, whose publish needs this whole workflow).
    assert job["if"] == "github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/')"
    assert job["with"] == {"expected_sha": "${{ inputs.expected_sha }}"}
    assert "needs" not in job                              # in parallel with the suites
    assert job["permissions"] == {"contents": "read"}

    fast = yaml.safe_load(_FAST_WORKFLOW)
    triggers = fast[True]                                   # YAML reads the bare key `on` as True
    assert triggers["workflow_call"]["inputs"]["expected_sha"]["type"] == "string"
    for own in ("pull_request", "push", "workflow_dispatch"):
        assert own in triggers                              # it still runs on its own as well
    lane = fast["jobs"]["fast"]
    assert sorted(lane["strategy"]["matrix"]["os"]) == ["ubuntu-latest", "windows-latest"]
    checkout = [s for s in lane["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkout) == 1
    assert checkout[0]["with"]["ref"] == "${{ inputs.expected_sha || github.sha }}"
    assert fast["concurrency"]["group"].startswith("fast-tests-")


def test_fast_host_pytest_job_installs_the_cross_platform_locked_environment():
    test_install = "python -m pip install -r tests/requirements-test.lock"
    dependency_check = "python -m pip check"
    pytest_command = 'python -m pytest -m "unit and not docker" --maxfail=1'
    install_order = [
        _FAST_WORKFLOW.index(test_install),
        _FAST_WORKFLOW.index(dependency_check),
        _FAST_WORKFLOW.index(pytest_command),
    ]

    assert _FAST_WORKFLOW.count(test_install) == 1
    assert _FAST_WORKFLOW.count(dependency_check) == 1
    assert (
        _FAST_WORKFLOW.count(
            "cache-dependency-path: tests/requirements-test.lock"
        )
        == 1
    )
    assert (
        "python -m pip install --force-reinstall --require-hashes -r requirements.lock"
        not in _FAST_WORKFLOW
    )
    assert "requirements.txt" not in _FAST_WORKFLOW
    assert install_order == sorted(install_order)


@pytest.mark.parametrize(
    ("workflow", "first_pytest_command"),
    [
        (_PREFLIGHT, "python -m pytest --collect-only -q"),
        (
            _job_text("integration", "scenarios"),
            "python -m pytest --maxfail=1 --junitxml=pytest-results.xml",
        ),
        (
            _job_text("scenarios", None),
            "python -m pytest tests/test_transfer_admission_live.py",
        ),
    ],
    ids=["preflight", "integration", "scenarios"],
)
def test_linux_host_pytest_jobs_layer_the_hash_locked_production_environment(
    workflow: str, first_pytest_command: str
):
    cache_inputs = (
        "cache-dependency-path: |\n"
        "            requirements.lock\n"
        "            tests/requirements-test.lock"
    )
    test_install = "python -m pip install -r tests/requirements-test.lock"
    production_install = (
        "python -m pip install --force-reinstall --require-hashes -r requirements.lock"
    )
    dependency_check = "python -m pip check"
    install_order = [
        workflow.index(test_install),
        workflow.index(production_install),
        workflow.index(dependency_check),
        workflow.index(first_pytest_command),
    ]

    assert workflow.count(test_install) == 1
    assert workflow.count(production_install) == 1
    assert workflow.count(dependency_check) == 1
    assert workflow.count(cache_inputs) == 1
    assert "python -m pip install -r requirements.txt" not in workflow
    assert cache_inputs in workflow
    assert install_order == sorted(install_order)


def test_full_suite_exit_and_result_count_are_authoritative():
    assert "|| true" not in _WORKFLOW
    assert "python -m pytest --maxfail=1 --junitxml=pytest-results.xml" in _WORKFLOW
    assert '--expected-total "${{ needs.preflight.outputs.test-count }}"' in _WORKFLOW
    assert "MIN_TESTS_ACTUALLY_RUN" not in _WORKFLOW


def test_missing_services_and_browser_fail_closed():
    api_gate = _step("Wait for the API health gate", "Wait for the SFTP banner")
    sftp_gate = _step(
        "Wait for the SFTP banner",
        "Install locked test dependencies and Chromium",
    )
    browser_gate = _step(
        "Verify Chromium launches against the API",
        "Run the full test suite",
    )

    assert "::error::Vault never reported healthy" in api_gate and "exit 1" in api_gate
    assert "::error::SFTP never presented an SSH banner" in sftp_gate and "exit 1" in sftp_gate
    assert "playwright.chromium.launch" in browser_gate
    assert "raise SystemExit" in browser_gate


def test_disposable_ci_enables_outage_and_same_commit_guards():
    assert "VAULT_REDIS_OUTAGE_TEST=1" in _WORKFLOW
    assert "VAULT_REDIS_CONTAINER=vault-redis" in _WORKFLOW
    assert "VAULT_SAME_COMMIT_CI=1" in _WORKFLOW


def test_same_commit_missing_endpoint_is_a_failure(monkeypatch):
    monkeypatch.setenv("VAULT_SAME_COMMIT_CI", "1")
    with pytest.raises(pytest.fail.Exception, match="newly built image"):
        skip_for_older_deployment("endpoint is missing")


def _isolated_pytest(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", *args],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_deliberate_collection_error_is_nonzero(tmp_path):
    broken = tmp_path / "test_broken_collection.py"
    broken.write_text("def test_broken(:\n", encoding="utf-8")

    result = _isolated_pytest("--collect-only", str(broken))

    assert result.returncode != 0
    assert "SyntaxError" in result.stdout + result.stderr


def test_maxfail_stops_before_the_second_test(tmp_path):
    sentinel = tmp_path / "second-test-ran"
    probe = tmp_path / "test_maxfail_probe.py"
    probe.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "",
                "def test_first_failure():",
                "    assert False",
                "",
                "def test_second_must_not_run():",
                f"    Path({str(sentinel)!r}).write_text('ran', encoding='utf-8')",
            ]
        ),
        encoding="utf-8",
    )

    result = _isolated_pytest("--maxfail=1", str(probe))

    assert result.returncode == 1
    assert not sentinel.exists()


def test_same_commit_update_endpoint_compatibility_is_fatal(monkeypatch):
    class MissingEndpoint:
        status_code = 404

    class Admin:
        def get(self, _path):
            return MissingEndpoint()

    monkeypatch.setenv("VAULT_SAME_COMMIT_CI", "1")
    with pytest.raises(pytest.fail.Exception, match="newly built image"):
        update_settings.test_update_status_reports_interval(Admin())


def test_same_commit_redis_outage_cannot_skip_fail_open(monkeypatch):
    monkeypatch.setenv("VAULT_SAME_COMMIT_CI", "1")
    monkeypatch.setattr(login_throttle, "ApiClient", lambda _base_url: object())
    monkeypatch.setattr(
        login_throttle,
        "_hammer_until_429",
        lambda _client, _username, max_attempts: [401] * max_attempts,
    )
    monkeypatch.setattr(login_throttle, "unique", lambda _prefix: "isolated-user")
    monkeypatch.setattr(login_throttle.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        login_throttle.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stderr="", stdout="PONG\n"),
    )
    monkeypatch.setattr(
        login_throttle.requests,
        "get",
        lambda *_args, **_kwargs: SimpleNamespace(
            json=lambda: {"redis": "connected"},
        ),
    )

    with pytest.raises(pytest.fail.Exception, match="failed open"):
        login_throttle.test_login_throttle_survives_redis_outage("http://vault.invalid")


def test_same_commit_zk_storage_probe_failure_is_fatal(monkeypatch):
    """Under same-commit CI the storage probe must FAIL, never skip -- by either route.

    There are two ways it can fail to read the stored blob, and both used to be one. It now looks
    the path up from `files.storage_path` before hashing it, because the blob's filename is no
    longer the row id, so "cannot find where the file is" joined "cannot hash the file" as a
    distinct failure. Both are checked here: this test previously matched one message, and the new
    route reached a different one -- fatal, correctly, but not what the contract asserted.
    """
    monkeypatch.setenv("VAULT_SAME_COMMIT_CI", "1")

    # Route 1: the path lookup itself comes back empty.
    monkeypatch.setattr(
        zk_vault.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stderr="container unavailable",
            stdout="",
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="no storage_path recorded"):
        zk_vault._stored_sha256("vault-id", "file-id")

    # Route 2: the path is known, and hashing it fails. The lookup succeeds, the hash does not.
    calls = {"n": 0}

    def _lookup_then_fail(*_args, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(returncode=0, stdout="some-vault/files/abc", stderr="")
        return SimpleNamespace(returncode=1, stderr="container unavailable", stdout="")

    monkeypatch.setattr(zk_vault.subprocess, "run", _lookup_then_fail)
    with pytest.raises(pytest.fail.Exception, match="could not hash"):
        zk_vault._stored_sha256("vault-id", "file-id")
    assert calls["n"] == 2, "the hash was not attempted after a successful path lookup"


def test_degraded_alert_regression_cleans_only_its_row():
    source = (_ROOT / "tests" / "test_infra_hardening.py").read_text(encoding="utf-8")
    target = source.split(
        "def test_detection_degraded_signal_fires_and_is_throttled():", 1
    )[1].split("def test_alert_dedup_key_is_per_user_and_severity", 1)[0]

    assert "SecurityAlert.id.in_(created)" in target
    assert "filter(SecurityAlert.event_type==SecurityEventType.DETECTION_DEGRADED).delete" not in target


# --- maintenance lines ---------------------------------------------------------------------------
#
# A line `release/X.Y` is a branch that publishes, so a merge into it gets the checks a merge into
# main gets. Release candidates are `candidate/X.Y.Z` and are tested by a manual run only, as before:
# a push-triggered run on a candidate would share its concurrency group with the dispatched one and
# cancel it.


def _github_filter(pattern: str) -> "re.Pattern[str]":
    """A GitHub Actions branch filter as a regular expression.

    The documented syntax: `*` matches within one path segment, `**` across them, `?` and `+` make
    the preceding character (or class) optional or repeated, `[...]` is a character class, and
    everything else is literal -- including `.`.
    """
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        char = pattern[i]
        if char == "*":
            out.append("[^/]*")
        elif char == "[":
            end = pattern.index("]", i)
            out.append(pattern[i:end + 1])
            i = end + 1
            continue
        elif char in "?+":
            out.append(char)
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile("".join(out))


def _branch_filter(workflow: str, event: str) -> list[str]:
    data = yaml.safe_load((_WORKFLOWS / workflow).read_text(encoding="utf-8"))
    triggers = data.get("on", data.get(True))  # YAML 1.1 reads a bare `on` as true
    branches = (triggers.get(event) or {}).get("branches")
    assert isinstance(branches, list) and branches, f"{workflow} {event} has no branch filter"
    return branches


def _fires(branches: list[str], branch: str) -> bool:
    return any(_github_filter(pattern).fullmatch(branch) for pattern in branches)


@pytest.mark.parametrize("workflow, event", [
    ("tests.yml", "push"),
    ("fast-tests.yml", "push"),
    ("codeql.yml", "push"),
    ("codeql.yml", "pull_request"),
    ("image-scan-pr.yml", "pull_request"),
])
def test_ci_gates_maintenance_lines_and_leaves_candidates_to_a_manual_run(workflow, event):
    branches = _branch_filter(workflow, event)

    assert _fires(branches, "main")
    assert _fires(branches, "release/0.33")
    assert _fires(branches, "release/1.0")
    # Candidates, in the new naming and in the one release candidates used before it.
    assert not _fires(branches, "candidate/0.34.0")
    assert not _fires(branches, "release/0.33.0")
    assert not _fires(branches, "release/0.33/extra")


def test_the_filter_reading_matches_githubs_documented_examples():
    """The reader above decides what the parametrized test proves, so it is checked against the
    examples GitHub documents for its filter syntax."""
    assert _github_filter("v[12].[0-9]+.[0-9]+").fullmatch("v2.10.3")
    assert not _github_filter("v[12].[0-9]+.[0-9]+").fullmatch("v3.1.0")
    assert _github_filter("feature/*").fullmatch("feature/my-branch")
    assert not _github_filter("feature/*").fullmatch("feature/your/branch")
    assert _github_filter("feature/**").fullmatch("feature/your/branch")
    assert _github_filter("*").fullmatch("main")
    assert not _github_filter("*").fullmatch("releases/v1")
