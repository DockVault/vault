"""Offline checks for the full-suite workflow's failure semantics."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import test_api_update_settings as update_settings
import test_login_throttle as login_throttle
import test_zk_vault as zk_vault

import pytest

from conftest import skip_for_older_deployment


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_WORKFLOW = (_ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
_FAST_WORKFLOW = (_ROOT / ".github" / "workflows" / "fast-tests.yml").read_text(
    encoding="utf-8"
)
_PREFLIGHT = (_ROOT / ".github" / "workflows" / "preflight.yml").read_text(encoding="utf-8")


def _step(name: str, next_name: str) -> str:
    return _WORKFLOW.split(f"- name: {name}", 1)[1].split(f"- name: {next_name}", 1)[0]


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
        (_WORKFLOW, "python -m pytest --maxfail=1 --junitxml=pytest-results.xml"),
    ],
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
    monkeypatch.setenv("VAULT_SAME_COMMIT_CI", "1")
    monkeypatch.setattr(
        zk_vault.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stderr="container unavailable",
            stdout="",
        ),
    )

    with pytest.raises(pytest.fail.Exception, match="could not hash"):
        zk_vault._stored_sha256("vault-id", "file-id")


def test_degraded_alert_regression_cleans_only_its_row():
    source = (_ROOT / "tests" / "test_infra_hardening.py").read_text(encoding="utf-8")
    target = source.split(
        "def test_detection_degraded_signal_fires_and_is_throttled():", 1
    )[1].split("def test_alert_dedup_key_is_per_user_and_severity", 1)[0]

    assert "SecurityAlert.id.in_(created)" in target
    assert "filter(SecurityAlert.event_type==SecurityEventType.DETECTION_DEGRADED).delete" not in target
