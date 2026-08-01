"""Unit tests for the subsystem checks behind the unauthenticated ``/health`` endpoint.

These run without a live instance: the checks are pure functions over the environment, the
settings, and a loopback socket.

The SFTP check is the interesting one. ``RUN_SFTP`` and a loopback probe answer different
questions — "does this DEPLOYMENT serve SFTP" versus "does THIS CONTAINER" — and the split
profile is where they diverge: ``vault-api`` runs an api-only command while SFTP lives in its own
container, yet ``RUN_SFTP`` still arrives from the shared ``.env``. Reading the first and acting
on the second made every split deployment report itself permanently degraded.
"""
import importlib.util
import socket
from pathlib import Path

import pytest

from app.core.health import (
    SFTP_IN_CONTAINER_ENV,
    check_sftp_status,
    check_storage_status,
)

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_combined_mod", _ROOT / "run_combined.py")
run_combined = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_combined)


@pytest.fixture(autouse=True)
def _clean_sftp_env(monkeypatch):
    """Neither variable may leak in from the host running the suite."""
    monkeypatch.delenv("RUN_SFTP", raising=False)
    monkeypatch.delenv(SFTP_IN_CONTAINER_ENV, raising=False)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_web_only_deployment_is_disabled_not_broken(monkeypatch):
    # A vault that was never meant to serve SFTP is healthy; collapsing this into "unreachable"
    # would make every web-only deployment look degraded.
    assert check_sftp_status() == "disabled"
    monkeypatch.setenv("RUN_SFTP", "0")
    assert check_sftp_status() == "disabled"


def test_split_deployment_declines_to_answer_for_another_container(monkeypatch):
    # THE REGRESSION GUARD. RUN_SFTP is set (the deployment does serve SFTP) but this process is
    # not the one serving it. Probing loopback here finds nothing, and calling that "unreachable"
    # reported a subsystem this container was never asked to run as broken.
    monkeypatch.setenv("RUN_SFTP", "1")
    status = check_sftp_status()
    assert status == "external"
    assert status != "unreachable", "a split deployment must not report itself broken"


def test_combined_deployment_reports_a_live_listener(monkeypatch):
    monkeypatch.setenv("RUN_SFTP", "1")
    monkeypatch.setenv(SFTP_IN_CONTAINER_ENV, "1")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        monkeypatch.setattr(
            "app.core.health.settings.sftp_port", listener.getsockname()[1], raising=False
        )
        assert check_sftp_status() == "listening"


def test_combined_deployment_reports_a_dead_listener(monkeypatch):
    # The case the check exists for: SFTP was meant to run HERE and is not answering.
    monkeypatch.setenv("RUN_SFTP", "1")
    monkeypatch.setenv(SFTP_IN_CONTAINER_ENV, "1")
    monkeypatch.setattr("app.core.health.settings.sftp_port", _free_port(), raising=False)
    assert check_sftp_status() == "unreachable"


def test_only_the_combined_launcher_claims_sftp(monkeypatch):
    # run_combined.py is the one launcher that serves both halves from a single container, so it
    # is the only place the marker may be set — and only when SFTP is actually being started.
    monkeypatch.delenv("RUN_SFTP", raising=False)
    assert run_combined.mark_sftp_in_container() is False
    assert SFTP_IN_CONTAINER_ENV not in run_combined.os.environ

    monkeypatch.setenv("RUN_SFTP", "1")
    assert run_combined.mark_sftp_in_container() is True
    assert run_combined.os.environ[SFTP_IN_CONTAINER_ENV] == "1"
    assert check_sftp_status() != "external", "the combined launcher must own the probe"


def test_storage_probe_writes_and_cleans_up(monkeypatch, tmp_path):
    monkeypatch.setattr("app.core.health.settings.file_storage_path", str(tmp_path), raising=False)
    assert check_storage_status() == "writable"
    assert list(tmp_path.iterdir()) == [], "the probe file must not be left behind"


def test_storage_probe_reports_an_unwritable_root(monkeypatch, tmp_path):
    # A path that cannot be created (a file where the directory should be) stands in for the real
    # failures this catches: a full disk and a volume that mounted read-only.
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"")
    monkeypatch.setattr(
        "app.core.health.settings.file_storage_path", str(blocker / "storage"), raising=False
    )
    assert check_storage_status() == "unwritable"
