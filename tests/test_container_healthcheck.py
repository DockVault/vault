"""The web container's healthcheck program (app/core/healthcheck.py) and where it is wired.

It must fail for exactly two reasons -- /health not answering 2xx, or the SFTP half in this container
reported down -- and pass everything else /health can say, including a degraded database or Redis
(restarting the container would not fix those).
"""

from __future__ import annotations

import ast
import io
import json
import re
import urllib.error
from pathlib import Path

import pytest
import yaml

from app.core import healthcheck

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _opener(body=None, raises=None, seen=None):
    def opener(url, context=None, timeout=None):
        if seen is not None:
            seen.update(url=url, context=context, timeout=timeout)
        if raises is not None:
            raise raises
        return io.BytesIO(json.dumps(body).encode("utf-8"))
    return opener


@pytest.mark.parametrize("sftp, healthy", [
    ("listening", True),
    ("disabled", True),        # a web-only vault
    ("external", True),        # split: another container's SFTP
    ("unresponsive", False),   # this container's SFTP half stopped beating
    ("unreachable", False),    # this container's SFTP half never started
])
def test_the_verdict_follows_the_sftp_half(sftp, healthy):
    body = {"status": "healthy", "database": "connected", "redis": "connected", "sftp": sftp}
    assert healthcheck.main(_opener(body)) == (0 if healthy else 1)


def test_a_degraded_database_still_passes():
    body = {"status": "degraded", "database": "disconnected", "redis": "connected", "sftp": "listening"}
    assert healthcheck.main(_opener(body)) == 0


@pytest.mark.parametrize("error", [
    urllib.error.HTTPError("u", 503, "schema incomplete", {}, None),
    urllib.error.URLError("refused"),
    TimeoutError(),
])
def test_no_2xx_answer_fails(error):
    assert healthcheck.main(_opener(raises=error)) == 1


@pytest.mark.parametrize("https, port, url", [
    ("true", "8000", "https://localhost:8000/health"),
    ("false", "8000", "http://localhost:8000/health"),
    ("false", "9001", "http://localhost:9001/health"),
])
def test_it_asks_where_the_container_serves(monkeypatch, https, port, url):
    monkeypatch.setenv("API_USE_HTTPS", https)
    monkeypatch.setenv("API_PORT", port)
    seen = {}
    healthcheck.main(_opener({"sftp": "listening"}, seen=seen))
    assert seen["url"] == url
    assert (seen["context"] is not None) == (https == "true")


def test_it_imports_only_the_standard_library():
    tree = ast.parse((ROOT / "app" / "core" / "healthcheck.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert names == {"json", "os", "ssl", "sys", "urllib.request"}, names


WEB_SERVICES = {
    "docker-compose.yml": ("vault-api",),                   # split is this file's only layout
    "docker-compose.secure.yml": ("vault", "vault-api"),    # combined, and split's web half
}


def test_the_image_carries_it_and_no_web_service_overrides_it():
    """The web check lives in the image, and every compose file leaves it there.

    A compose file that names the check pins a program to files an operator does not replace when an
    update or a rollback swaps only the image. That is how a rollback to a release without the
    program would run a check the image does not have: the container never turns healthy, and in
    the split layout vault-sftp, which waits on it, never starts. With no override, Docker runs the
    check of the image that is actually there.
    """
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r'^HEALTHCHECK .*\\\n\s+CMD \["python", "-B", "-m", "app\.core\.healthcheck"\]$',
                     dockerfile, re.M)
    for name, web in WEB_SERVICES.items():
        services = yaml.safe_load((ROOT / "deploy" / name).read_text(encoding="utf-8"))["services"]
        image_services = {s for s, v in services.items() if "DOCKVAULT_IMAGE" in str(v.get("image", ""))}
        assert image_services == set(web) | {"vault-sftp"}, (name, sorted(image_services))
        for service in web:
            assert "healthcheck" not in services[service], (
                f"{name}: {service} overrides the image's healthcheck")
        # vault-sftp is the one image service whose check differs from the image's, so it names it.
        assert services["vault-sftp"]["healthcheck"]["test"] == [
            "CMD", "python", "-B", "-m", "app.sftp.heartbeat"], name


def test_the_previous_release_must_turn_healthy_under_the_compose_files_under_test():
    """Scenario I runs the newest published image under this checkout's compose files: the pairing a
    rollback leaves. It must require Docker's verdict, not only an answering /health, because a
    check the older image lacks leaves /health answering and the container short of healthy."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "setup-matrix.yml").read_text(encoding="utf-8"))
    steps = [s for s in wf["jobs"]["scenarios"]["steps"]
             if s.get("name", "").startswith("Scenario I ") and "published release image" in s["name"]]
    assert len(steps) == 1
    run = steps[0]["run"]
    refused = run.index('! grep -q "did NOT report healthy" /tmp/setup-release.log')
    judged = run.index("{{.State.Health.Status}}' vault")
    assert run.index("python3 dockvault.py setup") < refused < judged
    assert 'test "$state" = healthy' in run[judged:]
    assert judged < run.index("/health", judged)       # Docker's verdict, then the answering check


def test_the_setup_matrix_checks_docker_runs_the_images_check():
    """Live: Docker reports the image's program as the combined container's check, and calls the
    container healthy, before the freeze."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "setup-matrix.yml").read_text(encoding="utf-8"))
    steps = [s for s in wf["jobs"]["scenarios"]["steps"] if "frozen SFTP half" in s.get("name", "")]
    assert len(steps) == 1
    run = steps[0]["run"]
    inspected = run.index("{{json .Config.Healthcheck.Test}}")
    assert "*app.core.healthcheck*" in run[inspected:]
    healthy = run.index("{{.State.Health.Status}}")
    assert inspected < healthy < run.index("sig -STOP")


def test_health_reports_degraded_from_the_same_list():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    assert code.count("sftp in SFTP_DOWN") == 1
    assert 'sftp == "unreachable"' not in code
    assert healthcheck.SFTP_DOWN == ("unreachable", "unresponsive")


def test_the_real_deployment_is_frozen_and_thawed_in_the_setup_matrix():
    """The live proof runs on a real combined deployment in the setup matrix (a release gate): the
    SFTP process is stopped, /health must say unresponsive and the healthcheck fail, then both
    must recover after it is continued."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "setup-matrix.yml").read_text(encoding="utf-8"))
    steps = [s for s in wf["jobs"]["scenarios"]["steps"] if "frozen SFTP half" in s.get("name", "")]
    assert len(steps) == 1
    run = steps[0]["run"]
    for needed in ("sig -STOP", "sig -CONT", '--user "$uid"', "= unresponsive", "= listening",
                   "python -B -m app.core.healthcheck", "app.sftp.sftp_server"):
        assert needed in run, needed
    # Frozen, then judged, then thawed -- in that order.
    judged = run.index("= unresponsive")
    thawed = run.index("sig -CONT", judged)
    assert run.index("sig -STOP") < judged < thawed
    assert "trap - EXIT" in run[thawed:]              # the thaw is the real one, not the trap's
