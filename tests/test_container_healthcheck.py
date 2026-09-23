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


def test_every_web_container_runs_it_and_the_sftp_container_keeps_its_own():
    argv = ["CMD", "python", "-B", "-m", "app.core.healthcheck"]
    services = yaml.safe_load((ROOT / "deploy" / "docker-compose.secure.yml").read_text(encoding="utf-8"))["services"]
    assert services["vault"]["healthcheck"]["test"] == argv          # combined
    assert services["vault-api"]["healthcheck"]["test"] == argv      # split, web half
    assert services["vault-sftp"]["healthcheck"]["test"] == ["CMD", "python", "-B", "-m", "app.sftp.heartbeat"]
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r'^HEALTHCHECK .*\\\n\s+CMD \["python", "-B", "-m", "app\.core\.healthcheck"\]$',
                     dockerfile, re.M)


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
