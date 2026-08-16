"""What a deployment reports when part of its schema did not apply.

There is no migration framework: a list of idempotent DDL statements is replayed at every boot, and
each step is wrapped so one failure cannot stop the rest. That is deliberate and right -- a step
that does not apply is usually one that already applied, and refusing to boot over it would strand
a self-hosted vault in the middle of an unattended update.

What used to be missing was any way for a failure to reach anyone. The step printed and the boot
carried on; `/health` returned a bare dict so FastAPI answered 200 whatever the body said; the
container healthcheck only asked whether that page loaded; and the host tool's health-wait read
Docker's verdict, which came from that healthcheck. A vault missing a column reported itself well
until an endpoint that needed the column returned a 500.

Each step now records its outcome, and `/health` answers **503** when any of them failed. The two
links below it did not have to change: the healthcheck calls the endpoint with `urlopen`, which
raises on a non-2xx, so Docker marks the container unhealthy and the tool waiting on Docker sees
it. That is why the endpoint was the right place to fix.

Half of this file asserts the fixed behaviour. The rest is still CHARACTERIZATION -- the two
downstream links are recorded as they are, because they are load-bearing in the chain above and a
change to either would silently break the signal.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
from pathlib import Path

import pytest
import requests

pytestmark = pytest.mark.characterization

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"

_spec = importlib.util.spec_from_file_location("dockvault_mod_health", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


def _node(source, name, kinds=(ast.FunctionDef, ast.AsyncFunctionDef)):
    """The AST node for a named function, found through the parser rather than by index.

    An earlier version of this file sliced a fixed character count after the first `except` it
    found. That is the same shape of false positive the sibling file already hit once: it silently
    reads the wrong region when the code moves, and passes.
    """
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, kinds) and getattr(node, "name", None) == name:
            return node
    raise AssertionError("%s is no longer defined; this test's premise has changed" % name)


@pytest.mark.unit
def test_a_failed_migration_step_is_recorded_and_not_only_printed():
    """The swallow stays -- one bad statement must not brick a boot -- but it leaves a trace now.

    Both halves matter. Continuing past the failure is correct and is asserted here so a later
    change cannot quietly turn a bad statement into a failed boot. Recording it is what lets
    anything downstream know.
    """
    source = API.read_text(encoding="utf-8")
    replay = ast.get_source_segment(source, _node(source, "_run_lightweight_migrations"))
    assert "for stmt in statements:" in replay, "the replay loop has moved"

    handler = None
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ExceptHandler):
            text = ast.get_source_segment(source, node) or ""
            if "Migration step skipped" in text:
                handler = text
                break
    assert handler, "the per-step failure handler has gone or stopped naming itself"

    assert "OUTCOME_FAILED" in handler, (
        "a failed step is no longer recorded, so /health has nothing to consult and a deployment "
        "with an incomplete schema is silent again")
    assert "raise" not in handler, (
        "the handler now re-raises, so one bad statement brings the boot down. That was the "
        "behaviour this deliberately avoided")


@pytest.mark.unit
def test_health_answers_503_when_the_schema_is_incomplete():
    """The link that carries the signal outward.

    Asserted through the parser rather than by string match: what matters is that the endpoint can
    return something other than a bare dict, and on which condition.
    """
    source = API.read_text(encoding="utf-8")
    health = _node(source, "health_check")
    text = ast.get_source_segment(source, health)

    assert "check_schema_state" in text, "/health no longer consults the recorded schema state"
    assert '"schema"' in text, "/health no longer reports a schema field"

    returns = [n for n in ast.walk(health) if isinstance(n, ast.Return) and n.value is not None]
    assert any(isinstance(r.value, ast.Call) and getattr(r.value.func, "id", "") == "JSONResponse"
               for r in returns), (
        "/health has no JSONResponse return, so it cannot answer non-2xx and the container "
        "healthcheck below it can never fail")
    assert "503" in text, "/health no longer answers 503 on any condition"

    # The asymmetry is deliberate and worth pinning: a dead database or Redis still answers 200,
    # because those recover without the container being replaced and a 503 would have Docker
    # restart a vault that was about to come back.
    assert 'schema == "incomplete"' in text, (
        "the 503 is no longer conditional on the schema specifically. If every degraded state now "
        "answers non-2xx, that is a much larger behaviour change: a transient Redis outage would "
        "fail an upgrade's health-wait and restart a working container")


@pytest.mark.unit
def test_the_container_healthcheck_only_asks_whether_the_page_loads():
    """CHARACTERIZATION, and load-bearing exactly as it is.

    `urlopen` raises on a non-2xx, so this link needs no logic of its own to carry the 503 above --
    which is why fixing the endpoint reached Docker for free. Recorded so that a well-meant change
    here (parsing the body, tolerating errors) cannot quietly break the chain.
    """
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    lines = dockerfile.splitlines()
    index = next((i for i, line in enumerate(lines) if line.startswith("HEALTHCHECK")), None)
    assert index is not None, "the image no longer declares a healthcheck"
    command = " ".join(lines[index:index + 3])

    assert "urlopen" in command and "/health" in command, (
        "the healthcheck no longer fetches /health, so a 503 from it reaches nothing")
    for tolerates_failure in ("try:", "except", "|| true"):
        assert tolerates_failure not in command, (
            "the healthcheck now swallows an error (%r), which breaks the only thing carrying an "
            "incomplete schema out to Docker" % tolerates_failure)


@pytest.mark.unit
def test_the_updaters_health_wait_reads_dockers_verdict(tmp_path, monkeypatch):
    """CHARACTERIZATION of the third link, driven rather than described.

    The tool trusts `docker inspect` alone, which is correct now that Docker's verdict reflects the
    endpoint. Recorded because it means the tool needs no schema knowledge of its own -- and if it
    ever grows some, this should be revisited rather than duplicated.
    """
    asked = []

    def fake_run(cmd, *args, **kwargs):
        asked.append(cmd)
        return argparse.Namespace(returncode=0, stdout="healthy\n", stderr="")

    def no_network(*args, **kwargs):
        raise AssertionError(
            "the health-wait reached the network. If it now asks the vault directly, revisit this "
            "test -- but assert rather than allow it: the wait retries 40 times, and a real "
            "connection attempt to a dead port turns a two-second failure into a several-minute "
            "one")

    monkeypatch.setattr(dv.subprocess, "run", fake_run)
    monkeypatch.setattr("urllib.request.urlopen", no_network)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    assert tool._wait_secure_healthy("combined") is True
    assert asked, "the wait returned without asking anything"
    assert all(cmd[:2] == ["docker", "inspect"] for cmd in asked), (
        "the health-wait now runs something other than docker inspect: %r" % (asked,))
    assert any("State.Health.Status" in part for cmd in asked for part in cmd), (
        "the health-wait no longer reads Docker's health status, which is what carries the "
        "endpoint's verdict to it")


@pytest.mark.integration
def test_the_live_health_body_reports_a_schema_state(base_url):
    """The wire contract on a running deployment.

    A healthy vault answers 200 both before and after this change, so the status code is not what
    is pinned here -- the parser-level assertion above covers that. What this pins is that the
    field exists and holds one of the four words, on a real deployment rather than in source.
    """
    response = requests.get("%s/health" % base_url, timeout=10)
    body = response.json()
    assert set(body) == {"status", "database", "redis", "sftp", "storage", "schema"}, (
        "/health now reports %s" % sorted(body))
    assert body["schema"] in ("complete", "incomplete", "partial", "unknown")
    if body["schema"] == "incomplete":
        assert response.status_code == 503, (
            "the deployment reports an incomplete schema but still answers 200, so nothing "
            "downstream can act on it")
    else:
        assert response.status_code == 200
