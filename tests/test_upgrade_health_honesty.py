"""What a deployment reports when something about it is broken.

There is no migration framework: a list of idempotent DDL statements is replayed at every boot, and
each step is wrapped so one failure cannot stop the rest. That is deliberate and right -- a step
that does not apply is usually one that already applied.

What is missing is a way for a failure to reach anyone. The step prints and is forgotten, and the
three things that could report it cannot:

  * `/health` returns a bare dict, so FastAPI answers **200 even when the body says `degraded`**;
  * the container healthcheck only asks whether that page loads, never what it said;
  * `dockvault.py`'s health-wait reads Docker's verdict, which came from the healthcheck.

So a vault whose database is gone already passes all three today -- this is not specific to a failed
migration. Each link is recorded separately below, because they are one chain: making `/health`
answer non-2xx when it calls itself degraded breaks it at the first link and reaches the other two
for free. A fix that only records failures, or only teaches the updater to look, changes nothing.

The codebase already contains the exception that proves the rule. `_verify_retired_object_id_triggers`
runs OUTSIDE the swallowing loop and raises, refusing to serve when the triggers that record retired
object ids are missing -- because a deployment must not advertise a property it does not have. That
is the in-repo precedent for what honest health looks like, and the pattern to generalise.

These are CHARACTERIZATION tests: they record the above so the phase that makes health honest
visibly flips them. A failure here means health has learned to report a problem, and each assertion
carries the message saying so.
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
def test_a_failed_migration_step_is_printed_and_recorded_nowhere():
    """The swallow, and the absence of anything durable beside it.

    Continuing past a failed step is correct and is not what this records. What it records is that
    nothing survives the print -- no table, no flag, nothing a later request could consult.
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

    assert "print(" in handler, "the failure is no longer even printed"
    for durable in ("schema_state", "INSERT", "UPDATE ", "commit(", "raise", "record"):
        assert durable not in handler, (
            "the failure handler now does something durable (%r); if it records failed steps, "
            "this characterization is obsolete and health should be asserting on that record"
            % durable)

    # The counterexample, pinned so it cannot quietly disappear: one check DOES refuse to serve.
    # It is the precedent a general fix should follow, not an inconsistency to remove.
    hard_stop = ast.get_source_segment(source, _node(source, "_verify_retired_object_id_triggers"))
    assert "raise RuntimeError" in hard_stop, (
        "the retired-object-id check no longer hard-stops; the codebase has lost its one example "
        "of a boot-time schema problem being treated as fatal")


@pytest.mark.unit
def test_health_answers_200_even_when_it_calls_itself_degraded():
    """The first link, and the one worth fixing: the endpoint has no way to fail.

    It already computes `degraded` -- for a dead database, dead Redis, unreachable SFTP or
    unwritable storage -- and then returns it as a field of an ordinary dict. FastAPI serialises
    that with a 200, so the summary is advisory text nobody downstream is able to act on.
    """
    source = API.read_text(encoding="utf-8")
    health = _node(source, "health_check")
    text = ast.get_source_segment(source, health)

    assert "degraded" in text, "the endpoint no longer computes a degraded state"

    # Through the parser: the value returned is a dict literal, not a Response carrying a status.
    returns = [n for n in ast.walk(health) if isinstance(n, ast.Return) and n.value is not None]
    assert returns, "the endpoint no longer returns anything"
    for ret in returns:
        assert isinstance(ret.value, ast.Dict), (
            "/health now returns %s rather than a plain dict; if it can answer non-2xx, this "
            "characterization is obsolete and the whole chain below it is fixed"
            % type(ret.value).__name__)
    for signals_failure in ("status_code", "JSONResponse", "HTTPException", "Response("):
        assert signals_failure not in text, (
            "/health now uses %r; if it can answer non-2xx, this characterization is obsolete"
            % signals_failure)


@pytest.mark.unit
def test_the_container_healthcheck_only_asks_whether_the_page_loads():
    """The second link. It calls the endpoint and discards the answer.

    `urlopen` raises on a non-2xx, so this link needs no change at all once `/health` can answer
    one -- which is why fixing the endpoint is worth more than fixing anything downstream of it.
    """
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    lines = dockerfile.splitlines()
    index = next((i for i, line in enumerate(lines) if line.startswith("HEALTHCHECK")), None)
    assert index is not None, "the image no longer declares a healthcheck"
    command = " ".join(lines[index:index + 3])

    assert "urlopen" in command and "/health" in command, (
        "the healthcheck no longer fetches /health; this test's premise has changed")
    for reads_the_answer in (".read()", "json", "loads", "degraded", "getcode"):
        assert reads_the_answer not in command, (
            "the healthcheck now inspects the response (%r); if it fails on a degraded vault, "
            "this characterization is obsolete" % reads_the_answer)


@pytest.mark.unit
def test_the_updaters_health_wait_returns_true_on_dockers_word_alone(tmp_path, monkeypatch):
    """The third link, driven rather than described.

    With no vault behind it at all -- nothing is running, nothing is asked -- the tool reports the
    deployment healthy, because `docker inspect` said so. That is the whole of its evidence.
    """
    asked = []

    def fake_run(cmd, *args, **kwargs):
        asked.append(cmd)
        return argparse.Namespace(returncode=0, stdout="healthy\n", stderr="")

    def no_network(*args, **kwargs):
        raise AssertionError(
            "the health-wait reached the network. That is the fix this test characterizes the "
            "absence of, so this is the expected way for it to flip -- but assert here rather "
            "than letting it happen: the wait retries 40 times, and a real connection attempt to "
            "a port nothing is listening on turns a two-second failure into a several-minute one")

    monkeypatch.setattr(dv.subprocess, "run", fake_run)
    monkeypatch.setattr("urllib.request.urlopen", no_network)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    assert tool._wait_secure_healthy("combined") is True, (
        "the health-wait no longer accepts Docker's verdict on its own; if it now consults the "
        "vault, this characterization is obsolete")

    assert asked, "the wait returned without asking anything"
    assert all(cmd[:2] == ["docker", "inspect"] for cmd in asked), (
        "the health-wait now runs something other than docker inspect: %r" % (asked,))
    assert any("State.Health.Status" in part for cmd in asked for part in cmd), (
        "the health-wait no longer reads Docker's health status")

    # And the tool has no other way of knowing: its only HTTP client asks GitHub for release tags.
    source = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    wait = ast.get_source_segment(source, _node(source, "_wait_secure_healthy"))
    for asks_the_vault in ("urlopen", "requests.", "urllib"):
        assert asks_the_vault not in wait, (
            "the health-wait now speaks to the vault directly (%r); this characterization is "
            "obsolete" % asks_the_vault)


@pytest.mark.integration
def test_the_live_health_body_has_no_field_for_a_schema_problem(base_url):
    """The wire contract, so the chain above is not only a reading of source.

    Scoped deliberately narrowly. It CANNOT show the 200-while-degraded behaviour, because it has
    no way to degrade the deployment it is pointed at -- and a healthy vault answers 200 both
    before and after the fix, so asserting on the status code here would record nothing. The proof
    that a degraded body still comes back 200 is the parser-level one above, which is conclusive:
    the endpoint's only return is a dict literal.

    What this pins is the shape of the answer: five fields from a fixed vocabulary, none of which
    can say the schema is incomplete. Adding one flips it.
    """
    response = requests.get("%s/health" % base_url, timeout=10)
    body = response.json()
    assert set(body) == {"status", "database", "redis", "sftp", "storage"}, (
        "/health now reports %s; if one of those fields can report an incomplete schema, this "
        "characterization is obsolete" % sorted(body))
    assert body["status"] in ("healthy", "degraded")
