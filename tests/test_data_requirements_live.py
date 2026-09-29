"""Live: the image refuses to start on a database a newer release has marked, and says why.

A release that stores something an older one cannot read writes a row in data_requirements naming
the oldest version that can read the data. This writes such a row into the stack's database, as a
newer release would, and starts the stack's own image in throwaway containers made from the stack's
web and SFTP containers -- same image, command, environment and network -- so the stack itself keeps
serving throughout:

- with the row, both processes refuse to start, and the log names what changed and the undo step;
- with ALLOW_START_ON_NEWER_DATA=true the web process starts, and warns;
- with the row gone, it starts as usual, with no warning.

The row and the containers are removed afterwards, whatever happens.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid

import pytest

from _account_change_helpers import API, DB, psql
from conftest import skip_if_container_absent

pytestmark = [pytest.mark.integration, pytest.mark.docker]

SFTP = os.environ.get("VAULT_SFTP_CONTAINER", "vault-sftp")
_KEY = "test-newer-release-" + uuid.uuid4().hex[:8]
_REASON = "moved audit history into compressed archive blocks"
_UNDO = "run python3 dockvault.py audit unarchive while the newer version is running"
_HEALTH = ("import urllib.request,sys;"
           "sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=5).status==200 "
           "else 1)")


def _docker(*args, timeout=60):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _inspect(name):
    r = _docker("inspect", name)
    if r.returncode != 0 and "No such object" in (r.stderr or ""):
        pytest.skip(f"no {name} container on this host")
    assert r.returncode == 0, r.stderr[:300]
    return json.loads(r.stdout)[0]


class _Probe:
    """A container started from another's image, command, environment and network."""

    def __init__(self, source, *, escape=False):
        info = _inspect(source)
        self.name = f"{source}-marker-probe-{uuid.uuid4().hex[:6]}"
        env = [e for e in info["Config"]["Env"]
               if not e.startswith(("ALLOW_START_ON_NEWER_DATA=", "HOSTNAME="))]
        env.append(f"ALLOW_START_ON_NEWER_DATA={'true' if escape else 'false'}")
        network = next(iter(info["NetworkSettings"]["Networks"]))
        # The environment carries the deployment's secrets, so it goes through a file only this
        # user can read, removed as soon as the container has been created.
        handle, env_file = tempfile.mkstemp(prefix="marker-probe-", suffix=".env")
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write("\n".join(env) + "\n")
            r = _docker("run", "-d", "--name", self.name, "--env-file", env_file,
                        "--network", network, info["Config"]["Image"], *info["Config"]["Cmd"],
                        timeout=120)
        finally:
            os.unlink(env_file)
        assert r.returncode == 0, r.stderr[:300]

    def running(self):
        r = _docker("inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", self.name)
        assert r.returncode == 0, r.stderr[:300]
        state, code = r.stdout.split()
        return state == "true", int(code)

    def logs(self):
        r = _docker("logs", self.name, timeout=60)
        return (r.stdout or "") + (r.stderr or "")

    def wait_for_exit(self, deadline=150):
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            running, code = self.running()
            if not running:
                return code
            time.sleep(2)
        pytest.fail(f"{self.name} was still running after {deadline}s:\n{self.logs()[-2000:]}")

    def wait_for_health(self, deadline=180):
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            running, code = self.running()
            assert running, f"{self.name} exited with {code}:\n{self.logs()[-3000:]}"
            if _docker("exec", self.name, "python", "-c", _HEALTH).returncode == 0:
                return
            time.sleep(3)
        pytest.fail(f"{self.name} never became healthy:\n{self.logs()[-3000:]}")

    def remove(self):
        _docker("rm", "-f", self.name)


@pytest.fixture
def probes():
    started = []

    def start(source, **kw):
        probe = _Probe(source, **kw)
        started.append(probe)
        return probe

    yield start
    for probe in started:
        probe.remove()


@pytest.fixture
def mark():
    r = _docker("exec", DB, "true")
    skip_if_container_absent(r, DB)
    if psql("SELECT to_regclass('public.data_requirements') IS NOT NULL") != "t":
        pytest.fail("the stack's image did not create data_requirements at start")
    psql("INSERT INTO data_requirements (key, requires_at_least, reason, undo) VALUES "
         f"('{_KEY}', '999.0.0', '{_REASON}', '{_UNDO}')")
    try:
        yield
    finally:
        psql(f"DELETE FROM data_requirements WHERE key = '{_KEY}'")


def test_the_web_process_refuses_to_start_and_says_how_to_undo_it(mark, probes):
    probe = probes(API)

    code = probe.wait_for_exit()

    logs = probe.logs()
    assert code != 0
    assert "[web] DockVault" in logs and "will not start" in logs
    assert f"Needs DockVault 999.0.0 or later ({_KEY}): {_REASON}" in logs
    assert f"first undo it with the newer version: {_UNDO}" in logs
    assert "ALLOW_START_ON_NEWER_DATA=true" in logs
    assert "Database initialized" not in logs, "the refusal came after the database was touched"


def test_the_sftp_process_refuses_to_start_too(mark, probes):
    probe = probes(SFTP)

    code = probe.wait_for_exit()

    logs = probe.logs()
    assert code != 0
    assert "[sftp] DockVault" in logs and "will not start" in logs
    assert f"({_KEY}): {_REASON}" in logs


def test_the_escape_starts_the_web_process_with_a_warning(mark, probes):
    probe = probes(API, escape=True)

    probe.wait_for_health()

    logs = probe.logs()
    assert "WARNING: ALLOW_START_ON_NEWER_DATA is set, so DockVault" in logs
    assert f"WARNING: - Needs DockVault 999.0.0 or later ({_KEY})" in logs
    # It is starting, with the setting already in place: not a refusal, not how to set it.
    assert "will not start" not in logs
    assert "To start this version anyway" not in logs


def test_with_no_mark_the_web_process_starts_as_usual(probes):
    r = _docker("exec", DB, "true")
    skip_if_container_absent(r, DB)
    assert psql("SELECT count(*) FROM data_requirements WHERE requires_at_least = '999.0.0'") == "0"
    probe = probes(API)

    probe.wait_for_health()

    logs = probe.logs()
    assert "will not start" not in logs
    assert "ALLOW_START_ON_NEWER_DATA" not in logs
