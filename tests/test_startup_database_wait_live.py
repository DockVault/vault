"""Live: a vault started before its database waits for it, without exiting or being restarted.

After a host restarts, Docker starts the vault and its database together, whatever compose's
depends_on says. The start-up check connected once; a database that did not answer stopped the
process, the one-container launcher stopped the container, and Docker started it again. This starts
the stack's own image in throwaway containers, made from the stack's web container (same image,
environment and network), each with a throwaway database of its own and Docker's restart policy:

- the one-container shape (web and SFTP), with its database created but not yet started (no name to
  reach), started twelve seconds later;
- the one-container shape again, with its database stopped (no name to reach) and started about
  ninety seconds later, after the launcher's old one-minute wait for the web app: SFTP must start
  only once the web app's start is done;
- the SFTP process alone, with its database's server process stopped (SIGSTOP), so a connection is
  accepted and then times out, as it did after a host restart ("timeout expired"); continued
  (SIGCONT) fifteen seconds later.

Each must start and serve without exiting: Docker's restart count stays 0. And one start that must not
wait: the SFTP process alone, given no database password where the database asks for one, stops at
once. The stack itself, its
database included, is not touched. Every container made here is removed with its anonymous volumes.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

import pytest

from _account_change_helpers import API, DB
from conftest import skip_if_container_absent

pytestmark = [pytest.mark.integration, pytest.mark.docker]

_HEALTH = ("import urllib.request,sys;"
           "sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=5).status==200 "
           "else 1)")
_SSH_BANNER = ("import socket,sys;s=socket.create_connection(('127.0.0.1',2222),timeout=5);"
               "sys.exit(0 if s.recv(64).startswith(b'SSH-2.0-') else 1)")


def _docker(*args, timeout=60):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _inspect(name):
    r = _docker("inspect", name)
    if r.returncode != 0 and "No such object" in (r.stderr or ""):
        pytest.skip(f"no {name} container on this host")
    assert r.returncode == 0, r.stderr[:300]
    return json.loads(r.stdout)[0]


def _env_file(lines):
    """The environment carries the deployment's secrets: a file only this user reads, removed by the
    caller as soon as the container is made."""
    handle, path = tempfile.mkstemp(prefix="db-wait-", suffix=".env")
    with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(lines) + "\n")
    return path


class _Pair:
    """A throwaway database, and a vault from the stack's image pointed at it."""

    def __init__(self):
        r = _docker("exec", API, "true")
        skip_if_container_absent(r, API)
        self.api, self.db = _inspect(API), _inspect(DB)
        self.network = next(iter(self.api["NetworkSettings"]["Networks"]))
        tag = uuid.uuid4().hex[:6]
        self.db_name = f"{DB}-wait-probe-{tag}"
        self.vault_name = f"{API}-wait-probe-{tag}"
        self.made = []

    def create_database(self):
        keep = ("POSTGRES_USER=", "POSTGRES_PASSWORD=", "POSTGRES_DB=")
        env = _env_file([e for e in self.db["Config"]["Env"] if e.startswith(keep)])
        try:
            r = _docker("create", "--name", self.db_name, "--env-file", env,
                        "--network", self.network, self.db["Config"]["Image"], timeout=120)
        finally:
            os.unlink(env)
        assert r.returncode == 0, r.stderr[:300]
        self.made.append(self.db_name)

    def start_database(self):
        r = _docker("start", self.db_name)
        assert r.returncode == 0, r.stderr[:300]

    def wait_database_ready(self, deadline=90):
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            if _docker("exec", self.db_name, "pg_isready", "-h", "127.0.0.1", "-U", "sftp_user", "-d", "sftp_db").returncode == 0:
                return
            time.sleep(2)
        pytest.fail("the throwaway database never became ready")

    def run_vault(self, *command, extra_env=(), restart="unless-stopped", with_password=True):
        env = []
        replaced = tuple(entry.split("=", 1)[0] + "=" for entry in extra_env)
        for entry in self.api["Config"]["Env"]:
            if entry.startswith(("HOSTNAME=", "PGPASSWORD=", *replaced)):
                continue
            if entry.startswith("DATABASE_URL="):
                url = urlsplit(entry.split("=", 1)[1])
                credentials, _, hostport = url.netloc.rpartition("@")
                if not with_password:
                    credentials = credentials.partition(":")[0]
                port = hostport.rpartition(":")[2] if ":" in hostport else "5432"
                entry = "DATABASE_URL=" + urlunsplit(
                    url._replace(netloc=f"{credentials}@{self.db_name}:{port}"))
            env.append(entry)
        env.extend(extra_env)
        path = _env_file(env)
        try:
            r = _docker("run", "-d", "--name", self.vault_name, "--restart", restart,
                        "--env-file", path, "--network", self.network, self.api["Config"]["Image"],
                        *command, timeout=120)
        finally:
            os.unlink(path)
        assert r.returncode == 0, r.stderr[:300]
        self.made.append(self.vault_name)
        self.started_at = self.state()["StartedAt"]

    def state(self):
        info = _inspect(self.vault_name)
        return {**info["State"], "RestartCount": info["RestartCount"]}

    def logs(self):
        r = _docker("logs", self.vault_name, timeout=60)
        return (r.stdout or "") + (r.stderr or "")

    def launcher_lines(self):
        """The one-container launcher's output, in order: it passes on every line of both
        processes, each tagged with the process's name, on its own standard output."""
        r = _docker("logs", self.vault_name, timeout=60)
        return (r.stdout or "").splitlines()

    def assert_never_restarted(self):
        state = self.state()
        assert state["RestartCount"] == 0 and state["StartedAt"] == self.started_at, (
            f"the vault stopped and Docker started it again (restarts: {state['RestartCount']}):\n"
            + self.logs()[-3000:])
        assert state["Running"], f"the vault is not running:\n{self.logs()[-3000:]}"

    def wait_inside(self, script, deadline, what):
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            self.assert_never_restarted()
            if _docker("exec", self.vault_name, "python", "-c", script).returncode == 0:
                return
            time.sleep(3)
        pytest.fail(f"the vault never {what}:\n{self.logs()[-3000:]}")

    def remove(self):
        for name in reversed(self.made):
            _docker("rm", "-fv", name)


@pytest.fixture
def pair():
    p = _Pair()
    try:
        yield p
    finally:
        p.remove()


def test_the_one_container_vault_waits_for_a_database_that_starts_after_it(pair):
    pair.create_database()                               # made, not started: no name to reach yet
    pair.run_vault("python", "run_combined.py", extra_env=["RUN_SFTP=true"])

    time.sleep(12)
    pair.assert_never_restarted()
    assert "The database cannot be reached yet" in pair.logs(), pair.logs()[-3000:]

    pair.start_database()
    pair.wait_inside(_HEALTH, 180, "served the web app")
    pair.wait_inside(_SSH_BANNER, 120, "served SFTP")
    pair.assert_never_restarted()
    logs = pair.logs()
    assert "The database answered after" in logs
    assert "exited with code" not in logs and "Traceback" not in logs, logs[-3000:]


def test_in_one_container_sftp_starts_only_after_a_web_start_that_waited_long(pair):
    """A database that answers about ninety seconds after the vault started: after the launcher's
    old one-minute wait for the web app, within the web app's own wait for its database. SFTP must
    start only once the web app's start, its schema step included, is done."""
    pair.create_database()
    pair.start_database()
    pair.wait_database_ready()            # initialised now, so its later start is quick
    assert _docker("stop", pair.db_name).returncode == 0     # stopped: no name to reach
    pair.run_vault("python", "run_combined.py", extra_env=["RUN_SFTP=true", "LOG_LEVEL=INFO"])

    end = time.monotonic() + 90
    while time.monotonic() < end:
        pair.assert_never_restarted()
        time.sleep(5)
    lines = pair.launcher_lines()
    assert any(line.startswith("[web] The database cannot be reached yet") for line in lines), lines[-40:]
    assert not any(line.startswith("[sftp]") for line in lines), (
        "SFTP started while the web app was still waiting for its database:\n" + "\n".join(lines[-40:]))

    pair.start_database()
    pair.wait_inside(_HEALTH, 120, "served the web app")
    pair.wait_inside(_SSH_BANNER, 120, "served SFTP")
    pair.assert_never_restarted()
    lines = pair.launcher_lines()
    text = "\n".join(lines[-60:])
    assert not any("starting SFTP anyway" in line for line in lines), text
    web_ready = next(i for i, line in enumerate(lines)
                     if line.startswith("[web]") and "Application startup complete" in line)
    first_sftp = next(i for i, line in enumerate(lines) if line.startswith("[sftp]"))
    assert any(line.startswith("[web] The database answered after") for line in lines[:web_ready]), text
    assert first_sftp > web_ready, "SFTP started before the web app's start was done:\n" + text
    logs = pair.logs()
    assert "exited with code" not in logs and "Traceback" not in logs, logs[-3000:]


def test_the_sftp_process_waits_for_a_database_that_does_not_answer_yet(pair):
    pair.create_database()
    pair.start_database()
    pair.wait_database_ready()
    # Stopped, not removed: the connection is accepted by the kernel and never answered.
    assert _docker("kill", "--signal", "STOP", pair.db_name).returncode == 0
    try:
        pair.run_vault("python", "-m", "app.sftp.sftp_server")
        time.sleep(15)
        pair.assert_never_restarted()
        assert "The database cannot be reached yet (timeout expired)" in pair.logs(), pair.logs()[-3000:]
    finally:
        _docker("kill", "--signal", "CONT", pair.db_name)
    pair.wait_inside(_SSH_BANNER, 90, "served SFTP")
    pair.assert_never_restarted()
    assert "[sftp] The database answered after" in pair.logs()


def test_a_start_the_client_library_cannot_make_stops_at_once(pair):
    """No password given, where the database asks for one: the client library refuses the connection
    itself, without a word from the server. That is not a database that cannot be reached yet, so it
    is not waited for: the start stops at once, with the library's own words."""
    pair.create_database()
    pair.start_database()
    pair.wait_database_ready()
    pair.run_vault("python", "-m", "app.sftp.sftp_server", restart="no", with_password=False)
    end = time.monotonic() + 60
    while time.monotonic() < end and pair.state()["Running"]:
        time.sleep(1)
    info = _inspect(pair.vault_name)
    state = info["State"]
    logs = pair.logs()
    assert not state["Running"], "the start is still waiting:\n" + logs[-3000:]
    assert state["ExitCode"] != 0, logs[-3000:]
    assert "fe_sendauth: no password supplied" in logs, logs[-3000:]
    assert "cannot be reached yet" not in logs, logs[-3000:]
    started = _docker_time(state["StartedAt"])
    finished = _docker_time(state["FinishedAt"])
    assert finished - started < 30, f"the start took {finished - started:.0f} s to stop"


def _docker_time(text):
    """Seconds since the epoch of one of Docker's RFC 3339 times (nanoseconds, 'Z')."""
    from datetime import datetime
    head, _, fraction = text.rstrip("Z").partition(".")
    return datetime.fromisoformat(f"{head}.{(fraction + '000000')[:6]}+00:00").timestamp()
