"""configured_int_setting (tests/conftest.py): the setting a running deployment has, asked of its container
with `docker exec`. Three live modules ask it while they are collected, so it runs in every lane, the offline
one too. On a machine whose docker command is there but whose engine does not answer, that collection hung or
failed, and on Windows a docker process killed with its output on a pipe could still block the read after it.

What must hold, with Docker replaced by stand-ins that answer at once:
  * no docker command: the setting is unreadable (None), as before;
  * an engine that does not answer: the module is skipped, saying why, and the engine is asked once a run;
  * an engine that answers and a container that does not: the test fails (a stuck stack never passes green);
  * nothing is read from a pipe: the output goes to a file, and a command that hangs is killed.
"""
import shutil
import subprocess

import pytest

import conftest

pytestmark = pytest.mark.unit

DOCKER = "/usr/local/bin/docker"


class _Docker:
    """Stands in for subprocess.Popen running docker: each subcommand (version, exec) answers as the test says,
    either ("hangs",) or (returncode, what it prints)."""

    answers = {}
    started = []

    def __init__(self, argv, stdout=None, stderr=None, stdin=None, **kwargs):
        assert argv[0] == "docker", argv
        assert stdout is not subprocess.PIPE and stderr is not subprocess.PIPE, "no output on a pipe"
        self.argv, self.stdout, self.killed, self.returncode = argv, stdout, False, None
        self.answer = type(self).answers[argv[1]]
        type(self).started.append(self)

    def wait(self, timeout=None):
        if self.killed:
            self.returncode = -9
            return self.returncode
        if self.answer[0] == "hangs":
            raise subprocess.TimeoutExpired(self.argv, timeout)
        self.returncode, printed = self.answer
        if printed and hasattr(self.stdout, "write"):
            self.stdout.write(printed.encode())
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True

    def communicate(self, *args, **kwargs):
        raise AssertionError("the output was read from a pipe")


@pytest.fixture
def docker(monkeypatch):
    """Docker as the test scripts it, asked afresh: the answer kept for the run is set aside."""
    monkeypatch.setattr(_Docker, "answers", {})
    monkeypatch.setattr(_Docker, "started", [])
    monkeypatch.setattr(subprocess, "Popen", _Docker)
    monkeypatch.setattr(shutil, "which", lambda name: DOCKER if name == "docker" else None)
    monkeypatch.setattr(conftest, "_DOCKER_ENGINE", {}, raising=False)
    return _Docker


def test_an_engine_that_does_not_answer_skips_the_module_and_is_asked_once(docker):
    docker.answers["version"] = ("hangs",)
    for _ in range(2):
        with pytest.raises(pytest.skip.Exception) as skipped:
            conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")
        assert "does not answer" in str(skipped.value) and "RATE_LIMIT_LOGIN_ATTEMPTS" in str(skipped.value)
        assert skipped.value.allow_module_level, "it is asked while a module is collected"
    assert [p.argv[1] for p in docker.started] == ["version"], "asked once a run, and no exec after it"
    assert docker.started[0].killed


def test_an_engine_that_refuses_skips_the_module_too(docker):
    docker.answers["version"] = (1, "")
    with pytest.raises(pytest.skip.Exception, match="does not answer"):
        conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")


def test_an_engine_that_answers_and_an_exec_that_does_not_fails(docker):
    docker.answers.update({"version": (0, "27.3.1\n"), "exec": ("hangs",)})
    with pytest.raises(pytest.fail.Exception, match="RATE_LIMIT_LOGIN_ATTEMPTS"):
        conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")
    assert [p.argv[1] for p in docker.started] == ["version", "exec"]
    assert docker.started[1].killed


def test_the_setting_is_read_from_the_container_when_both_answer(docker):
    docker.answers.update({"version": (0, "27.3.1\n"), "exec": (0, "2000\n")})
    assert conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS", container="vault") == 2000
    assert docker.started[1].argv == ["docker", "exec", "vault", "printenv", "RATE_LIMIT_LOGIN_ATTEMPTS"]
    docker.answers["exec"] = (1, "")                    # not set in the container: the default applies
    assert conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS") is None
    docker.answers["exec"] = (0, "many\n")
    assert conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS") is None


def test_without_a_docker_command_the_setting_is_unreadable(docker, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert conftest.configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS") is None
    assert docker.started == []


OPT_IN = {"test_auth_offload_under_outage.py": "VAULT_REDIS_OUTAGE_TEST",
          "test_login_offload_keeps_loop_free.py": "VAULT_LOOP_FREE_TEST"}


@pytest.mark.parametrize("module, flag", list(OPT_IN.items()))
def test_a_module_that_runs_only_when_asked_asks_the_deployment_only_then(monkeypatch, module, flag):
    # Both are skipped unless their flag is set, yet asked the deployment for its login limit while they were
    # collected, in every lane.
    import importlib.util
    from pathlib import Path
    asked = []
    monkeypatch.setattr(conftest, "configured_int_setting", lambda name, container=None: asked.append(name))
    for value, expected in ((None, []), ("1", ["RATE_LIMIT_LOGIN_ATTEMPTS"])):
        if value is None:
            monkeypatch.delenv(flag, raising=False)
        else:
            monkeypatch.setenv(flag, value)
        asked.clear()
        spec = importlib.util.spec_from_file_location(f"opt_in_{flag.lower()}",
                                                      Path(__file__).with_name(module))
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
        assert asked == expected, (flag, value)
