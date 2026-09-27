"""The upgrade tests' throwaway stacks keep to themselves, and are removed however setup ends.

tests/test_upgrade_email_nullable.py once left its stacks running, and one of them had mounted another
stack's volumes. Two causes: its fixture iterated the booting generator with `for ... yield`, so a skip
or a failure while seeding abandoned the generator before its teardown; and docker compose inherited
the test process's environment, which carries the worktree's .env, so that file's VAULT_VOLUME_PREFIX
won over the stack's own --env-file.

These run the real fixture code of both upgrade tests against a fake docker (tests/_throwaway_stack.py
routes every docker call through one replaceable runner), so nothing here starts a container.
"""
import json
import subprocess

import pytest

import _throwaway_stack
import test_upgrade_drill as drill_module
import test_upgrade_email_nullable as nullable_module

pytestmark = pytest.mark.unit

_ROLES = ("pg_data", "storage", "logs", "keys", "brand")


class FakeDocker:
    """Answers the docker commands the stacks run, and records each with the environment it got."""

    def __init__(self, *, up_rc=0, up_stderr="", health="healthy", existing=(), prefix=None):
        self.calls = []
        self.up_rc, self.up_stderr, self.health = up_rc, up_stderr, health
        self.existing = set(existing)      # volume roles that already exist, e.g. {"pg_data"}
        self.prefix = prefix               # a volume prefix other than the project's (a leak)

    def __call__(self, args, **kw):
        args = list(args)
        self.calls.append((args, kw.get("env")))
        out = ""
        rc = 0
        if args[:2] == ["docker", "compose"]:
            project = args[args.index("-p") + 1]
            sub = args[10:]
            if sub[:1] == ["config"]:
                prefix = self.prefix or project
                out = json.dumps({"volumes": {f"vault_{r}": {"name": f"{prefix}_vault_{r}"}
                                              for r in _ROLES}})
            elif sub[:1] == ["up"]:
                return subprocess.CompletedProcess(args, self.up_rc, "", self.up_stderr)
        elif args[:3] == ["docker", "volume", "inspect"]:
            rc = 0 if any(args[3].endswith("_vault_" + r) for r in self.existing) else 1
        elif args[:2] == ["docker", "inspect"] and "{{.State.Health.Status}}" in args:
            out = self.health
        return subprocess.CompletedProcess(args, rc, out, "")

    def compose(self, sub):
        return [a for a, _env in self.calls if a[:2] == ["docker", "compose"] and a[10:11] == [sub]]

    def removed(self):
        return sorted(a[3] for a, _env in self.calls if a[:3] == ["docker", "volume", "rm"])

    def project(self):
        first = next(a for a, _env in self.calls if a[:2] == ["docker", "compose"])
        return first[first.index("-p") + 1]

    def own_volumes(self):
        return sorted(f"{self.project()}_vault_{r}" for r in _ROLES)


@pytest.fixture
def docker(monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(_throwaway_stack, "_spawn", fake)
    return fake


def _torn_down(fake):
    assert fake.compose("down"), "the stack was never stopped"
    assert fake.removed() == fake.own_volumes(), "the stack's volumes were not all removed"


def test_a_skip_while_seeding_the_old_release_still_tears_the_stack_down(docker, monkeypatch,
                                                                       tmp_path_factory):
    # The case that leaked: the stack is up, and seeding it skips.
    monkeypatch.setattr(nullable_module, "_seed_then_upgrade",
                        lambda state: pytest.skip("the old release refused the seed data"))
    fixture = nullable_module._upgraded_stack(tmp_path_factory)
    with pytest.raises(pytest.skip.Exception):
        next(fixture)
    assert docker.compose("up"), "the stack never started, so this proves nothing"
    _torn_down(docker)


def test_a_failure_while_upgrading_still_tears_the_stack_down(docker, monkeypatch, tmp_path_factory):
    def upgrade_fails(state):
        raise AssertionError("the upgrade did not start")

    monkeypatch.setattr(nullable_module, "_seed_then_upgrade", upgrade_fails)
    with pytest.raises(AssertionError):
        next(nullable_module._upgraded_stack(tmp_path_factory))
    _torn_down(docker)


def test_the_stack_is_torn_down_once_the_tests_are_done(docker, monkeypatch, tmp_path_factory):
    monkeypatch.setattr(nullable_module, "_seed_then_upgrade", lambda state: None)
    fixture = nullable_module._upgraded_stack(tmp_path_factory)
    state = next(fixture)
    assert state["project"] == docker.project()
    assert not docker.compose("down"), "torn down while the tests still needed it"
    with pytest.raises(StopIteration):
        next(fixture)              # what pytest does after the module's last test
    _torn_down(docker)


def test_a_host_that_cannot_take_a_stack_skips_and_still_tears_down(monkeypatch, tmp_path_factory):
    fake = FakeDocker(up_rc=1, up_stderr="Bind for 127.0.0.1:30777 failed: port is already allocated")
    monkeypatch.setattr(_throwaway_stack, "_spawn", fake)
    with pytest.raises(pytest.skip.Exception):
        next(drill_module._install_oldest(tmp_path_factory))
    _torn_down(fake)


def test_an_image_that_will_not_boot_fails_with_its_logs_and_still_tears_down(monkeypatch,
                                                                             tmp_path_factory):
    # `up` waits on the API's health, so an image that comes up sick fails `up` itself.
    fake = FakeDocker(up_rc=1, up_stderr="dependency failed to start: container upg-api is unhealthy")
    monkeypatch.setattr(_throwaway_stack, "_spawn", fake)
    with pytest.raises(pytest.fail.Exception):
        next(nullable_module._boot_stack(tmp_path_factory, "old:image", "upg"))
    _torn_down(fake)
    order = [a[10:11] for a, _env in fake.calls if a[:2] == ["docker", "compose"]]
    assert order.index(["logs"]) < order.index(["down"]), "the logs must be read before teardown"


def test_the_compose_environment_excludes_the_process_vault_variables(docker, monkeypatch,
                                                                      tmp_path_factory):
    # What the worktree's .env puts into the test process, plus a compose setting and an engine.
    monkeypatch.setenv("VAULT_VOLUME_PREFIX", "someone-elses-stack")
    monkeypatch.setenv("VAULT_DB_PASSWORD", "someone-elses-password")
    monkeypatch.setenv("REDIS_PASSWORD", "someone-elses-redis")
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "someone-elses-project")
    monkeypatch.setenv("DOCKER_HOST", "tcp://engine.example:2376")
    stack = nullable_module._boot_stack(tmp_path_factory, "old:image", "upg")
    next(stack)
    stack.close()

    assert docker.calls
    for args, env in docker.calls:
        assert env is not None, f"{args[:3]} ran with the whole process environment"
        leaked = sorted(k for k in env if k.upper().startswith(("VAULT_", "COMPOSE_"))
                        or k.upper() == "REDIS_PASSWORD")
        assert not leaked, f"{args[:3]} was given {leaked}"
        assert env.get("DOCKER_HOST") == "tcp://engine.example:2376", "the engine setting must pass"
        assert any(k.upper() == "PATH" for k in env), "docker cannot be found without PATH"


def test_compose_environment_keeps_only_what_docker_needs():
    env = _throwaway_stack.compose_environment({
        "PATH": "/usr/bin", "HOME": "/home/u", "DOCKER_CONFIG": "/cfg", "SystemRoot": r"C:\Windows",
        "ProgramFiles": r"C:\Program Files", "VAULT_VOLUME_PREFIX": "x", "VAULT_DB_PASSWORD": "y",
        "COMPOSE_PROFILES": "split", "DOCKVAULT_IMAGE": "z", "ENCRYPTION_KEY": "k"})
    assert sorted(env) == ["DOCKER_CONFIG", "HOME", "PATH", "ProgramFiles", "SystemRoot"]


def test_a_stack_whose_volumes_already_exist_is_refused_and_nothing_is_touched(monkeypatch,
                                                                              tmp_path_factory):
    fake = FakeDocker(existing={"pg_data"})
    monkeypatch.setattr(_throwaway_stack, "_spawn", fake)
    with pytest.raises(pytest.fail.Exception, match="already exist"):
        next(drill_module._install_oldest(tmp_path_factory))
    assert not fake.compose("up"), "a stack over existing volumes must not start"
    assert not fake.compose("down") and not fake.removed(), (
        "the volumes are not the test's, so nothing may be removed")


def test_a_stack_whose_volumes_carry_another_name_is_refused(monkeypatch, tmp_path_factory):
    # What the leak looked like from inside: compose resolved another stack's volume prefix.
    fake = FakeDocker(prefix="dvother")
    monkeypatch.setattr(_throwaway_stack, "_spawn", fake)
    with pytest.raises(pytest.fail.Exception, match="not named for it"):
        next(nullable_module._boot_stack(tmp_path_factory, "old:image", "upg"))
    assert not fake.compose("up") and not fake.removed()


def test_teardown_never_raises_and_still_removes_every_volume(docker):
    def compose(*args, timeout=None):
        raise subprocess.TimeoutExpired(["docker", "compose", "down"], timeout)

    _throwaway_stack.tear_down(compose, ["p_vault_pg_data", "p_vault_storage"])
    assert docker.removed() == ["p_vault_pg_data", "p_vault_storage"]
