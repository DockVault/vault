"""Throwaway compose stacks for the tests that boot released images beside the one under test
(tests/test_upgrade_email_nullable.py and tests/test_upgrade_drill.py).

Such a stack is made and removed by its test, on a host that runs other stacks, so three rules keep it
to itself. Each is here because a stack broke it: a test run left three stacks running, and one of
them had mounted another stack's volumes, so two Postgres servers ran on one data directory.

* docker runs with an explicit, minimal environment (compose_environment). Compose takes a variable
  from its own environment over the --env-file it is given, and the test process carries the
  worktree's .env (app/core/config.py loads it when the app is imported). That file's
  VAULT_VOLUME_PREFIX and VAULT_DB_PASSWORD reached compose and pointed the throwaway stack at the
  other stack's volumes.
* The volumes a stack will use are read from `docker compose config` before it starts, and the stack
  is refused if any of them already exists or is not named for the stack's own project
  (refuse_volumes_in_use). Teardown removes exactly those volumes, by name.
* Teardown runs in `finally` in the generator that boots a stack, and a fixture that goes on using
  the stack after booting it closes the generator in `finally` too, so a skip or a failure anywhere
  in setup still removes what was created.
"""
import json
import os
import subprocess

import pytest

# What the docker CLI needs from the environment, and nothing compose could read as a value for the
# stack. On Windows the CLI also needs the system directory and the shell, and finds its compose
# plugin under PROGRAMFILES (or PROGRAMDATA): without them `docker compose` is an unknown command.
_KEEP = frozenset({"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "COMSPEC",
                   "PROGRAMFILES", "PROGRAMDATA"})

# The process runner. A module attribute so a test can put a fake in its place.
_spawn = subprocess.run


def compose_environment(environ=None):
    """The environment every docker call of a throwaway stack runs with: PATH, the home directory,
    the Windows system variables docker needs, and DOCKER_* (which say which engine to use). Nothing
    else, so no VAULT_*, COMPOSE_* or other value in the test process can change the stack."""
    environ = os.environ if environ is None else environ
    return {k: v for k, v in environ.items()
            if k.upper() in _KEEP or k.upper().startswith("DOCKER_")}


def run(args, **kw):
    """Run one docker command with compose_environment(), capturing its output."""
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 600)
    kw["env"] = compose_environment()
    return _spawn(args, **kw)


def compose_command(project, workdir, override_name):
    """The docker compose command line for the stack in `workdir`, before its subcommand."""
    return ["docker", "compose", "-p", project, "--env-file", os.path.join(workdir, ".env"),
            "-f", os.path.join(workdir, "deploy", "docker-compose.yml"),
            "-f", os.path.join(workdir, override_name)]


def stack_volumes(compose):
    """The names of the volumes the stack will use, as compose resolves them. Fails the test when
    they cannot be read: a stack whose volumes are unknown cannot be checked or cleaned up."""
    out = compose("config", "--format", "json", timeout=120)
    if out.returncode != 0:
        pytest.fail(f"docker compose config failed, so the stack's volumes are unknown: "
                    f"{(out.stderr or '')[-400:]}")
    try:
        config = json.loads(out.stdout)
    except ValueError:
        pytest.fail(f"docker compose config did not print JSON: {(out.stdout or '')[:200]}")
    volumes = config.get("volumes") or {}
    names = sorted(v.get("name") or "" for v in volumes.values() if isinstance(v, dict))
    if not names or not all(names):
        pytest.fail(f"docker compose config names no volumes for the stack: {volumes!r}")
    return names


def refuse_volumes_in_use(names, project):
    """Fail, before anything starts, when a volume the stack would use is not named for its project
    or already exists. Either means the stack would mount data it did not create: another stack's,
    or one left by an earlier run. Nothing is removed here, because none of it is the test's."""
    foreign = [n for n in names if not n.startswith(project + "_")]
    existing = [n for n in names if run(["docker", "volume", "inspect", n], timeout=60).returncode == 0]
    if foreign or existing:
        pytest.fail("refusing to start the throwaway stack %s: %s" % (project, "; ".join(
            ([f"volumes not named for it: {', '.join(foreign)}"] if foreign else [])
            + ([f"volumes that already exist: {', '.join(existing)}"] if existing else []))))


def tear_down(compose, volumes):
    """Stop the stack and remove exactly its volumes. Never `down -v` and never a prune, which can
    reach volumes that have nothing to do with the test. Never raises: it runs in `finally`, where an
    exception would replace the one that got there; a step that fails is printed instead."""
    steps = [("compose down", lambda: compose("down", timeout=300))]
    steps += [(f"volume rm {n}", lambda n=n: run(["docker", "volume", "rm", n], timeout=60))
              for n in volumes]
    for what, step in steps:
        try:
            out = step()
            if getattr(out, "returncode", 0) != 0:
                print(f"throwaway stack teardown: {what} failed: {(out.stderr or '')[-300:]}")
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"throwaway stack teardown: {what} failed: {exc}")
