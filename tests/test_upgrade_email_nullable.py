"""The schema change must actually reach an UPGRADED install, not just a fresh one.

This is the defect class the whole phase is built around, and it is invisible to every other test
in the suite:

``create_all()`` creates TABLES; it never ALTERs an existing one. So if the model says
``nullable=True`` and the boot DDL list lacks the matching ``ALTER``, a **fresh** install gets a
nullable column and the entire suite passes — while every **existing** self-hoster keeps
``NOT NULL`` and creating an email-less user fails at the database. Green locally, broken for
everyone who already runs it.

The only way to catch that is to boot the PREVIOUS RELEASE, write data with it, and then bring the
candidate up against the SAME volumes. Asserting nullability on a fresh install proves nothing.

The test owns its stack end to end: its own compose project, its own volume prefix, its own ports.
Teardown removes only resources it created and names explicitly — never a prune, and never
``down -v``, which on this host can reach volumes that have nothing to do with this test.
"""
import base64
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import uuid

import pytest

from conftest import host_cannot_take_a_stack
import requests

pytestmark = [pytest.mark.integration, pytest.mark.docker, pytest.mark.slow,
              pytest.mark.disruptive]

# The last released image. NOTE the "v" prefix: the bare tag "0.10.0" does not exist in GHCR.
BASELINE_IMAGE = "ghcr.io/dockvault/vault:v0.10.0"

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(args, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 600)
    return subprocess.run(args, **kw)


def _candidate_image():
    """The image the current round is running, so the upgrade targets THIS tree."""
    api = os.environ.get("VAULT_API_CONTAINER")
    if not api:
        pytest.skip("VAULT_API_CONTAINER is unset; cannot identify the candidate image")
    out = _run(["docker", "inspect", api, "--format", "{{.Config.Image}}"])
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip(f"cannot inspect {api}")
    return out.stdout.strip()


@pytest.fixture(scope="module")
def upgrade_stack(tmp_path_factory):
    """A throwaway stack, booted on the OLD image, torn down by exact name."""
    if _run(["docker", "image", "inspect", BASELINE_IMAGE]).returncode != 0:
        pulled = _run(["docker", "pull", BASELINE_IMAGE], timeout=900)
        if pulled.returncode != 0:
            pytest.skip(f"cannot pull {BASELINE_IMAGE}: {pulled.stderr[-300:]}")
    for state in _boot_stack(tmp_path_factory, BASELINE_IMAGE, "upg"):
        _seed_then_upgrade(state)
        yield state



def _seed_then_upgrade(st):
    """Record what the old release looked like, write data on it, then upgrade over its volumes.

    In the fixture rather than in a test, deliberately. It used to live in the first test, which
    made every later test in the module depend on that one having run first -- run the schema
    comparison on its own and it compared the BASELINE against a fresh install, reporting a page of
    differences that had nothing to do with what it was checking. A fixture called "upgrade_stack"
    has to hand back an upgraded stack.

    What it observed before upgrading is recorded on the state so the assertions stay in the tests.
    """
    st["pre"] = {
        "email_nullable": st["psql"](
            "SELECT is_nullable FROM information_schema.columns "
            "WHERE table_name='users' AND column_name='email'"),
    }

    token = _login(st["base_url"], st["env"]["ADMIN_USERNAME"], st["env"]["ADMIN_PASSWORD"])
    st["legacy_user"] = f"legacy_{uuid.uuid4().hex[:8]}"
    made = requests.post(f"{st['base_url']}/users", timeout=30,
                         headers={"Authorization": f"Bearer {token}"},
                         json={"username": st["legacy_user"],
                               "email": f"{st['legacy_user']}@example.com",
                               "password": "TestPassw0rd!123", "role": "user"})
    assert made.status_code < 400, f"could not seed data on the old release: {made.text[:200]}"

    st["override"](_candidate_image())
    up = st["compose"]("up", "-d")
    assert up.returncode == 0, f"the upgrade did not start: {up.stderr[-400:]}"
    assert st["wait_healthy"](), (
        "the deployment did not come back up after the upgrade -- this is exactly the "
        "unattended-update failure the phase exists to prevent")


def _boot_stack(tmp_path_factory, image, prefix):
    """Bring up one throwaway stack on `image` and hand back its handles.

    Shared by both fixtures. Duplicating it would mean two copies of the volume-naming and
    teardown-by-exact-name rules, and those are the parts that must not drift.
    """
    project = f"{prefix}{uuid.uuid4().hex[:8]}"
    workdir = str(tmp_path_factory.mktemp(project))
    port = 30400 + (int(uuid.uuid4().hex[:4], 16) % 300)

    # Copy the deploy compose out of the repo so the test never writes into the worktree.
    shutil.copytree(os.path.join(REPO, "deploy"), os.path.join(workdir, "deploy"))

    env = {
        "VAULT_DB_PASSWORD": secrets.token_hex(16),
        "ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "ADMIN_USERNAME": "admin",
        "ADMIN_EMAIL": "admin@example.com",
        "ADMIN_PASSWORD": secrets.token_hex(16),
        "VAULT_VOLUME_PREFIX": project,
        "ENVIRONMENT": "production",
        "RATE_LIMIT_LOGIN_ATTEMPTS": "2000",
        "RATE_LIMIT_API_AUTH": "2000",
        "RATE_LIMIT_API_DEFAULT": "5000",
        "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": "480",
    }
    io.open(os.path.join(workdir, ".env"), "w", newline="\n").write(
        "\n".join(f"{k}={v}" for k, v in env.items()) + "\n"
    )

    def override(image):
        io.open(os.path.join(workdir, "round.override.yml"), "w", newline="\n").write(
            "services:\n"
            f"  vault-db:\n    container_name: {project}-db\n"
            f"  vault-redis:\n    container_name: {project}-redis\n"
            f"  vault-api:\n    container_name: {project}-api\n"
            f"    image: {image}\n    build: !reset null\n"
            f"    ports: !override\n      - \"127.0.0.1:{port}:8000\"\n"
            f"  vault-sftp:\n    container_name: {project}-sftp\n"
            f"    image: {image}\n    build: !reset null\n"
            f"    ports: !override\n      - \"127.0.0.1:{port + 1}:2222\"\n"
        )

    def compose(*args, timeout=600):
        return _run(
            ["docker", "compose", "-p", project, "--env-file", os.path.join(workdir, ".env"),
             "-f", os.path.join(workdir, "deploy", "docker-compose.yml"),
             "-f", os.path.join(workdir, "round.override.yml")] + list(args),
            cwd=workdir, timeout=timeout,
        )

    def wait_healthy(timeout=240):
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = _run(["docker", "inspect", f"{project}-api",
                        "--format", "{{.State.Health.Status}}"], timeout=30)
            if out.stdout.strip() == "healthy":
                return True
            time.sleep(4)
        return False

    def psql(sql):
        out = _run(["docker", "exec", f"{project}-db", "psql", "-U", "sftp_user",
                    "-d", "sftp_db", "-tAc", sql], timeout=60)
        assert out.returncode == 0, f"psql failed: {out.stderr[:300]}"
        return out.stdout.strip()

    state = {
        "project": project, "port": port, "env": env, "compose": compose,
        "override": override, "wait_healthy": wait_healthy, "psql": psql,
        "base_url": f"http://127.0.0.1:{port}",
    }

    def purge():
        # Stop the project, then remove ONLY the volumes this test created, by exact name.
        # Never `down -v` and never a prune -- both can reach unrelated volumes on this host.
        compose("down", timeout=300)
        listed = _run(["docker", "volume", "ls", "-q"], timeout=60).stdout.split()
        for name in listed:
            if name.startswith(project):
                _run(["docker", "volume", "rm", name], timeout=60)

    override(image)
    up = compose("up", "-d")
    # As in the other drill: sftp waits on the API's health, so `up` blocks and an image that
    # comes up sick returns non-zero. Only the host being unable to take another stack is a
    # reason to skip; an image that will not boot is the thing under test.
    healthy = wait_healthy() if up.returncode == 0 else False
    if up.returncode != 0 or not healthy:
        note = (f"{prefix} stack did not come up (rc={up.returncode}, healthy={healthy}): "
                f"{(up.stderr or '')[-400:]}")
        if host_cannot_take_a_stack(up):
            purge()
            pytest.skip(f"this host cannot take another stack right now: {note}")
        logs = compose("logs", "--no-color", "--tail", "60", timeout=120).stdout
        purge()
        pytest.fail(f"the {prefix} image does not come up against the shipped compose, so the "
                    f"nullable-column upgrade below was never exercised.\n{note}\n"
                    f"  logs:\n{logs[-2000:]}")

    yield state

    purge()


def _login(base_url, username, password):
    r = requests.post(f"{base_url}/auth/login",
                      json={"username": username, "password": password}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def test_email_becomes_nullable_on_an_upgraded_install(upgrade_stack):
    """The schema change reaches an install that already existed, not only a fresh one."""
    st = upgrade_stack
    env, psql = st["env"], st["psql"]

    assert st["pre"]["email_nullable"] == "NO", (
        "the baseline image already had a nullable email, so this proves nothing about the ALTER "
        "running -- pick an older baseline")
    legacy_name = st["legacy_user"]

    # The data written by the old release must still be there; otherwise the volumes were not
    # reused and every assertion below would be about a fresh install.
    assert psql(f"SELECT count(*) FROM users WHERE username='{legacy_name}'") == "1", (
        "the pre-upgrade user is gone, so this was not an upgrade over existing volumes"
    )

    # The actual point.
    assert psql(
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_name='users' AND column_name='email'"
    ) == "YES", (
        "users.email is still NOT NULL after the upgrade. A fresh install would pass every other "
        "test while every existing self-hoster cannot create an email-less account"
    )

    # ...and it has to WORK, not merely be nullable.
    token = _login(st["base_url"], env["ADMIN_USERNAME"], env["ADMIN_PASSWORD"])
    headers = {"Authorization": f"Bearer {token}"}
    new_name = f"noemail_{uuid.uuid4().hex[:8]}"
    r = requests.post(f"{st['base_url']}/users", headers=headers, timeout=30, json={
        "username": new_name, "password": "TestPassw0rd!123", "role": "user",
    })
    assert r.status_code < 400, f"an email-less user could not be created after upgrade: {r.text[:300]}"
    assert r.json()["email"] is None


def test_the_upgrade_also_builds_the_case_insensitive_index(upgrade_stack):
    """The index is created by code, not by create_all, so an upgrade must build it too.

    Runs after the upgrade test in the same module-scoped stack.
    """
    st = upgrade_stack
    assert st["psql"](
        "SELECT count(*) FROM pg_indexes WHERE tablename='users' "
        "AND indexname='uq_users_email_lower'"
    ) == "1", "the upgraded install has no case-insensitive index, so only fresh installs are safe"


def test_the_upgrade_creates_tables_added_since_the_baseline(upgrade_stack):
    """Free coverage: the baseline predates the per-user view table, so create_all must add it.

    Cheap to assert and it pins that create_all still runs on the upgrade path at all.
    """
    st = upgrade_stack
    assert st["psql"](
        "SELECT count(*) FROM information_schema.tables WHERE table_name='vault_views'"
    ) == "1", "a table added after the baseline release was not created by the upgrade"


# --- the whole schema, not three named things -------------------------------------------------

SCHEMA_QUERY = (
    "SELECT table_name || '.' || column_name || ' ' || data_type "
    "|| ' null=' || is_nullable "
    "|| ' default=' || coalesce(column_default, '-') "
    "FROM information_schema.columns "
    "WHERE table_schema = 'public' ORDER BY table_name, column_name"
)


@pytest.fixture(scope="module")
def fresh_stack(tmp_path_factory):
    """A second throwaway stack, booted from the candidate on empty volumes.

    The upgraded install has to be compared against something, and the only honest comparison is a
    fresh install of the same code. Asserting the upgraded schema against a list written into the
    test would just move the drift into the test file.
    """
    yield from _boot_stack(tmp_path_factory, _candidate_image(), "fresh")


def _column_map(psql):
    rows = [line for line in psql(SCHEMA_QUERY).splitlines() if line.strip()]
    assert len(rows) > 100, f"only {len(rows)} columns found; the query is not seeing the schema"
    return {line.split(" ", 1)[0]: line.split(" ", 1)[1] for line in rows}


def test_a_fresh_install_and_an_upgraded_install_have_the_same_schema(upgrade_stack, fresh_stack):
    """The comparison nothing was making, which is why two columns could drift unnoticed.

    The harness already booted the previous release, seeded it, and upgraded over the same volumes.
    What it checked was three things it named -- one column, one index, one table -- so anything not
    on that list was upgraded without anyone looking. This enumerates instead, and diffs.

    Reported as a set difference rather than an equality assertion so a failure names the columns
    that disagree and how, which is the whole use of the test.

    WHAT THIS DOES NOT COVER, stated because the name reads as though it covers everything. The
    baseline is the previous release, and that release's own create_all already built its tables
    from its model. So a column whose ALTER has always disagreed with its declaration looks
    identical on both sides here: both got the model's shape, neither took the ALTER path. The
    divergence this phase closed is exactly that case, and it is caught by the scratch-table replay
    in test_upgrade_schema_divergence.py, which constructs the older shape by hand rather than
    hoping the baseline has it. Verified by removing the fix: this test still passed, and that one
    failed naming both columns.

    What this DOES catch is drift introduced since the baseline -- a column added to a pre-existing
    table between then and now whose ALTER does not match its declaration -- which is the case
    nothing was checking at all. Upgrading from the OLDEST supported release instead would widen it
    further, at the cost of another stack boot; worth doing deliberately rather than by accident.
    """
    upgraded = _column_map(upgrade_stack["psql"])
    fresh = _column_map(fresh_stack["psql"])

    only_upgraded = sorted(set(upgraded) - set(fresh))
    only_fresh = sorted(set(fresh) - set(upgraded))
    differing = sorted(
        f"{name}: upgraded has [{upgraded[name]}], fresh has [{fresh[name]}]"
        for name in set(upgraded) & set(fresh) if upgraded[name] != fresh[name]
    )

    problems = []
    if only_upgraded:
        problems.append("only on the upgraded install: " + ", ".join(only_upgraded))
    if only_fresh:
        problems.append("only on a fresh install: " + ", ".join(only_fresh))
    if differing:
        problems.append("differ: " + "; ".join(differing))

    assert not problems, (
        "a fresh install and an upgraded one do not have the same schema, so one of them is "
        "running a shape nobody tested:\n  " + "\n  ".join(problems))
