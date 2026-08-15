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

    project = f"upg{uuid.uuid4().hex[:8]}"
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

    override(BASELINE_IMAGE)
    up = compose("up", "-d")
    if up.returncode != 0 or not wait_healthy():
        compose("down", timeout=300)
        pytest.skip(f"baseline stack did not come up: {up.stderr[-400:]}")

    yield state

    # Teardown: stop the project, then remove ONLY the volumes this test created, by exact
    # name. Never `down -v` and never a prune -- both can reach unrelated volumes on this host.
    compose("down", timeout=300)
    listed = _run(["docker", "volume", "ls", "-q"], timeout=60).stdout.split()
    for name in listed:
        if name.startswith(project):
            _run(["docker", "volume", "rm", name], timeout=60)


def _login(base_url, username, password):
    r = requests.post(f"{base_url}/api/login",
                      json={"username": username, "password": password}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def test_email_becomes_nullable_on_an_upgraded_install(upgrade_stack):
    """Boot the previous release, write data, then upgrade in place over the same volumes."""
    st = upgrade_stack
    env, psql = st["env"], st["psql"]

    # --- Phase 1: the OLD release. Establish that it really is "old". ---
    assert psql(
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_name='users' AND column_name='email'"
    ) == "NO", (
        "the baseline image already has a nullable email, so this test cannot prove the ALTER "
        "runs -- pick an older baseline"
    )

    token = _login(st["base_url"], env["ADMIN_USERNAME"], env["ADMIN_PASSWORD"])
    headers = {"Authorization": f"Bearer {token}"}
    legacy_name = f"legacy_{uuid.uuid4().hex[:8]}"
    made = requests.post(f"{st['base_url']}/users", headers=headers, timeout=30, json={
        "username": legacy_name, "email": f"{legacy_name}@example.com",
        "password": "TestPassw0rd!123", "role": "user",
    })
    assert made.status_code < 400, f"could not seed data on the old release: {made.text[:200]}"

    # --- Phase 2: the CANDIDATE, same volumes. ---
    candidate = _candidate_image()
    st["override"](candidate)
    up = st["compose"]("up", "-d")
    assert up.returncode == 0, f"the upgrade did not start: {up.stderr[-400:]}"
    assert st["wait_healthy"](), (
        "the deployment did not come back up after the upgrade -- this is exactly the "
        "unattended-update failure the phase exists to prevent"
    )

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
