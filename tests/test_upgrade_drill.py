"""Walk a deployment across three released versions and prove nothing was lost.

Every other test in this area checks one hop, or checks it against source. This one does what an
operator does: installs an old release, puts real data in it, and upgrades forward release by
release to the code under test, checking after every step that the data is still there and that the
deployment is telling the truth about itself.

It matters because the tagged-release upgrade path took its FIRST schema change in 0.11.0: every
published version through 0.10.0 was schema-identical, and 0.11.0 added the vault_storage_grants
table and a nullable users.storage_quota_bytes column. The code under test (0.11.1) inherits that
same schema, so the boot-DDL machinery introduced in 0.11.0 is exactly what the candidate hop below
leans on.
A drill is the only way to find out whether the boot DDL applies cleanly on a database that has been
through several releases rather than one built fresh.

Two properties, checked at every step rather than only at the end:

  * the data written by the oldest release is still readable, byte for byte;
  * the deployment does not report healthy while its schema is incomplete.

The second is the one that would otherwise go unnoticed. A migration that silently failed leaves a
deployment that answers requests until something touches the column that never arrived.

Owns its stack end to end: its own compose project, its own volume prefix, its own ports. Teardown
removes only what it created, by exact name -- never a prune, never `down -v`, both of which reach
volumes on this host that have nothing to do with this test.
"""

from __future__ import annotations

import base64
import io
import os
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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Three released versions, oldest first, then the code under test. Spread across the published
# range rather than adjacent, so the walk crosses more of the DDL list than one hop would.
DRILL_TAGS = ("v0.6.0", "v0.8.0", "v0.10.0")
IMAGE = "ghcr.io/dockvault/vault:%s"

# Written on the OLDEST release and read back after every upgrade. Bytes rather than a row count:
# a count survives a truncation that replaced content, and the point is that the operator's file is
# the same file.
PAYLOAD = bytes((i * 31 + 7) % 256 for i in range(4096))


def _run(cmd, cwd=None, timeout=600):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


@pytest.fixture(scope="module")
def drill():
    """A deployment on the oldest drill release, for the stepped walk."""
    yield from _install_oldest()


@pytest.fixture(scope="module")
def direct_drill():
    """A second deployment on the oldest release, for the single-jump upgrade.

    Its own stack, because the two tests cannot share one: the stepped walk ends on the candidate,
    and a jump has to start from the old release.
    """
    yield from _install_oldest()


def _install_oldest():
    for tag in DRILL_TAGS:
        image = IMAGE % tag
        if _run(["docker", "image", "inspect", image]).returncode != 0:
            pulled = _run(["docker", "pull", image], timeout=1200)
            if pulled.returncode != 0:
                pytest.skip(f"cannot pull {image}: {pulled.stderr[-300:]}")

    project = f"drill{uuid.uuid4().hex[:8]}"
    workdir = os.path.join(REPO, ".pytest-drill", project)
    os.makedirs(workdir, exist_ok=True)
    port = 30700 + (int(uuid.uuid4().hex[:4], 16) % 200)
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
        "\n".join(f"{k}={v}" for k, v in env.items()) + "\n")

    def override(image):
        # A throwaway drill stack, not a real deployment: pin restart "no" so a container that dies
        # (e.g. an OOM under CI contention) STAYS down and the drill fails fast with diagnose() output
        # instead of crash-looping and eating the job's time budget. Give the DB a longer first-boot
        # grace (start_period/retries) so a slow initdb under load is not marked unhealthy prematurely
        # — start_period failures are not counted, so this is safe for the walk too.
        io.open(os.path.join(workdir, "drill.override.yml"), "w", newline="\n").write(
            "services:\n"
            f"  vault-db:\n    container_name: {project}-db\n"
            f"    restart: \"no\"\n"
            f"    healthcheck:\n      start_period: 45s\n      retries: 12\n"
            f"  vault-redis:\n    container_name: {project}-redis\n"
            f"    restart: \"no\"\n"
            f"  vault-api:\n    container_name: {project}-api\n"
            f"    image: {image}\n    build: !reset null\n"
            f"    restart: \"no\"\n"
            f"    ports: !override\n      - \"127.0.0.1:{port}:8000\"\n"
            f"  vault-sftp:\n    container_name: {project}-sftp\n"
            f"    image: {image}\n    build: !reset null\n"
            f"    restart: \"no\"\n"
            f"    ports: !override\n      - \"127.0.0.1:{port + 1}:2222\"\n")

    def compose(*args, timeout=900):
        return _run(["docker", "compose", "-p", project,
                     "--env-file", os.path.join(workdir, ".env"),
                     "-f", os.path.join(workdir, "deploy", "docker-compose.yml"),
                     "-f", os.path.join(workdir, "drill.override.yml")] + list(args),
                    cwd=workdir, timeout=timeout)

    def wait_healthy(timeout=300):
        """Docker's own verdict. Deliberately not the endpoint: after this change /health can
        answer 503, and waiting on a 200 would hang instead of reporting a broken upgrade."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = _run(["docker", "inspect", f"{project}-api",
                        "--format", "{{.State.Health.Status}}"], timeout=30)
            state = out.stdout.strip()
            if state in ("healthy", "unhealthy"):
                return state
            time.sleep(4)
        return "timeout"

    def psql(sql):
        out = _run(["docker", "exec", f"{project}-db", "psql", "-U", "sftp_user",
                    "-d", "sftp_db", "-tAc", sql], timeout=60)
        assert out.returncode == 0, f"psql failed: {out.stderr[:300]}"
        return out.stdout.strip()

    base_url = f"http://127.0.0.1:{port}"
    state = {"project": project, "env": env, "compose": compose, "override": override,
             "wait_healthy": wait_healthy, "psql": psql, "base_url": base_url, "port": port}

    def diagnose(note):
        """Why the stack is not up. Gathered before teardown, which destroys the evidence."""
        health = _run(["docker", "inspect", f"{project}-api",
                       "--format", "{{json .State.Health}}"], timeout=30).stdout.strip()
        logs = compose("logs", "--no-color", "--tail", "60", timeout=120).stdout
        return f"{note}\n  api health: {health[:600]}\n  logs:\n{logs[-2000:]}"

    def purge():
        """Stop the project and remove ONLY the volumes it created, by exact name. Never
        `down -v` and never a prune -- both can reach unrelated volumes on this host."""
        compose("down", timeout=300)
        for name in _run(["docker", "volume", "ls", "-q"], timeout=60).stdout.split():
            if name.startswith(project):
                _run(["docker", "volume", "rm", name], timeout=60)
        shutil.rmtree(workdir, ignore_errors=True)

    override(IMAGE % DRILL_TAGS[0])
    up = compose("up", "-d")
    # vault-sftp waits on the API being healthy, so `up` already blocks on it: a released image
    # that starts and then reports itself sick returns non-zero here rather than reaching
    # wait_healthy(). Either way, only the host running out of ports or disk is a reason to
    # stand down. An image that will not boot against the shipped compose is the breakage this
    # drill exists to catch, and skipping it leaves the suite green having proved nothing.
    boot = wait_healthy() if up.returncode == 0 else "never started"
    if up.returncode != 0 or boot != "healthy":
        note = (f"the {DRILL_TAGS[0]} stack did not come up (rc={up.returncode}, api={boot}): "
                f"{(up.stderr or '')[-400:]}")
        if host_cannot_take_a_stack(up):
            purge()
            pytest.skip(f"this host cannot take another stack right now: {note}")
        detail = diagnose(note)
        purge()
        pytest.fail(f"the published {DRILL_TAGS[0]} image does not come up against the shipped "
                    f"compose, so nothing below it was proved.\n{detail}")

    yield state

    purge()


def _token(state):
    r = requests.post(f"{state['base_url']}/auth/login", timeout=30,
                      json={"username": state["env"]["ADMIN_USERNAME"],
                            "password": state["env"]["ADMIN_PASSWORD"]})
    r.raise_for_status()
    return {"Authorization": "Bearer %s" % r.json()["access_token"]}


def _candidate_image():
    api = os.environ.get("VAULT_API_CONTAINER")
    if not api:
        pytest.skip("VAULT_API_CONTAINER is unset; cannot identify the candidate image")
    out = _run(["docker", "inspect", api, "--format", "{{.Config.Image}}"])
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip(f"cannot inspect {api}")
    return out.stdout.strip()


def test_data_written_on_an_old_release_survives_every_upgrade_to_here(drill):
    """The drill. One deployment, walked forward, checked at every stop.

    Written as one test rather than one per hop because the state is the point: each step has to
    start from what the previous one left, and a per-hop test would either share mutable state
    across tests or rebuild the deployment and stop being a walk.
    """
    state = drill
    headers = _token(state)
    base = state["base_url"]

    # --- Seed on the oldest release ---
    user = "drill_%s" % uuid.uuid4().hex[:8]
    made = requests.post(f"{base}/users", headers=headers, timeout=60, json={
        "username": user, "email": f"{user}@example.com",
        "password": "DrillPassw0rd!123", "role": "user"})
    assert made.status_code < 400, f"could not seed a user on {DRILL_TAGS[0]}: {made.text[:300]}"

    vault = requests.post(f"{base}/vaults", headers=headers, timeout=60, json={
        "name": "drill_%s" % uuid.uuid4().hex[:6], "description": "upgrade drill"})
    assert vault.status_code < 400, f"could not create a vault: {vault.text[:300]}"
    vault_id = vault.json()["id"]

    filename = "drill-%s.bin" % uuid.uuid4().hex[:6]
    sent = requests.post(f"{base}/vaults/{vault_id}/files", headers=headers, timeout=120,
                         files={"files": (filename, PAYLOAD, "application/octet-stream")})
    assert sent.status_code < 400, f"could not upload on {DRILL_TAGS[0]}: {sent.text[:300]}"
    body = sent.json()
    uploaded = body if isinstance(body, list) else (body.get("files") or body.get("uploaded") or [])
    file_id = (uploaded[0].get("id") if uploaded and isinstance(uploaded[0], dict)
               else body.get("id"))
    assert file_id, f"no file id in the upload response: {sent.text[:300]}"

    def still_there(where):
        """Everything the oldest release wrote, read back through the API of whatever is running."""
        headers_now = _token(state)
        users = requests.get(f"{base}/users", headers=headers_now, timeout=60).json()
        assert any(u["username"] == user for u in users), (
            f"the seeded account is gone after {where}")

        listed = requests.get(f"{base}/vaults/{vault_id}/files", headers=headers_now, timeout=60)
        assert listed.status_code < 400, f"cannot list files after {where}: {listed.text[:200]}"

        got = requests.get(f"{base}/vaults/{vault_id}/files/{file_id}/download",
                           headers=headers_now, timeout=120)
        assert got.status_code == 200, f"cannot download after {where}: {got.text[:200]}"
        assert got.content == PAYLOAD, (
            f"the file's bytes changed across {where}; {len(got.content)} bytes back, "
            f"{len(PAYLOAD)} written")

    def honest(where):
        """The deployment must not claim health while its schema is incomplete.

        Both directions are checked. A 503 with a complete schema would be a false alarm that
        restarts working deployments; a 200 with an incomplete one is the failure this whole plan
        exists to remove.
        """
        docker_says = state["wait_healthy"]()
        response = requests.get(f"{base}/health", timeout=30)
        body = response.json()
        schema = body.get("schema")

        if schema == "incomplete":
            assert response.status_code == 503, (
                f"after {where} the schema is incomplete and /health still answered "
                f"{response.status_code}")
            pytest.fail(f"the schema did not fully apply after {where}: {body}")
        if schema is not None:
            assert response.status_code == 200, (
                f"after {where} /health answered {response.status_code} with schema={schema!r}")
        assert docker_says == "healthy", (
            f"after {where} Docker reports {docker_says} (body: {body})")

    still_there("the initial install")

    # --- Walk forward, one released version at a time, then to the code under test ---
    for target in list(DRILL_TAGS[1:]) + [_candidate_image()]:
        image = target if "/" in target or ":" in target and not target.startswith("v") \
            else IMAGE % target
        where = "the upgrade to %s" % target
        state["override"](image)
        up = state["compose"]("up", "-d")
        assert up.returncode == 0, f"{where} did not start: {up.stderr[-400:]}"
        assert state["wait_healthy"]() in ("healthy", "unhealthy"), (
            f"{where} never settled; this is the unattended-update failure the plan exists to "
            "prevent")
        # Prove the hop actually happened. Without this the walk is assumed: if the override or
        # the recreate silently did nothing, every check below would pass against the release we
        # started on, and the drill would report that upgrading is safe without having upgraded.
        # The IMAGE the container runs, not the version it reports. Relying on a version string to
        # prove the hop is fragile -- a build can misreport it, and the candidate (0.11.1) differs
        # from the last released tag (0.11.0) by this release's log-injection fix and the bump.
        # The image reference is unambiguous, and it is what "did the upgrade take" actually means.
        running = _run(["docker", "inspect", f"{state['project']}-api",
                        "--format", "{{.Config.Image}}"], timeout=60)
        assert running.returncode == 0, f"cannot inspect the container after {where}"
        assert running.stdout.strip() == image, (
            f"{where} left the deployment on {running.stdout.strip()}; the upgrade did not take")

        honest(where)
        still_there(where)

    # --- And the end state describes itself ---
    final = requests.get(f"{base}/health", timeout=30).json()
    assert final.get("schema") == "complete", (
        f"after walking {' -> '.join(DRILL_TAGS)} -> candidate the schema is {final.get('schema')!r}")
    recorded = state["psql"]("SELECT count(*) FROM schema_steps WHERE outcome = 'failed'")
    assert recorded == "0", f"{recorded} boot step(s) are recorded failed after the walk"


def test_one_jump_from_the_oldest_release_applies_everything(direct_drill):
    """The path an operator actually takes, and the one the stepped walk above does not cover.

    `dockvault.py update` does NOT step through intermediate versions. It walks the matrix's edges
    to work out what the change involves -- unioning the backup and reversibility requirements
    along the route -- and then makes ONE jump straight to the target. So the common case is a
    deployment several releases behind moving to latest in a single recreate, and the boot DDL
    applying everything that accumulated in between at once.

    Applying six releases' worth of statements to one database in one boot is a different thing
    from applying them one release at a time, and only the second was being tested.
    """
    state = direct_drill
    headers = _token(state)
    base = state["base_url"]

    user = "jump_%s" % uuid.uuid4().hex[:8]
    made = requests.post(f"{base}/users", headers=headers, timeout=60, json={
        "username": user, "email": f"{user}@example.com",
        "password": "DrillPassw0rd!123", "role": "user"})
    assert made.status_code < 400, f"could not seed on {DRILL_TAGS[0]}: {made.text[:300]}"

    vault = requests.post(f"{base}/vaults", headers=headers, timeout=60, json={
        "name": "jump_%s" % uuid.uuid4().hex[:6], "description": "single-jump drill"})
    assert vault.status_code < 400, vault.text[:300]
    vault_id = vault.json()["id"]

    sent = requests.post(f"{base}/vaults/{vault_id}/files", headers=headers, timeout=120,
                         files={"files": ("jump.bin", PAYLOAD, "application/octet-stream")})
    assert sent.status_code < 400, sent.text[:300]
    body = sent.json()
    uploaded = body if isinstance(body, list) else (body.get("files") or body.get("uploaded") or [])
    file_id = (uploaded[0].get("id") if uploaded and isinstance(uploaded[0], dict)
               else body.get("id"))
    assert file_id, sent.text[:300]

    # Straight from the oldest release to the candidate. No intermediate stop.
    candidate = _candidate_image()
    state["override"](candidate)
    up = state["compose"]("up", "-d")
    assert up.returncode == 0, f"the jump did not start: {up.stderr[-400:]}"
    assert state["wait_healthy"]() == "healthy", (
        "a deployment several releases behind did not come back healthy after a single upgrade; "
        "this is the ordinary path, not an edge case")

    running = _run(["docker", "inspect", f"{state['project']}-api",
                    "--format", "{{.Config.Image}}"], timeout=60)
    assert running.stdout.strip() == candidate, "the jump did not take"

    response = requests.get(f"{base}/health", timeout=30)
    assert response.status_code == 200, (
        f"/health answered {response.status_code} after the jump: {response.text[:200]}")
    assert response.json().get("schema") == "complete", (
        f"skipping the intermediate releases left the schema {response.json().get('schema')!r}; "
        "the accumulated DDL does not all apply in one boot")

    headers_now = _token(state)
    users = requests.get(f"{base}/users", headers=headers_now, timeout=60).json()
    assert any(u["username"] == user for u in users), "the seeded account did not survive the jump"
    got = requests.get(f"{base}/vaults/{vault_id}/files/{file_id}/download",
                       headers=headers_now, timeout=120)
    assert got.status_code == 200, got.text[:200]
    assert got.content == PAYLOAD, (
        f"the file's bytes changed across the jump; {len(got.content)} back, {len(PAYLOAD)} written")

    assert state["psql"](
        "SELECT count(*) FROM schema_steps WHERE outcome = 'failed'") == "0", (
        "boot steps failed when several releases' worth applied at once")
