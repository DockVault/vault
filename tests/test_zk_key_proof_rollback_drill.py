"""Key proofs across a rollback, with real Docker: an older image ignores them, nothing becomes unreadable, and
the code under test takes up again where the older one left off.

Key proofs add two tables and change no stored format a read depends on, so the promise to an operator is
that a rollback to the previous release strands nothing -- only the protection is off while rolled back.
This walks one deployment through exactly that:

  1. on the code under test: create zero-knowledge vaults (each gets its first epoch's proof key), upload a
     file, rotate one vault (its new epoch gets a proof key), and set up the key check of a vault whose
     epoch has none;
  2. on a previous release: the deployment starts, every file reads, a rotation works (the older server
     answers the challenge route with its plain 404, so the request goes without a proof), and deleting a
     vault still removes its proof rows, because their delete rule lives in the database;
  3. back on the code under test: the epoch rotated while rolled back has no proof key and says so, a
     change that needs one is refused until it is set up, it is set up on demand, the change then goes
     through, requests without a proof are refused again, and every file still reads.

Steps 2 and 3 run once for each release in ROLLBACK_TAGS, in turn, on the same deployment.

Owns its stack end to end, with the isolation of tests/_throwaway_stack.py: its own compose project,
volume prefix, container names and ports, an explicit environment, and teardown in `finally` that
removes only its own volumes by name.
"""

from __future__ import annotations

import base64
import io
import os
import secrets
import shutil
import time
import uuid

import pytest

import zk_proof_harness as harness
from _throwaway_stack import compose_command, refuse_volumes_in_use, run, stack_volumes, tear_down
from conftest import (
    ApiClient, ZK_ENC_NAME_STUB, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, ensure_ecc_keypair,
    host_cannot_take_a_stack, post_zk, put_zk, zk_chunked_upload,
)

pytestmark = [pytest.mark.integration, pytest.mark.docker, pytest.mark.slow, pytest.mark.disruptive]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "ghcr.io/dockvault/vault:%s"
# The releases this one can be rolled back to that the drill checks: the published releases of the line
# before key proofs. A later maintenance release of the same line joins here once it is published.
ROLLBACK_TAGS = ("v0.33.0", "v0.33.1")
PAYLOAD = bytes((i * 17 + 3) % 256 for i in range(4096))


def _candidate_image():
    api = os.environ.get("VAULT_API_CONTAINER")
    if not api:
        pytest.skip("VAULT_API_CONTAINER is unset; cannot identify the candidate image")
    out = run(["docker", "inspect", api, "--format", "{{.Config.Image}}"])
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip(f"cannot inspect {api}")
    return out.stdout.strip()


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    yield from _boot_on_the_candidate(tmp_path_factory)


def _boot_on_the_candidate(tmp_path_factory):
    """The drill's own stack on the candidate image, and what the walk needs to move it between releases.
    Torn down in `finally`, however setup or the walk ends."""
    candidate = _candidate_image()
    for tag in ROLLBACK_TAGS:
        image = IMAGE % tag
        if run(["docker", "image", "inspect", image]).returncode != 0:
            pulled = run(["docker", "pull", image], timeout=1200)
            if pulled.returncode != 0:
                pytest.skip(f"cannot pull {image}: {pulled.stderr[-300:]}")

    project = f"zkrb{uuid.uuid4().hex[:8]}"
    workdir = str(tmp_path_factory.mktemp(project))   # outside the repository: it holds the stack's secrets
    port = 30900 + (int(uuid.uuid4().hex[:4], 16) % 200)
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
        io.open(os.path.join(workdir, "drill.override.yml"), "w", newline="\n").write(
            "services:\n"
            f"  vault-db:\n    container_name: {project}-db\n    restart: \"no\"\n"
            f"    healthcheck:\n      start_period: 45s\n      retries: 12\n"
            f"  vault-redis:\n    container_name: {project}-redis\n    restart: \"no\"\n"
            f"  vault-api:\n    container_name: {project}-api\n"
            f"    image: {image}\n    build: !reset null\n    restart: \"no\"\n"
            f"    ports: !override\n      - \"127.0.0.1:{port}:8000\"\n"
            f"  vault-sftp:\n    container_name: {project}-sftp\n"
            f"    image: {image}\n    build: !reset null\n    restart: \"no\"\n"
            f"    ports: !override\n      - \"127.0.0.1:{port + 1}:2222\"\n")

    def compose(*args, timeout=900):
        return run(compose_command(project, workdir, "drill.override.yml") + list(args), cwd=workdir,
                   timeout=timeout)

    def wait_healthy(timeout=300):
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = run(["docker", "inspect", f"{project}-api", "--format", "{{.State.Health.Status}}"],
                        timeout=30).stdout.strip()
            if state in ("healthy", "unhealthy"):
                return state
            time.sleep(4)
        return "timeout"

    def psql(sql):
        out = run(["docker", "exec", f"{project}-db", "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                  timeout=60)
        assert out.returncode == 0, f"psql failed: {out.stderr[:300]}"
        return out.stdout.strip()

    def switch_to(image, where):
        override(image)
        up = compose("up", "-d")
        assert up.returncode == 0, f"{where} did not start: {up.stderr[-400:]}"
        assert wait_healthy() == "healthy", f"after {where} the deployment is not healthy"
        running = run(["docker", "inspect", f"{project}-api", "--format", "{{.Config.Image}}"], timeout=60)
        assert running.stdout.strip() == image, f"{where} left the deployment on {running.stdout.strip()}"

    override(candidate)
    volumes = stack_volumes(compose)
    refuse_volumes_in_use(volumes, project)
    try:
        up = compose("up", "-d")
        boot = wait_healthy() if up.returncode == 0 else "never started"
        if up.returncode != 0 or boot != "healthy":
            if host_cannot_take_a_stack(up):
                pytest.skip(f"this host cannot take another stack right now: {(up.stderr or '')[-300:]}")
            logs = compose("logs", "--no-color", "--tail", "60", timeout=120).stdout or ""
            pytest.fail(f"the candidate stack did not come up (api={boot}):\n{logs[-2000:]}")
        yield {"base": f"http://127.0.0.1:{port}", "env": env, "psql": psql, "switch_to": switch_to,
               "candidate": candidate}
    finally:
        tear_down(compose, volumes)


def _admin(state):
    client = ApiClient(base_url=state["base"])
    client.login(state["env"]["ADMIN_USERNAME"], state["env"]["ADMIN_PASSWORD"])
    return client


def _vault(client):
    r = post_zk(client, "/vaults", json={"name": f"zkrb_{uuid.uuid4().hex[:6]}", "type": "zero_knowledge",
                                         "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1,
                                         "wrapped_dek": ZK_WRAPPED_DEK_STUB,
                                         "ephemeral_public_key": ZK_EPHEMERAL_STUB})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _rotate(client, vid, frm, *member_ids):
    return post_zk(client, f"/ecc/vaults/{vid}/rekey", json={
        "from_version": frm, "to_version": frm + 1,
        "member_keys": [{"user_id": user_id, "wrapped_dek": ZK_WRAPPED_DEK_STUB,
                         "ephemeral_public_key": ZK_EPHEMERAL_STUB} for user_id in member_ids]})


def _share(client, vid, user_id):
    return post_zk(client, f"/ecc/vaults/{vid}/members", json={
        "user_id": user_id, "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB})


def test_a_rollback_strands_nothing_and_the_proofs_take_up_again(stack):
    psql = stack["psql"]
    admin = _admin(stack)
    admin.put("/settings", json={"zero_knowledge_enabled": True}).raise_for_status()
    ensure_ecc_keypair(admin)
    owner_id = harness.client_user_id(admin)
    people = []
    for _ in range(2 * len(ROLLBACK_TAGS)):
        made = admin.create_user(username=f"zkrb_{uuid.uuid4().hex[:8]}")
        client = ApiClient(base_url=stack["base"])
        client.login(made["_username"], made["_password"])
        ensure_ecc_keypair(client)
        people.append(made["id"])

    # --- 1. On the code under test ---
    rotated, legacy = _vault(admin), _vault(admin)
    doomed = {tag: _vault(admin) for tag in ROLLBACK_TAGS}
    dek = secrets.token_bytes(32)
    file_id = zk_chunked_upload(admin, rotated, "drill.bin", PAYLOAD, dek)
    assert _rotate(admin, rotated, 1, owner_id).status_code == 200
    psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{legacy}'")
    _, material = harness.direct_proof_material(legacy, 1)
    assert put_zk(admin, f"/ecc/vaults/{legacy}/key-proof", json=dict({"dek_epoch": 1}, **material)).status_code == 200
    rows = lambda vid: psql(f"SELECT coalesce(string_agg(dek_epoch || ':' || source, ',' ORDER BY dek_epoch), '') "
                            f"FROM vault_key_proofs WHERE vault_id = '{vid}'")
    assert (rows(rotated), rows(legacy)) == ("1:create,2:rotate", "1:bootstrap")
    assert [rows(doomed[tag]) for tag in ROLLBACK_TAGS] == ["1:create"] * len(ROLLBACK_TAGS)

    def reads(where):
        got = admin.get(f"/vaults/{rotated}/files/{file_id}/download")
        assert got.status_code == 200 and got.content == PAYLOAD, f"the file does not read after {where}"

    reads("the uploads")

    epoch, expected, members = 2, "1:create,2:rotate", [owner_id]
    for round_number, tag in enumerate(ROLLBACK_TAGS):
        sharer, legacy_sharer = people[2 * round_number], people[2 * round_number + 1]

        # --- 2. Rolled back ---
        stack["switch_to"](IMAGE % tag, f"the rollback to {tag}")
        admin = _admin(stack)
        reads(f"the rollback to {tag}")
        assert admin.get(f"/ecc/vaults/{rotated}/keys").json()["current_dek_version"] == epoch
        # An older server has no challenge route: the request goes without a proof and is taken.
        r = _rotate(admin, rotated, epoch, *members)
        assert r.zk_challenge_status == 404 and r.status_code == 200, r.text
        epoch += 1
        # Its proof rows are gone with the vault, by the database's own delete rule.
        assert admin.post(f"/vaults/{doomed[tag]}/delete").status_code == 200
        assert rows(doomed[tag]) == ""
        assert rows(rotated) == expected, "an older release changed proof rows it knows nothing of"

        # --- 3. Forward again ---
        stack["switch_to"](stack["candidate"], f"the return from {tag} to the code under test")
        admin = _admin(stack)
        reads(f"the return from {tag} to the code under test")
        keys = admin.get(f"/ecc/vaults/{rotated}/keys").json()
        assert keys["current_dek_version"] == epoch and keys["key_proof"] == {"state": "missing"}, keys
        # A change that proves the current key needs the epoch set up first...
        r = _share(admin, rotated, sharer)
        assert r.status_code == 428 and r.json()["reason"] == "zk-key-proof-setup-required", r.text
        _, material = harness.direct_proof_material(rotated, epoch)
        assert put_zk(admin, f"/ecc/vaults/{rotated}/key-proof",
                      json=dict({"dek_epoch": epoch}, **material)).status_code == 200
        assert _share(admin, rotated, sharer).status_code == 200
        # The key alone is half a share: until the access row exists, a rotation treats the key as left
        # over from an unfinished share and leaves its holder out. Finish it, so the next rollback rotates
        # the vault for a member added by the code under test.
        granted = admin.post(f"/vaults/{rotated}/permissions", json={"user_id": sharer, "level": "read"})
        assert granted.status_code in (200, 201), granted.text
        members.append(sharer)
        # ... the vault set up before the rollback still proves with its key ...
        assert _share(admin, legacy, legacy_sharer).status_code == 200
        # ... and a request without a proof is refused again.
        prepared = harness.prepare_zk(admin, f"/ecc/vaults/{legacy}/members", {
            "user_id": sharer, "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB})
        r = harness.send_prepared(admin, f"/ecc/vaults/{legacy}/members", prepared, header=None)
        assert r.status_code == 428 and r.json()["reason"] == "zk-key-proof-required", r.text
        expected += f",{epoch}:bootstrap"
        assert rows(rotated) == expected
    assert epoch == 2 + len(ROLLBACK_TAGS)
    reads("the whole walk")
