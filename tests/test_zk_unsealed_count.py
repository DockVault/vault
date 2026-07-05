"""Operator migration signal: GET /zk/unsealed counts UNSEALED zero-knowledge name rows.

An unsealed row is a ZK file/folder whose enc_name is absent or not a client-sealed 'zk1:' blob —
leftover cleartext metadata from before client-side name sealing was enforced. The read guards
already mask such rows from being served; this endpoint lets an operator see whether any remain
(a re-seal to-do list). Admin-only.
"""
import contextlib
import os
import subprocess

import pytest

from conftest import create_zk_vault, zk_chunked_upload, ApiClient


@contextlib.contextmanager
def _zk_on(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _db_mutate(sql: str):
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


def test_zk_unsealed_count_detects_a_legacy_row(admin):
    """A sealed ZK upload is NOT counted; unsealing its name (simulating a pre-sealing legacy row)
    increments files_unsealed by exactly one and flags the vault as affected."""
    dek = os.urandom(32)
    vid = None
    try:
        with _zk_on(admin):
            v = create_zk_vault(admin)
            vid = v["id"]
            fid = zk_chunked_upload(admin, vid, "secret.txt", b"hello zk world", dek)
        base = admin.get("/zk/unsealed").json()
        assert set(base) >= {"zk_vaults", "files_unsealed", "folders_unsealed", "vaults_affected"}
        assert base["zk_vaults"] >= 1

        # Unseal the row: drop its client-sealed enc_name (as a legacy pre-sealing file would look).
        _db_mutate(f"UPDATE files SET enc_name = NULL WHERE id = '{fid}';")
        after = admin.get("/zk/unsealed").json()
        assert after["files_unsealed"] == base["files_unsealed"] + 1
        assert after["vaults_affected"] >= 1

        # Re-seal it back (with a marker blob) — no longer counted.
        _db_mutate(f"UPDATE files SET enc_name = 'zk1:reformatted' WHERE id = '{fid}';")
        healed = admin.get("/zk/unsealed").json()
        assert healed["files_unsealed"] == base["files_unsealed"]
    finally:
        if vid:
            admin.delete_vault(vid)


def test_zk_unsealed_count_is_admin_only(admin, temp_user, temp_user_client):
    assert temp_user_client.get("/zk/unsealed").status_code == 403
    assert admin.get("/zk/unsealed").status_code == 200
