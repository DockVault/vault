"""Zero-knowledge name-seal writers serialize against DEK-version retire (R6-06 TOCTOU).

retire_dek_versions holds a Vault-row lock while it scans file/folder epochs and deletes the
member keys below the floor. The ZK name-seal writers (folder-create, rename) read the seal
epoch and write under it; if they don't take the SAME Vault-row lock, a name sealed at an old
epoch can land in retire's scan->delete window and lose its member key -> a permanently
undecryptable name. The fix takes `Vault ... with_for_update()` on the ZK path before using the
seal epoch (same lock order as retire + upload-complete).

The serialization tests are DETERMINISTIC: they hold a `FOR KEY SHARE` lock on the vault row and
time a ZK seal write. The fix acquires `FOR UPDATE` (which CONFLICTS with FOR KEY SHARE) so the
write BLOCKS; WITHOUT the fix the path only takes the FK's own FOR KEY SHARE (which COEXISTS with
the held one) so it returns immediately. So these are red on unfixed code.
"""
import contextlib
import os
import subprocess
import time

import pytest

from conftest import (create_zk_vault, ensure_ecc_keypair, unique, zk_chunked_upload,
                      zk_encrypt_name, zk_name_blind_index)

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOLD = 4  # seconds the detached psql holds the vault-row lock
# Env-overridable so the suite can be pointed at a second stack instead of silently
# targeting whatever "vault-db" happens to be running.
DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


@contextlib.contextmanager
def _zk_on(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _assert_blocks_on_vault_lock(vid, fire):
    """Hold a FOR KEY SHARE lock on the vault row for _HOLD s, then run `fire()` (which performs a
    ZK seal write) and assert it BLOCKED — i.e. the seal path took FOR UPDATE (serialized with
    retire). `fire` must return the HTTP response. Skips cleanly if docker/psql is absent."""
    sql = (f"BEGIN; SELECT id FROM vaults WHERE id='{vid}' FOR KEY SHARE; "
           f"SELECT pg_sleep({_HOLD}); COMMIT;")
    try:
        holder = subprocess.Popen(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    try:
        time.sleep(1.0)  # let the holder acquire the FOR KEY SHARE lock
        t0 = time.time()
        r = fire()
        elapsed = time.time() - t0
        assert r.status_code == 200, r.text
        assert elapsed >= 2.0, (
            f"ZK seal write did NOT block on the held vault lock (took {elapsed:.2f}s) — its "
            "seal-epoch read/write is not serialized (FOR UPDATE) against retire")
    finally:
        holder.wait(timeout=_HOLD + 5)


def test_zk_folder_create_serializes_with_retire(admin):
    """create_folder's ZK seal path takes the Vault FOR UPDATE lock (serializes with retire)."""
    ensure_ecc_keypair(admin)
    with _zk_on(admin):
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
    try:
        dek = os.urandom(32)
        name = unique("dir")
        payload = {"enc_name": zk_encrypt_name(name, dek, vid, "name", 1),
                   "name_bi": zk_name_blind_index(name, dek, vid, 1), "name_key_version": 1}
        _assert_blocks_on_vault_lock(vid, lambda: admin.post(f"/vaults/{vid}/folders", json=payload))
    finally:
        admin.delete_vault(vid)


def test_zk_rename_serializes_with_retire(admin):
    """rename_file's ZK seal path takes the Vault FOR UPDATE lock (serializes with retire) —
    the rename counterpart to the folder-create test, closing the two edited paths symmetrically."""
    ensure_ecc_keypair(admin)
    with _zk_on(admin):
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
    try:
        dek = os.urandom(32)
        fid = zk_chunked_upload(admin, vid, unique("orig") + ".txt", b"x" * 16, dek, epoch=1)
        newname = unique("ren") + ".txt"
        payload = {"enc_name": zk_encrypt_name(newname, dek, vid, "name", 1),
                   "name_bi": zk_name_blind_index(newname, dek, vid, 1)}
        _assert_blocks_on_vault_lock(
            vid, lambda: admin.put(f"/vaults/{vid}/files/{fid}/rename", json=payload))
    finally:
        admin.delete_vault(vid)


def test_zk_seal_writers_hold_vault_lock():
    """Source guard: both ZK name-seal writers take the Vault row lock before using the seal
    epoch (so a regression removing it fails here too, even without a live race)."""
    src = open(os.path.join(_APP_DIR, "app/api/api_server.py"), encoding="utf-8").read()
    for fn in ("def create_folder", "def rename_file"):
        start = src.index(fn)
        body = src[start:src.index("\n@app.", start + 1)] if "\n@app." in src[start:] else src[start:start + 6000]
        # The lock must appear BEFORE the seal-epoch "ahead of the vault" check it protects.
        assert "with_for_update()" in body, f"{fn} no longer takes the Vault row lock on the ZK seal path"
        assert body.index("with_for_update()") < body.index("ahead of the vault"), \
            f"{fn}: the Vault lock must precede the seal-epoch check"
