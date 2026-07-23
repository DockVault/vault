"""Zero-knowledge name AAD binds the object id (v2) — anti-transposition.

A v1 (zk1:) sealed name binds only vault|field|epoch, so an operator with DB write can SWAP the
enc_name of two same-vault/same-epoch objects and the client decrypts the swapped value with no
error. v2 (zk2:) ALSO binds the object id, so a swapped blob fails to decrypt under its new row's
id (GCM auth). These prove v2 rejects the swap AND (control) that v1 did not — additive: both
formats coexist, existing v1 rows stay readable.
"""
import contextlib
import os
import subprocess
import uuid

import pytest

from conftest import (create_zk_vault, ensure_ecc_keypair, unique, zk_chunked_upload,
                      zk_encrypt_name, zk_name_blind_index, zk_decrypt_name)

# Env-overridable so the suite can be pointed at a second stack instead of silently
# targeting whatever "vault-db" happens to be running.
DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    try:
        p = subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert p.returncode == 0, f"psql failed: {p.stderr}"
    return p.stdout.strip()


@contextlib.contextmanager
def _zk_on(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _create_zk_folder(admin, vid, dek, name, folder_id, epoch=1):
    r = admin.post(f"/vaults/{vid}/folders", json={
        "id": folder_id,
        "enc_name": zk_encrypt_name(name, dek, vid, "name", epoch, obj_id=folder_id),
        "name_bi": zk_name_blind_index(name, dek, vid, epoch),
        "name_key_version": epoch,
    })
    assert r.status_code == 200, r.text
    return r.json()["folder"]["id"]


def test_zk_v2_file_name_not_transposable(admin):
    """Two files uploaded with client ids (v2). Swapping their enc_name makes each undecryptable
    under its own row id — the transposition is rejected."""
    ensure_ecc_keypair(admin)
    with _zk_on(admin):
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
    try:
        dek = os.urandom(32)
        fid_a, fid_b = str(uuid.uuid4()), str(uuid.uuid4())
        name_a, name_b = unique("A"), unique("B")
        got_a = zk_chunked_upload(admin, vid, name_a, b"a" * 16, dek, epoch=1, file_id=fid_a)
        got_b = zk_chunked_upload(admin, vid, name_b, b"b" * 16, dek, epoch=1, file_id=fid_b)
        assert got_a == fid_a and got_b == fid_b, "server must honour the client-supplied file ids"

        enc_a = _psql(f"SELECT enc_name FROM files WHERE id='{fid_a}'")
        enc_b = _psql(f"SELECT enc_name FROM files WHERE id='{fid_b}'")
        assert enc_a.startswith("zk2:") and enc_b.startswith("zk2:"), (enc_a, enc_b)
        # each decrypts correctly IN PLACE
        assert zk_decrypt_name(enc_a, dek, vid, "name", 1, obj_id=fid_a) == name_a
        assert zk_decrypt_name(enc_b, dek, vid, "name", 1, obj_id=fid_b) == name_b

        # TRANSPOSE the two blobs in the DB, RE-READ the stored (now-swapped) values, and decrypt
        # each with its OWN row id -> FAILS (the swap actually landed + is rejected at rest).
        _psql(f"UPDATE files SET enc_name='{enc_b}' WHERE id='{fid_a}'")
        _psql(f"UPDATE files SET enc_name='{enc_a}' WHERE id='{fid_b}'")
        stored_a = _psql(f"SELECT enc_name FROM files WHERE id='{fid_a}'")
        stored_b = _psql(f"SELECT enc_name FROM files WHERE id='{fid_b}'")
        assert stored_a == enc_b and stored_b == enc_a, "the DB swap did not land"
        with pytest.raises(Exception):
            zk_decrypt_name(stored_a, dek, vid, "name", 1, obj_id=fid_a)  # B's blob now on A's row
        with pytest.raises(Exception):
            zk_decrypt_name(stored_b, dek, vid, "name", 1, obj_id=fid_b)  # A's blob now on B's row
    finally:
        admin.delete_vault(vid)


def test_zk_v2_folder_name_not_transposable(admin):
    """The folder-create path binds the client folder id (v2) too — same anti-transposition."""
    ensure_ecc_keypair(admin)
    with _zk_on(admin):
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
    try:
        dek = os.urandom(32)
        fa, fb = str(uuid.uuid4()), str(uuid.uuid4())
        na, nb = unique("dirA"), unique("dirB")
        assert _create_zk_folder(admin, vid, dek, na, fa) == fa
        assert _create_zk_folder(admin, vid, dek, nb, fb) == fb
        ea = _psql(f"SELECT enc_name FROM folders WHERE id='{fa}'")
        eb = _psql(f"SELECT enc_name FROM folders WHERE id='{fb}'")
        assert ea.startswith("zk2:") and eb.startswith("zk2:")
        _psql(f"UPDATE folders SET enc_name='{eb}' WHERE id='{fa}'")
        stored = _psql(f"SELECT enc_name FROM folders WHERE id='{fa}'")
        assert stored == eb, "the DB swap did not land"
        with pytest.raises(Exception):
            zk_decrypt_name(stored, dek, vid, "name", 1, obj_id=fa)  # B's blob now on A's row
    finally:
        admin.delete_vault(vid)


def test_zk_v1_name_is_transposable_control(admin):
    """CONTROL: a v1 (legacy, unbound) name IS transposable — the vulnerability v2 closes. Upload
    two files WITHOUT client ids (v1) and show the swapped blob still decrypts under the wrong id."""
    ensure_ecc_keypair(admin)
    with _zk_on(admin):
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
    try:
        dek = os.urandom(32)
        name_a, name_b = unique("va"), unique("vb")
        fid_a = zk_chunked_upload(admin, vid, name_a, b"a" * 16, dek, epoch=1)   # no file_id -> v1
        fid_b = zk_chunked_upload(admin, vid, name_b, b"b" * 16, dek, epoch=1)
        enc_a = _psql(f"SELECT enc_name FROM files WHERE id='{fid_a}'")
        enc_b = _psql(f"SELECT enc_name FROM files WHERE id='{fid_b}'")
        assert enc_a.startswith("zk1:") and enc_b.startswith("zk1:")
        # v1 ignores obj_id, so B's blob decrypts as B's name regardless of the row it's placed on
        assert zk_decrypt_name(enc_b, dek, vid, "name", 1, obj_id=fid_a) == name_b
    finally:
        admin.delete_vault(vid)
