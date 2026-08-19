"""Same-name matching survives a rotation once the client sends per-epoch candidates.

The defect: a zero-knowledge name's blind index is keyed by (DEK, epoch), so after a rekey an
existing file's index sits at an OLD epoch. A new upload of the same name computes its index at the
NEW epoch, which cannot equal the stored one, so the server sees no clash — replace-on-clash
silently stops applying and `_reject_unreplaceable_upload` stops rejecting, and the vault ends up
with two rows sharing one visible name.

This is the server half of the fix (N2a): the upload accepts `name_bi_candidates`, a set the name
may match under, and matches the union at both the reject pre-check and the finalize replace. The
client half (computing the set from every epoch's DEK) is a separate increment; here the test plays
the client, sending the old-epoch index alongside the new one, exactly as the client will.

The first test is the reported failure, made to pass. The second pins that WITHOUT candidates the
old behaviour still stands — so the fix is opt-in and an old client is unaffected — which is also
the control proving the first test is exercising the candidates and not something else.
"""
import os
import subprocess
import uuid

import pytest

from conftest import (
    unique, ensure_ecc_keypair, create_zk_vault, zk_encrypt_name, zk_name_blind_index,
)

DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    try:
        proc = subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


def _rekey_to(admin, vid, from_v, to_v):
    """Advance the vault DEK epoch with the owner as the only remaining member."""
    def _stub(p):
        import base64
        return base64.b64encode(f"{p}-{uuid.uuid4().hex}".encode()).decode()
    r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
        "from_version": from_v, "to_version": to_v, "revoke_user_id": None,
        "member_keys": [{"user_id": str(admin.user["id"]),
                         "wrapped_dek": _stub("dek"), "ephemeral_public_key": _stub("eph")}],
    })
    r.raise_for_status()
    assert r.json()["dek_version"] == to_v


def _upload_named(admin, vid, name, dek, content, epoch, candidates=None):
    """A single-chunk ZK upload of a FIXED name at a given epoch, optionally sending the candidate
    match set. Returns the file id."""
    obj_id = str(uuid.uuid4())
    init = {
        "total_size": len(content), "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
        "zk_key_version": epoch,
        "enc_name": zk_encrypt_name(name, dek, vid, "name", epoch, obj_id=obj_id),
        "enc_mime": zk_encrypt_name("text/plain", dek, vid, "mime", epoch, obj_id=obj_id),
        "name_bi": zk_name_blind_index(name, dek, vid, epoch),
        "file_id": obj_id, "blob_id": uuid.uuid4().hex,
    }
    if candidates is not None:
        init["name_bi_candidates"] = candidates
    r = admin.post(f"/vaults/{vid}/uploads", json=init)
    r.raise_for_status()
    sid = r.json()["session_id"]
    admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=content,
              headers={"Content-Type": "application/octet-stream"}).raise_for_status()
    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete", json={"file_id": obj_id})
    done.raise_for_status()
    return done.json()["id"]


def _count_named(vid, name_bi_any):
    """How many File rows in the vault carry any of the given blind indices (i.e. this name)."""
    ids = "','".join(name_bi_any)
    return int(_psql(
        f"SELECT count(*) FROM files WHERE vault_id='{vid}' AND name_bi IN ('{ids}')"))


import contextlib


@contextlib.contextmanager
def _zk(client):
    before = client.get("/settings").json()
    client.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        client.put("/settings", json={
            "zero_knowledge_enabled": before.get("zero_knowledge_enabled", False)})


@pytest.fixture
def zk_vault(admin):
    ensure_ecc_keypair(admin)
    with _zk(admin):
        v = create_zk_vault(admin)
    yield v
    admin.delete_vault(v["id"])


def test_candidates_replace_a_pre_rotation_file_instead_of_duplicating_it(admin, zk_vault):
    """The reported failure, made to pass. Upload a name at epoch 1, rotate to epoch 2, upload the
    same name at epoch 2 sending BOTH epochs' indices as candidates. The epoch-1 row is replaced,
    not left beside a second row under a different index."""
    vid = zk_vault["id"]
    dek = os.urandom(32)
    name = unique("report") + ".txt"
    bi1 = zk_name_blind_index(name, dek, vid, 1)
    bi2 = zk_name_blind_index(name, dek, vid, 2)
    assert bi1 != bi2, "the two epochs must produce different indices, or there is nothing to fix"

    _upload_named(admin, vid, name, dek, b"epoch-1 content", epoch=1)
    assert _count_named(vid, [bi1, bi2]) == 1

    _rekey_to(admin, vid, 1, 2)

    # The client sends every epoch's candidate; the current-epoch value is the stored one.
    _upload_named(admin, vid, name, dek, b"epoch-2 content", epoch=2, candidates=[bi1, bi2])

    # Exactly one row for this name survives — the epoch-1 file was replaced, not duplicated.
    assert _count_named(vid, [bi1, bi2]) == 1, "the pre-rotation file was not replaced"
    # And it is the epoch-2 upload: the surviving row carries the epoch-2 index.
    surviving = _psql(
        f"SELECT name_bi FROM files WHERE vault_id='{vid}' AND name_bi IN ('{bi1}','{bi2}')")
    assert surviving == bi2, "the survivor should be the new (epoch-2) row"


def test_without_candidates_the_pre_rotation_file_is_still_missed(admin, zk_vault):
    """Control: the same sequence WITHOUT candidates reproduces the old behaviour — two rows under
    two indices. This is what proves the first test's pass is the candidates doing the work, and it
    pins that an old client (sending no candidates) is unaffected rather than silently changed."""
    vid = zk_vault["id"]
    dek = os.urandom(32)
    name = unique("memo") + ".txt"
    bi1 = zk_name_blind_index(name, dek, vid, 1)
    bi2 = zk_name_blind_index(name, dek, vid, 2)

    _upload_named(admin, vid, name, dek, b"epoch-1 content", epoch=1)
    _rekey_to(admin, vid, 1, 2)
    _upload_named(admin, vid, name, dek, b"epoch-2 content", epoch=2)  # no candidates

    # Two rows, one per epoch's index — the duplicate the candidate path prevents.
    assert _count_named(vid, [bi1, bi2]) == 2, "without candidates the clash should be missed"
