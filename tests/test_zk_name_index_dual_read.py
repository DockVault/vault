"""Same-name matching survives a rotation once the client sends per-epoch candidates.

The defect: a zero-knowledge name's blind index is keyed by (DEK, epoch), so after a rekey an
existing file's index sits at an OLD epoch. A new upload of the same name computes its index at the
NEW epoch, which cannot equal the stored one, so the server sees no clash — replace-on-clash
silently stops applying and `_reject_unreplaceable_upload` stops rejecting, and the vault ends up
with two rows sharing one visible name.

This is the server half of the fix: the upload accepts `name_bi_candidates`, a set the name
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


# --- rename and folder-create also match against the candidate set --------------------------

def _rename(admin, vid, fid, name, dek, epoch, candidates=None, key_version=None):
    body = {
        "enc_name": zk_encrypt_name(name, dek, vid, "name", epoch, obj_id=fid),
        "name_bi": zk_name_blind_index(name, dek, vid, epoch),
    }
    if candidates is not None:
        body["name_bi_candidates"] = candidates
    if key_version is not None:
        body["name_key_version"] = key_version
    return admin.put(f"/vaults/{vid}/files/{fid}/rename", json=body)


def test_rename_into_a_pre_rotation_name_is_caught_with_candidates(admin, zk_vault):
    """Renaming a file INTO a name that exists only at an OLD epoch must be rejected as a clash.
    Without candidates the old-epoch row is missed and the rename wrongly succeeds -- two files with
    one visible name. This is the rename counterpart of the upload defect."""
    vid = zk_vault["id"]
    dek = os.urandom(32)
    keep = unique("keep") + ".txt"           # exists from epoch 1
    other = unique("other") + ".txt"         # uploaded at epoch 2, then renamed to `keep`
    keep_bi1 = zk_name_blind_index(keep, dek, vid, 1)
    keep_bi2 = zk_name_blind_index(keep, dek, vid, 2)

    _upload_named(admin, vid, keep, dek, b"the original keep", epoch=1)
    _rekey_to(admin, vid, 1, 2)
    other_id = _upload_named(admin, vid, other, dek, b"a second file", epoch=2)

    # With candidates covering epoch 1, renaming `other` -> `keep` is caught (400/409).
    r = _rename(admin, vid, other_id, keep, dek, epoch=2, candidates=[keep_bi1, keep_bi2])
    assert r.status_code in (400, 409), f"clash should be rejected, got {r.status_code}: {r.text}"

    # The vault still has exactly one row named `keep` (the rename was refused).
    assert _count_named(vid, [keep_bi1, keep_bi2]) == 1, "the rename must not have created a duplicate"


def test_rename_without_candidates_still_misses_the_pre_rotation_name(admin, zk_vault):
    """Control: the same rename WITHOUT candidates misses the old-epoch row and succeeds, proving
    the candidates do the work and that an old client is unchanged."""
    vid = zk_vault["id"]
    dek = os.urandom(32)
    keep = unique("keepc") + ".txt"
    other = unique("otherc") + ".txt"
    keep_bi1 = zk_name_blind_index(keep, dek, vid, 1)

    _upload_named(admin, vid, keep, dek, b"original", epoch=1)
    _rekey_to(admin, vid, 1, 2)
    other_id = _upload_named(admin, vid, other, dek, b"second", epoch=2)

    r = _rename(admin, vid, other_id, keep, dek, epoch=2)  # no candidates
    assert r.status_code == 200, r.text
    # Two rows now answer to `keep` (its epoch-1 and epoch-2 indices) -- the missed clash.
    assert _count_named(vid, [keep_bi1, zk_name_blind_index(keep, dek, vid, 2)]) == 2


def _create_folder(admin, vid, name, dek, epoch, candidates=None):
    fid = str(uuid.uuid4())
    body = {
        "id": fid,
        "enc_name": zk_encrypt_name(name, dek, vid, "name", epoch, obj_id=fid),
        "name_bi": zk_name_blind_index(name, dek, vid, epoch),
        "name_key_version": epoch,
    }
    if candidates is not None:
        body["name_bi_candidates"] = candidates
    return admin.post(f"/vaults/{vid}/folders", json=body)


def test_folder_create_into_a_pre_rotation_name_is_caught_with_candidates(admin, zk_vault):
    """Creating a folder whose name already exists only at an OLD epoch must be rejected. Without
    candidates the old-epoch folder is missed and a duplicate-named folder is created."""
    vid = zk_vault["id"]
    dek = os.urandom(32)
    name = unique("docs")
    bi1 = zk_name_blind_index(name, dek, vid, 1)
    bi2 = zk_name_blind_index(name, dek, vid, 2)

    assert _create_folder(admin, vid, name, dek, epoch=1).status_code == 200
    _rekey_to(admin, vid, 1, 2)

    # With candidates: the epoch-1 folder is seen, the duplicate create is rejected.
    r = _create_folder(admin, vid, name, dek, epoch=2, candidates=[bi1, bi2])
    assert r.status_code in (400, 409), f"duplicate folder should be rejected, got {r.status_code}: {r.text}"

    # Without candidates: the clash is missed and a second same-name folder is created.
    r2 = _create_folder(admin, vid, name, dek, epoch=2)
    assert r2.status_code == 200, r2.text


def test_folder_create_rejects_an_oversized_candidate_list_cleanly(admin, zk_vault):
    """A candidate list over the 64 cap is a clean 400, not a 500. The rename and upload paths get
    this from a Pydantic max_length; the folder-create endpoint takes a raw dict, so it enforces
    the same bound by hand -- without it, an oversized list becomes one SQL bind parameter per
    element and the clash query fails past Postgres's limit (a 500 and an amplification lever)."""
    vid = zk_vault["id"]
    dek = os.urandom(32)
    name = unique("bounded")
    fid = str(uuid.uuid4())
    huge = [zk_name_blind_index(f"{name}-{i}", dek, vid, 1) for i in range(65)]
    r = admin.post(f"/vaults/{vid}/folders", json={
        "id": fid,
        "enc_name": zk_encrypt_name(name, dek, vid, "name", 1, obj_id=fid),
        "name_bi": zk_name_blind_index(name, dek, vid, 1),
        "name_bi_candidates": huge,
        "name_key_version": 1,
    })
    assert r.status_code == 400, f"an oversized candidate list must be a clean 400, got {r.status_code}: {r.text}"
    # And a list at the cap (64) is still accepted.
    ok = admin.post(f"/vaults/{vid}/folders", json={
        "id": str(uuid.uuid4()),
        "enc_name": zk_encrypt_name(unique("okname"), dek, vid, "name", 1, obj_id=fid),
        "name_bi": zk_name_blind_index(unique("okname2"), dek, vid, 1),
        "name_bi_candidates": huge[:64],
        "name_key_version": 1,
    })
    assert ok.status_code == 200, ok.text
