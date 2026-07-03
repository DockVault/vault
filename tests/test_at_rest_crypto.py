"""At-rest crypto: AES-GCM chunked stream with per-chunk AAD + legacy back-compat.

Two layers:

* test_upload_download_roundtrip_binary (always on, HTTP) - a multi-MB binary
  round-trips byte-for-byte through the new AES-GCM chunked writer/reader.

* test_at_rest_crypto_layer (docker-exec into vault-api) - exercises the crypto
  module directly (the HTTP harness can't write a legacy-format file or read
  at-rest bytes). Proves: GCM chunk-stream round-trip; format auto-detection;
  AAD binding rejects a blob swapped in from another file OR vault; reordered
  chunks are rejected; and the LEGACY Fernet chunk stream still decrypts
  (backward compatibility). Skips cleanly if docker / the container is absent.
"""
import hashlib
import os
import subprocess

import pytest

from conftest import unique


def test_upload_download_roundtrip_binary(admin, temp_vault):
    """A few MB of binary (multi-chunk) survives the new at-rest format intact."""
    vid = temp_vault["id"]
    content = bytes((i * 31 + 11) % 256 for i in range(3 * 1024 * 1024))  # ~3 MB
    name = unique("blob") + ".bin"

    r = admin.post(
        f"/vaults/{vid}/files",
        files=[("files", (name, content, "application/octet-stream"))],
    )
    assert r.status_code == 200, r.text
    file_id = r.json()["files"][0]["id"]

    r = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert r.status_code == 200
    assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(content).hexdigest()


# In-container self-test of the crypto module. Run with `docker exec -i <c> python -`.
_CRYPTO_SELFTEST = r'''
import os, struct, tempfile, uuid
import security as S

vid, fid = uuid.uuid4(), uuid.uuid4()
data = bytes((i * 5 + 1) % 256 for i in range(200003))  # not chunk-aligned
parts = [data[0:80000], data[80000:160000], data[160000:]]

# --- new AES-GCM chunked stream: write, detect, round-trip ---
codec = S.GcmChunkStreamCodec(vid, fid)
buf = bytearray(codec.header())
for i, p in enumerate(parts):
    buf += codec.encrypt(p, i)
gcm_path = tempfile.mktemp()
with open(gcm_path, "wb") as f:
    f.write(buf)
assert S.is_gcm_chunk_stream(gcm_path), "GCM stream not detected"
with open(gcm_path, "rb") as f:
    assert S.decrypt_gcm_chunk_stream(f, vid, fid) == data, "GCM round-trip mismatch"

# --- AAD binding: wrong file_id and wrong vault_id must both fail ---
for bad_vid, bad_fid, label in [(vid, uuid.uuid4(), "file"), (uuid.uuid4(), fid, "vault")]:
    try:
        with open(gcm_path, "rb") as f:
            S.decrypt_gcm_chunk_stream(f, bad_vid, bad_fid)
        raise SystemExit("FAIL: decrypted with wrong %s id (AAD not enforced)" % label)
    except S.EncryptionError:
        pass

# --- chunk reorder must fail (index is in the AAD) ---
hdr_len = len(S._GCM_STREAM_HEADER)
body, recs, i = bytes(buf)[hdr_len:], [], 0
while i < len(body):
    n = struct.unpack(">I", body[i:i+4])[0]; i += 4
    recs.append(body[i:i+n]); i += n
recs[0], recs[1] = recs[1], recs[0]
swapped = bytearray(bytes(buf)[:hdr_len])
for r in recs:
    swapped += struct.pack(">I", len(r)) + r
sp = tempfile.mktemp()
with open(sp, "wb") as f:
    f.write(swapped)
try:
    with open(sp, "rb") as f:
        S.decrypt_gcm_chunk_stream(f, vid, fid)
    raise SystemExit("FAIL: reordered chunks decrypted")
except S.EncryptionError:
    pass

# --- legacy Fernet chunk stream: still detected-as-not-GCM and still decrypts ---
fbuf = bytearray()
for p in parts:
    fbuf += S.encrypt_chunk(p)
fp = tempfile.mktemp()
with open(fp, "wb") as f:
    f.write(fbuf)
assert not S.is_gcm_chunk_stream(fp), "Fernet stream misdetected as GCM"
with open(fp, "rb") as f:
    assert b"".join(S.decrypt_chunk_stream(f)) == data, "legacy Fernet round-trip mismatch"

for p in (gcm_path, sp, fp):
    try: os.remove(p)
    except OSError: pass
print("ALL_OK")
'''


def test_filename_roundtrip_unicode(admin, temp_vault):
    """A file with a unicode/spaced name survives the at-rest name encryption: it lists
    and downloads under the exact original name (proves the transparent decrypt path)."""
    vid = temp_vault["id"]
    name = unique("rsum") + " éçà 文件.txt"  # spaces + non-ASCII
    content = b"name-encryption round-trip\n" * 20

    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code == 200, r.text
    file_id = r.json()["files"][0]["id"]

    items = admin.get(f"/vaults/{vid}/files").json()["items"]
    listed = next(it for it in items if it["id"] == file_id)
    assert listed["name"] == name, f"listed name {listed['name']!r} != {name!r}"

    r = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert r.status_code == 200 and r.content == content


# ---- at-rest plaintext-NULL checks (need a DB peek the HTTP API can't give) ----
def _db_scalar(sql):
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


def _db_run(sql):
    """Run SQL and return the CompletedProcess WITHOUT asserting success — for tests that
    expect a failure (e.g. a unique-constraint violation)."""
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    try:
        return subprocess.run(
            ["docker", "exec", container, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")


def test_filename_not_plaintext_at_rest(admin, temp_vault):
    """After upload to a Standard vault, the files row stores NO plaintext name/MIME —
    only the encrypted blobs + blind index."""
    vid = temp_vault["id"]
    sentinel = unique("SENTINEL")
    name = sentinel + ".txt"
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"x" * 64, "text/plain"))])
    assert r.status_code == 200, r.text
    fid = r.json()["files"][0]["id"]

    row = _db_scalar(
        "SELECT coalesce(original_name,'') || '|' || coalesce(\"name\",'') || '|' || "
        "(enc_name IS NOT NULL)::text || '|' || (enc_mime IS NOT NULL)::text || '|' || "
        f"(name_bi IS NOT NULL)::text FROM files WHERE id='{fid}'"
    )
    plain_orig, plain_name, has_enc_name, has_enc_mime, has_bi = row.split("|")
    assert plain_orig == "" and plain_name == "", f"plaintext name still at rest: {row!r}"
    assert sentinel not in row  # the sentinel must not appear in any plaintext column
    assert has_enc_name == "true" and has_enc_mime == "true" and has_bi == "true", row


def test_folder_name_not_plaintext_at_rest(admin, temp_vault):
    """Folder names are encrypted at rest too, and still list under their plaintext name."""
    vid = temp_vault["id"]
    fname = unique("SECRETDIR")
    r = admin.post(f"/vaults/{vid}/folders", json={"name": fname})
    assert r.status_code == 200, r.text
    folder_id = r.json()["folder"]["id"]

    row = _db_scalar(
        "SELECT coalesce(\"name\",'') || '|' || (enc_name IS NOT NULL)::text || '|' || "
        f"(name_bi IS NOT NULL)::text FROM folders WHERE id='{folder_id}'"
    )
    plain_name, has_enc_name, has_bi = row.split("|")
    assert plain_name == "" and fname not in row, f"plaintext folder name at rest: {row!r}"
    assert has_enc_name == "true" and has_bi == "true", row

    # still visible under its real name in the listing
    items = admin.get(f"/vaults/{vid}/files").json()["items"]
    assert any(it["id"] == folder_id and it["name"] == fname for it in items)


def test_audit_details_has_no_plaintext_filename(admin, temp_vault):
    """The upload audit record must not carry the plaintext filename (it would leave the
    name at rest in audit_logs one table over). resource_id still identifies the file."""
    vid = temp_vault["id"]
    sentinel = unique("AUDITSENT")
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (sentinel + ".txt", b"y" * 32, "text/plain"))])
    assert r.status_code == 200, r.text
    fid = r.json()["files"][0]["id"]
    hits = _db_scalar(
        f"SELECT count(*) FROM audit_logs WHERE resource_id='{fid}' AND details::text LIKE '%{sentinel}%'"
    )
    assert hits == "0", f"plaintext filename leaked into audit_logs.details for {fid}"


def test_chunked_session_row_removed_after_complete(admin, temp_vault):
    """A completed resumable-upload session must be deleted (it held the plaintext
    filename/MIME as working state); leaving it would persist the name at rest."""
    vid = temp_vault["id"]
    data = b"z" * 4096
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("chk") + ".bin", "total_size": len(data),
        "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
    })
    sid = r.json()["session_id"]
    admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=data,
              headers={"Content-Type": "application/octet-stream"})
    assert admin.post(f"/vaults/{vid}/uploads/{sid}/complete").status_code == 200
    cnt = _db_scalar(f"SELECT count(*) FROM chunked_upload_sessions WHERE id='{sid}'")
    assert cnt == "0", f"completed chunked session row still present (plaintext name lingers): {sid}"


@pytest.mark.skipif(
    os.environ.get("VAULT_SKIP_DOCKER_TESTS") in ("1", "true", "yes"),
    reason="docker-exec crypto self-test disabled via VAULT_SKIP_DOCKER_TESTS",
)
def test_at_rest_crypto_layer():
    """Exercise the at-rest crypto module inside the running container."""
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "python", "-"],
            input=_CRYPTO_SELFTEST, capture_output=True, text=True,
            # The container prints a non-ASCII startup banner; force UTF-8 decoding
            # with replacement so Windows' default cp1252 codec can't crash the read.
            encoding="utf-8", errors="replace", timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable for in-container crypto test: {exc}")
    assert "ALL_OK" in proc.stdout, (
        f"crypto self-test failed (rc={proc.returncode})\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# Gap #1 (verification regression): a PASSWORD-protected Standard vault must also
# store its names encrypted at rest. Name keys derive from the deployment secret (the
# vault password is only an access gate), so the eager backfill/seal applies to password
# vaults exactly like password-less ones — names are NEVER left plaintext in the DB. This
# locks that property in so a future change can't silently regress password vaults to
# plaintext names. (The server CAN still decrypt them with the deployment key, which is the
# intended Standard-vault posture; server-blind names are the ZK tier, tested elsewhere.)
# ---------------------------------------------------------------------------
def test_password_vault_filename_not_plaintext_at_rest(admin, temp_vault_pw):
    vid = temp_vault_pw["id"]
    pw = temp_vault_pw["_password"]
    hdr = {"X-Vault-Password": pw}
    sentinel = unique("PWSENTINEL")
    name = sentinel + ".txt"
    content = b"password-vault at-rest name check\n" * 8

    r = admin.post(f"/vaults/{vid}/files",
                   files=[("files", (name, content, "text/plain"))], headers=hdr)
    assert r.status_code == 200, r.text
    fid = r.json()["files"][0]["id"]

    # At rest: no plaintext name/MIME; enc blobs + blind index present.
    row = _db_scalar(
        "SELECT coalesce(original_name,'') || '|' || coalesce(\"name\",'') || '|' || "
        "(enc_name IS NOT NULL)::text || '|' || (enc_mime IS NOT NULL)::text || '|' || "
        f"(name_bi IS NOT NULL)::text FROM files WHERE id='{fid}'"
    )
    plain_orig, plain_name, has_enc_name, has_enc_mime, has_bi = row.split("|")
    assert plain_orig == "" and plain_name == "", f"plaintext name at rest in password vault: {row!r}"
    assert sentinel not in row, f"sentinel leaked into a plaintext column: {row!r}"
    assert has_enc_name == "true" and has_enc_mime == "true" and has_bi == "true", row

    # The server still decrypts the name for a download (deployment-key, password gates the
    # request): the round-trip content matches AND the real name comes back in the header.
    r = admin.get(f"/vaults/{vid}/files/{fid}/download", headers=hdr)
    assert r.status_code == 200 and r.content == content
    assert sentinel in r.headers.get("content-disposition", ""), r.headers.get("content-disposition")


# ---------------------------------------------------------------------------
# Gap #2: DB-level uniqueness on (vault_id, folder_id, name_bi) — dedup is no longer
# app-logic-only. Covers: the partial unique index exists; same-name re-upload REPLACES
# (no duplicate, no 500); the DB rejects a raw duplicate insert (incl. the NULL-folder
# root case via the COALESCE sentinel); duplicate folder creation is a clean 409.
# ---------------------------------------------------------------------------
def test_files_name_unique_index_exists():
    got = _db_scalar(
        "SELECT count(*) FROM pg_indexes WHERE indexname IN "
        "('uq_files_vault_folder_name_bi','uq_folders_vault_parent_name_bi')"
    )
    assert got == "2", f"expected both name unique indexes to exist, found {got}"


def test_duplicate_name_upload_replaces_not_duplicates(admin, temp_vault):
    """Re-uploading the same name REPLACES the prior file (one row survives, newest content)
    rather than 500ing against the unique index or leaving a duplicate row."""
    vid = temp_vault["id"]
    name = unique("dup") + ".bin"

    r1 = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"AAAA", "application/octet-stream"))])
    assert r1.status_code == 200, r1.text
    r2 = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"BBBBBB", "application/octet-stream"))])
    assert r2.status_code == 200, r2.text
    fid2 = r2.json()["files"][0]["id"]

    items = [it for it in admin.get(f"/vaults/{vid}/files").json()["items"]
             if it.get("type") != "folder" and it["name"] == name]
    assert len(items) == 1, f"expected exactly one '{name}' after replace, got {len(items)}: {items}"
    assert items[0]["id"] == fid2, "the surviving row should be the most recent upload"

    dl = admin.get(f"/vaults/{vid}/files/{fid2}/download")
    assert dl.status_code == 200 and dl.content == b"BBBBBB"

    # At rest there is exactly one row for this (vault, name_bi) — the index held.
    cnt = _db_scalar(
        f"SELECT count(*) FROM files WHERE vault_id='{vid}' AND name_bi="
        f"(SELECT name_bi FROM files WHERE id='{fid2}')"
    )
    assert cnt == "1", f"duplicate same-name rows at rest: {cnt}"


def test_duplicate_name_bi_insert_rejected_by_db(admin, temp_vault):
    """A raw INSERT of a second row with the same (vault_id, folder_id, name_bi) must be
    rejected by the partial unique index — proving dedup is enforced by the DB, not only by
    app logic. The file is uploaded at the vault ROOT (folder_id NULL), so this also proves
    the COALESCE-sentinel folds NULL folder_id (Postgres would otherwise treat NULLs as
    distinct and allow the duplicate)."""
    vid = temp_vault["id"]
    name = unique("uniq") + ".bin"
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"x" * 32, "application/octet-stream"))])
    assert r.status_code == 200, r.text
    fid = r.json()["files"][0]["id"]

    # Copy the row (new id + distinct storage_path) keeping the same vault/folder/name_bi.
    proc = _db_run(
        "INSERT INTO files (id, vault_id, folder_id, name_bi, size_bytes, checksum_sha256, "
        "storage_path, is_encrypted, enc_name, enc_mime, created_at, updated_at) "
        "SELECT gen_random_uuid(), vault_id, folder_id, name_bi, size_bytes, checksum_sha256, "
        "storage_path || '-dup', is_encrypted, enc_name, enc_mime, now(), now() "
        f"FROM files WHERE id='{fid}'"
    )
    assert proc.returncode != 0, "duplicate (vault_id, folder_id, name_bi) insert was NOT rejected"
    blob = (proc.stderr + proc.stdout).lower()
    assert "duplicate key" in blob or "unique" in blob, f"unexpected failure (not a unique violation): {proc.stderr}"

    # And the duplicate did not land.
    cnt = _db_scalar(
        f"SELECT count(*) FROM files WHERE vault_id='{vid}' AND name_bi="
        f"(SELECT name_bi FROM files WHERE id='{fid}')"
    )
    assert cnt == "1", f"a duplicate row leaked despite the unique index: {cnt}"


def test_duplicate_folder_create_rejected(admin, temp_vault):
    """Folders were never deduped at create time; now a same-name folder in the same parent
    is a clean 409 (backed by the (vault_id, parent_folder_id, name_bi) unique index)."""
    vid = temp_vault["id"]
    fname = unique("DUPDIR")
    r1 = admin.post(f"/vaults/{vid}/folders", json={"name": fname})
    assert r1.status_code == 200, r1.text
    r2 = admin.post(f"/vaults/{vid}/folders", json={"name": fname})
    assert r2.status_code == 409, f"expected 409 on duplicate folder, got {r2.status_code}: {r2.text}"

    cnt = _db_scalar(
        f"SELECT count(*) FROM folders WHERE vault_id='{vid}' AND name_bi="
        f"(SELECT name_bi FROM folders WHERE id='{r1.json()['folder']['id']}')"
    )
    assert cnt == "1", f"duplicate folder rows at rest: {cnt}"


# ---------------------------------------------------------------------------
# Gap #3: a File/Folder row must not be moved to a different vault_id without re-encryption
# (the at-rest AAD binds every blob to vault_id+id). Exercised at the ORM layer in-container
# (no HTTP move endpoint exists): a before_update guard rejects a vault_id change, while the
# documented _allow_vault_reencrypt opt-out permits an intentional re-encrypting migration.
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    os.environ.get("VAULT_SKIP_DOCKER_TESTS") in ("1", "true", "yes"),
    reason="docker-exec guard test disabled via VAULT_SKIP_DOCKER_TESTS",
)
def test_cross_vault_move_guard_layer(admin):
    va = admin.create_vault(name=unique("guardA"))
    vb = admin.create_vault(name=unique("guardB"))
    try:
        r = admin.post(f"/vaults/{va['id']}/files",
                       files=[("files", (unique("g") + ".bin", b"guard-me" * 8, "application/octet-stream"))])
        assert r.status_code == 200, r.text
        fid = r.json()["files"][0]["id"]

        script = (
            "import uuid\n"
            "from database import get_db_context\n"
            "from models import File\n"
            f"FID = '{fid}'\n"
            f"VB = '{vb['id']}'\n"
            # Each scenario uses its OWN session so the transient _allow_vault_reencrypt flag
            # (a plain instance attribute) can't leak across the shared identity-map object.
            # Scenario 1 — a loaded vault_id changed to another vault: the guard must fire.
            "with get_db_context() as db:\n"
            "    f = db.query(File).filter(File.id == FID).first()\n"
            "    assert f is not None, 'file row missing'\n"
            "    f.vault_id = uuid.UUID(VB)\n"
            "    try:\n"
            "        db.flush()\n"
            "        print('FAIL: cross-vault vault_id change was allowed')\n"
            "    except Exception as e:\n"
            "        print('GUARD_OK' if 're-encryption' in str(e) else 'OTHER_ERR:%s' % e)\n"
            "    db.rollback()\n"
            "# Scenario 2 — opt-out: an explicit re-encrypting migration may move the row.\n"
            "with get_db_context() as db:\n"
            "    f = db.query(File).filter(File.id == FID).first()\n"
            "    f._allow_vault_reencrypt = True\n"
            "    f.vault_id = uuid.UUID(VB)\n"
            "    try:\n"
            "        db.flush()\n"
            "        print('OPTOUT_OK')\n"
            "    except Exception as e:\n"
            "        print('OPTOUT_FAIL:%s' % e)\n"
            "    db.rollback()\n"
            "# Scenario 3 — expired vault_id (as after a prior commit with expire_on_commit):\n"
            "# reassigning WITHOUT reading the old value leaves attribute history with an empty\n"
            "# 'deleted'; the guard must STILL fire (fail-closed on an unknown old value).\n"
            "with get_db_context() as db:\n"
            "    f = db.query(File).filter(File.id == FID).first()\n"
            "    db.expire(f, ['vault_id'])  # deterministic stand-in for the post-commit expired state\n"
            "    f.vault_id = uuid.UUID(VB)  # assign without first reading the (expired) old value\n"
            "    try:\n"
            "        db.flush()\n"
            "        print('EXPIRED_FAIL: guard did not fire on expired vault_id')\n"
            "    except Exception as e:\n"
            "        print('EXPIRED_GUARD_OK' if 're-encryption' in str(e) else 'EXPIRED_OTHER:%s' % e)\n"
            "    db.rollback()\n"
        )
        container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
        try:
            proc = subprocess.run(
                ["docker", "exec", "-i", container, "python", "-"],
                input=script, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"docker unavailable for in-container guard test: {exc}")
        assert "GUARD_OK" in proc.stdout, (
            f"cross-vault move guard did not fire\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
        assert "OPTOUT_OK" in proc.stdout, (
            f"_allow_vault_reencrypt opt-out did not permit the move\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
        assert "EXPIRED_GUARD_OK" in proc.stdout, (
            f"guard did not fire on an expired (unread) vault_id\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    finally:
        admin.delete_vault(va["id"])
        admin.delete_vault(vb["id"])


def test_no_delete_member_cannot_overwrite_via_upload(admin, temp_vault, temp_user, temp_user_client):
    """RBAC regression: a vault member with WRITE but not DELETE must NOT be able to destroy
    an existing file by uploading a same-name file (the replace path deletes the prior row +
    blob). They get a 409 and the original file is preserved — the same authority the
    dedicated delete path enforces. (Before the fix, the replace gate used only the temp-cred
    capability, which is True for every non-scoped member, so this overwrite silently
    succeeded.)"""
    vid = temp_vault["id"]
    name = unique("rbac") + ".txt"

    # Owner (admin) uploads the original.
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"ORIGINAL-CONTENT", "text/plain"))])
    assert r.status_code == 200, r.text
    orig_id = r.json()["files"][0]["id"]

    # Grant the member WRITE (read+write, NOT delete).
    g = admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "write"})
    assert g.status_code == 200, g.text

    # Control: the member CAN create a NEW (non-clashing) file — proves they can upload at all,
    # isolating the rejection below to the replace case (not a missing upload permission).
    other = unique("rbac2") + ".txt"
    rc = temp_user_client.post(f"/vaults/{vid}/files", files=[("files", (other, b"NEW", "text/plain"))])
    assert rc.status_code == 200, f"member should be able to create a new file: {rc.status_code} {rc.text}"

    # The member must NOT be able to overwrite the owner's same-name file.
    rh = temp_user_client.post(f"/vaults/{vid}/files", files=[("files", (name, b"HIJACKED", "text/plain"))])
    assert rh.status_code == 409, f"no-delete member overwrite must be 409, got {rh.status_code}: {rh.text}"

    # Original is intact: same id, original content.
    dl = admin.get(f"/vaults/{vid}/files/{orig_id}/download")
    assert dl.status_code == 200 and dl.content == b"ORIGINAL-CONTENT", "original file was destroyed by a no-delete member"
