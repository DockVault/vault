"""A client-chosen object id is spent when its object dies, and can never be claimed again.

A client may choose the UUID of the object it creates. That exists for a real reason: in a
zero-knowledge vault the browser seals the name, the MIME type and the file content bound to that
id before any row exists, so the id must be known client-side first.

The guard on it asked whether a row holds the id *now*. A deleted row holds nothing, so every id a
deleted object used to own was free again — and deleting an object does not reliably erase its
bytes. `secure_delete` ends in a best-effort fallback, and deleting a FOLDER never removes its
directory at all; only deleting a vault does. So a blob outlives its row, and re-claiming the id it
was stored under puts an old version back where a reader finds it and authenticates it, because the
transcript binds the id and not the generation.

The two halves of the fix are tested separately because they fail separately:

- **The ledger** makes a retired id permanently unusable. Rows are written by database triggers
  rather than application code, because objects disappear through many paths including
  `ON DELETE CASCADE` constraints that have no Python site to patch.
- **Decoupling the blob's filename from the row id** removes the shared path that let one
  completion's cleanup delete another's committed bytes.
"""

import uuid

import pytest

from conftest import unique, ZK_ENC_NAME_STUB


pytestmark = pytest.mark.integration


@pytest.fixture
def vault(admin):
    r = admin.post("/vaults", json={"name": unique("retired")})
    r.raise_for_status()
    vid = r.json()["id"]
    yield vid
    admin.delete_vault(vid)


@pytest.fixture
def zk_enabled(admin):
    """Turn zero-knowledge vaults on for the duration, and put the setting back.

    Two tests below need it because a client-chosen vault id is only accepted for a
    zero-knowledge vault. Without this they pass or fail on whatever the last test in the run
    happened to leave the workspace set to -- which is exactly how one of them went green in
    isolation and red in the full lane, on a 400 that never reached the check under test.
    """
    before = admin.get("/settings").json().get("zero_knowledge_enabled", False)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": before})


def _seed_retired(object_id, kind: int) -> None:
    """Put an id straight into the ledger, for the cases whose natural route is unreachable here."""
    import subprocess
    container = __import__("os").environ.get("VAULT_DB_CONTAINER", "vault-db")
    sql = (f"INSERT INTO retired_object_ids (id, kind) VALUES ('{object_id}', {kind}) "
           "ON CONFLICT (id) DO NOTHING")
    done = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "{sql}"'],
        capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr


def _db_scalar(sql: str) -> str:
    """One value straight out of the database, for facts the API does not expose."""
    import subprocess
    container = __import__("os").environ.get("VAULT_DB_CONTAINER", "vault-db")
    done = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "{sql}"'],
        capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout.strip()


def _upload(admin, vault_id, name, body=b"contents", file_id=None):
    """One chunked upload, optionally under a client-chosen id."""
    init = {"file_name": name, "total_size": len(body), "total_chunks": 1,
            "chunk_size": max(len(body), 1)}
    if file_id:
        init["file_id"] = str(file_id)
    r = admin.post(f"/vaults/{vault_id}/uploads", json=init)
    if r.status_code not in (200, 201):
        return r
    sid = r.json()["session_id"]
    admin.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/0", data=body)
    return admin.post(f"/vaults/{vault_id}/uploads/{sid}/complete",
                      json={"file_id": str(file_id)} if file_id else None)


def test_a_deleted_files_id_cannot_be_claimed_again(admin, vault):
    """The defect, at its simplest.

    Delete the file, then try to create another one under the id it used to hold. Before the
    ledger this succeeded, and it succeeded at the exact path where the old blob may still be.
    """
    chosen = uuid.uuid4()
    made = _upload(admin, vault, "first.txt", b"original bytes", file_id=chosen)
    assert made.status_code in (200, 201), made.text
    assert made.json()["id"] == str(chosen), "the client-chosen id was not honoured"

    assert admin.post(f"/vaults/{vault}/files/{chosen}/delete").status_code in (200, 204)

    again = _upload(admin, vault, "second.txt", b"replacement", file_id=chosen)
    assert again.status_code == 409, (
        f"a retired file id was re-claimed ({again.status_code}) -- an id that is spent must stay "
        "spent, because the bytes it named may have outlived the row")


def test_a_deleted_vaults_object_ids_are_spent_too(admin):
    """The path with no Python site, and the reason the ledger lives in the database.

    Deleting a vault removes its files through an `ON DELETE CASCADE` foreign key. There is no
    application code on that path to record anything, so an implementation that inserted from
    Python would leave every file of every deleted vault re-claimable — and it would look correct.
    """
    v = admin.post("/vaults", json={"name": unique("cascade")})
    v.raise_for_status()
    vid = v.json()["id"]
    chosen = uuid.uuid4()
    made = _upload(admin, vid, "doomed.txt", b"bytes that outlive the row", file_id=chosen)
    assert made.status_code in (200, 201), made.text

    admin.delete_vault(vid)

    other = admin.post("/vaults", json={"name": unique("after")})
    other.raise_for_status()
    oid = other.json()["id"]
    try:
        again = _upload(admin, oid, "revived.txt", b"replacement", file_id=chosen)
        assert again.status_code == 409, (
            f"a file id freed by a vault cascade was re-claimed ({again.status_code})")
    finally:
        admin.delete_vault(oid)


def test_a_retired_vault_id_is_refused_by_the_create_endpoint(admin, zk_enabled):
    """The most valuable id to refuse, and the one a vault-scoped ledger would hand back.

    The server never generates a zero-knowledge vault's key -- it stores a wrap the browser
    supplies. So somebody still holding an old key could otherwise delete a vault, recreate it
    under the same id, re-supply that same wrap, and read whatever survived the delete. Any design
    that cleans the ledger per-vault on deletion reopens exactly this, which is why the ledger is
    keyed on the id alone and nothing removes a row from it.

    A client-chosen vault id is accepted only for a zero-knowledge vault, and standing one up
    through the API needs a browser-side keypair. So the retired id is seeded directly and the
    endpoint's answer is what is under test: it must refuse on the id, not fall through to the
    zero-knowledge validation behind it.
    """
    retired = uuid.uuid4()
    _seed_retired(retired, kind=3)

    r = admin.post("/vaults", json={"name": unique("reborn"), "id": str(retired),
                                    "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1})
    assert r.status_code == 409, (
        f"a retired vault id was not refused ({r.status_code}: {r.text[:200]})")
    assert "already in use" in r.text
    if r.status_code in (200, 201):            # pragma: no cover - defensive cleanup
        admin.delete_vault(retired)


def test_a_fresh_vault_id_still_reaches_the_zero_knowledge_checks(admin, zk_enabled):
    """Non-vacuity for the test above: without this, refusing every id would pass it.

    A fresh id must NOT produce the same 409 -- it goes on to whatever the zero-knowledge flow
    says, which for a request carrying no wrapped key is a different rejection entirely.
    """
    r = admin.post("/vaults", json={"name": unique("fresh-zk"), "id": str(uuid.uuid4()),
                                    "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1})
    assert "not enabled" not in r.text, (
        "zero-knowledge vaults are off, so this never reached the id check and proves nothing")
    assert r.status_code != 409 or "already in use" not in r.text, (
        "a never-used vault id was reported as already in use")
    if r.status_code in (200, 201):
        admin.delete_vault(r.json()["id"])


def _zk_vault(admin, vault_id=None):
    """A zero-knowledge vault, optionally under a client-chosen id."""
    from conftest import ensure_ecc_keypair, ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB
    ensure_ecc_keypair(admin)
    body = {"name": unique("zk"), "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1,
            "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}
    if vault_id:
        body["id"] = str(vault_id)
    return admin.post("/vaults", json=body)


def _zk_folder(admin, vault_id, folder_id):
    """A folder in a zero-knowledge vault, whose name must arrive already sealed."""
    from conftest import zk_encrypt_name, zk_name_blind_index
    dek = b"" * 32          # the server never opens these; any key produces valid-shaped input
    name = unique("dir")
    return admin.post(f"/vaults/{vault_id}/folders", json={
        "id": str(folder_id),
        "enc_name": zk_encrypt_name(name, dek, vault_id, "name", 1, obj_id=folder_id),
        "name_bi": zk_name_blind_index(name, dek, vault_id, 1),
    })


def test_a_deleted_folders_id_cannot_be_claimed_again(admin, zk_enabled):
    """The `folders` trigger, which had no test at all.

    Neutering it left the whole suite green while a deleted folder id was freely re-claimable --
    found by mutation, not by reading. That is the worst of the three to lose, because deleting a
    folder removes rows and nothing else: the only `rmtree` on persistent storage is in
    `delete_vault`, so `<vault>/folders/<folder_id>/` outlives the folder and any blob whose
    secure-delete fell through its fallback chain is still inside it. Re-claim the folder id and
    the file id and the old bytes are back at their exact path.
    """
    created = _zk_vault(admin)
    assert created.status_code in (200, 201), created.text
    vid = created.json()["id"]
    try:
        chosen = uuid.uuid4()
        made = _zk_folder(admin, vid, chosen)
        assert made.status_code in (200, 201), made.text

        gone = admin.post(f"/vaults/{vid}/folders/{chosen}/delete")
        assert gone.status_code in (200, 204), gone.text
        # The trigger, not the application, is what should have recorded this.
        assert _db_scalar(
            f"SELECT count(*) FROM retired_object_ids WHERE id = '{chosen}' AND kind = 2") == "1", (
            "the folders trigger did not record the deleted id")

        again = _zk_folder(admin, vid, chosen)
        assert again.status_code == 409, (
            f"a retired folder id was re-claimed ({again.status_code}: {again.text[:160]})")
    finally:
        admin.delete_vault(vid)


def test_a_deleted_vaults_id_cannot_be_claimed_again(admin, zk_enabled):
    """The `vaults` trigger, driven for real rather than seeded.

    The other vault test puts the row in the ledger by hand, so it proves the guard reads the
    ledger and proves nothing about what writes it. Two separate mutations survived because of
    that -- the trigger recording nothing, and a cleanup keyed on the vault's own id, which is
    exactly the "looks like tidiness in review" change the model docstring warns about.

    This is the attack the id-alone key exists to stop: the server never generates a
    zero-knowledge vault's key, it stores a wrap the browser supplies, so an old key holder who
    could recreate the vault under its own id would re-supply that wrap and read whatever
    survived the delete.
    """
    chosen = uuid.uuid4()
    created = _zk_vault(admin, vault_id=chosen)
    assert created.status_code in (200, 201), created.text
    assert created.json()["id"] == str(chosen)

    admin.delete_vault(chosen)
    assert _db_scalar(
        f"SELECT count(*) FROM retired_object_ids WHERE id = '{chosen}' AND kind = 3") == "1", (
        "the vaults trigger did not record the deleted vault's own id")

    again = _zk_vault(admin, vault_id=chosen)
    assert again.status_code == 409, (
        f"a deleted vault's id was re-claimed ({again.status_code}: {again.text[:160]})")
    if again.status_code in (200, 201):        # pragma: no cover - defensive cleanup
        admin.delete_vault(chosen)


def test_a_live_id_is_still_refused(admin, vault):
    """The check the ledger widens, still doing its original job.

    Worth pinning separately: an implementation that replaced the liveness check with a ledger
    lookup, rather than adding to it, would let two live rows contend for one id, and the ledger
    only learns about an id once something holding it dies.
    """
    chosen = uuid.uuid4()
    assert _upload(admin, vault, "held.txt", b"x", file_id=chosen).status_code in (200, 201)
    again = _upload(admin, vault, "clash.txt", b"y", file_id=chosen)
    assert again.status_code == 409, again.status_code


def test_a_fresh_id_is_still_accepted(admin, vault):
    """Non-vacuity. Every assertion above is satisfied by a build that refuses every id."""
    r = _upload(admin, vault, "fresh.txt", b"z", file_id=uuid.uuid4())
    assert r.status_code in (200, 201), r.text


def test_the_blob_filename_is_not_the_row_id(admin, vault):
    """What closes the concurrent-completion race, checked structurally rather than by racing.

    While the blob's name on disk was the row id, two completions carrying one client-chosen id
    opened the same path `'wb'` and interleaved; the loser hit the primary-key violation and its
    cleanup deleted the blob at that path -- the winner's committed bytes -- leaving a live row
    with nothing behind it. Two writers with independent filenames cannot reach each other.

    Read through the API rather than the filesystem, so it holds wherever the deployment stores
    things: the recorded path must not end in the row id.
    """
    chosen = uuid.uuid4()
    made = _upload(admin, vault, "decoupled.txt", b"payload", file_id=chosen)
    assert made.status_code in (200, 201), made.text
    fid = made.json()["id"]
    assert fid == str(chosen)

    # And it is still readable -- decoupling the name must not lose the bytes.
    got = admin.get(f"/vaults/{vault}/files/{fid}/download")
    assert got.status_code == 200 and got.content == b"payload", got.status_code

    # Read the recorded path from the database. There is no file-detail endpoint -- an earlier
    # version of this test looked for `storage_path` on one, found a 404, and skipped its only real
    # assertion without failing. It passed against a build with the decoupling reverted.
    path = _db_scalar(f"SELECT storage_path FROM files WHERE id = '{chosen}'")
    assert path, "no row found for the uploaded file"
    assert not path.endswith(str(chosen)), (
        f"the blob is still stored under the row id ({path}); two writers holding the same "
        "client-chosen id would open the same file, and the loser's cleanup would delete the "
        "winner's committed bytes")
    # And the leaf really is a UUID of its own, not some other id-shaped thing.
    leaf = path.replace(chr(92), "/").rsplit("/", 1)[-1]
    uuid.UUID(leaf)
