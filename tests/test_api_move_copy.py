"""Move / Copy of files and folders — within a vault and across Standard vaults.

A COPY (and any cross-vault operation) is a genuine decrypt-then-re-encrypt: the at-rest AAD is bound
to (vault_id, file_id), so the destination blob is encrypted under a NEW binding, never a raw copy of
the source bytes. These tests download both sides and compare content byte-for-byte, including a
multi-megabyte file so the streaming re-encrypt is exercised across many chunks.

A within-vault MOVE is a reparent (same id, no re-encryption). Zero-knowledge vaults hold client
ciphertext the server cannot re-encrypt, so copy / cross-vault ops involving them are refused.
Cross-vault folder move/copy is deferred and must return a clean error.
"""
import uuid

import pytest

from conftest import ApiClient, BASE_URL, unique, create_zk_vault, zk_chunked_upload

pytestmark = pytest.mark.integration


def _mint_temp(admin, caps, selected, mode):
    """Mint + log in a scoped temporary credential. `selected` is the selected_vaults list."""
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60,
        "scope": {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}},
        "vault_access_mode": mode,
        "selected_vaults": selected,
    }).json()
    c = ApiClient(BASE_URL)
    c.login(body["temp_username"], body["credential"])
    return c, body["temp_username"]


def _upload(client, vault_id, name, content, folder_id=None):
    files = [("files", (name, content, "text/plain"))]
    params = {"folder_id": folder_id} if folder_id else None
    r = client.post(f"/vaults/{vault_id}/files", files=files, params=params)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _download(client, vault_id, file_id):
    r = client.get(f"/vaults/{vault_id}/files/{file_id}/download")
    r.raise_for_status()
    return r.content


def _mkfolder(client, vault_id, name, parent=None):
    r = client.post(f"/vaults/{vault_id}/folders", json={"name": name, "parent_folder_id": parent})
    r.raise_for_status()
    return r.json()["folder"]["id"]


def _items(client, vault_id, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else None
    return client.get(f"/vaults/{vault_id}/files", params=params).json()["items"]


def _ids(items):
    return {it["id"] for it in items}


# ---- files: copy ---------------------------------------------------------------------------------

def test_copy_file_within_vault_keeps_original_and_roundtrips(admin):
    v = admin.create_vault(name=unique("cpv"))
    vid = v["id"]
    content = b"copy me within\n" * 100
    src = _upload(admin, vid, unique("f") + ".txt", content)
    folder = _mkfolder(admin, vid, unique("sub"))
    try:
        r = admin.post(f"/vaults/{vid}/files/{src}/copy",
                       json={"dest_vault_id": vid, "dest_folder_id": folder})
        assert r.status_code == 200, r.text
        new_id = r.json()["id"]
        assert new_id != src                                  # a copy is a new object
        assert _download(admin, vid, src) == content          # original untouched
        assert _download(admin, vid, new_id) == content       # copy round-trips byte-for-byte
        assert new_id in _ids(_items(admin, vid, folder))     # copy is in the destination folder
    finally:
        admin.delete_vault(vid)


def test_copy_file_cross_vault_reencrypts_and_roundtrips_multichunk(admin):
    a = admin.create_vault(name=unique("A"))
    b = admin.create_vault(name=unique("B"))
    # >2 MiB so the streaming re-encrypt spans many chunks — the case a single-chunk test misses.
    content = (b"x" * 1021 + b"\n") * 3000
    src = _upload(admin, a["id"], unique("big") + ".bin", content)
    try:
        r = admin.post(f"/vaults/{a['id']}/files/{src}/copy",
                       json={"dest_vault_id": b["id"]})
        assert r.status_code == 200, r.text
        new_id = r.json()["id"]
        assert _download(admin, a["id"], src) == content       # source vault keeps it
        assert _download(admin, b["id"], new_id) == content    # dest is a faithful re-encryption
        assert new_id in _ids(_items(admin, b["id"]))
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])


def test_copy_name_collision_409_then_replace(admin):
    v = admin.create_vault(name=unique("clash"))
    vid = v["id"]
    folder = _mkfolder(admin, vid, unique("dst"))
    name = unique("dup") + ".txt"
    src = _upload(admin, vid, name, b"source bytes")
    _upload(admin, vid, name, b"existing in dest", folder_id=folder)   # same name already in dest
    try:
        r = admin.post(f"/vaults/{vid}/files/{src}/copy",
                       json={"dest_vault_id": vid, "dest_folder_id": folder})
        assert r.status_code == 409, r.text
        r = admin.post(f"/vaults/{vid}/files/{src}/copy",
                       json={"dest_vault_id": vid, "dest_folder_id": folder, "replace_same_name": True})
        assert r.status_code == 200, r.text
        # The replaced copy carries the SOURCE content.
        assert _download(admin, vid, r.json()["id"]) == b"source bytes"
    finally:
        admin.delete_vault(vid)


# ---- files: move ---------------------------------------------------------------------------------

def test_move_file_within_vault_is_a_reparent_same_id(admin):
    v = admin.create_vault(name=unique("mv"))
    vid = v["id"]
    content = b"move me\n" * 50
    src = _upload(admin, vid, unique("f") + ".txt", content)
    folder = _mkfolder(admin, vid, unique("into"))
    try:
        r = admin.post(f"/vaults/{vid}/files/{src}/move",
                       json={"dest_vault_id": vid, "dest_folder_id": folder})
        assert r.status_code == 200, r.text
        assert r.json()["id"] == src                          # reparent keeps the id
        assert src not in _ids(_items(admin, vid))            # gone from root
        assert src in _ids(_items(admin, vid, folder))        # now in the folder
        assert _download(admin, vid, src) == content          # content intact
    finally:
        admin.delete_vault(vid)


def test_move_file_cross_vault_reencrypts_and_removes_source(admin):
    a = admin.create_vault(name=unique("mA"))
    b = admin.create_vault(name=unique("mB"))
    content = b"relocate across vaults\n" * 200
    src = _upload(admin, a["id"], unique("f") + ".txt", content)
    try:
        r = admin.post(f"/vaults/{a['id']}/files/{src}/move",
                       json={"dest_vault_id": b["id"]})
        assert r.status_code == 200, r.text
        new_id = r.json()["id"]
        assert new_id != src                                  # cross-vault move re-encrypts (new id)
        assert admin.get(f"/vaults/{a['id']}/files/{src}/download").status_code == 404  # source gone
        assert _download(admin, b["id"], new_id) == content   # dest faithful
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])


# ---- folders -------------------------------------------------------------------------------------

def test_move_folder_within_vault_reparents(admin):
    v = admin.create_vault(name=unique("fmv"))
    vid = v["id"]
    outer = _mkfolder(admin, vid, unique("outer"))
    mover = _mkfolder(admin, vid, unique("mover"))
    try:
        r = admin.post(f"/vaults/{vid}/folders/{mover}/move",
                       json={"dest_vault_id": vid, "dest_parent_folder_id": outer})
        assert r.status_code == 200, r.text
        assert mover not in _ids(_items(admin, vid))          # no longer at root
        assert mover in _ids(_items(admin, vid, outer))       # now under outer
    finally:
        admin.delete_vault(vid)


def test_move_folder_into_own_descendant_rejected(admin):
    v = admin.create_vault(name=unique("cyc"))
    vid = v["id"]
    parent = _mkfolder(admin, vid, unique("p"))
    child = _mkfolder(admin, vid, unique("c"), parent=parent)
    try:
        r = admin.post(f"/vaults/{vid}/folders/{parent}/move",
                       json={"dest_vault_id": vid, "dest_parent_folder_id": child})
        assert r.status_code == 400, r.text          # cannot move a folder into its own subtree
    finally:
        admin.delete_vault(vid)


def test_copy_folder_within_vault_recursive_roundtrips(admin):
    v = admin.create_vault(name=unique("fcp"))
    vid = v["id"]
    top = _mkfolder(admin, vid, unique("top"))
    sub = _mkfolder(admin, vid, unique("sub"), parent=top)
    dest = _mkfolder(admin, vid, unique("dest"))   # copy INTO a distinct folder (same name in one
    top_bytes = b"top file\n" * 10                  # location would legitimately 409)
    sub_bytes = b"sub file\n" * 10
    _upload(admin, vid, unique("t") + ".txt", top_bytes, folder_id=top)
    _upload(admin, vid, unique("s") + ".txt", sub_bytes, folder_id=sub)
    try:
        r = admin.post(f"/vaults/{vid}/folders/{top}/copy",
                       json={"dest_vault_id": vid, "dest_parent_folder_id": dest})
        assert r.status_code == 200, r.text
        new_top = r.json()["id"]
        assert new_top != top
        top_items = _items(admin, vid, new_top)
        # The copied top has one file and one subfolder.
        copied_file = next(it for it in top_items if it["type"] == "file")
        copied_sub = next(it for it in top_items if it["type"] == "folder")
        assert _download(admin, vid, copied_file["id"]) == top_bytes
        sub_items = _items(admin, vid, copied_sub["id"])
        copied_sub_file = next(it for it in sub_items if it["type"] == "file")
        assert _download(admin, vid, copied_sub_file["id"]) == sub_bytes
    finally:
        admin.delete_vault(vid)


def test_cross_vault_folder_move_and_copy_are_rejected(admin):
    a = admin.create_vault(name=unique("fA"))
    b = admin.create_vault(name=unique("fB"))
    folder = _mkfolder(admin, a["id"], unique("x"))
    try:
        rm = admin.post(f"/vaults/{a['id']}/folders/{folder}/move",
                        json={"dest_vault_id": b["id"]})
        assert rm.status_code == 400, rm.text
        rc = admin.post(f"/vaults/{a['id']}/folders/{folder}/copy",
                        json={"dest_vault_id": b["id"]})
        assert rc.status_code == 400, rc.text
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])


# ---- zero-knowledge refusal ----------------------------------------------------------------------

def test_zk_vault_copy_is_refused_both_directions(admin):
    before = admin.get("/settings").json().get("zero_knowledge_enabled", False)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    std = admin.create_vault(name=unique("std"))
    zk = create_zk_vault(admin, name=unique("zk"))
    dek = bytes(range(32))
    std_file = _upload(admin, std["id"], unique("s") + ".txt", b"standard bytes")
    zk_file = zk_chunked_upload(admin, zk["id"], unique("z") + ".txt", b"zk-ciphertext-bytes", dek)
    try:
        # Standard file INTO a ZK vault → refused (dest cannot be re-encrypted server-side).
        r = admin.post(f"/vaults/{std['id']}/files/{std_file}/copy",
                       json={"dest_vault_id": zk["id"]})
        assert r.status_code == 400, r.text
        # ZK file OUT to a Standard vault → refused (source is opaque to the server).
        r = admin.post(f"/vaults/{zk['id']}/files/{zk_file}/copy",
                       json={"dest_vault_id": std["id"]})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(std["id"])
        admin.delete_vault(zk["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": bool(before)})


# ---- authorization -------------------------------------------------------------------------------

def test_copy_into_a_vault_you_cannot_write_is_forbidden(admin):
    """A user who is not a member of the destination vault cannot copy into it."""
    owner_a = admin.create_user(role="user")
    a = admin.clone_anonymous(); a.login(owner_a["_username"], owner_a["_password"])
    src_vault = a.create_vault(name=unique("mine"))
    dest_vault = admin.create_vault(name=unique("theirs"))   # owned by admin; the user has no access
    src = _upload(a, src_vault["id"], unique("f") + ".txt", b"secret")
    try:
        r = a.post(f"/vaults/{src_vault['id']}/files/{src}/copy",
                   json={"dest_vault_id": dest_vault["id"]})
        assert r.status_code in (403, 404), r.text          # no write on the destination vault
    finally:
        a.delete_vault(src_vault["id"])
        admin.delete_vault(dest_vault["id"])
        admin.delete_user(owner_a["id"])


# ---- review-regression guards (quota, replace-authority, root-scope) ------------------------------

def test_copy_respects_destination_vault_size_limit(admin):
    """A copy must honour the destination vault's per-vault size_limit, like a normal upload."""
    a = admin.create_vault(name=unique("qA"))
    b = admin.create_vault(name=unique("qB"))
    payload = b"z" * 4000
    src = _upload(admin, a["id"], unique("f") + ".bin", payload)
    # Cap B just below what the copy would add, so the re-encrypt write must be refused.
    admin.patch(f"/vaults/{b['id']}/settings", json={"size_limit": 1000}).raise_for_status()
    try:
        r = admin.post(f"/vaults/{a['id']}/files/{src}/copy", json={"dest_vault_id": b["id"]})
        assert r.status_code == 413, r.text
        assert _ids(_items(admin, b["id"])) == set()   # nothing was written into the capped vault
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])


def test_replace_same_name_requires_delete_authority_on_destination(admin):
    """A principal with upload but NOT delete on the destination cannot overwrite a colliding file
    via replace_same_name — the victim survives and the copy 409s."""
    v = admin.create_vault(name=unique("raV"))
    vid = v["id"]
    victim_folder = _mkfolder(admin, vid, unique("dst"))
    name = unique("dup") + ".txt"
    victim = _upload(admin, vid, name, b"the victim's bytes", folder_id=victim_folder)
    # A temp credential on this vault with read+write but NO file.delete.
    caps = ["vault.see_info", "vault.see_files", "file.download", "file.upload"]
    temp, tname = _mint_temp(admin, caps, [], "all")
    try:
        # The temp stages its own same-name source file (at the root) to force a collision on paste.
        src = _upload(temp, vid, name, b"attacker replacement")
        r = temp.post(f"/vaults/{vid}/files/{src}/copy",
                      json={"dest_vault_id": vid, "dest_folder_id": victim_folder,
                            "replace_same_name": True})
        assert r.status_code == 409, r.text              # replace gated off -> clean collision
        assert _download(admin, vid, victim) == b"the victim's bytes"   # victim NOT destroyed
    finally:
        admin.post(f"/temp-creds/{tname}/delete")
        admin.delete_vault(vid)


def test_scoped_temp_cannot_copy_to_the_vault_root(admin):
    """An id-scoped temp (folder scope) must not deposit an item at the vault root, outside its subtree."""
    v = admin.create_vault(name=unique("rsV"))
    vid = v["id"]
    scoped_folder = _mkfolder(admin, vid, unique("scope"))
    fid = _upload(admin, vid, unique("f") + ".txt", b"in scope", folder_id=scoped_folder)
    caps = ["vault.see_info", "vault.see_files", "file.download", "file.upload"]
    temp, tname = _mint_temp(
        admin, caps,
        [{"vault_id": vid, "caps": caps, "scope_ids": {"folders": [scoped_folder], "files": []}}],
        "selected")
    try:
        # Copy the in-scope file to the ROOT (dest_folder_id omitted) — must be refused.
        r = temp.post(f"/vaults/{vid}/files/{fid}/copy", json={"dest_vault_id": vid})
        assert r.status_code == 403, r.text
    finally:
        admin.post(f"/temp-creds/{tname}/delete")
        admin.delete_vault(vid)
