"""Zero-knowledge vault wiring added for the browser-crypto UI:

  * GET /features                  — exposes the zero_knowledge_enabled flag to
                                     any authenticated user (full /settings is
                                     admin-only) so the UI can offer the option.
  * POST /vaults (type=zero_knowledge) now WRAPS a fresh vault DEK to the owner's
                                     ECC public key (VaultMemberKey) and requires
                                     the owner to have a keypair first.
  * GET /ecc/keys/private          — returns the opaque, password-encrypted private
                                     key blob so a new session can unlock locally.

The end-to-end browser round-trip (encrypt-before-upload / decrypt-after-download)
is covered by the Playwright test test_zero_knowledge_vault_end_to_end in
test_ui_e2e.py; here we pin the HTTP contracts these depend on.
"""
import contextlib
import json

import pytest

from conftest import (
    unique, ensure_ecc_keypair, create_zk_vault, ZK_WRAPPED_DEK_STUB,
    zk_encrypt_name, zk_decrypt_name, zk_name_blind_index, zk_chunked_upload, ZK_NAME_PREFIX,
    ZK_NAME_PREFIX_V2,
)


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@contextlib.contextmanager
def _force_zk(admin, allowed_groups=None):
    """Org confidentiality policy: force zero-knowledge for new vaults, with an
    optional whitelist of departments that may still create standard vaults."""
    admin.put("/settings", json={
        "zero_knowledge_enabled": True,
        "force_zero_knowledge": True,
        "standard_vault_allowed_groups": list(allowed_groups or []),
    })
    try:
        yield
    finally:
        admin.put("/settings", json={
            "zero_knowledge_enabled": False,
            "force_zero_knowledge": False,
            "standard_vault_allowed_groups": [],
        })


def test_zk_enabled_flag_reflects_setting(admin):
    with _zk_enabled(admin):
        assert admin.get("/zk-enabled").json().get("zero_knowledge_enabled") is True
    assert admin.get("/zk-enabled").json().get("zero_knowledge_enabled") is False


def test_zk_enabled_requires_auth(anon):
    assert anon.get("/zk-enabled").status_code in (401, 403)


def test_zk_vault_stores_owner_client_wrapped_dek_verbatim(admin):
    """Zero-knowledge: the DEK is generated + wrapped in the BROWSER. The server must
    store the owner's wrapped DEK VERBATIM (never generate or substitute one) and hand
    it back via GET /ecc/vaults/{id}/keys for the owner to unwrap. We send a known
    sentinel and assert it round-trips unchanged — proof the server didn't make a DEK."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        r = admin.post("/vaults", json={
            "name": unique("zk"), "type": "zero_knowledge",
            "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": "EPH-SENTINEL",
        })
        assert r.status_code == 200, r.text
        vault = r.json()
        assert vault["type"] == "zero_knowledge"
        vid = vault["id"]
        try:
            keys = admin.get(f"/ecc/vaults/{vid}/keys").json()
            assert keys["has_access"] is True, keys
            assert keys["wrapped_dek"] == ZK_WRAPPED_DEK_STUB  # server stored ours, didn't generate
            assert keys["ephemeral_public_key"] == "EPH-SENTINEL"
        finally:
            admin.delete_vault(vid)


def test_zk_vault_creation_requires_client_wrapped_dek(admin):
    """The server must NOT fabricate a DEK: creating a ZK vault without a
    browser-wrapped DEK is refused (and leaves no orphan vault)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        r = admin.post("/vaults", json={"name": unique("zk"), "type": "zero_knowledge"})
        assert r.status_code == 400, r.text
        assert "key" in r.json().get("detail", "").lower()


def test_zk_vault_creation_requires_a_keypair(admin):
    """Without an ECC keypair the server can't wrap a DEK, so ZK creation is
    refused (and no orphan vault is left behind). Uses a fresh user who has no
    keypair; the request is rejected (400 no-keypair, or 403 if the role lacks
    VAULT_CREATE — either way the vault is not created)."""
    user = admin.create_user(role="user")
    from conftest import ApiClient
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    try:
        with _zk_enabled(admin):
            # ensure this fresh user truly has no keypair
            assert client.get("/ecc/keys/public").json().get("has_keypair") is False
            r = client.post("/vaults", json={"name": unique("zk"), "type": "zero_knowledge"})
            assert r.status_code in (400, 403), r.text
            if r.status_code == 400:
                assert "key" in r.json().get("detail", "").lower()
    finally:
        admin.delete_user(user["id"])


def _fresh_pubkey_pem():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    return ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _register_fresh(client, blob: str):
    """Register a fresh keypair WITH a valid proof-of-possession (the server now requires one)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from conftest import compute_registration_pop
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return client.post("/ecc/keys/register", json={
        "public_key": pub, "encrypted_private_key": blob,
        "pop": compute_registration_pop(client, priv, pub),
    })


def test_ecc_private_key_blob_roundtrip(admin):
    """The password-encrypted private key blob registered by the client is handed
    back verbatim by GET /ecc/keys/private (so another session can unlock it).
    The server treats it as opaque — zero-knowledge is preserved. Uses a FRESH
    user because registration is reject-on-exists (the shared admin already holds
    a keypair from earlier tests)."""
    from conftest import ApiClient
    user = admin.create_user(role="user")
    client = ApiClient(); client.login(user["_username"], user["_password"])
    try:
        blob = json.dumps({"encrypted": unique("ct"), "salt": unique("s"), "iterations": 600000})
        assert _register_fresh(client, blob).status_code == 201
        got = client.get("/ecc/keys/private").json()
        assert got["has_keypair"] is True
        assert got["encrypted_private_key"] == blob
    finally:
        admin.delete_user(user["id"])


def test_ecc_keypair_register_rejects_overwrite(admin):
    """Re-registering a keypair is REFUSED (409). The vault DEKs are wrapped to the
    user's current public key, so silently replacing it would orphan every wrapped
    DEK and lock them out of their zero-knowledge vaults — the server must be the
    authoritative gate (clients also guard, but a race/direct call must not win).
    The original key/blob must survive the rejected attempt."""
    from conftest import ApiClient
    user = admin.create_user(role="user")
    client = ApiClient(); client.login(user["_username"], user["_password"])
    try:
        first = json.dumps({"encrypted": unique("first"), "salt": unique("s"), "iterations": 600000})
        assert _register_fresh(client, first).status_code == 201
        # A second registration is rejected (409), not silently applied.
        r = client.post("/ecc/keys/register", json={
            "public_key": _fresh_pubkey_pem(),
            "encrypted_private_key": json.dumps({"encrypted": unique("second"), "salt": "x", "iterations": 600000}),
        })
        assert r.status_code == 409, r.text
        # The original key/blob is untouched — no partial overwrite.
        assert client.get("/ecc/keys/private").json()["encrypted_private_key"] == first
    finally:
        admin.delete_user(user["id"])


def test_ecc_private_key_requires_auth(anon):
    assert anon.get("/ecc/keys/private").status_code in (401, 403)


# --- Zero-knowledge member sharing (client-wrapped DEK distribution) ----------

def test_get_another_users_public_key(admin, temp_user, temp_user_client):
    """An existing member can fetch another user's PUBLIC key to wrap the DEK to."""
    assert admin.get(f"/ecc/users/{temp_user['id']}/public-key").json()["has_keypair"] is False
    ensure_ecc_keypair(temp_user_client)
    body = admin.get(f"/ecc/users/{temp_user['id']}/public-key").json()
    assert body["has_keypair"] is True
    assert "PUBLIC KEY" in (body["public_key"] or "")


def test_grant_member_key_requires_granter_to_hold_key(admin, temp_user_client):
    """A user who holds no key for a ZK vault cannot push a member key for it."""
    ensure_ecc_keypair(admin)
    ensure_ecc_keypair(temp_user_client)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = temp_user_client.post(
            f"/ecc/vaults/{vid}/members",
            json={"user_id": str(temp_user_client.user["id"]), "wrapped_dek": "AAAA", "ephemeral_public_key": "AAAA"},
        )
        assert r.status_code == 403, r.text
    finally:
        admin.delete_vault(vid)


def test_grant_and_fetch_member_key(admin, temp_user, temp_user_client):
    """Owner (holds a key) stores a client-wrapped DEK for another user, who can
    then fetch it. Opaque base64 here — the real crypto round-trip is the UI test
    test_zero_knowledge_vault_sharing_two_users."""
    ensure_ecc_keypair(admin)
    ensure_ecc_keypair(temp_user_client)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = admin.post(
            f"/ecc/vaults/{vid}/members",
            json={"user_id": temp_user["id"], "wrapped_dek": "V1JBUFBFRA==", "ephemeral_public_key": "RVBL"},
        )
        assert r.status_code == 200, r.text
        keys = temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["has_access"] is True
        assert keys["wrapped_dek"] == "V1JBUFBFRA=="
    finally:
        admin.delete_vault(vid)


def test_grant_member_key_rejects_recipient_without_keypair(admin, temp_user):
    """Can't share to a user who has no encryption key to wrap to."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = admin.post(
            f"/ecc/vaults/{vid}/members",
            json={"user_id": temp_user["id"], "wrapped_dek": "AAAA", "ephemeral_public_key": "AAAA"},
        )
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_revoke_member_key(admin, temp_user, temp_user_client):
    ensure_ecc_keypair(admin)
    ensure_ecc_keypair(temp_user_client)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        admin.post(f"/ecc/vaults/{vid}/members",
                   json={"user_id": temp_user["id"], "wrapped_dek": "QQ==", "ephemeral_public_key": "QQ=="})
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        assert admin.delete(f"/ecc/vaults/{vid}/members/{temp_user['id']}").status_code == 200
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
    finally:
        admin.delete_vault(vid)


# --- Confidentiality org-policy: force zero-knowledge + Standard whitelist (§5) -

def test_force_zk_blocks_standard_for_non_whitelisted(admin):
    ensure_ecc_keypair(admin)
    with _force_zk(admin):  # no whitelist -> everyone must use ZK
        r = admin.post("/vaults", json={"name": unique("v")})  # standard (default)
        assert r.status_code == 400, r.text
        assert "zero-knowledge" in r.json()["detail"].lower()
        # a ZK vault is still allowed
        ok = create_zk_vault(admin, name=unique("v"))
        admin.delete_vault(ok["id"])


def test_force_zk_allows_standard_for_whitelisted_department(admin):
    ensure_ecc_keypair(admin)
    gid = admin.post("/groups", json={"name": unique("exempt")}).json()["id"]
    admin.post(f"/groups/{gid}/members", json={"user_ids": [str(admin.user["id"])]})
    try:
        with _force_zk(admin, allowed_groups=[gid]):
            r = admin.post("/vaults", json={"name": unique("v")})  # standard
            assert r.status_code == 200, r.text
            assert r.json()["type"] == "standard"
            admin.delete_vault(r.json()["id"])
    finally:
        admin.delete(f"/groups/{gid}")


def test_zk_enabled_reports_must_use_zk(admin):
    with _force_zk(admin):
        f = admin.get("/zk-enabled").json()
        assert f["zero_knowledge_enabled"] is True
        assert f["must_use_zk"] is True
    f = admin.get("/zk-enabled").json()
    assert f["must_use_zk"] is False


def test_force_zero_knowledge_rejects_non_bool(admin):
    try:
        assert admin.put("/settings", json={"force_zero_knowledge": "yes"}).status_code == 400
    finally:
        admin.put("/settings", json={"force_zero_knowledge": False})


def test_standard_vault_allowed_groups_rejects_unknown_id(admin):
    import uuid as _uuid
    try:
        r = admin.put("/settings", json={"standard_vault_allowed_groups": [str(_uuid.uuid4())]})
        assert r.status_code == 400, r.text
    finally:
        admin.put("/settings", json={"standard_vault_allowed_groups": []})


# --- ZK vaults reject department/group sharing (no key to wrap to a group) -----

def test_zk_vault_rejects_group_access_grant(admin):
    """A department/group has no encryption key, so granting it access to a
    zero-knowledge vault would hand out a permission row with no wrapped DEK —
    access the member can't use. The server refuses it (400) for BOTH read and
    write, and records nothing; ZK sharing must be per-user. See
    [[vault-zk-ui-scoping]]."""
    ensure_ecc_keypair(admin)
    gid = admin.post("/groups", json={"name": unique("dept")}).json()["id"]
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        for perm in ("read", "write"):
            r = admin.post(f"/vaults/{vid}/group-access",
                           json={"group_id": gid, "permission": perm})
            assert r.status_code == 400, (perm, r.text)
            assert "zero-knowledge" in r.json()["detail"].lower()
        # Nothing was recorded for either attempt.
        assert admin.get(f"/vaults/{vid}/group-access").json() == []
    finally:
        admin.delete_vault(vid)
        admin.delete(f"/groups/{gid}")


def test_zk_vault_group_share_blocked_for_manager_too(admin, temp_user, temp_user_client):
    """The block is at the endpoint, so a delegated Manager hits it as well — not
    just the owner/admin."""
    ensure_ecc_keypair(admin)
    gid = admin.post("/groups", json={"name": unique("dept")}).json()["id"]
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        # Make temp_user a Manager of the ZK vault.
        assert admin.post(f"/vaults/{vid}/permissions",
                          json={"user_id": temp_user["id"], "level": "manage"}).status_code == 200
        r = temp_user_client.post(f"/vaults/{vid}/group-access",
                                  json={"group_id": gid, "permission": "read"})
        assert r.status_code == 400, r.text
        assert "zero-knowledge" in r.json()["detail"].lower()
    finally:
        admin.delete_vault(vid)
        admin.delete(f"/groups/{gid}")


def test_zk_vault_group_access_revoke_allowed(admin):
    """Revoke (DELETE) is NOT blocked on ZK vaults — it must stay open so an
    operator can clean up any legacy group row that predates the grant block.
    It's a harmless no-op when no row exists."""
    ensure_ecc_keypair(admin)
    gid = admin.post("/groups", json={"name": unique("dept")}).json()["id"]
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        assert admin.delete(f"/vaults/{vid}/group-access/{gid}").status_code == 200
    finally:
        admin.delete_vault(vid)
        admin.delete(f"/groups/{gid}")


def test_standard_vault_still_allows_group_access(admin, temp_vault):
    """Regression: blocking ZK group access must not affect standard vaults."""
    gid = admin.post("/groups", json={"name": unique("dept")}).json()["id"]
    try:
        vid = temp_vault["id"]
        r = admin.post(f"/vaults/{vid}/group-access",
                       json={"group_id": gid, "permission": "read"})
        assert r.status_code == 200, r.text
        assert any(g["group_id"] == gid
                   for g in admin.get(f"/vaults/{vid}/group-access").json())
        admin.delete(f"/vaults/{vid}/group-access/{gid}")
    finally:
        admin.delete(f"/groups/{gid}")


_OCTET = {"Content-Type": "application/octet-stream"}


def test_zk_chunked_upload_resumes_and_stores_ciphertext_verbatim(admin):
    """Server-side foundation for cross-reload ZK upload resume: a zero-knowledge
    chunked upload can be PARTIALLY uploaded, resumed against the SAME session, and
    completed — and the bytes the server stores are exactly the ciphertext the client
    sent (verbatim, no server-side re-encryption), reassembled in order.

    The browser persists the encrypted blob in IndexedDB so a reload can replay the
    remaining chunks; this test pins the HTTP contract that replay relies on. The full
    browser reload→resume→decrypt path is covered by the Playwright E2E."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        # Opaque "ciphertext" split across two chunks (the server can't read it; it just
        # stores bytes). A tiny chunk_size keeps the payload small but genuinely multi-chunk.
        part0 = b"ZK-CIPHERTEXT-CHUNK-0-" * 4
        part1 = b"ZK-CIPHERTEXT-CHUNK-1-" * 4
        blob = part0 + part1

        # ZK uploads carry the name ENCRYPTED (never plaintext): supply enc_name + name_bi.
        import os as _os
        dek = _os.urandom(32)
        zkname = unique("zkbig") + ".bin"
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "total_size": len(blob), "total_chunks": 2, "chunk_size": len(part0),
            "zk_key_version": 1,
            "enc_name": zk_encrypt_name(zkname, dek, vid, "name", 1),
            "enc_mime": zk_encrypt_name("application/octet-stream", dek, vid, "mime", 1),
            "name_bi": zk_name_blind_index(zkname, dek, vid, 1),
        })
        assert r.status_code == 200, r.text
        sid = r.json()["session_id"]

        # Upload only chunk 0, then simulate a reload: the client re-syncs which chunks
        # the server already has (the session-detail endpoint) and replays only the rest.
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=part0, headers=_OCTET).status_code == 200
        detail = admin.get(f"/vaults/{vid}/uploads/{sid}").json()
        assert detail["received_chunks"] == [0]
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=part1, headers=_OCTET).status_code == 200

        out = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
        assert out.status_code == 200, out.text
        fid = out.json()["id"]

        # The file is tagged with the declared epoch and downloads back as the EXACT
        # ciphertext bytes (verbatim, in order) — proof the server never re-encrypted.
        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert listed.get("key_version") == 1
        assert admin.get(f"/vaults/{vid}/files/{fid}/download").content == blob
        # The name came back ENCRYPTED (no plaintext) and round-trips with the client DEK.
        assert not listed.get("name"), f"plaintext name leaked into listing: {listed.get('name')!r}"
        assert listed["enc_name"].startswith(ZK_NAME_PREFIX)
        assert zk_decrypt_name(listed["enc_name"], dek, vid, "name", 1) == zkname
    finally:
        admin.delete_vault(vid)


# ===========================================================================
# Zero-knowledge filename / MIME encryption (client-side, vault DEK)
# ---------------------------------------------------------------------------
# The server must NEVER see a plaintext ZK file/folder name or MIME. These pin the
# HTTP contract: ZK writes carry the name ENCRYPTED + a blind index, plaintext is
# rejected, and the at-rest row/listing hold only ciphertext. The full browser
# round-trip is additionally proven by the Playwright E2E.
# ===========================================================================
import os as _os  # noqa: E402
import subprocess as _subprocess  # noqa: E402


def _zk_db_scalar(sql):
    """Direct DB peek (the HTTP API can't show whether a column is NULL at rest)."""
    container = _os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    try:
        proc = _subprocess.run(
            ["docker", "exec", container, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, _subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


def test_zk_upload_name_not_plaintext_at_rest(admin):
    """A zero-knowledge upload stores NO plaintext name/MIME in files — only the
    client ciphertext (ZK-marked) + blind index — and the listing returns the same."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        sentinel = unique("ZKSENT")
        name = sentinel + ".txt"
        fid = zk_chunked_upload(admin, vid, name, b"opaque-ciphertext-bytes" * 8, dek, epoch=1)

        row = _zk_db_scalar(
            "SELECT coalesce(original_name,'') || '|' || coalesce(\"name\",'') || '|' || "
            "coalesce(mime_type,'') || '|' || coalesce(enc_name,'') || '|' || "
            f"(name_bi IS NOT NULL)::text FROM files WHERE id='{fid}'"
        )
        plain_orig, plain_name, plain_mime, enc_name, has_bi = row.split("|", 4)
        assert plain_orig == "" and plain_name == "" and plain_mime == "", f"plaintext at rest: {row!r}"
        assert sentinel not in row, f"sentinel leaked at rest: {row!r}"
        assert enc_name.startswith(ZK_NAME_PREFIX) and has_bi == "true", row

        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert not listed.get("name")
        assert zk_decrypt_name(listed["enc_name"], dek, vid, "name", 1) == name
        assert zk_decrypt_name(listed["enc_mime"], dek, vid, "mime", 1) == "text/plain"
    finally:
        admin.delete_vault(vid)


def test_zk_upload_rejects_plaintext_name(admin):
    """A ZK chunked init that sends a plaintext file_name (the old leak) is refused, as is
    one missing the encrypted name — the server must never receive the plaintext."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        # plaintext name present -> 400
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "file_name": "leak.txt", "total_size": 10, "total_chunks": 1, "zk_key_version": 1,
            "enc_name": zk_encrypt_name("leak.txt", dek, vid, "name", 1),
            "name_bi": zk_name_blind_index("leak.txt", dek, vid, 1),
        })
        assert r.status_code == 400, r.text
        # encrypted name missing -> 400
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "total_size": 10, "total_chunks": 1, "zk_key_version": 1,
        })
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_zk_multipart_upload_rejected(admin):
    """The plaintext multipart upload path would store cleartext content + name; it must be
    refused for zero-knowledge vaults (only the chunked, client-encrypted path is allowed)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = admin.post(f"/vaults/{vid}/files",
                       files=[("files", ("leak.txt", b"plaintext", "text/plain"))])
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_zk_folder_name_not_plaintext_at_rest(admin):
    """A zero-knowledge folder stores no plaintext name; the listing returns the encrypted
    blob + epoch and the name round-trips with the client DEK."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        sentinel = unique("ZKDIR")
        r = admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": zk_encrypt_name(sentinel, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(sentinel, dek, vid, 1),
            "name_key_version": 1,
        })
        assert r.status_code == 200, r.text
        folder_id = r.json()["folder"]["id"]

        row = _zk_db_scalar(
            "SELECT coalesce(\"name\",'') || '|' || coalesce(enc_name,'') || '|' || "
            f"coalesce(name_key_version::text,'') FROM folders WHERE id='{folder_id}'"
        )
        plain_name, enc_name, name_kv = row.split("|", 2)
        assert plain_name == "" and sentinel not in row, f"plaintext folder name at rest: {row!r}"
        assert enc_name.startswith(ZK_NAME_PREFIX) and name_kv == "1", row

        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == folder_id)
        assert not listed.get("name")
        assert zk_decrypt_name(listed["enc_name"], dek, vid, "name", 1) == sentinel
    finally:
        admin.delete_vault(vid)


def test_zk_folder_rejects_plaintext_name(admin):
    """Creating a ZK folder with a plaintext name (or no encrypted name) is refused."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        assert admin.post(f"/vaults/{vid}/folders", json={"name": "leak"}).status_code == 400
        assert admin.post(f"/vaults/{vid}/folders", json={}).status_code == 400
    finally:
        admin.delete_vault(vid)


def test_zk_rename_keeps_name_encrypted(admin):
    """Renaming a ZK file stores the new name ENCRYPTED only; no plaintext appears at rest
    and the new name round-trips with the client DEK."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        fid = zk_chunked_upload(admin, vid, unique("orig") + ".txt", b"x" * 32, dek, epoch=1)
        newname = unique("ZKRENAME") + ".txt"
        r = admin.put(f"/vaults/{vid}/files/{fid}/rename", json={
            "enc_name": zk_encrypt_name(newname, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(newname, dek, vid, 1),
        })
        assert r.status_code == 200, r.text

        row = _zk_db_scalar(
            "SELECT coalesce(original_name,'') || '|' || coalesce(\"name\",'') FROM files "
            f"WHERE id='{fid}'"
        )
        assert row == "|" and "ZKRENAME" not in row, f"plaintext rename at rest: {row!r}"
        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert zk_decrypt_name(listed["enc_name"], dek, vid, "name", 1) == newname
    finally:
        admin.delete_vault(vid)


def test_zk_seal_names_migrates_legacy_plaintext(admin):
    """A pre-existing ZK row with a PLAINTEXT name (created before client-side encryption)
    is migrated by POST /vaults/{id}/zk/seal-names: after sealing, no plaintext remains and
    the name decrypts from the stored ciphertext. We simulate a legacy row by writing the
    plaintext directly via the DB, then seal it."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        # Create a sealed file, then force it back to a LEGACY plaintext shape in the DB to
        # stand in for a row written before this feature existed.
        legacy = unique("LEGACY") + ".txt"
        fid = zk_chunked_upload(admin, vid, legacy, b"y" * 16, dek, epoch=1)
        _zk_db_scalar(
            f"UPDATE files SET original_name='{legacy}', \"name\"='{legacy}', enc_name=NULL, "
            f"enc_mime=NULL, name_bi=NULL WHERE id='{fid}'; SELECT '1'"
        )
        # Sanity: it's plaintext now.
        assert _zk_db_scalar(f"SELECT coalesce(original_name,'') FROM files WHERE id='{fid}'") == legacy

        # Seal it the way the browser would on next vault open.
        r = admin.post(f"/vaults/{vid}/zk/seal-names", json={"items": [{
            "id": fid, "kind": "file",
            "enc_name": zk_encrypt_name(legacy, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(legacy, dek, vid, 1),
            "enc_mime": zk_encrypt_name("text/plain", dek, vid, "mime", 1),
        }]})
        assert r.status_code == 200 and r.json()["sealed"] == 1, r.text

        row = _zk_db_scalar(
            "SELECT coalesce(original_name,'') || '|' || coalesce(\"name\",'') || '|' || "
            f"coalesce(enc_name,'') FROM files WHERE id='{fid}'"
        )
        plain_orig, plain_name, enc_name = row.split("|", 2)
        assert plain_orig == "" and plain_name == "" and legacy not in row, f"still plaintext: {row!r}"
        assert enc_name.startswith(ZK_NAME_PREFIX)
        assert zk_decrypt_name(enc_name, dek, vid, "name", 1) == legacy
    finally:
        admin.delete_vault(vid)


# ---- adversarial-review hardening regressions ----------------------------------

def test_zk_upload_rejects_unsealed_marker(admin):
    """The server must enforce the 'zk1:' marker on every ZK name write: a client can't park
    a non-sealed (e.g. plaintext) blob in enc_name (which would defeat the load-event skip and
    could leave cleartext at rest)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "total_size": 10, "total_chunks": 1, "zk_key_version": 1,
            "enc_name": "quarterly-layoffs.pdf",   # NOT a zk1: blob — must be rejected
            "name_bi": "deadbeef",
        })
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_zk_folder_rejects_unsealed_marker_and_future_epoch(admin):
    """ZK folder create rejects a non-'zk1:' name, and a name epoch ahead of the vault's
    current epoch (which would pin the name to a DEK no member holds yet)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        nm = unique("dir")
        # non-marker enc_name -> 400
        assert admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": "plain", "name_bi": zk_name_blind_index(nm, dek, vid, 1), "name_key_version": 1,
        }).status_code == 400
        # future epoch (vault is at epoch 1) -> 400
        assert admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": zk_encrypt_name(nm, dek, vid, "name", 9),
            "name_bi": zk_name_blind_index(nm, dek, vid, 9), "name_key_version": 9,
        }).status_code == 400
    finally:
        admin.delete_vault(vid)


def test_zk_rename_rejects_plaintext_and_unsealed(admin):
    """ZK rename must reject a plaintext new_name and a non-'zk1:' enc_name (contract parity
    with upload/folder-create)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        fid = zk_chunked_upload(admin, vid, unique("o") + ".txt", b"x" * 16, dek, epoch=1)
        nm = unique("new") + ".txt"
        # plaintext new_name present -> 400
        assert admin.put(f"/vaults/{vid}/files/{fid}/rename", json={
            "new_name": "leak.txt",
            "enc_name": zk_encrypt_name(nm, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(nm, dek, vid, 1),
        }).status_code == 400
        # non-marker enc_name -> 400
        assert admin.put(f"/vaults/{vid}/files/{fid}/rename", json={
            "enc_name": "plain", "name_bi": zk_name_blind_index(nm, dek, vid, 1),
        }).status_code == 400
    finally:
        admin.delete_vault(vid)


def test_zk_folder_create_malformed_fields_are_400_not_500(admin):
    """create_folder takes a raw dict, so a non-integer name_key_version or an oversized
    name_bi must be a clean 400, not an unhardened 500 (DB DataError / int() ValueError)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        nm = unique("dir")
        good_enc = zk_encrypt_name(nm, dek, vid, "name", 1)
        # non-integer name_key_version
        assert admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": good_enc, "name_bi": zk_name_blind_index(nm, dek, vid, 1),
            "name_key_version": "not-an-int",
        }).status_code == 400
        # name_bi longer than the VARCHAR(64) column
        assert admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": good_enc, "name_bi": "a" * 65, "name_key_version": 1,
        }).status_code == 400
    finally:
        admin.delete_vault(vid)


def test_zk_folder_rename_rejects_future_epoch(admin):
    """A ZK folder rename must not pin the name to a FUTURE DEK epoch (no member holds it yet —
    the name would be permanently undecryptable). Parity with create_folder/seal-names."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        nm = unique("dir")
        r = admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": zk_encrypt_name(nm, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(nm, dek, vid, 1), "name_key_version": 1,
        })
        r.raise_for_status()
        folder_id = r.json()["folder"]["id"]
        nm2 = unique("ren")
        # vault is at epoch 1; a rename declaring epoch 9 must be rejected.
        assert admin.put(f"/vaults/{vid}/files/{folder_id}/rename", json={
            "enc_name": zk_encrypt_name(nm2, dek, vid, "name", 9),
            "name_bi": zk_name_blind_index(nm2, dek, vid, 9), "name_key_version": 9,
        }).status_code == 400
        # the current epoch still works.
        assert admin.put(f"/vaults/{vid}/files/{folder_id}/rename", json={
            "enc_name": zk_encrypt_name(nm2, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(nm2, dek, vid, 1), "name_key_version": 1,
        }).status_code == 200
    finally:
        admin.delete_vault(vid)


def test_zk_seal_names_ignores_unsealed_marker(admin):
    """seal-names must skip a non-'zk1:' enc_name (it would otherwise NULL the plaintext and
    leave an undecryptable, load-event-breaking blob)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = _os.urandom(32)
        legacy = unique("L") + ".txt"
        fid = zk_chunked_upload(admin, vid, legacy, b"y" * 16, dek, epoch=1)
        _zk_db_scalar(
            f"UPDATE files SET original_name='{legacy}', \"name\"='{legacy}', enc_name=NULL, "
            f"name_bi=NULL WHERE id='{fid}'; SELECT '1'"
        )
        r = admin.post(f"/vaults/{vid}/zk/seal-names", json={"items": [{
            "id": fid, "kind": "file", "enc_name": "not-a-zk-blob", "name_bi": "abcd",
        }]})
        assert r.status_code == 200 and r.json()["sealed"] == 0, r.text
        # The plaintext row is untouched (not destroyed by a non-conformant seal).
        assert _zk_db_scalar(f"SELECT coalesce(original_name,'') FROM files WHERE id='{fid}'") == legacy
    finally:
        admin.delete_vault(vid)


def test_zk_seal_names_works_on_password_protected_vault(admin):
    """A password-protected ZK vault must still be sealable (the browser sends the vault
    password) — otherwise legacy plaintext names would never migrate for that vault class."""
    ensure_ecc_keypair(admin)
    pw = "Zk-Vault-Pass-123"
    with _zk_enabled(admin):
        r = admin.post("/vaults", json={
            "name": unique("zkpw"), "type": "zero_knowledge",
            "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": "EPH-SENTINEL",
            "password": pw,
        })
        r.raise_for_status()
        vid = r.json()["id"]
    PW = {"X-Vault-Password": pw}
    try:
        dek = _os.urandom(32)
        legacy = unique("PWLEG") + ".txt"
        # upload (with password) then force it back to a legacy plaintext shape
        fid = _zk_pw_upload(admin, vid, legacy, b"z" * 16, dek, pw)
        _zk_db_scalar(
            f"UPDATE files SET original_name='{legacy}', \"name\"='{legacy}', enc_name=NULL, "
            f"name_bi=NULL WHERE id='{fid}'; SELECT '1'"
        )
        # Without the password the seal is refused (proving the header is required)...
        assert admin.post(f"/vaults/{vid}/zk/seal-names", json={"items": [{
            "id": fid, "kind": "file",
            "enc_name": zk_encrypt_name(legacy, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(legacy, dek, vid, 1),
        }]}).status_code == 401
        # ...and WITH the password it seals (the path the browser now uses).
        r = admin.post(f"/vaults/{vid}/zk/seal-names", headers=PW, json={"items": [{
            "id": fid, "kind": "file",
            "enc_name": zk_encrypt_name(legacy, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(legacy, dek, vid, 1),
        }]})
        assert r.status_code == 200 and r.json()["sealed"] == 1, r.text
        assert _zk_db_scalar(f"SELECT coalesce(original_name,'') FROM files WHERE id='{fid}'") == ""
    finally:
        admin.delete_vault(vid, vault_password=pw)


# The browser name-crypto (ecc_crypto.js) and the Python mirror (conftest) MUST stay
# byte-compatible — otherwise a future edit to the AAD/HKDF/prefix in one file silently makes
# real ZK names undecryptable while the (self-referential) unit tests stay green. This runs the
# REAL ecc_crypto.js under Node and asserts the Python mirror reproduces its output both ways.
_NODE_PARITY = r'''
const { webcrypto } = require('crypto');
global.window = { crypto: webcrypto };
const ECC = require(process.env.ECC_JS);
(async () => {
  const lib = new ECC();
  const rawDek = Buffer.from(process.env.DEK_HEX, 'hex');
  const dek = await webcrypto.subtle.importKey('raw', rawDek, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  const vid = process.env.VID, nm = process.env.NM, epoch = Number(process.env.EPOCH);
  const objId = process.env.OBJ_ID;   // v2 names bind the object id
  const encName = await lib.encryptName(nm, dek, vid, 'name', epoch, objId);
  const encMime = await lib.encryptName('text/plain', dek, vid, 'mime', epoch, objId);
  const bi = await lib.nameBlindIndex(nm, dek, vid, epoch);
  // Also prove JS can decrypt a blob the Python side produced (passed in via env).
  const fromPy = await lib.decryptName(process.env.PY_ENC, dek, vid, 'name', epoch, objId);
  process.stdout.write(JSON.stringify({ encName, encMime, bi, fromPy }));
})().catch(e => { console.error(e); process.exit(1); });
'''


def test_zk_name_crypto_parity_with_browser_lib():
    """ecc_crypto.js (run under Node) and the conftest Python mirror agree on name encryption
    and the blind index, in BOTH directions. Skips if node is unavailable."""
    import shutil as _shutil
    import uuid as _uuid
    from pathlib import Path as _Path
    node = _shutil.which("node")
    if not node:
        pytest.skip("node unavailable for crypto-parity test")
    ecc_js = str((_Path(__file__).resolve().parent.parent / "static" / "js" / "ecc_crypto.js")).replace("\\", "/")
    dek = _os.urandom(32)
    vid = str(_uuid.uuid4())
    obj_id = str(_uuid.uuid4())  # the object id the v2 name binds to
    nm = "pärity 文件.txt"  # unicode to exercise UTF-8 framing
    epoch = 3
    py_enc = zk_encrypt_name(nm, dek, vid, "name", epoch, obj_id=obj_id)  # Python-sealed blob for JS to decrypt
    env = {**_os.environ, "ECC_JS": ecc_js, "DEK_HEX": dek.hex(),
           "VID": vid, "NM": nm, "EPOCH": str(epoch), "OBJ_ID": obj_id, "PY_ENC": py_enc}
    proc = _subprocess.run([node, "-"], input=_NODE_PARITY, capture_output=True, text=True,
                           encoding="utf-8", env=env, timeout=30)
    assert proc.returncode == 0, f"node parity script failed: {proc.stderr}"
    out = json.loads(proc.stdout)
    # JS -> Python: JS-sealed name/mime (now v2, obj-id-bound) decrypt with the Python mirror
    # under the same obj id; blind indexes match.
    assert out["encName"].startswith(ZK_NAME_PREFIX_V2)
    assert zk_decrypt_name(out["encName"], dek, vid, "name", epoch, obj_id=obj_id) == nm
    assert zk_decrypt_name(out["encMime"], dek, vid, "mime", epoch, obj_id=obj_id) == "text/plain"
    assert out["bi"] == zk_name_blind_index(nm, dek, vid, epoch), "blind index mismatch JS vs Python"
    # Python -> JS: a Python-sealed blob decrypts in the browser lib.
    assert out["fromPy"] == nm, "ecc_crypto.js could not decrypt a Python-sealed name"


def _zk_pw_upload(client, vid, name, content, dek, pw, epoch=1):
    """zk_chunked_upload variant that carries the vault password header on every call."""
    PW = {"X-Vault-Password": pw}
    init = client.post(f"/vaults/{vid}/uploads", headers=PW, json={
        "total_size": len(content), "total_chunks": 1, "chunk_size": max(1, len(content)),
        "zk_key_version": epoch,
        "enc_name": zk_encrypt_name(name, dek, vid, "name", epoch),
        "name_bi": zk_name_blind_index(name, dek, vid, epoch),
    })
    init.raise_for_status()
    sid = init.json()["session_id"]
    client.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=content,
               headers={**PW, "Content-Type": "application/octet-stream"}).raise_for_status()
    done = client.post(f"/vaults/{vid}/uploads/{sid}/complete", headers=PW)
    done.raise_for_status()
    return done.json()["id"]
