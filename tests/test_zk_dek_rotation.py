"""Zero-knowledge DEK rotation on member revoke (forward-only versioning) + Increment 1.5
(retire-version, authz/crypto reconciler).

HTTP-level contracts for the new /ecc rotation surface. The DEK wraps are opaque stubs
here (the server stores them verbatim and never unwraps) — the REAL ECDH crypto round-trip,
including a remaining member reading BOTH an old-epoch and a new-epoch file after a revoke,
is the Playwright test test_zero_knowledge_revoke_rotates_dek in test_ui_e2e.py.

Covers:
  * /ecc/vaults/{id}/rekey   — atomic revoke+rotate: version bump, re-wrap, validation,
                               optimistic lock (409), owner/manager authz.
  * GET /ecc/vaults/{id}/keys?key_version=N + current_dek_version — version-aware reads.
  * GET /ecc/vaults/{id}/member-keys — re-wrap target list (no blobs leaked).
  * upload-vs-rekey race — a stale-epoch upload is rejected (409); current-epoch tagged.
  * retire-version — drops member rows for epochs no live file uses.
  * reconciler — an AGED orphan key (authz gone, key left active) is swept; a FRESH key is
                 spared (the grace window that keeps in-flight shares working).
"""
import contextlib
import os
import subprocess
import uuid

import pytest

from conftest import (
    unique, ensure_ecc_keypair, create_zk_vault, ApiClient,
    zk_encrypt_name, zk_name_blind_index,
)


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _stub(prefix="w"):
    """A distinct opaque base64-ish blob (server stores wraps verbatim)."""
    import base64
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _mk(user_id):
    """A member_keys entry with fresh opaque wrap material for user_id."""
    return {"user_id": str(user_id), "wrapped_dek": _stub("dek"), "ephemeral_public_key": _stub("eph")}


def _share_zk(admin, vid, target_id, target_client, level="read"):
    """Share a ZK vault to another user the way the UI does: wrap the DEK (member key) AND
    grant authz (vault_members row). target_client must already have a keypair."""
    ensure_ecc_keypair(target_client)
    r = admin.post(f"/ecc/vaults/{vid}/members", json={
        "user_id": str(target_id), "wrapped_dek": _stub("share"), "ephemeral_public_key": _stub("eph"),
    })
    r.raise_for_status()
    r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": str(target_id), "level": level})
    r.raise_for_status()


# --- /rekey: happy path + version-aware reads --------------------------------

def test_rekey_bumps_version_revokes_and_keeps_old_epoch(admin, temp_user, temp_user_client):
    """Revoking via /rekey: epoch 1->2, the remaining member (owner) gets a v2 row AND keeps
    their v1 row (to read old files), and the revoked member loses access at EVERY epoch."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        # Both hold a key at epoch 1.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True

        owner_id = admin.user["id"]
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2,
            "revoke_user_id": str(temp_user["id"]),
            "member_keys": [_mk(owner_id)],  # only the owner remains
        })
        assert r.status_code == 200, r.text
        assert r.json()["dek_version"] == 2

        # Owner: current epoch is 2, and the v1 row is still readable (old files).
        cur = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert cur["has_access"] is True and cur["current_dek_version"] == 2 and cur["key_version"] == 2
        old = admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()
        assert old["has_access"] is True and old["key_version"] == 1

        # Revoked member: no access at the new epoch, the old epoch, or by default.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is False
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys?key_version=2").json()["has_access"] is False
    finally:
        admin.delete_vault(vid)


def test_rekey_forward_secrecy_new_epoch_unreadable_by_revoked(admin, temp_user, temp_user_client):
    """After a revoke+rotate, a NEW upload is tagged epoch 2 and the revoked member cannot
    obtain a usable DEK for it (has_access False at epoch 2)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": str(temp_user["id"]),
            "member_keys": [_mk(admin.user["id"])],
        }).raise_for_status()

        # New upload lands at epoch 2.
        fid = _zk_chunked_upload(admin, vid, b"new-epoch-content", zk_key_version=2)
        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert listed["key_version"] == 2
        # The revoked member has no key for epoch 2.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys?key_version=2").json()["has_access"] is False
    finally:
        admin.delete_vault(vid)


# --- /rekey: validation + concurrency ----------------------------------------

def test_rekey_rejects_omitted_remaining_member(admin, temp_user, temp_user_client):
    """member_keys must cover EXACTLY the remaining members — omitting one (which would
    lock them out) is rejected with no mutation."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        # Revoke nobody, but supply only the owner — temp_user is a remaining member omitted.
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        })
        assert r.status_code == 400, r.text
        # No mutation: still epoch 1.
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["current_dek_version"] == 1
    finally:
        admin.delete_vault(vid)


def test_rekey_rejects_revoked_user_in_member_keys(admin, temp_user, temp_user_client):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": str(temp_user["id"]),
            "member_keys": [_mk(admin.user["id"]), _mk(temp_user["id"])],  # revoked user must not be here
        })
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_rekey_rejects_stale_from_version(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 9, "to_version": 10, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        })
        assert r.status_code == 409, r.text
    finally:
        admin.delete_vault(vid)


def test_rekey_rejects_non_consecutive_to_version(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 3, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        })
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_rekey_requires_owner_or_manager(admin, temp_user, temp_user_client):
    """A plain member who holds a key (but isn't owner/manager) cannot force a rotation —
    the security-critical op is gated at owner/manager parity, not mere key possession."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client, level="read")  # plain member
        r = temp_user_client.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"]), _mk(temp_user["id"])],
        })
        assert r.status_code == 403, r.text
    finally:
        admin.delete_vault(vid)


def test_member_keys_lists_targets_without_blobs(admin, temp_user, temp_user_client):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        body = admin.get(f"/ecc/vaults/{vid}/member-keys").json()
        assert body["current_dek_version"] == 1
        members = {str(m) for m in body["members"]}
        assert {str(admin.user["id"]), str(temp_user["id"])} <= members
        # Must NOT leak any wrapped DEK material.
        assert "wrapped_dek" not in str(body) and "ephemeral" not in str(body)
    finally:
        admin.delete_vault(vid)


# --- upload-vs-rekey race -----------------------------------------------------

def _zk_chunked_upload(client, vid, content: bytes, zk_key_version=None, expect_status=200):
    """Drive a single-chunk resumable upload, declaring the ZK DEK epoch. Returns the new
    file id on success; on a non-200 'complete' returns the Response for assertions. The name
    is encrypted client-side (these tests don't decrypt it — they assert the content epoch)."""
    import os
    dek = os.urandom(32)
    name_epoch = zk_key_version if zk_key_version is not None else 1
    name = unique("zk") + ".bin"
    init = {"total_size": len(content), "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
            "enc_name": zk_encrypt_name(name, dek, vid, "name", name_epoch),
            "name_bi": zk_name_blind_index(name, dek, vid, name_epoch)}
    if zk_key_version is not None:
        init["zk_key_version"] = zk_key_version
    r = client.post(f"/vaults/{vid}/uploads", json=init)
    r.raise_for_status()
    sid = r.json()["session_id"]
    client.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=content,
               headers={"Content-Type": "application/octet-stream"})
    c = client.post(f"/vaults/{vid}/uploads/{sid}/complete")
    if expect_status == 200:
        assert c.status_code == 200, c.text
        return c.json()["id"]
    return c


def test_upload_with_stale_epoch_is_rejected(admin):
    """A ZK upload encrypted under an old epoch that lands AFTER a rotation is rejected
    (409) — it must not be committed as a stale-epoch file the revoked member could read."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        # Rotate to epoch 2 (no revoke; owner remains).
        admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        }).raise_for_status()
        # An upload still declaring epoch 1 is refused.
        c = _zk_chunked_upload(admin, vid, b"stale", zk_key_version=1, expect_status=409)
        assert c.status_code == 409, c.text
        # The same content at the current epoch succeeds and is tagged 2.
        fid = _zk_chunked_upload(admin, vid, b"fresh", zk_key_version=2)
        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert listed["key_version"] == 2
    finally:
        admin.delete_vault(vid)


def test_unrotated_vault_tags_epoch_1(admin):
    """A never-rotated ZK vault tags uploads epoch 1 (the legacy/default), proving the
    forward-only model is a no-op until the first rotation."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        fid = _zk_chunked_upload(admin, vid, b"hello", zk_key_version=1)
        listed = next(it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert listed["key_version"] == 1
        keys = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["current_dek_version"] == 1 and keys["key_version"] == 1
    finally:
        admin.delete_vault(vid)


# --- Increment 1.5: retire-version -------------------------------------------

def test_retire_version_drops_unused_epochs(admin):
    """After a rotation with NO files referencing the old epoch, retire-version hard-deletes
    the old-epoch member rows; the old epoch then reports no access."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        }).raise_for_status()
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is True

        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        assert r.json()["rows_deleted"] >= 1 and r.json()["retired_below_version"] == 2
        # Old epoch is gone; current epoch still works.
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is False
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)


def test_retire_version_keeps_epochs_still_in_use(admin):
    """retire-version must NOT drop an epoch a live file still uses — a file uploaded at
    epoch 1, then a rotation to 2, leaves epoch 1 un-retirable (the owner keeps reading it)."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _zk_chunked_upload(admin, vid, b"old-epoch-file", zk_key_version=1)  # file pins epoch 1
        admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        }).raise_for_status()
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        assert r.json()["rows_deleted"] == 0 and r.json()["retired_below_version"] == 1
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)


def test_retire_version_keeps_epoch_used_by_a_folder_name(admin):
    """retire-version must also honour a ZK FOLDER name's epoch (folders have no content, so
    their name carries its own epoch). A folder sealed at epoch 1, then a rotation to 2 with
    NO epoch-1 file, must NOT retire epoch 1 — else the folder name becomes permanently
    undecryptable for everyone (data loss). Regression for the adversarial-review finding."""
    import os
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        dek = os.urandom(32)
        nm = unique("dir")
        # ZK folder sealed under epoch 1 (no files reference epoch 1 at all).
        admin.post(f"/vaults/{vid}/folders", json={
            "enc_name": zk_encrypt_name(nm, dek, vid, "name", 1),
            "name_bi": zk_name_blind_index(nm, dek, vid, 1),
            "name_key_version": 1,
        }).raise_for_status()
        admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        }).raise_for_status()
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        # epoch 1 is still referenced (by the folder name) -> not retired, still readable.
        assert r.json()["rows_deleted"] == 0 and r.json()["retired_below_version"] == 1
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)


# --- Increment 1.5: authz/crypto reconciler (DIVERGENCE-2) -------------------

def _db_mutate(sql: str):
    """Run a mutating SQL statement against the vault DB via docker exec (list args, no
    shell). Skips when docker/psql is unavailable. Mirrors test_at_rest_crypto._db_scalar."""
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


def test_reconciler_sweeps_aged_orphan_key(admin, temp_user, temp_user_client):
    """DIVERGENCE-2: a member whose authz was removed but whose wrapped DEK was left active
    (a failed legacy best-effort revoke) must not keep crypto access. Once the orphan is
    older than the grace window, the next get_vault_keys deactivates it. We simulate the
    legacy state by dropping the vault_members row and back-dating granted_at via SQL."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True

        # Simulate the divergence: authz gone, key left active and AGED past the grace window.
        _db_mutate(f"DELETE FROM vault_members WHERE vault_id='{vid}' AND user_id='{temp_user['id']}'")
        _db_mutate("UPDATE vault_member_keys SET granted_at = now() - interval '1 hour' "
                   f"WHERE vault_id='{vid}' AND user_id='{temp_user['id']}'")

        # The reconciler (runs on get_vault_keys) now sweeps the orphan: access is gone...
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        # ...and the row is actually deactivated, not just filtered.
        active = _db_mutate("SELECT is_active FROM vault_member_keys "
                            f"WHERE vault_id='{vid}' AND user_id='{temp_user['id']}'")
        assert active.lower() in ("f", "false"), f"orphan key not deactivated: {active!r}"
    finally:
        admin.delete_vault(vid)


def test_rekey_does_not_rewrap_an_unauthorized_orphan(admin, temp_user, temp_user_client):
    """SECURITY (review must-fix #1a): the rekey 'remaining members' set is the active
    key-holders INTERSECTED with current authz. A user whose authz was removed but whose
    key is still active (and too FRESH for the grace reconciler) must be DROPPED from the
    rotation, never re-wrapped into the new epoch — otherwise a revoked user silently
    regains access to all new content."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        # Simulate an authz-only revoke that left the (fresh) key active — the exact orphan
        # the grace window deliberately does NOT sweep yet.
        _db_mutate(f"DELETE FROM vault_members WHERE vault_id='{vid}' AND user_id='{temp_user['id']}'")

        # Owner rotates (revoking nobody explicitly). 'remaining' must be {owner} ONLY —
        # the orphan is dropped — so supplying just the owner's wrap is accepted (it would
        # 400 'missing member' if the orphan were still counted as remaining).
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        })
        assert r.status_code == 200, r.text
        # The orphan got NO epoch-2 key — they cannot read new content.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys?key_version=2").json()["has_access"] is False
    finally:
        admin.delete_vault(vid)


def test_authz_revoke_deactivates_zk_key(admin, temp_user, temp_user_client):
    """SECURITY (review must-fix #1b): DELETE /vaults/{id}/permissions/{uid} on a ZK vault
    deactivates the user's wrapped DEK in the same transaction — no orphan key is left for
    the grace window. (The web UI rotates first; this covers a direct/non-rekey revoke.)"""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        # Direct authz revoke (no /rekey first).
        assert admin.delete(f"/vaults/{vid}/permissions/{temp_user['id']}").status_code == 200
        # Key is immediately unusable — not left active until the reconciler runs.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
    finally:
        admin.delete_vault(vid)


def test_grant_member_key_requires_manager_not_just_a_key(admin, temp_user, temp_user_client):
    """SECURITY (review must-fix #2): the DEK-minting grant is gated on owner/manager, the
    SAME as the authz grant — a plain member (holds a key but isn't a manager) cannot mint a
    member key, so they can't re-grant a revoked user a working DEK."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client, level="read")  # plain member, holds a key
        r = temp_user_client.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": str(admin.user["id"]), "wrapped_dek": _stub(), "ephemeral_public_key": _stub(),
        })
        assert r.status_code == 403, r.text
    finally:
        admin.delete_vault(vid)


def test_epochless_upload_after_rotation_is_rejected(admin):
    """SECURITY (review should-fix): after a rotation, a legacy/epoch-less ZK upload (no
    declared epoch) must be REJECTED (409) — accepting it would stamp the file at the new
    epoch while it was encrypted under the old DEK, making it undecryptable."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [_mk(admin.user["id"])],
        }).raise_for_status()
        # No zk_key_version declared on a rekeyed (epoch 2) vault -> 409.
        c = _zk_chunked_upload(admin, vid, b"epochless", zk_key_version=None, expect_status=409)
        assert c.status_code == 409, c.text
        body = c.json()
        assert isinstance(body.get("detail"), dict) and body["detail"].get("code") == "stale_zk_epoch", body
    finally:
        admin.delete_vault(vid)


def test_reconciler_spares_fresh_orphan_key(admin, temp_user, temp_user_client):
    """The reconciler must NOT sweep a key minted within the grace window — that window is
    what keeps an in-flight share (wrap-then-grant) and a just-shared member working."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        _share_zk(admin, vid, temp_user["id"], temp_user_client)
        # Remove authz but leave granted_at FRESH (just now) — still within grace.
        _db_mutate(f"DELETE FROM vault_members WHERE vault_id='{vid}' AND user_id='{temp_user['id']}'")
        # Fresh orphan is spared: the member can still fetch their key.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)
