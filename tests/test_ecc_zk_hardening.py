"""Regression tests for the zero-knowledge / ECC crypto plane (/ecc).

Covers the hardening pass:
* key registration is refused to a temporary session (a delegated cred must not set the
  account's permanent, irreversible ZK identity key);
* registration constrains the key to P-384 (a wrong-curve key would be stored mislabeled);
* the point-decompression utility now requires authentication + is rate-limited + body-bounded;
* a ZK download never serves a plaintext MIME (legacy-row leak);
* deactivating a user via PATCH /users blacklists their active ZK keys;
* a Manager cannot unseat a peer Manager via rekey (parity with the dedicated revoke path).
"""
import base64
import contextlib
import os
import shutil
import subprocess
import uuid

import pytest

from conftest import ApiClient, BASE_URL, unique, create_zk_vault, zk_chunked_upload


# --------------------------------------------------------------------------- helpers
def _psql(sql):
    if not shutil.which("docker"):
        return None
    try:
        u = subprocess.run(["docker", "exec", "vault-db", "printenv", "POSTGRES_USER"],
                           capture_output=True, text=True, timeout=10)
        d = subprocess.run(["docker", "exec", "vault-db", "printenv", "POSTGRES_DB"],
                           capture_output=True, text=True, timeout=10)
        if u.returncode != 0 or d.returncode != 0:
            return None
        return subprocess.run(
            ["docker", "exec", "vault-db", "psql", "-U", u.stdout.strip(), "-d", d.stdout.strip(),
             "-t", "-A", "-c", sql], capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return None


def _psql_scalar(sql):
    r = _psql(sql)
    if r is None or r.returncode != 0:
        return None
    return r.stdout.strip()


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _p384_pem():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    return ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _p256_pem():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


# --------------------------------------------------------------------------- register temp guard
def test_ecc_register_rejects_temp_session(admin):
    """A temporary session must not set the account's permanent ZK identity key — the guard fires
    before any key parsing, so even a minimal body is refused with 403 (mirrors PUT /keys/private)."""
    tc = admin.post("/auth/temp-credentials", json={"note": unique("reg-guard")}).json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    try:
        r = c.post("/ecc/keys/register", json={"public_key": _p384_pem()})
        assert r.status_code == 403, r.text
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")


# --------------------------------------------------------------------------- P-384 constraint
def test_ecc_register_rejects_non_p384_key(admin, temp_user_client):
    """Registration is constrained to P-384: a valid but wrong-curve (P-256) key is rejected
    before the account would store it mislabeled 'SECP384R1'. temp_user_client is a real
    (non-temp) user login, so it passes the temp guard and reaches the curve check."""
    r = temp_user_client.post("/ecc/keys/register", json={"public_key": _p256_pem()})
    assert r.status_code == 400, r.text
    assert "secp384r1" in r.text.lower()


# --------------------------------------------------------------------------- decompress-point
def test_ecc_decompress_point_requires_auth():
    anon = ApiClient(BASE_URL)
    good = base64.b64encode(b"\x02" + b"\x00" * 48).decode()  # 49-byte compressed shape
    r = anon.post("/ecc/decompress-point", json={"compressed_point": good, "curve": "P-384"})
    assert r.status_code in (401, 403), r.text


def test_ecc_decompress_point_authed_and_size_bounded(admin):
    # Authenticated: a wrong-length point passes auth and fails validation (400/422), NOT 401.
    short = base64.b64encode(b"short").decode()
    r = admin.post("/ecc/decompress-point", json={"compressed_point": short, "curve": "P-384"})
    assert r.status_code in (400, 422), r.text
    # Oversized body is rejected by the field max_length (422) before any work.
    r = admin.post("/ecc/decompress-point", json={"compressed_point": "A" * 300, "curve": "P-384"})
    assert r.status_code == 422, r.text


# --------------------------------------------------------------------------- ZK download neutral MIME
def test_ecc_zk_download_serves_neutral_mime(admin):
    """A ZK file download must never serve a plaintext MIME (a legacy pre-seal row still holds
    one). The server always returns a neutral Content-Type for ZK content."""
    with _zk_enabled(admin):
        vz = create_zk_vault(admin)
    vid = vz["id"]
    try:
        dek = os.urandom(32)
        fid = zk_chunked_upload(admin, vid, "secret.pdf", b"opaque-ciphertext", dek,
                                mime="application/pdf", file_id=str(uuid.uuid4()))
        # Simulate a legacy row: a server-readable plaintext mime_type.
        if _psql(f"UPDATE files SET mime_type='application/pdf' WHERE id='{fid}';") is None:
            pytest.skip("docker/vault-db unavailable")
        r = admin.get(f"/vaults/{vid}/files/{fid}/download")
        assert r.status_code == 200, r.text
        assert r.headers.get("Content-Type", "").startswith("application/octet-stream"), \
            r.headers.get("Content-Type")
    finally:
        admin.delete_vault(vid)


# --------------------------------------------------------------------------- PATCH deactivate blacklists ZK keys
def test_patch_user_deactivate_blacklists_zk_keys(admin, temp_user):
    """Deactivating a user via PATCH /users offboards their ZK key access (parity with the
    user-management deactivate path): their active wrapped-DEK rows are blacklisted."""
    uid = temp_user["id"]
    with _zk_enabled(admin):
        vz = create_zk_vault(admin)
    vid = vz["id"]
    try:
        # Seed an active ZK member-key row for temp_user on this vault (they are NOT the owner).
        seeded = _psql(
            "INSERT INTO vault_member_keys (id, vault_id, user_id, encrypted_dek, "
            "ephemeral_public_key, key_version, is_active) VALUES "
            f"(gen_random_uuid(), '{vid}', '{uid}', 'dummy-ct', 'dummy-epk', 1, true);")
        if seeded is None or seeded.returncode != 0:
            pytest.skip("cannot seed vault_member_keys (docker/vault-db)")
        assert _psql_scalar(
            f"SELECT count(*) FROM vault_member_keys WHERE user_id='{uid}' AND is_active=true;") == "1"

        assert admin.patch(f"/users/{uid}", json={"is_active": False}).status_code == 200
        assert _psql_scalar(
            f"SELECT count(*) FROM vault_member_keys WHERE user_id='{uid}' AND is_active=true;") == "0", \
            "the deactivated user's ZK key must be blacklisted"
    finally:
        admin.patch(f"/users/{uid}", json={"is_active": True})
        admin.delete_vault(vid)


# --------------------------------------------------------------------------- rekey peer-manager guard
def test_ecc_rekey_manager_cannot_unseat_peer_manager(admin):
    """A non-owner/admin Manager cannot revoke a PEER Manager via rekey (parity with
    revoke_member_key + DELETE /vaults/{id}/permissions)."""
    with _zk_enabled(admin):
        vz = create_zk_vault(admin)
    vid = vz["id"]
    m1 = admin.create_user(role="user")
    m2 = admin.create_user(role="user")
    try:
        # A ZK vault rejects the standard per-user permission grant (ZK sharing goes through
        # /ecc), so seed the two Manager memberships directly (manage_permission=true).
        for m in (m1, m2):
            seeded = _psql(
                "INSERT INTO vault_members (vault_id, user_id, read_permission, write_permission, "
                "delete_permission, manage_permission) VALUES "
                f"('{vid}', '{m['id']}', true, true, true, true);")
            if seeded is None or seeded.returncode != 0:
                pytest.skip("cannot seed vault_members (docker/vault-db)")
        c1 = ApiClient(BASE_URL)
        c1.login(m1["_username"], m1["_password"])
        # M1 (a Manager, not owner/admin) tries to strip peer Manager M2 via rekey.
        r = c1.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": m2["id"], "member_keys": []})
        assert r.status_code == 403, r.text
        assert "manager" in r.text.lower()
    finally:
        admin.delete_user(m1["id"])
        admin.delete_user(m2["id"])
        admin.delete_vault(vid)
