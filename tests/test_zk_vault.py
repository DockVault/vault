"""Zero-knowledge vault — Phase 1 backend (gated creation + opaque storage).

The browser 'client' is simulated: the test uploads opaque bytes (as a browser
would upload ciphertext) and asserts the server round-trips them verbatim and
stores them RAW — i.e. performs no server-side crypto and cannot read them.
SFTP exclusion of ZK vaults is covered in test_sftp_roundtrip.py.
"""
import contextlib
import hashlib
import shutil
import subprocess

import pytest

import os

from conftest import unique, ensure_ecc_keypair, create_zk_vault, zk_chunked_upload

_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _upload(client, vault_id, name, content):
    """Standard-vault multipart upload (plaintext name + bytes). Zero-knowledge vaults reject
    this path — use zk_chunked_upload (client-encrypted name + content) for them."""
    return client.post(
        f"/vaults/{vault_id}/files",
        files=[("files", (name, content, "application/octet-stream"))],
    )


@contextlib.contextmanager
def _zk_enabled(admin):
    """Opt the deployment into zero-knowledge vaults for the duration of a test,
    and ensure the creator has an ECC keypair (ZK creation wraps a DEK to it)."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    ensure_ecc_keypair(admin)
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_zk_creation_is_gated(admin):
    # OFF by default -> rejected
    admin.put("/settings", json={"zero_knowledge_enabled": False})
    r = admin.post("/vaults", json={"name": unique("zk"), "type": "zero_knowledge"})
    assert r.status_code == 400, r.text
    # opted in + a client-wrapped DEK -> allowed, and the vault reports its type
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
        assert v["type"] == "zero_knowledge"
        admin.delete_vault(v["id"])


def test_zk_opaque_roundtrip(admin):
    """Arbitrary 'ciphertext' bytes (deliberately NOT valid Fernet) round-trip
    verbatim through a ZK vault — proving the server applies no crypto of its own."""
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
        try:
            blob = bytes(range(256)) * 8  # opaque to the server; not Fernet/DockVault
            name = "enc_" + unique("f")   # an encrypted-name blob would look like this
            fid = zk_chunked_upload(admin, v["id"], name, blob, os.urandom(32))
            r = admin.get(f"/vaults/{v['id']}/files/{fid}/download")
            assert r.status_code == 200
            assert r.content == blob  # verbatim — no server-side decrypt
        finally:
            admin.delete_vault(v["id"])


def _stored_sha256(vault_id, file_id):
    """SHA-256 of the on-disk stored file inside the vault-api container, or None
    if it can't be read (docker unavailable / different layout)."""
    path = f"/app/storage/{vault_id}/files/{file_id}"
    out = subprocess.run(
        ["docker", "exec", _API_CONTAINER, "sha256sum", path],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        if os.environ.get("VAULT_SAME_COMMIT_CI", "").lower() in {"1", "true", "yes"}:
            detail = out.stderr.strip() or out.stdout.strip() or f"exit code {out.returncode}"
            pytest.fail(
                f"could not hash {path} in same-commit container {_API_CONTAINER}: {detail}"
            )
        return None
    return out.stdout.split()[0]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not available")
def test_zk_stored_raw_while_standard_is_server_encrypted(admin):
    """The core zero-knowledge property: on disk, a ZK vault holds the uploaded
    bytes VERBATIM (server stored ciphertext as-is), whereas a Standard vault holds
    DIFFERENT bytes (the server encrypted them)."""
    blob = b"OPAQUE-CIPHERTEXT-" + bytes(range(200))
    blob_sha = hashlib.sha256(blob).hexdigest()

    with _zk_enabled(admin):
        zk = create_zk_vault(admin)
    try:
        zk_fid = zk_chunked_upload(admin, zk["id"], unique("f"), blob, os.urandom(32))
        zk_sha = _stored_sha256(zk["id"], zk_fid)
        if zk_sha is None:
            pytest.skip("could not read stored file from vault-api container")
        assert zk_sha == blob_sha, "ZK vault must store the client's bytes verbatim"
    finally:
        admin.delete_vault(zk["id"])

    std = admin.create_vault(name=unique("std"))
    try:
        std_fid = _upload(admin, std["id"], unique("f"), blob).json()["files"][0]["id"]
        std_sha = _stored_sha256(std["id"], std_fid)
        if std_sha is None:
            pytest.skip("could not read stored file from vault-api container")
        assert std_sha != blob_sha, "Standard vault must server-encrypt at rest"
    finally:
        admin.delete_vault(std["id"])
