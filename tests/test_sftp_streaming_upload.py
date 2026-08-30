"""Integration tests for the memory-bounded streaming SFTP upload path.

These run against a stack with SFTP_STREAMING_UPLOAD=on (the harness sets it): the upload handle
encrypts + persists records as they arrive rather than buffering the whole plaintext. They assert the
result is CORRECT — a file uploaded over SFTP downloads back byte-identical through the web path (so
the at-rest format matches the buffered/web path), across large, small, and empty payloads, plus the
atomic same-name replacement — and that a rejected upload lands nothing. The memory bound itself is
verified out-of-band (a large upload with docker stats / scripts/measure_transfer_budget.py); pytest
cannot cheaply assert RSS.

Skipped automatically when the SFTP service is unreachable (the `sftp` marker + conftest health gate).
"""
import contextlib
import os
import uuid

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import ADMIN_PASS, unique  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))

pytestmark = pytest.mark.sftp

# file.upload also needs vault.see_files/see_info to place + read back; file.delete lets the
# atomic-overwrite test replace an existing same-name file.
_CAPS = ["vault.see_info", "vault.see_files", "file.download", "file.upload", "file.delete"]


@contextlib.contextmanager
def sftp_session(username, password):
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            yield sftp
        finally:
            sftp.close()
    finally:
        transport.close()


def _mint_upload_cred(admin, vault_id):
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": _CAPS,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False,
                      "delegate": False}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": _CAPS}]}).json()
    return body["temp_username"], body["credential"]


def _file_id(admin, vid, name, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else {}
    for it in admin.get(f"/vaults/{vid}/files", params=params).json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    return None


def _sftp_put(username, password, path, data):
    with sftp_session(username, password) as sftp:
        with sftp.open(path, "wb") as fh:
            fh.set_pipelined(True)
            fh.write(data)


@pytest.fixture(autouse=True)
def _need_admin_pw():
    if not ADMIN_PASS:
        pytest.skip("No admin password (set VAULT_ADMIN_PASS)")


@pytest.mark.parametrize("size", [
    5_000_000,   # multi-record: exercises the streamed 1 MiB record boundaries + the short tail
    1024,        # single short record
    0,           # empty file (opened, never written)
])
def test_streaming_roundtrip_is_byte_identical(admin, size):
    v = admin.create_vault(name=unique("strm"))
    vid, vname = v["id"], v["name"]
    tu, tc = _mint_upload_cred(admin, vid)
    payload = os.urandom(size)
    try:
        _sftp_put(tu, tc, f"/{vname}/blob.bin", payload)
        fid = _file_id(admin, vid, "blob.bin")
        assert fid is not None, "streamed file was not created"
        got = admin.get(f"/vaults/{vid}/files/{fid}/download").content
        assert got == payload, f"round-trip mismatch at size {size}: got {len(got)} of {size}"
    finally:
        admin.delete_vault(vid)


def test_streaming_atomic_same_name_replace(admin):
    # Uploading the same name twice replaces (not duplicates) the file, and the surviving copy is the
    # second upload -- the atomic overwrite runs inside finalize, same as the buffered/web path.
    v = admin.create_vault(name=unique("strm"))
    vid, vname = v["id"], v["name"]
    tu, tc = _mint_upload_cred(admin, vid)
    first, second = os.urandom(200_000), os.urandom(300_000)
    try:
        # Both uploads over ONE SFTP session (reconnecting rapidly with the same cred is a separate,
        # connection-admission concern; the round-trip tests already cover fresh-connection uploads).
        with sftp_session(tu, tc) as sftp:
            with sftp.open(f"/{vname}/dup.bin", "wb") as fh:
                fh.set_pipelined(True)
                fh.write(first)
            with sftp.open(f"/{vname}/dup.bin", "wb") as fh:
                fh.set_pipelined(True)
                fh.write(second)
        rows = [it for it in admin.get(f"/vaults/{vid}/files").json()["items"]
                if it.get("name") == "dup.bin" and it.get("type") == "file"]
        assert len(rows) == 1, f"expected one dup.bin after replace, found {len(rows)}"
        got = admin.get(f"/vaults/{vid}/files/{rows[0]['id']}/download").content
        assert got == second, "the surviving copy must be the second (replacing) upload"
    finally:
        admin.delete_vault(vid)


def test_streaming_read_only_member_cannot_open(admin, temp_user, temp_user_client):
    # A read-only member is refused at open() over SFTP too (the streaming path keeps the open()-time
    # write-permission gate). Minting an SFTP cred for a read-only member and putting a file must fail,
    # and no file lands.
    v = admin.create_vault(name=unique("strm"))
    vid, vname = v["id"], v["name"]
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "read"})
    # A member mints their own SFTP cred over their (read-only) access.
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": _CAPS,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False,
                      "delegate": False}}
    body = temp_user_client.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vid, "caps": _CAPS}]})
    try:
        if body.status_code != 200:
            pytest.skip("read-only member cannot mint an upload-capable SFTP cred (delegation floor)")
        tu, tc = body.json()["temp_username"], body.json()["credential"]
        # An SFTP upload need not RAISE for a read-only member: the streaming path re-checks write
        # permission in upload_file_streaming and drops the upload, and an SFTP close cannot signal
        # failure to the client. The security property is that NO FILE LANDS.
        try:
            _sftp_put(tu, tc, f"/{vname}/nope.bin", os.urandom(50_000))
        except Exception:
            pass  # a protocol-level refusal is equally fine
        assert _file_id(admin, vid, "nope.bin") is None, "a read-only member must land no file"
    finally:
        admin.delete_vault(vid)
