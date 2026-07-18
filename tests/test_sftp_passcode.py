"""SFTP authorization for a passcode-bearing temporary credential + no-downgrade on password change.

A temp credential that proved a vault's real password at mint (required to also issue a passcode)
carries a password fingerprint, so SFTP authorizes it via the existing mint-time proof — the holder
reaches the vault over SFTP without knowing the real password (SFTP has no per-request passcode
channel). A later vault-password change voids that standing proof (no downgrade). Needs a live SFTP
service (skips if unreachable — e.g. an API-only stack).
"""
import contextlib
import os
import socket
import subprocess

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import unique  # noqa: E402

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
_PW = "Sup3r-Secret-PW-9!"


def _reachable():
    try:
        with socket.create_connection((SFTP_HOST, SFTP_PORT), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason=f"SFTP not reachable at {SFTP_HOST}:{SFTP_PORT}")


def _psql(sql):
    subprocess.run(["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


@contextlib.contextmanager
def _sftp(username, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, password=password)
        s = paramiko.SFTPClient.from_transport(t)
        try:
            yield s
        finally:
            s.close()
    finally:
        t.close()


_CAPS = ["vault.see_info", "vault.see_files", "file.download"]


def _mint_passcode_cred(admin, vault_id):
    """A temp cred that proves the vault password (required to issue a passcode) — so it carries the
    SFTP fingerprint proof AND a passcode."""
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": _CAPS, "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": _CAPS, "password": _PW, "issue_passcode": True}]}).json()
    assert body["passcodes"], "expected a passcode to be issued"
    return body["temp_username"], body["credential"]


def test_passcode_credential_authorized_over_sftp(admin):
    admin.put("/settings", json={"temp_passcodes_enabled": True})
    v = admin.create_vault(name=unique("sftppc"), password=_PW)
    vid, vname = v["id"], v["name"]
    try:
        admin.post(f"/vaults/{vid}/files", files=[("files", ("f.txt", b"sftp-secret", "text/plain"))],
                   headers={"X-Vault-Password": _PW}).raise_for_status()
        user, cred = _mint_passcode_cred(admin, vid)
        with _sftp(user, cred) as s:
            assert vname in set(s.listdir("/"))                 # password-protected vault is reachable
            assert "f.txt" in set(s.listdir(f"/{vname}"))
            with s.open(f"/{vname}/f.txt", "rb") as fh:
                assert fh.read() == b"sftp-secret"              # downloadable without the real password
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_password_change_voids_sftp_proof(admin):
    """No downgrade: after the vault password changes, the credential's standing SFTP proof is void."""
    admin.put("/settings", json={"temp_passcodes_enabled": True})
    v = admin.create_vault(name=unique("sftppc2"), password=_PW)
    vid, vname = v["id"], v["name"]
    try:
        admin.post(f"/vaults/{vid}/files", files=[("files", ("f.txt", b"x", "text/plain"))],
                   headers={"X-Vault-Password": _PW}).raise_for_status()
        # two creds (SFTP auth is one-time per credential); both carry the fingerprint of the CURRENT hash
        u1, c1 = _mint_passcode_cred(admin, vid)
        u2, c2 = _mint_passcode_cred(admin, vid)
        with _sftp(u1, c1) as s:
            assert vname in set(s.listdir("/"))                 # authorized before the change
        # simulate a vault-password change/rotation -> the stored fingerprint no longer matches
        _psql(f"UPDATE vaults SET password_hash = password_hash || 'x' WHERE id = '{vid}';")
        with _sftp(u2, c2) as s:
            assert vname not in set(s.listdir("/"))             # standing proof voided -> vault hidden
    finally:
        _psql(f"UPDATE vaults SET password_hash = NULL WHERE id = '{vid}';")  # unbreak so delete needs no pw
        admin.delete_vault(vid)
