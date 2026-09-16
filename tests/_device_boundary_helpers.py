"""Shared helpers for the device-boundary hotfix tests (three sibling modules use these).

Everything here talks to the running deployment — routes over HTTP, the real SFTP door, the cache
paused via docker. No source-text assertions live in any of the three modules.
"""
import os
import subprocess
import time

import paramiko

from conftest import ApiClient, BASE_URL, unique

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")


def temp_login(admin):
    """A hand-out (interactive) temporary credential, logged in as its own web session."""
    tc = admin.post("/auth/temp-credentials", json={"note": unique("boundary")}).json()
    sess = ApiClient(BASE_URL)
    sess.login(tc["temp_username"], tc["credential"])
    return sess, tc


def register_device(admin, label="sync-box"):
    r = admin.post("/devices", json={"label": unique(label)})
    r.raise_for_status()
    return r.json()  # {device_id, label, secret, ...}


def grant(admin, device_id, vault_id):
    r = admin.post(f"/devices/{device_id}/grants", json={"vault_id": str(vault_id)})
    r.raise_for_status()
    return r.json()


def mint_sync_cred(secret, vault_id):
    """Mint a single-use SFTP credential as the device (Device-Bearer), returning the raw response."""
    anon = ApiClient(BASE_URL)
    return anon.session.post(
        f"{BASE_URL}/device/sync-credential",
        json={"vault_id": str(vault_id)},
        headers={"Authorization": f"Bearer {secret}"},
        timeout=15,
    )


def cred_row(admin, temp_username):
    """The owner's view of one temp credential from /temp-creds/list, or None."""
    for row in admin.get("/temp-creds/list").json():
        if row.get("temp_username") == temp_username:
            return row
    return None


def sftp_authenticates(temp_username, credential):
    """True iff the credential opens an authenticated SFTP session at the real door."""
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=temp_username, password=credential)
        return t.is_authenticated()
    except (paramiko.SSHException, EOFError, OSError):
        return False
    finally:
        t.close()


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)
