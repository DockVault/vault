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


def register_device(admin, label="sync-box", timeout=90):
    # Explicit timeout: a caller exercising a cache outage bounds every request at a value that
    # covers the worst-case count of per-call socket-timeout stalls (a paused Redis) with margin.
    r = admin.session.post(f"{BASE_URL}/devices", json={"label": unique(label)}, timeout=timeout)
    r.raise_for_status()
    return r.json()  # {device_id, label, secret, ...}


def grant(admin, device_id, vault_id, timeout=90):
    r = admin.session.post(f"{BASE_URL}/devices/{device_id}/grants",
                           json={"vault_id": str(vault_id)}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def mint_sync_cred(secret, vault_id, timeout=90):
    """Mint a single-use SFTP credential as the device (Device-Bearer), returning the raw response."""
    anon = ApiClient(BASE_URL)
    return anon.session.post(
        f"{BASE_URL}/device/sync-credential",
        json={"vault_id": str(vault_id)},
        headers={"Authorization": f"Bearer {secret}"},
        timeout=timeout,  # bounded high so a cache-outage caller waits out socket stalls, not a false red
    )


def preflight(secret, timeout=90):
    """Call GET /device/sync-preflight as the device (Device-Bearer), returning the raw response.
    Bounded high so a cache-outage caller waits out socket stalls rather than reading a false red."""
    anon = ApiClient(BASE_URL)
    return anon.session.get(
        f"{BASE_URL}/device/sync-preflight",
        headers={"Authorization": f"Bearer {secret}"},
        timeout=timeout,
    )


def cred_row(admin, temp_username, timeout=90):
    """The owner's view of one temp credential from /temp-creds/list, or None."""
    for row in admin.session.get(f"{BASE_URL}/temp-creds/list", timeout=timeout).json():
        if row.get("temp_username") == temp_username:
            return row
    return None


def sftp_authenticates(temp_username, credential):
    """True iff the credential opens an authenticated SFTP session at the real door."""
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    # Bounded high (not the default 15 s): during a cache outage the SFTP auth path pays the same
    # per-call socket-timeout stalls, so a tight banner/auth timeout would be a false red, not a bug.
    t.banner_timeout = 90
    t.auth_timeout = 90
    try:
        t.connect(username=temp_username, password=credential)
        return t.is_authenticated()
    except (paramiko.SSHException, EOFError, OSError):
        return False
    finally:
        t.close()


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)
