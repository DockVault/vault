"""Shared helpers for the live tests of administrators' changes to other people's accounts.

A second administrator, SQL and code run inside the stack's containers, a mail sink, and the
notifications an account was sent. Imported by the test modules that need them; holds no tests.
"""
import os
import subprocess
import time
from contextlib import contextmanager

import pytest
import requests

from conftest import ApiClient, BASE_URL, skip_if_container_absent

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = int(os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025"))


def psql(sql: str) -> str:
    """Run one statement against the stack's database and return its unaligned output."""
    try:
        r = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db",
                            "-v", "ON_ERROR_STOP=1", "-Atc", sql],
                           capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    skip_if_container_absent(r, DB)
    assert r.returncode == 0, r.stderr[:300]
    return r.stdout.strip()


def in_api_container(source: str, *, check=True) -> subprocess.CompletedProcess:
    """Run Python inside the web container, with the application's own configuration loaded."""
    script = ("from app.core.config import bootstrap_entrypoint\n"
              "bootstrap_entrypoint('account-change-test')\n" + source)
    try:
        r = subprocess.run(["docker", "exec", "-i", API, "python", "-c", script],
                           capture_output=True, text=True, timeout=90)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, API)
    if check:
        assert r.returncode == 0, (r.stderr or r.stdout)[-800:]
    return r


@contextmanager
def second_admin(admin):
    """Another administrator account, signed in. Deleted afterwards."""
    account = admin.create_user(role="admin")
    client = ApiClient(BASE_URL)
    client.login(account["_username"], account["_password"])
    try:
        yield account, client
    finally:
        admin.delete_user(account["id"])


def notifications(client, ntype=None):
    r = client.get("/notifications", params={"limit": 100})
    assert r.status_code == 200, r.text
    rows = r.json()["notifications"]
    return [n for n in rows if ntype is None or n["type"] == ntype]


def signed_in(user):
    client = ApiClient(BASE_URL)
    client.login(user["_username"], user["_password"])
    return client


@contextmanager
def mail_sink(admin):
    """Make the vault able to send mail for the duration: a default sending profile pointing at the
    round's Mailpit when there is one, otherwise at a local port nothing listens on (the vault then
    counts as email-configured and every send fails at once). The previous default is restored.
    Yields True when messages really arrive somewhere they can be read."""
    before = admin.get("/email/profiles").json().get("profiles", [])
    previous_default = next((p for p in before if p.get("is_default")), None)
    real = bool(MAILPIT_URL and MAILPIT_SMTP_HOST)
    r = admin.post("/email/profiles", json={
        "name": "account-change tests", "smtp_server": MAILPIT_SMTP_HOST if real else "127.0.0.1",
        "smtp_port": MAILPIT_SMTP_PORT if real else 9, "smtp_username": "",
        "from_email": "vault-tests@example.com", "is_default": True})
    assert r.status_code in (200, 201), r.text
    created = r.json()["id"]
    try:
        yield real
    finally:
        admin.delete(f"/email/profiles/{created}")
        if previous_default is not None:
            restore = {k: previous_default.get(k) for k in (
                "name", "description", "smtp_server", "smtp_port", "smtp_username", "from_email",
                "from_name", "smtp_allow_insecure_tls")}
            restore["is_default"] = True
            admin.put(f"/email/profiles/{previous_default['id']}",
                      json={k: v for k, v in restore.items() if v is not None})


def mail_to(address, subject_contains=None, timeout=20.0):
    """The newest Mailpit message to ``address`` (optionally with a subject containing the text), with
    its plain-text body, or None. Reads only; never deletes anyone's messages."""
    if not MAILPIT_URL:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{MAILPIT_URL}/api/v1/search", params={"query": f"to:{address}"}, timeout=10)
        for m in r.json().get("messages", []):
            if subject_contains is None or subject_contains in (m.get("Subject") or ""):
                body = requests.get(f"{MAILPIT_URL}/api/v1/message/{m['ID']}", timeout=10).json()
                return {"subject": m.get("Subject") or "", "text": body.get("Text") or ""}
        time.sleep(0.5)
    return None
