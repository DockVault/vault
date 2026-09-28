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
def second_admin(admin, *, independent=False):
    """Another administrator account, signed in. Deleted afterwards. ``independent``: made one that may
    approve the session's administrator's changes, and have its own approved by it (make_independent)."""
    account = admin.create_user(role="admin")
    if independent:
        make_independent(account["id"])
    client = ApiClient(BASE_URL)
    client.login(account["_username"], account["_password"])
    try:
        yield account, client
    finally:
        admin.delete_user(account["id"])


def make_independent(admin_id, *, days=15):
    """Make an administrator a test created independent of every other one, and of long standing, as
    far as approving a held change goes (app/core/credential_changes.py).

    An administrator a test creates is neither: its record names its creator as its maker (so neither
    may approve the other's changes), and it was made a moment ago (an approver must have been one for
    14 days before the request). So its record is rewritten in the database, as if the server's
    operator had made it an administrator ``days`` ago with the host tool: no maker among the
    administrators, no lineage."""
    psql(f"UPDATE admin_grants SET granted_by_id = NULL, granted_by_name = 'operator@host', "
         f"granted_at = (now() AT TIME ZONE 'utc') - interval '{int(days)} days', lineage = '[]' "
         f"WHERE user_id = '{admin_id}'")
    assert psql(f"SELECT granted_by_id IS NULL, lineage::text FROM admin_grants "
                f"WHERE user_id = '{admin_id}'") == "t|[]", "no record to rewrite"


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


# --- signing in from a second address, and the automatic locks -------------------------------------

REDIS = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")


def reset_sign_in_throttle():
    """Clear the sign-in throttle's buckets, so a test that counts failures meets the lock, not the
    throttle that fires at the same count within its window."""
    r = subprocess.run(["docker", "exec", REDIS, "sh", "-c",
                        "redis-cli --scan --pattern 'rate_limit:login_user:*' | xargs -r redis-cli del; "
                        "redis-cli --scan --pattern 'rate_limit:login_ip:*' | xargs -r redis-cli del"],
                       capture_output=True, text=True, timeout=30)
    skip_if_container_absent(r, REDIS)


SFTP_CONTAINER = os.environ.get("VAULT_SFTP_CONTAINER", "vault-sftp")


def sign_in_from_inside(username, password, *, container=None, url="http://127.0.0.1:8000"):
    """Sign in over HTTP from inside a container of the stack, so the vault sees the request come from
    another source address than the host's: 127.0.0.1 from the web container itself, or the SFTP
    container's own address when run there against http://vault-api:8000. Returns
    (status, body, Retry-After)."""
    container = container or API
    script = (
        "import json, urllib.request, urllib.error\n"
        f"data = json.dumps({{'username': {username!r}, 'password': {password!r}}}).encode()\n"
        f"req = urllib.request.Request({url + '/auth/login'!r}, data=data,\n"
        "                             headers={'Content-Type': 'application/json'})\n"
        "try:\n"
        "    r = urllib.request.urlopen(req, timeout=60)\n"
        "    print(json.dumps([r.status, json.loads(r.read() or b'null'), None]))\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(json.dumps([e.code, json.loads(e.read() or b'null'), e.headers.get('Retry-After')]))\n")
    try:
        r = subprocess.run(["docker", "exec", "-i", container, "python", "-c", script],
                           capture_output=True, text=True, timeout=90)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, container)
    assert r.returncode == 0, (r.stderr or r.stdout)[-600:]
    import json
    return tuple(json.loads(r.stdout.strip().splitlines()[-1]))


def lock_rows(user_id):
    """{source: (failed_attempts, locked)} for the account's rows in sign_in_lockouts."""
    out = psql(f"SELECT source, failed_attempts, locked_at IS NOT NULL FROM sign_in_lockouts "
               f"WHERE user_id='{user_id}'")
    rows = {}
    for line in out.splitlines():
        source, count, locked = line.split("|")
        rows[source] = (int(count), locked == "t")
    return rows


def arm_lock(user_id, source, minutes=10):
    """Put an automatic lock in force directly: `source` is an address, or '*' for account-wide."""
    psql("INSERT INTO sign_in_lockouts (id, user_id, source, failed_attempts, window_start, last_failure_at, "
         "locked_at, locked_until) VALUES (gen_random_uuid(), "
         f"'{user_id}', '{source}', 1000, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', "
         f"now() AT TIME ZONE 'utc', (now() AT TIME ZONE 'utc') + interval '{int(minutes)} minutes') "
         "ON CONFLICT (user_id, source) DO UPDATE SET locked_at = EXCLUDED.locked_at, "
         "locked_until = EXCLUDED.locked_until, failed_attempts = EXCLUDED.failed_attempts")


def host_address(admin, username):
    """The address the vault sees this test's host requests come from: that of a failed sign-in just
    made from here under `username`."""
    rows = admin.get("/audit/log", params={"action": "login_failure", "limit": 200}).json()
    mine = [r for r in rows if r["username"] == username and r.get("ip_address")]
    assert mine, "no failed sign-in from this host was recorded"
    return mine[0]["ip_address"]
