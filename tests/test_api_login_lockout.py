"""A locked account reports the lock — but only to a caller who proves the password.

A wrong password on a locked account still returns the uniform generic 401 so the lock
state can't be used to enumerate accounts.
"""
import os
import subprocess

import pytest


def _login(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password})


def _psql(sql):
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    return subprocess.run(
        ["docker", "exec", container, "psql", "-U", "sftp_user", "-d", "sftp_db", "-c", sql],
        capture_output=True, text=True, timeout=15,
    )


def test_locked_account_correct_password_reports_lock(admin):
    u = admin.create_user()
    admin.patch(f"/users/{u['id']}", json={"is_locked": True})
    try:
        r = _login(admin.clone_anonymous(), u["_username"], u["_password"])
        assert r.status_code == 403, r.text        # not the generic 401
        assert "lock" in r.text.lower()
    finally:
        admin.delete_user(u["id"])


def test_locked_account_wrong_password_stays_generic(admin):
    # verify-first ordering: a wrong password on a locked account must NOT reveal the lock,
    # or the lock state becomes an account-enumeration oracle.
    u = admin.create_user()
    admin.patch(f"/users/{u['id']}", json={"is_locked": True})
    try:
        r = _login(admin.clone_anonymous(), u["_username"], "definitely-the-wrong-password")
        assert r.status_code == 401, r.text
        assert "lock" not in r.text.lower()
    finally:
        admin.delete_user(u["id"])


def test_timed_lockout_reports_minutes_and_retry_after(admin):
    # the common failed-login auto-lock sets a FUTURE locked_until; the correct-password login
    # should report a temporary lock with a retry hint (set the lock directly — the auto-lock
    # threshold is tuned high in the test env so it won't trip on a few attempts).
    u = admin.create_user()
    try:
        try:
            r = _psql(
                f"UPDATE users SET is_locked=true, locked_until=now()+interval '10 minutes' "
                f"WHERE username='{u['_username']}';"
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"docker/psql unavailable: {exc}")
        if r.returncode != 0 or "UPDATE 1" not in (r.stdout + r.stderr):
            pytest.skip(f"could not set a timed lock: {r.stderr[:200]}")
        resp = _login(admin.clone_anonymous(), u["_username"], u["_password"])
        assert resp.status_code == 403, resp.text
        assert "minute" in resp.text.lower()          # the timed-lock copy, not the permanent one
        assert int(resp.headers.get("Retry-After", "0")) > 0
    finally:
        admin.delete_user(u["id"])
