"""Live: an administrator's automatic lock with no end ends, a user's does not, and the server's operator
unlocks an account from the host (python -m app.core.host_operator unlock, which `dockvault.py accounts
--action unlock` runs in this container).

A lock with no end is what a lockout duration of 0 arms; the locks here are written as such a lock is
stored (sign_in_lockouts, account-wide, locked_until NULL), armed long enough ago that an administrator's
would have ended. test_administrator_lock_ends.py covers the arming and the rules offline.
"""
import json
import subprocess
import uuid

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent
from _account_change_helpers import API, psql

pytestmark = pytest.mark.integration

HOST = "operator@host"


def _tool(*args):
    r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", "app.core.host_operator", *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines, (r.stderr or "")[-800:]
    return r.returncode, json.loads(lines[-1])


def _open_lock(uid, *, hours_ago):
    """An account-wide automatic lock with no end, armed ``hours_ago`` hours ago: it refuses new sign-ins
    to the account from every address."""
    psql("INSERT INTO sign_in_lockouts (id, user_id, source, failed_attempts, window_start, last_failure_at, "
         f"locked_at, locked_until) VALUES ('{uuid.uuid4()}', '{uid}', '*', 20, "
         f"(now() AT TIME ZONE 'utc') - interval '{hours_ago} hours', "
         f"(now() AT TIME ZONE 'utc') - interval '{hours_ago} hours', "
         f"(now() AT TIME ZONE 'utc') - interval '{hours_ago} hours', NULL)")


def _sign_in(name, password):
    client = ApiClient(BASE_URL)
    r = client.session.post(f"{BASE_URL}/auth/login", json={"username": name, "password": password}, timeout=20)
    return r.status_code


def test_an_administrators_lock_with_no_end_ends_and_a_users_does_not(admin):
    administrator, user = admin.create_user(role="admin"), admin.create_user()
    for account in (administrator, user):
        _open_lock(account["id"], hours_ago=6)
    assert _sign_in(user["_username"], user["_password"]) == 403
    assert _sign_in(administrator["_username"], administrator["_password"]) == 200
    ended = psql(f"SELECT locked_at IS NULL FROM sign_in_lockouts WHERE user_id = '{administrator['id']}'")
    assert ended == "t", "the administrator's lock was given an end and released"
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'account_auto_unlocked' "
                f"AND resource_id = '{administrator['id']}'") == "1"
    assert psql(f"SELECT locked_until IS NULL FROM sign_in_lockouts WHERE user_id = '{user['id']}'") == "t"


def test_the_host_unlock_clears_an_administrators_lock_and_the_automatic_one(admin):
    account = admin.create_user()
    uid, name = account["id"], account["_username"]
    r = admin.post(f"/api/user-management/users/{uid}/toggle-locked")
    assert r.status_code == 200 and r.json()["is_locked"] is True, r.text
    _open_lock(uid, hours_ago=1)
    assert _sign_in(name, account["_password"]) == 403

    code, answer = _tool("unlock", "--username", name, "--confirm-username", name.upper())
    assert code == 2 and not answer["ok"], "nothing changes unless the username is typed again exactly"
    assert _sign_in(name, account["_password"]) == 403

    code, answer = _tool("unlock", "--username", name, "--confirm-username", name)
    assert code == 0 and answer == {"ok": True, "account": name, "was_locked": True, "sign_in_locks_cleared": 1}
    assert _sign_in(name, account["_password"]) == 200
    assert psql(f"SELECT count(*) FROM sign_in_lockouts WHERE user_id = '{uid}'") == "0"
    row = psql("SELECT username, details::jsonb ->> 'was_locked' FROM audit_logs WHERE action = 'USER_LOCK_CHANGED' "
               f"AND resource_id = '{uid}' AND username = '{HOST}'")
    assert row == f"{HOST}|true"
