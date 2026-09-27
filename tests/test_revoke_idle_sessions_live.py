"""Live: ending a user's sessions also ends the web sessions that have gone idle.

A user signs in, and the session row is then marked inactive the way the periodic cleanup marks a
session that has been idle for its grace window (about an hour; a web request never updates that idle
time). The token still works: a regular token is refused only when its row is missing or revoked.
Terminating the user's sessions, an administrator's password change and a self-service password
change must each revoke that session, so the old token answers 401.

test_revoke_idle_sessions.py covers the same offline.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_STRONG = "Str0ng!Idle#Rotated7"


def _psql(sql):
    try:
        r = subprocess.run(
            ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-Atc", sql],
            capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    skip_if_container_absent(r, _DB_CONTAINER)
    assert r.returncode == 0, r.stderr[:300]
    return r.stdout.strip()


def _signed_in(user):
    client = ApiClient(BASE_URL)
    client.login(user["_username"], user["_password"])
    assert client.get("/users/me").status_code == 200
    return client


def _let_idle_sessions_lapse(user_id):
    """What the cleanup does to a session idle past its grace window: it marks the row inactive.
    Returns how many rows it marked."""
    return int(_psql(
        "WITH idled AS (UPDATE active_sessions SET is_active = false, "
        "last_activity = (now() AT TIME ZONE 'utc') - interval '2 hours' "
        f"WHERE user_id = '{user_id}' AND is_active RETURNING 1) SELECT count(*) FROM idled"))


def _idle_session(user):
    client = _signed_in(user)
    assert _let_idle_sessions_lapse(user["id"]) == 1
    # The anchor: the idle session's token still works. Without it, a 401 below would prove nothing.
    assert client.get("/users/me").status_code == 200, "an idle session's token is expected to still work"
    return client


def test_terminating_sessions_ends_an_idle_one(admin, temp_user):
    idle = _idle_session(temp_user)

    r = admin.post(f"/users/{temp_user['id']}/terminate-sessions")
    assert r.status_code == 200, r.text
    assert r.json()["terminated_count"] == 1, r.json()

    assert idle.get("/users/me").status_code == 401, "the idle session survived terminate-sessions"
    assert _psql(f"SELECT bool_and(revoked) FROM active_sessions WHERE user_id = '{temp_user['id']}'") == "t"


def test_an_admin_password_change_ends_an_idle_session(admin, temp_user):
    idle = _idle_session(temp_user)

    r = admin.patch(f"/users/{temp_user['id']}", json={"password": _STRONG})
    assert r.status_code == 200, r.text

    assert idle.get("/users/me").status_code == 401, "the idle session survived an admin password change"


def test_a_self_service_password_change_ends_the_accounts_idle_session(temp_user):
    idle = _idle_session(temp_user)
    current = _signed_in(temp_user)

    r = current.patch("/users/me", json={"current_password": temp_user["_password"],
                                         "new_password": _STRONG})
    assert r.status_code == 200, r.text

    assert idle.get("/users/me").status_code == 401, "the idle session survived a password change"
    assert current.get("/users/me").status_code == 401, "the session that made the change is ended too"
