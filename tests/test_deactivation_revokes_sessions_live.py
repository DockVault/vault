"""Live: a token a user held when an administrator deactivated them stays refused after reactivation.

The user signs in twice; one session is then marked inactive the way the periodic cleanup marks a
session that has been idle for its grace window, whose token still works until it is revoked. An
administrator deactivates the user, and reactivates them. Both old tokens must answer 401, while a
new sign-in works: the account is back, its old sessions are not.

Covers the two user-management API routes that deactivate: POST .../toggle-active and
PUT /api/user-management/users/{id}. PATCH /users/{id}, which the web app's Users page uses, already
revoked, and is the control. test_deactivation_revokes_sessions.py covers the same offline.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent

pytestmark = pytest.mark.integration

UM = "/api/user-management"
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


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


def _two_old_sessions(user):
    """A live session and an idle one, both working."""
    idle = _signed_in(user)
    assert _psql("WITH idled AS (UPDATE active_sessions SET is_active = false, "
                 "last_activity = (now() AT TIME ZONE 'utc') - interval '2 hours' "
                 f"WHERE user_id = '{user['id']}' AND is_active RETURNING 1) "
                 "SELECT count(*) FROM idled") == "1"
    assert idle.get("/users/me").status_code == 200, "an idle session's token is expected to work"
    return _signed_in(user), idle


def _set_active(admin, route, user_id, active):
    if route == "toggle-active":
        r = admin.post(f"{UM}/users/{user_id}/toggle-active")
        assert r.status_code == 200, r.text
        assert r.json()["is_active"] is active
    elif route == "put":
        r = admin.put(f"{UM}/users/{user_id}", json={"is_active": active})
        assert r.status_code == 200, r.text
    else:
        r = admin.patch(f"/users/{user_id}", json={"is_active": active})
        assert r.status_code == 200, r.text


@pytest.mark.parametrize("route", ["toggle-active", "put", "patch"])
def test_an_old_token_is_refused_after_the_user_is_reactivated(admin, temp_user, route):
    live, idle = _two_old_sessions(temp_user)

    _set_active(admin, route, temp_user["id"], False)
    for client in (live, idle):
        assert client.get("/users/me").status_code in (401, 403), "a deactivated user got through"

    _set_active(admin, route, temp_user["id"], True)
    assert live.get("/users/me").status_code == 401, f"{route}: a live session survived deactivation"
    assert idle.get("/users/me").status_code == 401, f"{route}: an idle session survived deactivation"
    assert _psql(f"SELECT bool_and(revoked) FROM active_sessions WHERE user_id = '{temp_user['id']}'") == "t"

    # The account itself is back: a new sign-in works.
    assert _signed_in(temp_user).get("/users/me").status_code == 200
