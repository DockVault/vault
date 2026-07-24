"""Every mounted router must share the canonical authentication boundary."""

import base64
import hashlib
import json
import os
import subprocess

from conftest import ApiClient, unique


_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")

_AUTH_PLANES = (
    "/users/me",                    # canonical monolithic dependency
    "/api/dashboard/stats",         # dashboard router
    "/api/user-management/roles",   # user-management router
    "/ecc/keys/public",             # ECC router
)


def _db(sql):
    result = subprocess.run(
        [
            "docker", "exec", _DB_CONTAINER,
            "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _redis(*args):
    result = subprocess.run(
        ["docker", "exec", _REDIS_CONTAINER, "redis-cli", *args],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _token_payload(token):
    encoded = token.split(".")[1]
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))


def _statuses(client):
    return {path: client.get(path).status_code for path in _AUTH_PLANES}


def _assert_all(client, expected):
    statuses = _statuses(client)
    assert statuses == {path: expected for path in _AUTH_PLANES}, statuses


def _expired_token(payload):
    script = r"""
import json
import sys
from datetime import timedelta
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("auth-parity-test")
from app.core.security import create_access_token
print(create_access_token(json.load(sys.stdin), expires_delta=timedelta(seconds=-1)))
"""
    result = subprocess.run(
        ["docker", "exec", "-i", _API_CONTAINER, "python", "-c", script],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    token = [line for line in result.stdout.splitlines() if line.count(".") == 2][-1]
    return token


def test_inactive_account_is_denied_identically_on_every_router(temp_user, temp_user_client):
    try:
        _db(f"UPDATE users SET is_active=false WHERE id='{temp_user['id']}'")
        _assert_all(temp_user_client, 403)
    finally:
        _db(f"UPDATE users SET is_active=true WHERE id='{temp_user['id']}'")


def test_locked_account_is_denied_identically_on_every_router(temp_user, temp_user_client):
    try:
        _db(
            "UPDATE users SET is_locked=true, locked_until=NULL "
            f"WHERE id='{temp_user['id']}'"
        )
        _assert_all(temp_user_client, 403)
    finally:
        _db(
            "UPDATE users SET is_locked=false, failed_login_attempts=0, locked_until=NULL "
            f"WHERE id='{temp_user['id']}'"
        )


def test_redis_denylisted_session_is_denied_identically(temp_user_client):
    session_token = _token_payload(temp_user_client.token)["session_token"]
    key = f"denylist:session:{hashlib.sha256(session_token.encode()).hexdigest()}"
    try:
        _redis("SETEX", key, "120", "1")
        _assert_all(temp_user_client, 401)
    finally:
        _redis("DEL", key)


def test_durably_revoked_session_is_denied_identically(temp_user, temp_user_client):
    session_token = _token_payload(temp_user_client.token)["session_token"].replace("'", "''")
    _db(
        "UPDATE active_sessions SET revoked=true "
        f"WHERE user_id='{temp_user['id']}' AND session_token='{session_token}'"
    )
    _assert_all(temp_user_client, 401)


def test_expired_jwt_is_denied_identically(temp_user_client):
    payload = _token_payload(temp_user_client.token)
    payload.pop("exp", None)
    payload.pop("iat", None)
    expired = temp_user_client.clone_anonymous()
    expired.token = _expired_token(payload)
    expired.session.headers["Authorization"] = f"Bearer {expired.token}"
    _assert_all(expired, 401)


def test_active_then_deactivated_temp_session_has_router_parity(temp_user_client):
    created = temp_user_client.post(
        "/auth/temp-credentials",
        json={"note": unique("router-parity")},
    )
    assert created.status_code == 200, created.text
    credential = created.json()
    temp_client = ApiClient()
    try:
        temp_client.login(credential["temp_username"], credential["credential"])
        _assert_all(temp_client, 200)

        deactivated = temp_user_client.post(
            f"/temp-creds/{credential['temp_username']}/deactivate"
        )
        assert deactivated.status_code == 200, deactivated.text
        _assert_all(temp_client, 401)
    finally:
        temp_user_client.post(f"/temp-creds/{credential['temp_username']}/delete")
