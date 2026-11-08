"""Staying signed in (POST /auth/session/extend).

A new token for the same account; the session behind the old one ends at once, so the old token is refused
everywhere and the extend request cannot be replayed; a temporary credential's session is not extended;
recorded.
"""
import os
import subprocess

import pytest
import requests

from conftest import ApiClient, BASE_URL

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


def _me(token):
    return requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"}, timeout=15)


def _extend(token):
    return requests.post(f"{BASE_URL}/auth/session/extend", headers={"Authorization": f"Bearer {token}"}, timeout=15)


def test_extend_gives_a_new_token_and_kills_the_old_one(admin):
    u = admin.create_user(role="user")
    try:
        c = ApiClient(); c.login(u["_username"], u["_password"])
        old = c.token
        assert _me(old).status_code == 200
        r = _extend(old)
        assert r.status_code == 200, r.text
        new = r.json()["access_token"]
        assert new and new != old and r.json()["expires_at"].endswith("Z")
        # The new token works; the old one is refused at once, so the same request replayed is refused too.
        assert _me(new).status_code == 200
        assert _me(old).status_code == 401
        assert _extend(old).status_code == 401
        # The new session can be extended again in its turn, and the one before it dies the same way.
        r2 = _extend(new)
        assert r2.status_code == 200, r2.text
        assert _me(new).status_code == 401 and _me(r2.json()["access_token"]).status_code == 200
        assert int(_psql(f"SELECT count(*) FROM audit_logs WHERE action='session_extended' AND username='{u['_username']}'")) >= 2
    finally:
        admin.delete_user(u["id"])


def test_a_temporary_credentials_session_is_not_extended(admin):
    v = admin.create_vault(name="extend-temp")
    try:
        tc = admin.post("/temp-creds", json={"vault_id": v["id"], "duration_minutes": 30, "permissions": ["read"]})
        if tc.status_code != 200:
            pytest.skip(f"no temporary credential here: {tc.status_code} {tc.text[:100]}")
        t = ApiClient(); t.login(tc.json()["username"], tc.json()["password"])
        assert _extend(t.token).status_code == 403
        assert _me(t.token).status_code == 200   # and its own session still works
    finally:
        admin.delete_vault(v["id"])
