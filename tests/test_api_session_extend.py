"""Staying signed in (POST /auth/session/extend).

A new token for the same account; the session behind the old one ends at once, so the old token is refused
everywhere and the extend request cannot be replayed; the token carries how and when the person signed in; a
renewal is refused once a second factor is needed that the token does not show; a temporary credential's
session is not extended; the renewal limit setting is bounded; recorded.
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
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info", "vault.see_files"], "temp": {}}
        tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30, "scope": scope,
                                                        "vault_access_mode": "all", "selected_vaults": []})
        assert tc.status_code == 200, tc.text   # the test is not optional: a credential is minted here
        t = ApiClient(); t.login(tc.json()["temp_username"], tc.json()["credential"])
        assert _extend(t.token).status_code == 403
        assert _me(t.token).status_code == 200   # and its own session still works
    finally:
        admin.delete_vault(v["id"])


def _claims(token):
    import base64
    import json
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_a_renewal_carries_how_the_person_signed_in_and_when(admin):
    from _sf_helpers import enroll_totp, totp
    u = admin.create_user(role="user")
    try:
        c = ApiClient(); c.login(u["_username"], u["_password"])
        secret, _codes = enroll_totp(u, c)
        # A two-step sign-in: the token says password and TOTP, and when the factor was proved.
        pre = requests.post(f"{BASE_URL}/auth/login", json={"username": u["_username"], "password": u["_password"]},
                            timeout=15).json()["pre_auth_token"]
        r = requests.post(f"{BASE_URL}/auth/second-factor/verify", headers={"Authorization": f"Bearer {pre}"},
                          json={"method": "totp", "code": totp(secret, 1)}, timeout=15)
        assert r.status_code == 200, r.text
        first = r.json()["access_token"]
        before = _claims(first)
        assert before["amr"] == ["pwd", "totp"] and before["mfa_at"]
        renewed = _extend(first)
        assert renewed.status_code == 200, renewed.text
        after = _claims(renewed.json()["access_token"])
        assert after["amr"] == before["amr"] and after["mfa_at"] == before["mfa_at"]
        assert after["auth_time"] == before["iat"]          # the sign-in, not the renewal
        again = _claims(_extend(renewed.json()["access_token"]).json()["access_token"])
        assert again["auth_time"] == before["iat"] and again["amr"] == before["amr"]
        rows = _psql(f"SELECT details::text FROM audit_logs WHERE action='session_extended' AND username='{u['_username']}' "
                     "ORDER BY timestamp DESC LIMIT 1")
        assert '"ended_session"' in rows and '"new_session"' in rows and '"signed_in_at"' in rows
    finally:
        admin.delete_user(u["id"])


def test_a_renewal_is_refused_once_the_account_needs_a_second_factor_its_token_does_not_show(admin):
    from _sf_helpers import enroll_totp
    u = admin.create_user(role="user")
    try:
        c = ApiClient(); c.login(u["_username"], u["_password"])
        assert _extend(c.token).status_code == 200
        c.login(u["_username"], u["_password"])
        # Enrolled after signing in with the password alone: this sign-in is not renewed, and goes on until it ends.
        enroll_totp(u, c)
        r = _extend(c.token)
        assert r.status_code == 403 and "second factor" in r.text, r.text
        assert _me(c.token).status_code == 200
    finally:
        admin.delete_user(u["id"])


def test_the_renewal_limit_setting_is_bounded_by_the_timeout_and_thirty_days(admin):
    before = admin.get("/settings").json()
    try:
        assert admin.put("/settings", json={"session_renewal_max_hours": 721}).status_code == 400
        assert admin.put("/settings", json={"session_renewal_max_hours": "x"}).status_code == 400
        assert admin.put("/settings", json={"session_renewal_max_hours": -1}).status_code == 400
        r = admin.put("/settings", json={"session_timeout": 180, "session_renewal_max_hours": 2})
        assert r.status_code == 400 and "at least the session timeout" in r.text, r.text
        assert admin.put("/settings", json={"session_timeout": 180, "session_renewal_max_hours": 3}).status_code in (200, 204)
        assert admin.get("/settings").json()["session_renewal_max_hours"] == 3
        assert admin.put("/settings", json={"session_renewal_max_hours": 0}).status_code in (200, 204)
    finally:
        admin.put("/settings", json={"session_timeout": before.get("session_timeout") or 0,
                                     "session_renewal_max_hours": before.get("session_renewal_max_hours") or 0})


def test_a_temporary_credentials_session_knows_when_its_credential_ends(admin):
    v = admin.create_vault(name="extend-temp-end")
    try:
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info", "vault.see_files"], "temp": {}}
        tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30, "scope": scope,
                                                        "vault_access_mode": "all", "selected_vaults": []})
        assert tc.status_code == 200, tc.text
        t = ApiClient(); t.login(tc.json()["temp_username"], tc.json()["credential"])
        probe = requests.get(f"{BASE_URL}/auth/session", headers={"Authorization": f"Bearer {t.token}"}, timeout=15).json()
        assert probe["is_temp_session"] is True and probe["temp_ends_at"].endswith("Z")
        from datetime import datetime, timedelta
        ends = datetime.fromisoformat(probe["temp_ends_at"].replace("Z", ""))
        assert datetime.utcnow() < ends <= datetime.utcnow() + timedelta(minutes=31)
        assert "temp_ends_at" not in requests.get(f"{BASE_URL}/auth/session", headers={"Authorization": f"Bearer {admin.token}"},
                                                  timeout=15).json()
    finally:
        admin.delete_vault(v["id"])
