"""The two-step login: an enrolled account gets NO session from the password step — it must present the
second factor. A pre-auth token cannot reach a real endpoint; a non-enrolled account logs in unchanged.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor as sf          # noqa: E402
from conftest import ApiClient, BASE_URL          # noqa: E402


def _totp(secret, step_offset=0):
    return sf._totp_at_step(secret, sf.current_totp_step() + step_offset)


def _enroll(user, client):
    secret = client.post("/users/me/second-factor/totp/enroll",
                         json={"current_password": user["_password"]}).json()["secret"]
    client.post("/users/me/second-factor/totp/confirm", json={"code": _totp(secret)}).raise_for_status()
    client.post("/users/me/second-factor/recovery/acknowledge").raise_for_status()
    return secret


def test_two_step_login_for_an_enrolled_user(temp_user, temp_user_client):
    secret = _enroll(temp_user, temp_user_client)

    # A fresh login now returns NO session — just a pre-auth challenge.
    fresh = ApiClient()
    r = fresh.session.post(f"{BASE_URL}/auth/login",
                           json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] is None and body["second_factor_required"] is True
    assert body["enrollment_required"] is False and "totp" in body["methods"] and "recovery" in body["methods"]
    pre = body["pre_auth_token"]
    ph = {"Authorization": f"Bearer {pre}"}

    # The pre-auth token has no session_token, so it cannot reach a normal endpoint.
    assert fresh.session.get(f"{BASE_URL}/users/me/second-factor", headers=ph).status_code == 401

    # A wrong code is refused and mints no session.
    assert fresh.session.post(f"{BASE_URL}/auth/second-factor/verify", headers=ph,
                              json={"method": "totp", "code": "000000"}).status_code == 401

    # A correct code (next step, so it isn't the one the enrollment confirm already consumed) mints the
    # real session.
    r = fresh.session.post(f"{BASE_URL}/auth/second-factor/verify", headers=ph,
                           json={"method": "totp", "code": _totp(secret, 1)})
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    assert tok
    # The session works and reports the enrollment.
    assert fresh.session.get(f"{BASE_URL}/users/me/second-factor",
                             headers={"Authorization": f"Bearer {tok}"}).json()["enrolled"] is True
    # The pre-auth token is single-use — it's now consumed.
    assert fresh.session.post(f"{BASE_URL}/auth/second-factor/verify", headers=ph,
                              json={"method": "totp", "code": _totp(secret, 1)}).status_code == 401


def test_non_enrolled_user_logs_in_in_one_step(temp_user):
    c = ApiClient()
    r = c.session.post(f"{BASE_URL}/auth/login",
                       json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert r.status_code == 200 and r.json().get("access_token")


def test_recovery_code_logs_in_and_is_consumed(temp_user, temp_user_client):
    # enroll, capturing the recovery codes
    secret = temp_user_client.post("/users/me/second-factor/totp/enroll",
                                   json={"current_password": temp_user["_password"]}).json()["secret"]
    codes = temp_user_client.post("/users/me/second-factor/totp/confirm",
                                  json={"code": _totp(secret)}).json()["recovery_codes"]
    temp_user_client.post("/users/me/second-factor/recovery/acknowledge").raise_for_status()

    fresh = ApiClient()
    pre = fresh.session.post(f"{BASE_URL}/auth/login",
                             json={"username": temp_user["_username"], "password": temp_user["_password"]}
                             ).json()["pre_auth_token"]
    r = fresh.session.post(f"{BASE_URL}/auth/second-factor/verify",
                           headers={"Authorization": f"Bearer {pre}"},
                           json={"method": "recovery", "code": codes[0]})
    assert r.status_code == 200, r.text
    assert r.json()["recovery_code_used"] is True and r.json()["recovery_codes_remaining"] == 9
