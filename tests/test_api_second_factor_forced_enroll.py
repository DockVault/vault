"""Forced enrollment (a required-but-unenrolled user bootstraps their factor from a pre-auth token) and
admin reset of a user's second factor.

Setting mfa_mode=required is global, so every test restores it to 'optional' in a finally. Toggling it
needs the account.second_factor step-up (an enrolled actor + a recovery-code receipt).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import ApiClient, BASE_URL                             # noqa: E402
from _sf_helpers import enrolled_admin, enroll_totp, step_up_receipt, totp   # noqa: E402


def _set_mfa_mode(c, codes, mode):
    r = c.put("/settings", json={"mfa_mode": mode},
              headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                          recovery_codes=codes)})
    r.raise_for_status()


def test_forced_enrollment_bootstraps_a_session(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    newu = admin.create_user(role="user")
    try:
        _set_mfa_mode(c, codes, "required")
        try:
            # A required-but-unenrolled user's fresh login yields enrollment_required + a pre-auth token,
            # NO session.
            fresh = ApiClient()
            r = fresh.session.post(f"{BASE_URL}/auth/login",
                                   json={"username": newu["_username"], "password": newu["_password"]})
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["access_token"] is None and body["second_factor_required"] is True
            assert body["enrollment_required"] is True
            pre = body["pre_auth_token"]
            ph = {"Authorization": f"Bearer {pre}"}

            # The pre-auth token cannot reach a normal endpoint.
            assert fresh.session.get(f"{BASE_URL}/users/me/second-factor", headers=ph).status_code == 401

            # Enroll through the pre-auth token: enroll -> confirm -> acknowledge mints the real session.
            er = fresh.session.post(f"{BASE_URL}/users/me/second-factor/totp/enroll",
                                    headers=ph, json={"current_password": newu["_password"]})
            assert er.status_code == 200, er.text
            secret = er.json()["secret"]
            cr = fresh.session.post(f"{BASE_URL}/users/me/second-factor/totp/confirm",
                                    headers=ph, json={"code": totp(secret)})
            assert cr.status_code == 200, cr.text
            ar = fresh.session.post(f"{BASE_URL}/users/me/second-factor/recovery/acknowledge", headers=ph)
            assert ar.status_code == 200, ar.text
            tok = ar.json().get("access_token")
            assert tok, ar.text

            # The minted session works and reports the enrollment.
            me = fresh.session.get(f"{BASE_URL}/users/me/second-factor",
                                   headers={"Authorization": f"Bearer {tok}"})
            assert me.status_code == 200 and me.json()["enrolled"] is True

            # The pre-auth token is single-use -> a second acknowledge is refused.
            assert fresh.session.post(f"{BASE_URL}/users/me/second-factor/recovery/acknowledge",
                                      headers=ph).status_code == 401
        finally:
            _set_mfa_mode(c, codes, "optional")
    finally:
        admin.delete_user(newu["id"])
        admin.delete_user(ta["id"])


def test_pre_auth_token_of_an_enrolled_user_cannot_reach_the_enroll_endpoints(temp_user, temp_user_client):
    """An already-enrolled user's login pre-auth token (enrollment_required=False) must NOT reach the
    enroll endpoints — those are only for the forced-enrollment path; the enrolled user uses /verify."""
    enroll_totp(temp_user, temp_user_client)
    fresh = ApiClient()
    body = fresh.session.post(f"{BASE_URL}/auth/login",
                              json={"username": temp_user["_username"], "password": temp_user["_password"]}).json()
    assert body["enrollment_required"] is False
    ph = {"Authorization": f"Bearer {body['pre_auth_token']}"}
    assert fresh.session.post(f"{BASE_URL}/users/me/second-factor/totp/enroll",
                              headers=ph, json={"current_password": temp_user["_password"]}).status_code == 401


def test_admin_reset_clears_enrollment_and_revokes_sessions(admin, temp_user, temp_user_client):
    enroll_totp(temp_user, temp_user_client)     # user enrolled; temp_user_client holds a live session
    # admin.user.manage defaults OFF, so the admin needs no step-up receipt here.
    r = admin.post(f"/users/{temp_user['id']}/second-factor/reset")
    assert r.status_code == 200 and r.json()["reset"] is True, r.text
    # The enrollment is gone and the user's session was revoked.
    assert temp_user_client.get("/users/me/second-factor").status_code == 401
    # A fresh login is one-step again (no factor, mode is optional).
    fresh = ApiClient()
    lr = fresh.session.post(f"{BASE_URL}/auth/login",
                            json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert lr.status_code == 200 and lr.json().get("access_token"), lr.text


def test_admin_cannot_reset_own_factor_as_last_enrolled_admin_when_required(admin):
    ta, c, _secret, codes = enrolled_admin(admin)   # c is the (only) enrolled admin on a fresh stack
    try:
        _set_mfa_mode(c, codes, "required")
        try:
            # Own reset is refused while MFA is required and c is the only enrolled admin.
            assert c.post(f"/users/{ta['id']}/second-factor/reset").status_code == 400
        finally:
            _set_mfa_mode(c, codes, "optional")
        # With MFA optional the guard does not apply -> own reset succeeds (and revokes c's session).
        assert c.post(f"/users/{ta['id']}/second-factor/reset").status_code == 200
    finally:
        admin.delete_user(ta["id"])
