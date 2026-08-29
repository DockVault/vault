"""Managing an existing second factor -- disable and regenerate recovery codes -- is gated by the
account.second_factor step-up (an enrolled caller presents their factor to change it)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor as sf   # noqa: E402


def _totp(secret, step_offset=0):
    return sf._totp_at_step(secret, sf.current_totp_step() + step_offset)


def _enroll(user, client):
    secret = client.post("/users/me/second-factor/totp/enroll",
                         json={"current_password": user["_password"]}).json()["secret"]
    client.post("/users/me/second-factor/totp/confirm", json={"code": _totp(secret)}).raise_for_status()
    client.post("/users/me/second-factor/recovery/acknowledge").raise_for_status()
    return secret


def _step_up_receipt(client, secret, action):
    return client.post("/auth/second-factor/step-up",
                       json={"action": action, "method": "totp", "code": _totp(secret, 1)}).json()["receipt"]


def test_disable_requires_step_up(temp_user, temp_user_client):
    secret = _enroll(temp_user, temp_user_client)
    # Without a step-up receipt, disable is refused (account.second_factor ships require_otp on).
    r = temp_user_client.delete("/users/me/second-factor")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["action"] == "account.second_factor"
    # With a receipt it succeeds and the account is no longer enrolled.
    receipt = _step_up_receipt(temp_user_client, secret, "account.second_factor")
    r = temp_user_client.delete("/users/me/second-factor", headers={"X-Second-Factor": receipt})
    assert r.status_code == 200 and r.json()["disabled"] is True
    assert temp_user_client.get("/users/me/second-factor").json()["status"] == "not_setup"


def test_regenerate_recovery_codes_requires_step_up(temp_user, temp_user_client):
    secret = _enroll(temp_user, temp_user_client)
    assert temp_user_client.post("/users/me/second-factor/recovery/regenerate").status_code == 403
    receipt = _step_up_receipt(temp_user_client, secret, "account.second_factor")
    r = temp_user_client.post("/users/me/second-factor/recovery/regenerate",
                              headers={"X-Second-Factor": receipt})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10 and len(set(r.json()["recovery_codes"])) == 10
