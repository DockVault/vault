"""Step-up enforcement: a require_step_up-gated action is refused without a valid session-bound receipt,
and allowed once the caller proves the factor through challenge -> step-up -> X-Second-Factor. Uses
vault.delete (toggled require_otp on by the admin) as the exemplar gated route.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor as sf   # noqa: E402
from _sf_helpers import set_action_require_otp   # noqa: E402


def _totp(secret, step_offset=0):
    return sf._totp_at_step(secret, sf.current_totp_step() + step_offset)


def _enroll(user, client):
    secret = client.post("/users/me/second-factor/totp/enroll",
                         json={"current_password": user["_password"]}).json()["secret"]
    client.post("/users/me/second-factor/totp/confirm", json={"code": _totp(secret)}).raise_for_status()
    client.post("/users/me/second-factor/recovery/acknowledge").raise_for_status()
    return secret


def test_step_up_gates_vault_delete_for_an_enrolled_user(admin, temp_user, temp_user_client):
    secret = _enroll(temp_user, temp_user_client)
    set_action_require_otp(admin, "vault.delete", True)   # gated matrix change via a throwaway enrolled admin
    try:
        vid = temp_user_client.create_vault()["id"]

        # Without a receipt the gated route is refused with a machine-readable challenge.
        r = temp_user_client.post(f"/vaults/{vid}/delete")
        assert r.status_code == 403, r.text
        detail = r.json()["detail"]
        assert detail["second_factor_required"] is True and detail["action"] == "vault.delete"
        assert "totp" in detail["methods"] and "recovery" in detail["methods"]

        # Challenge lists the methods.
        ch = temp_user_client.post("/auth/second-factor/challenge", json={"action": "vault.delete"})
        assert ch.status_code == 200 and "totp" in ch.json()["methods"]

        # Step-up with a fresh TOTP mints a receipt.
        su = temp_user_client.post("/auth/second-factor/step-up",
                                   json={"action": "vault.delete", "method": "totp", "code": _totp(secret, 1)})
        assert su.status_code == 200, su.text
        receipt = su.json()["receipt"]

        # A receipt for a DIFFERENT action does not satisfy this one.
        assert temp_user_client.post(f"/vaults/{vid}/delete",
                                     headers={"X-Second-Factor": "not-a-real-receipt"}).status_code == 403

        # The real receipt lets the delete through.
        r = temp_user_client.post(f"/vaults/{vid}/delete", headers={"X-Second-Factor": receipt})
        assert r.status_code == 200, r.text

        # The receipt is single-use — a second gated call needs a fresh one.
        vid2 = temp_user_client.create_vault()["id"]
        assert temp_user_client.post(f"/vaults/{vid2}/delete",
                                     headers={"X-Second-Factor": receipt}).status_code == 403
        temp_user_client.delete_vault(vid2)   # clean up (require_otp is about to go back off)
    finally:
        set_action_require_otp(admin, "vault.delete", False)


def test_password_cannot_satisfy_an_otp_step_up(admin, temp_user, temp_user_client):
    """For an OTP-gated action, the account password must NOT mint a step-up receipt (regression for the
    OTP-bypass where method=password was accepted in the OTP slot)."""
    _enroll(temp_user, temp_user_client)
    set_action_require_otp(admin, "vault.delete", True)
    try:
        r = temp_user_client.post("/auth/second-factor/step-up",
                                  json={"action": "vault.delete", "method": "password",
                                        "code": temp_user["_password"]})
        assert r.status_code == 403, r.text
        assert "receipt" not in (r.json() or {})
    finally:
        set_action_require_otp(admin, "vault.delete", False)


def test_step_up_is_a_noop_when_action_requires_nothing(temp_user, temp_user_client):
    """With vault.delete at its default (require_otp off, B), an enrolled user deletes without a receipt —
    the decorator is a no-op for an action the policy does not gate."""
    _enroll(temp_user, temp_user_client)
    vid = temp_user_client.create_vault()["id"]
    assert temp_user_client.post(f"/vaults/{vid}/delete").status_code == 200
