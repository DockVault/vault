"""MFA / settings UX round: the admin users list reports each account's MFA status, and the step-up
action matrix can be saved in bulk under a SINGLE step-up (instead of an OTP per toggle).
"""
import pytest

from conftest import ApiClient, BASE_URL, unique
from _sf_helpers import enrolled_admin, step_up_receipt

pytestmark = pytest.mark.integration


def test_list_users_reports_second_factor_status(admin):
    # A fresh user has no second factor; an enrolled admin does. GET /users returns a bare list.
    ta, c, _secret, codes = enrolled_admin(admin)
    u = admin.create_user(role="user")
    try:
        rows = {x["username"]: x for x in admin.get("/users").json()}
        assert "second_factor_enabled" in rows[u["_username"]]
        assert rows[u["_username"]]["second_factor_enabled"] is False
        assert rows[ta["_username"]]["second_factor_enabled"] is True
    finally:
        admin.delete_user(u["id"])
        admin.delete_user(ta["id"])


def test_bulk_action_matrix_save_is_one_step_up(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        # Still step-up gated: no receipt -> 403.
        r0 = c.put("/second-factor/actions",
                   json={"actions": [{"key": "vault.delete", "require_otp": True}]})
        assert r0.status_code == 403, r0.text

        # ONE receipt applies MULTIPLE toggles at once (the whole point).
        body = {"actions": [{"key": "vault.delete", "require_otp": True},
                            {"key": "share.create", "require_password": True}]}
        r = c.put("/second-factor/actions", json=body, headers={
            "X-Second-Factor": step_up_receipt(c, action="account.second_factor", recovery_codes=codes)})
        assert r.status_code == 200, r.text
        acts = {a["key"]: a for a in r.json()["actions"]}
        assert acts["vault.delete"]["require_otp"] is True
        assert acts["share.create"]["require_password"] is True

        # An unknown key rejects the WHOLE batch (all-or-nothing), 400.
        r2 = c.put("/second-factor/actions",
                   json={"actions": [{"key": "vault.change_password", "require_otp": True},
                                     {"key": "not.a.real.action", "require_otp": True}]},
                   headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                              recovery_codes=codes)})
        assert r2.status_code == 400, r2.text
        # ...and the valid one in that rejected batch was NOT applied.
        assert c.get("/second-factor/actions").json()
        after = {a["key"]: a for a in c.get("/second-factor/actions").json()["actions"]}
        assert after["vault.change_password"]["require_otp"] is False

        # Revert for a clean shared DB.
        c.put("/second-factor/actions",
              json={"actions": [{"key": "vault.delete", "require_otp": False},
                                {"key": "share.create", "require_password": False}]},
              headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                         recovery_codes=codes)})
    finally:
        admin.delete_user(ta["id"])
