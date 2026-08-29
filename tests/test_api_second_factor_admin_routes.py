"""Step-up wiring on the admin-plane and self-service routes.

Every gated action defaults require_otp OFF (owner model B), so these tests OPT the action in first and
prove the route is refused without a session-bound receipt and allowed with one. The receipts are minted
from RECOVERY codes (a 30s TOTP code is single-use, so several step-ups in one window would collide).

A wrinkle unique to admin.user.manage: once it is ON, the shared un-enrolled `admin` can no longer manage
users, so it cannot be used to flip the toggle back. That test edits the matrix DIRECTLY as an enrolled
actor (the matrix write is gated by account.second_factor, not admin.user.manage), sidestepping the loop.
"""
import uuid

from _sf_helpers import enroll_totp, enrolled_admin, step_up_receipt, set_action_require_otp   # noqa: E402


def test_admin_user_manage_gates_user_routes(admin):
    ta, c, _secret, codes = enrolled_admin(admin)   # enrolled admin actor; toggle still OFF here
    target = None
    extra_id = None

    def _set_user_manage(value):
        # Flip admin.user.manage via the matrix as the enrolled actor `c`. The matrix PUT is gated by
        # account.second_factor (which `c` can satisfy) -- NOT by admin.user.manage -- so turning the
        # toggle back off never depends on a user-management op that the toggle itself would block.
        r = c.put("/second-factor/actions/admin.user.manage", json={"require_otp": value},
                  headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                              recovery_codes=codes)})
        r.raise_for_status()

    try:
        target = admin.create_user(role="user")   # created while OFF
        _set_user_manage(True)
        try:
            # A user_management_api route (its router is mounted at /api/user-management) is refused
            # without a receipt.
            toggle = f"/api/user-management/users/{target['id']}/toggle-active"
            r = c.post(toggle)
            assert r.status_code == 403 and r.json()["detail"]["action"] == "admin.user.manage", r.text
            r = c.post(toggle, headers={"X-Second-Factor": step_up_receipt(c, action="admin.user.manage",
                                                                          recovery_codes=codes)})
            assert r.status_code == 200, r.text

            # An api_server route (POST /users) is gated the same way.
            body = {"username": f"gu{uuid.uuid4().hex[:8]}", "password": "TestPassw0rd!123", "role": "user"}
            assert c.post("/users", json=body).status_code == 403
            r = c.post("/users", json=body,
                       headers={"X-Second-Factor": step_up_receipt(c, action="admin.user.manage",
                                                                   recovery_codes=codes)})
            assert r.status_code in (200, 201), r.text
            extra_id = r.json()["id"]
        finally:
            _set_user_manage(False)   # back OFF before any un-enrolled cleanup below
    finally:
        if extra_id:
            admin.delete_user(extra_id)
        if target:
            admin.delete_user(target["id"])
        admin.delete_user(ta["id"])


def test_temp_credential_create_is_gated_when_opted_in(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        set_action_require_otp(admin, "temp_credential.create", True)
        try:
            r = c.post("/auth/temp-credentials", json={})
            assert r.status_code == 403 and r.json()["detail"]["action"] == "temp_credential.create", r.text
            r = c.post("/auth/temp-credentials", json={},
                       headers={"X-Second-Factor": step_up_receipt(c, action="temp_credential.create",
                                                                   recovery_codes=codes)})
            assert r.status_code == 200, r.text
        finally:
            set_action_require_otp(admin, "temp_credential.create", False)
    finally:
        admin.delete_user(ta["id"])


def test_self_password_change_is_conditionally_gated(admin, temp_user, temp_user_client):
    _secret, codes = enroll_totp(temp_user, temp_user_client)
    set_action_require_otp(admin, "account.change_password", True)
    try:
        # An SFTP-toggle-only save touches no gated field -> not gated (sftp_enabled defaults True,
        # so flip it to False for a real, non-sensitive change).
        assert temp_user_client.patch("/users/me", json={"sftp_enabled": False}).status_code == 200
        # A password change without a receipt is refused.
        r = temp_user_client.patch("/users/me", json={"current_password": temp_user["_password"],
                                                       "new_password": "NewPassw0rd!456"})
        assert r.status_code == 403 and r.json()["detail"]["action"] == "account.change_password", r.text
        # With a receipt it succeeds (this revokes the session, so keep it last).
        r = temp_user_client.patch(
            "/users/me",
            json={"current_password": temp_user["_password"], "new_password": "NewPassw0rd!456"},
            headers={"X-Second-Factor": step_up_receipt(temp_user_client, action="account.change_password",
                                                        recovery_codes=codes)})
        assert r.status_code == 200, r.text
    finally:
        set_action_require_otp(admin, "account.change_password", False)


def test_settings_write_gated_but_mfa_keys_still_use_the_account_gate(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        set_action_require_otp(admin, "admin.settings.write", True)
        try:
            # A plain settings save now needs an admin.settings.write receipt.
            assert c.put("/settings", json={"note_max_chars": 4096}).status_code == 403
            r = c.put("/settings", json={"note_max_chars": 4096},
                      headers={"X-Second-Factor": step_up_receipt(c, action="admin.settings.write",
                                                                  recovery_codes=codes)})
            assert r.status_code == 200, r.text
            # An mfa_* change routes to account.second_factor instead: an admin.settings.write receipt
            # must NOT satisfy it (receipts are action-bound), but an account.second_factor one does.
            assert c.put("/settings", json={"mfa_email_code_ttl_minutes": 7},
                         headers={"X-Second-Factor": step_up_receipt(c, action="admin.settings.write",
                                                                     recovery_codes=codes)}).status_code == 403
            assert c.put("/settings", json={"mfa_email_code_ttl_minutes": 7},
                         headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                                     recovery_codes=codes)}).status_code == 200
        finally:
            set_action_require_otp(admin, "admin.settings.write", False)
    finally:
        admin.delete_user(ta["id"])
