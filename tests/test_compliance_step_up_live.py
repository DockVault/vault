"""The compliance step-up on a running stack (app/core/fixed_step_up.py, compliance_step_up).

The step-up matrix lists the compliance steps read-only and refuses to change them. An account without TOTP is
told to enroll before any compliance step, whatever it offers; an enrolled one must give both its password
and a code, and then gets a receipt. test_compliance_step_up.py covers the receipts' binding offline.
"""
from _sf_helpers import enrolled_admin, step_up_receipt

KEYS = ("compliance.grant.propose", "compliance.grant.approve", "compliance.grant.reconfirm",
        "compliance.case.request", "compliance.case.approve", "compliance.case.export", "compliance.hold.place",
        "compliance.hold.decide")


def test_the_matrix_lists_the_compliance_steps_read_only_and_cannot_change_them(admin):
    r = admin.get("/second-factor/actions")
    assert r.status_code == 200, r.text
    body = r.json()
    fixed = {f["key"]: f for f in body["fixed"]}
    assert set(KEYS) <= set(fixed)
    assert all(fixed[k]["policy"] == "compliance" and fixed[k]["fixed"] is True for k in KEYS)
    assert not {a["key"] for a in body["actions"]} & set(KEYS)
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        r = c.put("/second-factor/actions/compliance.case.request", json={"require_otp": False},
                  headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor", recovery_codes=codes)})
        assert r.status_code == 404, r.text
        r = c.put("/second-factor/actions", json={"actions": [{"key": "compliance.case.request", "require_otp": False}]},
                  headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor", recovery_codes=codes)})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_user(ta["id"])


def test_an_account_without_totp_is_told_to_enroll(admin, admin_creds):
    """The stack's own administrator has no second factor."""
    for key in KEYS:
        r = admin.post("/auth/second-factor/challenge", json={"action": key})
        assert r.status_code == 200, r.text
        assert r.json() == {"second_factor_required": True, "reason": "enroll_required", "methods": []}
    r = admin.post("/auth/second-factor/step-up", json={"action": "compliance.case.request", "method": "password",
                                                         "password": admin_creds["password"]})
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "enroll_required"


def test_an_enrolled_account_gives_its_password_and_a_code(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        r = c.post("/auth/second-factor/challenge", json={"action": "compliance.case.request"})
        assert r.json() == {"second_factor_required": True, "methods": ["totp", "recovery", "password"]}
        # A code alone, and the password alone, are refused.
        r = c.post("/auth/second-factor/step-up", json={"action": "compliance.case.request", "method": "recovery",
                                                         "code": codes.pop(0)})
        assert r.status_code == 403, r.text
        r = c.post("/auth/second-factor/step-up", json={"action": "compliance.case.request", "method": "password",
                                                         "password": ta["_password"]})
        assert r.status_code == 403, r.text
        r = c.post("/auth/second-factor/step-up", json={"action": "compliance.case.request", "method": "recovery",
                                                         "code": codes.pop(0), "password": ta["_password"]})
        assert r.status_code == 200, r.text
        assert r.json()["receipt"]
    finally:
        admin.delete_user(ta["id"])
