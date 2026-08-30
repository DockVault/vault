"""Changing MFA configuration -- the action matrix AND the mfa_* policy -- requires the
account.second_factor step-up (the owner's "changing OTP settings requires OTP"). A THROWAWAY enrolled
admin exercises it, so the shared admin (and everyone else) stays un-enrolled and ungated. This is the
safeguard against a lock-out: an admin who wants to tighten MFA enrolls first, so they always keep an OTP
to loosen it again.
"""
from _sf_helpers import enrolled_admin, step_up_receipt   # noqa: E402


def _receipt(client, codes):
    return step_up_receipt(client, action="account.second_factor", recovery_codes=codes)


def test_changing_the_matrix_requires_step_up(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        # Without a receipt the toggle is refused with the account.second_factor challenge.
        r = c.put("/second-factor/actions/vault.delete", json={"require_password": True})
        assert r.status_code == 403 and r.json()["detail"]["action"] == "account.second_factor"
        # With a receipt it goes through.
        r = c.put("/second-factor/actions/vault.delete", json={"require_password": True},
                  headers={"X-Second-Factor": _receipt(c, codes)})
        assert r.status_code == 200 and r.json()["require_password"] is True
        # A single receipt covers one call -- a second toggle needs a fresh one.
        assert c.put("/second-factor/actions/vault.delete", json={"require_password": False},
                     headers={"X-Second-Factor": _receipt(c, codes)}).status_code == 200
    finally:
        admin.delete_user(ta["id"])


def test_changing_the_mfa_policy_requires_step_up_validates_and_persists(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        # A non-MFA settings save is NOT gated (baseline: the gate is conditional on mfa_* keys).
        assert c.put("/settings", json={"note_max_chars": 5000}).status_code == 200
        # An mfa_* change without a receipt is refused.
        assert c.put("/settings", json={"mfa_email_code_ttl_minutes": 10}).status_code == 403
        # With a receipt it persists, and GET reflects it (benign key -- no global login effect).
        assert c.put("/settings", json={"mfa_email_code_ttl_minutes": 10},
                     headers={"X-Second-Factor": _receipt(c, codes)}).status_code == 200
        assert admin.get("/settings").json()["mfa_email_code_ttl_minutes"] == 10
        # A bad value is rejected 400 (a fresh receipt lets us reach validation).
        assert c.put("/settings", json={"mfa_email_code_ttl_minutes": 999},
                     headers={"X-Second-Factor": _receipt(c, codes)}).status_code == 400
    finally:
        # Restore note_max_chars to its default so a low value can't leak into later tests (a long-note
        # test elsewhere in the full suite posts ~5800 chars). admin.settings.write defaults off -> no step-up.
        admin.put("/settings", json={"note_max_chars": 100000})
        admin.delete_user(ta["id"])
