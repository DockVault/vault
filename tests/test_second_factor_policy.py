"""Pure second-factor policy resolution + the action catalog (no DB / no vault).

Pins the owner's two-toggle model (require_password + require_otp, with require_otp+not-enrolled =>
block/enroll), the never-a-no-op admin rule, the computed per-user state, the lockout guards, and that
the catalog excludes routes that do not exist yet.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor_policy as pol       # noqa: E402
from app.core import second_factor_actions as acts     # noqa: E402


def test_effective_policy_defaults_and_lenient_degradation():
    p = pol.effective_policy(None)
    assert p["mfa_mode"] == "optional" and p["mfa_allowed_methods"] == ["totp"]
    assert p["mfa_email_code_ttl_minutes"] == 5 and p["mfa_sftp_policy"] == "allow"
    assert p["mfa_required_group_ids"] == [] and p["mfa_required_user_ids"] == []
    # corrupt/out-of-range values degrade to the default, never raise (validation is at save time)
    assert pol.effective_policy({"mfa_mode": "garbage"})["mfa_mode"] == "optional"
    assert pol.effective_policy({"mfa_email_code_ttl_minutes": 999})["mfa_email_code_ttl_minutes"] == 5


def test_effective_second_factor_state_and_source():
    base = dict(required_group_ids=[], required_user_ids=[], user_group_ids=[], user_id="u1")
    assert pol.effective_second_factor(mode="optional", has_active_enrollment=False, **base) == \
        {"required": False, "source": None, "state": "not_setup", "in_effect": False}
    e = pol.effective_second_factor(mode="required", has_active_enrollment=False, **base)
    assert e["required"] and e["source"] == "global" and e["state"] == "pending" and e["in_effect"]
    e = pol.effective_second_factor(mode="optional", has_active_enrollment=False,
                                    required_group_ids=["g1"], required_user_ids=[],
                                    user_group_ids=["g1"], user_id="u1")
    assert e["required"] and e["source"] == "department"
    e = pol.effective_second_factor(mode="optional", has_active_enrollment=False,
                                    required_group_ids=[], required_user_ids=["u1"],
                                    user_group_ids=[], user_id="u1")
    assert e["required"] and e["source"] == "user"
    # enrolled -> setup + in_effect even when not required (the safety-net state)
    e = pol.effective_second_factor(mode="optional", has_active_enrollment=True, **base)
    assert e["state"] == "setup" and e["in_effect"] and not e["required"]


def test_resolve_action_requirement_two_toggles_and_block_enroll():
    r = pol.resolve_action_requirement(require_otp=True, require_password=False,
                                       has_active_enrollment=True, is_admin_action=False)
    assert r == {"password": False, "otp": True, "must_enroll": False}
    # require_otp + not enrolled -> BLOCK (enroll to continue), not a silent no-op
    r = pol.resolve_action_requirement(require_otp=True, require_password=False,
                                       has_active_enrollment=False, is_admin_action=False)
    assert r["must_enroll"] and not r["otp"] and not r["password"]
    # require_password only -> a re-auth, no enrollment needed
    r = pol.resolve_action_requirement(require_otp=False, require_password=True,
                                       has_active_enrollment=False, is_admin_action=False)
    assert r == {"password": True, "otp": False, "must_enroll": False}
    # both toggles, enrolled -> password AND otp
    r = pol.resolve_action_requirement(require_otp=True, require_password=True,
                                       has_active_enrollment=True, is_admin_action=False)
    assert r["password"] and r["otp"] and not r["must_enroll"]
    # neither -> a true no-op
    r = pol.resolve_action_requirement(require_otp=False, require_password=False,
                                       has_active_enrollment=False, is_admin_action=False)
    assert not any(r.values())


def test_admin_action_follows_the_general_rule_no_special_gate():
    # Owner's model B: admin.* has NO special "never a no-op" rule -- you cannot force an admin to own an
    # OTP device. With no toggles set it is a no-op even for an un-enrolled admin.
    r = pol.resolve_action_requirement(require_otp=False, require_password=False,
                                       has_active_enrollment=False, is_admin_action=True)
    assert not any(r.values())
    # An admin who opts in (require_otp on) requires everyone, themselves included, to enroll.
    r = pol.resolve_action_requirement(require_otp=True, require_password=False,
                                       has_active_enrollment=False, is_admin_action=True)
    assert r["must_enroll"] and not r["otp"]
    r = pol.resolve_action_requirement(require_otp=True, require_password=False,
                                       has_active_enrollment=True, is_admin_action=True)
    assert r["otp"] and not r["must_enroll"]


def test_validate_policy_bounds_and_email_lockout_guards():
    ok = pol.validate_policy({"mfa_mode": "required", "mfa_allowed_methods": ["totp"]},
                             active_admins_without_email=0, smtp_configured=True)
    assert ok["mfa_mode"] == "required"
    for bad in ({"mfa_mode": "sometimes"}, {"mfa_email_code_ttl_minutes": 0},
                {"mfa_email_code_ttl_minutes": 61}, {"mfa_allowed_methods": []},
                {"mfa_allowed_methods": ["sms"]}, {"mfa_sftp_policy": "never"}):
        with pytest.raises(pol.SecondFactorPolicyError):
            pol.validate_policy(bad, active_admins_without_email=0, smtp_configured=True)
    # email is a DEFERRED method (issuance not wired) — not currently selectable, so any policy that
    # includes it is rejected before it can lock anyone out.
    for email_blob in ({"mfa_allowed_methods": ["email"]}, {"mfa_allowed_methods": ["totp", "email"]}):
        with pytest.raises(pol.SecondFactorPolicyError):
            pol.validate_policy(email_blob, active_admins_without_email=0, smtp_configured=True)


def test_catalog_excludes_unbuilt_routes_and_has_metadata():
    assert "login" in acts.ACTION_KEYS and "admin.user.manage" in acts.ACTION_KEYS
    # routes that don't exist yet must NOT be seeded (they'd trip the boot contract)
    assert "receiver.create" not in acts.ACTION_KEYS
    assert acts.is_admin_action("admin.settings.write") and not acts.is_admin_action("vault.delete")
    for k in acts.ACTION_KEYS:
        assert k in acts.ACTION_META and acts.ACTION_META[k]["name"]
