"""Admin MFA policy UI + step-up action matrix (Settings -> Security). An enrolled admin changes the
MFA policy and a matrix toggle; each save is account.second_factor-gated, so the step-up modal appears
and a recovery code completes it. Changes are verified to persist via the API.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest                                              # noqa: E402
from playwright.sync_api import Page, expect               # noqa: E402

from _sf_helpers import enrolled_admin, step_up_receipt     # noqa: E402

pytestmark = pytest.mark.ui


def _stepup_with_recovery(page, code):
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    modal = page.locator("#stepup-modal")
    modal.get_by_role("button", name="Use a recovery code instead").click()
    page.fill("#stepup-code-input", code)
    modal.get_by_role("button", name="Confirm").click()


def test_admin_mfa_policy_and_action_matrix(page: Page, admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        # Log in as the enrolled admin (finish the second factor with a recovery code).
        page.goto("/")
        page.fill("#username", ta["_username"])
        page.fill("#password", ta["_password"])
        page.click("#login-form button[type=submit]")
        page.get_by_role("button", name="Use a recovery code instead").click()
        # Pop recovery codes from the FRONT so the browser and step_up_receipt (which also pops from the
        # front) never reuse the same single-use code — otherwise the teardown's reset step-up reuses a
        # spent code, fails, and leaves mfa_mode=required leaking into later tests.
        page.fill("#sf-code-input", codes.pop(0))
        page.click("#login-second-factor button")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)

        # Open admin Settings -> Security.
        item = page.locator('[data-section="settings"]')
        expect(item).to_be_visible(timeout=10000)
        item.click()
        page.click('.tab-btn[data-tab="security"]')
        expect(page.locator("#setting-mfa-mode")).to_be_visible(timeout=10000)
        # loadSettings populates the policy select then fetches the matrix asynchronously; wait for the
        # matrix rows so loadSettings has fully run before we set the select — otherwise a late load can
        # overwrite our choice back to the stored value and the save persists the wrong mode.
        expect(page.get_by_label("Require OTP for Delete a vault")).to_be_visible(timeout=10000)

        # Change the requirement to 'required' and save -> step-up -> persisted.
        page.select_option("#setting-mfa-mode", "required")
        expect(page.locator("#setting-mfa-mode")).to_have_value("required")
        page.click("#save-mfa-policy-btn")
        _stepup_with_recovery(page, codes.pop(0))
        expect(page.locator("#mfa-policy-msg")).to_contain_text("saved", timeout=10000)
        assert c.get("/settings").json()["mfa_mode"] == "required"

        # Toggle an action in the matrix (require OTP for vault delete) -> step-up -> persisted.
        expect(page.locator("#mfa-actions-table")).to_be_visible()
        page.get_by_label("Require OTP for Delete a vault").check()
        _stepup_with_recovery(page, codes.pop(0))
        expect(page.locator("#mfa-actions-msg")).to_contain_text("Updated", timeout=10000)
        acts = c.get("/second-factor/actions").json()["actions"]
        vd = next(a for a in acts if a["key"] == "vault.delete")
        assert vd["require_otp"] is True
    finally:
        # Reset global state (both writes are account.second_factor-gated).
        try:
            c.put("/settings", json={"mfa_mode": "optional"},
                  headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor", recovery_codes=codes)})
            c.put("/second-factor/actions/vault.delete", json={"require_otp": False},
                  headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor", recovery_codes=codes)})
        except Exception:
            pass
        admin.delete_user(ta["id"])
