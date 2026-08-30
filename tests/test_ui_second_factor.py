"""Two-step login in the browser: an enrolled user meets the second-factor card and finishes with a
TOTP code or a recovery code; a required-but-unenrolled user meets the forced-enrollment wizard in place
and completes it to a session. Driven against the real app.js login flow.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest                                              # noqa: E402
from playwright.sync_api import Page, expect               # noqa: E402

from app.core import second_factor as sf                   # noqa: E402
from _sf_helpers import enroll_totp, enrolled_admin, step_up_receipt, set_action_require_otp   # noqa: E402

pytestmark = pytest.mark.ui


def _totp_now(secret):
    return sf._totp_at_step(secret, sf.current_totp_step())


def _totp_next(secret):
    # The enrollment confirm already consumed the current step; a login verify uses the next one.
    return sf._totp_at_step(secret, sf.current_totp_step() + 1)


def _enroll_via_api(admin, user):
    c = admin.clone_anonymous()
    c.login(user["_username"], user["_password"])
    return enroll_totp(user, c)   # (secret, recovery_codes)


def _submit_login(page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")


@pytest.fixture
def enrolled_user(admin):
    u = admin.create_user(role="user")
    secret, codes = _enroll_via_api(admin, u)
    yield u, secret, codes
    admin.delete_user(u["id"])


def test_enrolled_user_sees_card_and_verifies_with_totp(page: Page, enrolled_user):
    u, secret, _codes = enrolled_user
    _submit_login(page, u["_username"], u["_password"])
    # The second-factor card appears; the dashboard is withheld until the factor is proven.
    expect(page.locator("#login-second-factor")).to_be_visible(timeout=10000)
    expect(page.locator("#sf-code-input")).to_be_visible()
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    page.fill("#sf-code-input", _totp_next(secret))
    page.click("#login-second-factor button")   # the single button in the card is "Verify"
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_enrolled_user_can_verify_with_a_recovery_code(page: Page, enrolled_user):
    u, _secret, codes = enrolled_user
    _submit_login(page, u["_username"], u["_password"])
    expect(page.locator("#sf-code-input")).to_be_visible(timeout=10000)
    page.get_by_role("button", name="Use a recovery code instead").click()
    page.fill("#sf-code-input", codes[0])
    page.click("#login-second-factor button")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_forced_enrollment_wizard_completes_in_place(page: Page, admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    newu = admin.create_user(role="user")

    def _set_mode(mode):
        c.put("/settings", json={"mfa_mode": mode},
              headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                          recovery_codes=codes)}).raise_for_status()
    try:
        _set_mode("required")
        try:
            _submit_login(page, newu["_username"], newu["_password"])
            # The enrollment wizard appears in place (not the code card).
            expect(page.locator("#sf-enroll-secret")).to_be_visible(timeout=10000)
            secret = page.locator("#sf-enroll-secret").inner_text().strip()
            assert secret, "manual TOTP secret should be shown"
            page.fill("#sf-enroll-code", _totp_now(secret))
            page.get_by_role("button", name="Continue").click()
            # Recovery-codes step: acknowledge, then land signed in.
            expect(page.locator("#sf-ack-cb")).to_be_visible(timeout=10000)
            page.check("#sf-ack-cb")
            page.get_by_role("button", name="Finish and sign in").click()
            expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        finally:
            _set_mode("optional")
    finally:
        admin.delete_user(newu["id"])
        admin.delete_user(ta["id"])


def test_gated_action_triggers_step_up_modal_then_retries(page: Page, admin):
    """A gated action (vault.delete with require_otp on) surfaces the step-up modal through apiRequest;
    confirming a factor mints a receipt and the original request is retried and succeeds."""
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    _secret, codes = enroll_totp(u, c)
    vid = c.create_vault()["id"]
    set_action_require_otp(admin, "vault.delete", True)
    try:
        # Log in through the browser, finishing the second factor with a recovery code.
        page.goto("/")
        page.fill("#username", u["_username"])
        page.fill("#password", u["_password"])
        page.click("#login-form button[type=submit]")
        page.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#sf-code-input", codes[0])
        page.click("#login-second-factor button")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)

        # Trigger the gated delete via apiRequest; it should surface the step-up modal. Fire-and-forget:
        # the arrow returns nothing, so evaluate() does NOT await the (still-pending) request — the
        # request only resolves once we complete the modal below, and awaiting it here would deadlock.
        page.evaluate(
            "(vid) => { window.__del = undefined;"
            " apiRequest('/vaults/' + vid + '/delete', {method:'POST'})"
            "   .then(() => { window.__del = 'ok'; })"
            "   .catch(e => { window.__del = 'err:' + (e && e.message); }); }",
            vid,
        )
        expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
        expect(page.locator("#stepup-code-input")).to_be_visible()

        # Confirm with a recovery code; the modal mints a receipt and apiRequest retries the delete.
        page.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#stepup-code-input", codes[1])
        page.get_by_role("button", name="Confirm").click()
        # Poll for the fire-and-forget result via evaluate() (CDP-based, CSP-safe). wait_for_function's
        # string form is eval-based and the app's strict CSP (no unsafe-eval) blocks it.
        result = None
        for _ in range(50):
            result = page.evaluate("() => window.__del")
            if result is not None:
                break
            page.wait_for_timeout(200)
        assert result == "ok", result
    finally:
        set_action_require_otp(admin, "vault.delete", False)
        try:
            admin.delete_user(u["id"])
        except Exception:
            pass


def test_account_settings_enable_2fa_end_to_end(page: Page, admin):
    """A signed-in user turns ON 2FA from Your Account: password -> QR/secret -> confirm code ->
    recovery codes -> the section shows it enabled."""
    u = admin.create_user(role="user")
    try:
        page.goto("/")
        page.fill("#username", u["_username"])
        page.fill("#password", u["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)

        page.evaluate("openUserSettingsModal()")
        expect(page.locator("#us-2fa-section")).to_be_visible()
        page.get_by_role("button", name="Set up two-factor").click()
        page.fill("#us-2fa-cur-pw", u["_password"])
        page.get_by_role("button", name="Continue").click()

        expect(page.locator("#sf-enroll-secret")).to_be_visible(timeout=10000)
        secret = page.locator("#sf-enroll-secret").inner_text().strip()
        page.fill("#sf-enroll-code", _totp_now(secret))
        page.get_by_role("button", name="Continue").click()
        expect(page.locator("#sf-ack-cb")).to_be_visible(timeout=10000)
        page.check("#sf-ack-cb")
        page.get_by_role("button", name="Finish").click()

        # The section reflects the enabled state (the "Turn off" control appears).
        expect(page.get_by_role("button", name="Turn off")).to_be_visible(timeout=10000)
    finally:
        admin.delete_user(u["id"])


def test_account_settings_disable_2fa_requires_step_up(page: Page, admin):
    """Turning OFF 2FA is gated by the step-up modal (account.second_factor); confirming a recovery code
    disables it and the section returns to the off state."""
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    _secret, codes = enroll_totp(u, c)
    try:
        page.on("dialog", lambda d: d.accept())   # accept the native 'turn off?' confirm
        page.goto("/")
        page.fill("#username", u["_username"])
        page.fill("#password", u["_password"])
        page.click("#login-form button[type=submit]")
        page.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#sf-code-input", codes[0])
        page.click("#login-second-factor button")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)

        page.evaluate("openUserSettingsModal()")
        expect(page.get_by_role("button", name="Turn off")).to_be_visible(timeout=10000)
        page.get_by_role("button", name="Turn off").click()
        # The gated DELETE surfaces the step-up modal (on top of the account modal); confirm with a
        # recovery code. Scope to the modal so locators aren't ambiguous across the two open modals.
        expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
        modal = page.locator("#stepup-modal")
        modal.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#stepup-code-input", codes[1])
        modal.get_by_role("button", name="Confirm").click()
        # Back to the off state.
        expect(page.get_by_role("button", name="Set up two-factor")).to_be_visible(timeout=10000)
    finally:
        admin.delete_user(u["id"])
