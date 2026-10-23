"""Settings -> Security: the step-ups no switch changes are listed read-only below the matrix
(static/js/compliance.js).

An administrator opening the step-up matrix sees each compliance step, and the other fixed step-ups, with what
it always asks for, and no switch to change it; the list fits a phone's width.
"""
import pytest
from playwright.sync_api import Page, expect

from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

COMPLIANCE_STEPS = ("Propose an auditor grant", "Approve or turn down an auditor grant", "Reconfirm your auditor right",
                    "Request a compliance case", "Approve, turn down or extend a compliance case",
                    "Export files from a compliance case", "Place a legal hold", "Confirm or release a legal hold")
# The compliance steps and the four other fixed step-ups (app/core/second_factor_actions.py, FIXED_STEP_UP_ACTIONS).
FIXED_ROWS = len(COMPLIANCE_STEPS) + 4


def _open_security(page: Page, admin_creds, width=1440, height=900):
    page.set_viewport_size({"width": width, "height": height})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.locator('#settings-section .tab-btn[data-tab="security"]').click()
    show_advanced(page, "security")                       # the step-up matrix is an advanced setting
    expect(page.get_by_label("Require OTP for Delete a vault")).to_be_visible(timeout=10000)


def test_the_compliance_steps_are_listed_as_always_required_without_a_switch(page: Page, admin_creds):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _open_security(page, admin_creds)
    box = page.locator("#mfa-fixed-table")
    expect(box).to_contain_text("Always required", timeout=10000)
    for name in COMPLIANCE_STEPS:
        row = box.locator(".mfa-fixed-row", has_text=name)
        expect(row).to_have_count(1)
        expect(row.locator(".mfa-fixed-requires")).to_have_text(
            "Always: your password and an authenticator or recovery code (never an email code)")
    expect(box.locator(".mfa-fixed-row")).to_have_count(FIXED_ROWS)
    expect(box.locator("input, select, button")).to_have_count(0)
    # The matrix's own save never carries them.
    assert page.evaluate("() => document.querySelectorAll('#mfa-actions-table [data-fixed-key]').length") == 0
    assert errors == []


def test_the_list_fits_a_phone(page: Page, admin_creds):
    _open_security(page, admin_creds, width=390, height=844)
    box = page.locator("#mfa-fixed-table")
    expect(box.locator(".mfa-fixed-row")).to_have_count(FIXED_ROWS, timeout=10000)
    width = page.evaluate("() => document.getElementById('mfa-fixed-table').scrollWidth")
    viewport = page.evaluate("() => document.documentElement.clientWidth")
    assert width <= viewport, (width, viewport)
