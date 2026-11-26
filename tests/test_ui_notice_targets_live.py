"""Where a notice about the Settings page leads, in the browser (static/js/app.js, openAppTarget): "#settings" opens the
Settings page, and "#settings/signin" opens it on its Sign-in methods tab.

The offline twin of these tests, driven in Node, is tests/test_ui_notice_targets.py."""
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_settings_notice_opens_the_settings_page(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    understood = page.evaluate("() => openAppTarget('#settings')")
    assert understood is True
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)


def test_a_sign_in_notice_opens_the_sign_in_methods_tab(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    understood = page.evaluate("() => openAppTarget('#settings/signin')")
    assert understood is True
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    expect(page.locator("#settings-tab-signin")).to_have_class(re.compile(r"(^|\s)active(\s|$)"), timeout=10000)
    expect(page.locator("#settings-tab-signin")).to_be_visible()
