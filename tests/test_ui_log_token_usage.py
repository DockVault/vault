"""Minting a log-pull token shows a ready-to-copy usage example.

The /logs endpoint needs a `service=web|sftp` query param (a missing one 404s by design), which was
undocumented in the UI. When an admin mints a token, the reveal panel now shows a working curl per
granted component, header-only (never a ?token= query param).
"""
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


def test_log_token_reveal_shows_usage_curl(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('[data-section="settings"]')
    page.click('.tab-btn[data-tab="logs"]')
    page.click("#log-token-generate-btn")
    page.fill("#log-token-name", "usage-doc-test")
    # the component scope checkboxes default to checked; mint the token
    page.click("#log-token-create-btn")
    reveal = page.locator("#log-token-reveal")
    expect(reveal).to_be_visible(timeout=8000)
    curl = reveal.locator("code", has_text="curl -H").first
    expect(curl).to_be_visible()
    txt = curl.inner_text()
    assert "?service=" in txt              # the required, previously-undocumented param
    assert "Authorization: Bearer" in txt  # header auth
    assert "/logs" in txt
    assert "token=" not in txt             # never leak the token into the query string
