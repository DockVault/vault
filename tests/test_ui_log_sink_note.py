"""The Log access panel must not offer a command that cannot work.

Three reasons a token is useless, and the panel now covers all three. Two of them surface as a 404
and were already explained. The third does not: every gate passes, the request returns 200, and the
body is an empty list forever, because nothing in this deployment shape writes the log file the
endpoint reads.

Both states are driven by stubbing GET /settings/logs, the way test_ui_create_vault_modal.py stubs
/zk-enabled — so these run identically whichever shape the instance under test happens to be, and
neither depends on the deployment's real profile.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

_BASE = {
    "ceiling": True,
    "components": ["web", "sftp", "db-diag", "redis-diag"],
    "serveable": ["web", "sftp"],
    "flags": {"web": True, "sftp": False, "db-diag": False, "redis-diag": False},
    "stealth_404": False,
    "tokens": [],
}


def _stub_settings_logs(page: Page, **overrides):
    payload = dict(_BASE, **overrides)
    page.route(
        "**/settings/logs",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(payload)
        ) if route.request.method == "GET" else route.continue_(),
    )


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_log_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.click('.tabs .tab-btn[data-tab="logs"]')
    expect(page.locator("#settings-tab-logs")).to_be_visible(timeout=10000)
    page.wait_for_timeout(700)


def test_unavailable_sink_is_explained_and_the_mint_button_is_disabled(page: Page, admin_creds):
    _stub_settings_logs(page, sink_available={"web": False, "sftp": False})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)

    note = page.locator("#log-ceiling-note")
    expect(note).to_be_visible()
    # The wording must name the actual cause. A generic "check your configuration" would send the
    # admin back to the env vars, which are correct in this state.
    expect(note).to_contain_text("not being collected in this deployment")
    expect(note).to_contain_text("no new lines")
    assert page.locator("#log-token-generate-btn").is_disabled(), (
        "an admin must not be able to mint a token whose curl returns nothing"
    )


def test_an_available_sink_shows_no_warning_and_allows_minting(page: Page, admin_creds):
    """The positive control: without it, a panel that ALWAYS warned would pass the test above."""
    _stub_settings_logs(page, sink_available={"web": True, "sftp": True})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)

    expect(page.locator("#log-ceiling-note")).to_be_hidden()
    assert not page.locator("#log-token-generate-btn").is_disabled()


def test_the_ceiling_message_still_wins_when_both_are_off(page: Page, admin_creds):
    """Ordering matters: with no ceiling the endpoint 404s, which is the more actionable cause,
    and pointing at the deployment shape instead would send the admin down the wrong path."""
    _stub_settings_logs(page, ceiling=False, sink_available={"web": False, "sftp": False})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)

    note = page.locator("#log-ceiling-note")
    expect(note).to_be_visible()
    expect(note).to_contain_text("PLAN_LOG_PULL")
    expect(note).not_to_contain_text("not being collected")
    assert page.locator("#log-token-generate-btn").is_disabled()


def test_no_component_ticked_still_takes_priority_over_the_shape_warning(page: Page, admin_creds):
    """Same reasoning one step down: a component that is switched off returns 404, and that is
    the thing to fix first."""
    _stub_settings_logs(
        page,
        flags={"web": False, "sftp": False, "db-diag": False, "redis-diag": False},
        sink_available={"web": False, "sftp": False},
    )
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)

    note = page.locator("#log-ceiling-note")
    expect(note).to_be_visible()
    expect(note).to_contain_text("no component is exposed")


def test_only_the_affected_component_is_named(page: Page, admin_creds):
    """SFTP-only gaps are the shipped default (RUN_SFTP empty), so naming both would misdirect."""
    _stub_settings_logs(
        page,
        flags={"web": True, "sftp": True, "db-diag": False, "redis-diag": False},
        sink_available={"web": True, "sftp": False},
    )
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)
    note = page.locator("#log-ceiling-note")
    expect(note).to_be_visible()
    expect(note).to_contain_text("sftp logs are")
    expect(note).not_to_contain_text("web and sftp")


def test_a_ticked_non_serveable_component_does_not_trigger_the_shape_warning(page, admin_creds):
    """db-diag/redis-diag 404 for an unrelated reason; blaming the shape would misdirect."""
    _stub_settings_logs(
        page,
        flags={"web": False, "sftp": False, "db-diag": True, "redis-diag": False},
        sink_available={"web": False, "sftp": False},
    )
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)
    expect(page.locator("#log-ceiling-note")).not_to_contain_text("not being collected")


def test_minting_stays_allowed_before_a_component_is_ticked(page: Page, admin_creds):
    """Minting first and ticking later has always been allowed, and this fix must not change it.

    The button gate covers only the reason this change introduced — a ticked component with no
    writer. With nothing ticked there is no such component, so the button stays enabled and carries
    no tooltip pointing at a note that says something else.
    """
    _stub_settings_logs(
        page,
        flags={"web": False, "sftp": False, "db-diag": False, "redis-diag": False},
        sink_available={"web": False, "sftp": False},
    )
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)
    expect(page.locator("#log-ceiling-note")).to_contain_text("no component is exposed")
    btn = page.locator("#log-token-generate-btn")
    assert not btn.is_disabled(), "minting before ticking a component must remain possible"
    assert not (btn.get_attribute("title") or ""), "no tooltip should point at an unrelated note"
