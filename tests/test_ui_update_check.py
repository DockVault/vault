"""UI e2e for the update-check controls (Settings -> General). The /api/update-status response is
mocked via page.route, so these are deterministic and never hit the real network — they run on any
live instance regardless of whether UPDATE_CHECK_ENABLED is set."""
import json
import time

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_general(page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-tab-general")).to_be_visible(timeout=10000)


def _mock_status(page, payload):
    page.route("**/api/update-status*", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(payload)))


def test_update_controls_and_banner_when_enabled(page: Page, admin_creds):
    _mock_status(page, {"enabled": True, "managed": False, "current": "0.6.0", "latest": "0.9.0",
                        "update_available": True, "url": "https://github.com/DockVault/vault/releases",
                        "notes": "x", "checked_at": 1700000000, "interval_minutes": 360})
    _open_general(page, admin_creds)
    # controls appear when the check is enabled
    expect(page.locator("#update-controls")).to_be_visible()
    expect(page.locator("#update-check-now-btn")).to_be_visible()
    expect(page.locator("#update-interval-input")).to_have_value("360")
    expect(page.locator("#update-last-checked")).to_contain_text("Last checked")
    # a newer release -> the banner shows with the version
    expect(page.locator("#update-banner")).to_be_visible()
    expect(page.locator("#update-banner-text")).to_contain_text("0.9.0")


def test_update_controls_hidden_when_disabled(page: Page, admin_creds):
    _mock_status(page, {"enabled": False, "managed": False, "current": "0.6.0",
                        "update_available": False, "interval_minutes": 360})
    _open_general(page, admin_creds)
    expect(page.locator("#update-controls")).to_be_hidden()
    expect(page.locator("#update-banner")).to_be_hidden()


def test_check_now_issues_a_forced_check(page: Page, admin_creds):
    forced = {"n": 0}

    def handle(route):
        if "force=1" in route.request.url:
            forced["n"] += 1
        route.fulfill(status=200, content_type="application/json", body=json.dumps(
            {"enabled": True, "managed": False, "current": "0.6.0", "latest": "0.6.0",
             "update_available": False, "checked_at": 1700000000, "interval_minutes": 60}))

    page.route("**/api/update-status*", handle)
    _open_general(page, admin_creds)
    expect(page.locator("#update-check-now-btn")).to_be_visible()
    page.click("#update-check-now-btn")
    deadline = time.time() + 5
    while forced["n"] == 0 and time.time() < deadline:
        page.wait_for_timeout(150)
    assert forced["n"] >= 1, "clicking Check for updates must issue a force=1 request"


def _banner_payload(upgrade):
    payload = {"enabled": True, "managed": False, "current": "0.6.0", "latest": "0.9.0",
               "update_available": True, "url": "https://github.com/DockVault/vault/releases",
               "notes": "x", "checked_at": 1700000000, "interval_minutes": 360}
    if upgrade is not None:
        payload["upgrade"] = upgrade
    return payload


def test_the_banner_says_a_drop_in_update_is_a_drop_in(page: Page, admin_creds):
    """The distinction the banner exists to make.

    Announcing only that a version exists leaves the operator to discover the difference between a
    drop-in and a one-way schema change after pressing the button.
    """
    _mock_status(page, _banner_payload({"known": True, "requires_backup": False,
                                        "irreversible": False, "blocked": False,
                                        "conditions": [], "steps": 1}))
    _open_general(page, admin_creds)
    expect(page.locator("#update-banner-text")).to_contain_text("drop-in")


def test_the_banner_says_when_an_update_needs_a_backup_and_cannot_be_undone(page: Page, admin_creds):
    _mock_status(page, _banner_payload({"known": True, "requires_backup": True,
                                        "irreversible": True, "blocked": False,
                                        "conditions": [], "steps": 2}))
    _open_general(page, admin_creds)
    text = page.locator("#update-banner-text")
    expect(text).to_contain_text("a backup")
    expect(text).to_contain_text("no rollback")
    expect(text).not_to_contain_text("drop-in")


def test_an_undescribed_update_is_not_presented_as_safe(page: Page, admin_creds):
    """A gap in the matrix is where nobody has considered the hop, so the banner says so."""
    _mock_status(page, _banner_payload({"known": False, "requires_backup": True,
                                        "irreversible": True, "blocked": False,
                                        "conditions": [], "steps": 0}))
    _open_general(page, admin_creds)
    text = page.locator("#update-banner-text")
    expect(text).to_contain_text("does not describe")
    expect(text).not_to_contain_text("drop-in")


def test_a_server_that_says_nothing_about_the_hop_still_shows_the_banner(page: Page, admin_creds):
    """Backwards compatibility, and the degrade path.

    An older deployment, or one whose matrix fetch failed, sends no `upgrade` key at all. The
    banner must still announce the release rather than break on the missing field.
    """
    _mock_status(page, _banner_payload(None))
    _open_general(page, admin_creds)
    expect(page.locator("#update-banner")).to_be_visible()
    expect(page.locator("#update-banner-text")).to_contain_text("0.9.0")


def test_the_banner_does_not_call_a_blocked_upgrade_a_drop_in(page: Page, admin_creds):
    """The matrix can say an upgrade must not be taken, and the tool refuses it outright.

    The banner used to branch only on known/backup/reversible, so a blocked hop whose booleans
    happened to be benign rendered as "Upgrading is a drop-in change" -- the two surfaces
    contradicting each other, with the banner being the one an operator reads first.
    """
    _mock_status(page, _banner_payload({"known": True, "requires_backup": False,
                                        "irreversible": False, "blocked": True,
                                        "conditions": [], "steps": 1}))
    _open_general(page, admin_creds)
    text = page.locator("#update-banner-text")
    expect(text).not_to_contain_text("drop-in")
    expect(text).to_contain_text("advises against")
