"""Settings page surfaces a PLAN-mandated zero-knowledge requirement.

When the plan forces zero-knowledge (Enterprise tier -> PLAN_FORCE_ZERO_KNOWLEDGE),
the local "Require zero-knowledge for all new vaults" toggle can't lower that floor,
so the Settings page shows it checked + locked with an explanatory note — instead of
an unchecked box that looks contradictory. Driven by intercepting /zk-enabled so the
test doesn't depend on this instance's plan.
"""
import json

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


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def _stub_zk_enabled(page: Page, plan_forced: bool):
    payload = {
        "zero_knowledge_enabled": True, "must_use_zk": plan_forced,
        "plan_zero_knowledge": True, "plan_force_zero_knowledge": plan_forced,
        "max_zk_vaults": -1, "zk_vault_count": 0,
        "allowed_vault_types": ["standard", "zero_knowledge"],
    }
    page.route("**/zk-enabled", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(payload)))


def _open_sftp_settings(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.click('.tab-btn[data-tab="sftp"]')
    expect(page.locator("#settings-tab-sftp")).to_be_visible()


def test_plan_forced_zk_locks_settings_toggles(page: Page, fresh_admin):
    _stub_zk_enabled(page, plan_forced=True)
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_sftp_settings(page)

    # The "require ZK" toggle is checked, locked, and explained by the plan note.
    require = page.locator("#setting-force-zero-knowledge")
    expect(require).to_be_checked()
    expect(require).to_be_disabled()
    expect(page.locator("#force-zk-plan-note")).to_be_visible()
    # "Allow ZK" is likewise mandated (can't disable ZK when the plan requires it).
    allow = page.locator("#setting-zero-knowledge-enabled")
    expect(allow).to_be_checked()
    expect(allow).to_be_disabled()


def test_no_plan_force_leaves_settings_editable(page: Page, fresh_admin):
    _stub_zk_enabled(page, plan_forced=False)
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_sftp_settings(page)

    # Without a plan mandate the toggle is editable and the plan note is hidden.
    expect(page.locator("#setting-force-zero-knowledge")).to_be_enabled()
    expect(page.locator("#force-zk-plan-note")).to_be_hidden()
