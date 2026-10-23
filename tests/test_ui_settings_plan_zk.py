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
from _settings_ui import show_advanced

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
    show_advanced(page, "sftp")
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


LOCKED = "This deployment's plan does not include zero-knowledge vaults."


def _route_settings(page: Page, lock):
    """Serve GET /settings with the switches locked as ``lock`` says (None: as the stack has them), and
    record each PUT /settings body, answering it without saving (the stack's settings stay untouched)."""
    sent = []

    def handle(route):
        if route.request.method == "GET":
            response = route.fetch()
            data = response.json()
            if lock:
                data.update({"zero_knowledge_enabled": True, "force_zero_knowledge": True,
                             "zero_knowledge_in_effect": False, "force_zero_knowledge_in_effect": False,
                             "zero_knowledge_switches_locked": lock})
            route.fulfill(response=response, body=json.dumps(data))
        else:
            sent.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json", body="{}")

    page.route("**/settings", handle)
    return sent


def _save_and_wait(page: Page, sent):
    page.click("#save-all-settings-btn")
    for _ in range(100):
        if sent:
            break
        page.wait_for_timeout(100)
    assert sent, "the page sent no settings save"
    return sent[-1]


def test_switches_the_server_locks_show_what_is_in_effect_and_stay_out_of_a_save(page: Page, fresh_admin):
    """While the plan lacks zero-knowledge the switches are saved on but in effect off: the page shows them
    off, disabled, with the server's reason, and its save leaves them out so the saved values are kept."""
    sent = _route_settings(page, LOCKED)
    _stub_zk_enabled(page, plan_forced=False)
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_sftp_settings(page)
    for switch in ("#setting-zero-knowledge-enabled", "#setting-force-zero-knowledge"):
        expect(page.locator(switch)).not_to_be_checked()
        expect(page.locator(switch)).to_be_disabled()
    expect(page.locator("#zk-switches-locked-note")).to_be_visible()
    expect(page.locator("#zk-switches-locked-note")).to_contain_text(LOCKED)
    body = _save_and_wait(page, sent)
    assert "zero_knowledge_enabled" not in body and "force_zero_knowledge" not in body, body
    assert "directory_search_scope" in body, body       # the rest of the page was sent


def test_switches_that_can_change_something_are_sent(page: Page, fresh_admin):
    """The control: unlocked, the same save sends both switches as shown."""
    sent = _route_settings(page, None)
    _stub_zk_enabled(page, plan_forced=False)
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_sftp_settings(page)
    expect(page.locator("#setting-zero-knowledge-enabled")).to_be_enabled()
    expect(page.locator("#zk-switches-locked-note")).to_be_hidden()
    body = _save_and_wait(page, sent)
    assert isinstance(body.get("zero_knowledge_enabled"), bool), body
    assert isinstance(body.get("force_zero_knowledge"), bool), body
