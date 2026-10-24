"""Settings → Email — the "Automated emails" section: the action catalog, template binding, the
notify toggle, and the protected (non-removable) badge on a bound template card."""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import unique
from _settings_ui import show_advanced

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_email_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="email"]')
    show_advanced(page, "email")
    expect(page.locator("#email-actions-list")).to_be_visible(timeout=10000)


@pytest.fixture
def admin_page(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


@pytest.fixture(autouse=True)
def _clean(admin):
    def reset():
        for a in admin.get("/email/actions").json().get("actions", []):
            admin.put(f"/email/actions/{a['key']}",
                      json={"template_id": None, "enabled": (a["category"] == "system")})
        for t in admin.get("/email/templates").json().get("templates", []):
            if t.get("is_default"):
                continue                       # built-in defaults are permanent (undeletable)
            admin.delete(f"/email/templates/{t['id']}")
    reset()
    yield
    reset()


def test_automated_emails_section_lists_actions_with_badges(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    sys_row = page.locator('.email-action-row[data-action-key="email_change"]')
    expect(sys_row).to_be_visible()
    expect(sys_row.locator(".ear-badge-system")).to_have_text("System")
    opt_row = page.locator('.email-action-row[data-action-key="share_created"]')
    expect(opt_row.locator(".ear-badge-optional")).to_have_text("Optional")
    # a system action shows no notify switch (always on); an optional one shows the on/off switch
    expect(sys_row.locator(".ear-notify")).to_have_count(0)
    expect(opt_row.locator(".ear-notify .dv-switch-track")).to_be_visible()


def test_bind_template_to_action_persists_and_badges_the_template(admin_page: Page, admin):
    t = admin.post("/email/templates", json={"name": "Reset copy", "subject": "s",
                                             "body_html": "<p>{{action.link}}</p>"}).json()
    page = admin_page
    _open_email_tab(page)
    row = page.locator('.email-action-row[data-action-key="password_reset"]')
    row.locator(".ear-template").select_option(label="Reset copy")
    # persisted server-side
    def bound():
        acts = {a["key"]: a for a in admin.get("/email/actions").json()["actions"]}
        return acts["password_reset"]["template_id"]
    import time
    deadline = time.time() + 8
    while time.time() < deadline and bound() != t["id"]:
        page.wait_for_timeout(200)
    assert bound() == t["id"]
    # the template card now shows a System badge and no Delete button (non-removable while bound)
    card = page.locator('#email-templates-grid .email-profile-card:has-text("Reset copy")')
    expect(card.locator(".epc-badge-system")).to_be_visible()
    expect(card.locator(".etc-delete")).to_have_count(0)


def test_toggle_notify_by_email_on_optional_action(admin_page: Page, admin):
    # An optional email needs a bound template before it can be turned on, so bind one first.
    t = admin.post("/email/templates", json={"name": "Notify tpl", "subject": "s",
                                             "body_html": "<p>hi {{user.username}}</p>"}).json()
    admin.put("/email/actions/vault_member_added", json={"template_id": t["id"]})
    page = admin_page
    _open_email_tab(page)
    row = page.locator('.email-action-row[data-action-key="vault_member_added"]')
    sw = row.locator(".ear-notify input")
    expect(sw).to_be_enabled()           # a template is bound, so the switch is live
    sw.check()

    def enabled():
        acts = {a["key"]: a for a in admin.get("/email/actions").json()["actions"]}
        return acts["vault_member_added"]["enabled"]
    import time
    deadline = time.time() + 8
    while time.time() < deadline and not enabled():
        page.wait_for_timeout(200)
    assert enabled() is True


def test_notify_switch_is_disabled_without_a_template(admin_page: Page, admin):
    # No template bound -> the switch is disabled (an email with nothing to send can't be turned on).
    admin.put("/email/actions/vault_member_added", json={"template_id": None, "enabled": False})
    page = admin_page
    _open_email_tab(page)
    row = page.locator('.email-action-row[data-action-key="vault_member_added"]')
    expect(row.locator(".ear-notify input")).to_be_disabled()
    expect(row.locator(".ear-notify-state")).to_contain_text("pick a template")


def test_send_test_opens_a_styled_modal_with_user_search(admin_page: Page, admin):
    # "Send test" opens an in-app modal (not a native prompt) with a username/email search; picking a
    # user shows the "will send to their email" banner.
    uname = unique("tpick")
    u = admin.create_user(username=uname, email=uname + "@example.com")
    try:
        page = admin_page
        _open_email_tab(page)
        page.locator('.email-action-row[data-action-key="account_welcome"] .ear-test').click()
        expect(page.locator("#email-test-modal")).to_have_class(re.compile(r"\bactive\b"))
        page.fill("#et-test-search", uname[:8])
        opt = page.locator("#et-test-results .pick-row").filter(has_text=uname)
        expect(opt.first).to_be_visible(timeout=8000)
        opt.first.click()
        expect(page.locator("#et-test-selected")).to_be_visible()
        expect(page.locator("#et-test-selected")).to_contain_text(uname)
        # typing a specific address supersedes the picked user (mutually exclusive)
        page.fill("#et-test-addr", "someone@example.com")
        expect(page.locator("#et-test-selected")).to_be_hidden()
    finally:
        admin.delete_user(u["id"])


def test_the_locked_owner_notice_is_shown_read_only(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    row = page.locator('.email-action-row[data-action-key="compliance_access_notice"]')
    expect(row).to_be_visible()
    expect(row.locator(".ear-badge")).to_have_text("Locked")
    expect(row.locator(".ear-locked")).to_contain_text("cannot be changed")
    # Nothing to choose and nothing to turn off; a test send is still offered.
    expect(row.locator("select.ear-template")).to_have_count(0)
    expect(row.locator(".ear-notify")).to_have_count(0)
    expect(row.locator(".ear-test")).to_be_visible()
    # And the server refuses a change made around the page.
    assert admin.put("/email/actions/compliance_access_notice", json={"template_id": None}).status_code == 409


@pytest.mark.parametrize("key", ["encryption_key_release_code", "encryption_key_notice"])
def test_an_encryption_key_email_is_shown_locked_with_no_template_to_choose(admin_page: Page, admin, key):
    """It always sends its built-in text through the default sending profile: the list offers no template
    for it, and a template made meanwhile is no choice for it."""
    made = admin.post("/email/templates", json={"name": unique("Not for keys"), "subject": "s",
                                                "body_html": "<p>{{action.code}}</p>"})
    assert made.status_code in (200, 201), made.text
    tid = made.json()["id"]
    try:
        page = admin_page
        _open_email_tab(page)
        row = page.locator(f'.email-action-row[data-action-key="{key}"]')
        expect(row).to_be_visible()
        expect(row.locator(".ear-badge")).to_have_text("Locked")
        expect(row.locator(".ear-locked")).to_contain_text("cannot be changed")
        expect(row.locator("select.ear-template")).to_have_count(0)
        expect(row.locator(".ear-notify")).to_have_count(0)
        # An action that is not locked still offers the templates, the new one among them.
        other = page.locator('.email-action-row[data-action-key="password_reset"] .ear-template option')
        expect(other.filter(has_text="Not for keys")).not_to_have_count(0)
        # And the server refuses a binding made around the page.
        assert admin.put(f"/email/actions/{key}", json={"template_id": tid}).status_code == 409
    finally:
        admin.delete(f"/email/templates/{tid}")
