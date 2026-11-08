"""A dashboard that starts work (static/js/dashboard-actions.js).

Quick actions by role and permission open the page and dialog the action lives in; the stat cards are links
and the accounts card counts accounts; a Needs-attention lane names the account's items expiring within seven
days and, for an administrator, invitations still pending; an administrator's Get-started checklist ticks what
is recorded and goes away when dismissed.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

ACCOUNT_KEYS = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
                "signup_email_domain_mode", "signup_email_domains", "login_identifier",
                "email_change_requires_verification")


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def invites_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional",
                                 "signup_email_domain_mode": "off", "signup_email_domains": []})
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def checklist_fresh(admin):
    before = admin.get("/admin/get-started").json().get("recorded") or {}
    admin.post("/admin/get-started", json={"reset": True})
    yield
    admin.post("/admin/get-started", json={"reset": True})
    for key, flag in (("backup_recorded_at", "backup_recorded"), ("second_factor_decided_at", "second_factor_decided"),
                      ("dismissed_at", "dismissed")):
        if before.get(key):
            admin.post("/admin/get-started", json={flag: True})


def test_quick_actions_and_stat_cards_for_an_administrator(page: Page, admin, admin_creds, invites_on):
    v = admin.create_vault(name=unique("qa"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        actions = page.locator("#dashboard-quick-actions")
        expect(actions).to_be_visible(timeout=15000)
        for qa in ("qa-upload", "qa-new-vault", "qa-share", "qa-invite", "qa-temp-cred"):
            expect(page.locator(f"#{qa}")).to_be_visible()
        # The accounts card counts accounts and says so; the cards are links.
        expect(page.locator("#dashboard-users-card .stat-label")).to_have_text("Accounts")
        users = admin.get("/users").json()
        expect(page.locator("#dashboard-users-count")).to_have_text(str(len(users)), timeout=10000)
        page.locator('.stat-card[data-go="temp-creds"]').click()
        expect(page.locator("#temp-creds-section")).to_be_visible()
        page.click('.sidebar-item[data-section="dashboard"]')
        # New vault opens the create dialog on the Vaults page; Invite a user opens the invitation dialog.
        page.locator("#qa-new-vault").click()
        expect(page.locator("#create-vault-modal.active")).to_be_visible(timeout=10000)
        page.keyboard.press("Escape")
        page.click('.sidebar-item[data-section="dashboard"]')
        page.locator("#qa-invite").click()
        expect(page.locator("#invite-user-modal.active")).to_be_visible(timeout=10000)
        page.keyboard.press("Escape")
    finally:
        admin.delete_vault(v["id"])


def test_a_user_gets_no_administrator_actions_or_checklist(page: Page, admin, invites_on):
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        expect(page.locator("#lane-attention")).to_be_visible(timeout=15000)
        expect(page.locator("#qa-invite")).to_have_count(0)
        expect(page.locator("#dashboard-get-started")).to_be_hidden()
        expect(page.locator("#lane-attention")).to_contain_text("Nothing needs your attention")
    finally:
        admin.delete_user(u["id"])


def test_needs_attention_names_an_expiring_share_and_pending_invitations(page: Page, admin, admin_creds, invites_on):
    sharing_before = admin.get("/settings").json().get("sharing_enabled", False)
    admin.put("/settings", json={"sharing_enabled": True}).raise_for_status()
    v = admin.create_vault(name=unique("Soon"))
    inv = admin.post("/invites", json={"username": unique("att"), "role": "user"}).json()
    tag = admin.post("/share-tags", json={"name": unique("soon"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True}).json()
    try:
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "lifetime_minutes": 2 * 24 * 60})
        assert r.status_code == 200, r.text
        _login(page, admin_creds["username"], admin_creds["password"])
        lane = page.locator("#lane-attention")
        expect(lane.locator(".attention-item", has_text=v["name"])).to_be_visible(timeout=15000)
        expect(lane.locator(".attention-item", has_text=v["name"])).to_contain_text("expires in 2 days")
        expect(lane.locator(".attention-item", has_text="invitation")).to_contain_text("pending")
        lane.locator(".attention-item", has_text="invitation").click()
        expect(page.locator("#users-section")).to_be_visible()
    finally:
        admin.delete(f"/invites/{inv['id']}")
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"sharing_enabled": bool(sharing_before)})


def test_the_get_started_checklist_ticks_what_is_recorded_and_can_be_dismissed(page: Page, admin, admin_creds, checklist_fresh):
    _login(page, admin_creds["username"], admin_creds["password"])
    card = page.locator("#dashboard-get-started")
    expect(card).to_be_visible(timeout=15000)
    expect(card.locator(".get-started-item")).to_have_count(4)
    backup = card.locator('.get-started-item[data-check="backup"]')
    assert "is-done" not in (backup.get_attribute("class") or "")
    backup.locator("button.get-started-ack").click()
    expect(card.locator('.get-started-item[data-check="backup"]')).to_have_class("get-started-item is-done", timeout=10000)
    assert admin.get("/admin/get-started").json()["items"]["backup"] is True
    card.locator(".get-started-dismiss").click()
    expect(card).to_be_hidden()
    assert admin.get("/admin/get-started").json()["dismissed"] is True
    # Dismissed stays dismissed on the next visit.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#lane-attention")).to_be_visible(timeout=15000)
    expect(card).to_be_hidden()
