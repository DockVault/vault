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
    # The vault keeps no record of backup runs, and says so: the item is ticked on the administrator's word.
    expect(backup.locator(".get-started-label")).to_have_text("Backups set up")
    expect(backup.locator(".get-started-hint")).to_contain_text("dockvault.py backup")
    expect(backup.locator(".get-started-hint")).to_contain_text("DockVault cannot see backups taken on the host")
    expect(backup.locator("button.get-started-ack")).to_have_text("I have set up backups")
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


def test_an_expiring_share_row_leads_to_its_card_on_the_shared_by_me_tab(page: Page, admin, admin_creds, invites_on):
    """A Needs-attention row for a share lands on Shared's "Shared by me" tab with that share's card (and its
    Extend button) in view, not on "Shared with me" where the person's own share is not listed. The reminder
    notices carry the same target, so a click on one lands in the same place."""
    sharing_before = admin.get("/settings").json().get("sharing_enabled", False)
    admin.put("/settings", json={"sharing_enabled": True}).raise_for_status()
    v = admin.create_vault(name=unique("Soonest"))
    tag = admin.post("/share-tags", json={"name": unique("soonest"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True}).json()
    try:
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "lifetime_minutes": 2 * 24 * 60})
        assert r.status_code == 200, r.text
        share_id = r.json()["id"]
        _login(page, admin_creds["username"], admin_creds["password"])
        lane = page.locator("#lane-attention")
        lane_row = lane.locator(".attention-item", has_text=v["name"])
        expect(lane_row).to_be_visible(timeout=15000)
        lane_row.click()
        expect(page.locator("#shared-section")).to_be_visible()
        expect(page.locator('#shared-section .tab-btn[data-shared-tab="by-me"]')).to_have_class("tab-btn active")
        card = page.locator(f'#shared-by-me-list [data-share-id="{share_id}"]')
        expect(card).to_be_visible(timeout=15000)
        expect(card.locator("button.share-extend")).to_be_visible()
        # A notice with the same target lands in the same place; a plain "#shared" target still opens the page.
        page.click('.sidebar-item[data-section="dashboard"]')
        page.evaluate("t => openAppTarget(t)", "#uploadlinks/drops")
        if page.locator("#uploadlinks-section").is_visible():
            expect(page.locator("#receivers-tab-vaults")).to_be_visible()
        page.evaluate("t => openAppTarget(t)", "#notes/shared")
        expect(page.locator("#notes-section")).to_be_visible()
        expect(page.locator("#notes-tab-shared")).to_be_visible(timeout=10000)
        page.evaluate("t => openAppTarget(t)", "#shared")
        expect(page.locator("#shared-section")).to_be_visible()
        expect(page.locator('#shared-section .tab-btn[data-shared-tab="with-me"]')).to_have_class("tab-btn active")
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"sharing_enabled": sharing_before})


def test_an_attention_row_shows_its_whole_title_on_hover(page: Page, admin, admin_creds, invites_on):
    sharing_before = admin.get("/settings").json().get("sharing_enabled", False)
    admin.put("/settings", json={"sharing_enabled": True}).raise_for_status()
    v = admin.create_vault(name=unique("A vault with a name long enough that the lane cuts it short"))
    tag = admin.post("/share-tags", json={"name": unique("hover"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True}).json()
    try:
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "lifetime_minutes": 2 * 24 * 60})
        assert r.status_code == 200, r.text
        _login(page, admin_creds["username"], admin_creds["password"])
        title = page.locator("#lane-attention .attention-item", has_text=v["name"]).locator(".dashboard-lane-title")
        expect(title).to_be_visible(timeout=15000)
        expect(title).to_have_attribute("title", title.text_content())
        assert v["name"] in title.get_attribute("title")
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"sharing_enabled": bool(sharing_before)})


@pytest.fixture
def drop_link(admin):
    before = admin.get("/settings").json()
    keys = ("public_receivers_enabled", "public_receiver_user_cap")
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    tag = admin.post("/receiver-tags", json={"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
                                             "max_total_bytes_cap": 100 * 1024 * 1024, "auto_enroll_new_users": True,
                                             "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
    rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * 1024 * 1024,
                                         "label": unique("Inbox"), "ttl_hours": 24}).json()
    anon = admin.clone_anonymous()
    for name in ("a.txt", "b.txt"):
        o = anon.post(f"/receivers/{rec['token']}/upload-session", json={"filename": name, "total_size": 1, "total_chunks": 1})
        sid = o.json()["session_id"]
        anon.put(f"/receivers/{rec['token']}/upload-session/{sid}/chunks/0", data=b"x",
                 headers={"Content-Type": "application/octet-stream"})
        assert anon.post(f"/receivers/{rec['token']}/upload-session/{sid}/complete", json={}).status_code == 200
    try:
        yield rec
    finally:
        admin.put("/settings", json={k: before.get(k) for k in keys})


def test_the_drop_vault_row_counts_the_files_still_waiting(page: Page, admin, admin_creds, drop_link):
    """Two files arrive; one is moved out: the row says one file waits, not two uploads received. With both
    moved out, the row goes."""
    rec = drop_link
    _login(page, admin_creds["username"], admin_creds["password"])
    lane = page.locator("#lane-attention")
    row = lane.locator(".attention-item", has_text=rec["label"]).filter(has_text="waiting")
    expect(row).to_contain_text("2 files waiting", timeout=15000)
    dest = admin.create_vault(name=unique("Dest"))
    try:
        files = admin.get(f"/vaults/{rec['vault_id']}/files").json()["items"]
        moved = admin.post(f"/vaults/{rec['vault_id']}/files/{files[0]['id']}/move", json={"dest_vault_id": dest["id"]})
        assert moved.status_code in (200, 202), moved.text
        listed = next(r for r in admin.get("/receivers").json()["receivers"] if r["id"] == rec["id"])
        assert listed["upload_count"] == 2 and listed["files_in_vault"] == 1, listed
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        expect(row).to_contain_text("1 file waiting", timeout=15000)
        admin.post(f"/vaults/{rec['vault_id']}/files/{files[1]['id']}/move", json={"dest_vault_id": dest["id"]})
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        # The lane has drawn again (it lists at most six rows, so which others it shows depends on the data),
        # and the files row is gone.
        expect(lane.locator(".attention-item").first).to_be_visible(timeout=15000)
        expect(row).to_have_count(0)
    finally:
        admin.delete_vault(dest["id"])


def test_a_thing_in_needs_attention_is_not_listed_again_under_whats_waiting(page: Page, admin, admin_creds, drop_link):
    """The upload notice about files the Needs-attention lane already lists is left out of What's waiting; a
    notice of another kind stays."""
    rec = drop_link
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(page.locator("#lane-attention .attention-item", has_text=rec["label"]).filter(has_text="waiting")).to_be_visible(timeout=15000)
    page.evaluate("""() => {
        notifItems = [{ id: 'n-up', type: 'receiver_upload', title: 'Files received on the inbox', body: '', target: '#uploadlinks', is_read: false },
                      { id: 'n-other', type: 'share_received', title: 'A colleague shared a vault with you', body: '', target: '#shared', is_read: false }];
        renderWaitingLane(state.dashboardShared || []); }""")
    waiting = page.locator("#lane-waiting")
    expect(waiting).to_contain_text("A colleague shared a vault with you")
    expect(waiting).not_to_contain_text("Files received on the inbox")
    assert page.evaluate("() => DashboardActions.listsNotice({ type: 'receiver_upload', target: '#uploadlinks' })") is True
    assert page.evaluate("() => DashboardActions.listsNotice({ type: 'share_received', target: '#shared' })") is False


def test_get_started_opens_the_settings_page_of_its_item(page: Page, admin, admin_creds, checklist_fresh):
    _login(page, admin_creds["username"], admin_creds["password"])
    card = page.locator("#dashboard-get-started")
    expect(card).to_be_visible(timeout=15000)
    email = card.locator('.get-started-item[data-check="email"]')
    if "is-done" in (email.get_attribute("class") or ""):
        pytest.skip("email is already set up on this install, so its item offers no button")
    email.get_by_role("button", name="Open settings").click()
    expect(page.locator("#settings-tab-email")).to_be_visible(timeout=15000)
    expect(page.locator('#settings-section .tab-btn[data-tab="email"]')).to_have_attribute("aria-current", "page")
    # The settings menu in the rail marks the same page.
    expect(page.locator('#sidebar .sidebar-settings-item[data-tab="email"]')).to_have_attribute("aria-current", "page")
    expect(page.locator("#settings-tab-general")).to_be_hidden()
    page.click("#sidebar-settings-back")   # Back: to the dashboard Settings was opened from
    expect(card).to_be_visible(timeout=15000)
    card.locator('.get-started-item[data-check="second_factor"]').get_by_role("button", name="Open settings").click()
    expect(page.locator("#settings-tab-security")).to_be_visible(timeout=15000)
    expect(page.locator('#settings-section .tab-btn[data-tab="security"]')).to_have_attribute("aria-current", "page")
    expect(page.locator('#sidebar .sidebar-settings-item[data-tab="security"]')).to_have_attribute("aria-current", "page")
