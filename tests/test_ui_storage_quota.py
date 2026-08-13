"""UI — the storage surfaces: the deployment limit, a per-account quota, and vault contributions.

The point of each screen is that a number is shown WITH the bound that applies to it, so nobody
has to know a magic value: the deployment field is capped by the deployment's own ceiling, the
per-account field says what it inherits, and a vault says who paid for its size.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui

GIB = 1024 ** 3


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_storage_settings(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="storage"]')
    # The settings form populates asynchronously and the app marks it ready by enabling Save.
    # Typing before that lands is a race the form itself loses: the load overwrites the field.
    expect(page.locator('#save-all-settings-btn[data-settings-ready="true"]')).to_be_enabled(timeout=15000)


def _open_vault_info(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    card = page.locator(f'.vault-card[data-vault-id="{vault_id}"]')
    expect(card).to_be_visible(timeout=10000)
    card.locator(".open-vault-btn").click()
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.click('[data-vault-tab="info"]')


def _open_user_editor(page: Page, user_id: str):
    """Expand the user's row (the Edit button lives in the collapsed detail panel) and open the
    edit modal."""
    row = page.locator(f'.exp-row[data-id="{user_id}"]')
    expect(row).to_be_visible(timeout=10000)
    row.locator(".exp-toggle").click()
    edit = page.locator(f'.edit-user-btn[data-user-id="{user_id}"]')
    expect(edit).to_be_visible(timeout=10000)
    edit.click()


# --- the deployment limit -------------------------------------------------------------------

def test_deployment_limit_shows_its_ceiling_and_usage(page: Page, admin, admin_creds):
    settings = admin.get("/settings").json()
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_storage_settings(page)

    field = page.locator("#setting-deployment-storage")
    expect(field).to_be_visible()
    label = page.locator("#setting-deployment-storage-max")
    if settings["deployment_storage_max_gb"]:
        # The ceiling is stated in words AND enforced by the input, so "-1 for unlimited" never
        # has to be explained to anyone. JSON carries the ceiling as a number, so a whole one
        # renders as "50", not "50.0" — match the browser's own formatting.
        ceiling = settings["deployment_storage_max_gb"]
        shown = str(int(ceiling)) if float(ceiling) == int(ceiling) else str(ceiling)
        expect(label).to_contain_text(f"{shown} GB maximum")
        expect(field).to_have_attribute("max", shown)
    else:
        expect(label).to_contain_text("no deployment maximum")
    expect(page.locator("#setting-deployment-storage-help")).to_contain_text("stored of")


def test_saving_a_deployment_limit_takes_effect(page: Page, admin, admin_creds):
    ceiling = admin.get("/settings").json()["deployment_storage_max_gb"]
    target = min(7, ceiling) if ceiling else 7
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_storage_settings(page)
        page.fill("#setting-deployment-storage", str(target))
        page.click("#save-all-settings-btn")
        expect(page.locator("#setting-deployment-storage")).to_have_value(str(target), timeout=8000)

        # The server is what matters, not the field: the saved limit is the one being enforced.
        def _limit():
            return admin.get("/storage/stats").json()["limit_bytes"]
        page.wait_for_timeout(500)
        assert _limit() == target * GIB
    finally:
        admin.put("/settings", json={"deployment_storage_limit_gb": None})


def test_clearing_the_field_returns_to_the_deployment_maximum(page: Page, admin, admin_creds):
    admin.put("/settings", json={"deployment_storage_limit_gb": 3})
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_storage_settings(page)
        expect(page.locator("#setting-deployment-storage")).to_have_value("3")
        page.fill("#setting-deployment-storage", "")
        page.click("#save-all-settings-btn")
        page.wait_for_timeout(800)
        assert admin.get("/settings").json()["deployment_storage_limit_gb"] is None
    finally:
        admin.put("/settings", json={"deployment_storage_limit_gb": None})


def test_the_storage_statistics_report_allocation_separately(page: Page, admin, admin_creds):
    v = admin.post("/vaults", json={"name": unique("uistat"), "size_limit_gb": 2}).json()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_storage_settings(page)
        expect(page.locator("#storage-stat-allocated")).to_contain_text("allocated across")
    finally:
        admin.delete_vault(v["id"])


# --- a per-account quota --------------------------------------------------------------------

def test_editing_a_user_quota_writes_the_override(page: Page, admin, admin_creds):
    user = admin.create_user(role="user")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="users"]')
        page.fill("#users-search", user["username"])
        _open_user_editor(page, user["id"])
        expect(page.locator("#edit-user-modal")).to_be_visible()

        # Default state: inherits, and the GB box stays out of the way until it is relevant.
        expect(page.locator("#edit-user-quota-mode")).to_have_value("inherit")
        expect(page.locator("#edit-user-quota-gb")).to_be_hidden()
        expect(page.locator("#edit-user-quota-help")).to_contain_text("Allocated")

        page.select_option("#edit-user-quota-mode", "custom")
        expect(page.locator("#edit-user-quota-gb")).to_be_visible()
        page.fill("#edit-user-quota-gb", "6")
        page.click("#edit-user-form button[type=submit]")
        expect(page.locator("#edit-user-modal")).not_to_be_visible(timeout=8000)

        assert admin.get(f"/users/{user['id']}").json()["storage_quota_bytes"] == 6 * GIB
    finally:
        admin.delete_user(user["id"])


def test_unlimited_is_a_distinct_choice_from_inherit(page: Page, admin, admin_creds):
    user = admin.create_user(role="user")
    try:
        admin.patch(f"/users/{user['id']}", json={"storage_quota_gb": "unlimited"})
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="users"]')
        page.fill("#users-search", user["username"])
        _open_user_editor(page, user["id"])

        # A stored exemption comes back as "unlimited", not as a blank that would read as inherit.
        expect(page.locator("#edit-user-quota-mode")).to_have_value("unlimited")
        expect(page.locator("#edit-user-quota-gb")).to_be_hidden()
    finally:
        admin.delete_user(user["id"])


# --- vault contributions --------------------------------------------------------------------

def test_vault_info_offers_the_contribution_control_to_the_owner(page: Page, admin, admin_creds):
    v = admin.post("/vaults", json={"name": unique("uigrant"), "size_limit_gb": 1}).json()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_info(page, v["id"])

        editor = page.locator("#vault-storage-editor")
        expect(editor).to_be_visible(timeout=10000)
        expect(page.locator("#vault-storage-input")).to_have_value("1")

        page.fill("#vault-storage-input", "3")
        page.click("#vault-storage-save-btn")
        page.wait_for_timeout(1200)
        assert admin.get(f"/vaults/{v['id']}").json()["size_limit"] == 3 * GIB
        expect(page.locator("#info-storage-text")).to_contain_text("of 3 GB")
    finally:
        admin.delete_vault(v["id"])


def test_a_manager_sees_the_control_and_the_contributor_breakdown(page: Page, admin, admin_creds):
    """The Manager case is why this card lives in the Info tab: the Settings tab is owner-only,
    so a manager who may fund the vault has to be able to reach the control somewhere."""
    owner = admin.create_user(role="user")
    manager = admin.create_user(role="user")
    oc = ApiClient()
    oc.login(owner["_username"], owner["_password"])
    created = oc.post("/vaults", json={"name": unique("uimgr"), "size_limit_gb": 1})
    if created.status_code == 403:
        admin.delete_user(owner["id"])
        admin.delete_user(manager["id"])
        pytest.skip("this deployment's default role can't create vaults")
    vault = created.json()
    try:
        assert oc.post(f"/vaults/{vault['id']}/permissions",
                       json={"user_id": manager["id"], "level": "manage"}).status_code == 200

        _login(page, manager["_username"], manager["_password"])
        _open_vault_info(page, vault["id"])

        expect(page.locator("#vault-storage-editor")).to_be_visible(timeout=10000)
        expect(page.locator("#vault-storage-input")).to_have_value("0")
        page.fill("#vault-storage-input", "2")
        page.click("#vault-storage-save-btn")
        page.wait_for_timeout(1200)

        assert oc.get(f"/vaults/{vault['id']}").json()["size_limit"] == 3 * GIB
        # Two contributors now, so the breakdown names both and the manager's own row is marked.
        breakdown = page.locator("#vault-storage-contributors")
        expect(breakdown).to_contain_text(owner["username"])
        expect(breakdown).to_contain_text("you")
    finally:
        oc.delete_vault(vault["id"])
        admin.delete_user(manager["id"])
        admin.delete_user(owner["id"])


def test_a_read_only_member_gets_no_contribution_control(page: Page, admin, admin_creds):
    reader = admin.create_user(role="user")
    v = admin.post("/vaults", json={"name": unique("uiread"), "size_limit_gb": 1}).json()
    try:
        assert admin.post(f"/vaults/{v['id']}/permissions",
                          json={"user_id": reader["id"], "level": "read"}).status_code == 200
        _login(page, reader["_username"], reader["_password"])
        _open_vault_info(page, v["id"])

        expect(page.locator("#info-storage-text")).to_contain_text("of 1 GB")
        expect(page.locator("#vault-storage-editor")).to_be_hidden()
        expect(page.locator("#vault-storage-contributors")).to_be_empty()
    finally:
        admin.delete_vault(v["id"])
        admin.delete_user(reader["id"])
