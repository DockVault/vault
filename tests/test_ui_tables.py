"""Business tables (static/js/tables.js): sortable headers with aria-sort, a search box, columns a business
reads first, and a density the person chooses, remembered for the account.

Users gains Last sign-in and Created; a vault's members gain Granted by; the Shared cards say who shared, when
and until when; the administrators' link tables gain Created and Last used; the temporary credentials table
sorts and searches. A sort is kept for the account across a reload; the density switch beside the interface
switch sets data-density on the page and is kept too.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def two_users(admin):
    a = admin.create_user(username="aaa" + unique("")[1:9], role="user")
    z = admin.create_user(username="zzz" + unique("")[1:9], role="user")
    try:
        yield a, z
    finally:
        admin.delete_user(a["id"])
        admin.delete_user(z["id"])


def test_users_table_has_the_new_columns_sorts_and_remembers_the_sort(page: Page, admin, admin_creds, two_users):
    a, z = two_users
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="users"]')
    table = page.locator("#users-list table")
    expect(table).to_be_visible(timeout=15000)
    headers = [h.strip() for h in table.locator("thead th").all_text_contents()]
    assert headers[-2:] == ["Last sign-in", "Created"], headers
    row_a = table.locator(f'.exp-row[data-id="{a["id"]}"]')
    expect(row_a.locator("td.col-time").first).to_have_text("Never")  # never signed in
    expect(row_a.locator("td.col-time time.when")).to_have_count(1)    # created, as a moment
    # Sort by User: ascending puts aaa… before zzz…, a second click reverses, and aria-sort says so.
    user_th = table.locator("thead th", has_text="User")
    expect(user_th).to_have_attribute("aria-sort", "none")
    user_th.click()
    expect(user_th).to_have_attribute("aria-sort", "ascending")
    names = table.locator("tbody tr.exp-row .cell-user-name").all_inner_texts()
    assert names.index(a["_username"]) < names.index(z["_username"])
    user_th.click()
    expect(user_th).to_have_attribute("aria-sort", "descending")
    names = table.locator("tbody tr.exp-row .cell-user-name").all_inner_texts()
    assert names.index(z["_username"]) < names.index(a["_username"])
    # The detail row still belongs to its row after a sort.
    page.locator(f'.exp-row[data-id="{z["id"]}"] .exp-toggle').click()
    expect(page.locator(f'.exp-detail[data-id="{z["id"]}"]')).to_be_visible()
    assert page.evaluate(
        "id => document.querySelector(`.exp-row[data-id='${id}']`).nextElementSibling.matches(`.exp-detail[data-id='${id}']`)", z["id"])
    # The sort is remembered for the account, on the server: with the browser's own copy gone, a reload
    # comes back sorted the same way.
    import time as _time
    for _ in range(40):   # the save goes out a moment after the click
        if "users" in (admin.get("/users/me/preferences").json().get("tables") or ""):
            break
        _time.sleep(0.25)
    assert "users" in (admin.get("/users/me/preferences").json().get("tables") or ""), "the sort was not saved to the account"
    page.evaluate("() => { localStorage.removeItem('dv_tables'); }")
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.click('.sidebar-item[data-section="users"]')
    expect(table.locator("thead th", has_text="User")).to_have_attribute("aria-sort", "descending", timeout=15000)
    names = table.locator("tbody tr.exp-row .cell-user-name").all_inner_texts()
    assert names.index(z["_username"]) < names.index(a["_username"])


def test_the_density_switch_is_kept_for_the_account(page: Page, admin):
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        assert page.evaluate("() => document.documentElement.getAttribute('data-density')") is None
        page.click("#profile-btn")
        page.click('.density-choice[data-density="compact"]')
        assert page.evaluate("() => document.documentElement.getAttribute('data-density')") == "compact"
        page.wait_for_timeout(600)
        page.evaluate("() => { localStorage.removeItem('dv_density'); }")  # only the account remembers it now
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.wait_for_function("() => document.documentElement.getAttribute('data-density') === 'compact'", timeout=10000)
        # And the next person on this tab starts comfortable.
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => document.documentElement.getAttribute('data-density')") is None
    finally:
        admin.delete_user(u["id"])


@pytest.fixture
def shared_world(admin):
    """An owner who granted a member access and shared a vault with them."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    owner = admin.create_user(role="user")
    member = admin.create_user(role="user")
    co = ApiClient(BASE_URL); co.login(owner["_username"], owner["_password"])
    cm = ApiClient(BASE_URL); cm.login(member["_username"], member["_password"])
    vault = co.create_vault(name=unique("granted"))
    assert co.post(f"/vaults/{vault['id']}/permissions", json={"user_id": member["id"], "level": "read"}).status_code in (200, 201)
    tag = admin.post("/share-tags", json={"name": unique("tbl"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True}).json()
    share = co.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
                                     "claim_audience": "anyone_internal", "lifetime_minutes": 5 * 24 * 60})
    assert share.status_code == 200, share.text
    assert cm.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
    try:
        yield owner, member, vault
    finally:
        co.delete_vault(vault["id"])
        admin.delete_user(owner["id"]); admin.delete_user(member["id"])
        admin.put("/settings", json={"sharing_enabled": before})


def test_vault_members_show_who_granted_and_the_table_searches(page: Page, shared_world):
    owner, member, vault = shared_world
    _login(page, owner["_username"], owner["_password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    page.click('[data-vault-tab="permissions"]')
    row = page.locator("#permissions-table-body tr", has_text=member["_username"])
    expect(row).to_be_visible(timeout=15000)
    headers = [h.strip() for h in page.locator("#permissions-table-body").locator("xpath=..").locator("thead th").all_text_contents()]
    assert "Granted by" in headers, headers
    granted_by = row.locator("td").nth(headers.index("Granted by")).locator(".person-chip")
    expect(granted_by).to_have_text(owner["_username"])
    search = page.locator("#table-search-vault-members")
    expect(search).to_be_visible()
    search.fill("no-such-member")
    expect(row).to_be_hidden()
    expect(page.locator(".table-search-empty")).to_be_visible()
    search.fill("")
    expect(row).to_be_visible()


def test_shared_cards_say_who_shared_when_and_until_when(page: Page, shared_world):
    owner, member, vault = shared_world
    _login(page, member["_username"], member["_password"])
    page.click('.sidebar-item[data-section="shared"]')
    card = page.locator("[data-share-id]", has_text=vault["name"]).first
    expect(card).to_be_visible(timeout=15000)
    by = card.locator(".shared-by")
    expect(by).to_contain_text("Shared by")
    expect(by.locator(".person-chip")).to_have_text(owner["_username"])
    expect(by.locator("time.when")).to_have_count(1)
    expect(card.locator(".shared-expires time.when")).to_have_count(1)
    assert "UTC" in (card.locator(".shared-expires time.when").get_attribute("title") or "")
    # The sharer's own card: shared on, and expires.
    page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
    _login(page, owner["_username"], owner["_password"])
    page.click('.sidebar-item[data-section="shared"]')
    page.click('[data-shared-tab="by-me"]')
    mine = page.locator("[data-share-id]", has_text=vault["name"]).first
    expect(mine.locator(".shared-on time.when")).to_have_count(1, timeout=15000)
    expect(mine.locator(".shared-expires time.when")).to_have_count(1)


def test_link_tables_have_created_and_last_used_and_sort(page: Page, admin, admin_creds):
    enabled = admin.get("/settings").json()
    admin.put("/settings", json={"public_note_links_enabled": True})
    tag = admin.post("/note-link-tags", json={"name": unique("nlt"), "auto_enroll_new_users": True})
    note = admin.post("/notes", json={"title": unique("linked"), "body": "x"}).json()
    body = {"note_id": note["id"]}
    if tag.status_code == 200:
        body["tag_id"] = tag.json()["id"]
    made = admin.post("/note-links", json=body)
    if made.status_code not in (200, 201):
        pytest.skip(f"no note link could be made here: {made.status_code} {made.text[:120]}")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="settings"]')
        expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
        page.click('#settings-section .tab-btn[data-tab="notelinks"]')
        table = page.locator("#settings-tab-notelinks table.data-table").first
        expect(table).to_be_visible(timeout=15000)
        headers = [h.strip() for h in table.locator("thead th").all_text_contents()]
        assert "Created" in headers and "Last used" in headers, headers
        created = table.locator("tbody tr").first.locator("td").nth(headers.index("Created")).locator("time.when")
        expect(created).to_have_count(1)
        th = table.locator("thead th", has_text="Created")
        th.click()
        expect(th).to_have_attribute("aria-sort", "ascending")
        expect(table.locator("xpath=preceding-sibling::input[contains(@class,'table-search')]")).to_have_count(1)
    finally:
        admin.put("/settings", json={"public_note_links_enabled": enabled.get("public_note_links_enabled")})
