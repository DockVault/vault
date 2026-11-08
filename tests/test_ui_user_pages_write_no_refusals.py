"""A user's own pages ask nothing of the administrators' routes, so a user's ordinary day writes no refused
administrator action.

Every refused administrator read is recorded (admin_access_denied): it is the signal of a non-administrator
reaching for an administrator function, and it must stay. The web app itself was producing it. The Permissions
tab of a vault asked the administrators' /groups for the departments a non-administrator owner could add, so the
owner got an empty list and a recorded refusal on every open; and an administrator's sidebar items left behind on
a shared tab (see test_ui_admin_nav_role_switch) led a user into Settings, Groups and Users, each read refused and
recorded. Now the Permissions tab lists the caller's own departments (the only ones the server lets them add), and
the administrators' pages and settings modules load only for an administrator.

The direct probe stays recorded: a user asking GET /settings themselves writes exactly one row, naming the route.
"""
import os
import re
import subprocess

import pytest
from playwright.sync_api import Page, expect
from urllib.parse import urlparse

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _refusals_of(user_id: str) -> int:
    return int(_psql(f"SELECT count(*) FROM audit_logs WHERE action='admin_access_denied' AND user_id='{user_id}'") or "0")


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def owner_in_a_department(admin):
    """A user who belongs to a department and owns a Standard vault, with an API client signed in as them."""
    u = admin.create_user(role="user")
    group = admin.post("/groups", json={"name": unique("dept")})
    assert group.status_code == 200, group.text
    gid = group.json()["id"]
    added = admin.post(f"/groups/{gid}/members", json={"user_ids": [u["id"]]})
    assert added.status_code == 200, added.text
    client = ApiClient()
    client.login(u["_username"], u["_password"])
    vault = client.create_vault(name=unique("owned"))
    try:
        yield {"user": u, "client": client, "vault": vault, "group_id": gid, "group_name": group.json()["name"]}
    finally:
        client.delete_vault(vault["id"])
        admin.delete(f"/groups/{gid}")
        admin.delete_user(u["id"])


def test_a_users_pages_and_vault_tabs_write_no_refused_administrator_action(page: Page, owner_in_a_department):
    u, vault = owner_in_a_department["user"], owner_in_a_department["vault"]
    before = _refusals_of(u["id"])

    _login(page, u["_username"], u["_password"])
    # Every page the sidebar offers this account.
    sections = page.evaluate(
        "() => [...document.querySelectorAll('.sidebar-item[data-section]')]"
        "  .filter(i => getComputedStyle(i).display !== 'none')"
        "  .map(i => i.getAttribute('data-section'))")
    assert "vaults" in sections and "settings" not in sections, sections
    for section in sections:
        page.click(f'.sidebar-item[data-section="{section}"]')
        expect(page.locator(f"#{section}-section")).to_be_visible(timeout=10000)
    # The vault they own, and every one of its tabs.
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.vault-card[data-vault-id="{vault["id"]}"] .vault-open')
    expect(page.locator("#vault-view-title")).to_have_text(vault["name"], timeout=10000)
    for tab in ("info", "permissions", "settings", "files"):
        page.click(f'[data-vault-tab="{tab}"]')
        page.wait_for_timeout(400)
    # The Permissions tab offers the owner their own department to add.
    page.click('[data-vault-tab="permissions"]')
    select = page.locator("#vga-group-select")
    expect(select).to_be_visible(timeout=10000)
    expect(select.locator("option", has_text=owner_in_a_department["group_name"])).to_have_count(1)
    # A reload restores the vault view and runs every loader again.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#vault-view-title")).to_have_text(vault["name"], timeout=15000)
    page.wait_for_timeout(1500)

    assert _refusals_of(u["id"]) == before, _psql(
        f"SELECT endpoint FROM audit_logs WHERE action='admin_access_denied' AND user_id='{u['id']}' "
        "ORDER BY timestamp DESC LIMIT 10")


def test_a_users_own_probe_of_an_administrator_route_is_still_recorded_once(owner_in_a_department):
    """The negative control: the web app is quiet, the record is not."""
    u, client = owner_in_a_department["user"], owner_in_a_department["client"]
    before = _refusals_of(u["id"])
    assert client.get("/settings?section=general").status_code == 403
    assert _refusals_of(u["id"]) == before + 1
    endpoint = _psql(f"SELECT endpoint FROM audit_logs WHERE action='admin_access_denied' AND user_id='{u['id']}' "
                     "ORDER BY timestamp DESC LIMIT 1")
    assert endpoint == "/settings", endpoint  # the route, never the query
    assert not re.search(r"[?=]", endpoint)


def test_the_guarded_loaders_ask_nothing_when_forced_as_a_user(page: Page, owner_in_a_department):
    """The sidebar hides the administrators' pages from a user; behind it, each page's loader and the two
    settings modules return at once for a non-administrator. Forced open anyway (a script, a link, a restored
    view), none of them asks an administrator route, and the record gains no refused administrator action."""
    u = owner_in_a_department["user"]
    before = _refusals_of(u["id"])
    _login(page, u["_username"], u["_password"])
    asked = []
    page.on("request", lambda r: asked.append(f"{r.method} {r.url}")
            if re.match(r"^/(settings|groups|users|audit|activity)(/|$)", urlparse(r.url).path)
            and not urlparse(r.url).path.startswith(("/users/me", "/users/search")) else None)
    page.evaluate(
        "async () => {"
        "  await initSettings(); await loadGroups(); await loadUsers();"
        "  await SettingsLevels.load(); await RetentionSettings.load();"
        "  navigateToSection('settings'); navigateToSection('groups'); navigateToSection('users');"
        "}")
    expect(page.locator("#dashboard-section")).to_have_class(re.compile(r"\bactive\b"))
    # A restored view of Settings, as a reload after an administrator used this browser would leave it.
    page.evaluate("() => sessionStorage.setItem('dv_nav', JSON.stringify({section: 'settings'}))")
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#dashboard-lanes")).to_be_visible(timeout=10000)
    page.wait_for_timeout(1500)
    assert not asked, f"a forced loader asked an administrator route: {asked}"
    assert _refusals_of(u["id"]) == before
