"""Dashboard personal lanes: What's waiting / Favourites / Most recent.

These lanes replace the administrator ops cards for a non-admin (and sit alongside them for an
admin). They are fed entirely from data the account can already see — the vault list, the
shared-with-me list, and the notification bell — with no new endpoint. Every row is built with
createElement + textContent, so a vault name or another user's name is never interpreted as HTML.

Each lane is anchored on a specific row so a test cannot pass merely because the dashboard failed
to render (an empty lane looks the same as a missing one otherwise).
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

FAV = "#lane-favourites"
RECENT = "#lane-recent"
WAITING = "#lane-waiting"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _client_for(user) -> ApiClient:
    c = ApiClient(BASE_URL)
    c.login(user["_username"], user["_password"])
    return c


def _share_tag(admin):
    r = admin.post("/share-tags", json={"name": unique("lanetag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users"], "max_recipients_cap": 10})
    r.raise_for_status()
    return r.json()


def test_favourites_and_recent_lanes_populate_and_separate(page: Page, admin):
    """A favourited vault lands in Favourites; a viewed non-favourite in Most recent — not both."""
    user = admin.create_user(role="user")
    client = _client_for(user)
    fav = client.create_vault(name=unique("Fav"))
    rec = client.create_vault(name=unique("Recent"))
    try:
        client.put(f"/vaults/{fav['id']}/favorite").raise_for_status()
        # A GET on the vault detail (no X-Access-Check) stamps last_viewed_at, so both sort sanely.
        client.get(f"/vaults/{fav['id']}").raise_for_status()
        client.get(f"/vaults/{rec['id']}").raise_for_status()

        _login(page, user["_username"], user["_password"])
        # Favourites lane holds the favourite and NOT the plain vault.
        expect(page.locator(f"{FAV} .dashboard-lane-title", has_text=fav["name"])).to_be_visible(timeout=10000)
        expect(page.locator(f"{FAV} .dashboard-lane-title", has_text=rec["name"])).to_have_count(0)
        # Most-recent lane holds the non-favourite and NOT the favourite (favourites are excluded).
        expect(page.locator(f"{RECENT} .dashboard-lane-title", has_text=rec["name"])).to_be_visible()
        expect(page.locator(f"{RECENT} .dashboard-lane-title", has_text=fav["name"])).to_have_count(0)
    finally:
        client.delete_vault(fav["id"])
        client.delete_vault(rec["id"])
        admin.delete_user(user["id"])


def test_clicking_a_favourite_lane_row_opens_the_vault(page: Page, admin):
    user = admin.create_user(role="user")
    client = _client_for(user)
    fav = client.create_vault(name=unique("OpenMe"))
    try:
        client.put(f"/vaults/{fav['id']}/favorite").raise_for_status()
        client.get(f"/vaults/{fav['id']}").raise_for_status()
        _login(page, user["_username"], user["_password"])
        row = page.locator(f"{FAV} .dashboard-lane-item", has_text=fav["name"])
        expect(row).to_be_visible(timeout=10000)
        row.click()
        # openVault() activates the vault browser and titles it with the vault name.
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        expect(page.locator("#vault-view-title")).to_have_text(fav["name"])
    finally:
        client.delete_vault(fav["id"])
        admin.delete_user(user["id"])


def test_empty_lanes_show_their_guidance(page: Page, admin):
    """A brand-new account has nothing in any lane — each shows its own empty message, not a blank."""
    user = admin.create_user(role="user")
    try:
        _login(page, user["_username"], user["_password"])
        expect(page.locator(f"{FAV} .dashboard-lane-empty")).to_be_visible(timeout=10000)
        expect(page.locator(f"{RECENT} .dashboard-lane-empty")).to_be_visible()
        expect(page.locator(f"{WAITING} .dashboard-lane-empty")).to_be_visible()
        # Non-vacuous: the waiting lane says "caught up", not a generic blank.
        expect(page.locator(f"{WAITING} .dashboard-lane-empty")).to_contain_text("caught up")
    finally:
        admin.delete_user(user["id"])


def test_waiting_lane_surfaces_a_pushed_share(page: Page, admin):
    """A vault pushed to the user appears in 'What's waiting for you' as claimable."""
    # Internal sharing defaults OFF on a fresh deployment; a push cannot be created until it is on.
    sharing_before = admin.get("/settings").json().get("sharing_enabled", False)
    admin.put("/settings", json={"sharing_enabled": True}).raise_for_status()
    v = admin.create_vault(name=unique("PushedV"))
    recipient = admin.create_user(role="user")
    try:
        admin.post("/shares", json={"vault_id": v["id"], "tag_id": _share_tag(admin)["id"],
                                    "target_type": "vault", "claim_audience": "users",
                                    "audience_user_ids": [recipient["id"]]}).raise_for_status()
        _login(page, recipient["_username"], recipient["_password"])
        # The pushed vault surfaces as a claimable row (a notification about it also appears; this
        # targets the shared-item row specifically via its "claim to open" hint).
        row = page.locator(f"{WAITING} .dashboard-lane-item", has_text="claim to open")
        expect(row).to_be_visible(timeout=10000)
        expect(row.locator(".dashboard-lane-title")).to_have_text(v["name"])
    finally:
        admin.delete_user(recipient["id"])
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"sharing_enabled": bool(sharing_before)})


def test_lane_titles_render_as_text_not_html(page: Page, admin):
    """The render path must emit a hostile name as literal text — no injected element, no script.

    The server rejects a vault named with '<', so the vector is closed at creation too; this drives
    renderDashboardLanes() directly with a hostile name to pin the client-side textContent guarantee
    independent of that server validation.
    """
    user = admin.create_user(role="user")
    try:
        _login(page, user["_username"], user["_password"])
        expect(page.locator(FAV)).to_be_visible(timeout=10000)
        hostile = "<img src=x onerror=window.__xss=1>zz"
        page.evaluate(
            "(name) => renderDashboardLanes("
            "[{id:'00000000-0000-0000-0000-000000000000', name, is_favorite:true, last_viewed_at:null}], [])",
            hostile,
        )
        title = page.locator(f"{FAV} .dashboard-lane-title")
        expect(title).to_have_count(1)
        assert title.inner_text() == hostile             # literal text, not parsed HTML
        assert page.locator("#dashboard-lanes img").count() == 0
        page.wait_for_timeout(200)
        assert page.evaluate("() => window.__xss === undefined") is True
    finally:
        admin.delete_user(user["id"])
