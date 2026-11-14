"""A sign-out leaves nothing of the person in the dashboard's lists (static/js/app.js logout).

The lists Most recent, Favourites and What's waiting name the person's vaults (an unlocked zero-knowledge vault by
its real name) and what was shared with them. A sign-out empties them, so the sign-in screen hides none of it in the
page, and the next person signed in on the same tab never sees any of it painted before their own lists are drawn.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

LISTS = ("#lane-recent", "#lane-favourites", "#lane-waiting")

# Every painted frame, from the next sign-in on: which of the given names is on screen.
WATCH = r"""(names) => {
  window.__seen = [];
  const t0 = performance.now();
  const frame = () => {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) {
      const t = n.nodeValue || '';
      for (const name of names) if (t.includes(name)) {
        const el = n.parentElement, r = el.getBoundingClientRect();
        if (el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) && r.width > 0 && r.height > 0)
          window.__seen.push(name);
      }
    }
    if (performance.now() - t0 < 8000) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}"""


def _sign_in(page: Page, user):
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_a_sign_out_empties_the_dashboards_lists_and_the_next_person_never_sees_them(page: Page, admin):
    sharing_before = admin.get("/settings").json().get("sharing_enabled", False)
    admin.put("/settings", json={"sharing_enabled": True}).raise_for_status()
    ana, ben = admin.create_user(role="user"), admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    names = {"favourite": unique("AnaFavourite"), "recent": unique("AnaRecent"), "pushed": unique("AnaPushed")}
    pushed = admin.create_vault(name=names["pushed"])
    try:
        fav = client.create_vault(name=names["favourite"])
        rec = client.create_vault(name=names["recent"])
        client.put(f"/vaults/{fav['id']}/favorite").raise_for_status()
        client.get(f"/vaults/{fav['id']}").raise_for_status()
        client.get(f"/vaults/{rec['id']}").raise_for_status()
        tag = admin.post("/share-tags", json={"name": unique("listtag"), "auto_enroll_new_users": True,
                                              "allowed_audiences": ["users"], "max_recipients_cap": 10})
        tag.raise_for_status()
        admin.post("/shares", json={"vault_id": pushed["id"], "tag_id": tag.json()["id"], "target_type": "vault",
                                    "claim_audience": "users", "audience_user_ids": [ana["id"]]}).raise_for_status()

        page.goto("/")
        _sign_in(page, ana)
        for lane, name in (("#lane-favourites", "favourite"), ("#lane-recent", "recent"), ("#lane-waiting", "pushed")):
            expect(page.locator(lane)).to_contain_text(names[name], timeout=15000)

        # The app's own sign-out.
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        for lane in LISTS:
            expect(page.locator(f"{lane} > *")).to_have_count(0)
        held = page.evaluate("(names) => names.filter((n) => document.body.textContent.includes(n))",
                             list(names.values()))
        assert held == [], f"still in the page after the sign-out: {held}"

        # The next person on the same tab: none of it is painted at any moment.
        page.evaluate(WATCH, list(names.values()))
        _sign_in(page, ben)
        page.wait_for_timeout(6000)
        assert page.evaluate("() => Array.from(new Set(window.__seen))") == []
    finally:
        admin.delete_user(ana["id"])
        admin.delete_user(ben["id"])
        admin.delete_vault(pushed["id"])
        admin.put("/settings", json={"sharing_enabled": bool(sharing_before)})
