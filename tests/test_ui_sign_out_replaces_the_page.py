"""After every end of a session the page is replaced, and nothing of the person stays in it (static/js/app.js logout).

An administrator goes through every section (a vault with a file, an unlocked zero-knowledge vault, a favourite,
shares both ways, a note, the users list, an invitation, a held credential change, the events, a notification,
the settings), and the session ends: by the Sign out button, ended by another administrator, run out on its own,
or signed out in another tab of the same browser. The page is then a new one: none of the person's text is in the
document, nothing of theirs is in the browser's storage, and the next person signed in on the same tab never sees
any of it painted. The reason the session ended is on the sign-in screen once, and a sign-out by hand gives none.
A request still on its way when the session ended cannot write into the new page.
"""
import time

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

PASSPHRASE = "replace-the-page-passphrase-1"

# Every place a marker can hide in the document: text, attributes, form values; and the browser's storage.
FIND = r"""(markers) => {
  const found = [];
  const html = document.documentElement;
  const text = html.textContent || '';
  for (const m of markers) if (text.includes(m)) found.push('text:' + m);
  for (const el of html.querySelectorAll('*')) {
    for (const a of Array.from(el.attributes)) for (const m of markers) if (a.value.includes(m)) found.push('attr:' + m);
    if (typeof el.value === 'string') for (const m of markers) if (el.value.includes(m)) found.push('value:' + m);
  }
  const stored = {};
  for (const [name, store] of [['local', localStorage], ['session', sessionStorage]]) {
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i), v = store.getItem(k) || '';
      stored[name + ':' + k] = markers.filter((m) => v.includes(m));
    }
  }
  return { found: Array.from(new Set(found)), stored };
}"""

# Every painted frame from now on: which markers are on screen.
WATCH = r"""(markers) => {
  window.__painted = [];
  const t0 = performance.now();
  const frame = () => {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) {
      const t = n.nodeValue || '';
      for (const m of markers) if (t.includes(m)) {
        const el = n.parentElement, r = el.getBoundingClientRect();
        if (el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) && r.width > 0 && r.height > 0)
          window.__painted.push(m);
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


def _sign_out_by_hand(page: Page):
    page.click("#profile-btn")
    page.click("#dropdown-logout-btn")


def _go(page: Page, section: str):
    item = page.locator(f'.sidebar-item[data-section="{section}"]')
    if item.count() and item.first.is_visible():
        item.first.click()
        page.wait_for_timeout(1200)


def _ended(page: Page, seconds: float) -> bool:
    """Wait for the sign-in screen; then whether this page was replaced by a new one (the mark set on the old one is
    gone). The checks of what is left run either way, and the replacement is asserted last."""
    expect(page.locator("#login-screen")).to_be_visible(timeout=seconds * 1000)
    try:
        page.wait_for_function("() => !window.__oldPage", timeout=5000)
    except Exception:
        return False
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    return True


def _zero_knowledge_vault(page: Page, name: str, desc: str, label: str):
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    page.click("#encryption-key-setup-btn")
    page.click("#confirm-modal-confirm-btn")
    for _ in range(2):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", PASSPHRASE)
        page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
    page.locator("#encryption-key-modal .close-modal-btn").first.click()
    _go(page, "vaults")
    page.click("#create-vault-btn")
    page.select_option("#vault-type", "zero_knowledge")
    page.fill("#vault-name", name)
    page.fill("#vault-desc", desc)
    if page.locator("#vault-label-group").is_visible():
        page.fill("#vault-label", label)
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden(timeout=15000)


@pytest.fixture
def world(admin):
    """An administrator with something of theirs in every section, a second person, and the markers to look for."""
    before = admin.get("/settings").json()
    admin.put("/settings", json={"sharing_enabled": True, "invite_enabled": True, "zero_knowledge_enabled": True})
    a = admin.create_user(role="admin")
    b = admin.create_user(role="user")
    c = admin.create_user(role="user", email=None)
    ca, cc = ApiClient(BASE_URL), ApiClient(BASE_URL)
    ca.login(a["_username"], a["_password"])
    cc.login(c["_username"], c["_password"])
    m = {"a_user": a["_username"], "a_email": f"{a['_username']}@example.com", "c_user": c["_username"],
         "vault": unique("AnaVault"), "favourite": unique("AnaFavourite"), "file": unique("ana-report") + ".txt",
         "note": unique("AnaNote"), "note_body": unique("AnaNoteBody"), "c_vault": unique("CarlShared"),
         "invitee": unique("anainvitee"), "zk_name": unique("AnaSecretZk"), "zk_desc": unique("AnaZkDesc"),
         "zk_label": unique("anazklabel")}
    v = ca.create_vault(name=m["vault"])
    fav = ca.create_vault(name=m["favourite"])
    ca.put(f"/vaults/{fav['id']}/favorite").raise_for_status()
    ca.get(f"/vaults/{fav['id']}").raise_for_status()
    ca.post(f"/vaults/{v['id']}/files", files=[("files", (m["file"], b"probe", "text/plain"))]).raise_for_status()
    ca.post("/notes", json={"title": m["note"], "body": m["note_body"]}).raise_for_status()
    tag = admin.post("/share-tags", json={"name": unique("replacetag"), "auto_enroll_new_users": True,
                                          "allowed_audiences": ["users"], "max_recipients_cap": 10}).json()
    ca.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                             "claim_audience": "users", "audience_user_ids": [c["id"]]}).raise_for_status()
    cv = cc.create_vault(name=m["c_vault"])
    cc.post("/shares", json={"vault_id": cv["id"], "tag_id": tag["id"], "target_type": "vault",
                             "claim_audience": "users", "audience_user_ids": [a["id"]]}).raise_for_status()
    ca.post("/invites", json={"username": m["invitee"], "email": f"{m['invitee']}@example.com",
                              "role": "user"}).raise_for_status()
    # A credential change held for a second administrator: the second reset link for one account within 14 days.
    ca.post(f"/users/{c['id']}/reset-link")
    held = ca.post(f"/users/{c['id']}/reset-link")
    yield {"a": a, "b": b, "c": c, "m": m, "admin": admin, "held_change": held.status_code}
    admin.put("/settings", json={k: before.get(k) for k in ("sharing_enabled", "invite_enabled",
                                                            "zero_knowledge_enabled", "session_timeout")
                                 if k in before})
    for u in (a, b, c):
        admin.delete_user(u["id"])


def _go_everywhere(page: Page, m: dict):
    """Through every section, as the administrator, and back to the dashboard with the zero-knowledge key unlocked."""
    _zero_knowledge_vault(page, m["zk_name"], m["zk_desc"], m["zk_label"])
    for section in ("vaults", "shared", "notes", "users", "temp-creds", "groups", "activity", "settings"):
        _go(page, section)
        if section == "vaults":
            card = page.locator(".vault-card", has_text=m["vault"]).locator(".vault-open")
            if card.count():
                card.first.click()
                page.wait_for_timeout(1500)
        if section == "notes":
            row = page.locator("#notes-list", has_text=m["note"])
            if row.count():
                row.locator("button", has_text=m["note"]).first.click()
                page.wait_for_timeout(800)
                # The note opened in a dialog, its text drawn there; closed again, so the next section can be opened.
                page.evaluate("() => { if (typeof closeModal === 'function') closeModal(); }")
                page.wait_for_timeout(300)
    _go(page, "dashboard")
    if page.evaluate("() => typeof zkUnlockAllVaults === 'function'"):
        page.evaluate("() => { zkUnlockAllVaults(); }")
        # Asked for the passphrase only when the key is locked again by now.
        try:
            expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
            page.fill("#confirm-modal-input", PASSPHRASE)
            page.click("#confirm-modal-confirm-btn")
        except AssertionError:
            pass
    page.wait_for_timeout(2500)


def _nothing_of_a_left(page: Page, world: dict):
    markers = list(world["m"].values())
    left = page.evaluate(FIND, markers)
    assert left["found"] == [], f"still in the page: {left['found']}"
    held = {k: v for k, v in left["stored"].items() if v}
    assert held == {}, f"still in the browser's storage: {held}"
    assert not any(k.endswith(":authToken") or k.endswith(":currentUser") for k in left["stored"]), left["stored"]
    # The next person on the same tab: none of it painted in any frame.
    page.evaluate(WATCH, markers)
    _sign_in(page, world["b"])
    page.wait_for_timeout(6000)
    assert page.evaluate("() => Array.from(new Set(window.__painted))") == []


@pytest.mark.parametrize("how", ["button", "ended_by_an_administrator", "run_out", "another_tab"])
def test_after_the_session_ends_the_page_is_new_and_holds_nothing_of_the_person(page: Page, world, how):
    admin, a = world["admin"], world["a"]
    if how == "run_out":
        admin.put("/settings", json={"session_timeout": 2})
    page.goto("/")
    _sign_in(page, a)
    if how == "run_out":
        admin.put("/settings", json={"session_timeout": 240})
    signed_in_at = time.time()
    _go_everywhere(page, world["m"])
    page.evaluate("() => { window.__oldPage = true; }")
    if how == "button":
        _sign_out_by_hand(page)
        replaced = _ended(page, 20)
    elif how == "ended_by_an_administrator":
        assert admin.post(f"/users/{a['id']}/terminate-sessions").status_code == 200
        page.evaluate("() => { if (typeof refreshNotifUnread === 'function') refreshNotifUnread(); }")
        replaced = _ended(page, 20)
        expect(page.locator("#login-error")).to_contain_text("Your session has ended")
    elif how == "run_out":
        # The token runs out two minutes after the sign-in; the page's next request (its minute's poll) is refused.
        replaced = _ended(page, max(30, 200 - (time.time() - signed_in_at)))
        expect(page.locator("#login-error")).to_contain_text("Your session has ended")
    else:
        other = page.context.new_page()
        other.goto("/")
        expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        _sign_out_by_hand(other)
        replaced = _ended(page, 20)
        expect(page.locator("#login-error")).to_contain_text("Signed out in another tab")
        other.close()
    _nothing_of_a_left(page, world)
    assert replaced, "the page was not replaced"


def test_the_reason_is_shown_once_and_a_sign_out_by_hand_gives_none(page: Page, admin):
    ana = admin.create_user(role="user")
    try:
        page.goto("/")
        _sign_in(page, ana)
        page.evaluate("() => { window.__oldPage = true; }")
        assert admin.post(f"/users/{ana['id']}/terminate-sessions").status_code == 200
        page.evaluate("() => { if (typeof refreshNotifUnread === 'function') refreshNotifUnread(); }")
        replaced = _ended(page, 20)
        note = page.locator("#login-error")
        assert replaced, "the page was not replaced"
        expect(note).to_have_text("Your session has ended. Sign in again.")
        assert note.get_attribute("role") == "alert"
        assert page.evaluate("() => sessionStorage.getItem('dv_signed_out_reason')") is None
        # Once: a reload shows none.
        page.reload()
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        expect(page.locator("#login-error")).to_be_hidden()
        # A sign-out by hand gives no reason.
        _sign_in(page, ana)
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        replaced = _ended(page, 20)
        expect(page.locator("#login-error")).to_be_hidden()
        assert replaced, "the page was not replaced"
    finally:
        admin.delete_user(ana["id"])


def test_a_request_on_its_way_when_the_session_ends_cannot_write_into_the_new_page(page: Page, admin):
    ana = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    names = [client.create_vault(name=unique("AnaHeld"))["name"] for _ in range(2)]
    try:
        page.goto("/")
        _sign_in(page, ana)
        page.wait_for_load_state("networkidle", timeout=15000)
        held = []
        page.route("**/vaults", lambda route: held.append((route, route.fetch())))
        # A dashboard refresh asks for her vaults; the answer is on its way when she signs out.
        page.evaluate("() => { loadDashboardStats(); }")
        for _ in range(100):
            if held:
                break
            page.wait_for_timeout(100)
        assert held, "the dashboard did not ask for the vaults"
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        replaced = _ended(page, 20)
        route, response = held[0]
        try:
            route.fulfill(response=response)
        except Exception:
            pass                                  # the request belonged to the page that is gone
        page.unroute("**/vaults")
        page.wait_for_timeout(1500)
        for name in names:
            expect(page.locator("body")).not_to_contain_text(name)
        expect(page.locator("#dashboard-vaults-count")).not_to_have_text(str(len(names)))
        assert replaced, "the page was not replaced"
    finally:
        admin.delete_user(ana["id"])


def test_an_unlocked_zero_knowledge_key_is_locked_for_the_next_sign_in(page: Page, admin):
    before = bool(admin.get("/settings").json().get("zero_knowledge_enabled", False))
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    ana = admin.create_user(role="user")
    try:
        page.goto("/")
        _sign_in(page, ana)
        _zero_knowledge_vault(page, unique("AnaLocked"), unique("desc"), unique("label"))
        assert page.evaluate("() => zkKeyUnlocked()") is True
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        replaced = _ended(page, 20)
        _sign_in(page, ana)
        assert page.evaluate("() => zkKeyUnlocked()") is False
        assert replaced, "the page was not replaced"
    finally:
        admin.delete_user(ana["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": before})
