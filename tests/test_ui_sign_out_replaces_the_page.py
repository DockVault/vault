"""After every end of a session the page is replaced, and nothing of the person stays in it (static/js/app.js logout).

An administrator goes through every section (a vault with a file, an unlocked zero-knowledge vault, a favourite,
shares both ways, a note, the users list, an invitation, a held credential change, the events, a notification,
the settings), and the session ends: by the Sign out button, ended by another administrator, run out on its own,
or signed out in another tab of the same browser. The page is then a new one: none of the person's text is in the
document, nothing of theirs is in the browser's storage, and the next person signed in on the same tab never sees
any of it painted. The reason the session ended is on the sign-in screen once, and a sign-out by hand gives none.
A request still on its way when the session ended cannot write into the new page.

On a page that ended a session, a two-factor sign-in still reaches the dashboard; a download under way is stopped
and saves nothing; a name another page gave the tab says nothing of its own and drops no session; an address the
load did not bring opens nothing for the next person, while a copied link still opens after the sign-in.
"""
import json
import time
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import psql
from _sf_helpers import enroll_totp, enrolled_admin, step_up_receipt, totp
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


def _seen(page: Page, markers) -> set:
    """The markers the page holds now (text, attributes, form values)."""
    return {f.split(":", 1)[1] for f in page.evaluate(FIND, list(markers))["found"]}


def _go_everywhere(page: Page, m: dict) -> set:
    """Through every section, as the administrator, and back to the dashboard with the zero-knowledge key unlocked.
    Returns the markers the page held on the way (the control: the checks after the sign-out look for what was
    really there)."""
    seen = set()
    _zero_knowledge_vault(page, m["zk_name"], m["zk_desc"], m["zk_label"])
    for section in ("vaults", "shared", "notes", "users", "temp-creds", "groups", "activity", "settings"):
        _go(page, section)
        seen |= _seen(page, m.values())
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
                seen |= _seen(page, m.values())
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
    return seen | _seen(page, m.values())


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


@pytest.mark.parametrize("how", ["button", "ended_by_an_administrator", "deactivated", "made_inactive", "run_out", "another_tab"])
def test_after_the_session_ends_the_page_is_new_and_holds_nothing_of_the_person(page: Page, world, how):
    admin, a = world["admin"], world["a"]
    if how == "run_out":
        admin.put("/settings", json={"session_timeout": 2})
    page.goto("/")
    _sign_in(page, a)
    if how == "run_out":
        admin.put("/settings", json={"session_timeout": 240})
    signed_in_at = time.time()
    seen = _go_everywhere(page, world["m"])
    # The control: every marker was in the page on the way, and the page still holds them when the session ends.
    assert set(world["m"].values()) - seen == set(), f"never in the page: {set(world['m'].values()) - seen}"
    assert {world["m"]["vault"], world["m"]["zk_name"]} <= _seen(page, world["m"].values())
    page.evaluate("() => { window.__oldPage = true; }")
    if how == "button":
        _sign_out_by_hand(page)
        replaced = _ended(page, 20)
    elif how == "ended_by_an_administrator":
        assert admin.post(f"/users/{a['id']}/terminate-sessions").status_code == 200
        page.evaluate("() => { if (typeof refreshNotifUnread === 'function') refreshNotifUnread(); }")
        replaced = _ended(page, 20)
        expect(page.locator("#login-error")).to_contain_text("Your session has ended")
    elif how == "deactivated":
        # An administrator's deactivation ends the account's sessions; the refusals that follow carry Clear-Site-Data,
        # which empties this tab's storage after the reason was put there: the reason still reaches the new page.
        assert admin.patch(f"/users/{a['id']}", json={"is_active": False}).status_code == 200
        page.evaluate("() => { if (typeof refreshNotifUnread === 'function') refreshNotifUnread(); }")
        replaced = _ended(page, 20)
        expect(page.locator("#login-error")).to_have_text("Your session has ended. Sign in again.")
    elif how == "made_inactive":
        # A refusal that names the account (403): its own sentence is the reason. Made inactive in the database, so
        # the session itself stays valid (an administrator's deactivation also ends the account's sessions, and the
        # page is then told its session has ended, as above).
        psql(f"UPDATE users SET is_active = false WHERE id = '{a['id']}'")
        page.evaluate("() => { if (typeof refreshNotifUnread === 'function') refreshNotifUnread(); }")
        replaced = _ended(page, 20)
        expect(page.locator("#login-error")).to_have_text("User account is inactive")
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
    """Her vaults' answer, on its way when she signs out, is let through while the page waits for its replacement:
    nothing of it is drawn or kept, and nothing throws; the new page holds none of it either."""
    ana = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    names = [client.create_vault(name=unique("AnaHeld"))["name"] for _ in range(2)]
    try:
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
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
        held_out = _hold(page, "**/auth/sign-out")         # the page waits for its sign-out meanwhile
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        page.evaluate("""() => { window.__added = 0;
            new MutationObserver((rs) => { for (const r of rs) window.__added += r.addedNodes.length; })
              .observe(document.body, { childList: true, subtree: true, characterData: true }); }""")
        route, response = held[0]
        route.fulfill(response=response)                    # answered before the route goes, which would drop it
        page.unroute("**/vaults")
        page.wait_for_timeout(2000)
        assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
        assert _seen(page, names) == set(), "her vaults are in the page"
        assert page.evaluate("() => window.__added") == 0, "the answer drew into the page"
        kept = page.evaluate("() => JSON.stringify(state.dashboardVaults || null)")
        assert not any(name in kept for name in names), f"the answer was kept by the page: {kept}"
        assert errors == [], errors
        page.unroute("**/auth/sign-out")
        _release(held_out)
        page.wait_for_function("() => !window.__oldPage", timeout=30000)
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        assert _seen(page, names) == set(), "her vaults are in the new page"
        expect(page.locator("#dashboard-vaults-count")).not_to_have_text(str(len(names)))
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


# ---------------------------------------------------------------------------------------------------------------
# The page waiting for its replacement, the sign-out request, and what the new page shows.

# Every painted frame on every document of the page from now on (the old one and those that replace it), reported to
# the test through window.__painted_seen (an exposed binding, which outlives the documents).
WATCH_ALL = r"""(() => {
  const markers = %s;
  const t0 = performance.now();
  const frame = () => {
    if (!document.body) { requestAnimationFrame(frame); return; }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) {
      const t = n.nodeValue || '';
      for (const m of markers) if (t.includes(m)) {
        const el = n.parentElement, r = el.getBoundingClientRect();
        if (el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) && r.width > 0 && r.height > 0)
          window.__painted_seen(m);
      }
    }
    if (performance.now() - t0 < 30000) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
})();"""


def _watch_every_document(page: Page, markers) -> list:
    painted = []
    page.expose_binding("__painted_seen", lambda source, m: painted.append(m))
    script = WATCH_ALL % json.dumps(list(markers))
    page.add_init_script(script)
    page.evaluate(script)
    return painted


def _sign_out_posts(page: Page) -> list:
    sent = []
    page.on("request", lambda r: sent.append(r.url) if r.method == "POST" and "/auth/sign-out" in r.url else None)
    return sent


@pytest.fixture
def ana(admin):
    """A person with a vault and a note of hers, and the markers to look for."""
    u = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(u["_username"], u["_password"])
    m = {"user": u["_username"], "vault": unique("AnaWaits"), "note": unique("AnaWaitNote")}
    client.create_vault(name=m["vault"])
    client.post("/notes", json={"title": m["note"], "body": unique("body")}).raise_for_status()
    u["m"] = m
    yield u
    admin.delete_user(u["id"])


def _hold(page: Page, pattern: str) -> list:
    """Hold every request to ``pattern``; the held routes are returned, to be released by the test."""
    held = []
    page.route(pattern, lambda route: held.append(route))
    return held


def _release(held: list):
    for route in held:
        try:
            route.continue_()
        except Exception:
            pass                                   # its page has gone


def test_while_the_page_waits_for_its_sign_out_it_holds_nothing_and_goes_at_the_latest_after_15_seconds(
        page: Page, ana):
    page.goto("/")
    _sign_in(page, ana)
    _go(page, "notes")
    _go(page, "dashboard")
    assert {ana["m"]["vault"], ana["m"]["note"]} <= _seen(page, ana["m"].values()), "the control: not in the page"
    sent = _sign_out_posts(page)
    held = _hold(page, "**/auth/sign-out")         # never answered
    page.evaluate("() => { window.__oldPage = true; }")
    started = time.time()
    _sign_out_by_hand(page)
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    for _ in range(3):
        page.wait_for_timeout(1000)
        assert page.evaluate("() => window.__oldPage === true"), "the page went before its sign-out was over"
        assert _seen(page, ana["m"].values()) == set(), "the page waiting for its replacement holds the person"
        expect(page.locator("#dashboard-screen")).to_have_count(0)
    page.wait_for_function("() => !window.__oldPage", timeout=30000)
    took = time.time() - started
    assert 13 <= took <= 25, f"replaced {took:.1f} s after the sign-out, not at the cap"
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.unroute("**/auth/sign-out")
    _release(held)
    assert len(sent) == 1, f"sign-out requests: {sent}"


def test_one_sign_out_request_and_a_reason_shown_as_text(page: Page, ana):
    page.goto("/")
    sent = _sign_out_posts(page)
    _sign_in(page, ana)
    page.evaluate("() => { window.__oldPage = true; }")
    _sign_out_by_hand(page)
    assert _ended(page, 20), "the page was not replaced"
    page.wait_for_timeout(1500)
    assert len(sent) == 1, f"sign-out requests: {sent}"
    # A reason is shown as text, never as markup.
    page.evaluate("() => sessionStorage.setItem('dv_signed_out_reason', '<b>bold</b> <img src=x onerror=alert(1)>')")
    page.reload()
    note = page.locator("#login-error")
    expect(note).to_have_text("<b>bold</b> <img src=x onerror=alert(1)>")
    assert note.locator("b, img").count() == 0


def test_a_sign_out_answered_during_the_next_sign_in_does_not_bring_the_old_page_back(page: Page, admin, ana):
    bob = admin.create_user(role="user")
    try:
        page.goto("/")
        _sign_in(page, ana)
        _go(page, "notes")
        _go(page, "dashboard")
        assert ana["m"]["vault"] in _seen(page, ana["m"].values()), "the control: her vault is not on the dashboard"
        held_out = _hold(page, "**/auth/sign-out")
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        # From the sign-out on: every frame of this page and of the pages that replace it.
        painted = _watch_every_document(page, list(ana["m"].values()))
        # The next person signs in on the page still waiting; the sign-out is answered while that sign-in loads.
        held_prefs = _hold(page, "**/users/me/preferences")
        page.fill("#username", bob["_username"])
        page.fill("#password", bob["_password"])
        page.click("#login-form button[type=submit]")
        page.wait_for_function("() => !window.__oldPage || (typeof authToken !== 'undefined' && !!authToken)",
                               timeout=15000)
        page.unroute("**/auth/sign-out")
        _release(held_out)
        page.wait_for_timeout(1000)
        page.unroute("**/users/me/preferences")
        _release(held_prefs)
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => !window.__oldPage"), "the app was shown on the page that ended the session"
        expect(page.locator("body")).to_contain_text(bob["_username"])
        page.wait_for_timeout(2000)
        assert sorted(set(painted)) == [], f"painted of the person before: {sorted(set(painted))}"
    finally:
        admin.delete_user(bob["id"])


def test_a_tab_whose_own_session_ended_shows_the_sign_in_screen_whatever_another_tab_stored(
        page: Page, admin, ana):
    bob = admin.create_user(role="user")
    try:
        page.goto("/")
        _sign_in(page, ana)
        held = _hold(page, "**/auth/sign-out")
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        # Meanwhile another tab of the browser signs in to another account.
        other = page.context.new_page()
        other.goto("/")
        _sign_in(other, bob)
        page.unroute("**/auth/sign-out")
        _release(held)
        page.wait_for_function("() => !window.__oldPage", timeout=30000)
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(2000)
        expect(page.locator("#dashboard-screen")).to_be_hidden()
        expect(page.locator("#login-error")).to_be_hidden()
        # The other tab's session is untouched.
        expect(other.locator("#dashboard-screen")).to_be_visible()
        other.reload()
        expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        other.close()
    finally:
        admin.delete_user(bob["id"])


def test_a_tab_told_of_a_sign_out_waits_for_the_server_before_it_is_replaced(page: Page, ana):
    page.goto("/")
    _sign_in(page, ana)
    other = page.context.new_page()
    other.goto("/")
    expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    # This tab finds the server not answering (a proxy's 502) when it is told.
    page.route("**/health", lambda route: route.fulfill(status=502, body="Bad Gateway"))
    page.evaluate("() => { window.__oldPage = true; }")
    _sign_out_by_hand(other)
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(7000)
    assert page.evaluate("() => window.__oldPage === true"), "replaced while the server did not answer"
    assert _seen(page, ana["m"].values()) == set()
    expect(page.locator("#dashboard-screen")).to_have_count(0)
    page.unroute("**/health")
    page.wait_for_function("() => !window.__oldPage", timeout=15000)
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-error")).to_contain_text("Signed out in another tab")
    other.close()


def test_a_session_refused_before_the_app_is_shown_says_why_and_the_page_stays(page: Page, ana):
    page.goto("/")
    _sign_in(page, ana)
    # The next load's session is refused while it starts, before the app is shown.
    page.route("**/temp-passcode-policy", lambda route: route.fulfill(
        status=401, content_type="application/json", body='{"detail": "Not authenticated"}'))
    loads = []
    page.on("load", lambda _p: loads.append(time.time()))
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-error")).to_have_text("Your session has ended. Sign in again.")
    page.wait_for_timeout(4000)
    assert len(loads) == 1, f"the page loaded {len(loads)} times"
    page.unroute("**/temp-passcode-policy")
    expect(page.locator("#dashboard-screen")).to_have_count(0)


def test_back_after_a_sign_out_shows_nothing_of_the_person(page: Page, admin, anon):
    boss = admin.create_user(role="admin")
    ghost = unique("ghostback")
    anon.post("/auth/login", json={"username": ghost, "password": "not-it-1"})
    try:
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("/")
        _sign_in(page, boss)
        toggle = page.locator("#mobile-nav-toggle")
        if toggle.is_visible():
            toggle.click()
        page.click('.sidebar-item[data-section="activity"]')
        expect(page.locator("#act-pager")).to_be_visible(timeout=15000)
        page.click("#act-filter-btn")
        page.fill("#act-fp-user", ghost)
        page.locator("#act-fp-user").press("Enter")
        page.click("#act-fp-done")
        page.locator("#activity-cards .act-card").first.click()
        expect(page.locator("#activity-event-modal")).to_be_visible(timeout=10000)
        assert page.evaluate("() => history.state && history.state.activityDetail") is True, "no history entry"
        assert ghost in _seen(page, [ghost]), "the control: the event is not in the page"
        page.evaluate("() => { window.__oldPage = true; }")
        page.evaluate("() => logout()")
        assert _ended(page, 20), "the page was not replaced"
        page.go_back()
        page.wait_for_timeout(3000)
        assert _seen(page, [ghost, boss["_username"]]) == set(), "Back showed the person"
        expect(page.locator("#dashboard-screen")).to_be_hidden()
    finally:
        admin.delete_user(boss["id"])


def test_an_answer_that_comes_after_the_sign_out_does_nothing_on_the_page(page: Page, admin):
    """A call on its way when the session ends (the storage figures of Settings): its answer, let through while the
    page waits for its replacement, draws nothing and throws nothing."""
    boss = admin.create_user(role="admin")
    try:
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto("/")
        _sign_in(page, boss)
        held = _hold(page, "**/storage/stats")
        _go(page, "settings")
        for _ in range(100):
            if held:
                break
            page.wait_for_timeout(100)
        assert held, "Settings did not ask for the storage figures"
        held_out = _hold(page, "**/auth/sign-out")         # the page waits for its sign-out meanwhile
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        page.evaluate("""() => { window.__added = 0;
            new MutationObserver((rs) => { for (const r of rs) window.__added += r.addedNodes.length; })
              .observe(document.body, { childList: true, subtree: true, characterData: true }); }""")
        page.unroute("**/storage/stats")
        _release(held)
        page.wait_for_timeout(1500)
        assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
        assert page.evaluate("() => window.__added") == 0, "the answer drew into the page"
        assert errors == [], errors
        page.unroute("**/auth/sign-out")
        _release(held_out)
    finally:
        admin.delete_user(boss["id"])


# ---------------------------------------------------------------------------------------------------------------
# A sign-in on a page that ended a session, downloads, the tab's name, the address, and late answers.

# Every painted frame of the sign-in screen on the documents that replace this one, reported through
# window.__sign_in_seen (an exposed binding, which outlives the documents).
WATCH_SIGN_IN = r"""(() => {
  const t0 = performance.now();
  const frame = () => {
    const s = document.getElementById('login-screen');
    if (s && s.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) {
      const r = s.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) window.__sign_in_seen(location.href);
    }
    if (performance.now() - t0 < 20000) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
})();"""


def _watch_sign_in_on_new_documents(page: Page) -> list:
    seen = []
    page.expose_binding("__sign_in_seen", lambda source, href: seen.append(href))
    page.add_init_script(WATCH_SIGN_IN)
    return seen


def _end_a_session_before_the_app_is_shown(page: Page, user):
    """A stored session the server refuses (a token it never issued): the page ends it as it starts, before the app
    is shown, and keeps its sign-in screen."""
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.evaluate("""(u) => { localStorage.setItem('authToken', 'x.y.z');
                               localStorage.setItem('currentUser', JSON.stringify(u)); }""",
                  {"id": user["id"], "username": user["_username"], "role": user.get("role", "user")})
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.wait_for_function("() => _pageEnded === true", timeout=15000)
    assert page.evaluate("() => localStorage.getItem('authToken')") is None


def _signed_in_on_a_new_page(page: Page, user, sign_in_seen: list):
    page.wait_for_function("() => !window.__oldPage", timeout=30000)
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => currentUser && currentUser.username") == user["_username"]
    stored = page.evaluate("() => JSON.parse(localStorage.getItem('currentUser') || 'null')")
    assert stored and stored.get("username") == user["_username"], stored
    page.wait_for_timeout(1500)
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert sign_in_seen == [], f"a sign-in screen was shown on the new page: {sign_in_seen}"


def test_a_two_factor_sign_in_on_a_page_that_ended_a_session_reaches_the_dashboard(page: Page, admin):
    """A person with an authenticator app signs in on a page that has just ended a session: after the code, the
    new page shows her dashboard, signed in as her, with no second sign-in screen in between."""
    ana = admin.create_user(role="user")
    client = admin.clone_anonymous()
    client.login(ana["_username"], ana["_password"])
    secret, _codes = enroll_totp(ana, client)
    try:
        _end_a_session_before_the_app_is_shown(page, ana)
        sign_in_seen = _watch_sign_in_on_new_documents(page)
        page.evaluate("() => { window.__oldPage = true; }")
        page.fill("#username", ana["_username"])
        page.fill("#password", ana["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#sf-code-input")).to_be_visible(timeout=10000)
        page.fill("#sf-code-input", totp(secret, 1))       # the confirm spent the current step
        page.click("#login-second-factor button")
        _signed_in_on_a_new_page(page, ana, sign_in_seen)
    finally:
        admin.delete_user(ana["id"])


def test_a_forced_enrolment_on_a_page_that_ended_a_session_reaches_the_dashboard(page: Page, admin):
    """The organisation requires a second factor of this person, who has none yet: she sets it up on the sign-in
    screen of a page that has just ended a session, and the new page shows her dashboard, signed in as her."""
    ta, c, _secret, codes = enrolled_admin(admin)
    ana = admin.create_user(role="user")
    before = list(admin.get("/settings").json().get("mfa_required_user_ids") or [])

    def _require(ids):
        c.put("/settings", json={"mfa_required_user_ids": ids},
              headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                          recovery_codes=codes)}).raise_for_status()
    try:
        _require(before + [ana["id"]])
        try:
            _end_a_session_before_the_app_is_shown(page, ana)
            sign_in_seen = _watch_sign_in_on_new_documents(page)
            page.evaluate("() => { window.__oldPage = true; }")
            page.fill("#username", ana["_username"])
            page.fill("#password", ana["_password"])
            page.click("#login-form button[type=submit]")
            expect(page.locator("#sf-enroll-secret")).to_be_visible(timeout=10000)
            secret = page.locator("#sf-enroll-secret").inner_text().strip()
            page.fill("#sf-enroll-code", totp(secret))
            page.get_by_role("button", name="Continue").click()
            expect(page.locator("#sf-ack-cb")).to_be_visible(timeout=10000)
            page.check("#sf-ack-cb")
            page.get_by_role("button", name="Finish and sign in").click()
            _signed_in_on_a_new_page(page, ana, sign_in_seen)
        finally:
            _require(before)
    finally:
        admin.delete_user(ana["id"])
        admin.delete_user(ta["id"])


def _ana_with_a_file(ana, size=None):
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    vault = client.create_vault(name=unique("AnaFiles"))
    name = unique("ana-download") + ".bin"
    body = b"ana's file\n" if size is None else bytes((i * 7) % 251 for i in range(size))
    client.post(f"/vaults/{vault['id']}/files", files=[("files", (name, body, "application/octet-stream"))]
                ).raise_for_status()
    return vault, name


def _open_the_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    expect(page.locator('[data-action="download"]').first).to_be_visible(timeout=10000)


def _watch_downloads(page: Page) -> dict:
    seen = {"downloads": [], "errors": [], "failed": []}
    page.on("download", lambda d: seen["downloads"].append(d.suggested_filename))
    page.on("pageerror", lambda exc: seen["errors"].append(str(exc)))
    page.on("requestfailed", lambda r: seen["failed"].append(r.url) if "/download" in r.url else None)
    return seen


def test_a_download_waiting_for_its_answer_when_the_session_ends_saves_nothing(page: Page, ana):
    """She presses Download and signs out before the file's answer comes: the page stops the request, draws no
    download tray and saves nothing, even when the answer is let through while the page waits for its replacement."""
    vault, name = _ana_with_a_file(ana)
    seen = _watch_downloads(page)
    page.goto("/")
    _sign_in(page, ana)
    _open_the_vault(page, vault["id"])
    held = _hold(page, "**/files/*/download")
    page.locator('[data-action="download"]').first.click()
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(100)
    assert held, "the download was not asked for"
    held_out = _hold(page, "**/auth/sign-out")             # the page waits for its sign-out meanwhile
    page.evaluate("() => { window.__oldPage = true; }")
    _sign_out_by_hand(page)
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    refused = []
    for route in held:
        try:
            route.continue_()
        except Exception as exc:                            # the page stopped the request
            refused.append(str(exc))
    page.unroute("**/files/*/download")
    page.wait_for_timeout(3000)
    assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
    assert seen["failed"] or refused, "the download's request was not stopped by the page"
    expect(page.locator("#download-tray")).to_have_count(0)
    assert seen["downloads"] == [], f"saved after the sign-out: {seen['downloads']}"
    assert _seen(page, [name]) == set(), "the file's name is in the page"
    assert seen["errors"] == [], seen["errors"]
    page.unroute("**/auth/sign-out")
    _release(held_out)
    page.wait_for_function("() => !window.__oldPage", timeout=30000)
    page.wait_for_timeout(1000)
    assert seen["downloads"] == [], f"saved after the sign-out: {seen['downloads']}"


def test_a_download_still_reading_when_the_session_ends_saves_nothing(page: Page, ana):
    """A file is half read (the download tray counts its bytes, the file saved only once whole) when she signs out:
    the read stops, and nothing is saved, however fast the rest would come."""
    vault, name = _ana_with_a_file(ana, size=3 * 1024 * 1024)
    seen = _watch_downloads(page)
    page.goto("/")
    _sign_in(page, ana)
    _open_the_vault(page, vault["id"])
    page.evaluate("() => { state.downloadSink = 'buffered'; }")     # saved once whole
    cdp = page.context.new_cdp_session(page)
    cdp.send("Network.enable")
    cdp.send("Network.emulateNetworkConditions",
             {"offline": False, "latency": 0, "downloadThroughput": 128 * 1024, "uploadThroughput": -1})
    try:
        page.locator('[data-action="download"]').first.click()
        page.wait_for_function(r"""() => { const s = document.querySelector('#download-tray .dl-sub');
            return !!s && !/Downloading/.test(s.textContent) && !/100%/.test(s.textContent); }""", timeout=20000)
        held_out = _hold(page, "**/auth/sign-out")         # the page waits for its sign-out meanwhile
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    finally:
        # The rest of the file would now come at once.
        cdp.send("Network.emulateNetworkConditions",
                 {"offline": False, "latency": 0, "downloadThroughput": -1, "uploadThroughput": -1})
    page.wait_for_timeout(4000)
    assert page.evaluate("() => window.__oldPage === true"), "the page went: the read reached nothing to test"
    assert seen["failed"], "the download's read was not stopped by the page"
    expect(page.locator("#download-tray")).to_have_count(0)
    assert seen["downloads"] == [], f"saved after the sign-out: {seen['downloads']}"
    assert _seen(page, [name]) == set(), "the file's name is in the page"
    assert seen["errors"] == [], seen["errors"]
    page.unroute("**/auth/sign-out")
    _release(held_out)
    page.wait_for_function("() => !window.__oldPage", timeout=30000)
    page.wait_for_timeout(1000)
    assert seen["downloads"] == [], f"saved after the sign-out: {seen['downloads']}"


FOREIGN = "<b>not ours</b> verify at https://example.invalid"


def test_a_name_another_page_gave_the_tab_neither_shows_its_text_nor_drops_the_session(page: Page, ana):
    """Any page can name a tab. Signed out, a name in the app's own shape but with text of its own shows nothing,
    and one with a reason the app knows shows the app's own sentence, once. Signed in, no such name drops or hides
    the session; and the name is emptied as the page loads."""
    foreign = ["dv-signed-out:" + json.dumps({"c": FOREIGN, "t": True}),
               "dv-signed-out:" + json.dumps({"r": FOREIGN, "t": False})]
    known = "dv-signed-out:" + json.dumps({"c": "ended", "t": True})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    for name in foreign:
        page.evaluate("(n) => { window.name = n; }", name)
        page.reload()
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(500)
        expect(page.locator("#login-error")).to_be_hidden()
        assert _seen(page, ["not ours", "example.invalid"]) == set(), name
        assert page.evaluate("() => window.name") == ""
    page.evaluate("(n) => { window.name = n; }", known)
    page.reload()
    expect(page.locator("#login-error")).to_have_text("Your session has ended. Sign in again.", timeout=15000)
    assert page.evaluate("() => window.name") == ""
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(500)
    expect(page.locator("#login-error")).to_be_hidden()
    # Signed in: the session stays, whatever the tab's name says.
    _sign_in(page, ana)
    for name in foreign + [known]:
        page.evaluate("(n) => { window.name = n; }", name)
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => currentUser && currentUser.username") == ana["_username"], name
        assert _seen(page, ["not ours", "example.invalid"]) == set(), name
        assert page.evaluate("() => window.name") == ""
    expect(page.locator("#login-screen")).to_be_hidden()


def _activity_with_a_search(page: Page, term: str):
    toggle = page.locator("#mobile-nav-toggle")
    if toggle.is_visible():
        toggle.click()
    page.click('.sidebar-item[data-section="activity"]')
    expect(page.locator("#act-pager")).to_be_visible(timeout=15000)
    page.click("#act-filter-btn")
    page.fill("#act-fp-user", term)
    page.locator("#act-fp-user").press("Enter")
    page.click("#act-fp-done")


def test_back_after_a_sign_out_opens_nothing_of_the_person_for_the_next_administrator(page: Page, admin, anon):
    """On a phone, an administrator searched the Activity page and opened an event, then signed out. Back brings
    an address with none of her search, and the next administrator who signs in on that page is not taken to her
    search: the Activity page does not open, and none of her terms are in its filters."""
    boss = admin.create_user(role="admin")
    other = admin.create_user(role="admin")
    ghost = unique("ghostback")
    anon.post("/auth/login", json={"username": ghost, "password": "not-it-1"})
    try:
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("/")
        _sign_in(page, boss)
        _activity_with_a_search(page, ghost)
        page.locator("#activity-cards .act-card").first.click()
        expect(page.locator("#activity-event-modal")).to_be_visible(timeout=10000)
        assert ghost in page.url, "the control: her search is not in the address"
        page.evaluate("() => { window.__oldPage = true; }")
        page.evaluate("() => logout()")
        assert _ended(page, 20), "the page was not replaced"
        page.go_back()
        page.wait_for_timeout(3000)
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => location.hash") == "", page.url
        assert ghost not in page.url, page.url
        page.fill("#username", other["_username"])
        page.fill("#password", other["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(2500)
        expect(page.locator("#activity-section")).to_be_hidden()
        assert ghost not in page.url, page.url
        chips = page.evaluate("() => (document.getElementById('act-chips') || {}).textContent || ''")
        assert ghost not in chips, chips
        fields = page.evaluate("""(t) => Array.from(document.querySelectorAll('input, textarea, select'))
                                       .filter((el) => (el.value || '').includes(t)).map((el) => el.id)""", ghost)
        assert fields == [], f"her search is in the fields {fields}"
    finally:
        admin.delete_user(boss["id"])
        admin.delete_user(other["id"])


def test_a_copied_link_to_an_activity_search_opens_after_the_sign_in_and_leaves_the_address_meanwhile(
        page: Page, admin, anon):
    """A link to an Activity search opened signed out: the sign-in screen shows with the search out of the
    address, and the administrator who signs in lands on that search."""
    boss = admin.create_user(role="admin")
    someone = unique("linkedsearch")
    anon.post("/auth/login", json={"username": someone, "password": "not-it-1"})
    try:
        page.goto(f"/#activity?range=24h&user={someone}")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(500)
        assert page.evaluate("() => location.hash") == "", page.url
        assert someone not in page.url, page.url
        _sign_in(page, boss)
        expect(page.locator("#activity-section")).to_be_visible(timeout=15000)
        expect(page.locator("#act-chips")).to_contain_text(someone, timeout=15000)
        assert page.evaluate("() => location.hash").startswith("#activity")
    finally:
        admin.delete_user(boss["id"])


def test_a_tab_told_of_a_sign_out_while_it_is_in_front_asks_for_the_sign_in_policy_at_once(page: Page, ana):
    """The tab in front and focused is told that another tab signed out: the page that replaces it asks for the
    sign-in screen's policy as it loads, without waiting to be shown or focused again."""
    page.goto("/")
    _sign_in(page, ana)
    other = page.context.new_page()
    other.goto("/")
    expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.bring_to_front()
    shown = []
    page.expose_binding("__shown_again", lambda source, kind: shown.append(kind))
    page.add_init_script("""(() => {
      window.addEventListener('focus', () => window.__shown_again('focus'));
      document.addEventListener('visibilitychange', () => window.__shown_again('visibility'));
    })();""")
    events = []
    page.on("framenavigated", lambda f: events.append(("nav", time.time())) if f == page.main_frame else None)
    page.on("request", lambda r: events.append(("policy", time.time()))
            if r.method == "GET" and r.url.endswith("/auth/policy") else None)
    page.evaluate("() => { window.__oldPage = true; }")
    other.evaluate("() => logout()")
    page.wait_for_function("() => !window.__oldPage", timeout=30000)
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-error")).to_contain_text("Signed out in another tab")
    page.wait_for_timeout(2500)
    assert page.evaluate("() => document.visibilityState === 'visible' && document.hasFocus()"), \
        "the control: the tab is not the one in front"
    navs = [t for kind, t in events if kind == "nav"]
    assert navs, "the page was not replaced"
    asked = [t for kind, t in events if kind == "policy" and t >= navs[0]]
    assert shown == [], f"the new page was shown or focused again: {shown}"
    assert len(asked) >= 1, "the new page did not ask for the sign-in policy"
    other.close()


def test_an_answer_about_the_account_that_comes_after_the_session_ended_writes_nothing_back(page: Page, ana):
    """A page opening her stored session waits for her account's answer when another tab signs out: the answer,
    let through after that, stores nothing, and the sign-in screen keeps saying why."""
    page.goto("/")
    _sign_in(page, ana)
    held = []
    page.route("**/users/me", lambda route: held.append((route, route.fetch())))
    page.wait_for_timeout(500)
    held.clear()                                            # only the asking of the page that loads now
    page.reload()
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(100)
    assert held, "the page did not ask for the account"
    assert len(held) == 1, f"the page asked for the account {len(held)} times"
    page.evaluate("() => { window.__oldPage = true; }")
    other = page.context.new_page()
    other.goto("/")
    expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _sign_out_by_hand(other)
    expect(page.locator("#login-error")).to_contain_text("Signed out in another tab", timeout=15000)
    assert page.evaluate("() => localStorage.getItem('currentUser')") is None
    route, response = held[0]
    route.fulfill(response=response)                        # answered before the route goes, which would drop it
    page.unroute("**/users/me")
    page.wait_for_timeout(3000)
    assert page.evaluate("() => localStorage.getItem('currentUser') || sessionStorage.getItem('currentUser')") is None
    assert page.evaluate("() => currentUser") is None
    assert page.evaluate("() => window.__oldPage === true"), "the page was replaced"
    expect(page.locator("#login-screen")).to_be_visible()
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    expect(page.locator("#login-error")).to_have_text("Signed out in another tab.")
    other.close()


def test_the_next_sign_in_on_the_waiting_page_is_not_cut_off_by_its_replacement(page: Page, admin, ana):
    """The next person signs in on the page waiting for its sign-out, and the sign-out is answered while that
    sign-in is on its way: the page stays until the sign-in ends, and then a new page shows their dashboard."""
    bob = admin.create_user(role="user")
    try:
        page.goto("/")
        _sign_in(page, ana)
        held_out = _hold(page, "**/auth/sign-out")
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        held_in = _hold(page, "**/auth/login")
        page.fill("#username", bob["_username"])
        page.fill("#password", bob["_password"])
        page.click("#login-form button[type=submit]")
        for _ in range(100):
            if held_in:
                break
            page.wait_for_timeout(100)
        assert held_in, "the sign-in was not sent"
        page.unroute("**/auth/sign-out")
        _release(held_out)
        page.wait_for_timeout(4000)
        assert page.evaluate("() => window.__oldPage === true"), "the page was replaced during the sign-in"
        page.unroute("**/auth/login")
        _release(held_in)
        page.wait_for_function("() => !window.__oldPage", timeout=30000)
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => currentUser && currentUser.username") == bob["_username"]
        assert _seen(page, ana["m"].values()) == set()
    finally:
        admin.delete_user(bob["id"])


def test_a_failed_sign_in_on_the_waiting_page_lets_it_go_with_the_failure_as_its_reason(page: Page, admin, anon,
                                                                                            ana):
    """The next person mistypes the password on the page waiting for its sign-out: once the sign-in has failed the
    page is replaced, and the new page says why the sign-in failed."""
    bob = admin.create_user(role="user")
    said = anon.post("/auth/login", json={"username": unique("nobody"), "password": "not-it-1"}).json()["detail"]
    try:
        page.goto("/")
        _sign_in(page, ana)
        held_out = _hold(page, "**/auth/sign-out")
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        held_in = _hold(page, "**/auth/login")
        page.fill("#username", bob["_username"])
        page.fill("#password", "not-the-password-1")
        page.click("#login-form button[type=submit]")
        for _ in range(100):
            if held_in:
                break
            page.wait_for_timeout(100)
        assert held_in, "the sign-in was not sent"
        page.unroute("**/auth/sign-out")
        _release(held_out)
        page.wait_for_timeout(4000)
        assert page.evaluate("() => window.__oldPage === true"), "the page was replaced during the sign-in"
        page.unroute("**/auth/login")
        _release(held_in)
        page.wait_for_function("() => !window.__oldPage", timeout=30000)
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        expect(page.locator("#login-error")).to_have_text(said)
        expect(page.locator("#dashboard-screen")).to_be_hidden()
    finally:
        admin.delete_user(bob["id"])


def test_a_search_brought_back_by_history_within_the_signed_out_page_is_dropped_and_never_opened(page: Page, admin):
    """Back or Forward within the signed-out page itself (what Chromium can do after the page that ended a session was
    replaced, to an entry that page left): the search leaves the address at once, and the administrator who signs in
    next gets no Activity search opened."""
    boss = admin.create_user(role="admin")
    ghost = unique("historyghost")
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.evaluate("""(term) => new Promise((done) => {
            history.pushState(null, '', '/#activity?range=24h&user=' + term);
            history.back();
            setTimeout(() => { history.forward(); setTimeout(done, 600); }, 600);
        })""", ghost)
        assert page.evaluate("() => location.hash") == "", "the search stayed in the address"
        _sign_in(page, boss)
        page.wait_for_timeout(1500)
        assert ghost not in page.evaluate("() => location.href")
        expect(page.locator("#activity-section")).to_be_hidden()
        assert _seen(page, [ghost]) == set(), "the search was opened for the next person"
    finally:
        admin.delete_user(boss["id"])



# ---------------------------------------------------------------------------------------------------------------
# The page's own history entries, a copied link across a reload, the back-and-forward cache, and a session's late
# answers.

def _where_the_search_is(page: Page, term: str) -> list:
    """Where a person would see the search for ``term``: the address, the Activity filters' chips, any field."""
    return page.evaluate("""(t) => {
        const out = [];
        if (location.href.includes(t)) out.push('address');
        const chips = document.getElementById('act-chips');
        if (chips && (chips.textContent || '').includes(t)) out.push('chips');
        for (const el of document.querySelectorAll('input, textarea, select'))
            if ((el.value || '').includes(t)) out.push('field ' + (el.id || el.name || el.tagName));
        return out;
    }""", term)


def _open_activity(page: Page):
    toggle = page.locator("#mobile-nav-toggle")
    if toggle.is_visible():
        toggle.click()
    page.click('.sidebar-item[data-section="activity"]')
    expect(page.locator("#act-pager")).to_be_visible(timeout=15000)
    page.wait_for_timeout(1500)


def _hold_get(page: Page, pattern: str) -> list:
    """Hold every GET to ``pattern`` (anything else goes through); the held routes are returned."""
    held = []

    def hold(route):
        if route.request.method == "GET":
            held.append(route)
        else:
            route.continue_()
    page.route(pattern, hold)
    return held


def _wait_held(page: Page, held: list, what: str):
    for _ in range(150):
        if held:
            return
        page.wait_for_timeout(100)
    raise AssertionError(f"{what} was not asked for")


def test_back_and_forward_after_the_next_administrator_signed_in_bring_back_no_earlier_search(
        page: Page, admin, anon):
    """On a phone, an administrator searched the Activity page for a person, opened an event and signed out. The
    next administrator signs in on the new page and then presses Back and Forward: at every step the address holds
    none of the earlier search, the Activity page shows none of it, and neither does a reload."""
    boss = admin.create_user(role="admin")
    other = admin.create_user(role="admin")
    ghost = unique("nextghost")
    anon.post("/auth/login", json={"username": ghost, "password": "not-it-1"})
    try:
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("/")
        _sign_in(page, boss)
        _activity_with_a_search(page, ghost)
        page.locator("#activity-cards .act-card").first.click()
        expect(page.locator("#activity-event-modal")).to_be_visible(timeout=10000)
        assert ghost in page.url, "the control: her search is not in the address"
        page.evaluate("() => { window.__oldPage = true; }")
        page.evaluate("() => logout()")
        assert _ended(page, 20), "the page was not replaced"
        _sign_in(page, other)
        page.wait_for_timeout(1500)
        # Chromium steps within the new page here, to the entries the page that ended the session left.
        for step in (page.go_back, page.go_forward, page.go_back):
            step()
            page.wait_for_timeout(2000)
            expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
            assert page.evaluate("() => location.hash") == "", page.url
            assert ghost not in page.url, page.url
        _open_activity(page)
        assert _where_the_search_is(page, ghost) == [], "the earlier search is on the Activity page"
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(2500)
        assert _where_the_search_is(page, ghost) == [], "a reload opened the earlier search"
    finally:
        admin.delete_user(boss["id"])
        admin.delete_user(other["id"])


def test_a_search_on_an_entry_this_page_did_not_write_leaves_the_address_while_signed_in(page: Page, admin, anon):
    """Signed in, Back and Forward reach an entry with an Activity search that this page never wrote (one an earlier
    page left): the search leaves the address at once, and opening the Activity page shows none of it. The page's
    own entries keep theirs: a search of her own, and the event she opened and closed with Back."""
    boss = admin.create_user(role="admin")
    ghost = unique("entryghost")
    mine = unique("ownsearch")
    anon.post("/auth/login", json={"username": mine, "password": "not-it-1"})
    try:
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto("/")
        _sign_in(page, boss)
        page.evaluate("""(term) => new Promise((done) => {
            history.pushState(null, '', '/#activity?range=24h&user=' + term);
            history.back();
            setTimeout(() => { history.forward(); setTimeout(done, 600); }, 600);
        })""", ghost)
        assert page.evaluate("() => location.hash") == "", "the search stayed in the address"
        _open_activity(page)
        assert _where_the_search_is(page, ghost) == [], "the search was opened"
        # The page's own entries: her search, and an event's view pushed over it, closed by Back.
        _activity_with_a_search(page, mine)
        page.locator("#activity-cards .act-card").first.click()
        expect(page.locator("#activity-event-modal")).to_be_visible(timeout=10000)
        assert page.evaluate("() => !!(history.state && history.state.activityDetail)"), "no entry for the event"
        page.evaluate("() => new Promise((done) => { history.back(); setTimeout(done, 800); })")
        expect(page.locator("#activity-event-modal")).to_be_hidden(timeout=5000)
        assert mine in page.evaluate("() => location.hash"), page.url
        page.evaluate("() => new Promise((done) => { history.forward(); setTimeout(done, 800); })")
        assert mine in page.evaluate("() => location.hash"), page.url
        page.evaluate("() => new Promise((done) => { history.back(); setTimeout(done, 800); })")
        assert mine in page.evaluate("() => location.hash"), page.url
        expect(page.locator("#act-chips")).to_contain_text(mine)
    finally:
        admin.delete_user(boss["id"])


def test_a_copied_link_opens_after_a_sign_in_that_reloads_for_the_accounts_saved_look(page: Page, admin, anon):
    """The administrator's account keeps another look (the Classic skin) than this browser shows: the sign-in loads
    the page again to apply it, and the copied link to an Activity search opened before signing in still opens."""
    boss = admin.create_user(role="admin")
    client = ApiClient(BASE_URL)
    client.login(boss["_username"], boss["_password"])
    client.put("/users/me/preferences", json={"ui": "v1"}).raise_for_status()
    someone = unique("skinlink")
    anon.post("/auth/login", json={"username": someone, "password": "not-it-1"})
    try:
        loads = []
        page.on("load", lambda _p: loads.append(time.time()))
        page.goto(f"/#activity?range=24h&user={someone}")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => localStorage.getItem('ui')") != "v1", "the control: the browser has the skin"
        page.fill("#username", boss["_username"])
        page.fill("#password", boss["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#activity-section")).to_be_visible(timeout=20000)
        expect(page.locator("#act-chips")).to_contain_text(someone, timeout=15000)
        assert page.evaluate("() => localStorage.getItem('ui')") == "v1"
        assert len(loads) >= 2, "the control: the sign-in did not load the page again"
    finally:
        admin.delete_user(boss["id"])


@pytest.mark.parametrize("kind", ["reset", "invitation"])
def test_a_reset_or_invitation_page_brought_back_from_the_cache_is_loaded_again_without_its_form(
        page: Page, admin, kind):
    """A password-reset or invitation page shown again from the browser's back-and-forward cache, with no session:
    it is loaded again as the sign-in screen, and neither the form nor its link's token is in the page."""
    before = admin.get("/settings").json()
    keys = ("invite_enabled", "email_requirement", "signup_email_domain_mode")
    user = None
    try:
        if kind == "reset":
            user = admin.create_user(role="user", email=None)
            r = admin.post(f"/users/{user['id']}/reset-link")
            assert r.status_code == 200, r.text
            token = r.json()["reset_link"].split("?reset=", 1)[1]
            page.goto(f"/?reset={token}")
            screen, body = "#reset-screen", "#reset-card-body"
        else:
            admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional",
                                         "signup_email_domain_mode": "off"})
            r = admin.post("/invites", json={"username": unique("cacheinv").replace("_", ""), "role": "user"})
            assert r.status_code == 200, r.text
            token = r.json()["token"]
            page.goto(f"/?invite={token}")
            screen, body = "#invite-screen", "#invite-card-body"
        expect(page.locator(screen)).to_be_visible(timeout=10000)
        expect(page.locator(f"{body} input[type=password]")).to_be_visible(timeout=10000)
        page.evaluate("() => { window.__oldPage = true; }")
        page.evaluate("""() => { setTimeout(() => window.dispatchEvent(
            new PageTransitionEvent('pageshow', { persisted: true })), 0); }""")
        page.wait_for_function("() => !window.__oldPage && document.readyState === 'complete'", timeout=15000)
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        expect(page.locator(screen)).to_be_hidden()
        expect(page.locator(f"{body} input[type=password]")).to_have_count(0)
        assert token not in page.url, page.url
        assert _seen(page, [token]) == set(), "the link's token is in the page"
    finally:
        if user:
            admin.delete_user(user["id"])
        if kind == "invitation":
            admin.put("/settings", json={k: before.get(k) for k in keys if k in before})


def test_a_session_stored_without_its_account_opens_the_app(page: Page, ana):
    """The browser holds a session's token but not the account stored beside it (as a two-factor sign-in on an ended
    page can leave it): the page asks for the account itself and opens the app."""
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.evaluate("(t) => { localStorage.setItem('authToken', t); localStorage.removeItem('currentUser'); }",
                  client.token)
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => currentUser && currentUser.username") == ana["_username"]
    stored = page.evaluate("() => JSON.parse(localStorage.getItem('currentUser') || 'null')")
    assert stored and stored.get("username") == ana["_username"], stored


def test_a_two_factor_sign_in_on_a_page_that_ended_a_session_stores_the_account_before_the_page_goes(
        page: Page, admin):
    """On a page that ended a session, the two-factor sign-in stores the account beside its token before it hands
    over to a new page: kept on the old page (the new page's load is answered with nothing), the browser holds both."""
    ana = admin.create_user(role="user")
    client = admin.clone_anonymous()
    client.login(ana["_username"], ana["_password"])
    secret, _codes = enroll_totp(ana, client)
    try:
        _end_a_session_before_the_app_is_shown(page, ana)
        assert page.evaluate("() => localStorage.getItem('currentUser')") is None
        page.evaluate("() => { window.__oldPage = true; }")
        asked = []

        def no_new_page(route):
            if route.request.resource_type == "document":
                asked.append(route.request.url)
                route.fulfill(status=204)
            else:
                route.continue_()

        def the_page(url):
            return urlsplit(url).path == "/" and not urlsplit(url).query
        page.route(the_page, no_new_page)
        page.fill("#username", ana["_username"])
        page.fill("#password", ana["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#sf-code-input")).to_be_visible(timeout=10000)
        page.fill("#sf-code-input", totp(secret, 1))
        page.click("#login-second-factor button")
        for _ in range(150):
            if asked:
                break
            page.wait_for_timeout(100)
        assert asked, "the sign-in did not hand over to a new page"
        page.wait_for_timeout(500)
        assert page.evaluate("() => window.__oldPage === true"), "the old page went: nothing to read"
        assert page.evaluate("() => !!localStorage.getItem('authToken')")
        stored = page.evaluate("() => JSON.parse(localStorage.getItem('currentUser') || 'null')")
        assert stored and stored.get("username") == ana["_username"], stored
        page.unroute(the_page)
    finally:
        admin.delete_user(ana["id"])


def test_permissions_answered_after_the_session_ended_on_a_starting_page_are_not_kept(page: Page, ana):
    """A page opening her stored session waits for her permissions when the session ends: the answer, let through
    after that, is not kept in the browser."""
    page.goto("/")
    _sign_in(page, ana)
    assert page.evaluate("() => localStorage.getItem('userPermissions')") is not None, \
        "the control: her permissions are not kept after a sign-in"
    held = _hold(page, "**/permissions/users/**")
    page.reload()
    _wait_held(page, held, "her permissions")
    held_out = _hold(page, "**/auth/sign-out")             # her session stays valid on the server meanwhile
    page.evaluate("() => { window.__oldPage = true; }")
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => localStorage.getItem('userPermissions')") is None
    answered = []
    page.on("response", lambda r: answered.append(r.status) if "/permissions/users/" in r.url else None)
    page.unroute("**/permissions/users/**")
    _release(held)
    page.wait_for_timeout(2500)
    assert answered == [200], f"the control: the permissions were answered {answered}"
    assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
    kept = page.evaluate("() => localStorage.getItem('userPermissions') || sessionStorage.getItem('userPermissions')")
    assert kept is None, f"her permissions were kept: {kept}"
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    page.unroute("**/auth/sign-out")
    _release(held_out)


LOOK = """() => [localStorage.getItem('theme'), localStorage.getItem('accent'),
                 document.documentElement.getAttribute('data-theme'),
                 document.documentElement.getAttribute('data-accent')]"""


def test_preferences_answered_after_the_session_ended_on_a_starting_page_are_not_applied(page: Page, ana):
    """A page opening her stored session waits for her saved look when the session ends: the answer, let through
    after that, is neither kept nor applied."""
    page.goto("/")
    _sign_in(page, ana)
    before = page.evaluate(LOOK)
    assert "dark" not in before and "rose" not in before, f"the control: the browser has her look already {before}"
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    client.put("/users/me/preferences", json={"theme": "dark", "accent": "rose"}).raise_for_status()
    held = _hold_get(page, "**/users/me/preferences")
    page.reload()
    _wait_held(page, held, "her saved look")
    held_out = _hold(page, "**/auth/sign-out")             # her session stays valid on the server meanwhile
    page.evaluate("() => { window.__oldPage = true; }")
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    after_sign_out = page.evaluate(LOOK)
    answered = []
    page.on("response", lambda r: answered.append(r.status)
            if r.url.endswith("/users/me/preferences") and r.request.method == "GET" else None)
    page.unroute("**/users/me/preferences")
    _release(held)
    page.wait_for_timeout(2500)
    assert answered == [200], f"the control: her look was answered {answered}"
    assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
    assert page.evaluate("() => state.userPreferences") is None, "her saved look was kept"
    assert page.evaluate(LOOK) == after_sign_out, "her saved look was applied"
    page.unroute("**/auth/sign-out")
    _release(held_out)


def test_a_copied_link_opens_after_a_two_factor_sign_in(page: Page, admin, anon):
    """A link to an Activity search opened signed out, by an administrator who signs in with a password and a code
    from an authenticator app: the Activity page opens on that search."""
    ta, _client, secret, _codes = enrolled_admin(admin)
    someone = unique("twofactorlink")
    anon.post("/auth/login", json={"username": someone, "password": "not-it-1"})
    try:
        page.goto(f"/#activity?range=24h&user={someone}")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(500)
        assert page.evaluate("() => location.hash") == "", page.url
        page.fill("#username", ta["_username"])
        page.fill("#password", ta["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#sf-code-input")).to_be_visible(timeout=10000)
        page.fill("#sf-code-input", totp(secret, 1))
        page.click("#login-second-factor button")
        expect(page.locator("#activity-section")).to_be_visible(timeout=15000)
        expect(page.locator("#act-chips")).to_contain_text(someone, timeout=15000)
        assert page.evaluate("() => location.hash").startswith("#activity")
    finally:
        admin.delete_user(ta["id"])


def test_a_copied_link_pasted_into_the_sign_in_screen_opens_after_the_sign_in(page: Page, admin):
    """A link to an Activity search pasted into the address bar of a tab already on the sign-in screen (a link
    followed, not a step through history): it leaves the address meanwhile and opens once an administrator signs
    in."""
    boss = admin.create_user(role="admin")
    term = unique("pastedlink")
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.goto(f"/#activity?range=24h&user={term}")
        page.wait_for_timeout(500)
        assert page.evaluate("() => location.hash") == "", "the link stayed in the address on the sign-in screen"
        _sign_in(page, boss)
        expect(page.locator("#activity-section")).to_be_visible(timeout=15000)
        expect(page.locator("#act-chips")).to_contain_text(term, timeout=15000)
    finally:
        admin.delete_user(boss["id"])
