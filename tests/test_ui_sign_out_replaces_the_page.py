"""After every end of a session the page is replaced, and nothing of the person stays in it (static/js/app.js logout).

An administrator goes through every section (a vault with a file, an unlocked zero-knowledge vault, a favourite,
shares both ways, a note, the users list, an invitation, a held credential change, the events, a notification,
the settings), and the session ends: by the Sign out button, ended by another administrator, or run out on its own
(a sign-out in one tab does not sign out the others on this line). The page is then a new one: none of the person's text is in the
document, nothing of theirs is in the browser's storage, and the next person signed in on the same tab never sees
any of it painted. The reason the session ended is on the sign-in screen once, and a sign-out by hand gives none.
A request still on its way when the session ended cannot write into the new page.

A sign-in with a second factor on a page that ended a session opens the app, signed in as that account. A download
under way when the session ends is stopped and saves nothing. The tab's name carries only the app's own reason code:
another page's text in it is never shown and never drops a session. A search address the next person did not bring
(Back after a sign-out) is never opened. A copied link to a search, opened signed out,
leaves the address on the sign-in screen and still opens after the sign-in. A late answer about the account after the
session ended stores nothing.
"""
import json
import time
from urllib.parse import urlparse

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

# Every node added to the page from now on is counted.
OBSERVE = r"""() => { window.__added = 0;
    new MutationObserver((rs) => { for (const r of rs) window.__added += r.addedNodes.length; })
      .observe(document.documentElement, { childList: true, subtree: true, characterData: true }); }"""


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


@pytest.mark.parametrize("how", ["button", "ended_by_an_administrator", "deactivated", "made_inactive", "run_out"])
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
    """The answer reaches the page after the session ended and before the page is replaced: the page does nothing
    with it (draws none of it, and does not go on to the next call it would have made with it)."""
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
        held = _hold(page, "**/vaults")
        # A dashboard refresh asks for her vaults; the answer is on its way when she signs out.
        page.evaluate("() => { loadDashboardStats(); }")
        _wait_until(page, lambda: held, 10, "the dashboard did not ask for the vaults")
        new_page = _hold_the_new_page(page)
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        _wait_until(page, lambda: new_page["held"], 10, "the page did not ask for its replacement")
        # The session has ended and the page is still here: the answer comes now.
        page.evaluate(OBSERVE)
        asked_after, answered = [], []
        page.on("request", lambda r: asked_after.append(urlparse(r.url).path))
        page.on("response", lambda r: answered.append(r.url) if urlparse(r.url).path == "/vaults" else None)
        page.unroute("**/vaults")
        _release(held)
        _wait_until(page, lambda: answered, 10, "the held answer never reached the page")
        page.wait_for_timeout(1000)
        assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
        assert page.evaluate("() => window.__added") == 0, "the answer drew into the page"
        assert _seen(page, names) == set(), "the answer is in the page"
        # With the answer, the dashboard asks next for the temporary credentials: the page went no further.
        assert [p for p in asked_after if p != "/"] == [], f"the page went on with the answer: {asked_after}"
        assert errors == [], errors
        _let_the_new_page_come(page, new_page)
        assert _ended(page, 20), "the page was not replaced"
        assert _seen(page, names) == set(), "the answer is in the new page"
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
# The page waiting for its replacement, the reason, a refusal before the app is shown, and Back.

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


def test_while_the_page_waits_for_its_replacement_it_holds_nothing(page: Page, ana):
    """The new page is kept from coming, so the page that waits for it stays and can be read."""
    page.goto("/")
    _sign_in(page, ana)
    _go(page, "notes")
    _go(page, "dashboard")
    assert {ana["m"]["vault"], ana["m"]["note"]} <= _seen(page, ana["m"].values()), "the control: not in the page"
    new_page = _hold_the_new_page(page)
    page.evaluate("() => { window.__oldPage = true; }")
    started = time.time()
    _sign_out_by_hand(page)
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    _wait_until(page, lambda: new_page["held"], 10, "the page did not ask for its replacement")
    assert time.time() - started < 6, "the page waited longer than the deletion may take"
    assert page.evaluate("() => window.__oldPage === true"), "the page went at once: nothing to read while it waits"
    assert _seen(page, ana["m"].values()) == set(), "the page waiting for its replacement holds the person"
    expect(page.locator("#dashboard-screen")).to_have_count(0)
    _let_the_new_page_come(page, new_page)
    assert _ended(page, 20), "the page was not replaced"


def test_a_reason_is_shown_as_text(page: Page):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.evaluate("() => sessionStorage.setItem('dv_signed_out_reason', '<b>bold</b> <img src=x onerror=alert(1)>')")
    page.reload()
    note = page.locator("#login-error")
    expect(note).to_have_text("<b>bold</b> <img src=x onerror=alert(1)>")
    assert note.locator("b, img").count() == 0
    assert page.evaluate("() => sessionStorage.getItem('dv_signed_out_reason')") is None


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


def _wait_until(page: Page, ready, seconds: float, what: str):
    """Wait until ``ready()`` (a check of what the test has seen) is true."""
    deadline = time.time() + seconds
    while not ready():
        assert time.time() < deadline, what
        page.wait_for_timeout(100)


def _hold_the_new_page(page: Page) -> dict:
    """Keep the page that waits for its replacement: the request for the new page (the app's own address, no query)
    is answered with No Content, so the browser stays on the page that asked, to be read and acted on. (A request held
    unanswered would keep it too, but the browser then answers nothing about a page whose navigation is on its way.)
    ``held`` lists the requests asked; ``_let_the_new_page_come`` replaces the page as the app does."""
    hold = {"held": []}

    def is_the_app(url: str) -> bool:
        u = urlparse(url)
        return u.path == "/" and not u.query

    def keep(route):
        if route.request.resource_type == "document":
            hold["held"].append(route.request.url)
            route.fulfill(status=204)
        else:
            route.continue_()

    hold["match"], hold["handler"] = is_the_app, keep
    page.route(is_the_app, keep)
    return hold


def _let_the_new_page_come(page: Page, hold: dict):
    """The replacement the page asked for, now let through (the notes it leaves for the new page are already
    written)."""
    page.unroute(hold["match"], hold["handler"])
    assert hold["held"], "the page never asked for its replacement"
    page.evaluate("() => { location.replace(location.pathname); }")


def test_an_answer_that_comes_after_the_sign_out_does_nothing_on_the_page(page: Page, admin):
    """A call on its way when the session ends (the storage figures of Settings): its answer, let through while the
    page waits for its replacement (the new page kept from coming), draws nothing and throws nothing."""
    boss = admin.create_user(role="admin")
    try:
        errors = []
        page.on("pageerror", lambda exc: errors.append(str(exc)))
        page.goto("/")
        _sign_in(page, boss)
        held = _hold(page, "**/storage/stats")
        _go(page, "settings")
        _wait_until(page, lambda: held, 10, "Settings did not ask for the storage figures")
        new_page = _hold_the_new_page(page)
        page.evaluate("() => { window.__oldPage = true; }")
        _sign_out_by_hand(page)
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
        _wait_until(page, lambda: new_page["held"], 10, "the page did not ask for its replacement")
        page.evaluate(OBSERVE)
        answered = []
        page.on("response", lambda r: answered.append(r.url) if "/storage/stats" in r.url else None)
        page.unroute("**/storage/stats")
        _release(held)
        _wait_until(page, lambda: answered, 10, "the held answer never reached the page")
        page.wait_for_timeout(1000)
        assert page.evaluate("() => window.__oldPage === true"), "the page went: the answer reached nothing to test"
        assert page.evaluate("() => window.__added") == 0, "the answer drew into the page"
        assert errors == [], errors
        _let_the_new_page_come(page, new_page)
        assert _ended(page, 20), "the page was not replaced"
    finally:
        admin.delete_user(boss["id"])


# ---------------------------------------------------------------------------------------------------------------
# A sign-in with a second factor on a page that ended a session, downloads, the tab's name, a hash, a late answer.

def _end_a_session_before_the_app_is_shown(page: Page, user: dict):
    """A stored session that is refused as the page starts: the page ends it before anything of the app is shown,
    and keeps its sign-in screen."""
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.evaluate("""(u) => {
        localStorage.setItem('authToken', 'x.y.z');
        localStorage.setItem('currentUser', JSON.stringify(u));
    }""", {"id": user["id"], "username": user["_username"], "role": user.get("role", "user")})
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.wait_for_function("() => _pageEnded === true", timeout=15000)
    page.evaluate("() => { window.__oldPage = true; }")


def _password_step(page: Page, user: dict):
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")


def _signed_in_as(page: Page, user: dict):
    """The new page shows the app, signed in as ``user`` (the account in the page and stored beside the token)."""
    page.wait_for_function("() => !window.__oldPage", timeout=15000)
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => currentUser && currentUser.username") == user["_username"]
    stored = page.evaluate("() => localStorage.getItem('currentUser')")
    assert stored and json.loads(stored)["username"] == user["_username"], stored


def test_a_sign_in_with_a_code_on_a_page_that_ended_a_session_opens_the_app(page: Page, admin):
    ana = admin.create_user(role="user")
    client = admin.clone_anonymous()
    client.login(ana["_username"], ana["_password"])
    secret, _codes = enroll_totp(ana, client)
    try:
        _end_a_session_before_the_app_is_shown(page, ana)
        _password_step(page, ana)
        expect(page.locator("#sf-code-input")).to_be_visible(timeout=10000)
        # The enrolment spent this step's code: the next one.
        page.fill("#sf-code-input", totp(secret, 1))
        page.get_by_role("button", name="Verify").click()
        _signed_in_as(page, ana)
    finally:
        admin.delete_user(ana["id"])


def test_a_required_enrolment_on_a_page_that_ended_a_session_opens_the_app(page: Page, admin):
    boss, boss_client, _secret, codes = enrolled_admin(admin)
    ana = admin.create_user(role="user")
    before = admin.get("/settings").json().get("mfa_mode") or "optional"

    def set_mode(mode):
        boss_client.put("/settings", json={"mfa_mode": mode}, headers={"X-Second-Factor": step_up_receipt(
            boss_client, action="account.second_factor", recovery_codes=codes)}).raise_for_status()
    try:
        set_mode("required")
        try:
            _end_a_session_before_the_app_is_shown(page, ana)
            _password_step(page, ana)
            expect(page.locator("#sf-enroll-secret")).to_be_visible(timeout=10000)
            secret = page.locator("#sf-enroll-secret").inner_text().strip()
            page.fill("#sf-enroll-code", totp(secret))
            page.get_by_role("button", name="Continue").click()
            expect(page.locator("#sf-ack-cb")).to_be_visible(timeout=10000)
            page.check("#sf-ack-cb")
            page.get_by_role("button", name="Finish and sign in").click()
            _signed_in_as(page, ana)
        finally:
            set_mode(before)
    finally:
        admin.delete_user(ana["id"])
        admin.delete_user(boss["id"])


def test_a_download_under_way_when_the_session_ends_saves_nothing(page: Page, ana):
    """The file's own request is on its way when she signs out: the page stops it, draws no download tray and
    saves nothing, while it waits for its replacement (kept) and after."""
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    vault = client.create_vault(name=unique("AnaDownloads"))
    name = unique("ana-download") + ".txt"
    client.post(f"/vaults/{vault['id']}/files",
                files=[("files", (name, b"hers alone\n" * 2000, "text/plain"))]).raise_for_status()
    errors, saved, failed = [], [], []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("download", lambda d: saved.append(d.suggested_filename))
    page.on("requestfailed", lambda r: failed.append(r.url) if r.url.endswith("/download") else None)
    page.goto("/")
    _sign_in(page, ana)
    _go(page, "vaults")
    page.click(f'.open-vault-btn[data-vault-id="{vault["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    held = _hold(page, "**/files/*/download")
    page.locator('button[data-action="download"]:visible').first.click()
    _wait_until(page, lambda: held, 10, "the download did not ask for the file")
    new_page = _hold_the_new_page(page)
    page.evaluate("() => { window.__oldPage = true; }")
    _sign_out_by_hand(page)
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    _wait_until(page, lambda: new_page["held"], 10, "the page did not ask for its replacement")
    page.unroute("**/files/*/download")
    _release(held)
    _wait_until(page, lambda: failed, 10, "the page did not stop the file's request")
    page.wait_for_timeout(1500)
    assert page.evaluate("() => window.__oldPage === true"), "the page went: nothing to read while it waits"
    expect(page.locator("#download-tray")).to_have_count(0)
    assert _seen(page, [name]) == set(), "the file's name is in the page"
    _let_the_new_page_come(page, new_page)
    assert _ended(page, 20), "the page was not replaced"
    page.wait_for_timeout(1000)
    expect(page.locator("#download-tray")).to_have_count(0)
    assert saved == [], f"saved after the sign-out: {saved}"
    assert errors == [], errors


FOREIGN_NAME = "dv-signed-out:<b>not ours</b> verify at https://example.invalid"


def test_a_name_another_page_gave_the_tab_never_drops_a_session_or_shows_its_text(page: Page, ana):
    page.goto("/")
    _sign_in(page, ana)
    page.evaluate("(n) => { window.name = n; }", FOREIGN_NAME)
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => currentUser && currentUser.username") == ana["_username"]
    assert page.evaluate("() => window.name") == ""
    assert _seen(page, ["not ours", "example.invalid"]) == set(), "the name's text is in the page"


def test_signed_out_the_tab_name_shows_only_the_apps_own_sentence(page: Page):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    # A text of another page: nothing shown.
    page.evaluate("(n) => { window.name = n; }", FOREIGN_NAME)
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-error")).to_be_hidden()
    assert _seen(page, ["not ours", "example.invalid"]) == set(), "the name's text is in the page"
    assert page.evaluate("() => window.name") == ""
    # The app's own code: its sentence, once.
    page.evaluate("() => { window.name = 'dv-signed-out:ended'; }")
    page.reload()
    expect(page.locator("#login-error")).to_have_text("Your session has ended. Sign in again.", timeout=15000)
    assert page.evaluate("() => window.name") == ""
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-error")).to_be_hidden()


def _activity_search_of(page: Page, term: str) -> list:
    """Where an Activity search for ``term`` is in the page: the address, the page itself, its filter chips and
    fields."""
    return page.evaluate("""(t) => {
        const at = [];
        if (location.hash.includes(t) || decodeURIComponent(location.hash).includes(t)) at.push('address');
        const section = document.getElementById('activity-section');
        if (section && section.classList.contains('active')) at.push('activity page');
        const chips = document.getElementById('act-chips');
        if (chips && (chips.textContent || '').includes(t)) at.push('chips');
        for (const el of document.querySelectorAll('#activity-section input'))
            if ((el.value || '').includes(t)) at.push('field:' + (el.id || el.name));
        return at;
    }""", term)


def test_back_after_a_sign_out_opens_no_search_of_the_person_for_the_next(page: Page, admin, anon):
    boss, other = admin.create_user(role="admin"), admin.create_user(role="admin")
    ghost = unique("ghostsearch")
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
        assert ghost in page.evaluate("() => decodeURIComponent(location.hash)"), "the control: no search in the address"
        page.evaluate("() => { window.__oldPage = true; }")
        page.evaluate("() => logout()")
        assert _ended(page, 20), "the page was not replaced"
        page.go_back()
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.wait_for_timeout(1000)
        assert page.evaluate("() => location.hash") == "", "Back brought the person's search into the address"
        _sign_in(page, other)
        page.wait_for_timeout(3000)
        assert _activity_search_of(page, ghost) == [], "the next administrator was shown the person's search"
    finally:
        admin.delete_user(boss["id"])
        admin.delete_user(other["id"])


def test_a_copied_link_to_a_search_opens_after_the_sign_in(page: Page, admin):
    boss = admin.create_user(role="admin")
    someone = unique("someone")
    try:
        page.set_viewport_size({"width": 1440, "height": 900})
        page.goto(f"/#activity?range=24h&user={someone}")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        assert page.evaluate("() => location.hash") == "", "the link stays in the address on the sign-in screen"
        _sign_in(page, boss)
        expect(page.locator("#activity-section")).to_be_visible(timeout=15000)
        expect(page.locator("#act-chips")).to_contain_text(someone, timeout=15000)
        assert f"user={someone}" in page.evaluate("() => location.hash")
    finally:
        admin.delete_user(boss["id"])


def test_a_late_account_answer_after_the_session_ended_stores_nothing(page: Page, ana):
    """The page starts with a stored session and asks who it belongs to; the session ends on that page before the
    answer comes: the answer stores nothing."""
    page.goto("/")
    _sign_in(page, ana)
    held = []

    def is_the_account(url: str) -> bool:
        return urlparse(url).path == "/users/me"

    page.route(is_the_account, lambda route: held.append(route))
    page.reload()
    _wait_until(page, lambda: held, 15, "the page did not ask for the account")
    # Every write to the browser's storage from now on is listed; a replacement the page would ask for is kept from
    # coming, so the list can be read whatever the page then does.
    new_page = _hold_the_new_page(page)
    page.evaluate("""() => {
        window.__written = [];
        const set = Storage.prototype.setItem;
        Storage.prototype.setItem = function (k, v) { window.__written.push(k); return set.call(this, k, v); };
        window.__oldPage = true;
        logout();
    }""")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    answered, failed = [], []
    page.on("response", lambda r: answered.append(r.status) if is_the_account(r.url) else None)
    page.on("requestfailed", lambda r: failed.append(r.failure) if is_the_account(r.url) else None)
    page.unroute(is_the_account)
    _release(held)
    _wait_until(page, lambda: answered, 10, f"the held answer never reached the page {failed}")
    assert answered == [200], answered
    page.wait_for_timeout(1500)
    assert page.evaluate("() => window.__oldPage === true"), "the page went: nothing to read"
    written = page.evaluate("() => window.__written")
    assert "currentUser" not in written and "userPermissions" not in written, f"the answer was stored: {written}"
    assert page.evaluate("() => localStorage.getItem('currentUser') || sessionStorage.getItem('currentUser')") is None
    assert page.evaluate("() => localStorage.getItem('authToken') || sessionStorage.getItem('authToken')") is None
    assert new_page["held"] == [], "the answer opened the app"
    expect(page.locator("#dashboard-screen")).to_have_count(0)


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
