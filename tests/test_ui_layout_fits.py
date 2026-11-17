"""Tables keep their sort and their actions, and cards keep their notes and buttons inside, in both skins.

A remembered sort is kept by column id and survives the table being drawn again; a sort on a time column orders
the rows by their moments. The pending invitations sort and search like the other tables and leave a revoked
invitation out. The administrators' link tables keep each row's Revoke inside the table's scroll box on a laptop.
A Shared card's view-only note, and a drop vault card's buttons, stay inside their card. The dashboard's Recent
Events name each person with the person chip and each moment with the time element.
"""
import json
import time

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique
from _ui_hand_over import replaced

pytestmark = pytest.mark.ui

_MB = 1024 * 1024
SKINS = ["v1", "v2"]


def _login(page: Page, username: str, password: str, skin: str = None, size=None):
    if size:
        page.set_viewport_size({"width": size[0], "height": size[1]})
    page.goto("/")
    if skin:
        page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
        page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _section(page: Page, name: str):
    """Opens a section from the menu; on a phone the menu is a drawer, opened first and closed after."""
    drawer = page.locator("#mobile-nav-toggle")
    if drawer.is_visible():
        drawer.click()
        page.wait_for_timeout(300)
    page.click(f'.sidebar-item[data-section="{name}"]')
    expect(page.locator(f"#{name}-section")).to_be_visible(timeout=15000)
    if drawer.is_visible():
        page.wait_for_function("() => getComputedStyle(document.getElementById('sidebar')).visibility === 'hidden'", timeout=5000)
    page.wait_for_timeout(300)


def _sign_out(page: Page):
    # Back once the page has been replaced: a navigation started meanwhile would be cut short by the replacement.
    with replaced(page):
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")


def _row_order(page: Page, selector: str, ids):
    """The positions of the rows with these data ids among the rows the selector finds, in page order."""
    found = page.eval_on_selector_all(selector, "rows => rows.map(r => r.getAttribute('data-id') || r.getAttribute('data-invite-id'))")
    return [found.index(i) for i in ids]


# Whether every element the selector finds inside `host` lies within the host's visible box (its scroll box when
# it scrolls). Returns the ones that do not, and how many were measured.
INSIDE_JS = """([host, sel]) => {
  const h = typeof host === 'string' ? document.querySelector(host) : host;
  if (!h) return {count: 0, out: ['no host ' + host]};
  const b = h.getBoundingClientRect();
  const left = b.left + h.clientLeft, right = left + h.clientWidth;
  const out = [];
  const els = Array.from(h.querySelectorAll(sel)).filter(e => e.getClientRects().length);
  for (const e of els) {
    const r = e.getBoundingClientRect();
    if (r.left < left - 1 || r.right > right + 1) out.push(`${(e.textContent || '').trim().slice(0, 40)} ${Math.round(r.left)}..${Math.round(r.right)} not in ${Math.round(left)}..${Math.round(right)}`);
  }
  return {count: els.length, out};
}"""


@pytest.fixture
def no_saved_sort(admin):
    """The account starts with no remembered sort, and gets its own back."""
    before = admin.get("/users/me/preferences").json().get("tables")
    admin.put("/users/me/preferences", json={"tables": "{}"})
    try:
        yield
    finally:
        admin.put("/users/me/preferences", json={"tables": before if isinstance(before, str) and before else "{}"})


@pytest.fixture
def older_and_newer(admin):
    """Two accounts made a second apart, named so that their names sort the other way round from their ages."""
    older = admin.create_user(username="zzz" + unique("")[1:9], role="user")
    time.sleep(1.2)
    newer = admin.create_user(username="aaa" + unique("")[1:9], role="user")
    try:
        yield older, newer
    finally:
        admin.delete_user(older["id"])
        admin.delete_user(newer["id"])


def test_a_sort_on_a_time_column_is_kept_by_its_id_across_a_redraw(page: Page, admin, admin_creds, no_saved_sort, older_and_newer):
    older, newer = older_and_newer
    _login(page, admin_creds["username"], admin_creds["password"])
    _section(page, "users")
    table = page.locator("#users-list table")
    expect(table).to_be_visible(timeout=15000)
    rows = "#users-list tbody tr.exp-row"
    created = table.locator('thead th[data-col="created"]')
    created.click()
    expect(created).to_have_attribute("aria-sort", "ascending")
    a, b = _row_order(page, rows, [older["id"], newer["id"]])
    assert a < b, "ascending by Created puts the older account first, whatever the names say"
    created.click()
    expect(created).to_have_attribute("aria-sort", "descending")
    a, b = _row_order(page, rows, [older["id"], newer["id"]])
    assert b < a, "descending by Created puts the newer account first"
    # Remembered by the column's id, not its position.
    saved = json.loads(page.evaluate("() => localStorage.getItem('dv_tables') || '{}'"))
    assert saved.get("users") == {"col": "created", "dir": "desc"}, saved
    # Drawn again (leave and come back): still sorted by Created, newest first.
    _section(page, "dashboard")
    _section(page, "users")
    created = page.locator('#users-list table thead th[data-col="created"]')
    expect(created).to_have_attribute("aria-sort", "descending", timeout=15000)
    a, b = _row_order(page, rows, [older["id"], newer["id"]])
    assert b < a, "the redrawn table keeps the remembered order"


@pytest.fixture
def invitations(admin):
    keys = ("invite_enabled", "email_requirement", "signup_email_domain_mode")
    before = admin.get("/settings").json()
    admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional", "signup_email_domain_mode": "off"})
    made = []
    try:
        for prefix in ("zzz", "aaa", "rev"):
            r = admin.post("/invites", json={"username": prefix + unique("")[1:9], "role": "user"})
            assert r.status_code in (200, 201), r.text
            made.append(r.json())
        assert admin.delete(f"/invites/{made[2]['id']}").status_code in (200, 204)
        yield made
    finally:
        for inv in made:
            admin.delete(f"/invites/{inv['id']}")
        admin.put("/settings", json={k: before.get(k) for k in keys})


def test_the_invitations_table_sorts_searches_and_leaves_out_revoked(page: Page, admin_creds, invitations, no_saved_sort):
    late, early, revoked = invitations
    _login(page, admin_creds["username"], admin_creds["password"])
    _section(page, "users")
    table = page.locator("#invites-table")
    expect(table).to_be_visible(timeout=15000)
    expect(table.locator(f'.invite-row[data-invite-id="{late["id"]}"]')).to_be_visible()
    expect(table.locator(f'.invite-row[data-invite-id="{revoked["id"]}"]')).to_have_count(0)
    rows = "#invites-table tbody tr.invite-row"
    name = table.locator("thead th", has_text="Name")
    name.click()
    expect(name).to_have_attribute("aria-sort", "ascending")
    a, z = _row_order(page, rows, [early["id"], late["id"]])
    assert a < z
    name.click()
    expect(name).to_have_attribute("aria-sort", "descending")
    a, z = _row_order(page, rows, [early["id"], late["id"]])
    assert z < a
    # The search keeps only the rows holding every typed word.
    search = page.locator("#table-search-invites-table")
    expect(search).to_be_visible()
    search.fill(late["username"])
    expect(table.locator(f'.invite-row[data-invite-id="{late["id"]}"]')).to_be_visible()
    expect(table.locator(f'.invite-row[data-invite-id="{early["id"]}"]')).to_be_hidden()
    search.fill("")
    expect(table.locator(f'.invite-row[data-invite-id="{early["id"]}"]')).to_be_visible()


@pytest.fixture
def links_everywhere(admin):
    """One active note link, public file link and upload link, each with a long name, made by the test account."""
    keys = ("public_note_links_enabled", "public_file_links_enabled", "public_note_link_user_cap",
            "public_receivers_enabled", "public_receiver_user_cap")
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_note_links_enabled": True, "public_file_links_enabled": True,
                                 "public_note_link_user_cap": 100, "public_receivers_enabled": True,
                                 "public_receiver_user_cap": 50})
    vault = admin.create_vault(name=unique("Revoke within reach"))
    made = {}
    try:
        ltag = admin.post("/note-link-tags", json={"name": unique("A link type with a long name"), "auto_enroll_new_users": True,
                                                   "allowed_targets": ["note", "file", "folder"],
                                                   "default_ttl_hours": 24, "max_ttl_hours": 48})
        assert ltag.status_code in (200, 201), ltag.text
        note = admin.post("/notes", json={"title": "A note whose title runs on for quite a while " + unique("n"), "body": "x"}).json()
        nl = admin.post("/note-links", json={"note_id": note["id"], "tag_id": ltag.json()["id"]})
        assert nl.status_code in (200, 201), nl.text
        made["note"] = nl.json()
        name = "a-rather-long-file-name-for-the-revoke-check-" + unique("f") + ".txt"
        assert admin.post(f"/vaults/{vault['id']}/files", files=[("files", (name, b"x", "text/plain"))]).status_code in (200, 201)
        fid = next(f["id"] for f in admin.get(f"/vaults/{vault['id']}/files").json()["items"] if f["name"] == name)
        pl = admin.post("/public-links", json={"vault_id": vault["id"], "target_type": "file", "target_file_id": fid,
                                               "tag_id": ltag.json()["id"], "ttl_hours": 24})
        assert pl.status_code in (200, 201), pl.text
        made["file"] = pl.json()
        rtag = admin.post("/receiver-tags", json={"name": unique("An upload link type"), "min_token_len": 6, "require_secret": "none",
                                                  "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                                  "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
        rc = admin.post("/receivers", json={"tag_id": rtag["id"], "max_total_bytes": 10 * _MB, "ttl_hours": 24,
                                            "label": "An upload link with a long label " + unique("r")})
        assert rc.status_code in (200, 201), rc.text
        made["upload"] = rc.json()
        yield made
    finally:
        if "note" in made:
            admin.post(f"/note-links/{made['note']['id']}/revoke")
        if "file" in made:
            admin.post(f"/public-links/{made['file']['id']}/revoke")
        if "upload" in made:
            admin.post(f"/receivers/{made['upload']['id']}/revoke")
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={k: before.get(k) for k in keys})


@pytest.mark.parametrize("skin", SKINS)
@pytest.mark.parametrize("width", [1280, 1440])
def test_each_admin_link_tables_revoke_is_inside_its_scroll_box(page: Page, admin_creds, links_everywhere, skin, width):
    _login(page, admin_creds["username"], admin_creds["password"], skin, (width, 900))
    _section(page, "settings")
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
    problems = {}
    for tab, hosts in (("notelinks", ("#nl-admin-links", "#pfl-admin-links")), ("uploadlinks", ("#rc-admin-links",))):
        page.click(f'#settings-section .tab-btn[data-tab="{tab}"]')
        for host in hosts:
            expect(page.locator(f"{host} table.data-table tbody tr").first).to_be_visible(timeout=15000)
            page.locator(host).scroll_into_view_if_needed()
            got = page.evaluate(INSIDE_JS, [host, "tbody td:last-child button"])
            assert got["count"] > 0, f"{host}: no Revoke to measure"
            if got["out"]:
                problems[host] = got["out"]
    assert problems == {}, problems


@pytest.fixture
def view_only_shared(admin):
    """A sharer who shared a vault view-only, with an expiry, and the recipient who claimed it."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    tag = admin.post("/share-tags", json={"name": unique("fits"), "auto_enroll_new_users": True,
                                          "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10,
                                          "allow_view_only": True}).json()
    sharer = admin.create_user(role="user")
    recipient = admin.create_user(role="user")
    cs = ApiClient(BASE_URL); cs.login(sharer["_username"], sharer["_password"])
    cr = ApiClient(BASE_URL); cr.login(recipient["_username"], recipient["_password"])
    vault = cs.create_vault(name=unique("Quarterly figures"))
    share = cs.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
                                     "claim_audience": "anyone_internal", "view_only": True,
                                     "lifetime_minutes": 5 * 24 * 60})
    assert share.status_code == 200, share.text
    assert cr.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
    try:
        yield sharer, recipient, share.json()
    finally:
        cs.delete_vault(vault["id"])
        admin.delete_user(sharer["id"]); admin.delete_user(recipient["id"])
        admin.put("/settings", json={"sharing_enabled": before})


@pytest.mark.parametrize("skin", SKINS)
@pytest.mark.parametrize("size", [(390, 844), (1280, 900)], ids=["phone", "desktop"])
def test_the_shared_cards_keep_the_view_only_note_inside(page: Page, view_only_shared, skin, size):
    sharer, recipient, share = view_only_shared
    card = f'[data-share-id="{share["id"]}"]'
    _login(page, recipient["_username"], recipient["_password"], skin, size)
    _section(page, "shared")
    expect(page.locator(f"{card} .shared-view-only")).to_be_visible(timeout=15000)
    expect(page.locator(f"{card} .shared-view-only")).to_contain_text("View only (preview in the browser, no Download button)")
    got = page.evaluate(INSIDE_JS, [card, ".vault-meta > span"])
    assert got["count"] >= 3 and got["out"] == [], got   # Shared by, Expires, View only
    # The sharer's own card: its View only badge stays inside too.
    _sign_out(page)
    _login(page, sharer["_username"], sharer["_password"], skin, size)
    _section(page, "shared")
    page.click('[data-shared-tab="by-me"]')
    expect(page.locator(f"{card} .shared-view-only")).to_be_visible(timeout=15000)
    got = page.evaluate(INSIDE_JS, [card, ".vault-meta > span"])
    assert got["count"] >= 3 and got["out"] == [], got


@pytest.mark.parametrize("skin", SKINS)
def test_a_drop_vault_cards_buttons_stay_inside_it(page: Page, admin, admin_creds, skin):
    keys = ("public_receivers_enabled", "public_receiver_user_cap")
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    rec = None
    try:
        tag = admin.post("/receiver-tags", json={"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
                                                 "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                                 "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
        rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB,
                                             "label": unique("Drop"), "ttl_hours": 24}).json()
        _login(page, admin_creds["username"], admin_creds["password"], skin, (1280, 900))
        _section(page, "uploadlinks")
        page.click('button[data-rc-tab="vaults"]')
        card = page.locator(".rc-vault-card", has_text=rec["label"]).first
        expect(card).to_be_visible(timeout=15000)
        expect(card.locator("button.link-extend")).to_be_visible()
        got = page.evaluate(INSIDE_JS, [card.element_handle(), ".rc-vault-actions button"])
        assert got["count"] >= 4 and got["out"] == [], got   # Replace link, Extend, Open vault, Info
    finally:
        if rec:
            admin.post(f"/receivers/{rec['id']}/revoke")
        admin.put("/settings", json={k: before.get(k) for k in keys})


def test_recent_events_name_people_with_a_chip_and_a_time(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])   # signing in is itself an event
    feed = page.locator("#events-feed")
    expect(feed.locator(".event-item").first).to_be_visible(timeout=15000)
    expect(feed.locator(".event-item .event-user .person-chip").first).to_be_visible()
    expect(feed.locator(".event-item .event-time time.when").first).to_be_visible()
    # Every event carries its moment as a time element.
    assert feed.locator(".event-item").count() == feed.locator(".event-item .event-time time.when").count()
