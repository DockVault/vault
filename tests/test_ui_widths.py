"""The phone and tablet pass: every section of the signed-in app, both skins, at 390, 768 and 1024 pixels, as an
administrator, as a user and as a share recipient; every Settings page; nothing wider than the screen, no sideways
scroll, the dialogs on screen at every width; the public upload, file-link and note-link pages at phone width too,
each with an owner's message."""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui

WIDTHS = {"phone": (390, 844), "tablet": (768, 1024), "small-laptop": (1024, 768)}
ADMIN_SECTIONS = ["dashboard", "vaults", "shared", "notes", "uploadlinks", "temp-creds", "users", "groups",
                  "activity", "compliance", "settings"]
USER_SECTIONS = ["dashboard", "vaults", "shared", "notes", "temp-creds"]
SETTINGS_PAGES = ["general", "branding", "storage", "security", "accounts", "sftp", "sharing", "notelinks",
                  "uploadlinks", "email", "records", "logs"]
OWNER_MESSAGE = ("A message long enough to wrap on a phone screen, twice over, so that its box is tested: "
                 "averyveryverylongwordwithoutanyspacesinitatalltoseethatitbreaksinsteadofoverflowing.")

OVERFLOW_JS = """() => {
  const w = document.documentElement.clientWidth;
  const bad = [];
  const root = document.scrollingElement || document.documentElement;
  if (root.scrollWidth > w + 1) bad.push(`page scrollWidth ${root.scrollWidth} > ${w}`);
  const active = document.querySelector('.content-section.active') || document.getElementById('dashboard-screen');
  if (active) {
    for (const el of active.querySelectorAll('*')) {
      const r = el.getBoundingClientRect();
      if (r.width === 0) continue;
      const cs = getComputedStyle(el);
      if (cs.position === 'fixed') continue;
      if (r.right > w + 1 && !el.closest('[style*="overflow"], .tabs, .files-toolbar, table, .table-wrap, pre, .data-table, .act-table, .scroll-x')) {
        bad.push(`${el.tagName.toLowerCase()}#${el.id || ''}.${String(el.className).split(' ')[0]} right=${Math.round(r.right)}`);
        if (bad.length > 6) break;
      }
    }
  }
  return bad;
}"""


def _login(page: Page, user, skin, size):
    page.set_viewport_size({"width": size[0], "height": size[1]})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _go(page: Page, section):
    """Opens a section; False when its item is not in the menu (a feature switched off here)."""
    drawer = page.locator("#mobile-nav-toggle")
    if drawer.is_visible():
        drawer.click()
        page.wait_for_timeout(300)
    item = page.locator(f'.sidebar-item[data-section="{section}"]')
    if not item.is_visible():
        if drawer.is_visible():
            page.keyboard.press("Escape")
            page.wait_for_timeout(300)
        return False
    item.click()
    expect(page.locator(f"#{section}-section")).to_be_visible(timeout=15000)
    if drawer.is_visible():
        page.wait_for_function("() => getComputedStyle(document.getElementById('sidebar')).visibility === 'hidden'", timeout=5000)
    page.wait_for_timeout(500)
    return True


@pytest.fixture
def people(admin):
    """An administrator of the test's own, with a vault of their own (a vault is listed for its owner)."""
    a = admin.create_user(role="admin")
    u = admin.create_user(role="user")
    ca = ApiClient(); ca.login(a["_username"], a["_password"])
    v = ca.create_vault(name=unique("Wide"))
    ca.post(f"/vaults/{v['id']}/files", files=[("files", ("a-rather-long-file-name-for-the-width-pass.txt", b"x", "text/plain"))])
    try:
        yield a, u, v
    finally:
        ca.delete_vault(v["id"])
        admin.delete_user(a["id"]); admin.delete_user(u["id"])


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("width", list(WIDTHS))
def test_an_administrators_sections_fit_the_screen(page: Page, people, skin, width):
    a, _u, v = people
    _login(page, a, skin, WIDTHS[width])
    problems = {}
    for section in ADMIN_SECTIONS:
        if not _go(page, section):
            continue
        bad = page.evaluate(OVERFLOW_JS)
        if bad:
            problems[section] = bad
    # The open vault, both views, with a long file name.
    _go(page, "vaults")
    page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    expect(page.locator("#vault-files-table-body tr")).to_have_count(1, timeout=15000)
    page.wait_for_timeout(500)
    for view in ("table", "grid"):
        page.click(f'[data-files-view="{view}"]')
        page.wait_for_timeout(300)
        bad = page.evaluate(OVERFLOW_JS)
        if bad:
            problems[f"vault-{view}"] = bad
    assert problems == {}, problems


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("width", list(WIDTHS))
def test_a_users_sections_fit_the_screen(page: Page, people, skin, width):
    _a, u, _v = people
    _login(page, u, skin, WIDTHS[width])
    problems = {}
    for section in USER_SECTIONS:
        if not _go(page, section):
            continue
        bad = page.evaluate(OVERFLOW_JS)
        if bad:
            problems[section] = bad
    assert problems == {}, problems


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_main_dialogs_stay_on_a_phone_screen(page: Page, people, skin):
    a, _u, v = people
    _login(page, a, skin, WIDTHS["phone"])
    checks = []
    _go(page, "vaults")
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal.active")).to_be_visible()
    checks.append(("create-vault-modal", page.locator("#create-vault-modal .modal-content").bounding_box()))
    page.evaluate("() => closeModal()")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden()
    _go(page, "users")
    page.click("#create-user-btn")
    expect(page.locator("#create-user-modal.active")).to_be_visible()
    checks.append(("create-user-modal", page.locator("#create-user-modal .modal-content").bounding_box()))
    page.evaluate("() => closeModal()")
    expect(page.locator("#create-user-modal.active")).to_be_hidden()
    page.evaluate("() => SessionWatch.armAt(Date.now() + 90000) || SessionWatch.show()")
    page.evaluate("() => SessionWatch.show()")
    checks.append(("session-expiry-modal", page.locator("#session-expiry-modal .modal-content").bounding_box()))
    page.evaluate("() => SessionWatch.disarm()")
    bad = {name: box for name, box in checks if not box or box["x"] < 0 or box["x"] + box["width"] > 391}
    assert bad == {}, bad


def test_the_upload_page_fits_a_phone(page: Page, admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    try:
        tag = admin.post("/receiver-tags", json={"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
                                                 "max_total_bytes_cap": 100 * 1024 * 1024, "auto_enroll_new_users": True}).json()
        rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * 1024 * 1024,
                                             "message": "A message long enough to wrap on a phone screen, twice over, so that its box is tested."}).json()
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"/u/{rec['token']}")
        expect(page.locator("#form")).to_be_visible(timeout=15000)
        page.set_input_files("#file-input", files=[{"name": "a-long-name-" + "x" * 60 + ".txt", "mimeType": "text/plain", "buffer": b"1"}])
        assert page.evaluate("() => document.documentElement.scrollWidth") <= 391
        page.click("#upload-btn")
        expect(page.locator("#receipt")).to_be_visible(timeout=20000)
        assert page.evaluate("() => document.documentElement.scrollWidth") <= 391
    finally:
        admin.put("/settings", json={k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")})


def _dialog_box_fits(page: Page, modal_id: str, width: int):
    box = page.locator(f"#{modal_id} .modal-content").bounding_box()
    return bool(box) and box["x"] >= 0 and box["x"] + box["width"] <= width + 1, box


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("width", list(WIDTHS))
def test_every_settings_page_fits_the_screen(page: Page, people, skin, width):
    a, _u, _v = people
    _login(page, a, skin, WIDTHS[width])
    assert _go(page, "settings")
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
    problems = {}
    visited = []
    for tab in SETTINGS_PAGES:
        btn = page.locator(f'#settings-section .tab-btn[data-tab="{tab}"]')
        if not btn.is_visible():
            continue
        btn.click()
        expect(page.locator(f"#settings-tab-{tab}")).to_be_visible(timeout=10000)
        page.wait_for_timeout(400)          # the pages that load lists on opening draw them
        visited.append(tab)
        bad = page.evaluate(OVERFLOW_JS)
        if bad:
            problems[tab] = bad
    assert len(visited) >= 10, visited      # the loop reached the pages, not one of them
    assert problems == {}, problems


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("width", list(WIDTHS))
def test_the_new_dialogs_stay_on_screen_at_every_width(page: Page, people, skin, width):
    """The Extend dialog and the Move to vault dialog, at 390, 768 and 1024, both skins."""
    a, _u, v = people
    size = WIDTHS[width]
    _login(page, a, skin, size)
    bad = {}
    # Extend: opened as a card's Extend button opens it, on a share that ends tomorrow with a type allowing a week.
    page.evaluate("""() => { const soon = new Date(Date.now() + 86400000).toISOString();
        const most = new Date(Date.now() + 7 * 86400000).toISOString();
        openExtendExpiry('share', '00000000-0000-0000-0000-000000000000', soon,
                         'the share of a vault with a rather long name that has to wrap on a phone', null, most); }""")
    expect(page.locator("#extend-expiry-modal.active")).to_be_visible()
    ok, box = _dialog_box_fits(page, "extend-expiry-modal", size[0])
    if not ok:
        bad["extend-expiry-modal"] = box
    assert page.evaluate("() => document.documentElement.scrollWidth") <= size[0] + 1
    page.keyboard.press("Escape")
    expect(page.locator("#extend-expiry-modal.active")).to_be_hidden()
    # Move to vault: from an open vault with a file in it, as the drop vault's button opens it.
    _go(page, "vaults")
    page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    expect(page.locator("#vault-files-table-body tr")).to_have_count(1, timeout=15000)
    page.evaluate("() => openMoveToVaultModal()")
    expect(page.locator("#move-to-vault-modal.active")).to_be_visible(timeout=10000)
    ok, box = _dialog_box_fits(page, "move-to-vault-modal", size[0])
    if not ok:
        bad["move-to-vault-modal"] = box
    assert page.evaluate("() => document.documentElement.scrollWidth") <= size[0] + 1
    page.keyboard.press("Escape")
    assert bad == {}, bad


@pytest.fixture
def recipient(admin):
    """A user holding two claimed shares: one view-only, one with download, each a vault with a file in it."""
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    r = admin.create_user(role="user")
    rc = ApiClient(); rc.login(r["_username"], r["_password"])
    tag = admin.post("/share-tags", json={"name": unique("widetag"), "auto_enroll_new_users": True,
                                          "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10,
                                          "allow_view_only": True}).json()
    vaults = []
    try:
        for view_only in (True, False):
            v = admin.create_vault(name=unique("Shared with a rather long vault name" + (" view" if view_only else "")))
            vaults.append(v)
            admin.post(f"/vaults/{v['id']}/files",
                       files=[("files", ("a-rather-long-file-name-for-the-width-pass.txt", b"x", "text/plain"))])
            share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                                "claim_audience": "anyone_internal", "view_only": view_only})
            assert share.status_code == 200, share.text
            assert rc.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
        yield r, vaults
    finally:
        for v in vaults:
            admin.delete_vault(v["id"])
        admin.delete_user(r["id"])
        admin.put("/settings", json={"sharing_enabled": before})


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("width", list(WIDTHS))
def test_a_recipients_shared_section_and_shared_vaults_fit_the_screen(page: Page, recipient, skin, width):
    r, vaults = recipient
    _login(page, r, skin, WIDTHS[width])
    problems = {}
    for section in USER_SECTIONS:
        if not _go(page, section):
            continue
        if section == "shared":
            # Both cards drawn, the view-only one with its note, before anything is measured.
            expect(page.locator("#shared-tab-with-me [data-share-id]")).to_have_count(2, timeout=15000)
        bad = page.evaluate(OVERFLOW_JS)
        if bad:
            problems[section] = bad
    # Each shared vault, opened from the Shared page: the view-only one offers less, both must fit.
    for v in vaults:
        _go(page, "shared")
        page.evaluate("id => openSharedItem(id)", v["id"])
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        expect(page.locator("#vault-files-table-body tr")).to_have_count(1, timeout=15000)
        page.wait_for_timeout(400)
        bad = page.evaluate(OVERFLOW_JS)
        if bad:
            problems[f"shared-vault-{v['name']}"] = bad
    assert problems == {}, problems


@pytest.fixture
def public_links_on(admin):
    keys = ("public_file_links_enabled", "public_note_links_enabled", "public_note_link_user_cap")
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True,
                                 "public_note_link_user_cap": 100})
    yield
    admin.put("/settings", json={k: before.get(k) for k in keys})


def test_the_file_link_and_note_link_pages_fit_a_phone(page: Page, admin, public_links_on):
    """/p and /l, each with an owner's message holding a long unbroken word, at phone width: no sideways scroll."""
    tag = admin.post("/note-link-tags", json={"name": unique("widelink"), "min_token_len": 10, "require_secret": "none",
                                              "auto_enroll_new_users": True, "allowed_targets": ["note", "file", "folder"],
                                              "default_ttl_hours": 24, "max_ttl_hours": 24}).json()
    v = admin.create_vault(name=unique("Wide link"))
    try:
        admin.post(f"/vaults/{v['id']}/files",
                   files=[("files", ("a-long-name-" + "x" * 60 + ".txt", b"x", "text/plain"))])
        fid = admin.get(f"/vaults/{v['id']}/files").json()["items"][0]["id"]
        link = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file", "target_file_id": fid,
                                                 "tag_id": tag["id"], "ttl_hours": 1, "message": OWNER_MESSAGE})
        assert link.status_code == 200, link.text
        note = admin.post("/notes", json={"title": "A title long enough to wrap " * 3, "body": "line one " * 40}).json()
        nl = admin.post("/note-links", json={"note_id": note["id"], "tag_id": tag["id"], "message": OWNER_MESSAGE})
        assert nl.status_code == 200, nl.text
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"/p/{link.json()['token']}")
        expect(page.locator("#owner-message")).to_have_text(OWNER_MESSAGE, timeout=15000)
        assert page.evaluate("() => document.documentElement.scrollWidth") <= 391
        page.goto(f"/l/{nl.json()['token']}")
        expect(page.locator("#owner-message-reveal")).to_have_text(OWNER_MESSAGE, timeout=15000)
        assert page.evaluate("() => document.documentElement.scrollWidth") <= 391
        page.click("#reveal-btn")
        expect(page.locator("#content")).to_be_visible(timeout=10000)
        assert page.evaluate("() => document.documentElement.scrollWidth") <= 391
    finally:
        admin.delete_vault(v["id"])
