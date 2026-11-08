"""The phone and tablet pass: every section of the signed-in app, both skins, at 390, 768 and 1024 pixels, as an
administrator and as a user; nothing wider than the screen, no sideways scroll, the main dialogs on screen; the
public upload page at phone width too."""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui

WIDTHS = {"phone": (390, 844), "tablet": (768, 1024), "small-laptop": (1024, 768)}
ADMIN_SECTIONS = ["dashboard", "vaults", "shared", "notes", "uploadlinks", "temp-creds", "users", "groups",
                  "activity", "compliance", "settings"]
USER_SECTIONS = ["dashboard", "vaults", "shared", "notes", "temp-creds"]

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
@pytest.mark.parametrize("width", ["phone", "tablet"])
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
