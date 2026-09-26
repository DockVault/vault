"""The web app at phone width (390 x 844 CSS px), in both skins.

  * unit — the phone stylesheet loads after both skins, and no stylesheet uses the --spacing-* names,
           which are defined nowhere (the toasts lost their padding and gaps to them).
  * ui   — the sidebar is a drawer behind a menu button; no section is wider than the screen; a file
           row's actions are on screen; the notifications panel stays on screen; a PDF preview says to
           download it when the browser has no inline PDF viewer; toasts have room between icon and text.

The ui tests log in as a THROWAWAY admin: applyServerPreferences() replaces the skin with the account's
stored one after login, so a skin chosen against a shared account can be silently discarded. Each test
re-asserts the skin that applied.
"""
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent
PHONE = {"width": 390, "height": 844}


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_the_phone_stylesheet_loads_after_both_skins():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    links = re.findall(r'<link rel="stylesheet" href="/static/css/([a-z0-9-]+)\.css', html)
    assert links.count("mobile") == 1, links
    assert links.index("mobile") > links.index("redesign") and links.index("mobile") > links.index("ui-v2"), \
        "mobile.css must come after both skins, or a skin rule of the same specificity wins"


@pytest.mark.unit
def test_no_stylesheet_uses_the_undefined_spacing_names():
    for css in (ROOT / "static" / "css").glob("*.css"):
        text = css.read_text(encoding="utf-8")
        assert "var(--spacing-" not in text, f"{css.name} uses --spacing-*, which no stylesheet defines"


# --------------------------------------------------------------------------- ui lane

@pytest.fixture
def phone_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, user, skin: str, viewport=PHONE):
    page.set_viewport_size(viewport)
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    applied = page.evaluate("() => document.documentElement.getAttribute('data-ui') || 'v1'")
    assert applied == skin, f"skin {skin!r} did not apply (got {applied!r})"


def _drawer_open(page: Page) -> bool:
    return page.evaluate("""() => {
        const s = document.getElementById('sidebar'), r = s.getBoundingClientRect();
        return s.classList.contains('mobile-open') && r.left >= 0 && getComputedStyle(s).visibility === 'visible';
    }""")


def _go(page: Page, section: str):
    page.click("#mobile-nav-toggle")
    expect(page.locator(f'.sidebar-item[data-section="{section}"]')).to_be_visible()
    page.click(f'.sidebar-item[data-section="{section}"]')
    expect(page.locator(f"#{section}-section")).to_be_visible(timeout=10000)
    # The sidebar slides out over .2s; wait for it to finish before measuring anything.
    page.wait_for_function("() => getComputedStyle(document.getElementById('sidebar')).visibility === 'hidden'")


@pytest.mark.ui
@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_menu_button_opens_a_drawer_that_closes_on_every_exit(page: Page, phone_admin, skin):
    _login(page, phone_admin, skin)
    toggle = page.locator("#mobile-nav-toggle")
    expect(toggle).to_be_visible()
    assert not _drawer_open(page)
    expect(page.locator('.sidebar-item[data-section="vaults"]')).to_be_hidden()

    toggle.click()
    assert _drawer_open(page)
    expect(toggle).to_have_attribute("aria-expanded", "true")
    expect(page.locator("#sidebar-backdrop")).to_be_visible()

    page.click('.sidebar-item[data-section="vaults"]')          # choosing a section closes it
    expect(page.locator("#vaults-section")).to_be_visible()
    expect(toggle).to_have_attribute("aria-expanded", "false")
    expect(page.locator("#sidebar-backdrop")).to_be_hidden()

    toggle.click()
    page.mouse.click(370, 500)                                   # a tap outside it closes it
    expect(toggle).to_have_attribute("aria-expanded", "false")

    toggle.click()
    page.keyboard.press("Escape")                                # so does Escape
    expect(toggle).to_have_attribute("aria-expanded", "false")

    page.set_viewport_size({"width": 1280, "height": 800})       # a wide screen has the rail, no button
    expect(toggle).to_be_hidden()
    expect(page.locator('.sidebar-item[data-section="vaults"]')).to_be_visible()


@pytest.mark.ui
@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_no_section_is_wider_than_the_phone(page: Page, phone_admin, skin):
    _login(page, phone_admin, skin)
    wide = {}
    for section in ("dashboard", "vaults", "shared", "notes", "temp-creds", "users", "groups",
                    "monitor", "settings"):
        _go(page, section)
        page.wait_for_timeout(300)
        doc_w = page.evaluate("() => document.documentElement.scrollWidth")
        if doc_w > PHONE["width"] + 1:
            wide[section] = doc_w
    assert not wide, f"these sections scroll sideways at {PHONE['width']}px: {wide}"


@pytest.mark.ui
@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_a_file_row_shows_its_actions_on_the_phone(page: Page, phone_admin, skin):
    from conftest import ApiClient

    client = ApiClient()
    client.login(phone_admin["_username"], phone_admin["_password"])
    v = client.create_vault(name=unique("phone"))
    try:
        name = "Quarterly board meeting notes and appendices.txt"
        r = client.post(f"/vaults/{v['id']}/files", files=[("files", (name, b"x", "text/plain"))])
        assert r.status_code in (200, 201), r.text
        _login(page, phone_admin, skin)
        _go(page, "vaults")
        page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        page.click('[data-files-view="table"]')
        row = page.locator("#vault-files-table-body tr", has_text="Quarterly")
        expect(row).to_be_visible(timeout=10000)
        fit = page.evaluate("""() => {
            const t = document.querySelector('.files-table'), w = t.parentElement;
            const row = [...document.querySelectorAll('#vault-files-table-body tr')].find(r => r.innerText.includes('Quarterly'));
            const acts = row.querySelector('.file-actions').getBoundingClientRect();
            return {table: t.getBoundingClientRect().width, frame: w.clientWidth, actsRight: acts.right,
                    vw: document.documentElement.clientWidth};
        }""")
        assert fit["table"] <= fit["frame"] + 1, f"the file table is wider than its frame: {fit}"
        assert fit["actsRight"] <= fit["vw"], f"the row's actions are off screen: {fit}"
    finally:
        client.delete_vault(v["id"])


@pytest.mark.ui
@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_notifications_panel_stays_on_the_phone_screen(page: Page, phone_admin, skin):
    _login(page, phone_admin, skin)
    page.click("#notif-btn")
    panel = page.locator("#notif-dropdown")
    expect(panel).to_be_visible()
    page.wait_for_timeout(300)                                   # its open transition
    box = panel.bounding_box()
    assert box["x"] >= 0 and box["x"] + box["width"] <= PHONE["width"], f"panel off screen: {box}"


def _open_synthetic_pdf(page: Page, pdf_viewer: bool):
    """Preview a listing entry that names a PDF; no real file exists, so any /download is observable."""
    page.evaluate(
        """() => {
            if (!Array.isArray(state.currentFiles)) state.currentFiles = [];
            state.currentFiles.push({ id: 'phone-pdf', name: 'report.pdf', type: 'file', size: 4096 });
            openFilePreview('phone-pdf', 'report.pdf', 'application/pdf');
        }"""
    )
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)


@pytest.mark.ui
@pytest.mark.parametrize("pdf_viewer", [False, True])
def test_a_pdf_preview_without_a_pdf_viewer_points_at_download(page: Page, phone_admin, pdf_viewer):
    # Chrome on Android reports navigator.pdfViewerEnabled === false and paints an empty frame for a
    # PDF. Pinned both ways: without a viewer the page says so and fetches nothing; with one it
    # fetches the file to show it (the entry is synthetic, so that fetch fails, which is fine here).
    page.add_init_script(
        "Object.defineProperty(navigator, 'pdfViewerEnabled', { get: () => %s });" % ("true" if pdf_viewer else "false"))
    from conftest import ApiClient

    client = ApiClient()
    client.login(phone_admin["_username"], phone_admin["_password"])
    v = client.create_vault(name=unique("pdfphone"))
    downloads = []
    page.on("request", lambda r: downloads.append(r.url) if "/download" in r.url else None)
    try:
        _login(page, phone_admin, "v2")
        _go(page, "vaults")
        page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        _open_synthetic_pdf(page, pdf_viewer)
        body = page.locator("#file-preview-body")
        page.wait_for_timeout(600)
        if pdf_viewer:
            assert downloads, "with a PDF viewer the preview should fetch the file"
            expect(body).not_to_contain_text("can't show PDFs")
        else:
            expect(body).to_contain_text("This browser can't show PDFs inside the page.")
            assert page.locator("#file-preview-body iframe").count() == 0
            assert not downloads, f"no file should be fetched for a PDF the page cannot show: {downloads}"
    finally:
        client.delete_vault(v["id"])


@pytest.mark.ui
@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_toasts_have_room_between_icon_and_text(page: Page, phone_admin, skin):
    _login(page, phone_admin, skin, viewport={"width": 1280, "height": 800})
    page.evaluate("() => showToast('Copied: report.pdf', 'info', 60000)")
    toast = page.locator("#toast-container .toast").first
    expect(toast).to_be_visible()
    gaps = page.evaluate("""() => {
        const t = document.querySelector('#toast-container .toast');
        const icon = t.querySelector('.toast-icon').getBoundingClientRect();
        const text = t.querySelector('.toast-content').getBoundingClientRect();
        return {between: text.left - icon.right, padLeft: parseFloat(getComputedStyle(t).paddingLeft)};
    }""")
    assert gaps["between"] >= 8, f"the icon runs into the text: {gaps}"
    assert gaps["padLeft"] >= 8, f"the toast has no padding: {gaps}"
