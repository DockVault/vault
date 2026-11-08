"""Selecting files moves no row.

The selection bar (count, Download, Delete, Clear) sat in the page's flow between the toolbar and the table,
hidden until the first file was selected: the table then dropped by the bar's height and jumped back when the
last selection was undone, under the pointer that was selecting. The bar now lies over the toolbar row while a
selection exists, so no row moves, and Delete sits above the table header, not where a row's own controls are.

Both skins, a desk and a phone width. The cap gating of the two actions (a scoped credential without the
capability sees no Download or Delete) is unchanged and pinned elsewhere.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui

ROWS = "#vault-files-table-body tr"


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def vault_with_files(admin):
    u = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(u["_username"], u["_password"])
    vault = client.create_vault(name=unique("rows"))
    for i in range(3):
        r = client.post(f"/vaults/{vault['id']}/files", files=[("files", (f"row-{i}.txt", b"a few bytes " * 20, "text/plain"))])
        assert r.status_code == 200, r.text
    try:
        yield u, vault
    finally:
        client.delete_vault(vault["id"])
        admin.delete_user(u["id"])


def _row_boxes(page: Page) -> list:
    # The pointer parked off the table first: the v1 skin lifts a hovered card by two pixels.
    page.mouse.move(0, 0)
    return page.evaluate(
        "() => [...document.querySelectorAll('#vault-files-table-body tr')]"
        "  .map(r => { const b = r.getBoundingClientRect(); return [Math.round(b.top), Math.round(b.height)]; })")


def _settled_rows(page: Page) -> list:
    """The rows' boxes once the page has stopped moving: the header above the table settles for a second
    or so after the rows render (badges, the lock control), which is not the selection moving anything."""
    last = _row_boxes(page)
    for _ in range(25):
        page.wait_for_timeout(400)
        now = _row_boxes(page)
        if now == last:
            return now
        last = now
    raise AssertionError(f"the rows never settled: {last}")


def _overlaps(a: dict, b: dict) -> bool:
    return not (a["x"] + a["width"] <= b["x"] or b["x"] + b["width"] <= a["x"]
                or a["y"] + a["height"] <= b["y"] or b["y"] + b["height"] <= a["y"])


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("width,height", [(1280, 800), (390, 844)])
def test_selecting_and_clearing_moves_no_row(page: Page, vault_with_files, skin, width, height):
    user, vault = vault_with_files
    page.set_viewport_size({"width": width, "height": height})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    _login(page, user)
    drawer = page.locator("#mobile-nav-toggle")
    if drawer.is_visible():  # the phone's sidebar is a drawer
        drawer.click()
        expect(page.locator('.sidebar-item[data-section="vaults"]')).to_be_visible()
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.vault-card[data-vault-id="{vault["id"]}"] .vault-open')
    expect(page.locator(ROWS)).to_have_count(3, timeout=15000)
    expect(page.locator("#files-bulk-bar")).to_be_hidden()
    before = _settled_rows(page)
    assert len(before) == 3 and before[0][0] < before[2][0]

    page.locator(f"{ROWS} .files-check").first.check()
    expect(page.locator("#files-bulk-bar")).to_be_visible()
    expect(page.locator("#files-bulk-count")).to_have_text("1")
    assert _row_boxes(page) == before, "a row moved when the first file was selected"

    # Delete sits where no row's own controls are.
    delete = page.locator("#files-bulk-delete").bounding_box()
    for row in page.locator(ROWS).all():
        box = row.bounding_box()
        assert box and not _overlaps(delete, box), "the selection bar's Delete lies over a row"

    page.click("#files-bulk-clear")
    expect(page.locator("#files-bulk-bar")).to_be_hidden()
    assert _row_boxes(page) == before, "a row moved when the selection was undone"
