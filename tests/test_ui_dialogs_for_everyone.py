"""Dialogs and keyboard for everyone (static/js/dialogs.js and the page).

Every dialog is a dialog to assistive technology: role="dialog", aria-modal and a name from its heading, set
by the controller for dialogs on the page and for ones built later. Focus moves into a dialog when it opens
and back to the control that opened it when it closes; Tab and Shift+Tab stay inside the top dialog. A toast
is announced (an error as an alert, the rest as status). A file's context menu takes the arrow keys, Home and
End. A file's name is a button for the keyboard in both views.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def test_every_dialog_on_the_page_has_a_role_and_a_name(page: Page, person):
    """Every dialog has the role, is modal, and names itself by a heading that exists (a dialog whose heading
    is filled when it opens, the Activity event's, names it then)."""
    _login(page, person)
    unnamed = page.evaluate(
        "() => [...document.querySelectorAll('.modal')].filter(d => !['dialog', 'alertdialog'].includes(d.getAttribute('role'))"
        "  || d.getAttribute('aria-modal') !== 'true'"
        "  || !((d.getAttribute('aria-labelledby') && document.getElementById(d.getAttribute('aria-labelledby')))"
        "        || d.getAttribute('aria-label')))"
        "  .map(d => d.id || d.className)")
    assert unnamed == [], unnamed
    count = page.evaluate("() => document.querySelectorAll('.modal').length")
    assert count >= 40, count  # the page's dialogs really were counted


def test_focus_moves_into_a_dialog_and_back_to_its_opener(page: Page, person):
    _login(page, person)
    page.click('.sidebar-item[data-section="vaults"]')
    opener = page.locator("#create-vault-btn")
    opener.focus()
    opener.press("Enter")
    expect(page.locator("#create-vault-modal.active")).to_be_visible()
    page.wait_for_timeout(200)
    inside = page.evaluate("() => document.getElementById('create-vault-modal').contains(document.activeElement) && document.activeElement.tagName")
    assert inside in ("INPUT", "SELECT", "TEXTAREA", "BUTTON"), inside
    # Tab stays inside: many presses later, focus is still in the dialog.
    for _ in range(25):
        page.keyboard.press("Tab")
    assert page.evaluate("() => document.getElementById('create-vault-modal').contains(document.activeElement)")
    for _ in range(25):
        page.keyboard.press("Shift+Tab")
    assert page.evaluate("() => document.getElementById('create-vault-modal').contains(document.activeElement)")
    page.keyboard.press("Escape")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden()
    assert page.evaluate("() => document.activeElement && document.activeElement.id") == "create-vault-btn"


def test_toasts_are_announced(page: Page, person):
    _login(page, person)
    expect(page.locator("#toast-container")).to_have_attribute("aria-live", "polite")
    page.evaluate("() => { showToast('Something went wrong', 'error'); showToast('Saved', 'success'); }")
    expect(page.locator("#toast-container .toast-error")).to_have_attribute("role", "alert")
    expect(page.locator("#toast-container .toast-success")).to_have_attribute("role", "status")


@pytest.fixture
def vault_with_a_file(admin, person):
    client = ApiClient(BASE_URL)
    client.login(person["_username"], person["_password"])
    vault = client.create_vault(name=unique("keys"))
    r = client.post(f"/vaults/{vault['id']}/files", files=[("files", ("one.txt", b"one", "text/plain")), ("files", ("two.txt", b"two", "text/plain"))])
    assert r.status_code == 200, r.text
    yield vault
    client.delete_vault(vault["id"])


def test_a_files_menu_takes_the_arrow_keys_and_its_name_takes_enter(page: Page, person, vault_with_a_file):
    _login(page, person)
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_with_a_file["id"]}"]')
    expect(page.locator("#vault-files-table-body tr")).to_have_count(2, timeout=15000)
    # The name is a button for the keyboard: Enter opens the preview.
    name = page.locator("#vault-files-table-body tr").first.locator(".file-name[data-file-id]")
    expect(name).to_have_attribute("role", "button")
    expect(name).to_have_attribute("tabindex", "0")
    name.focus()
    name.press("Enter")
    expect(page.locator("#file-preview-modal.active")).to_be_visible(timeout=10000)
    page.keyboard.press("Escape")
    expect(page.locator("#file-preview-modal.active")).to_be_hidden()
    # The row's menu: focus lands on its first item; the arrows move; End and Home jump; Escape closes.
    page.locator("#vault-files-table-body tr").first.locator('button[data-action="more"]').click()
    menu = page.locator("#file-context-menu")
    expect(menu).to_be_visible()
    items = menu.locator(".context-menu-item:not([disabled])")
    first = items.first.inner_text()
    assert page.evaluate("() => document.activeElement.closest('#file-context-menu') !== null")
    assert page.evaluate("() => document.activeElement.innerText.trim()") == first.strip()
    page.keyboard.press("ArrowDown")
    assert page.evaluate("() => document.activeElement.innerText.trim()") == items.nth(1).inner_text().strip()
    page.keyboard.press("End")
    assert page.evaluate("() => document.activeElement.innerText.trim()") == items.last.inner_text().strip()
    page.keyboard.press("Home")
    assert page.evaluate("() => document.activeElement.innerText.trim()") == first.strip()
    page.keyboard.press("ArrowUp")
    assert page.evaluate("() => document.activeElement.innerText.trim()") == items.last.inner_text().strip()
    page.keyboard.press("Escape")
    expect(menu).to_be_hidden()


def test_the_screen_reader_only_class_is_shared():
    from pathlib import Path
    css = (Path(__file__).resolve().parents[1] / "static" / "css" / "utilities.css").read_text(encoding="utf-8")
    assert ".sr-only {" in css
