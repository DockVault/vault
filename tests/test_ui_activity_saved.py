"""UI — saved searches on the Activity page: saved, loaded, changed, opened by default after signing in
again, renamed, set back to no default and deleted; and a saved vault filter holds the vault's id,
never its name, since a saved search is stored in the clear."""
import json

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import (activity_admin, failed_sign_in, filter_by_person, login, open_activity,  # noqa: F401
                          sign_in, sign_out)
from conftest import ApiClient, unique

pytestmark = pytest.mark.ui


def _menu_item(page: Page, text):
    page.click("#act-saved-btn")
    menu = page.locator("#act-saved-menu")
    expect(menu).to_be_visible()
    return menu.get_by_role("menuitem", name=text, exact=True)


def _saved_item(page: Page, name):
    page.click("#act-saved-btn")
    expect(page.locator("#act-saved-menu")).to_be_visible()
    return page.locator("#act-saved-menu .act-saved-item").filter(has_text=name)


def _toast(page: Page, text):
    expect(page.locator(".toast").filter(has_text=text)).to_have_count(1, timeout=10000)


def test_a_saved_search_from_saving_to_deleting(page: Page, anon, activity_admin):
    name = failed_sign_in(anon)
    login(page, activity_admin)
    open_activity(page)
    page.click("#act-saved-btn")
    expect(page.locator("#act-saved-menu")).to_contain_text(
        "No saved searches yet. Set the filters you use often, then choose Save current search.")
    page.keyboard.press("Escape")
    filter_by_person(page, name)
    page.click("#act-p-time .act-key-btn[data-fkey=key-bad]")
    chips = page.locator("#act-chips .act-chip")
    expect(chips).to_have_count(2)

    _menu_item(page, "Save current search…").click()
    expect(page.locator("#act-save-modal")).to_be_visible()
    expect(page.locator("#act-save-name")).to_have_value(f"Failed or refused · {name}")
    title = unique("Failed ghosts")
    page.fill("#act-save-name", title)
    page.check("#act-save-default")
    page.click("#act-save-submit")
    _toast(page, f'Saved "{title}".')
    expect(page.locator("#act-save-modal")).to_be_hidden()
    expect(page.locator("#act-saved-label")).to_have_text(title)
    expect(page.locator("#act-chips .act-chip-saved")).to_have_text(f"Saved search: {title}")

    # Changed, then loaded again from the menu.
    page.click("#act-chips .act-clear-all")
    expect(chips).to_have_count(0)
    expect(page.locator("#act-saved-label")).to_have_text(f"{title} (changed)")
    item = _saved_item(page, title)
    expect(item).to_contain_text("★")
    expect(item).to_contain_text(f"Last 7 days · Failed or refused · Person contains: {name}")
    expect(page.locator("#act-saved-menu").get_by_role("menuitem", name=f'Update "{title}"')).to_have_count(1)
    item.click()
    expect(chips).to_have_count(2)
    expect(page.locator("#act-chips")).to_contain_text(f"Person contains: {name}")
    expect(page.locator("#act-saved-label")).to_have_text(title)

    # The default opens the page, from the server, after signing in again with nothing kept locally.
    sign_out(page)
    page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
    sign_in(page, activity_admin)
    open_activity(page)
    expect(page.locator("#act-chips .act-chip-saved")).to_have_text(f"Saved search: {title}")
    expect(chips).to_have_count(2)
    expect(page.locator("#activity-rows tr.act-row")).to_have_count(1, timeout=10000)

    # Manage: rename it, open the page with no filters instead, then delete it.
    _menu_item(page, "Manage saved searches…").click()
    manage = page.locator("#act-manage-modal")
    expect(manage).to_be_visible()
    expect(manage.locator("input[type=radio]:checked")).to_have_count(1)
    expect(manage.locator("label", has=page.locator("input[type=radio]:checked"))).to_contain_text(title)
    row = manage.locator(".act-manage-row")
    row.get_by_role("button", name="Rename").click()
    renamed = unique("Sign-in trouble")
    field = row.locator("input.act-manage-input")
    field.fill(renamed)
    field.press("Enter")
    _toast(page, f'Renamed to "{renamed}".')
    expect(manage.locator(".act-manage-row .act-saved-name")).to_have_text(renamed)
    with page.expect_response(lambda r: "/activity/saved-searches/" in r.url and r.request.method == "DELETE"):
        manage.get_by_label("My last time range, no filters").check()
    manage.locator(".act-manage-row").get_by_role("button", name="Delete").click()
    expect(manage.locator(".act-manage-confirm")).to_contain_text(f'Delete "{renamed}"?')
    manage.locator(".act-manage-confirm .btn-danger").click()
    _toast(page, f'Deleted "{renamed}".')
    expect(manage.locator(".act-manage-row")).to_have_count(0)
    page.click("#act-manage-close")
    expect(page.locator("#act-saved-label")).to_have_text("Saved")
    expect(page.locator("#act-chips .act-chip-saved")).to_have_count(0)


def test_a_saved_vault_filter_holds_the_vault_id_never_its_name(page: Page, activity_admin):
    owner = ApiClient()
    owner.login(activity_admin["_username"], activity_admin["_password"])
    secret = unique("Project Nightjar")
    vault = owner.create_vault(name=secret)
    try:
        login(page, activity_admin, path=f"/#activity?vault={vault['id']}")
        expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
        expect(page.locator("#act-chips")).to_contain_text(f"Vault: {secret}", timeout=10000)
        _menu_item(page, "Save current search…").click()
        expect(page.locator("#act-save-name")).to_have_value("one vault")
        page.fill("#act-save-name", "Nightjar")
        page.click("#act-save-submit")
        _toast(page, 'Saved "Nightjar".')
        stored = owner.get("/activity/saved-searches").json()
        text = json.dumps(stored)
        assert vault["id"] in text and secret not in text, text
    finally:
        owner.delete_vault(vault["id"])
