"""A department that single sign-on group mappings name, in the browser: its page counts them, the question before its
deletion says they go with it, and the toast after says how many went. A department no mapping names reads as before.

The department is stood in for with page.route (GET and DELETE /groups/{id}), so nothing on the server is deleted.
The offline twin of these tests, driven in Node, is tests/test_ui_department_mappings.py."""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

GROUP_ID = "d0d0d0d0-0000-4000-8000-00000000d0d0"


def _department(mapped):
    return {"id": GROUP_ID, "name": "Mapped department", "description": None, "color": None, "parent_id": None,
            "member_count": 0, "child_count": 0, "members": [], "children": [], "sso_group_mappings": mapped}


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _stand_in(page: Page, mapped, removed):
    deleted = []

    def handle(route):
        method = route.request.method
        if method == "GET":
            route.fulfill(status=200, json=_department(mapped))
        elif method == "DELETE":
            deleted.append(route.request.url)
            route.fulfill(status=200, json={"message": "Group 'Mapped department' deleted",
                                            "sso_group_mappings_removed": removed})
        else:
            route.continue_()
    page.route(f"**/groups/{GROUP_ID}", handle)
    return deleted


def _open_department(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => navigateToSection('groups')")
    expect(page.locator("#groups-section")).to_be_visible(timeout=10000)
    # The section's own load draws the tree and then the empty detail pane; the stood-in department opens after it.
    expect(page.locator("#groups-tree .loading-spinner")).to_have_count(0, timeout=10000)
    page.evaluate(f"() => openGroupDetail('{GROUP_ID}')")
    expect(page.locator("#group-detail .group-detail-title")).to_contain_text("Mapped department", timeout=8000)


def test_deleting_a_department_says_its_mappings_go_with_it(page: Page, admin_creds):
    deleted = _stand_in(page, 2, 2)
    _open_department(page, admin_creds)
    stat = page.locator("#group-detail .group-stats .meta-item", has_text="Single sign-on group mappings")
    expect(stat).to_have_count(1)
    expect(stat.locator(".meta-value")).to_have_text("2")
    page.click("#group-delete-btn")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=8000)
    expect(page.locator("#confirm-modal-message")).to_contain_text(
        "2 single sign-on group mappings name this department and are removed with it")
    page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#toast-container")).to_contain_text(
        "Department deleted, with 2 single sign-on group mappings", timeout=8000)
    assert len(deleted) == 1


def test_a_department_no_mapping_names_is_deleted_as_before(page: Page, admin_creds):
    deleted = _stand_in(page, 0, 0)
    _open_department(page, admin_creds)
    expect(page.locator("#group-detail .group-stats .meta-item",
                        has_text="Single sign-on group mappings")).to_have_count(0)
    page.click("#group-delete-btn")
    message = page.locator("#confirm-modal-message")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=8000)
    expect(message).to_contain_text("Members are kept; any sub-groups move up to its parent.")
    expect(message).not_to_contain_text("single sign-on group mapping")
    page.click("#confirm-modal-confirm-btn")
    toast = page.locator("#toast-container")
    expect(toast).to_contain_text("Department deleted", timeout=8000)
    expect(toast).not_to_contain_text("single sign-on group mapping")
    assert len(deleted) == 1
