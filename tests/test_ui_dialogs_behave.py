"""Dialogs that behave (static/js/dialogs.js).

A dialog opened again kept the scroll position of its last use, so a long form opened mid-way down. Escape
was handled by the shared confirm and prompt only. A click on any dialog's backdrop closed every open dialog
at once, so a confirm asked from inside Your account took Your account down with it, and the confirm's
promise was left unanswered; a text selection dragged out of a field and released on the backdrop counted as
that click, and what was typed was lost.

Now a dialog opens scrolled to the top; Escape closes the top dialog only; a backdrop closes only the top
dialog, only when the press and the release were both on the backdrop, and not while the dialog holds
something typed since it opened; a confirm or prompt closed either way is answered as cancelled.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

ACCOUNT = "#user-settings-modal"
CONFIRM = "#confirm-modal"
CREATE = "#create-vault-modal"


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


def _open_account(page: Page):
    page.click("#profile-btn")
    page.click("#settings-btn")
    expect(page.locator(f"{ACCOUNT}.active")).to_be_visible(timeout=10000)


def _ask(page: Page):
    """A confirm asked over whatever is open; its answer is read back from window.__answer."""
    page.evaluate("() => { window.__answer = 'pending'; showConfirm('Remove this key?', 'Remove key').then(v => { window.__answer = v; }); }")
    expect(page.locator(f"{CONFIRM}.active")).to_be_visible()


def _backdrop_point(page: Page, selector: str):
    """A point on the dialog's backdrop: its left edge, half way down, clear of the content box."""
    content = page.locator(f"{selector} .modal-content").bounding_box()
    assert content and content["x"] > 20, "the content box leaves no backdrop at the left"
    return 8, content["y"] + content["height"] / 2


def _open_create_vault(page: Page):
    page.route("**/zk-enabled", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body=json.dumps({"zero_knowledge_enabled": True, "must_use_zk": False,
                         "plan_zero_knowledge": True, "allowed_vault_types": ["standard", "zero_knowledge"]})))
    page.evaluate("showCreateVault()")
    expect(page.locator(f"{CREATE}.active")).to_be_visible()
    expect(page.locator("#vault-type-group")).to_be_visible(timeout=10000)


def test_a_dialog_opens_scrolled_to_the_top(page: Page, person):
    page.set_viewport_size({"width": 1280, "height": 560})  # short: the create-vault body scrolls
    _login(page, person)
    _open_create_vault(page)
    scrolled = page.evaluate(
        "() => { let moved = 0; for (const box of document.querySelectorAll('#create-vault-modal .modal-content, #create-vault-modal .modal-body')) {"
        "  box.scrollTop = 10000; moved = Math.max(moved, box.scrollTop); } return moved; }")
    assert scrolled > 0, "the dialog did not scroll at this height, so nothing is being tested"
    page.click(f"{CREATE} .modal-footer .close-modal-btn")
    expect(page.locator(f"{CREATE}.active")).to_be_hidden()
    page.evaluate("showCreateVault()")
    expect(page.locator(f"{CREATE}.active")).to_be_visible()
    tops = page.evaluate(
        "() => [...document.querySelectorAll('#create-vault-modal .modal-content, #create-vault-modal .modal-body')].map(b => b.scrollTop)")
    assert all(t == 0 for t in tops), tops


def test_escape_closes_the_top_dialog_only(page: Page, person):
    _login(page, person)
    _open_account(page)
    _ask(page)
    page.keyboard.press("Escape")
    expect(page.locator(f"{CONFIRM}.active")).to_be_hidden()
    expect(page.locator(f"{ACCOUNT}.active")).to_be_visible()
    assert page.evaluate("() => window.__answer") is False
    page.keyboard.press("Escape")
    expect(page.locator(f"{ACCOUNT}.active")).to_be_hidden()


def test_a_backdrop_click_closes_the_confirm_alone_and_answers_it(page: Page, person):
    _login(page, person)
    _open_account(page)
    _ask(page)
    x, y = _backdrop_point(page, CONFIRM)
    page.mouse.click(x, y)
    expect(page.locator(f"{CONFIRM}.active")).to_be_hidden()
    expect(page.locator(f"{ACCOUNT}.active")).to_be_visible()
    assert page.evaluate("() => window.__answer") is False
    # And the dialog under it closes on its own backdrop, as before.
    x, y = _backdrop_point(page, ACCOUNT)
    page.mouse.click(x, y)
    expect(page.locator(f"{ACCOUNT}.active")).to_be_hidden()


def test_a_press_inside_the_dialog_released_on_the_backdrop_closes_nothing(page: Page, person):
    _login(page, person)
    _open_create_vault(page)
    field = page.locator("#vault-name").bounding_box()
    x, y = _backdrop_point(page, CREATE)
    page.mouse.move(field["x"] + 10, field["y"] + field["height"] / 2)
    page.mouse.down()
    page.mouse.move(x, y, steps=5)
    page.mouse.up()
    expect(page.locator(f"{CREATE}.active")).to_be_visible()
    # A press and release both on the backdrop closes it.
    page.mouse.click(x, y)
    expect(page.locator(f"{CREATE}.active")).to_be_hidden()


def test_a_form_with_edits_ignores_the_backdrop(page: Page, person):
    _login(page, person)
    _open_create_vault(page)
    page.fill("#vault-name", "Quarterly reports")
    x, y = _backdrop_point(page, CREATE)
    page.mouse.click(x, y)
    expect(page.locator(f"{CREATE}.active")).to_be_visible()
    assert page.input_value("#vault-name") == "Quarterly reports"
    # Back to what it opened with: the backdrop closes it again.
    page.fill("#vault-name", "")
    page.mouse.click(x, y)
    expect(page.locator(f"{CREATE}.active")).to_be_hidden()


def test_a_prompt_closed_by_its_backdrop_is_answered_as_cancelled(page: Page, person):
    _login(page, person)
    page.evaluate("() => { window.__answer = 'pending'; showPrompt('Name the folder', 'New folder').then(v => { window.__answer = v; }); }")
    expect(page.locator(f"{CONFIRM}.active")).to_be_visible()
    x, y = _backdrop_point(page, CONFIRM)
    page.mouse.click(x, y)
    expect(page.locator(f"{CONFIRM}.active")).to_be_hidden()
    assert page.evaluate("() => window.__answer") is None


def test_escape_on_the_step_up_settles_it_as_cancelled_and_leaves_the_dialog_under_it(page: Page, person):
    """The step-up dialog floats above whatever asked for it. Escape closes it alone and answers the asker
    with no receipt (cancelled), never with one."""
    _login(page, person)
    _open_account(page)
    page.evaluate("() => { window.__receipt = 'pending'; requestStepUpReceipt('test', ['password']).then(r => { window.__receipt = r; }); }")
    expect(page.locator("#stepup-modal.active")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator("#stepup-modal.active")).to_be_hidden()
    expect(page.locator(f"{ACCOUNT}.active")).to_be_visible()
    assert page.evaluate("() => window.__receipt") is None
