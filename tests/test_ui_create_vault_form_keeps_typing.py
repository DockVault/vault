"""The create-vault form keeps what was typed when the type changes.

The type chooser (Standard / Zero-knowledge) was the last control of the form, after the name, description,
size and password. Choosing zero-knowledge then inserted the label field between the name and the description,
added a help line under the name and renamed it: every field above the cursor moved after the person had typed
into it. The chooser now comes first, so the form below it is laid out before anything is typed; the help line
under the name is always one line (its text says where the name is readable for the chosen type); and what a
type switch changes sits below the typed fields (the password gives way to the label, team mode appears). The
values stay where they were typed.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

TYPED = ("#vault-name", "#vault-desc", "#vault-size-gb")


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def _both_types(page: Page):
    page.route("**/zk-enabled", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body=json.dumps({"zero_knowledge_enabled": True, "must_use_zk": False,
                         "plan_zero_knowledge": True, "allowed_vault_types": ["standard", "zero_knowledge"]})))


def _boxes(page: Page) -> dict:
    """Where each typed field sits in the dialog's body, to the pixel: its top from the body's top, with the
    body's own scroll added back (at a short viewport the body scrolls, and filling a field scrolls it), and
    its height. Measured from the body, not the viewport: the dialog is centred and sized to its content, so
    a change in its height or width moves the whole dialog by a few pixels, which is not a field moving."""
    return page.evaluate(
        """sels => {
            const body = document.querySelector('#create-vault-modal .modal-body');
            const b = body.getBoundingClientRect();
            return Object.fromEntries(sels.map(sel => {
                const r = document.querySelector(sel).getBoundingClientRect();
                return [sel, [Math.round(r.top - b.top + body.scrollTop), Math.round(r.height)]];
            }));
        }""", list(TYPED))


def _unmoved(before: dict, after: dict, what: str) -> None:
    """The same tops and heights, to within two pixels: the v1 dialog is sized to its content, so its
    width changes by a few pixels with the chosen type and the rounding of each line's height with it."""
    for sel, (top, height) in before.items():
        top2, height2 = after[sel]
        assert abs(top2 - top) <= 2 and abs(height2 - height) <= 2, f"{what}: {sel} {before[sel]} -> {after[sel]}"


def _top(page: Page, sel: str) -> float:
    box = page.locator(sel).bounding_box()
    assert box, f"{sel} has no box"
    return box["y"]


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_type_comes_first_and_a_switch_moves_or_changes_nothing_typed(page: Page, fresh_user, skin):
    # Tall enough for the dialog's body not to scroll in any state: a scrollbar that comes and goes
    # changes the fields' width and so the rounding of every line's height, which is not a field moving.
    page.set_viewport_size({"width": 1280, "height": 960})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    _login(page, fresh_user)
    _both_types(page)
    page.evaluate("showCreateVault()")
    expect(page.locator("#create-vault-modal.active")).to_be_visible()
    expect(page.locator("#vault-type-group")).to_be_visible(timeout=10000)
    assert not page.evaluate("() => { const b = document.querySelector('#create-vault-modal .modal-body'); return b.scrollHeight > b.clientHeight; }"),         "the dialog's body scrolls at this height; the measurements below would see the scrollbar, not the fields"
    # The dialog's entry animation scales it up over a quarter of a second; measured during it, every box is
    # a little smaller than it ends up, which is not a field moving either.
    page.evaluate("() => Promise.allSettled(document.querySelector('#create-vault-modal .modal-content')"
                  ".getAnimations({subtree: true}).map(a => a.finished))")

    # The chooser is above the first typed field.
    assert _top(page, "#vault-type") < _top(page, "#vault-name")

    page.fill("#vault-name", "Quarterly reports")
    page.fill("#vault-desc", "Board pack and the appendices")
    page.fill("#vault-size-gb", "2.5")
    before = _boxes(page)

    for choice in ("zero_knowledge", "standard", "zero_knowledge"):
        page.select_option("#vault-type", choice)
        page.wait_for_timeout(150)
        assert page.input_value("#vault-name") == "Quarterly reports"
        assert page.input_value("#vault-desc") == "Board pack and the appendices"
        assert page.input_value("#vault-size-gb") == "2.5"
        _unmoved(before, _boxes(page), f"a typed field moved after choosing {choice}")

    # Zero-knowledge is chosen now: the label took the password's place below the typed fields.
    expect(page.locator("#vault-label-group")).to_be_visible()
    expect(page.locator("#vault-password-group")).to_be_hidden()
    expect(page.locator("#vault-hierarchical-wrap")).to_be_visible()
    assert _top(page, "#vault-label") > _top(page, "#vault-size-gb")
    assert _top(page, "#vault-hierarchical") > _top(page, "#vault-label")
    expect(page.locator("#vault-name-label")).to_have_text("Vault Name (encrypted)")
    expect(page.locator("#vault-name-zk-help")).to_contain_text("Encrypted in your browser")

    # And back to Standard: the password is back where the label was, the name's line says the server reads it.
    page.select_option("#vault-type", "standard")
    expect(page.locator("#vault-password-group")).to_be_visible()
    expect(page.locator("#vault-label-group")).to_be_hidden()
    expect(page.locator("#vault-hierarchical-wrap")).to_be_hidden()
    expect(page.locator("#vault-name-label")).to_have_text("Vault Name")
    expect(page.locator("#vault-name-zk-help")).to_contain_text("server")
    _unmoved(before, _boxes(page), "a typed field moved after choosing standard")
