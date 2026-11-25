"""The Users page's "Administrator requests from single sign-on" card, in both skins and at phone width.

A sign-in through a provider that maps a group to the administrator role raises a request that waits for an
administrator's approval; the administrators' notice sends them to the Users page. The card lists the waiting
requests: one this administrator may decide has Approve and Deny, one they may not shows why in place of the
buttons. Approve asks first, then sends the approval, and a reset link the promotion took back a password for is
shown once to copy, as after any promotion.

The requests are the browser's own answers here (page.route): no provider is configured on the test deployment,
so nothing there can raise one. tests/test_users_page_sso_admin_requests.py drives the same functions offline.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

DESKTOP = {"width": 1280, "height": 900}
PHONE = {"width": 375, "height": 812}

HELD = [
    {"id": "11111111-1111-4111-8111-111111111111", "username": "bob-sso", "provider": "Contoso",
     "provider_group": "vault-admins", "requested_at": "2026-06-14T09:00:00Z", "expires_at": "2026-06-21T09:00:00Z",
     "state": "held", "decided_by": None, "decided_at": None, "you_may_decide": True, "refusal": None},
    {"id": "22222222-2222-4222-8222-222222222222", "username": "carol-sso", "provider": "Contoso",
     "provider_group": "vault-admins", "requested_at": "2026-06-13T09:00:00Z", "expires_at": "2026-06-20T09:00:00Z",
     "state": "held", "decided_by": None, "decided_at": None, "you_may_decide": False,
     "refusal": "You made or approved a change to this account's sign-in details in the last 14 days."},
]


@pytest.fixture
def page_admin(admin):
    """A throwaway administrator who drives the page, deleted afterwards."""
    account = admin.create_user(role="admin")
    yield account
    admin.delete_user(account["id"])


def _login(page: Page, user, skin: str, viewport):
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


def _fake_requests(page: Page, approved: list):
    def listing(route):
        if route.request.method != "GET":
            return route.continue_()
        route.fulfill(status=200, content_type="application/json", body=json.dumps({"held": HELD, "decided": []}))

    def approve(route):
        approved.append(route.request.url)
        route.fulfill(status=200, content_type="application/json", body=json.dumps({
            "request": dict(HELD[0], state="approved"), "username": "bob-sso",
            "handed_over": {"emailed": False, "reset_link": "/reset-password#one-time-link", "expires_in_minutes": 30}}))
    page.route("**/admin/sso/admin-requests", listing)
    page.route("**/admin/sso/admin-requests/*/approve", approve)


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_card_lists_the_requests_and_an_approval_hands_the_reset_link_over(page: Page, page_admin, skin):
    approved = []
    _fake_requests(page, approved)
    _login(page, page_admin, skin, DESKTOP)
    page.evaluate("document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    card = page.locator("#sso-admin-requests")
    expect(card).to_be_visible(timeout=15000)
    expect(card).to_contain_text("Administrator requests from single sign-on")
    bob = card.locator(f'[data-request-id="{HELD[0]["id"]}"]')
    carol = card.locator(f'[data-request-id="{HELD[1]["id"]}"]')
    expect(bob).to_contain_text("bob-sso signed in through Contoso in the group vault-admins, which is mapped to "
                                "the administrator role.")
    # The one this administrator may not decide: its reason, and no buttons.
    expect(carol).to_contain_text("You made or approved a change to this account's sign-in details in the last "
                                  "14 days.")
    expect(carol.get_by_role("button")).to_have_count(0)

    bob.get_by_role("button", name="Approve bob-sso").click()
    modal = page.locator("#confirm-modal.active")
    expect(modal).to_be_visible(timeout=8000)
    expect(modal).to_contain_text("Make bob-sso an administrator?")
    page.click("#confirm-modal-confirm-btn")
    overlay = page.locator(".reset-link-overlay")
    expect(overlay).to_be_visible(timeout=10000)
    expect(overlay).to_contain_text("Password reset link for bob-sso")
    assert overlay.locator("input").input_value().endswith("/reset-password#one-time-link")
    assert len(approved) == 1 and approved[0].endswith(f"/admin/sso/admin-requests/{HELD[0]['id']}/approve")
    overlay.get_by_role("button", name="Close").click()


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_card_fits_a_phone(page: Page, page_admin, skin):
    _fake_requests(page, [])
    _login(page, page_admin, skin, PHONE)
    page.evaluate("document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    card = page.locator("#sso-admin-requests")
    expect(card).to_be_visible(timeout=15000)
    card.scroll_into_view_if_needed()
    widest = card.evaluate("c => Math.max(...[c, ...c.querySelectorAll('*')].map(e => e.getBoundingClientRect().right))")
    assert widest <= page.evaluate("document.documentElement.clientWidth") + 1, "the card fits the phone's screen"
    height = card.get_by_role("button", name="Approve bob-sso").evaluate("b => b.getBoundingClientRect().height")
    assert height >= 40, "the buttons are large enough to tap"
