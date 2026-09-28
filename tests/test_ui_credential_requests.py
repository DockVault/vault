"""The Users page's "Changes waiting for approval" block, in both skins and at phone width.

An administrator may change someone's sign-in details once in 14 days; a second change waits for a
different administrator. The block lists what is waiting:

  * an administrator sees another's request with Approve and Deny, and approving it through the
    confirmation makes the change (the address changes) and takes the request off the list;
  * the administrator who asked sees their own request as waiting, with Withdraw and no Approve, and
    withdrawing it changes nothing;
  * a change made from the page that is held says so, and appears in the block at once;
  * on a phone each request's buttons take their own line, large enough to tap, and nothing in the
    block is wider than the screen.

The page is driven as a THROWAWAY administrator: the skin is applied after sign-in from the account's
stored preference, so a skin chosen against the shared account could be replaced. Each test asserts
the skin that applied. test_credential_change_rule_live.py covers the rule through the API.
"""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique
from _account_change_helpers import psql

pytestmark = pytest.mark.ui

DESKTOP = {"width": 1280, "height": 900}
PHONE = {"width": 390, "height": 844}


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


def _open_users(page: Page):
    # On a phone the sidebar is a drawer; its items are still in the page, so click through script.
    page.evaluate("document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    expect(page.locator("#users-section")).to_be_visible(timeout=10000)
    expect(page.locator(".exp-row").first).to_be_visible(timeout=15000)


def _confirm(page: Page):
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
    page.click("#confirm-modal-confirm-btn")


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_another_administrators_request_is_approved_from_the_block(page: Page, admin, page_admin,
                                                                     temp_user, skin):
    uid = temp_user["id"]
    new_email = f"{unique('approved')}@example.com"
    assert admin.post(f"/users/{uid}/reset-link").status_code == 200           # the first change
    held = admin.patch(f"/users/{uid}", json={"email": new_email})             # the second: held
    assert held.status_code == 202, held.text
    request_id = held.json()["held_changes"][0]["request"]["id"]

    _login(page, page_admin, skin, DESKTOP)
    _open_users(page)
    row = page.locator(f'#credential-requests-block [data-request-id="{request_id}"]')
    expect(row).to_be_visible(timeout=10000)
    expect(row).to_contain_text("Change the email address")
    expect(row).to_contain_text(temp_user["_username"])
    # Under the heading, only what it does not say.
    expect(row.locator(".credential-request-summary")).to_have_text(f"New address: {new_email}")
    expect(row.get_by_role("button", name="Deny")).to_be_visible()
    expect(row.get_by_role("button", name="Withdraw")).to_have_count(0)

    row.get_by_role("button", name="Approve").click()
    _confirm(page)
    expect(row).to_have_count(0, timeout=10000)
    assert admin.get(f"/users/{uid}").json()["email"] == new_email
    assert psql(f"SELECT status, decided_by_name FROM credential_changes WHERE id='{request_id}'") == \
        f"approved|{page_admin['_username']}"


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_a_held_change_made_on_a_phone_shows_as_waiting_and_can_be_withdrawn(page: Page, admin, page_admin,
                                                                           temp_user, skin):
    uid, name = temp_user["id"], temp_user["_username"]
    asker = ApiClient(BASE_URL)
    asker.login(page_admin["_username"], page_admin["_password"])
    first = asker.patch(f"/users/{uid}", json={"email": f"{unique('first')}@example.com"})
    assert first.status_code == 200, first.text                                # the first change: made

    _login(page, page_admin, skin, PHONE)
    _open_users(page)
    page.fill("#users-search", name)
    user_row = page.locator(f'.exp-row[data-id="{uid}"]')
    expect(user_row).to_have_count(1, timeout=10000)
    user_row.click()
    copy = page.locator(f'.copy-reset-link-btn[data-user-id="{uid}"]')
    copy.scroll_into_view_if_needed()
    copy.click()                                                               # the second change
    # Asked as what it is, before anything is sent: the first change was this administrator's own.
    expect(page.locator("#confirm-modal-title")).to_have_text("Ask for approval?", timeout=10000)
    expect(page.locator("#confirm-modal-confirm-btn")).to_have_text("Send for approval")
    expect(page.locator("#confirm-modal-message")).to_contain_text(
        f"You already changed {name}’s sign-in details on")
    expect(page.locator("#confirm-modal-message")).to_contain_text("only when another administrator approves it")
    _confirm(page)

    toast = page.locator(".toast", has_text="waiting for approval").first
    expect(toast).to_be_visible(timeout=10000)
    expect(toast).to_contain_text(f"You already changed {name}")
    said = toast.inner_text()
    assert "by an administrator" not in said and not re.search(r"\d{4}-\d{2}-\d{2}", said), said
    row = page.locator("#credential-requests-block .credential-request-row", has_text=name)
    expect(row).to_have_count(1, timeout=10000)
    expect(row).to_contain_text("Create a password reset link")
    expect(row).to_contain_text("Waiting for another administrator")
    expect(row.get_by_role("button", name="Approve")).to_have_count(0)
    assert psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id='{uid}'") == "0", \
        "a held reset link must not exist yet"

    # On the phone: the buttons on a line of their own, tall enough to tap, and nothing off screen.
    withdraw = row.get_by_role("button", name="Withdraw")
    withdraw.scroll_into_view_if_needed()
    geometry = row.evaluate("""row => {
        const text = row.querySelector('.credential-request-text').getBoundingClientRect();
        const actions = row.querySelector('.credential-request-actions').getBoundingClientRect();
        const button = row.querySelector('.credential-request-actions button').getBoundingClientRect();
        const block = document.getElementById('credential-requests-block');
        let widest = 0;
        for (const el of [block, ...block.querySelectorAll('*')]) {
            widest = Math.max(widest, el.getBoundingClientRect().right);
        }
        return {textBottom: text.bottom, actionsTop: actions.top, buttonHeight: button.height,
                widest, screen: document.documentElement.clientWidth};
    }""")
    assert geometry["actionsTop"] >= geometry["textBottom"] - 1, geometry
    assert geometry["buttonHeight"] >= 40, geometry
    assert geometry["widest"] <= geometry["screen"] + 1, geometry

    withdraw.click()
    _confirm(page)
    expect(row).to_have_count(0, timeout=10000)
    assert psql(f"SELECT status FROM credential_changes WHERE target_user_id='{uid}' AND kind='reset_link'") == \
        "withdrawn"
    assert psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id='{uid}'") == "0"


def test_an_open_users_page_shows_a_request_the_moment_it_is_made(page: Page, admin, page_admin, temp_user):
    """Another administrator's held change reaches an open Users page with its notice, with no reload:
    the request appears with Approve. Before, the notice moved only the bell, and the block showed the
    request after a reload. The socket's nudge is also handed to the page's own frame handler here, as
    the socket does (the frame carries only the notice's type, target and owner), so the test does not
    depend on the socket having connected in time."""
    uid = temp_user["id"]
    _login(page, page_admin, "v2", DESKTOP)
    _open_users(page)
    page.wait_for_timeout(500)                                                 # the block has been read
    assert admin.post(f"/users/{uid}/reset-link").status_code == 200           # the first change
    held = admin.patch(f"/users/{uid}", json={"email": f"{unique('live')}@example.com"})
    assert held.status_code == 202, held.text                                  # the second: held
    request_id = held.json()["held_changes"][0]["request"]["id"]
    row = page.locator(f'#credential-requests-block [data-request-id="{request_id}"]')
    # The page's socket may deliver the real notice first; either way the page must read the list again.
    page.evaluate("""() => handleSocketFrame({ event: { type: 'notification', target: '#users',
        notification_type: 'credential_change_approval_needed', owner_user_id: currentUser.id } })""")
    expect(row).to_be_visible(timeout=10000)
    expect(row.get_by_role("button", name="Approve")).to_be_visible()
    admin.post(f"/admin/credential-requests/{request_id}/deny")               # leave nothing waiting
