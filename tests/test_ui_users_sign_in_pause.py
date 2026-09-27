"""The Users page for an account whose new sign-ins failed sign-ins have paused, in both skins.

A pause is not an administrator's lock: it refuses new sign-ins and leaves the account's sessions
running. The page shows the difference and offers both actions:

  * the row says "Sign-ins paused", not "Locked", and the details say what is paused and until when;
  * Unlock clears the pause (every automatic lock on the account goes) and leaves the account
    unlocked;
  * Lock is still offered, and makes it an administrator's lock, which ends the account's session.

The page is driven as a THROWAWAY administrator, so the skin chosen before sign-in is the one that
applies. test_smart_lockout_live.py covers the pause itself.
"""
import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import arm_lock, lock_rows, signed_in

pytestmark = pytest.mark.ui


@pytest.fixture
def page_admin(admin):
    account = admin.create_user(role="admin")
    yield account
    admin.delete_user(account["id"])


def _login(page: Page, user, skin: str):
    page.set_viewport_size({"width": 1280, "height": 900})
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


def _open_account(page: Page, user):
    page.evaluate("document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    expect(page.locator(".exp-row").first).to_be_visible(timeout=15000)
    page.fill("#users-search", user["_username"])
    row = page.locator(f'.exp-row[data-id="{user["id"]}"]')
    expect(row).to_have_count(1, timeout=10000)
    return row


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_a_paused_account_offers_unlock_and_lock_and_unlock_clears_the_pause(page: Page, page_admin,
                                                                            temp_user, skin):
    uid = temp_user["id"]
    arm_lock(uid, "*")
    _login(page, page_admin, skin)
    row = _open_account(page, temp_user)
    expect(row.locator(".sign-in-block-badge")).to_be_visible()
    expect(row).not_to_contain_text("Locked")
    row.click()
    expect(page.locator(f'.credential-change-note[data-user-id="{uid}"]')).to_contain_text(
        "New sign-ins are paused from every address")
    expect(page.locator(f'.lock-user-btn[data-user-id="{uid}"]')).to_be_visible()
    page.locator(f'.unlock-user-btn[data-user-id="{uid}"]').click()

    expect(page.locator(f'.exp-row[data-id="{uid}"] .sign-in-block-badge')).to_have_count(0, timeout=10000)
    assert lock_rows(uid) == {}, "Unlock clears every automatic lock on the account"


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_locking_a_paused_account_ends_its_session(page: Page, admin, page_admin, temp_user, skin):
    uid = temp_user["id"]
    session = signed_in(temp_user)
    arm_lock(uid, "*")
    assert session.get("/users/me").status_code == 200, "a pause leaves the session running"

    _login(page, page_admin, skin)
    _open_account(page, temp_user).click()
    page.locator(f'.lock-user-btn[data-user-id="{uid}"]').click()
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
    expect(page.locator("#confirm-modal-message")).to_contain_text("signed out everywhere")
    page.click("#confirm-modal-confirm-btn")

    expect(page.locator(f'.exp-row[data-id="{uid}"]')).to_contain_text("Locked", timeout=10000)
    assert admin.get(f"/users/{uid}").json()["is_locked"] is True
    assert session.get("/users/me").status_code in (401, 403), "an administrator's lock ends the session"
    admin.patch(f"/users/{uid}", json={"is_locked": False})
