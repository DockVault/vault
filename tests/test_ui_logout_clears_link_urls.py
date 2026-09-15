"""Signing out must not leave an upload-link URL behind for the next person on this tab.

An upload link's URL is a bearer credential, and the server keeps only a hash of it — so the copy
shown once at creation, held in memory for the drop-vault card's Copy button and left in the
dialog's result field, is the only copy there is. None of that was cleared by logout. On a shared
tab the next person to sign in could open the dialog, or click Copy on the card, and take a working
credential the previous person was told would never be shown again. The same class of residue as
the vault title, which logout already scrubs.

Lanes:
  * ui — create a link in the browser, sign out, and look for it.
"""
import re
import time

import pytest
from playwright.sync_api import Page, expect

from conftest import unique


def _login(page: Page, username: str, password: str):
    """Sign in, waiting out the login rate limit rather than failing on it."""
    for _ in range(8):
        page.fill("#username", username)
        page.fill("#password", password)
        page.click("#login-form button[type=submit]")
        try:
            page.wait_for_selector("#dashboard-screen.active", timeout=8000)
            return
        except Exception:
            msg = page.evaluate(
                "() => (document.getElementById('login-error') || {}).textContent || ''")
            m = re.search(r"(\d+) seconds", msg or "")
            if not m:
                raise AssertionError(f"login failed, and not because of rate limiting: {msg!r}")
            time.sleep(int(m.group(1)) + 3)
    raise AssertionError("login was rate limited on every attempt")


@pytest.mark.ui
def test_signing_out_leaves_no_upload_link_url_behind(page: Page, admin, admin_creds):
    # Restored to what it WAS, not to off: a fresh deployment has upload links on, and a test that
    # switched them off on its way out would make every later test skip for a reason it created.
    before = admin.get("/settings").json().get("public_receivers_enabled")
    admin.put("/settings", json={"public_receivers_enabled": True})
    tag_name = unique("Residue")
    tag = admin.post("/receiver-tags", json={"name": tag_name, "min_token_len": 10,
                                             "auto_enroll_new_users": True, "is_active": True}).json()
    try:
        page.goto("/")
        _login(page, admin_creds["username"], admin_creds["password"])
        expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
        page.locator("#nav-uploadlinks").click()
        page.click("#receiver-new-btn")
        expect(page.locator("#receiver-create-modal")).to_be_visible()
        page.select_option("#rc-tag", label=tag_name)
        page.fill("#rc-max-total-mb", "100")
        page.click("#rc-create")
        expect(page.locator("#rc-result")).to_be_visible(timeout=15000)

        held = page.evaluate(
            """() => ({ field: document.getElementById('rc-link-value').value,
                        session: Object.keys(rcSessionUrls).length,
                        last: state._lastRcUrl || '' })""")
        assert held["field"] and held["session"] == 1 and held["last"], (
            f"anchor: a link should be on screen and in memory before signing out: {held}")
        page.click("#rc-done")

        # Seed the two other remembered URLs too: their Copy handlers fall back to them once the
        # fields are blank, so a scrub that blanked only the fields would leave both copyable.
        page.evaluate("""() => { state._lastPflUrl = 'https://example.invalid/p/file';
                                 state._lastPublicLinkUrl = 'https://example.invalid/n/note'; }""")

        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")
        expect(page.locator("#login-screen")).to_be_visible(timeout=10000)

        after = page.evaluate(
            """() => ({ field: document.getElementById('rc-link-value').value,
                        pfl: (document.getElementById('pfl-link-value') || {}).value || '',
                        note: (document.getElementById('note-public-link-value') || {}).value || '',
                        session: Object.keys(rcSessionUrls).length,
                        last: state._lastRcUrl || '',
                        lastPfl: state._lastPflUrl || '',
                        lastPublic: state._lastPublicLinkUrl || '' })""")
        assert after == {"field": "", "pfl": "", "note": "", "session": 0, "last": "",
                         "lastPfl": "", "lastPublic": ""}, (
            f"a link URL survived logout on this tab: {after}")
    finally:
        admin.put("/settings", json={"public_receivers_enabled": bool(before)})
        admin.delete(f"/receiver-tags/{tag['id']}")
