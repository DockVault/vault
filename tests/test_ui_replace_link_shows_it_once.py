"""Replacing an upload link hands the new URL over the same way creating one does.

It used to open a text prompt and write the new URL to the clipboard on its own. Two things wrong
with that: the person was never asked before their clipboard was overwritten, and the prompt did
not carry the warning the create dialog does — that the link is shown once and cannot be retrieved.
Now both flows use the create dialog's result pane: the warning, the URL, and a Copy button the
person clicks.

The clipboard is observed, not trusted: a stand-in records every write, so the test can say nothing
was written until Copy was pressed, and exactly the shown URL when it was.

Lanes:
  * ui — a link the page has never seen, replaced from its drop-vault card.
"""
import re
import time

import pytest
from playwright.sync_api import Page, expect


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
def test_replace_shows_the_new_link_once_and_copies_only_on_request(page: Page, admin, admin_creds):
    settings = admin.get("/settings").json()
    if settings.get("public_receivers_enabled") is not True:
        pytest.skip("upload links are disabled on this deployment")
    tag = next((t for t in admin.get("/receiver-tags").json()
                if t["name"] in ("Drop vault", "Drop box")), None)
    if tag is None:
        pytest.skip("no open upload-link tag on this deployment")
    # Minted outside the browser, so the page has never held its URL and the card offers Replace.
    rec = admin.post("/receivers", json={"tag_id": tag["id"], "label": "replace-once",
                                         "max_total_bytes": 10 * 1024 * 1024})
    assert rec.status_code in (200, 201), rec.text
    rec = rec.json()

    page.add_init_script(
        """window.__clipboardWrites = [];
           Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
               writeText: (t) => { window.__clipboardWrites.push(t); return Promise.resolve(); } } });""")
    try:
        page.goto("/")
        _login(page, admin_creds["username"], admin_creds["password"])
        expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
        page.locator("#nav-uploadlinks").click()
        page.click('#uploadlinks-section [data-rc-tab="vaults"]')
        card = page.locator("#receivers-vaults .rc-vault-actions", has_text="Replace link").first
        card.wait_for(state="visible", timeout=10000)
        card.get_by_role("button", name="Replace link").click()
        page.click("#confirm-modal-confirm-btn")

        result = page.locator("#rc-result")
        expect(result).to_be_visible(timeout=15000)
        shown = page.evaluate("() => document.getElementById('rc-link-value').value")
        assert "/u/" in shown, f"the new link should be on screen: {shown!r}"
        assert "only once" in result.inner_text() and "cannot be retrieved" in result.inner_text(), (
            "the replacement must carry the same warning as creation")
        assert page.evaluate("() => window.__clipboardWrites") == [], (
            "the new link was written to the clipboard without anyone asking")

        page.click("#rc-copy")
        page.wait_for_function("() => window.__clipboardWrites.length === 1", timeout=5000)
        assert page.evaluate("() => window.__clipboardWrites") == [shown]
    finally:
        admin.post(f"/receivers/{rec['id']}/revoke")
