"""Opening a vault must not move you to a page you were never on.

A vault is reachable from two places: the vault list, and the drop-vault cards under Upload links.
Both ends of the journey were hardcoded to the vault list — `openVault` moved the sidebar to Vaults,
and `closeVault` switched the content section to Vaults and reloaded it. So opening a drop vault
from Upload links claimed you had navigated to Vaults, and Back then stranded you there, having lost
your place on the page you actually came from.

Measured against a live deployment before the fix:

    opened from Upload links   rail=vaults      <- already wrong, before touching Back
    after Back                 vaults-section

The vault now remembers which section it was opened from, `closeVault` returns there, and the nav
state carries it so a refresh inside the vault does not silently revert the answer to Vaults.
Anything unrecognised falls back to Vaults, which is where nearly every open comes from.

Lanes:
  * ui   — open from each origin and check where you land and where Back returns you. The Vaults
           path is asserted too: a fix that redirected everything to Upload links would satisfy the
           report and break the common case.
  * unit — source guards that neither end is hardcoded again. They read text, prove no behaviour.
"""
import re
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page

ROOT = Path(__file__).resolve().parent.parent


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


def _where(page: Page) -> dict:
    return page.evaluate(
        """() => {
            const section = document.querySelector('.content-section.active');
            const rail = document.querySelector('.sidebar-item.active');
            return {
                section: section ? section.id : null,
                rail: rail ? rail.getAttribute('data-section') : null,
            };
        }"""
    )


@pytest.mark.ui
@pytest.mark.parametrize("origin,expected_section", [
    ("uploadlinks", "uploadlinks-section"),
    ("vaults", "vaults-section"),
])
def test_leaving_a_vault_returns_to_the_page_it_was_opened_from(
    page: Page, admin_creds, temp_vault, origin, expected_section
):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])

    page.evaluate("([id, from]) => openVault(id, { from })", [temp_vault["id"], origin])
    page.wait_for_selector("#vault-view-section.active", timeout=15000)

    inside = _where(page)
    # The sidebar was wrong BEFORE Back was ever pressed — that is where this starts.
    assert inside["rail"] == origin, (
        f"opening from {origin} should leave the rail on {origin}, got {inside}")

    page.evaluate("() => closeVault()")
    page.wait_for_selector(f"#{expected_section}.active", timeout=15000)

    after = _where(page)
    assert after["section"] == expected_section, f"Back should return to {origin}: {after}"
    assert after["rail"] == origin, f"the rail should follow Back to {origin}: {after}"


@pytest.mark.unit
def test_neither_open_nor_close_hardcodes_the_vault_list():
    """A source guard, not a behaviour test — see this module's docstring."""
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

    def body_of(fn):
        start = app.index(f"function {fn}(")
        return app[start:app.index("\nfunction ", start + 1)]

    close = body_of("closeVault")
    assert "vaultOriginSection()" in close, (
        "closeVault must return to the section the vault was opened from")
    assert 'getElementById("vaults-section")' not in close and \
           "getElementById('vaults-section')" not in close, (
        "closeVault still forces the vault list")
    assert 'data-section="vaults"]' not in close, "closeVault still forces the Vaults rail item"

    # The drop-vault card must actually declare its origin, or the whole mechanism is inert.
    assert "openVault(r.vault_id, { from: 'uploadlinks' })" in app, (
        "the drop-vault card must say where it is opening from")

    # And a refresh inside the vault must not lose the answer.
    assert re.search(r"from: vaultOriginSection\(\),", app), (
        "the saved nav state must carry the origin, or a refresh reverts Back to the vault list")
    assert "openVault(nav.vaultId, { from: nav.from })" in app, (
        "restoring a view must pass the origin back in")
