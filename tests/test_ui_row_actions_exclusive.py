"""A file row offers its actions two ways, and only one of them may be on screen at a time.

Hovering the "more" button slides out a horizontal cluster (rename / copy / move / delete / public
link). Clicking that same button opens the vertical context menu, which offers those actions again
plus Info and Show-hash. They were not exclusive:

  * The cursor is, by definition, still on the button at the moment it is clicked, so
    `.action-more-wrap:hover` was still true and the cluster stayed up underneath the menu — the
    same actions twice, one overlapping the other.
  * `:focus-within` then outlasted the cursor. The clicked button keeps focus, so the cluster
    remained open even after the pointer left the row entirely.

Neither state belongs to the cluster's own element, so app.js marks the document while the menu is
open (openContextMenu / closeContextMenu) and one CSS rule answers both.

Lanes:
  * ui   — the behaviour, in a real browser, walking the whole cycle the report describes: hover,
           click, move away, dismiss, hover again. This is the test that would have caught it.
  * unit — a cheap source guard that the marker is still set AND cleared, and that the CSS still
           suppresses on both :hover and :focus-within. It reads text and proves no behaviour.
"""
import re
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

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


def _showing(page: Page) -> dict:
    """What is actually on screen — computed style, not class names."""
    return page.evaluate(
        """() => {
            const cluster = document.querySelector('.action-cluster');
            const menu = document.getElementById('file-context-menu');
            const visible = (el) => {
                if (!el) return false;
                const s = getComputedStyle(el);
                return s.visibility !== 'hidden' && s.opacity !== '0' && s.display !== 'none';
            };
            return { bar: visible(cluster), menu: !!(menu && !menu.hidden) };
        }"""
    )


@pytest.mark.ui
def test_the_hover_bar_and_the_three_dot_menu_are_never_both_on_screen(
    page: Page, admin_creds, admin, temp_vault
):
    admin.post(
        f"/vaults/{temp_vault['id']}/files",
        files=[("files", ("a.txt", b"x", "application/octet-stream"))],
    )

    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("(id) => openVault(id)", temp_vault["id"])

    more = page.locator(".action-more").first
    more.wait_for(state="visible", timeout=10000)

    # 1. Hovering shows the horizontal quick options. Also the non-vacuous anchor: if this were
    #    false, every "not visible" below would pass for the wrong reason.
    more.hover()
    hovered = _showing(page)
    assert hovered["bar"], f"hovering the button should reveal the quick-action bar: {hovered}"
    assert not hovered["menu"], f"hover alone must not open the menu: {hovered}"

    # 2. Clicking the 3 dots hides the bar and shows only the vertical menu.
    more.click()
    clicked = _showing(page)
    assert clicked["menu"], f"clicking the button should open the menu: {clicked}"
    assert not clicked["bar"], (
        f"the quick-action bar is still showing underneath the menu: {clicked}")

    # 3. It must not come back while the menu is open — this is the half `:focus-within` broke,
    #    because the clicked button keeps focus after the pointer has gone.
    page.mouse.move(5, 5)
    away = _showing(page)
    assert away["menu"], f"moving the cursor away should not close the menu: {away}"
    assert not away["bar"], (
        f"the bar reappeared while the menu was open, after the cursor left: {away}")

    # 4. Clicking elsewhere dismisses the menu, and hovering works normally again afterwards.
    page.mouse.click(5, 5)
    dismissed = _showing(page)
    assert not dismissed["menu"], f"clicking away should close the menu: {dismissed}"
    assert not dismissed["bar"], f"nothing should be showing after dismissal: {dismissed}"

    more.hover()
    again = _showing(page)
    assert again["bar"], f"hovering should reveal the bar again after dismissal: {again}"
    assert not again["menu"], f"hovering must not reopen the menu: {again}"


@pytest.mark.unit
def test_the_open_menu_marker_is_set_cleared_and_honoured_by_the_css():
    """A source guard, not a behaviour test — see this module's docstring."""
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")

    def body_of(fn):
        start = app.index(f"function {fn}(")
        return app[start:app.index("\nfunction ", start + 1)]

    assert "classList.add('ctx-menu-open')" in body_of("openContextMenu"), (
        "openContextMenu must mark the document, or the hover bar stays up behind the menu")
    assert "classList.remove('ctx-menu-open')" in body_of("closeContextMenu"), (
        "closeContextMenu must clear the marker, or the hover bar never works again")

    # Both reveal paths have to be suppressed, on BOTH wrap variants. Naming the four selectors
    # individually is deliberate: an earlier version of this test just looked for the substring
    # ":focus-within .action-cluster" anywhere in the block, and deleting the plain focus-within
    # selector left the .cluster-right one to satisfy it -- the guard passed while the behaviour
    # broke. Mutation caught that; re-reading it never would have.
    suppression = css[css.index("body.ctx-menu-open"):]
    suppression = suppression[:suppression.index("}") + 1]
    for selector in (
        "body.ctx-menu-open .action-more-wrap:hover .action-cluster",
        "body.ctx-menu-open .action-more-wrap:focus-within .action-cluster",
        "body.ctx-menu-open .action-more-wrap.cluster-right:hover .action-cluster",
        "body.ctx-menu-open .action-more-wrap.cluster-right:focus-within .action-cluster",
    ):
        assert selector in suppression, f"the menu-open state must suppress: {selector}"
    assert "visibility: hidden" in suppression, "suppression must actually hide the bar"
