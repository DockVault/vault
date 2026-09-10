"""Signing out must not leave the previous session's view — or its vault name — on the screen.

`showScreen()` only swaps the `.screen` wrappers (login-screen / dashboard-screen). The active
`.content-section` INSIDE the dashboard screen is a different thing entirely, and `logout()` never
touched it. So the section you were on survived a sign-out, and the next sign-in on that tab landed
straight back on it.

For a vault that view is empty by then, because logout scrubs `state.currentVault` and empties
`#vault-files-table-body` — and nothing reloads it, because `state.currentVault` is null. That is the
reported bug: idle logout while inside a vault, sign back in, and the vault sits there with no files
and no way to get them back short of a refresh.

The header is the worse half and is a leak rather than an annoyance. `#vault-view-title` still held
the previous session's vault NAME, and for a zero-knowledge vault that is the CLIENT-DECRYPTED name —
the one the server is never permitted to see. A different person signing in on a shared tab read it
straight off the screen. That is the same finding as the content scrub logout already does
(F-R015-004); this closes the half that was missed.

Lanes:
  * ui   — the behaviour, in a real browser: open a populated vault, log out, log back in, and check
           where you land and what the header says. This is the test that would have caught it.
  * unit — a cheap source guard so the reset cannot be quietly dropped from `logout()` again. It
           reads text and proves nothing about behaviour; the ui lane above is the real one.
"""
import re
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- helpers

def _login(page: Page, username: str, password: str):
    """Sign in, waiting out the deployment's login rate limit rather than failing on it.

    This test signs in TWICE by design (that is the bug), and the second attempt lands well inside
    the login limiter's window. Without this the test fails on a 429 that has nothing to do with
    what it is checking — which is the kind of failure that gets a test deleted instead of read.
    """
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


def _view(page: Page) -> dict:
    """What a person would see: which section is showing, how many file rows, what the header says."""
    return page.evaluate(
        """() => {
            const active = document.querySelector('.content-section.active');
            const tbody = document.getElementById('vault-files-table-body');
            const title = document.getElementById('vault-view-title');
            return {
                section: active ? active.id : null,
                rows: tbody ? tbody.children.length : -1,
                title: title ? title.textContent : null,
            };
        }"""
    )


# --------------------------------------------------------------------------- ui lane

@pytest.mark.ui
def test_signing_out_of_an_open_vault_does_not_leave_it_on_screen(
    page: Page, admin_creds, admin, temp_vault
):
    vault_id = temp_vault["id"]
    admin.post(
        f"/vaults/{vault_id}/files",
        files=[("files", ("hello.txt", b"hello", "application/octet-stream"))],
    )

    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("(id) => openVault(id)", vault_id)
    expect(page.locator("#vault-view-section")).to_have_class(re.compile(r"\bactive\b"))

    # Non-vacuous anchor: we really are inside a vault that really is listing a file. Without this
    # an "empty afterwards" proves nothing — it could have been empty the whole time.
    inside = _view(page)
    assert inside["section"] == "vault-view-section", inside
    assert inside["rows"] >= 1, f"the vault should be listing the uploaded file: {inside}"
    assert temp_vault["name"] in (inside["title"] or ""), inside

    # The idle path: the session ends and the app signs the user out. This is what apiRequest's own
    # 401 branch calls when the token has expired while the tab sat idle.
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible()

    after_logout = _view(page)
    assert after_logout["section"] == "dashboard-section", (
        f"logout left the previous view active: {after_logout}")
    assert not (after_logout["title"] or ""), (
        f"logout left the previous vault's name in the header: {after_logout['title']!r}")

    # And signing back in lands on the dashboard, not on a hollowed-out vault.
    _login(page, admin_creds["username"], admin_creds["password"])
    after_login = _view(page)
    assert after_login["section"] == "dashboard-section", (
        f"signing back in returned to the stale vault view: {after_login}")
    assert not (after_login["title"] or ""), (
        f"the previous vault's name survived a full sign-out and sign-in: {after_login['title']!r}")


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_logout_resets_the_active_section_and_clears_the_vault_header():
    """A source guard, not a behaviour test — see this module's docstring.

    It exists because the ui lane needs a running deployment and a browser, so on a plain
    `pytest -m unit` run nothing else would notice this being removed.
    """
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = app.index("function logout()")
    body = app[start:app.index("\nfunction ", start + 1)]

    assert "content-section" in body, (
        "logout() must reset the active content section, or the next sign-in on this tab lands "
        "back on the previous session's view")
    assert "dashboard-section" in body, "logout() must leave the dashboard as the active section"
    assert "vault-view-title" in body, (
        "logout() must clear the vault header, which holds the previous session's vault name")
