"""The upload-link dialog: only Done after the link exists, and a 1 GB budget offered for a new one.

Two separate findings that happen to live in the same dialog.

1. The footer buttons would not hide. `submitReceiver()` has always set `hidden` on Cancel and
   "Create link" the moment the link is created, and cleared it on Done — the JS was correct. But
   `.btn` sets `display: flex`, which beats the user-agent's `[hidden] { display: none }` on
   specificity and source order, so all three stayed on screen: a Cancel that cannot cancel anything
   (the link exists and is already listed) and a spent, disabled "Create link" beside the only
   button that does anything. Measured in a browser before the fix, with `hidden = true` set on each:

       {'rc-cancel': 'flex', 'rc-create': 'flex', 'rc-done': 'flex'}

   The same trap is already documented twice in components.css, for `#copied-items-btn` and the
   copied-items panel. This is the third instance.

2. The total upload budget offered for a NEW link was 100 MB. It is now 1 GB. This fills the field
   only when the chosen tag sets no ceiling of its own; a tag WITH a cap still wins, and a link that
   already exists carries its own stored budget that nothing here revisits.

Lanes:
  * ui   — set `hidden` on each footer button and read the COMPUTED display. That is the only thing
           that distinguishes "the attribute is set" from "the button is gone", and the attribute
           was set correctly the whole time.
  * unit — source guards for the CSS rule and the budget constant. They read text and prove no
           behaviour; the ui lane above is the one that would have caught the button bug.
"""
import re
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page

ROOT = Path(__file__).resolve().parent.parent
FOOTER_BUTTONS = ("rc-cancel", "rc-create", "rc-done")


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
def test_the_dialog_footer_buttons_actually_hide_when_hidden(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])

    shown = page.evaluate(
        """(ids) => {
            const before = {}, after = {};
            for (const id of ids) {
                const el = document.getElementById(id);
                if (!el) { before[id] = after[id] = 'MISSING'; continue; }
                el.hidden = false;
                before[id] = getComputedStyle(el).display;
                el.hidden = true;
                after[id] = getComputedStyle(el).display;
            }
            return { before, after };
        }""",
        list(FOOTER_BUTTONS),
    )

    # Non-vacuous anchor: each button really does render when it is not hidden. Without this,
    # "display: none" below would also be satisfied by a button that never existed.
    for name in FOOTER_BUTTONS:
        assert shown["before"][name] not in ("none", "MISSING"), (
            f"{name} should render when not hidden, got {shown['before'][name]!r}")

    for name in FOOTER_BUTTONS:
        assert shown["after"][name] == "none", (
            f"{name} is still displayed as {shown['after'][name]!r} with hidden set — `.btn` is "
            f"beating the [hidden] rule, so the dialog shows spent buttons beside Done")


@pytest.mark.unit
def test_the_css_restores_hidden_for_the_dialog_footer():
    """A source guard, not a behaviour test — see this module's docstring."""
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")
    rule = re.search(r"^([^\n]*\[hidden\][^\n]*)\{\s*display:\s*none;?\s*\}", css, re.M)
    assert rule, "no [hidden] restoration rule found at all"

    # Every one of the three must be named. Checking that the rule merely mentions "rc-" would pass
    # while two of the buttons stayed visible.
    hidden_rules = "\n".join(
        line for line in css.splitlines() if "[hidden]" in line and "display: none" in line)
    for name in FOOTER_BUTTONS:
        assert f"#{name}[hidden]" in hidden_rules, (
            f"#{name} must have its hidden attribute restored, or it stays on screen next to Done")


@pytest.mark.unit
def test_a_new_upload_link_is_offered_a_one_gigabyte_budget():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

    # Read to the end of the declaration and compare as a NUMBER: matching "= 1024" as text would
    # also be satisfied by "= 10240".
    m = re.search(r"^const RC_DEFAULT_TOTAL_MB = (\d+);", app, re.M)
    assert m, "RC_DEFAULT_TOTAL_MB is not declared on its own line"
    assert int(m.group(1)) == 1024, (
        f"the default budget should be 1 GB expressed in MB, got {m.group(1)}")

    # And the field must actually use it rather than repeating a literal.
    assert "mt.value = mt.value || String(RC_DEFAULT_TOTAL_MB)" in app, (
        "the budget field must fall back to the named constant")
    assert "mt.value = mt.value || '100'" not in app, "the old 100 MB literal is still in place"
