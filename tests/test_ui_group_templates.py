"""Creating departments from a template: a proposal you can edit, then exactly what you agreed.

"New Group" keeps working as it always did. An arrow attached to it offers "Load from template",
which shows a choice of preset department sets and then the chosen set AS THE TREE IT WOULD CREATE —
tickable, renameable, extendable. Nothing reaches the server until Create is pressed, so the second
screen is a proposal rather than a report of work already done.

Two things are easy to get wrong here and are asserted directly:

  * What is created must match what the tree SHOWED after editing. An untick that still creates the
    department, or a rename that posts the original name, is the failure that matters — the person
    agreed to one thing and got another.
  * Parents must exist before their children, because a child is created with its parent's id. The
    creation walk is sequential for exactly this reason; firing the posts in parallel would race a
    child against the parent it depends on. Verified against the nested preset, not just a flat one.

Lanes:
  * ui   — the whole path in a real browser: the control, the presets, editing the tree, and the
           groups that exist afterwards.
  * unit — source guards for the split control's markup and for the sequential, parent-first walk.
           They read text and prove no behaviour.
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


def _open_templates(page: Page):
    page.evaluate("() => navigateToSection('groups')")
    page.wait_for_selector("#new-group-split", timeout=15000)
    page.click("#new-group-more")
    page.click("#group-template-open")
    page.wait_for_selector("#group-template-cards .tpl-card", timeout=10000)


def _wait_dialog_closed(page: Page, timeout: int):
    """Wait for the dialog to CLOSE.

    `wait_for_selector("#group-template-modal:not(.active)")` cannot express this. It defaults to
    waiting for the element to be VISIBLE, and a closed modal is hidden — so the selector matches an
    element that never becomes visible, and the wait times out on a feature that worked. Ask about
    the class directly instead.
    """
    page.wait_for_function(
        "() => !document.getElementById('group-template-modal').classList.contains('active')",
        timeout=timeout,
    )


def _group_names(page: Page):
    return page.evaluate("async () => (await apiRequest('/groups', {silent: true})).map(g => g.name)")


@pytest.mark.ui
def test_the_arrow_is_closed_until_asked_and_then_offers_the_template_flow(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => navigateToSection('groups')")
    page.wait_for_selector("#new-group-split", timeout=15000)

    state = page.evaluate(
        """() => {
            const menu = document.getElementById('new-group-menu');
            return {
                main: !!document.getElementById('create-group-btn'),
                arrow: !!document.getElementById('new-group-more'),
                display: menu ? getComputedStyle(menu).display : null,
            };
        }"""
    )
    assert state["main"] and state["arrow"], f"the split control is incomplete: {state}"
    # `.split-btn-menu` sets display, which beats the UA [hidden] rule unless restored — the trap
    # this codebase has now hit three times. Assert the COMPUTED value, not the attribute.
    assert state["display"] == "none", f"the menu must start closed, got {state['display']!r}"

    page.click("#new-group-more")
    opened = page.evaluate(
        "() => getComputedStyle(document.getElementById('new-group-menu')).display")
    assert opened != "none", "the arrow should open the menu"


@pytest.mark.ui
def test_nothing_marked_hidden_is_painting_on_the_pick_screen(page: Page, admin_creds):
    """Ask the browser what is on screen, not the stylesheet what it says.

    The first version of this feature's tests asserted that components.css contained a restoration
    rule for .split-btn-menu — and passed while three sibling controls in the same dialog painted
    anyway, because each carried a class (.btn, .btn-primary, .alert) whose display beat the user
    agent's [hidden] rule. Asserting the CSS text proved the text. This asks the only question that
    matters: with `hidden` set, is it drawn?
    """
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_templates(page)

    # On the pick screen these three are marked hidden and must not be drawn.
    state = page.evaluate(
        """() => {
            const out = {};
            for (const id of ['group-template-back', 'group-template-create', 'group-template-error']) {
                const el = document.getElementById(id);
                out[id] = el ? { hidden: el.hidden, display: getComputedStyle(el).display } : 'MISSING';
            }
            return out;
        }"""
    )
    for name, seen in state.items():
        assert seen != 'MISSING', f"{name} is gone from the dialog"
        assert seen["hidden"] is True, f"{name} should be marked hidden on the pick screen: {seen}"
        assert seen["display"] == "none", (
            f"{name} is marked hidden and still painting as {seen['display']!r} — a class is beating "
            f"the hidden attribute")

    # And the anchor: they DO appear once the screen that owns them is reached, so the assertions
    # above cannot be passing merely because these controls never draw at all.
    page.evaluate(
        """() => [...document.querySelectorAll('#group-template-cards .tpl-card')]
              .find(c => c.querySelector('h4').textContent.includes('Small team')).click()"""
    )
    page.wait_for_selector("#group-template-tree .tpl-node", timeout=10000)
    after = page.evaluate(
        """() => ['group-template-back', 'group-template-create'].map(
               id => getComputedStyle(document.getElementById(id)).display)"""
    )
    assert all(d != "none" for d in after), (
        f"the review screen's own controls must appear once it is shown: {after}")


@pytest.mark.ui
def test_only_what_the_edited_tree_shows_is_created(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_templates(page)

    page.evaluate(
        """() => [...document.querySelectorAll('#group-template-cards .tpl-card')]
              .find(c => c.querySelector('h4').textContent.includes('Small team')).click()"""
    )
    page.wait_for_selector("#group-template-tree .tpl-node", timeout=10000)

    rows = page.evaluate(
        """() => [...document.querySelectorAll('#group-template-tree .tpl-node input[type=text]')]
              .map(i => i.value)"""
    )
    # Non-vacuous anchor: the preset really did land in the tree before we edit it.
    assert len(rows) >= 3, f"the preset should have filled the tree: {rows}"
    before = set(_group_names(page))

    # Drop the last one and rename the first, to a name no preset contains.
    unique = f"Everybody-{int(time.time())}"
    page.evaluate(
        """(name) => {
            const nodes = [...document.querySelectorAll('#group-template-tree .tpl-node')];
            nodes[nodes.length - 1].querySelector('input[type=checkbox]').click();
            const first = nodes[0].querySelector('input[type=text]');
            first.value = name;
            first.dispatchEvent(new Event('input', { bubbles: true }));
        }""",
        unique,
    )
    dropped = rows[-1]
    renamed_from = rows[0]

    page.click("#group-template-create")
    _wait_dialog_closed(page, 20000)

    after = set(_group_names(page))
    created = after - before
    assert unique in created, f"the renamed department should exist: {sorted(created)}"
    assert renamed_from not in created, (
        f"{renamed_from!r} was renamed before Create, so it must not have been created")
    assert dropped not in created, (
        f"{dropped!r} was unticked before Create, so it must not have been created")


@pytest.mark.ui
def test_a_nested_preset_creates_children_under_their_parents(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_templates(page)

    page.evaluate(
        """() => [...document.querySelectorAll('#group-template-cards .tpl-card')]
              .find(c => c.querySelector('h4').textContent.includes('Whole organisation')).click()"""
    )
    page.wait_for_selector("#group-template-tree .tpl-node", timeout=10000)
    page.click("#group-template-create")
    _wait_dialog_closed(page, 40000)

    pairs = page.evaluate(
        """async () => {
            const all = await apiRequest('/groups', { silent: true });
            const byId = Object.fromEntries(all.map(g => [g.id, g.name]));
            return all.filter(g => g.parent_id).map(g => [g.name, byId[g.parent_id] || null]);
        }"""
    )
    as_set = {tuple(p) for p in pairs}
    assert ("Platform", "Engineering") in as_set, f"nesting was lost: {sorted(as_set)[:8]}"
    assert ("Payroll", "Finance") in as_set, f"nesting was lost: {sorted(as_set)[:8]}"
    assert all(parent is not None for _, parent in pairs), (
        "a child was created pointing at a parent that does not exist — the walk must create "
        "parents first")


@pytest.mark.unit
def test_the_split_control_and_the_template_dialog_are_wired():
    """A source guard, not a behaviour test — see this module's docstring."""
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")

    assert 'id="new-group-split"' in html, "the split control is missing"
    assert 'id="create-group-btn"' in html, "the primary New Group action must survive"
    assert 'id="group-template-open"' in html, "the menu must offer the template flow"
    # The dialog's Cancel has to use the class the app actually wires. An attribute nobody reads
    # leaves a button that does nothing, which is how this was first written.
    assert 'id="group-template-cancel"' in html and "close-modal-btn" in html
    assert "data-close-modal" not in html, "that attribute is wired to nothing"
    # The icon has to exist, or the arrow renders empty.
    assert 'symbol id="i-chevron-down"' in html, "the arrow's icon is not defined"
    # One general rule replaced the per-element restorations, this menu's included. Asserting the
    # old targeted selector would now fail on a fix that is strictly better than it.
    utilities = (ROOT / "static" / "css" / "utilities.css").read_text(encoding="utf-8")
    assert "[hidden] { display: none !important; }" in utilities, (
        "the general hidden rule is gone; the menu sets display and would never close")


@pytest.mark.unit
def test_creation_is_sequential_and_parent_first():
    """The ordering the whole feature depends on.

    A child is posted with its parent's id, so the parent must already exist. Awaiting each post
    inside the loop is what guarantees that; mapping the nodes into concurrent promises would look
    tidier and would race.
    """
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = app.index("async function submitGroupTemplate(")
    body = app[start:app.index("\nfunction ", start + 1) if "\nfunction " in app[start:] else len(app)]

    assert "for (const node of nodes)" in body, "the walk must iterate, not fan out"
    assert "await apiRequest('/groups'" in body, "each department must be awaited before the next"
    assert re.search(r"await walk\(node\.children, saved\.id\)", body), (
        "children must be created under the id their parent was just given")
    assert "Promise.all" not in body, (
        "parallel creation races a child against the parent it depends on")
