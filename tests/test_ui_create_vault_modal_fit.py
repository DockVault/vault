"""Create-vault modal: the Cancel / Create Vault buttons stay reachable without scrolling.

A .modal-content caps at 90vh and scrolls as one block, so a tall form pushes its own footer out
of view. Measured before the fix, at 1280px wide with the vault-type chooser shown, the dialog
needed 817px on the Classic skin and 689px on Console: Classic overflowed at 900, 800 and 700px
of viewport height, and Console overflowed at 700.

Two things these tests are careful about:

* The tallest state is forced by stubbing /zk-enabled, the way test_ui_create_vault_modal.py does,
  so they neither depend on this deployment's plan/policy nor mutate settings other tests inherit.
* They log in as a THROWAWAY user, not the shared admin. applyServerPreferences() overwrites the
  skin and theme from the account's stored preferences after login — and reloads the page when the
  skin differs — so a localStorage choice made against a shared account is silently discarded if
  anyone ever persisted a preference on it. Every skin-sensitive test also re-asserts the skin
  that actually applied, so a wrong-skin run fails loudly instead of quietly measuring the other
  one.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

# Both types creatable -> the vault-type chooser renders, which is the tallest form state.
_ZK_BOTH = {
    "zero_knowledge_enabled": True,
    "must_use_zk": False,
    "plan_zero_knowledge": True,
    "allowed_vault_types": ["standard", "zero_knowledge"],
    "zk_idle_lock_minutes": 0,
}


@pytest.fixture
def fresh_user(admin):
    """A throwaway account with no stored UI preferences (see the module docstring)."""
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def fresh_client(fresh_user):
    """An API client for the throwaway account.

    Needed because a vault this user creates in the browser is owned by THEM: /vaults lists only
    what the caller can reach, so an admin client does not see it and cannot be used to verify or
    clean it up.
    """
    from conftest import ApiClient

    c = ApiClient()
    c.login(fresh_user["_username"], fresh_user["_password"])
    return c


def _stub_zk_enabled(page: Page, payload: dict):
    page.route(
        "**/zk-enabled",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(payload)
        ),
    )


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _prepare(page: Page, user, skin: str = "v2", theme: str = "light"):
    """Log in with an explicit skin + theme, then open the create-vault modal in its tallest state.

    The skin is read from localStorage key `ui` by ui-boot.js pre-paint, so it must be set on a
    loaded page and then re-entered — setting it after boot would not re-link the stylesheet.
    """
    page.goto("/")
    page.evaluate(
        "([ui, th]) => { localStorage.setItem('ui', ui); localStorage.setItem('theme', th); }",
        [skin, theme],
    )
    _stub_zk_enabled(page, _ZK_BOTH)
    _login(page, user["_username"], user["_password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.evaluate("() => showCreateVault()")
    expect(page.locator("#create-vault-modal.active")).to_be_visible(timeout=10000)
    # The chooser is revealed by an awaited fetch; waiting for it makes this the tall state for
    # real rather than racing it. Without this the measurements below would be of the SHORT form,
    # which never overflowed and would make the whole file vacuous.
    expect(page.locator("#vault-type-group")).to_be_visible(timeout=10000)
    applied = page.evaluate("() => document.documentElement.getAttribute('data-ui') || 'v1'")
    assert applied == skin, f"skin {skin!r} did not apply (got {applied!r}) — server prefs won"
    return page


def _fit(page: Page) -> dict:
    """Geometry of the dialog, its scroller, and the footer.

    `footerBelowContent` is the assertion that carries the weight at normal viewports:
    getBoundingClientRect() reports layout geometry and is blind to an ancestor's overflow
    clipping, so a footer can sit inside the viewport while being clipped out of sight by
    .modal-content. The dialog is centred with margin to spare, so a viewport-only check would
    pass in exactly the case that breaks.

    Note `contentTallerThanBox` means the content does not fit — NOT that the user can scroll it.
    scrollHeight/scrollTop/getBoundingClientRect are all identical between `overflow-y: auto` and
    `overflow: hidden` (scrollTop is settable programmatically either way), which is measured and
    recorded in test_the_dialog_keeps_a_usable_last_resort_scroller below.
    """
    return page.evaluate(
        """() => {
          const c = document.querySelector('#create-vault-modal .modal-content');
          const b = document.querySelector('#create-vault-modal .modal-body');
          const f = document.querySelector('#create-vault-modal .modal-footer');
          const fr = f.getBoundingClientRect(), cr = c.getBoundingClientRect();
          return {
            contentTallerThanBox: c.scrollHeight > c.clientHeight + 1,
            bodyScrolls: b.scrollHeight > b.clientHeight + 1,
            overflowY: getComputedStyle(c).overflowY,
            footerInViewport: fr.top >= 0 && fr.bottom <= window.innerHeight,
            footerBelowContent: fr.bottom > cr.bottom + 1,   // clipped by the dialog's overflow
            viewportH: window.innerHeight,
            skin: document.documentElement.getAttribute('data-ui') || 'v1',
          };
        }"""
    )


@pytest.mark.parametrize("skin", ["v1", "v2"])
@pytest.mark.parametrize("height", [900, 800, 700])
def test_footer_reachable_without_scrolling_in_the_tallest_state(page, fresh_user, skin, height):
    page.set_viewport_size({"width": 1280, "height": height})
    _prepare(page, fresh_user, skin=skin)
    fit = _fit(page)
    # The dialog itself must never be the scroller — that is what hid the buttons.
    assert not fit["contentTallerThanBox"], f"the dialog itself overflows: {fit}"
    assert fit["footerInViewport"], f"footer is not fully on screen: {fit}"
    assert not fit["footerBelowContent"], f"footer is clipped by the dialog: {fit}"


def test_layout_holds_in_dark_mode(page, fresh_user):
    """Dark mode is colours-only today; this guards against a future rule changing box metrics."""
    page.set_viewport_size({"width": 1280, "height": 800})
    _prepare(page, fresh_user, skin="v1", theme="dark")
    assert page.evaluate("() => document.documentElement.getAttribute('data-theme')") == "dark"
    fit = _fit(page)
    assert not fit["contentTallerThanBox"], fit
    assert fit["footerInViewport"], fit
    assert not fit["footerBelowContent"], fit


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_body_scrolls_instead_of_the_dialog_when_space_runs_out(page, fresh_user, skin):
    """At a height where the form genuinely cannot fit, the body scrolls and the footer stays."""
    page.set_viewport_size({"width": 1280, "height": 420})
    _prepare(page, fresh_user, skin=skin)
    fit = _fit(page)
    assert fit["bodyScrolls"], f"expected the body to be the scroller at 420px: {fit}"
    assert not fit["contentTallerThanBox"], f"the dialog itself must still fit: {fit}"
    assert fit["footerInViewport"], f"footer must stay on screen even here: {fit}"
    assert not fit["footerBelowContent"], f"footer is clipped by the dialog: {fit}"


# The height at which even header + footer alone exceed 90vh differs per skin, because their
# padding does: Classic's chrome is ~199px, Console's ~99px. Measured, not guessed — at 200px the
# Console dialog still fits comfortably, so a shared height would have left the v2 case silently
# not exercising this at all. The self-check inside the test enforces that.
@pytest.mark.parametrize("skin,height", [("v1", 200), ("v2", 100)])
def test_the_dialog_keeps_a_usable_last_resort_scroller(page, fresh_user, skin, height):
    """The degenerate case: header + footer alone exceed 90vh.

    Both are `flex: 0 0 auto` and floored at content height, so something must give. The dialog
    keeps `overflow-y: auto` precisely so this degrades to a scrollbar rather than clipping the
    buttons away with no way to reach them — the failure ui-v2.css records from a prior incident.
    A viewport this small is reachable at high browser zoom (a WCAG 1.4.10 reflow case).

    This assertion is STRUCTURAL, on the computed property, and deliberately so. The behavioural
    difference is not observable from the page: with `overflow: hidden` the element still reports
    scrollHeight > clientHeight, still accepts a programmatic scrollTop, and lays the footer out in
    exactly the same place. That was measured against a mutated build — every geometric signal was
    byte-identical between `auto` and `hidden`, and only getComputedStyle told them apart. So a
    geometry-based test here would pass against the broken build and read as coverage it does not
    have.
    """
    page.set_viewport_size({"width": 1280, "height": height})
    _prepare(page, fresh_user, skin=skin)
    fit = _fit(page)
    assert fit["contentTallerThanBox"], (
        f"{height}px should not fit — if it does, this test no longer exercises the case: {fit}"
    )
    assert fit["overflowY"] in ("auto", "scroll"), (
        f"the dialog must stay user-scrollable when even its chrome does not fit: {fit}"
    )


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_description_defaults_to_one_row_and_stays_resizable(page, fresh_user, skin):
    _prepare(page, fresh_user, skin=skin)
    info = page.evaluate(
        """() => {
          const ta = document.querySelector('#vault-desc');
          const cs = getComputedStyle(ta);
          const name = document.querySelector('#vault-name');
          return {
            tag: ta.tagName, rows: ta.rows,
            height: ta.getBoundingClientRect().height,
            inputHeight: name.getBoundingClientRect().height,
            resize: cs.resize,
          };
        }"""
    )
    assert info["tag"] == "TEXTAREA", "must stay a textarea, not become a single-line input"
    assert info["rows"] == 1, f"description should default to one row: {info}"
    # Anchored to the sibling single-line input rather than a magic pixel number, so this keeps
    # meaning if padding or font size changes: one row plus padding, not three.
    assert info["height"] < info["inputHeight"] * 1.6, f"not a one-line box: {info}"
    # Only the v1 case exercises the new rule: Console already declares `resize: vertical` for all
    # textareas, while Classic has no matching declaration and falls through to the UA default
    # `both`, which lets a horizontal drag push the field outside the dialog. The v2 case is a
    # lock on existing behaviour, not a test of the change.
    assert info["resize"] == "vertical", f"resize should be vertical-only: {info}"


def test_description_still_accepts_newlines_and_round_trips(page, fresh_user, fresh_client):
    """One row is a default height, not a change of field type — multi-line input must survive."""
    _prepare(page, fresh_user)
    name = "modal-fit-multiline"
    page.fill("#vault-name", name)
    page.fill("#vault-desc", "first line\nsecond line")
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden(timeout=15000)

    def _find():
        return next((v for v in fresh_client.get("/vaults").json() if v["name"] == name), None)

    try:
        created = _find()
        assert created, f"vault {name} was not created"
        assert created["description"] == "first line\nsecond line", created["description"]
    finally:
        # Re-resolve, so the vault is cleaned up even if the lookup above raised first.
        leftover = _find()
        if leftover:
            fresh_client.delete_vault(leftover["id"])


def test_reopening_resets_every_field_including_the_password(page, fresh_user):
    """Only a SUCCESSFUL create used to reset the form, so a cancelled one kept what was typed.

    The password is the field that matters here, not the description: it is the one with a
    security cost to leaving in the DOM.
    """
    _prepare(page, fresh_user)
    page.fill("#vault-name", "abandoned-name")
    page.fill("#vault-desc", "typed then abandoned")
    page.fill("#vault-password", "abandoned-secret-123")
    page.fill("#vault-size-gb", "7")
    # Team mode is a zero-knowledge-only control and is hidden while the type is standard, so the
    # type has to be switched before it can be touched at all.
    page.select_option("#vault-type", "zero_knowledge")
    page.check("#vault-hierarchical")

    page.click("#create-vault-modal .modal-footer .close-modal-btn")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden(timeout=10000)

    page.evaluate("() => showCreateVault()")
    expect(page.locator("#create-vault-modal.active")).to_be_visible(timeout=10000)
    expect(page.locator("#vault-type-group")).to_be_visible(timeout=10000)
    assert page.input_value("#vault-name") == "", "a reopened modal must not keep the old name"
    assert page.input_value("#vault-desc") == "", "a reopened modal must not keep the old text"
    assert page.input_value("#vault-password") == "", "the typed password must not survive"
    # Read .checked directly: the control is hidden again now the type is back to standard.
    assert page.evaluate("() => document.querySelector('#vault-hierarchical').checked") is False
    assert page.input_value("#vault-type") == "standard", "the type must fall back to standard"
    assert page.evaluate("() => document.querySelector('#vault-desc').rows") == 1
    # The size input has value="1" in markup, so reset() restores it rather than emptying it —
    # which is only meaningful because it was changed to 7 above.
    assert page.input_value("#vault-size-gb") == "1"
