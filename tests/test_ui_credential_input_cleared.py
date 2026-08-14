"""A dialog that has closed must not still be holding a secret.

One input, `#confirm-modal-input`, is reused by every prompt in the application — including the
zero-knowledge master passphrase, which the interface itself describes as unrecoverable and as the
only key to every zero-knowledge vault. Closing the dialog hid the field and switched it back to a
text input, but never emptied it, so the passphrase stayed readable in the page.

The overwrite was not reliable either: only another prompt, or a confirm that asks the user to type
something, ever rewrote the value. A plain confirm hid the field and left it alone, so the value
could outlive any number of intervening dialogs.

Two paths had no dismissal at all, and so no clearing: logging out never closes an open dialog
(the screen swap only touches `.screen` elements), and the login form kept the account password for
the whole session after a successful sign-in.

Exploiting any of this needs a second foothold — script injection elsewhere, a hostile browser
extension, a session-replay tool, a crash dump — but the asset is the highest-value secret the
product holds, and the fix is to not keep it.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

INPUT = "#confirm-modal-input"
SECRET = "correct-horse-battery-staple-9271"
VAULT_PW = "vault-access-secret-4417"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _value(page: Page, selector: str = INPUT) -> str:
    """Read the raw DOM value — what someone with page access would read."""
    return page.evaluate("(sel) => document.querySelector(sel).value", selector)


def _open_password_prompt(page: Page):
    page.evaluate(
        "() => { window.__promptResult = showPrompt('Passphrase', 'Unlock',"
        " { password: true }); }"
    )
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
    page.fill(INPUT, SECRET)
    # Non-vacuous anchor: the secret really is in the field before we close it, so an empty value
    # afterwards is the clearing and not a prompt that never received anything.
    assert _value(page) == SECRET


@pytest.fixture
def logged_in(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def test_a_confirmed_passphrase_is_not_left_in_the_page(logged_in: Page):
    page = logged_in
    _open_password_prompt(page)
    page.click("#confirm-modal-confirm-btn")
    # Asserts the VALUE, not merely "not None". The clear now lives inside the same cleanup() the
    # confirm path runs, so the one regression this fix could plausibly cause is reordering the
    # clear above the read — after which every prompt in the app silently resolves to an empty
    # string. `"" is not None` is True, so a truthiness check would not notice.
    assert page.evaluate("() => window.__promptResult") == SECRET, (
        "the prompt resolved with the wrong value — is cleanup() clearing before the read?"
    )
    assert _value(page) == "", "the passphrase is still readable in the DOM after confirming"


def test_a_cancelled_passphrase_is_not_left_in_the_page(logged_in: Page):
    page = logged_in
    _open_password_prompt(page)
    page.click("#confirm-modal-cancel-btn")
    assert _value(page) == "", "the passphrase is still readable in the DOM after cancelling"


def test_a_dismissed_passphrase_is_not_left_in_the_page(logged_in: Page):
    """The header close button carries the global close class, so it fires BOTH the shared
    closeModal() and the prompt's own cancel path. It therefore does not isolate either one — it
    is here to pin that dismissing leaves nothing behind, whichever path does the work."""
    page = logged_in
    _open_password_prompt(page)
    page.click("#confirm-modal-close-btn")
    assert _value(page) == "", "the passphrase is still readable in the DOM after dismissing"


def test_opening_a_plain_confirm_clears_whatever_was_left_behind(logged_in: Page):
    """Isolates the clear on the plain-confirm OPEN path.

    Every close path now clears, so in normal operation the field is already empty by the time a
    confirm opens — which means driving this through a real prompt would prove nothing about this
    line. The value is planted directly instead, standing in for any future path that closes a
    dialog without clearing. Reverting the open-path clear fails this test and nothing else.
    """
    page = logged_in
    page.evaluate(
        "(v) => { document.getElementById('confirm-modal-input').value = v; }", SECRET
    )
    assert _value(page) == SECRET
    page.evaluate("() => { window.__c = showConfirm('Are you sure?', 'Check'); }")
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
    assert _value(page) == "", "a plain confirm is displaying a value left by something else"
    page.click("#confirm-modal-cancel-btn")


def test_a_typed_confirmation_string_is_not_left_in_the_page(logged_in: Page):
    """The confirm primitive clears on close too, so the invariant holds for both.

    Today's callers type back a username rather than a secret, but the two primitives share one
    input and an invariant that holds on only one of them is a refactor away from not holding.
    """
    page = logged_in
    page.evaluate(
        "() => { window.__c2 = showConfirm('Type it', 'Danger', 'DELETE-ME'); }"
    )
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
    page.fill(INPUT, "DELETE-ME")
    assert _value(page) == "DELETE-ME"
    page.click("#confirm-modal-confirm-btn")
    assert page.evaluate("() => window.__c2") is True, "the confirm did not read the typed value"
    assert _value(page) == ""


def test_the_field_is_empty_when_a_prompt_opens(logged_in: Page):
    """Locks pre-existing behaviour; this one does NOT fail if the fix is reverted.

    showPrompt has always assigned `defaultValue || ''` on open, so this passes before and after.
    It is kept as a guard from the other side — if a future change made opening reuse the previous
    value, no other test here would notice — but it is not evidence for this change.
    """
    page = logged_in
    _open_password_prompt(page)
    page.click("#confirm-modal-cancel-btn")
    page.evaluate("() => { window.__p2 = showPrompt('Another', 'Second'); }")
    expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
    assert _value(page) == ""
    page.click("#confirm-modal-cancel-btn")


def test_logging_out_does_not_leave_an_open_prompt_holding_a_passphrase(logged_in: Page):
    """The path with no dismissal at all.

    A session can expire from a background poll while the unlock prompt is open and a master
    passphrase typed. The screen swap only touches `.screen` elements, so the dialog was never
    dismissed and its cleanup never ran — the login screen appeared with the passphrase still in
    the page, ready for whoever uses the tab next.
    """
    page = logged_in
    _open_password_prompt(page)
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    assert _value(page) == "", "the passphrase survived logout into the login screen"
    assert page.locator("#confirm-modal.active").count() == 0, "the dialog is still open"


def test_the_account_password_is_not_kept_after_signing_in(logged_in: Page):
    """Guaranteed residue: every session, every user, with no user action required."""
    page = logged_in
    assert _value(page, "#password") == "", (
        "the account password is still in the login field after signing in"
    )


def test_a_cancelled_vault_password_does_not_linger_until_the_next_open(page: Page, admin_creds):
    """The create-vault dialog already cleared on OPEN, which bounded the value's life to "until
    someone opens this again" — forever, for a user who types one, cancels, and never returns.

    /zk-enabled is stubbed so the password group is guaranteed present and enabled: on a
    zero-knowledge-only deployment the field is hidden and disabled, and fill() would time out
    rather than skip.
    """
    page.route(
        "**/zk-enabled",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=json.dumps({"zero_knowledge_enabled": False, "must_use_zk": False,
                             "plan_zero_knowledge": False,
                             "allowed_vault_types": ["standard"], "zk_idle_lock_minutes": 0}),
        ),
    )
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
    page.evaluate("() => showCreateVault()")
    expect(page.locator("#create-vault-modal.active")).to_be_visible(timeout=10000)

    page.fill("#vault-password", VAULT_PW)
    assert _value(page, "#vault-password") == VAULT_PW

    page.click("#create-vault-modal .modal-footer .close-modal-btn")
    expect(page.locator("#create-vault-modal.active")).to_be_hidden(timeout=10000)
    assert _value(page, "#vault-password") == "", (
        "the typed vault password is still in the page after the dialog closed"
    )


def test_every_dialog_password_field_is_covered_not_just_the_two_that_prompted_this(
    logged_in: Page,
):
    """The helper finds fields by type rather than from a list of ids, so a dialog added later
    cannot opt out by existing. This pins that, and covers the create-user field in particular —
    which had no reset on open OR on cancel, making it a worse case than the one reported.
    """
    page = logged_in
    ids = page.evaluate(
        "() => Array.from(document.querySelectorAll('.modal input[type=\"password\"]'))"
        ".map(el => el.id).filter(Boolean)"
    )
    assert len(ids) >= 8, f"expected the app's dialog password fields, found {ids}"
    assert "new-password" in ids, "the create-user password field should be among them"

    page.evaluate("(ids) => ids.forEach(i => { document.getElementById(i).value = 'x-secret'; })", ids)
    assert all(_value(page, f"#{i}") == "x-secret" for i in ids)

    page.evaluate("() => closeModal()")
    left = [i for i in ids if _value(page, f"#{i}") != ""]
    assert not left, f"these dialog password fields kept their value after closing: {left}"
