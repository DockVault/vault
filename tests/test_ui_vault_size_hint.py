"""The create-vault size hint only promises "you can change this later" to someone who can.

Changing a vault's size limit afterwards is PATCH /vaults/{id}/settings — not PATCH /vaults/{id},
which only edits name and description. That endpoint is gated by the VAULT_SETTINGS group, the
vault.change_expiry cap, and an OWNER-ONLY check with no admin arm. Here the owner check is
satisfied by construction, since whoever creates the vault owns it, so VAULT_SETTINGS is the whole
question for this dialog.

Worth stating plainly, because it is easy to get backwards: VAULT_SETTINGS is a role default for
BOTH `user` and `admin`, exactly like VAULT_CREATE. On a default deployment every account that can
open this dialog can also change the limit later, so the clause is true for them and is shown. It
is withheld only where an administrator has deliberately revoked the group — which is the case
this gate exists for, and the case test_user_without_the_group_is_not_promised_it pins.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

NOTE = "#vault-size-avail"
CLAUSE = "you can change it later"
BASE = "The most this vault may hold."
# The NEGATIVE assertions match on "later" rather than the exact clause. The previous wording was
# "changeable later in policies", so an exact-clause check would have passed against the old build
# for the wrong reason — absence of a phrase that never existed there, not absence of a promise.
PROMISE = "later"


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_create_vault(page: Page):
    """Open the dialog and return the note text ONLY once the async render has landed.

    Anchoring on text does not work here, and both obvious choices are traps:

    * BASE is now also the opening of the static markup, so waiting for it is satisfied instantly
      by the un-rendered node — the wait would be a no-op and a slow fetch would leave every
      assertion reading the placeholder.
    * The account-headroom sentence is absent for most accounts. Measured on a default deployment:
      a fresh non-admin gets available_bytes=null with budget_exempt=false, and
      renderVaultSizeAvailability then writes the base text and nothing else. For a reader without
      the clause that settled text is byte-identical to the static markup, so "wait until the text
      changes" would hang forever.

    So the anchor is the network response that feeds the render. After it resolves, the awaited
    continuation writes textContent in a microtask; the short settle below covers that hop and is
    tied to a real event rather than being a bare guess at how slow the box is.
    """
    page.click('.sidebar-item[data-section="vaults"]')
    with page.expect_response(lambda r: "/account/storage" in r.url and r.status == 200):
        page.evaluate("() => showCreateVault()")
    expect(page.locator("#create-vault-modal.active")).to_be_visible(timeout=10000)
    page.wait_for_timeout(300)
    return page.locator(NOTE).inner_text()


def test_admin_is_promised_the_later_change(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    note = _open_create_vault(page)
    assert CLAUSE in note, note
    assert note.startswith(BASE), note


def test_ordinary_user_is_also_promised_it(page: Page, fresh_user):
    """NOT admin-only, and deliberately so: VAULT_SETTINGS is a role default for `user` too, and
    the creator owns what they create, so an ordinary user genuinely can change the limit later.
    Hiding this from them would withhold a true statement."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    note = _open_create_vault(page)
    assert CLAUSE in note, note


def test_user_without_the_group_is_not_promised_it(page: Page, admin, fresh_user):
    """The case the gate exists for: an administrator has revoked VAULT_SETTINGS."""
    r = admin.delete(f"/permissions/users/{fresh_user['id']}/revoke/VAULT_SETTINGS")
    assert r.status_code < 300, (r.status_code, r.text)
    # Non-vacuous anchor: prove the revoke actually landed, so a hint missing for some unrelated
    # reason cannot pass this test.
    perms = admin.get(f"/permissions/users/{fresh_user['id']}").json()
    groups = {p["endpoint_group"] for p in perms.get("permissions", perms)} if isinstance(
        perms, dict) else {p["endpoint_group"] for p in perms}
    assert "VAULT_SETTINGS" not in groups, groups

    _login(page, fresh_user["_username"], fresh_user["_password"])
    note = _open_create_vault(page)
    assert PROMISE not in note.lower(), (
        f"a user who cannot change it must not be told they can, in any wording: {note}"
    )
    # The rest of the hint — including the account-headroom sentence — must survive; the clause is
    # all that is withheld.
    assert note.startswith(BASE), note


def test_scoped_temp_credential_is_never_promised_later(page: Page, admin):
    """A temp credential authenticates as its owner, so hasPermission() would report the OWNER's
    authority. The promise is withheld outright: the credential expires, so "later" is a claim
    this dialog cannot honestly make for it."""
    scope = {"v": 1, "pages": ["dashboard", "vaults"], "caps": ["vault.create"],
             "vault_caps_default": ["vault.see_info"], "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all",
        "selected_vaults": []}).json()
    try:
        _login(page, body["temp_username"], body["credential"])
        # Non-vacuous anchor: prove this really is the scoped-temp shape before asserting absence.
        expect(page.locator('.sidebar-item[data-section="settings"]')).to_be_hidden()
        note = _open_create_vault(page)
        assert PROMISE not in note.lower(), f"an expiring credential must not be promised: {note}"
        assert note.startswith(BASE), note
    finally:
        admin.post(f"/temp-creds/{body['temp_username']}/delete")


def test_static_markup_carries_the_ungated_wording(page: Page, admin_creds):
    """Before the storage fetch settles, the note must not claim something it may then withdraw."""
    _login(page, admin_creds["username"], admin_creds["password"])
    initial = page.evaluate(
        "() => document.querySelector('#vault-size-avail').textContent.trim()"
    )
    assert PROMISE not in initial.lower(), f"static markup pre-promises the clause: {initial}"
    assert initial.startswith(BASE), initial
