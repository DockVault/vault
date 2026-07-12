"""Create-vault modal: vault-type chooser + conditional password field.

Drives the three deployment states deterministically by intercepting /zk-enabled,
so the tests don't depend on this instance's plan/force configuration:

  * both types creatable     -> real enabled chooser; password shown for standard,
                                hidden (with team-mode shown) when ZK is picked.
  * zero-knowledge forced     -> a clear message instead of a DEAD disabled dropdown;
                                password hidden.
  * zero-knowledge unavailable-> chooser hidden; standard only; password shown.
"""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def logged_in(page: Page, fresh_user):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    return page


def _stub_zk_enabled(page: Page, payload: dict):
    page.route(
        "**/zk-enabled",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(payload)
        ),
    )


def _open_create_vault(page: Page):
    page.evaluate("showCreateVault()")
    expect(page.locator("#create-vault-modal.active")).to_be_visible()


def test_both_types_offer_real_choice_and_toggle_password(logged_in: Page):
    page = logged_in
    _stub_zk_enabled(page, {
        "zero_knowledge_enabled": True, "must_use_zk": False,
        "plan_zero_knowledge": True, "allowed_vault_types": ["standard", "zero_knowledge"],
    })
    _open_create_vault(page)

    # The real, enabled chooser is shown; standard is the default; password visible.
    expect(page.locator("#vault-type-group")).to_be_visible()
    expect(page.locator("#vault-type-choice")).to_be_visible()
    expect(page.locator("#vault-type-forced-note")).to_be_hidden()
    assert page.locator("#vault-type").is_enabled()
    expect(page.locator("#vault-password-group")).to_be_visible()
    expect(page.locator("#vault-hierarchical-wrap")).to_be_hidden()  # team mode is ZK-only

    # Type a partial (too-short) password, THEN switch to zero-knowledge: the password
    # group hides AND the input is DISABLED — so its stale, minlength-invalid value can
    # neither silently block the (non-focusable) Create button nor be submitted for a ZK vault.
    page.fill("#vault-password", "abc")
    page.select_option("#vault-type", "zero_knowledge")
    expect(page.locator("#vault-password-group")).to_be_hidden()
    expect(page.locator("#vault-hierarchical-wrap")).to_be_visible()
    assert page.locator("#vault-password").is_disabled()

    # Switching back to standard restores the password field (enabled + visible).
    page.select_option("#vault-type", "standard")
    expect(page.locator("#vault-password-group")).to_be_visible()
    assert page.locator("#vault-password").is_enabled()
    expect(page.locator("#vault-hierarchical-wrap")).to_be_hidden()


def test_forced_zero_knowledge_shows_message_not_dead_dropdown(logged_in: Page):
    page = logged_in
    _stub_zk_enabled(page, {
        "zero_knowledge_enabled": True, "must_use_zk": True,
        "plan_zero_knowledge": True, "allowed_vault_types": ["standard", "zero_knowledge"],
    })
    _open_create_vault(page)

    # A clear "required" message replaces the interactive chooser (no dead dropdown).
    expect(page.locator("#vault-type-group")).to_be_visible()
    expect(page.locator("#vault-type-forced-note")).to_be_visible()
    expect(page.locator("#vault-type-choice")).to_be_hidden()
    # Password is hidden (ZK uses the browser passphrase flow), team mode is available.
    expect(page.locator("#vault-password-group")).to_be_hidden()
    expect(page.locator("#vault-hierarchical-wrap")).to_be_visible()
    # The effective type the form will submit is zero_knowledge.
    assert page.evaluate("effectiveVaultType()") == "zero_knowledge"


def test_allowlist_without_standard_forces_zero_knowledge(logged_in: Page):
    """An allowlist that omits 'standard' is treated like the force policy."""
    page = logged_in
    _stub_zk_enabled(page, {
        "zero_knowledge_enabled": True, "must_use_zk": False,
        "plan_zero_knowledge": True, "allowed_vault_types": ["zero_knowledge"],
    })
    _open_create_vault(page)
    expect(page.locator("#vault-type-forced-note")).to_be_visible()
    expect(page.locator("#vault-type-choice")).to_be_hidden()
    expect(page.locator("#vault-password-group")).to_be_hidden()
    assert page.evaluate("effectiveVaultType()") == "zero_knowledge"


def test_zero_knowledge_unavailable_hides_chooser_and_shows_password(logged_in: Page):
    page = logged_in
    _stub_zk_enabled(page, {
        "zero_knowledge_enabled": False, "must_use_zk": False,
        "plan_zero_knowledge": False, "allowed_vault_types": ["standard"],
    })
    _open_create_vault(page)

    expect(page.locator("#vault-type-group")).to_be_hidden()
    expect(page.locator("#zk-unavailable-note")).to_be_visible()
    expect(page.locator("#vault-password-group")).to_be_visible()
    assert page.evaluate("effectiveVaultType()") == "standard"
