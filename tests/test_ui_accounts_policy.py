"""The admin Settings -> Accounts & Access tab renders and behaves.

Covers: the tab opens and its controls render with a live policy summary; the invitation and
self-signup sub-controls enable/disable with their master switches; the signup-domain chip editor
adds and removes domains; the email-change verification toggle is disabled until SMTP is configured;
a save round-trips through reload; and the tab produces no console errors.

Every to_be_disabled()/to_be_enabled() is preceded by a visibility assertion so a MISSING control
can't pass as merely disabled. The save/reload test restores the settings it changed.
"""
import pytest
from playwright.sync_api import Page, expect
from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

TAB = "#settings-tab-accounts"


@pytest.fixture
def restore_settings(admin):
    keys = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
            "signup_email_domain_mode", "signup_email_domains", "login_identifier",
            "email_change_requires_verification", "email_change_otp_ttl_minutes",
            "password_reset_enabled", "password_reset_ttl_minutes", "smtp_server", "from_email")
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in keys}
    yield
    admin.put("/settings", json=snap)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _logout(page: Page):
    page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def _open_accounts_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.click('#sidebar .sidebar-settings-item[data-tab="accounts"]')
    show_advanced(page, "accounts")
    expect(page.locator(TAB)).to_be_visible()
    # The settings load fills the form after the tab shows, and resets anything touched before it
    # lands. This field starts empty and the load always fills it, so it says the load has landed.
    expect(page.locator("#setting-password-reset-ttl-minutes")).not_to_have_value("", timeout=10000)


def test_tab_renders_with_controls_and_summary(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    for sel in ("#setting-invite-enabled", "#setting-signup-enabled", "#setting-invite-ttl-hours",
                "#setting-signup-domain-mode", "#setting-email-requirement",
                "#setting-login-identifier", "#setting-email-change-verification"):
        expect(page.locator(sel)).to_be_visible()
    # the live summary is populated (non-vacuous: not the "—" placeholder)
    expect(page.locator("#accounts-policy-summary")).not_to_have_text("—")


def test_sub_controls_follow_their_master_switches(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    ttl = page.locator("#setting-invite-ttl-hours")
    mode = page.locator("#setting-signup-domain-mode")
    expect(ttl).to_be_visible(); expect(mode).to_be_visible()
    # Wait for the async settings load to finish before toggling: invite-by-link defaults ON, so the
    # load re-checks the box after render — toggling before it settles lets the late load override the
    # click ("clicking did not change its state"). Waiting for the loaded state races it out.
    expect(page.locator("#setting-invite-enabled")).to_be_checked()
    # master OFF -> the sub-control is disabled. Set a known OFF state first (invite now defaults ON),
    # so this tests the follow-the-master behavior independent of the shipped default.
    page.set_checked("#setting-invite-enabled", False)
    expect(ttl).to_be_disabled()
    # The email domain gate also holds invitations and single sign-on providers to it, so it stays editable
    # with self-signup off.
    page.set_checked("#setting-signup-enabled", False)
    expect(mode).to_be_enabled()
    # turning the masters on enables them
    page.set_checked("#setting-invite-enabled", True)
    expect(ttl).to_be_enabled()
    page.set_checked("#setting-signup-enabled", True)
    expect(mode).to_be_enabled()
    # and back off disables again
    page.set_checked("#setting-invite-enabled", False)
    expect(ttl).to_be_disabled()


def test_domain_chip_add_and_remove(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    page.check("#setting-signup-enabled")
    page.select_option("#setting-signup-domain-mode", "allowlist")
    inp = page.locator("#setting-signup-domain-input")
    expect(inp).to_be_enabled()
    inp.fill("Example.COM")
    page.click("#setting-signup-domain-add")
    chip = page.locator("#setting-signup-domains-list .chip", has_text="example.com")
    expect(chip).to_be_visible()          # added, normalized to lowercase
    # adding the same domain again does not duplicate it
    inp.fill("example.com")
    page.click("#setting-signup-domain-add")
    expect(page.locator("#setting-signup-domains-list .chip")).to_have_count(1)
    # remove it
    chip.locator(".chip-remove").click()
    expect(page.locator("#setting-signup-domains-list .chip")).to_have_count(0)


def test_domain_gate_stays_editable_with_self_signup_off(page: Page, admin_creds):
    """Accepting an invitation is held to the gate too, so turning self-signup off leaves it usable."""
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-invite-enabled")).to_be_checked()     # the settings load has landed
    page.set_checked("#setting-signup-enabled", False)
    mode = page.locator("#setting-signup-domain-mode")
    expect(mode).to_be_visible()
    expect(mode).to_be_enabled()
    page.select_option("#setting-signup-domain-mode", "allowlist")
    inp = page.locator("#setting-signup-domain-input")
    expect(inp).to_be_visible()
    expect(inp).to_be_enabled()


# One enabled provider that makes accounts at a first sign-in, holds people to the sign-up list and has no tenant,
# domain or required group of its own: the allow-list is all that says who may sign in through it.
RELYING_PROVIDER = {
    "id": "p-contoso", "name": "Contoso", "label": "Sign in with Contoso", "state": "enabled",
    "policy": {"sso_use_signup_domains": True, "sso_account_creation": "jit", "sso_link_by_email": False,
               "sso_allowed_tenants": [], "sso_allowed_domains": [], "sso_required_groups": []},
}


def _answer_providers(page: Page, providers):
    def handle(route):
        if route.request.method == "GET":
            route.fulfill(status=200, json={"providers": providers, "presets": []})
        else:
            route.continue_()
    page.route("**/admin/sso/providers", handle)


def _settings_puts(page: Page):
    puts = []
    page.on("request", lambda r: puts.append(r.url)
            if r.method == "PUT" and r.url.split("?")[0].endswith("/settings") else None)
    return puts


def test_turning_the_allow_list_off_asks_when_a_provider_relies_on_it(page: Page, admin_creds, admin,
                                                                      restore_settings):
    admin.put("/settings", json={"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.com"]})
    _answer_providers(page, [RELYING_PROVIDER])
    puts = _settings_puts(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-signup-domain-mode")).to_have_value("allowlist")
    page.select_option("#setting-signup-domain-mode", "off")
    page.click("#save-all-settings-btn")
    modal = page.locator("#confirm-modal")
    expect(modal).to_be_visible(timeout=8000)
    expect(page.locator("#confirm-modal-title")).to_have_text("Single sign-on depends on the sign-up list")
    expect(page.locator("#confirm-modal-message")).to_contain_text("“Contoso”")
    expect(page.locator("#confirm-modal-message")).to_contain_text("makes accounts at a first sign-in")
    page.click("#confirm-modal-cancel-btn")
    expect(modal).to_be_hidden()
    page.wait_for_timeout(800)
    assert puts == [], f"a Cancel must send no PUT /settings: {puts}"
    assert admin.get("/settings").json().get("signup_email_domain_mode") == "allowlist"


def test_turning_the_allow_list_off_saves_without_asking_when_no_provider_relies_on_it(
        page: Page, admin_creds, admin, restore_settings):
    admin.put("/settings", json={"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.com"]})
    unticked = dict(RELYING_PROVIDER, policy=dict(RELYING_PROVIDER["policy"], sso_use_signup_domains=False))
    _answer_providers(page, [unticked])
    puts = _settings_puts(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-signup-domain-mode")).to_have_value("allowlist")
    page.select_option("#setting-signup-domain-mode", "off")
    with page.expect_request(lambda r: r.method == "PUT" and r.url.split("?")[0].endswith("/settings"),
                             timeout=8000):
        page.click("#save-all-settings-btn")
    expect(page.locator("#confirm-modal")).to_be_hidden()
    assert len(puts) == 1


def test_email_change_toggle_disabled_without_smtp(page: Page, admin_creds, admin, restore_settings):
    # ensure SMTP is not configured for this check
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    ecv = page.locator("#setting-email-change-verification")
    expect(ecv).to_be_visible()
    expect(ecv).to_be_disabled()          # gated behind SMTP being configured


def test_save_round_trips_through_reload(page: Page, admin_creds, restore_settings):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    # invite-by-link defaults ON — wait for the loaded state before editing (this also races out the
    # async settings load, so the fields below aren't touched while the form is still populating).
    expect(page.locator("#setting-invite-enabled")).to_be_checked()
    page.fill("#setting-invite-ttl-hours", "96")
    page.select_option("#setting-login-identifier", "either")
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1200)           # let the PUT settle
    # fresh session from scratch, then back to the tab — proves it persisted server-side
    _logout(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-invite-enabled")).to_be_checked()
    expect(page.locator("#setting-invite-ttl-hours")).to_have_value("96")
    expect(page.locator("#setting-login-identifier")).to_have_value("either")


def test_password_reset_and_otp_ttl_controls_round_trip(page: Page, admin_creds, restore_settings):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    for sel in ("#setting-password-reset-enabled", "#setting-password-reset-ttl-minutes",
                "#setting-email-change-otp-ttl-minutes"):
        expect(page.locator(sel)).to_be_visible()
    page.check("#setting-password-reset-enabled")
    page.fill("#setting-password-reset-ttl-minutes", "12")
    page.fill("#setting-email-change-otp-ttl-minutes", "9")
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1200)
    _logout(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-password-reset-enabled")).to_be_checked()
    expect(page.locator("#setting-password-reset-ttl-minutes")).to_have_value("12")
    expect(page.locator("#setting-email-change-otp-ttl-minutes")).to_have_value("9")


def test_no_console_errors_on_the_tab(page: Page, admin_creds):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    page.check("#setting-signup-enabled")
    page.select_option("#setting-signup-domain-mode", "denylist")
    page.wait_for_timeout(800)
    assert not errors, f"Accounts & Access tab produced console errors: {errors}"


def test_the_reset_note_shows_exactly_when_there_is_no_public_address(page: Page, admin_creds, admin):
    """Self-service reset emails a link built on the public address: Settings says beside its switch that no reset
    email is sent while ALLOWED_HOSTS is not set, and says nothing when it is."""
    from conftest import public_address_configured
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    note = page.locator("#password-reset-address-note")
    if public_address_configured(admin):
        expect(note).to_be_hidden()
    else:
        expect(note).to_be_visible()
        expect(note).to_contain_text("public address (ALLOWED_HOSTS) is not set")
