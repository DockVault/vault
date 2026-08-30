"""UI — the Settings page must not invent values for limits the deployment configures.

Env-backed settings are stored as "0 = use the value from the environment". A page that substitutes
the SHIPPED default for a stored 0 does not merely display the wrong number — the next save persists
it and permanently overrides the operator's .env.

Two surfaces enforce this:
  * `session_timeout` and `max_file_size` are still simple env-backed inputs bundled into
    "Save All Changes" — a stored 0 must render BLANK and survive a whole-page save.
  * The login / lockout / vault-unlock / SFTP / API rate limits render in the dedicated **Rate
    limits** section as a read-only deployment value plus an optional custom override. With no override
    set, the custom box is EMPTY, the Override box is UNCHECKED, and the deployment value is shown
    explicitly — the page never copies the deployment value into the (writable) custom field, and its
    own "Save rate limits" persists a custom only for rows the operator actually overrode.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

# Simple env-backed inputs still bundled into "Save All Changes".
SAVE_ALL_ENV_KEYS = ("session_timeout", "max_file_size")
SAVE_ALL_FIELDS = {
    "session_timeout": ("security", "#setting-session-timeout"),
    "max_file_size": ("general", "#setting-max-file-size"),
}

# Rate limits rendered in the Rate limits section (security tab), by their override key.
RATE_LIMIT_KEYS = (
    "max_login_attempts", "lockout_duration", "rate_limit_login_window_seconds",
    "rate_limit_vault_attempts", "rate_limit_vault_attempts_admin",
    "rate_limit_vault_window_seconds", "rate_limit_sftp_key_attempts",
    "rate_limit_api_default", "rate_limit_api_auth",
)

LOAD_SENTINEL = "#setting-password-min-length"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_settings(page: Page, expected_sentinel: str):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.wait_for_function(
        "sel => { const el = document.querySelector(sel); return !!el && el.value !== ''; }",
        arg=LOAD_SENTINEL, timeout=15000,
    )
    expect(page.locator("#save-all-settings-btn")).to_have_attribute(
        "data-settings-ready", "true", timeout=15000
    )
    expect(page.locator(LOAD_SENTINEL)).to_have_value(expected_sentinel)


def _tab(page: Page, tab: str):
    page.click(f'.tab-btn[data-tab="{tab}"]')
    expect(page.locator(f"#settings-tab-{tab}")).to_be_visible()


def _sentinel_value(admin) -> str:
    return str(admin.get("/settings").json().get("password_min_length") or 8)


def _save_all(page: Page):
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT"
    ) as resp:
        page.click("#save-all-settings-btn")
    assert resp.value.ok, f"PUT /settings failed: {resp.value.status}"


def _save_rate_limits(page: Page):
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT"
    ) as resp:
        page.click("#save-rate-limits-btn")
    assert resp.value.ok, f"PUT /settings failed: {resp.value.status}"


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def restore_limits(admin):
    """Always hand the deployment back its env defaults (stored 0), whatever the test did. A small
    max_login_attempts left behind would throttle every later test from their shared address."""
    yield
    admin.put("/settings", json={k: 0 for k in (SAVE_ALL_ENV_KEYS + RATE_LIMIT_KEYS)})


def test_stored_zero_renders_blank_and_no_spurious_custom(page: Page, admin, fresh_admin, restore_limits):
    admin.put("/settings", json={k: 0 for k in (SAVE_ALL_ENV_KEYS + RATE_LIMIT_KEYS)})

    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_settings(page, _sentinel_value(admin))

    # Save-All env fields render blank.
    for key in SAVE_ALL_ENV_KEYS:
        tab, sel = SAVE_ALL_FIELDS[key]
        _tab(page, tab)
        expect(page.locator(sel)).to_have_value("")

    # Rate-limit rows: unchecked, empty custom, deployment value shown, effective == deployment.
    _tab(page, "security")
    for key in RATE_LIMIT_KEYS:
        row = page.locator(f'.rl-row[data-key="{key}"]')
        expect(row).to_have_count(1)
        expect(row.locator(".rl-override")).not_to_be_checked()
        expect(row.locator(".rl-custom")).to_have_value("")
        expect(row.locator(".rl-custom")).to_be_disabled()
        dep = row.locator(".rl-deployment-val").inner_text().strip()
        assert dep != "" and int(dep) >= 0
        assert row.locator(".rl-effective-val").inner_text().strip() == dep

    _save_all(page)   # whole-page save must not persist any rate limit (they are decoupled now)

    stored = admin.get("/settings").json()
    for key in (SAVE_ALL_ENV_KEYS + RATE_LIMIT_KEYS):
        assert stored.get(key, 0) == 0, f"a stored 0 must stay 0; {key}={stored.get(key)!r}"


def test_override_roundtrips_and_untick_clears(page: Page, admin, fresh_admin, restore_limits):
    admin.put("/settings", json={k: 0 for k in RATE_LIMIT_KEYS})

    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_settings(page, _sentinel_value(admin))
    _tab(page, "security")

    key = "rate_limit_vault_attempts"
    row = page.locator(f'.rl-row[data-key="{key}"]')
    # Turn on the override and set a custom value, then save via the section's own button.
    row.locator(".rl-override").check()
    expect(row.locator(".rl-custom")).to_be_enabled()
    row.locator(".rl-custom").fill("9")
    _save_rate_limits(page)
    assert admin.get("/settings").json().get(key) == 9

    # After the save the row reflects the stored override: checked + value 9 + effective 9.
    expect(row.locator(".rl-override")).to_be_checked()
    expect(row.locator(".rl-custom")).to_have_value("9")
    expect(row.locator(".rl-effective-val")).to_have_text("9")

    # Unticking Override and saving clears the custom back to the deployment default.
    dep = row.locator(".rl-deployment-val").inner_text().strip()
    row.locator(".rl-override").uncheck()
    _save_rate_limits(page)
    assert admin.get("/settings").json().get(key, 0) == 0
    expect(row.locator(".rl-override")).not_to_be_checked()
    expect(row.locator(".rl-effective-val")).to_have_text(dep)


def test_configured_override_is_displayed_on_load(page: Page, admin, fresh_admin, restore_limits):
    # A pre-existing custom override renders as checked + populated (page did not invent it, but must
    # show a real one). Deliberately harmless values so an interrupted run cannot throttle later tests.
    configured = {"rate_limit_vault_attempts": 50, "rate_limit_api_default": 100000}
    admin.put("/settings", json=configured)

    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_settings(page, _sentinel_value(admin))
    _tab(page, "security")
    for key, expected in configured.items():
        row = page.locator(f'.rl-row[data-key="{key}"]')
        expect(row.locator(".rl-override")).to_be_checked()
        expect(row.locator(".rl-custom")).to_have_value(str(expected))
        expect(row.locator(".rl-effective-val")).to_have_text(str(expected))
