"""UI — the Settings page must not invent values for limits the deployment configures.

The authentication, upload-size, and general API rate-limit settings below are stored as
"0 = use the value from the environment". The Settings page renders every field it knows and
"Save All Changes" writes back every field it rendered — so a page that
substitutes the SHIPPED default for a stored 0 does not merely display the wrong number, it
persists it on the next save and permanently overrides the operator's .env.

That is what `settings.max_login_attempts || 5` did: an operator who set
RATE_LIMIT_LOGIN_ATTEMPTS=50, opened Settings to change an unrelated field, and clicked Save was
silently dropped to 5 attempts. These tests pin both halves of the contract — a stored 0 stays 0
across a save, and a real configured override is displayed and still round-trips.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

# Settings whose stored 0 means "defer to the deployment env".
ENV_BACKED_KEYS = (
    "max_login_attempts",
    "session_timeout",
    "lockout_duration",
    "max_file_size",
    "rate_limit_api_default",
    "rate_limit_api_default_window",
    "rate_limit_api_auth",
    "rate_limit_api_auth_window",
    "rate_limit_api_upload",
    "rate_limit_api_upload_window",
    "rate_limit_api_download",
    "rate_limit_api_download_window",
)

# Field ids, and which Settings tab each one lives on.
FIELDS = {
    "max_login_attempts": ("security", "#setting-max-login-attempts"),
    "session_timeout": ("security", "#setting-session-timeout"),
    "lockout_duration": ("security", "#setting-lockout-duration"),
    "max_file_size": ("general", "#setting-max-file-size"),
    "rate_limit_api_default": ("security", "#setting-rate-limit-api-default"),
    "rate_limit_api_default_window": ("security", "#setting-rate-limit-api-default-window"),
    "rate_limit_api_auth": ("security", "#setting-rate-limit-api-auth"),
    "rate_limit_api_auth_window": ("security", "#setting-rate-limit-api-auth-window"),
    "rate_limit_api_upload": ("security", "#setting-rate-limit-api-upload"),
    "rate_limit_api_upload_window": ("security", "#setting-rate-limit-api-upload-window"),
    "rate_limit_api_download": ("security", "#setting-rate-limit-api-download"),
    "rate_limit_api_download_window": ("security", "#setting-rate-limit-api-download-window"),
}

# Populated on every load (loadSettings renders it as `password_min_length || 8`). It is a
# positive control for the payload value; data-settings-ready below proves all asynchronous
# population has completed before a blank-field assertion is allowed to pass.
LOAD_SENTINEL = "#setting-password-min-length"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_settings(page: Page, expected_sentinel: str):
    """Open Settings and block until the form has actually been populated from GET /settings."""
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.wait_for_function(
        "sel => { const el = document.querySelector(sel); return !!el && el.value !== ''; }",
        arg=LOAD_SENTINEL, timeout=15000,
    )
    expect(page.locator("#save-all-settings-btn")).to_have_attribute(
        "data-settings-ready", "true", timeout=15000
    )
    # Positive control: the sentinel shows what the server actually returned, so the blank
    # assertions below are being made against freshly loaded data.
    expect(page.locator(LOAD_SENTINEL)).to_have_value(expected_sentinel)


def _tab(page: Page, tab: str):
    page.click(f'.tab-btn[data-tab="{tab}"]')
    expect(page.locator(f"#settings-tab-{tab}")).to_be_visible()


def _sentinel_value(admin) -> str:
    """What the page will render in LOAD_SENTINEL for the current stored settings."""
    return str(admin.get("/settings").json().get("password_min_length") or 8)


def _save_all(page: Page):
    """Click Save All Changes and wait for the PUT to land, asserting it succeeded."""
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT"
    ) as resp:
        page.click("#save-all-settings-btn")
    assert resp.value.ok, f"PUT /settings failed: {resp.value.status}"


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def restore_limits(admin):
    """Always hand the deployment back its env defaults (stored 0), whatever the test did.

    Leaving a small max_login_attempts behind would throttle every later test in the run from the
    single address they all share — the failure mode this file exists to prevent.
    """
    yield
    admin.put("/settings", json={k: 0 for k in ENV_BACKED_KEYS})


def test_stored_zero_survives_a_settings_save(page: Page, admin, fresh_admin, restore_limits):
    """The regression: nothing stored -> the fields render BLANK -> saving leaves them unset.

    Blank is the honest rendering of "the deployment's env decides". Showing 5 here would claim a
    limit that is not in effect, and the save below would then make the claim true.
    """
    admin.put("/settings", json={k: 0 for k in ENV_BACKED_KEYS})
    before = admin.get("/settings").json()
    assert all(before.get(k, 0) == 0 for k in ENV_BACKED_KEYS), before

    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_settings(page, _sentinel_value(admin))
    for key in ENV_BACKED_KEYS:
        tab, sel = FIELDS[key]
        _tab(page, tab)
        expect(page.locator(sel)).to_have_value("")

    _save_all(page)

    stored = admin.get("/settings").json()
    for key in ENV_BACKED_KEYS:
        assert stored.get(key, 0) == 0, (
            f"saving Settings persisted {key}={stored.get(key)!r}; a stored 0 must stay 0, or the "
            f"page silently overrides the deployment's env value"
        )


def test_configured_override_survives_a_settings_save(page: Page, admin, fresh_admin, restore_limits):
    """The other half: a real stored override is displayed and preserved, not reset by a save.

    The values are deliberately harmless if this test were interrupted before its cleanup — a
    HIGHER login limit than the suite needs and a session timeout matching what CI already
    configures — so a failed run here cannot throttle the runs after it.
    """
    configured = {
        "max_login_attempts": 4000,
        "session_timeout": 240,
        "lockout_duration": 1,
        "max_file_size": 4096,
        "rate_limit_api_default": 100000,
        "rate_limit_api_default_window": 120,
        "rate_limit_api_auth": 100000,
        "rate_limit_api_auth_window": 120,
        "rate_limit_api_upload": 100000,
        "rate_limit_api_upload_window": 120,
        "rate_limit_api_download": 100000,
        "rate_limit_api_download_window": 120,
    }
    admin.put("/settings", json=configured)

    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_settings(page, _sentinel_value(admin))
    for key, expected in configured.items():
        tab, sel = FIELDS[key]
        _tab(page, tab)
        expect(page.locator(sel)).to_have_value(str(expected))

    _save_all(page)

    stored = admin.get("/settings").json()
    for key, expected in configured.items():
        assert stored.get(key) == expected, (
            f"saving Settings changed {key} from {expected} to {stored.get(key)!r}"
        )
