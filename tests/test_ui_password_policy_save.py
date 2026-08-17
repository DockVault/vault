"""Opening Settings and pressing Save must not turn on a password policy nobody chose.

The four complexity toggles were rendered from `settings.require_uppercase !== false`. An unset
toggle is `undefined`, and `undefined !== false` is true, so a deployment that had never configured
a policy showed all four CHECKED -- claiming a policy the server was not enforcing, because
`password_policy_errors` treats a missing toggle as off.

That alone would be a display bug. What made it a real one is "Save All Changes": it submits the
rendered state, so an admin who opened Settings to change the session timeout also switched on
uppercase, lowercase, digit and symbol requirements for every account password, without seeing a
prompt about it. The next person who tried to create a user with a simple password got a rejection
nobody had asked for.

It also broke the test suite in a way that looked like something else: the browser lane left the
policy on, and a later UI test that creates a user with a lowercase password failed -- reported as
a create-user bug, with the actual cause several files away.
"""
import json
import os
import subprocess

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

POLICY_KEYS = ("require_uppercase", "require_lowercase", "require_numbers", "require_special")


# The real selectors, taken from tests/test_ui_settings_auth_limits.py rather than guessed. The
# button is #save-all-settings-btn, the tabs are .tab-btn[data-tab=...], and the form is populated
# asynchronously -- so a click before it has loaded reads the empty page, not the settings.
SAVE_BTN = "#save-all-settings-btn"


def _open_settings(page, admin):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    sentinel = str(admin.get("/settings").json().get("password_min_length") or 8)
    page.wait_for_function(
        "expected => { const el = document.querySelector('#setting-password-min-length');"
        " return !!el && el.value === expected; }",
        arg=sentinel, timeout=15000)


def _tab(page, tab):
    page.click('.tab-btn[data-tab="%s"]' % tab)
    expect(page.locator("#settings-tab-%s" % tab)).to_be_visible()


def _save_all(page):
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT"
    ) as resp:
        page.click(SAVE_BTN)
    assert resp.value.ok, "PUT /settings failed: %s" % resp.value.status


def _login(page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _psql(sql):
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    probe = subprocess.run(
        ["docker", "exec", container, "sh", "-c", "echo $POSTGRES_USER; echo $POSTGRES_DB"],
        capture_output=True, text=True, timeout=60)
    if probe.returncode != 0:
        pytest.skip("cannot reach the database container %s" % container)
    lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    out = subprocess.run(
        ["docker", "exec", container, "psql", "-U", lines[0], "-d", lines[1], "-tAc", sql],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, "psql failed: %s" % (out.stderr or "")[:300]
    return out.stdout.strip()


@pytest.fixture
def policy_absent():
    """The four keys ABSENT from the settings blob, which is the state a fresh deployment is in.

    Not `PUT {key: false}`. That was the first attempt and it made the tests vacuous: the old code
    read `settings.require_uppercase !== false`, and an explicit false satisfies that correctly.
    The bug needs the key MISSING, so `undefined !== false` is true. Setting them false destroyed
    the very condition under test, and all three tests passed against the unfixed build.

    Removed from the JSON blob directly, and the whole blob is restored afterwards, because the API
    has no way to un-set a key -- only to set it to something.
    """
    before = _psql("SELECT value FROM system_settings WHERE key = 'global'")
    if not before:
        pytest.skip("this deployment has no global settings row")
    stripped = json.loads(before)
    for key in POLICY_KEYS:
        stripped.pop(key, None)
    _psql("UPDATE system_settings SET value = %s WHERE key = 'global'"
          % _sql_literal(json.dumps(stripped)))
    yield
    _psql("UPDATE system_settings SET value = %s WHERE key = 'global'" % _sql_literal(before))


def _sql_literal(text):
    return "'" + text.replace("'", "''") + "'"


def test_an_unset_policy_renders_unchecked(page: Page, admin, admin_creds, policy_absent):
    """The display half: the page must show what is enforced, not a stricter guess."""
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_settings(page, admin)
    _tab(page, "security")

    for key in POLICY_KEYS:
        box = page.locator("#setting-%s" % key.replace("_", "-"))
        expect(box).not_to_be_checked()


def test_saving_settings_does_not_switch_the_policy_on(page: Page, admin, admin_creds,
                                                       policy_absent):
    """The half that bit: Save submits the rendered state.

    Nothing here touches the Security tab. An admin saving an unrelated change must not come away
    with a password policy they never chose.
    """
    before = admin.get("/settings").json()
    assert not any(before.get(key) for key in POLICY_KEYS), (
        "the policy is already on, so this cannot show that saving turned it on: %s"
        % {k: before.get(k) for k in POLICY_KEYS})

    _login(page, admin_creds["username"], admin_creds["password"])
    _open_settings(page, admin)
    _save_all(page)

    after = admin.get("/settings").json()
    switched_on = [key for key in POLICY_KEYS if after.get(key)]
    assert not switched_on, (
        "opening Settings and pressing Save turned on %s. An operator who changed the session "
        "timeout would find account passwords rejected for reasons they never configured."
        % ", ".join(switched_on))


def test_a_policy_that_was_configured_is_still_preserved(page: Page, admin, admin_creds,
                                                         policy_absent):
    """The other direction, so the fix cannot become "always render unchecked".

    A deployment that DID configure a policy must see it, and saving must keep it.
    """
    admin.put("/settings", json={"require_uppercase": True, "require_numbers": True})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_settings(page, admin)
    _tab(page, "security")
    expect(page.locator("#setting-require-uppercase")).to_be_checked()
    expect(page.locator("#setting-require-numbers")).to_be_checked()
    expect(page.locator("#setting-require-lowercase")).not_to_be_checked()

    _save_all(page)

    after = admin.get("/settings").json()
    assert after.get("require_uppercase") is True and after.get("require_numbers") is True, after
    assert not after.get("require_lowercase"), after
