"""The admin 'Log access' Settings tab, end to end through the real UI.

Logs in as admin, opens Settings -> Log access, toggles a component flag (persists via
PUT /settings/logs), generates a token (the plaintext is revealed ONCE and the list shows
only its prefix), and disables it. Cleans up the minted token.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import skip_for_older_deployment


def _endpoint_present(admin):
    return admin.get("/settings/logs").status_code == 200


def _ceiling_on(admin):
    r = admin.get("/settings/logs")
    return r.status_code == 200 and bool(r.json().get("ceiling"))


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_log_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="logs"]')
    expect(page.locator("#settings-tab-logs")).to_be_visible(timeout=10000)


def test_log_access_tab_generate_and_disable(page: Page, admin_creds, admin):
    if not _endpoint_present(admin):
        skip_for_older_deployment("running vault image predates the log-pull endpoint")
    if not _ceiling_on(admin):
        pytest.skip("the mint UI is now gated on the log ceiling; needs a ceiling-on instance")

    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)

    # the component flags render (at least web + sftp checkboxes)
    flags = page.locator("#log-flags input[type=checkbox]")
    expect(flags.first).to_be_visible(timeout=10000)
    assert flags.count() >= 2

    # generate a token
    page.click("#log-token-generate-btn")
    expect(page.locator("#log-token-generate-panel")).to_be_visible()
    unique_name = "ui-tok-" + page.evaluate("() => String(Date.now())")
    page.fill("#log-token-name", unique_name)
    # scope checkboxes default checked (web/sftp) — leave as-is
    page.click("#log-token-create-btn")

    # the plaintext is revealed exactly once
    reveal = page.locator("#log-token-value")
    expect(reveal).to_be_visible(timeout=10000)
    plaintext = reveal.inner_text().strip()
    assert len(plaintext) >= 20, f"token not revealed: {plaintext!r}"

    # the list shows the token by name + prefix, and NOT the plaintext
    row = page.locator("#log-token-list", has_text=unique_name)
    expect(row).to_be_visible(timeout=10000)
    list_text = page.locator("#log-token-list").inner_text()
    assert plaintext not in list_text, "plaintext token leaked into the list"
    assert plaintext[:12] in list_text, "token prefix not shown in the list"

    # server truth: the token exists (by prefix), hash/plaintext never returned
    listed = admin.get("/settings/logs").json()["tokens"]
    mine = next(t for t in listed if t["name"] == unique_name)
    assert mine["token_prefix"] == plaintext[:12]
    assert "token" not in mine and "token_hash" not in mine

    try:
        # disable it from the API cleanly (the UI 'Disable' has a confirm() dialog)
        assert admin.post(f"/settings/logs/{mine['id']}/disable", json={}).status_code == 200
    finally:
        pass


def test_flag_toggle_persists(page: Page, admin_creds, admin):
    if not _endpoint_present(admin):
        skip_for_older_deployment("running vault image predates the log-pull endpoint")
    import time
    before = admin.get("/settings/logs").json().get("flags", {})
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_log_tab(page)
        web = page.locator('#log-flags input[data-component="web"]')
        expect(web).to_be_visible(timeout=10000)
        # flip whatever the current state is, then confirm the server reflects it. Verify via the
        # authenticated Python client — a bare in-page fetch('/settings/logs') would 403 (the app
        # sends the bearer token via its own apiRequest, not on a raw fetch).
        target = not web.is_checked()
        web.check() if target else web.uncheck()
        deadline = time.time() + 10
        got = None
        while time.time() < deadline:
            got = bool(admin.get("/settings/logs").json().get("flags", {}).get("web"))
            if got == target:
                break
            time.sleep(0.3)
        assert got == target, f"flag toggle did not persist (wanted {target}, server has {got})"
    finally:
        admin.put("/settings/logs", json={"flags": before})


def test_stealth_toggle_persists(page: Page, admin_creds, admin):
    if not _endpoint_present(admin):
        skip_for_older_deployment("running vault image predates the log-pull endpoint")
    import time
    before = bool(admin.get("/settings/logs").json().get("stealth_404", False))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_log_tab(page)
        toggle = page.locator('#log-stealth-toggle')
        expect(toggle).to_be_visible(timeout=10000)
        # the toggle reflects the current server state on load
        assert toggle.is_checked() == before
        target = not before
        toggle.check() if target else toggle.uncheck()
        deadline = time.time() + 10
        got = None
        while time.time() < deadline:
            got = bool(admin.get("/settings/logs").json().get("stealth_404", False))
            if got == target:
                break
            time.sleep(0.3)
        assert got == target, f"stealth toggle did not persist (wanted {target}, server has {got})"
    finally:
        admin.put("/settings/logs", json={"stealth_404": before})


def test_settings_logs_reports_ceiling(admin):
    """Backend signal the UI gates on: GET /settings/logs exposes a boolean `ceiling` + the
    per-component flags. No policy change here — the endpoint stays default-off."""
    if not _endpoint_present(admin):
        skip_for_older_deployment("running vault image predates the log-pull endpoint")
    body = admin.get("/settings/logs").json()
    assert isinstance(body.get("ceiling"), bool)
    assert isinstance(body.get("flags"), dict)
    assert "web" in body.get("components", [])


def test_log_gating_ceiling_off_disables_generator(page: Page, admin_creds, admin):
    """Ceiling OFF: the UI must NOT hand out a token/curl for an endpoint that only 404s. The
    Generate button is disabled and an actionable note names the two env vars to set."""
    if not _endpoint_present(admin):
        skip_for_older_deployment("running vault image predates the log-pull endpoint")
    if _ceiling_on(admin):
        pytest.skip("this instance has the log ceiling ON; needs a ceiling-off instance")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_log_tab(page)
    expect(page.locator("#log-token-generate-btn")).to_be_disabled()
    note = page.locator("#log-ceiling-note")
    expect(note).to_be_visible()
    expect(note).to_contain_text("PLAN_LOG_PULL")
    expect(note).to_contain_text("LOG_TOKEN_PEPPER")
    # no reveal/curl block is offered
    expect(page.locator("#log-token-reveal")).to_be_hidden()


def test_log_gating_ceiling_on_component_hint_and_reveal_warning(page: Page, admin_creds, admin):
    """Ceiling ON: the Generate button works; when no component is enabled the note nudges the
    admin to tick one; and minting a token scoped to a NOT-enabled component surfaces a distinct
    'not enabled … returns 404' warning next to the curl (the second common 404 cause)."""
    if not _endpoint_present(admin):
        skip_for_older_deployment("running vault image predates the log-pull endpoint")
    if not _ceiling_on(admin):
        pytest.skip("this instance has the log ceiling OFF; needs a ceiling-on instance")
    before = admin.get("/settings/logs").json().get("flags", {})
    try:
        # ensure both components are disabled so a minted token is guaranteed 'not enabled'
        admin.put("/settings/logs", json={"flags": {"web": False, "sftp": False}})
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_log_tab(page)
        expect(page.locator("#log-token-generate-btn")).to_be_enabled()
        expect(page.locator("#log-ceiling-note")).to_contain_text("no component is exposed")
        # mint a token (scope defaults to web/sftp, both disabled) -> the not-enabled warning shows
        page.click("#log-token-generate-btn")
        expect(page.locator("#log-token-generate-panel")).to_be_visible()
        name = "logtok-" + page.evaluate("() => String(Date.now())")
        page.fill("#log-token-name", name)
        page.click("#log-token-create-btn")
        reveal = page.locator("#log-token-reveal")
        expect(reveal.locator("#log-token-value")).to_be_visible(timeout=10000)
        expect(reveal).to_contain_text("not enabled")
        expect(reveal).to_contain_text("returns 404")
        # clean up the minted token
        listed = admin.get("/settings/logs").json()["tokens"]
        mine = next((t for t in listed if t["name"] == name), None)
        if mine:
            admin.post(f"/settings/logs/{mine['id']}/disable", json={})
    finally:
        admin.put("/settings/logs", json={"flags": before})
