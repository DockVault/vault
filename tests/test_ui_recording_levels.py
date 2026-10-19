"""Settings -> Activity and records: the recording levels' table renders and behaves (static/js/settings-records.js).

The tab lists one row per kind of data with its levels, the limit and what a sample row records; a level the
.env limit forbids is a disabled choice that says the line to add (the stack's own limits are all full, so the
page is shown a description with a lowered limit); with full addresses kept for a number of days, the card says an
archived day's can be shortened up to a day later; a preset fills the rows; the save button waits for a change
and asks for the password; the page has no console errors and fits a phone's width.
"""
import json

import pytest
from playwright.sync_api import Page, expect
from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

TAB = "#settings-tab-records"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.click('#settings-section .tab-btn[data-tab="records"]')
    show_advanced(page, "records")
    expect(page.locator(TAB)).to_be_visible()
    expect(page.locator("#recording-levels-table tbody tr")).to_have_count(5, timeout=10000)


def _lowered(page: Page):
    """Serve the page the stack's own description with the address limit lowered to shortened."""
    def handle(route):
        if route.request.method != "GET":
            return route.continue_()
        response = route.fetch()
        data = response.json()
        for kind in data["kinds"]:
            if kind["key"] == "ip":
                kind["limit"], kind["limit_source"], kind["level"] = "shortened", "env", "shortened"
                for choice in kind["choices"]:
                    if choice["level"] == "full":
                        choice["allowed"], choice["env_line"] = False, "AUDIT_MAX_IP=full"
        route.fulfill(response=response, body=json.dumps(data))
    page.route("**/settings/recording", handle)


def test_the_table_renders_with_a_forbidden_level_disabled_and_its_env_line(page: Page, admin_creds):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    _login(page, admin_creds["username"], admin_creds["password"])
    _lowered(page)
    _open(page)
    ip_row = page.locator('#recording-levels-table tbody tr[data-kind="ip"]')
    full = ip_row.locator('input[value="full"]')
    expect(full).to_be_visible()
    expect(full).to_be_disabled()
    expect(ip_row).to_contain_text("Add AUDIT_MAX_IP=full to .env, then run docker compose up -d")
    expect(ip_row.locator('input[value="shortened"]')).to_be_checked()
    expect(ip_row).to_contain_text("203.0.113.0/24")
    expect(ip_row).to_contain_text("AUDIT_MAX_IP in .env")
    expect(page.locator("#recording-levels-history li").first).to_contain_text("Version")
    assert not errors, errors


def test_the_card_says_an_address_in_an_archived_day_can_stay_in_full_a_day_longer(page: Page, admin_creds):
    """With full addresses kept for a number of days (served here as 30), the card says when an address is shortened,
    and that in a day the archive holds it is once the whole day is that old: up to a day later."""
    def handle(route):
        if route.request.method != "GET":
            return route.continue_()
        response = route.fetch()
        data = response.json()
        data["ip_full_days"] = 30
        route.fulfill(response=response, body=json.dumps(data))
    _login(page, admin_creds["username"], admin_creds["password"])
    page.route("**/settings/recording", handle)
    _open(page)
    expect(page.locator(TAB)).to_contain_text(
        "An address recorded in full is shortened to its network once its row is 30 days old, and in a day the archive "
        "holds once the whole day is that old (up to a day later;")


def test_a_preset_fills_the_rows_and_the_save_waits_for_a_change(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    save = page.locator("#recording-levels-save")
    expect(save).to_be_visible()
    expect(save).to_be_disabled()
    page.click('#recording-levels-presets button:has-text("Minimal")')
    for kind in ("names", "signin_names", "emails", "ip", "user_agent"):
        expect(page.locator(f'#recording-levels-table tr[data-kind="{kind}"] input[value="none"]')).to_be_checked()
    expect(save).to_be_enabled()
    page.click('#recording-levels-presets button:has-text("Full")')
    expect(page.locator('#recording-levels-table tr[data-kind="names"] input[value="full"]')).to_be_checked()


def test_saving_asks_for_the_password(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open(page)
    page.check('#recording-levels-table tr[data-kind="user_agent"] input[value="none"]')
    page.click("#recording-levels-save")
    # The step-up prompt opens (nothing is saved unless the password is given; the prompt is left unanswered).
    expect(page.locator("#stepup-modal")).to_be_visible(timeout=10000)
    expect(page.locator("#stepup-modal-body")).to_contain_text("assword")


def test_the_table_fits_a_phone(page: Page, admin_creds):
    page.set_viewport_size({"width": 375, "height": 812})
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.locator('#settings-section .tab-btn[data-tab="records"]').click()
    show_advanced(page, "records")
    expect(page.locator("#recording-levels-table tbody tr")).to_have_count(5, timeout=10000)
    width = page.evaluate("() => document.getElementById('recording-levels-card').scrollWidth")
    assert width <= 375, width
