"""Settings → Email — the sending-profile card grid + modal (replaces the old single SMTP form).

Profiles are cards (title + description + Edit/Delete), with a trailing "+ Create profile" card; the
modal lays Server|Port and Username|Password on single rows, keeps Send-test + Save side by side and
in view without scrolling, and saves each profile on its own (no central Save).

Saving, deleting and testing a profile ask for the administrator's password every time (the mail server
settings' step-up): the page's prompt is answered with it. The tests sign in as an administrator of their
own, so the step-ups they make are counted apart from the suite's administrator's.
"""
import os
import re
import time

import pytest
import requests
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_email_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="email"]')
    expect(page.locator("#email-profiles-grid")).to_be_visible(timeout=10000)


@pytest.fixture
def boss(admin):
    """An administrator of the test's own: every save here asks the step-up, whose budget is kept per account."""
    made = admin.create_user(role="admin")
    yield {"username": made["_username"], "password": made["_password"]}
    admin.delete_user(made["id"])


@pytest.fixture
def admin_page(page: Page, boss):
    _login(page, boss["username"], boss["password"])
    page.boss_password = boss["password"]
    return page


def _with_the_password(page: Page):
    """Answer the step-up prompt the save, delete or test send opened, with the administrator's password."""
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    page.fill("#stepup-password-input", page.boss_password)
    page.locator("#stepup-modal-body .btn-primary").click()
    expect(page.locator("#stepup-modal.active")).to_be_hidden(timeout=10000)


def _save(page: Page):
    page.click("#ep-save")
    _with_the_password(page)


@pytest.fixture(autouse=True)
def _clean(admin):
    def wipe():
        for p in admin.get("/email/profiles").json().get("profiles", []):
            admin.delete(f"/email/profiles/{p['id']}")
    wipe()
    yield
    wipe()


def _fill_profile(page, *, name, server="smtp.example.com", port="587", username="", password="",
                  from_email="noreply@example.com", from_name="Vault"):
    page.fill("#ep-name", name)
    page.fill("#ep-server", server)
    page.fill("#ep-port", port)
    page.fill("#ep-username", username)
    if password:
        page.fill("#ep-password", password)
    page.fill("#ep-from-email", from_email)
    page.fill("#ep-from-name", from_name)


def test_email_tab_shows_profile_grid_and_create_card(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    # The old single-form controls are gone; the create card is present.
    expect(page.locator("#test-email-btn")).to_have_count(0)
    expect(page.locator("#setting-smtp-server")).to_have_count(0)
    expect(page.locator("#email-profile-add")).to_be_visible()


def test_create_modal_layout_rows_and_buttons_in_view(admin_page: Page):
    page = admin_page
    page.set_viewport_size({"width": 1280, "height": 720})   # pin so "in view" is deterministic
    _open_email_tab(page)
    page.click("#email-profile-add")
    expect(page.locator("#email-profile-modal")).to_have_class(re.compile(r"\bactive\b"))
    # Server|Port share one row; Username|Password share one row (same top offset).
    sy = page.locator("#ep-server").bounding_box()["y"]
    py = page.locator("#ep-port").bounding_box()["y"]
    assert abs(sy - py) < 6, "SMTP Server and Port should sit on the same line"
    uy = page.locator("#ep-username").bounding_box()["y"]
    wy = page.locator("#ep-password").bounding_box()["y"]
    assert abs(uy - wy) < 6, "Username and Password should sit on the same line"
    # Send test + Save are both visible without scrolling the page.
    expect(page.locator("#ep-send-test")).to_be_in_viewport()
    expect(page.locator("#ep-save")).to_be_in_viewport()


def test_create_edit_delete_profile_roundtrip(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="Primary")
    _save(page)
    card = page.locator('.email-profile-card:has-text("Primary")')
    expect(card).to_be_visible(timeout=10000)
    assert len(admin.get("/email/profiles").json()["profiles"]) == 1

    card.locator(".epc-edit").click()
    expect(page.locator("#email-profile-modal-title")).to_have_text("Edit sending profile")
    page.fill("#ep-name", "Renamed")
    _save(page)
    expect(page.locator('.email-profile-card:has-text("Renamed")')).to_be_visible(timeout=10000)

    page.locator('.email-profile-card:has-text("Renamed") .epc-delete').click()
    page.click("#confirm-modal-confirm-btn")         # themed confirm for the delete
    _with_the_password(page)
    expect(page.locator('.email-profile-card:has-text("Renamed")')).to_have_count(0, timeout=10000)
    assert admin.get("/email/profiles").json()["profiles"] == []


def test_password_is_write_only_in_the_modal(admin_page: Page, admin):
    admin.post("/email/profiles", json={"name": "HasPw", "smtp_server": "s.example.com",
                                        "smtp_port": 587, "from_email": "a@example.com",
                                        "smtp_password": "secret-pw"})
    page = admin_page
    _open_email_tab(page)
    page.locator('.email-profile-card:has-text("HasPw") .epc-edit').click()
    expect(page.locator("#ep-password")).to_have_value("")
    expect(page.locator("#ep-password-hint")).to_contain_text("leave blank to keep")


def test_a_new_server_asks_for_the_smtp_password_beside_its_field(admin_page: Page, admin):
    """The stored password goes only to the server it was entered for: saving the profile with another server
    is refused before any step-up, with the sentence beside the password field; with the password it is saved."""
    admin.post("/email/profiles", json={"name": "Moving", "smtp_server": "s.example.com", "smtp_port": 587,
                                        "from_email": "a@example.com", "smtp_password": "secret-pw"})
    page = admin_page
    _open_email_tab(page)
    page.locator('.email-profile-card:has-text("Moving") .epc-edit').click()
    page.fill("#ep-server", "elsewhere.example.com")
    page.click("#ep-save")
    said = page.locator("#ep-password-error")
    expect(said).to_be_visible(timeout=10000)
    expect(said).to_contain_text("Re-enter the SMTP password")
    expect(page.locator("#ep-password")).to_have_attribute("aria-invalid", "true")
    expect(page.locator("#ep-password")).to_be_focused()
    expect(page.locator("#stepup-modal.active")).to_have_count(0)
    assert admin.get("/email/profiles").json()["profiles"][0]["smtp_server"] == "s.example.com"

    page.fill("#ep-password", "secret-pw-2")
    expect(said).to_be_hidden()
    _save(page)
    expect(page.locator("#email-profile-modal")).not_to_have_class(re.compile(r"\bactive\b"), timeout=10000)
    assert admin.get("/email/profiles").json()["profiles"][0]["smtp_server"] == "elsewhere.example.com"


def test_profile_saves_individually_not_central(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="Solo")
    seen = []
    page.on("request", lambda r: seen.append((r.method, r.url)))
    _save(page)
    expect(page.locator('.email-profile-card:has-text("Solo")')).to_be_visible(timeout=10000)
    assert any(m == "POST" and "/email/profiles" in u for m, u in seen), seen
    # ...and the central settings save (PUT /settings) is NOT invoked.
    assert not any(m == "PUT" and u.rstrip("/").endswith("/settings") for m, u in seen), seen


def test_card_shows_description_and_default_badge(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="Described")
    page.fill("#ep-description", "The support desk sender")
    _save(page)   # first profile -> becomes default
    card = page.locator('.email-profile-card:has-text("Described")')
    expect(card).to_be_visible(timeout=10000)
    expect(card.locator(".epc-desc")).to_have_text("The support desk sender")
    expect(card.locator(".epc-badge")).to_have_text("Default")


def test_default_badge_moves_when_another_marked_default(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add"); _fill_profile(page, name="First"); _save(page)
    expect(page.locator('.email-profile-card:has-text("First")')).to_be_visible(timeout=10000)
    page.click("#email-profile-add"); _fill_profile(page, name="Second"); _save(page)
    expect(page.locator('.email-profile-card:has-text("Second")')).to_be_visible(timeout=10000)
    # promote Second
    page.locator('.email-profile-card:has-text("Second") .epc-edit').click()
    page.check("#ep-default")
    _save(page)
    expect(page.locator('.email-profile-card:has-text("Second") .epc-badge')).to_have_text("Default", timeout=10000)
    expect(page.locator('.email-profile-card:has-text("First") .epc-badge')).to_have_count(0)


def test_validation_error_shows_and_keeps_modal_open(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="BadFrom", from_email="not-an-email")
    page.click("#ep-save")
    expect(page.locator("#email-profile-result")).to_contain_text("✗", timeout=10000)
    expect(page.locator("#email-profile-modal")).to_have_class(re.compile(r"\bactive\b"))  # stays open
    assert admin.get("/email/profiles").json()["profiles"] == []                          # nothing saved


def test_cancel_closes_without_saving(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="Discarded")
    page.click("#ep-cancel")
    expect(page.locator("#email-profile-modal")).not_to_have_class(re.compile(r"\bactive\b"))
    assert admin.get("/email/profiles").json()["profiles"] == []


def test_modal_scrolls_on_a_short_viewport(admin_page: Page):
    page = admin_page
    page.set_viewport_size({"width": 900, "height": 480})
    _open_email_tab(page)
    page.click("#email-profile-add")
    content = page.locator("#email-profile-modal .modal-content")
    # the modal-content scrolls internally, and Save is reachable by scrolling within it.
    assert page.evaluate(
        "() => { const c = document.querySelector('#email-profile-modal .modal-content');"
        " return c.scrollHeight > c.clientHeight; }"), "modal should scroll on a short viewport"
    page.locator("#ep-save").scroll_into_view_if_needed()
    expect(page.locator("#ep-save")).to_be_in_viewport()


def test_no_console_errors_on_email_tab(admin_page: Page):
    page = admin_page
    errors = []
    # The browser logs the step-up's refusal (403) as a resource that failed to load: that is the prompt's cue.
    # Only that refusal is let through; any other resource that fails to load (a 404, a 500) still counts.
    step_up_refusal = "the server responded with a status of 403"
    page.on("console", lambda m: errors.append(m.text) if m.type == "error"
            and step_up_refusal not in m.text else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="Quiet")
    _save(page)
    expect(page.locator('.email-profile-card:has-text("Quiet")')).to_be_visible(timeout=10000)
    assert errors == [], errors


@pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST),
                    reason="no Mailpit sink (bring the round up WITH_MAILPIT)")
def test_send_test_delivers_without_saving(admin_page: Page, admin):
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
    page = admin_page
    _open_email_tab(page)
    page.click("#email-profile-add")
    _fill_profile(page, name="Mailpit", server=MAILPIT_SMTP_HOST, port=str(MAILPIT_SMTP_PORT),
                  from_email="tester@example.com")
    page.click("#ep-send-test")
    _with_the_password(page)
    expect(page.locator("#email-profile-result")).to_contain_text("✓", timeout=15000)
    assert admin.get("/email/profiles").json()["profiles"] == []   # Send test did NOT save
    deadline, seen = time.time() + 15, False
    while time.time() < deadline and not seen:
        msgs = requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", [])
        seen = any("test email" in (m.get("Subject") or "") for m in msgs)
        if not seen:
            time.sleep(0.5)
    assert seen, "the test email never reached Mailpit"
