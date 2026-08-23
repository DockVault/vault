"""The dashboard's System Status card, Active Users tile, and Recent-Events/System-Status row are
administrator-only. A non-admin sees the personal lanes instead.

This is presentation, not confidentiality: GET /health is deliberately unauthenticated and answers
from a fixed vocabulary. The ops cards are hidden from people who cannot act on them; a non-admin's
lower row is hidden entirely (they get the lanes), and an admin keeps the two-column events + status
layout.

The case worth pinning is the scoped temporary credential: it authenticates AS its owning account,
so one minted from an admin reports role 'admin'. A naive role check would show it the card.

Every to_be_hidden() below is preceded by to_be_attached(), because Playwright reports a MISSING
element as hidden — without that guard these would all pass against a build that never had the
card at all.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

CARD = "#dashboard-system-status"
LANES = "#dashboard-lanes"
LOWER = "#dashboard-lower-grid"
USERS_CARD = "#dashboard-users-card"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _logout(page: Page):
    """Drop the stored session and reload — what a same-tab account switch looks like."""
    page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def _expect_card_hidden(page: Page):
    expect(page.locator(CARD)).to_be_attached()  # missing != hidden
    expect(page.locator(CARD)).to_be_hidden()


def _expect_non_admin_dashboard(page: Page):
    """A non-admin sees the personal lanes; the ops cards and their whole row are hidden."""
    expect(page.locator(LANES)).to_be_visible(timeout=10000)  # anchor: dashboard really rendered
    expect(page.locator(LOWER)).to_be_attached()
    expect(page.locator(LOWER)).to_be_hidden()
    expect(page.locator(USERS_CARD)).to_be_attached()
    expect(page.locator(USERS_CARD)).to_be_hidden()
    _expect_card_hidden(page)


def _grid_track_count(page: Page) -> int:
    """How many column tracks the lower dashboard row resolves to.

    getComputedStyle returns used values ("1064px" vs "704px 344px"), so counting whitespace-
    separated tokens distinguishes the one- and two-column layouts without asserting on any
    particular pixel width.
    """
    css = page.evaluate(
        "() => {"
        "  const g = document.querySelector('#dashboard-lower-grid');"
        "  if (!g) throw new Error('#dashboard-lower-grid is missing');"
        "  return getComputedStyle(g).gridTemplateColumns;"
        "}"
    )
    return len(css.split())


def _health_requests(page: Page) -> list:
    """Collect every /health request from now on.

    updateSystemStatus() is the only client-side caller of that endpoint, so a non-empty list
    means the gated code path ran.
    """
    seen = []
    page.on("request", lambda r: seen.append(r.url) if "/health" in r.url else None)
    return seen


def test_admin_sees_system_status_populated(page: Page, admin_creds):
    reqs = _health_requests(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(page.locator(CARD)).to_be_visible()
    # Non-vacuous: the card is not merely present, it is fed by a real /health response. Without
    # this, the test would still pass if the fetch were gated off for everyone.
    expect(page.locator("#status-db")).to_have_text("Connected", timeout=10000)
    expect(page.locator("#status-sessions")).to_have_text("Healthy", timeout=10000)
    assert reqs, "admin dashboard should have requested /health"
    assert _grid_track_count(page) == 2, "admin keeps the two-column events + status layout"
    # The lanes are shown to everyone, and the admin ops tile is present for an admin.
    expect(page.locator(LANES)).to_be_visible()
    expect(page.locator(USERS_CARD)).to_be_visible()


@pytest.mark.parametrize("role", ["user", "external"])
def test_non_admin_does_not_see_system_status(page: Page, admin, role):
    u = admin.create_user(role=role)
    try:
        reqs = _health_requests(page)
        _login(page, u["_username"], u["_password"])
        _expect_non_admin_dashboard(page)
        page.wait_for_timeout(1500)  # let any stray fetch fire before asserting absence
        assert not reqs, f"non-admin should not request /health, got {reqs}"
    finally:
        admin.delete_user(u["id"])


def test_scoped_temp_credential_of_an_admin_does_not_see_system_status(page: Page, admin):
    """A temp credential authenticates as its owner, so this one's role IS 'admin'."""
    scope = {"v": 1, "pages": ["dashboard", "vaults"], "caps": [],
             "vault_caps_default": ["vault.see_info"], "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all",
        "selected_vaults": []}).json()
    try:
        reqs = _health_requests(page)
        _login(page, body["temp_username"], body["credential"])
        # Non-vacuous anchor: prove this really is the scoped-temp shape (admin nav suppressed)
        # before asserting the card is hidden — a plain login failure would otherwise satisfy it.
        expect(page.locator('.sidebar-item[data-section="settings"]')).to_be_hidden()
        _expect_non_admin_dashboard(page)
        page.wait_for_timeout(1500)
        assert not reqs, f"a temp session should not request /health, got {reqs}"
    finally:
        admin.post(f"/temp-creds/{body['temp_username']}/delete")


def test_account_switch_in_one_tab_does_not_strand_the_card(page: Page, admin, admin_creds):
    """Both directions, because a one-way hide would leave the previous account's layout behind."""
    u = admin.create_user(role="user")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        expect(page.locator(CARD)).to_be_visible()
        assert _grid_track_count(page) == 2

        # admin -> user: the ops cards must go away, and the lanes take over
        _logout(page)
        _login(page, u["_username"], u["_password"])
        _expect_non_admin_dashboard(page)

        # user -> admin: and they must come back, not stay hidden from the previous account
        _logout(page)
        _login(page, admin_creds["username"], admin_creds["password"])
        expect(page.locator(CARD)).to_be_visible()
        expect(page.locator(USERS_CARD)).to_be_visible()
        assert _grid_track_count(page) == 2
    finally:
        admin.delete_user(u["id"])


def test_dashboard_re_entry_keeps_the_card_hidden_for_a_non_admin(page: Page, admin):
    """Navigating away and back re-runs loadDashboardStats — a second chance to leak the card."""
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        _expect_non_admin_dashboard(page)
        page.click('.sidebar-item[data-section="vaults"]')
        expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
        page.click('.sidebar-item[data-section="dashboard"]')
        _expect_non_admin_dashboard(page)
    finally:
        admin.delete_user(u["id"])


def test_no_console_errors_on_a_non_admin_dashboard(page: Page, admin):
    u = admin.create_user(role="user")
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        _login(page, u["_username"], u["_password"])
        _expect_non_admin_dashboard(page)
        page.wait_for_timeout(1500)
        assert not errors, f"non-admin dashboard produced console errors: {errors}"
    finally:
        admin.delete_user(u["id"])
