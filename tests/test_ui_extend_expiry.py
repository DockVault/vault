"""Extending an expiry from the web app: a shared-by-me card and a drop-vault card offer Extend, the dialog
suggests a week later, a date past the type's ceiling is refused with the server's words, and a date within it
moves the expiry shown on the card."""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

_MB = 1024 * 1024


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _local_input(page: Page, days: int) -> str:
    """Now plus `days`, as a datetime-local field takes it (local time, to the minute), on the page's clock."""
    return page.evaluate(
        "days => { const d = new Date(Date.now() + days * 86400000); const p = n => String(n).padStart(2, '0');"
        " return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }",
        days)


@pytest.fixture
def features_on(admin):
    before = admin.get("/settings").json()
    keys = ("sharing_enabled", "public_receivers_enabled", "public_receiver_user_cap")
    admin.put("/settings", json={"sharing_enabled": True, "public_receivers_enabled": True, "public_receiver_user_cap": 50})
    yield
    admin.put("/settings", json={k: before.get(k) for k in keys})


def test_a_share_is_extended_from_its_card(page: Page, admin, admin_creds, features_on):
    tag = admin.post("/share-tags", json={"name": unique("uiext"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 10 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    v = admin.create_vault(name=unique("Extend"))
    try:
        share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal", "lifetime_minutes": 24 * 60}).json()
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="shared"]')
        page.click('[data-shared-tab="by-me"]')
        card = page.locator(f'[data-share-id="{share["id"]}"]')
        expect(card).to_be_visible(timeout=15000)
        before = card.locator(".shared-expires time.when").get_attribute("datetime")
        card.locator("button.share-extend").click()
        modal = page.locator("#extend-expiry-modal.active")
        expect(modal).to_be_visible()
        expect(page.locator("#extend-expiry-title")).to_contain_text("Extend the share of " + v["name"])
        # Past the ceiling (ten days for this tag; 400 days from now, read on the page's own clock): refused
        # with the server's words, the dialog stays.
        page.fill("#extend-expiry-until", _local_input(page, days=400))
        page.click("#extend-expiry-save")
        expect(page.locator("#extend-expiry-error")).to_contain_text("no later than")
        expect(modal).to_be_visible()
        # The suggested date (a week later) is within it: the card shows the new expiry.
        suggested = page.evaluate("() => { const d = new Date(); d.setDate(d.getDate() + 5); const p = n => String(n).padStart(2, '0');"
                                  " return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; }")
        page.fill("#extend-expiry-until", suggested)
        page.click("#extend-expiry-save")
        expect(modal).to_be_hidden(timeout=10000)
        expect(page.locator("#toast-container")).to_contain_text("Extended to")
        card = page.locator(f'[data-share-id="{share["id"]}"]')
        expect(card.locator(".shared-expires time.when")).not_to_have_attribute("datetime", before, timeout=15000)
        after = admin.get("/shares").json()
        mine = next(s for s in (after if isinstance(after, list) else after.get("shares", [])) if s["id"] == share["id"])
        assert mine["expires_at"] != share["expires_at"]
    finally:
        admin.delete_vault(v["id"])


def test_an_upload_link_card_offers_extend(page: Page, admin, admin_creds, features_on):
    tag = admin.post("/receiver-tags", json={"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
                                             "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                             "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
    rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB, "label": unique("Drop"), "ttl_hours": 24}).json()
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="uploadlinks"]')
    page.click('button[data-rc-tab="vaults"]')
    card = page.locator(".rc-vault-card", has_text=rec["label"]).first
    expect(card).to_be_visible(timeout=15000)
    card.locator("button.link-extend").click()
    expect(page.locator("#extend-expiry-modal.active")).to_be_visible()
    expect(page.locator("#extend-expiry-current")).to_contain_text("Expires now")
    page.keyboard.press("Escape")
    expect(page.locator("#extend-expiry-modal.active")).to_be_hidden()


def test_the_suggested_date_is_within_the_ceiling_and_the_server_accepts_it(page: Page, admin, admin_creds, features_on):
    """A share on a seven-day tag: the dialog pre-fills a date the server accepts (clamped to the ceiling), the
    input will not go past the ceiling, and the ceiling is shown in the viewer's own time."""
    tag = admin.post("/share-tags", json={"name": unique("week"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 7 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    v = admin.create_vault(name=unique("Week"))
    try:
        share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal"}).json()
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="shared"]')
        page.click('[data-shared-tab="by-me"]')
        card = page.locator(f'[data-share-id="{share["id"]}"]')
        expect(card).to_be_visible(timeout=15000)
        card.locator("button.share-extend").click()
        modal = page.locator("#extend-expiry-modal.active")
        expect(modal).to_be_visible()
        listed = admin.get("/shares").json()
        mine = next(s for s in (listed if isinstance(listed, list) else listed.get("shares", [])) if s["id"] == share["id"])
        ceiling_local = page.evaluate("iso => _toLocalInputValue(parseServerTime(iso))", mine["extend_ceiling"])
        attrs = page.evaluate("() => { const i = document.getElementById('extend-expiry-until'); return { value: i.value, max: i.max }; }")
        assert attrs["max"] == ceiling_local, attrs
        assert attrs["value"] == ceiling_local, attrs      # a week later would be past it: clamped
        expect(page.locator("#extend-expiry-current")).to_contain_text("Its type allows no later than")
        expect(page.locator("#extend-expiry-current")).not_to_contain_text("T0")  # a local date and time, not an ISO string
        expect(page.locator("#extend-expiry-error")).to_have_attribute("role", "alert")
        # Extend on the pre-filled date: accepted, no refusal.
        page.click("#extend-expiry-save")
        expect(modal).to_be_hidden(timeout=10000)
        expect(page.locator("#toast-container")).to_contain_text("Extended to")
        after = admin.get("/shares").json()
        mine_after = next(s for s in (after if isinstance(after, list) else after.get("shares", [])) if s["id"] == share["id"])
        assert mine_after["expires_at"] != share["expires_at"]
        # Now at its ceiling: the card offers no Extend any more.
        expect(page.locator(f'[data-share-id="{share["id"]}"]')).to_be_visible(timeout=15000)
        expect(page.locator(f'[data-share-id="{share["id"]}"] button.share-extend')).to_have_count(0, timeout=15000)
    finally:
        admin.delete_vault(v["id"])


def test_a_link_already_at_its_ceiling_offers_no_extend(page: Page, admin, admin_creds, features_on):
    """An upload link made at its tag's default lifetime, where the default is the maximum: every date would be
    refused, so the drop-vault card shows Replace link, Open and Info but no Extend."""
    tag = admin.post("/receiver-tags", json={"name": unique("rmax"), "min_token_len": 6, "require_secret": "none",
                                             "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                             "default_ttl_hours": 48, "max_ttl_hours": 48}).json()
    rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB, "label": unique("Full")}).json()
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="uploadlinks"]')
    page.click('button[data-rc-tab="vaults"]')
    card = page.locator(".rc-vault-card", has_text=rec["label"]).first
    expect(card).to_be_visible(timeout=15000)
    expect(card.locator("button.link-extend")).to_have_count(0)
    expect(card.locator("button", has_text="Info")).to_be_visible()


def test_the_dialog_is_described_and_a_refusal_is_announced(page: Page, admin_creds):
    """The dialog is described by the current expiry, the date field by its help and the current expiry, and a
    refusal is an alert."""
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("""() => openExtendExpiry('share', '00000000-0000-0000-0000-000000000000',
        new Date(Date.now() + 86400000).toISOString(), 'a share', null, new Date(Date.now() + 7 * 86400000).toISOString())""")
    expect(page.locator("#extend-expiry-modal.active")).to_be_visible()
    modal = page.locator("#extend-expiry-modal")
    expect(modal).to_have_attribute("aria-describedby", "extend-expiry-current")
    expect(page.locator("#extend-expiry-current")).to_contain_text("Expires now")
    described = page.locator("#extend-expiry-until").get_attribute("aria-describedby").split()
    assert "extend-expiry-help" in described and "extend-expiry-current" in described, described
    expect(page.locator("#extend-expiry-help")).to_be_visible()
    expect(page.locator("#extend-expiry-error")).to_have_attribute("role", "alert")
    page.keyboard.press("Escape")
