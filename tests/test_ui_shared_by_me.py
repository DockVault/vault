"""UI — the creator "Shared by me" management sub-tab: list your shares, expand recipients, kick a
recipient, and revoke the whole share. Setup via the API; the browser logs in as the creator.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    u["_client"] = c
    yield u
    admin.delete_user(u["id"])


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("sbmtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def test_shared_by_me_list_kick_and_revoke(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"sharing_enabled": True})
    tag = _tag(admin)
    fc = fresh_admin["_client"]
    v = fc.create_vault(name=unique("sbmv"))
    recipient = admin.create_user(role="user")
    rc = ApiClient()
    rc.login(recipient["_username"], recipient["_password"])
    try:
        share = fc.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "anyone_internal"}).json()
        assert rc.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200

        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        page.click('.sidebar-item[data-section="shared"]')
        expect(page.locator("#shared-section")).to_be_visible()
        page.click('.tab-btn[data-shared-tab="by-me"]')

        card = page.locator(f'#shared-by-me-list .vault-card[data-share-id="{share["id"]}"]')
        expect(card).to_be_visible(timeout=10000)
        expect(card).to_contain_text("Active")
        expect(card).to_contain_text(tag["name"])

        # expand recipients -> the claimant + a Remove button
        card.locator('button:has-text("Recipients")').click()
        expect(card).to_contain_text(recipient["_username"], timeout=10000)

        # kick the recipient
        card.locator('button:has-text("Remove")').first.click()
        page.click("#confirm-modal-confirm-btn")
        expect(card).to_contain_text("(removed)", timeout=10000)

        # revoke the whole share -> the card re-renders as Revoked
        card.locator('button:has-text("Revoke")').click()
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator(f'#shared-by-me-list .vault-card[data-share-id="{share["id"]}"]')
               ).to_contain_text("Revoked", timeout=10000)
    finally:
        admin.delete_user(recipient["id"])
        fc.delete_vault(v["id"])


def test_shared_by_me_card_padding_pill_and_layout(page: Page, admin, fresh_admin):
    """The tag renders as a padded pill, the status badge has real vertical padding, and the action
    row + recipients disclosure live INSIDE the padded .vault-card-body (not flush to the card
    edge). Regression guard: previously the action row + recipients were appended to the
    padding-less .card, and the Console-skin badge padding was ~1.9px."""
    import re as _re
    admin.put("/settings", json={"sharing_enabled": True})
    tag = _tag(admin)
    fc = fresh_admin["_client"]
    v = fc.create_vault(name=unique("sbmv"))
    recipient = admin.create_user(role="user")
    rc = ApiClient()
    rc.login(recipient["_username"], recipient["_password"])
    try:
        share = fc.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "anyone_internal"}).json()
        assert rc.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200

        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        page.click('.sidebar-item[data-section="shared"]')
        expect(page.locator("#shared-section")).to_be_visible()
        page.click('.tab-btn[data-shared-tab="by-me"]')

        card = page.locator(f'#shared-by-me-list .vault-card[data-share-id="{share["id"]}"]')
        expect(card).to_be_visible(timeout=10000)

        # (a) the tag renders as a real padded pill (a .badge) inside the padded body
        pill = card.locator('.vault-card-body .badge.badge-secondary')
        expect(pill).to_have_text(tag["name"])
        pill_pad = pill.evaluate("el => parseFloat(getComputedStyle(el).paddingTop)")
        assert pill_pad >= 2.5, f"pill vertical padding too small: {pill_pad}px"

        # (b) the status badge ("Active") has real breathing room (was ~1.9px in the Console skin)
        status = card.locator('.vault-name .badge')
        badge_pad = status.evaluate("el => parseFloat(getComputedStyle(el).paddingTop)")
        assert badge_pad >= 2.5, f"status badge vertical padding too small: {badge_pad}px"

        # (c) the action row (Revoke) lives INSIDE .vault-card-body (aligned), not flush to .card.
        # Previously it was appended to the padding-less .card, so this locator matched nothing.
        expect(card.locator('.vault-card-body button:has-text("Revoke")')).to_be_visible()
        # the card's only direct child is the padded body (actions/recipients moved inside it)
        assert card.evaluate(
            "el => Array.from(el.children).every(c => c.classList.contains('vault-card-body'))")

        # recipients disclosure also lands inside the padded body
        card.locator('button:has-text("Recipients")').click()
        expect(card.locator('.vault-card-body')).to_contain_text(recipient["_username"], timeout=10000)

        # (d) dark mode: the new pill is themed (no light island)
        page.evaluate("document.documentElement.setAttribute('data-theme','dark')")
        bg = pill.evaluate("el => getComputedStyle(el).backgroundColor")
        nums = [int(x) for x in _re.findall(r"\d+", bg)[:3]]
        assert nums and (sum(nums) / len(nums)) < 150, f"pill not dark in dark mode: {bg}"
    finally:
        admin.delete_user(recipient["id"])
        fc.delete_vault(v["id"])


def test_shared_by_me_empty_state(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"sharing_enabled": True})
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        page.click('.sidebar-item[data-section="shared"]')
        page.click('.tab-btn[data-shared-tab="by-me"]')
        expect(page.locator("#shared-by-me-list")).to_contain_text("not shared anything", timeout=10000)
    finally:
        pass
