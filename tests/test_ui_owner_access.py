"""Access to my vaults and the banners of compliance access, in a real browser (static/js/compliance.js, the shared
notice banner in static/js/notice-banner.js).

A vault's owner sees, after sign-in, the same banner component the recording notice uses while a notice about
access to their vaults is unread; its link opens the page with the case; "I've read it" takes it away for good.
A member who opens the vault sees a neutral banner that names no case number, purpose, auditor or person
concerned. On a phone (390 px) the page fits the screen without scrolling sideways. A name revealed from the
owner's vault outside a case is listed with who revealed it, when and why (the category), never the reason's text.
Past a case's records' time the page says its list of files opened may not be complete.
"""
import json
import re

import pytest
from playwright.sync_api import Page, expect

from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import CASE_TEXT, approved_case, forget_cases, owner_with_vault

pytestmark = pytest.mark.ui


@pytest.fixture(scope="module")
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        mia = admin.create_user()
        assert olga_c.post(f"/vaults/{vid}/permissions", json={"user_id": mia["id"], "level": "read"}).status_code \
            in (200, 201)
        case = approved_case(admins, (uma, uma_c, codes), [vid])
        try:
            yield {"olga": olga, "olga_c": olga_c, "vid": vid, "mia": mia, "case": case, "auditor": uma["_username"]}
        finally:
            forget_cases([case["id"]], [vid])
            forget_grants(uma["id"])


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_the_owner_reads_the_banner_opens_the_page_and_the_banner_goes(page: Page, world):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _login(page, world["olga"])
    banner = page.locator('#notice-banners .notice-banner[data-notice="compliance-access"]')
    expect(banner).to_be_visible(timeout=15000)
    expect(banner).to_contain_text("access to your vaults")
    for hidden in (CASE_TEXT["justification"], world["case"]["number"]):
        assert hidden not in banner.inner_text()
    banner.locator(".notice-banner-link").click()
    dialog = page.locator("#my-access-modal")
    expect(dialog).to_be_visible()
    card = dialog.locator(f'.my-access-case[data-case-id="{world["case"]["id"]}"]')
    expect(card).to_contain_text("Case " + world["case"]["number"])
    expect(card).to_contain_text(world["auditor"])
    expect(card).to_contain_text(CASE_TEXT["owner_note"])
    expect(card).not_to_contain_text(CASE_TEXT["justification"])
    expect(card.locator(f'.my-access-vault[data-vault-id="{world["vid"]}"]')).to_contain_text("legal hold")
    dialog.locator(".modal-close").click()
    expect(dialog).to_be_hidden()
    # Still there until the owner says they have read it.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    banner = page.locator('#notice-banners .notice-banner[data-notice="compliance-access"]')
    expect(banner).to_be_visible(timeout=15000)
    banner.locator(".notice-banner-read").click()
    expect(banner).to_have_count(0)
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(1500)
    expect(page.locator('.notice-banner[data-notice="compliance-access"]')).to_have_count(0)
    # The page stays: the account menu opens it.
    page.evaluate("() => window.openMyAccess()")
    expect(page.locator("#my-access-modal .my-access-case")).to_have_count(1)
    assert errors == []


def test_a_member_sees_a_neutral_banner_on_the_vault(page: Page, world):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _login(page, world["mia"])
    page.evaluate("(id) => openVault(id)", world["vid"])
    banner = page.locator("#vault-review-banner")
    expect(banner).to_be_visible(timeout=15000)
    expect(banner).to_contain_text("This vault is part of an authorised review until")
    expect(banner).to_contain_text("Files deleted here are kept until it ends.")
    text = banner.inner_text()
    for hidden in (world["case"]["number"], world["auditor"], "investigation", "Internal", CASE_TEXT["justification"]):
        assert hidden not in text, hidden
    # Opening another vault takes it away.
    other = world["olga_c"].create_vault()
    try:
        world["olga_c"].post(f"/vaults/{other['id']}/permissions", json={"user_id": world["mia"]["id"], "level": "read"})
        page.evaluate("(id) => openVault(id)", other["id"])
        expect(page.locator("#vault-review-banner")).to_have_count(0)
    finally:
        world["olga_c"].delete_vault(other["id"])
    assert errors == []


def test_the_page_fits_a_phone(page: Page, world):
    page.set_viewport_size({"width": 390, "height": 844})
    _login(page, world["olga"])
    page.evaluate("() => window.openMyAccess()")
    card = page.locator("#my-access-modal .my-access-case")
    expect(card).to_have_count(1)
    sizes = page.evaluate("""() => {
        const content = document.querySelector('#my-access-modal .modal-content');
        return {doc: document.documentElement.scrollWidth, view: window.innerWidth,
                content: content.scrollWidth, contentBox: content.clientWidth,
                card: document.querySelector('#my-access-modal .my-access-case').getBoundingClientRect().right};
    }""")
    assert sizes["doc"] <= sizes["view"], sizes
    assert sizes["content"] <= sizes["contentBox"] + 1, sizes
    assert sizes["card"] <= sizes["view"], sizes


def test_the_page_lists_a_name_revealed_from_the_owners_vault(page: Page, world):
    """A reveal outside a case on the owner's vault (written as the reveal writes its row) is listed on the page
    with when, who and the reason's category, never the reason's text."""
    from _account_change_helpers import psql
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    reveal = psql("INSERT INTO compliance_reveals (id, event_id, auditor_username, vault_id, reason_category, "
                  "reason_text_enc, created_at) VALUES (gen_random_uuid(), gen_random_uuid(), "
                  f"'{world['auditor']}', '{world['vid']}', 'regulator_request', 'not-a-sealed-reason', "
                  "now() AT TIME ZONE 'utc') RETURNING id").splitlines()[0]
    try:
        _login(page, world["olga"])
        page.evaluate("() => window.openMyAccess()")
        line = page.locator(f'#my-access-modal .my-access-reveal[data-vault-id="{world["vid"]}"]')
        expect(line).to_have_count(1, timeout=15000)
        expect(line).to_contain_text("by " + world["auditor"] + ", reason: Regulator or authority request")
        expect(page.locator("#my-access-modal")).not_to_contain_text("not-a-sealed-reason")
        assert errors == []
    finally:
        psql(f"DELETE FROM compliance_reveals WHERE id = '{reveal}'")


def test_a_case_past_its_records_time_says_its_list_of_files_opened_may_not_be_complete(page: Page, world):
    """While a case's records are kept, an empty list of files opened says none were; past their time the case's
    audit rows follow the audit log's retention, and the page says the list may not be complete instead."""
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))

    def past_its_time(route):
        response = route.fetch()
        data = response.json()
        for case in data.get("cases", []):
            if case["id"] == world["case"]["id"]:
                case["opened"], case["opened_kept_until"] = [], "2025-01-02T03:04:05Z"
        route.fulfill(response=response, body=json.dumps(data))
    _login(page, world["olga"])
    page.evaluate("() => window.openMyAccess()")
    opened = page.locator(f'#my-access-modal .my-access-case[data-case-id="{world["case"]["id"]}"] .my-access-opened')
    expect(opened).to_contain_text("None so far.", timeout=15000)
    expect(opened.locator(".my-access-opened-ended")).to_have_count(0)
    page.route(re.compile(r".*/me/compliance-access$"), past_its_time)
    page.evaluate("() => window.openMyAccess()")
    expect(opened.locator(".my-access-opened-ended")).to_contain_text("may not be complete", timeout=15000)
    expect(opened).not_to_contain_text("None so far.")
    assert errors == []
