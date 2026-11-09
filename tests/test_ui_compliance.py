"""The Compliance page in a real browser, in both skins (static/js/compliance.js, static/css/compliance.css, the
auditor's parts of static/js/activity.js).

The whole flow, each step through the screens and the app's own step-up dialog (the password and a recovery code):
an administrator proposes the auditor right, a second one reviews where the account came from and approves it; the
auditor sees the badge, asks for a case on the new-case sheet (the owners' preview shows the note); the second
administrator finds it under "Waiting for my approval", reads the provenance and the justification, and approves it;
the owner sees the banner; the auditor opens the workspace, moves through the files with j and k (each opened, with
the watermark), exports them (one archive, through the download), and closes the case. Then, on one case approved
through the API: the workspace on a phone (one screen at a time, nothing wider than the screen), the case list, the
new-case sheet and an administrator's tabs, sheets and case page on a phone (in both skins), the Activity page
for the auditor (no administrator's panel asked for, the Reveal dialog, the Case chip), the badge and the nav for
each kind of account, and the count of what waits for an administrator.

Waits are on state, never on time (the timing rules of the browser tests).
"""
import io
import json
import re
import zipfile
from datetime import datetime

import pytest
from playwright.sync_api import Browser, Page, expect

from _account_change_helpers import psql
from _auditor_helpers import compliance_receipt, forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import CASE_TEXT, approved_case, forget_cases, owner_with_vault
from conftest import BASE_URL

pytestmark = pytest.mark.ui

DESK = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}
JUSTIFICATION = "Suspected exfiltration of client records, ticket SEC-2041, raised by the security team."
NOTE = "Your vault is part of an internal review; nothing in it is changed."

# The errors each page reported, and the skin it was opened in, by page.
ERRORS, SKINS = {}, {}


def _page(browser: Browser, skin: str, viewport=DESK) -> Page:
    context = browser.new_context(base_url=BASE_URL, viewport=viewport, accept_downloads=True)
    context.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    page = context.new_page()
    ERRORS[id(page)], SKINS[id(page)] = [], skin
    page.on("pageerror", lambda exc: ERRORS[id(page)].append(str(exc)))
    return page


def _errors(page: Page) -> list:
    return ERRORS.get(id(page), [])


def _close(page: Page):
    try:
        page.context.close()
    except Exception:  # noqa: BLE001 -- already closed
        pass


def _login(page: Page, account, codes=None):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", account["_username"])
    page.fill("#password", account["_password"])
    page.click("#login-form button[type=submit]")
    if codes is not None:
        card = page.locator("#login-second-factor")
        expect(card).to_be_visible(timeout=15000)
        card.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#sf-code-input", codes.pop(0))
        card.locator("button").last.click()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => document.documentElement.getAttribute('data-ui') || 'v1'") == SKINS[id(page)]


def _step_up(page: Page, account, codes):
    modal = page.locator("#stepup-modal.active")
    expect(modal).to_be_visible(timeout=15000)
    modal.get_by_role("button", name="Use a recovery code instead").click()
    modal.locator("#stepup-code-input").fill(codes.pop(0))
    modal.locator("#stepup-password-input").fill(account["_password"])
    modal.get_by_role("button", name="Confirm").click()
    expect(page.locator("#stepup-modal.active")).to_have_count(0, timeout=15000)


def _compliance(page: Page, *, drawer=False):
    nav = page.locator("#nav-compliance")
    if drawer:
        # On a phone the sidebar is a drawer: the item is there, shown once the account's standing is read.
        expect(nav).to_have_css("display", "flex", timeout=15000)
        page.evaluate("() => navigateToSection('compliance')")
    else:
        expect(nav).to_be_visible(timeout=15000)
        nav.scroll_into_view_if_needed()
        nav.click()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)


def _tab(page: Page, key: str):
    tab = page.locator(f'#compliance-section .tab-btn[data-cmp-tab="{key}"]')
    tab.click()
    expect(tab).to_have_attribute("aria-selected", "true")


def _confirm_dialog(page: Page):
    modal = page.locator("#confirm-modal.active")
    expect(modal).to_be_visible(timeout=10000)
    modal.locator("#confirm-modal-confirm-btn").click()
    expect(page.locator("#confirm-modal.active")).to_have_count(0)


def _prompt(page: Page, text: str):
    modal = page.locator("#confirm-modal.active")
    expect(modal).to_be_visible(timeout=10000)
    modal.locator("#confirm-modal-input").fill(text)
    modal.locator("#confirm-modal-confirm-btn").click()
    expect(page.locator("#confirm-modal.active")).to_have_count(0)


# What sticks out past the screen's right edge, for the message of a failed width check.
_WIDE = """() => Array.from(document.querySelectorAll('body *')).filter((n) => {
    const r = n.getBoundingClientRect();
    return r.width && r.right > window.innerWidth + 1 && getComputedStyle(n).position !== 'fixed';
}).slice(0, 8).map((n) => n.tagName + '.' + String(n.className).slice(0, 60) + ' ' + Math.round(n.getBoundingClientRect().right))"""


def _fits(page: Page):
    sizes = page.evaluate("() => ({doc: document.documentElement.scrollWidth, view: window.innerWidth})")
    assert sizes["doc"] <= sizes["view"], (sizes, page.evaluate(_WIDE))


def _awake(*clients):
    """Drop the pooled connections of API clients left idle while a browser worked: the server closes an idle
    keep-alive connection, and a POST sent on one just as it closes is lost rather than retried."""
    for client in clients:
        client.session.close()


def _upload(client, vid, name, data, mime):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, data, mime))])
    assert r.status_code in (200, 201), r.text


def _png() -> bytes:
    """A valid 2x2 PNG, built here."""
    import struct
    import zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    rows = b"".join(b"\x00" + b"\xff\x00\x00" * 2 for _ in range(2))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


PNG = _png()


@pytest.fixture(params=["v2", "v1"])
def skin(request):
    return request.param


@pytest.fixture
def flow_world(admin):
    """Fresh people for one run of the flow: ada and bob (independent administrators with recovery codes), uma (an
    account fit to be an auditor, not one yet), olga (an owner with three files)."""
    with two_admins(admin) as admins:
        uma, uma_c, uma_codes = new_auditor_account(admin)
        olga, olga_c, vid = owner_with_vault(admin)
        _upload(olga_c, vid, "minutes-monday.txt", b"The board met on Monday.", "text/plain")
        _upload(olga_c, vid, "minutes-tuesday.txt", b"The board met on Tuesday.", "text/plain")
        _upload(olga_c, vid, "chart.png", PNG, "image/png")
        try:
            yield {"admins": admins, "uma": (uma, uma_c, uma_codes), "olga": (olga, olga_c, vid)}
        finally:
            cids = psql(f"SELECT coalesce(string_agg(id::text, ','), '') FROM compliance_cases "
                        f"WHERE auditor_id = '{uma['id']}'")
            forget_cases([c for c in cids.split(",") if c], [vid])
            forget_grants(uma["id"])


def test_the_whole_flow_in_the_browser(browser: Browser, flow_world, skin):
    ada, _ada_c, ada_codes = flow_world["admins"]["ada"]
    bob, _bob_c, bob_codes = flow_world["admins"]["bob"]
    uma, _uma_c, uma_codes = flow_world["uma"]
    olga, _olga_c, vid = flow_world["olga"]
    pages = []

    def page_for(account, codes):
        p = _page(browser, skin)
        pages.append(p)
        _login(p, account, codes)
        return p

    try:
        # ada proposes the right for uma.
        a = page_for(ada, ada_codes)
        _compliance(a)
        _tab(a, "auditors")
        a.locator(".cmp-propose").click()
        sheet = a.locator("#cmp-propose-sheet.active")
        sheet.locator("input").first.fill(uma["_username"])
        sheet.locator(".cmp-propose-go").click()
        _step_up(a, ada, ada_codes)
        row = a.locator(f'.cmp-grant-row[data-username="{uma["_username"]}"]')
        expect(row.locator(".cmp-status")).to_have_attribute("data-status", "proposed", timeout=15000)

        # bob reviews where the account came from, and approves.
        b = page_for(bob, bob_codes)
        _compliance(b)
        _tab(b, "auditors")
        b.locator(f'.cmp-grant-row[data-username="{uma["_username"]}"] .cmp-grant-review').click()
        sheet = b.locator("#cmp-grant-sheet.active")
        expect(sheet.locator(".cmp-provenance")).to_contain_text("their own", timeout=15000)
        expect(sheet.locator(".cmp-provenance")).to_contain_text("Authenticator")
        sheet.locator(".cmp-grant-approve").click()
        _step_up(b, bob, bob_codes)
        row = b.locator(f'.cmp-grant-row[data-username="{uma["_username"]}"]')
        expect(row.locator(".cmp-status")).to_have_attribute("data-status", "active", timeout=15000)

        # uma: the badge, the nav, and a case asked for on the sheet.
        u = page_for(uma, uma_codes)
        expect(u.locator("#auditor-badge")).to_have_text("Auditor", timeout=15000)
        expect(u.locator('.sidebar-item[data-section="activity"]')).to_be_visible()
        _compliance(u)
        u.locator(".cmp-new-case").click()
        sheet = u.locator("#cmp-new-case.active")
        expect(sheet).to_be_visible()
        selects = sheet.locator("select")
        selects.nth(0).select_option("internal_investigation")
        selects.nth(1).select_option("legal_obligation")
        sheet.locator("textarea").nth(0).fill(JUSTIFICATION)
        sheet.locator("textarea").nth(1).fill(NOTE)
        expect(sheet.locator(".cmp-preview")).to_contain_text(NOTE)
        expect(sheet.locator(".cmp-preview")).to_contain_text("internal investigation")
        sheet.locator(".cmp-pick-row input").fill(olga["_username"])
        sheet.locator(".cmp-pick").click()
        box = sheet.locator(f'.cmp-vault-picker input[data-vault-id="{vid}"]')
        expect(box).to_be_visible(timeout=15000)
        box.check()
        expect(sheet.locator(f'.cmp-picked-row[data-vault-id="{vid}"]')).to_be_visible()
        expect(sheet.locator(".cmp-new-summary")).to_contain_text("in 1 vault")
        sheet.locator(".cmp-check", has_text="Allow exports").locator("input").check()
        expect(sheet.locator(".cmp-new-summary")).to_contain_text("and export copies")
        sheet.locator(".cmp-send").scroll_into_view_if_needed()
        sheet.locator(".cmp-send").click()
        _step_up(u, uma, uma_codes)
        page_case = u.locator(".cmp-case")
        expect(page_case.locator(".cmp-case-head .cmp-status")).to_have_attribute("data-status", "pending",
                                                                                   timeout=15000)
        case_id = page_case.get_attribute("data-case-id")

        # bob finds it waiting for his approval, reads the provenance and the justification, and approves.
        _compliance(b)
        _tab(b, "cases")
        chip = b.locator('.cmp-chip[data-filter="mine"]')
        expect(chip).to_be_visible(timeout=15000)
        chip.click()
        expect(chip).to_have_attribute("aria-checked", "true")
        b.locator(f'.cmp-case-row[data-case-id="{case_id}"]').click()
        expect(b.locator(".cmp-provenance")).to_contain_text("Created", timeout=15000)
        expect(b.locator(".cmp-justification")).to_contain_text(JUSTIFICATION)
        b.locator(".cmp-approve").click()
        _confirm_dialog(b)
        _step_up(b, bob, bob_codes)
        expect(b.locator(".cmp-case-head .cmp-status")).to_have_attribute("data-status", "active", timeout=15000)
        expect(b.locator(".cmp-told")).to_contain_text("Owners told")

        # olga, the owner, sees the banner.
        o = page_for(olga, None)
        banner = o.locator('#notice-banners .notice-banner[data-notice="compliance-access"]')
        expect(banner).to_be_visible(timeout=15000)

        # uma opens the workspace and moves through the files with j and k.
        _compliance(u)
        u.locator(f'.cmp-case-row[data-case-id="{case_id}"]').click()
        u.locator(".cmp-open-ws").click()
        rows = u.locator(".cmp-file-row")
        expect(rows).to_have_count(3, timeout=15000)
        ids = [rows.nth(i).get_attribute("data-file-id") for i in range(3)]
        viewer = u.locator(".cmp-ws-viewer")
        u.locator(".cmp-ws-number").click()          # the page has the focus, not an input
        u.keyboard.press("j")
        expect(viewer).to_have_attribute("data-file-id", ids[0])
        expect(viewer.locator(".cmp-viewer-text")).to_have_text("The board met on Monday.", timeout=15000)
        expect(viewer.locator(".cmp-watermark")).to_contain_text(uma["_username"])
        u.keyboard.press("j")
        expect(viewer).to_have_attribute("data-file-id", ids[1])
        expect(viewer.locator(".cmp-viewer-text")).to_have_text("The board met on Tuesday.", timeout=15000)
        u.keyboard.press("ArrowDown")
        expect(viewer).to_have_attribute("data-file-id", ids[2])
        expect(viewer.locator(".cmp-viewer-img")).to_be_visible(timeout=15000)
        u.keyboard.press("k")
        expect(viewer).to_have_attribute("data-file-id", ids[1])
        expect(u.locator(".cmp-file-row.selected")).to_have_attribute("data-file-id", ids[1])
        expect(viewer.locator(".cmp-viewer-text")).to_have_text("The board met on Tuesday.", timeout=15000)
        opened = psql("SELECT count(DISTINCT resource_id) FROM audit_logs WHERE action = 'case_file_viewed' "
                      f"AND status = 'success' AND case_id = '{case_id}'")
        assert opened == "3", opened

        # The case log lists what was recorded under the case.
        u.locator('.cmp-ws-tab[data-tab="log"]').click()
        expect(u.locator(".cmp-log-row").first).to_be_visible(timeout=15000)
        u.locator('.cmp-ws-tab[data-tab="files"]').click()

        # The export: one archive, through the download, after the step-up.
        u.locator(".cmp-ws-export").click()
        u.locator("#cmp-export-sheet.active .cmp-export-go").click()
        with u.expect_download(timeout=60000) as got:
            _step_up(u, uma, uma_codes)
        with open(got.value.path(), "rb") as fh:
            data = fh.read()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
        assert "SHA256SUMS" in names and any(n.endswith("minutes-monday.txt") for n in names), names
        done = psql("SELECT count(*) FROM audit_logs WHERE action = 'case_export_completed' AND status = 'success' "
                    f"AND case_id = '{case_id}'")
        assert done == "1", done

        # uma closes the case (its hold is released with it: the step-up again).
        u.locator(".cmp-ws-close").click()
        _prompt(u, "The review is complete.")
        _step_up(u, uma, uma_codes)
        expect(u.locator(".cmp-case-head .cmp-status")).to_have_attribute("data-status", "closed", timeout=15000)
        for p in pages:
            assert _errors(p) == [], _errors(p)
    finally:
        for p in pages:
            _close(p)


# --------------------------------------------------------------------------- on one case approved through the API

@pytest.fixture(scope="module")
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        _upload(olga_c, vid, "a-first.txt", b"first", "text/plain")
        _upload(olga_c, vid, "b-second.txt", b"second", "text/plain")
        case = approved_case(admins, (uma, uma_c, codes), [vid])
        try:
            yield {"admins": admins, "uma": uma, "uma_c": uma_c, "codes": codes, "olga": olga, "olga_c": olga_c,
                   "vid": vid, "case": case}
        finally:
            forget_cases([case["id"]], [vid])
            forget_grants(uma["id"])


@pytest.mark.parametrize("ui", ["v2", "v1"])
def test_the_workspace_on_a_phone_shows_one_screen_at_a_time(browser: Browser, world, ui):
    page = _page(browser, ui, PHONE)
    try:
        _login(page, world["uma"], world["codes"])
        # The top bar has no room for the badge on a phone: the account menu says it.
        expect(page.locator("#auditor-badge-menu")).to_have_text("Auditor", timeout=15000)
        expect(page.locator("#auditor-badge")).to_be_hidden()
        _compliance(page, drawer=True)
        page.locator(f'.cmp-case-row[data-case-id="{world["case"]["id"]}"]').click()
        page.locator(".cmp-open-ws").click()
        ws = page.locator(".cmp-ws")
        expect(ws).to_have_attribute("data-screen", "list", timeout=15000)
        expect(page.locator(".cmp-file-row")).to_have_count(2, timeout=15000)
        expect(page.locator(".cmp-ws-viewer")).to_be_hidden()
        page.locator(".cmp-file-row").first.click()
        expect(ws).to_have_attribute("data-screen", "file")
        expect(page.locator(".cmp-ws-files")).to_be_hidden()
        expect(page.locator(".cmp-viewer-text")).to_have_text("first", timeout=15000)
        page.locator(".cmp-viewer-next").click()
        expect(page.locator(".cmp-viewer-text")).to_have_text("second", timeout=15000)
        page.locator(".cmp-viewer-back").click()
        expect(ws).to_have_attribute("data-screen", "list")
        expect(page.locator(".cmp-ws-files")).to_be_visible()
        _fits(page)
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)


@pytest.mark.parametrize("ui", ["v2", "v1"])
def test_the_case_list_and_the_new_case_sheet_fit_a_phone(browser: Browser, world, ui):
    page = _page(browser, ui, PHONE)
    try:
        _login(page, world["uma"], world["codes"])
        _compliance(page, drawer=True)
        expect(page.locator(f'.cmp-case-row[data-case-id="{world["case"]["id"]}"]')).to_be_visible(timeout=15000)
        page.locator(".cmp-new-case").click()
        sheet = page.locator("#cmp-new-case.active .cmp-sheet-content")
        expect(sheet).to_be_visible()
        box = sheet.bounding_box()
        assert box["width"] <= PHONE["width"] + 1, box
        _fits(page)
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)


def _sheet_fits(page: Page, sheet_id: str, opener: str, shows: str = None):
    page.locator(opener).click()
    sheet = page.locator(f"#{sheet_id}.active .cmp-sheet-content")
    expect(sheet).to_be_visible()
    if shows:
        expect(sheet.locator(shows)).to_be_visible()
    box = sheet.bounding_box()
    assert box["width"] <= PHONE["width"] + 1, box
    _fits(page)
    page.locator(f"#{sheet_id}.active .modal-close").click()
    expect(page.locator(f"#{sheet_id}.active")).to_have_count(0)


@pytest.mark.parametrize("ui", ["v2", "v1"])
def test_an_administrators_tabs_sheets_and_a_case_fit_a_phone(browser: Browser, world, ui):
    """An administrator's Cases, Legal holds and Auditors tabs, the place-hold and propose sheets, and a case's page:
    each no wider than a phone, in both skins."""
    ada, _ada_c, ada_codes = world["admins"]["ada"]
    page = _page(browser, ui, PHONE)
    try:
        _login(page, ada, ada_codes)
        _compliance(page, drawer=True)
        expect(page.locator(f'.cmp-case-row[data-case-id="{world["case"]["id"]}"]')).to_be_visible(timeout=15000)
        _fits(page)
        _tab(page, "holds")
        expect(page.locator(".cmp-place-hold")).to_be_visible(timeout=15000)
        _fits(page)
        _sheet_fits(page, "cmp-hold-sheet", ".cmp-place-hold")
        _tab(page, "auditors")
        expect(page.locator(".cmp-propose")).to_be_visible(timeout=15000)
        _fits(page)
        # The sheet says, before anyone proposes, whom the account's creator keeps from approving.
        _sheet_fits(page, "cmp-propose-sheet", ".cmp-propose", shows=".cmp-propose-creator")
        _tab(page, "cases")
        row = page.locator(f'.cmp-case-row[data-case-id="{world["case"]["id"]}"]')
        expect(row).to_be_visible(timeout=15000)
        row.click()
        expect(page.locator(".cmp-case-head")).to_be_visible(timeout=15000)
        _fits(page)
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)


def test_an_auditor_reads_activity_reveals_a_recorded_name_and_selects_a_case(browser: Browser, world):
    vid, case = world["vid"], world["case"]
    event = psql("SELECT id FROM audit_logs WHERE action IN ('file_upload', 'file_uploaded') "
                 f"AND details->>'vault_id' = '{vid}' ORDER BY timestamp DESC LIMIT 1")
    assert event, "no upload recorded in the owner's vault"
    page = _page(browser, "v2")
    asked = []
    page.on("request", lambda r: asked.append(r.url))
    try:
        _login(page, world["uma"], world["codes"])
        nav = page.locator('.sidebar-item[data-section="activity"]')
        expect(nav).to_be_visible(timeout=15000)
        page.evaluate("(ev) => history.replaceState(null, '', location.pathname + '#activity?range=30d&ev=' + ev)",
                      event)
        nav.click()
        detail = page.locator("#act-detail")
        expect(detail).to_be_visible(timeout=20000)
        expect(page.locator("#act-blocked")).to_be_hidden()
        # Reveal: the reason, then the names as recorded (or that none was recorded in full).
        detail.locator(".act-reveal").scroll_into_view_if_needed()
        detail.locator(".act-reveal").click()
        sheet = page.locator("#cmp-reveal-sheet.active")
        sheet.locator("select").select_option("internal_investigation")
        sheet.locator("textarea").fill("Checking who uploaded the file named in the incident ticket.")
        with page.expect_request(lambda r: r.url.endswith(f"/activity/events/{event}/reveal"),
                                 timeout=15000) as sent:
            sheet.locator(".cmp-reveal-go").click()
        expect(sheet.locator(".cmp-reveal-result")).not_to_be_empty(timeout=15000)
        # The event's time goes with it: an event of an archived day is looked for in the hour it names.
        at = json.loads(sent.value.post_data)["at"]
        stored = float(psql(f"SELECT extract(epoch FROM timestamp) FROM audit_logs WHERE id = '{event}'"))
        assert at and abs(datetime.fromisoformat(at.replace("Z", "+00:00")).timestamp() - stored) < 0.001, (at, stored)
        done = psql("SELECT count(*) FROM audit_logs WHERE action = 'audit_name_revealed' "
                    f"AND details->>'event_id' = '{event}'")
        assert done == "1", done
        sheet.locator(".modal-close").click()
        expect(page.locator("#cmp-reveal-sheet.active")).to_have_count(0)
        # The Case chip lists the auditor's active case; choosing it reads the list under the case.
        chip = page.locator("#act-case")
        expect(chip.locator(f'option[value="{case["id"]}"]')).to_have_count(1)
        with page.expect_response(lambda r: "/activity/events" in r.url and f"case={case['id']}" in r.url,
                                  timeout=20000) as got:
            chip.select_option(case["id"])
        assert got.value.status == 200
        # The administrators' own reads were never asked for.
        assert not [x for x in asked if "/activity/now" in x or "/activity/temp-credentials" in x], asked
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)


def test_the_badge_and_the_nav_for_each_kind_of_account(browser: Browser, world):
    # The owner: no badge, no Compliance, no Activity.
    page = _page(browser, "v2")
    try:
        _login(page, world["olga"])
        expect(page.locator("#my-access-btn")).to_be_attached()
        expect(page.locator("#nav-compliance")).to_be_hidden()
        expect(page.locator("#auditor-badge")).to_have_count(0)
        expect(page.locator('.sidebar-item[data-section="activity"]')).to_be_hidden()
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)
    # An administrator: Compliance, with the count of what waits for their approval.
    bob, _bob_c, bob_codes = world["admins"]["bob"]
    uma_c = world["uma_c"]
    _awake(uma_c)
    r = uma_c.post("/compliance/cases", json={"scope": [{"kind": "vault", "target_id": world["vid"]}], **CASE_TEXT},
                   headers=compliance_receipt(uma_c, "compliance.case.request", world["uma"]["_password"],
                                              world["codes"]))
    assert r.status_code == 201, r.text
    waiting = r.json()["id"]
    page = _page(browser, "v2")
    try:
        _login(page, bob, bob_codes)
        expect(page.locator("#nav-compliance-count")).to_have_text(re.compile(r"^[1-9][0-9]*$"), timeout=15000)
        expect(page.locator("#auditor-badge")).to_have_count(0)
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)
        _awake(uma_c)
        uma_c.post(f"/compliance/cases/{waiting}/withdraw")


def test_a_password_vault_opens_in_the_workspace_with_its_password(browser: Browser, world):
    olga_c = world["olga_c"]
    _awake(olga_c, world["uma_c"], *[c for _a, c, _codes in world["admins"].values()])
    pv = olga_c.create_vault(password="Vault-Pass-2026!")["id"]
    r = olga_c.post(f"/vaults/{pv}/files", files=[("files", ("secret-plan.txt", b"the plan", "text/plain"))],
                    headers={"X-Vault-Password": "Vault-Pass-2026!"})
    assert r.status_code in (200, 201), r.text
    case = approved_case(world["admins"], (world["uma"], world["uma_c"], world["codes"]), [pv])
    page = _page(browser, "v2")
    try:
        _login(page, world["uma"], world["codes"])
        _compliance(page)
        page.locator(f'.cmp-case-row[data-case-id="{case["id"]}"]').click()
        page.locator(".cmp-open-ws").click()
        row = page.locator(".cmp-file-row")
        expect(row).to_have_count(1, timeout=15000)
        expect(row).to_contain_text("Name hidden until the vault is unlocked")
        form = page.locator(f'.cmp-tree-vault[data-vault-id="{pv}"] .cmp-unlock')
        form.locator("input").fill("not the password")
        form.locator("button").click()
        expect(form.locator("small")).not_to_have_text("For 15 minutes, in this case.", timeout=15000)
        form.locator("input").fill("Vault-Pass-2026!")
        form.locator("button").click()
        expect(page.locator(".cmp-file-row")).to_contain_text("secret-plan.txt", timeout=15000)
        expect(page.locator(f'.cmp-tree-vault[data-vault-id="{pv}"] .cmp-unlock')).to_have_count(0)
        page.locator(".cmp-file-row").click()
        expect(page.locator(".cmp-viewer-text")).to_have_text("the plan", timeout=15000)
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)
        forget_cases([case["id"]], [pv])
        _awake(olga_c)
        olga_c.delete_vault(pv, vault_password="Vault-Pass-2026!")


def test_a_legal_hold_is_placed_confirmed_and_released_in_the_browser(browser: Browser, world):
    ada, _ada_c, ada_codes = world["admins"]["ada"]
    bob, _bob_c, bob_codes = world["admins"]["bob"]
    olga, olga_c = world["olga"], world["olga_c"]
    _awake(olga_c)
    held = olga_c.create_vault()["id"]
    pages = []
    try:
        a = _page(browser, "v1")
        pages.append(a)
        _login(a, ada, ada_codes)
        _compliance(a)
        _tab(a, "holds")
        a.locator(".cmp-place-hold").click()
        sheet = a.locator("#cmp-hold-sheet.active")
        sheet.locator("textarea").nth(0).fill("Preserve the records named in the claim served last week, case 2026-17.")
        sheet.locator("textarea").nth(1).fill("Files deleted from your vault are kept for a legal matter.")
        sheet.locator(".cmp-pick-row input").fill(olga["_username"])
        sheet.locator(".cmp-pick-row button").click()
        sheet.locator(f'.cmp-vault-picker input[data-vault-id="{held}"]').check()
        sheet.locator(".cmp-hold-go").click()
        _step_up(a, ada, ada_codes)
        card = a.locator(".cmp-hold").filter(has=a.locator(".cmp-h", has_text="Legal hold")).first
        expect(card).to_be_visible(timeout=15000)
        case_id = psql("SELECT case_id FROM legal_hold_vaults WHERE vault_id = '" + held + "' AND released_at IS NULL")
        assert case_id, "no hold was placed"

        b = _page(browser, "v1")
        pages.append(b)
        _login(b, bob, bob_codes)
        _compliance(b)
        _tab(b, "holds")
        card = b.locator(f'.cmp-hold[data-case-id="{case_id}"]')
        card.locator(".cmp-hold-confirm").click()
        _step_up(b, bob, bob_codes)
        card = b.locator(f'.cmp-hold[data-case-id="{case_id}"]')
        expect(card).to_contain_text("Confirmed", timeout=15000)
        card.locator(".cmp-hold-release").click()
        _prompt(b, "The claim was settled.")
        _step_up(b, bob, bob_codes)
        expect(b.locator(f'.cmp-hold[data-case-id="{case_id}"]')).to_contain_text("Released", timeout=15000)
        assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' AND released_at IS NULL") == "0"
        for p in pages:
            assert _errors(p) == [], _errors(p)
    finally:
        for p in pages:
            _close(p)
        cid = psql(f"SELECT coalesce(string_agg(case_id::text, ','), '') FROM legal_hold_vaults WHERE vault_id = '{held}'")
        forget_cases([c for c in cid.split(",") if c], [held])
        _awake(olga_c)
        olga_c.delete_vault(held)


# --------------------------------------------------------------------------- the addresses the viewer draws from

RAN = "SCRIPT-RAN"
XHTML = (f'<html xmlns="http://www.w3.org/1999/xhtml"><head><title>quiet</title></head>'
         f"<body><script>document.title = '{RAN}';</script></body></html>")


@pytest.fixture(scope="module")
def typed_world(admin):
    """A case on a vault that holds a page its uploader called a picture, the same page called a video, and a real
    picture."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        _upload(olga_c, vid, "a-page-called-a-picture.img", XHTML.encode(), "image/x-thing+xml")
        _upload(olga_c, vid, "b-page-called-a-video.vid", XHTML.encode(), "video/x-thing+xml")
        _upload(olga_c, vid, "c-picture.png", _png(), "image/png")
        case = approved_case(admins, (uma, uma_c, codes), [vid])
        try:
            yield {"uma": uma, "codes": codes, "case": case}
        finally:
            forget_cases([case["id"]], [vid])
            forget_grants(uma["id"])


def _open_alone(page: Page, address: str) -> Page:
    """Open an address in a new tab of the same browser, as a person pasting it would."""
    tab = page.context.new_page()
    tab.goto(address, wait_until="load", timeout=10000)
    tab.wait_for_timeout(500)
    return tab


def test_a_page_stored_as_a_picture_or_a_video_never_runs_from_the_viewers_address(browser: Browser, typed_world):
    page = _page(browser, "v2")
    try:
        _login(page, typed_world["uma"], typed_world["codes"])
        # Control: this browser runs an XHTML object address opened on its own, with the vault's origin, so the
        # checks below can fail.
        address = page.evaluate("(x) => URL.createObjectURL(new Blob([x], { type: 'application/xhtml+xml' }))", XHTML)
        tab = _open_alone(page, address)
        try:
            assert tab.title() == RAN, "control: this browser no longer runs an XHTML object address"
            assert tab.evaluate("() => location.origin") == page.evaluate("() => location.origin")
        finally:
            tab.close()
        _compliance(page)
        page.locator(f'.cmp-case-row[data-case-id="{typed_world["case"]["id"]}"]').click()
        page.locator(".cmp-open-ws").click()
        rows = page.locator(".cmp-file-row")
        expect(rows).to_have_count(3, timeout=15000)
        viewer = page.locator(".cmp-ws-viewer")
        # The page called a picture, then called a video: shown as its text, never drawn from an address.
        for index in (0, 1):
            rows.nth(index).click()
            expect(viewer.locator(".cmp-viewer-text")).to_contain_text("document.title", timeout=15000)
            expect(viewer.locator(".cmp-viewer-img, .cmp-viewer-media")).to_have_count(0)
            assert page.title() != RAN
        # The real picture still shows, drawn from an address made under its own type, which opens as a picture.
        rows.nth(2).click()
        img = viewer.locator(".cmp-viewer-img")
        expect(img).to_be_visible(timeout=15000)
        page.wait_for_function("() => { const i = document.querySelector('.cmp-viewer-img');"
                               " return i && i.complete && i.naturalWidth === 2; }", timeout=15000)
        src = img.get_attribute("src") or ""
        assert src.startswith("blob:"), src
        tab = _open_alone(page, src)
        try:
            assert tab.evaluate("() => document.contentType") == "image/png"
            assert tab.title() != RAN
        finally:
            tab.close()
        assert _errors(page) == [], _errors(page)
    finally:
        _close(page)
