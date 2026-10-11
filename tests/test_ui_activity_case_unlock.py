"""The auditor's "Show names in this case" form on the Activity page, in a real browser, in both skins and on a
phone (static/js/activity.js, app/services/activity_case.py).

An auditor who is not a member of a vault with a vault password, with a case on that vault selected, opens the
event of a file uploaded to it: the details say the vault's password hides the name and ask for it in the case. A
wrong password says so and asks again; the right one shows the file's name without a reload, and the form goes.
Before the case is selected the same event reads "Not shown" with no form, and an administrator is never offered
it. test_activity_auditor.py and test_activity_auditor_form.py hold the rules offline.

Waits are on state, never on time (the timing rules of the browser tests).
"""
import pytest
from playwright.sync_api import Browser, Page, expect

from _account_change_helpers import psql
from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, owner_with_vault, wait_for
from conftest import BASE_URL, unique

pytestmark = pytest.mark.ui

DESK = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}
PASSWORD = "Vault-Pass-2026!"
HIDDEN = "Name hidden: the vault has a password"
NOT_SHOWN = "Not shown: you are not a member of this vault"
OFFER = "Show names in this case"

ERRORS, SKINS = {}, {}


def _page(browser: Browser, skin: str, viewport) -> Page:
    context = browser.new_context(base_url=BASE_URL, viewport=viewport)
    context.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    page = context.new_page()
    ERRORS[id(page)], SKINS[id(page)] = [], skin
    page.on("pageerror", lambda exc: ERRORS[id(page)].append(str(exc)))
    return page


def _close(page: Page):
    try:
        page.context.close()
    except Exception:  # noqa: BLE001 -- already closed
        pass


def _login(page: Page, account, codes):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", account["_username"])
    page.fill("#password", account["_password"])
    page.click("#login-form button[type=submit]")
    card = page.locator("#login-second-factor")
    expect(card).to_be_visible(timeout=15000)
    card.get_by_role("button", name="Use a recovery code instead").click()
    page.fill("#sf-code-input", codes.pop(0))
    card.locator("button").last.click()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => document.documentElement.getAttribute('data-ui') || 'v1'") == SKINS[id(page)]


def _activity(page: Page, hash_: str):
    """The Activity page, entered from the sidebar (a drawer on a phone) with ``hash_`` as its link."""
    page.evaluate("(h) => history.replaceState(null, '', location.pathname + h)", hash_)
    toggle = page.locator("#mobile-nav-toggle")
    if toggle.is_visible():
        toggle.click()
    nav = page.locator('.sidebar-item[data-section="activity"]')
    expect(nav).to_be_visible(timeout=15000)
    nav.click()
    expect(page.locator("#activity-section")).to_be_visible(timeout=15000)
    expect(page.locator("#act-blocked")).to_be_hidden()


def _detail(page: Page, phone: bool):
    return page.locator("#activity-event-modal" if phone else "#act-detail")


# What sticks out past the screen's right edge, for the message of a failed width check.
_WIDE = """() => Array.from(document.querySelectorAll('body *')).filter((n) => {
    const r = n.getBoundingClientRect();
    return r.width && r.right > window.innerWidth + 1 && getComputedStyle(n).position !== 'fixed';
}).slice(0, 8).map((n) => n.tagName + '.' + String(n.className).slice(0, 60) + ' ' + Math.round(n.getBoundingClientRect().right))"""


def _fits(page: Page):
    sizes = page.evaluate("() => ({doc: document.documentElement.scrollWidth, view: window.innerWidth})")
    assert sizes["doc"] <= sizes["view"], (sizes, page.evaluate(_WIDE))


@pytest.fixture(scope="module")
def world(admin):
    """uma, an auditor with a case on olga's vault with a vault password (uma is no member of it), and the event of a
    file uploaded to it."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        _olga, olga_c, _plain = owner_with_vault(admin)
        pv = olga_c.create_vault(name=unique("locked"), password=PASSWORD)["id"]
        name = f"{unique('plan')}.txt"
        up = olga_c.post(f"/vaults/{pv}/files", files=[("files", (name, b"the plan", "text/plain"))],
                         headers={"X-Vault-Password": PASSWORD})
        assert up.status_code in (200, 201), up.text
        fid = up.json()["files"][0]["id"]
        event = wait_for(lambda: psql(f"SELECT id FROM audit_logs WHERE resource_type = 'file' "
                                      f"AND resource_id = '{fid}' ORDER BY timestamp DESC LIMIT 1"))
        case = approved_case(admins, (uma, uma_c, codes), [pv])
        try:
            yield {"admins": admins, "uma": uma, "codes": codes, "pv": pv, "name": name, "event": event,
                   "case": case}
        finally:
            forget_cases([case["id"]], [pv])
            forget_grants(uma["id"])
            olga_c.session.close()
            olga_c.delete_vault(pv, vault_password=PASSWORD)


@pytest.mark.parametrize("ui,viewport", [("v2", DESK), ("v1", DESK), ("v2", PHONE), ("v1", PHONE)],
                         ids=["v2-desk", "v1-desk", "v2-phone", "v1-phone"])
def test_an_auditor_unlocks_a_vault_in_the_case_from_the_activity_page(browser: Browser, world, ui, viewport):
    phone = viewport is PHONE
    ev, case, name = world["event"], world["case"], world["name"]
    page = _page(browser, ui, viewport)
    try:
        _login(page, world["uma"], world["codes"])
        detail = _detail(page, phone)
        if not phone:
            # Without the case: the event's file is not shown, and no password is asked for.
            _activity(page, f"#activity?range=30d&ev={ev}")
            expect(detail).to_contain_text(NOT_SHOWN, timeout=20000)
            expect(detail.locator("form.act-unlock")).to_have_count(0)
            expect(detail).not_to_contain_text(OFFER)
            detail.locator(".act-d-close").click()
            expect(detail).to_be_hidden()
        else:
            _activity(page, "#activity?range=30d")
        chip = page.locator("#act-case")
        expect(chip.locator(f'option[value="{case["id"]}"]')).to_have_count(1, timeout=15000)
        with page.expect_response(lambda r: "/activity/events" in r.url and f"case={case['id']}" in r.url,
                                  timeout=20000) as got:
            chip.select_option(case["id"])
        assert got.value.status == 200
        row = page.locator((f'#activity-cards .act-card[data-id="{ev}"]' if phone
                            else f'#activity-rows tr.act-row[data-id="{ev}"]'))
        expect(row).to_be_visible(timeout=20000)
        row.click()
        expect(detail).to_be_visible(timeout=15000)
        expect(detail).to_contain_text(HIDDEN, timeout=15000)
        expect(detail).not_to_contain_text(name)
        form = detail.locator("form.act-unlock")
        expect(form).to_have_count(1)
        expect(form.locator("button[type=submit]")).to_have_text(OFFER)
        form.scroll_into_view_if_needed()
        expect(form).to_be_visible()
        if phone:
            box = form.bounding_box()
            assert box["x"] >= 0 and box["x"] + box["width"] <= viewport["width"] + 1, box
            _fits(page)
        else:
            # A wrong password: said so, the form stays and asks again.
            form.locator("input[type=password]").fill("not the password")
            form.locator("button[type=submit]").click()
            expect(form.locator(".act-unlock-msg")).not_to_have_text("For 15 minutes, in this case.", timeout=15000)
            expect(form.locator("button[type=submit]")).to_be_enabled()
            expect(detail).not_to_contain_text(name)
        form.locator("input[type=password]").fill(PASSWORD)
        form.locator("button[type=submit]").click()
        expect(detail).to_contain_text(name, timeout=15000)
        expect(detail.locator("form.act-unlock")).to_have_count(0)
        expect(detail).not_to_contain_text(HIDDEN)
        if phone:
            _fits(page)
        assert ERRORS[id(page)] == [], ERRORS[id(page)]
    finally:
        _close(page)


def test_an_administrator_is_never_offered_the_password_in_a_case(browser: Browser, world):
    bob, _bob_c, bob_codes = world["admins"]["bob"]
    page = _page(browser, "v2", DESK)
    try:
        _login(page, bob, bob_codes)
        _activity(page, f"#activity?range=30d&ev={world['event']}")
        detail = _detail(page, False)
        expect(detail).to_contain_text(NOT_SHOWN, timeout=20000)
        expect(detail.locator("form.act-unlock")).to_have_count(0)
        expect(detail).not_to_contain_text(OFFER)
        expect(page.locator("#act-case")).to_have_count(0)
        assert ERRORS[id(page)] == [], ERRORS[id(page)]
    finally:
        _close(page)
