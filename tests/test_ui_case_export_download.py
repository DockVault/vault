"""A case export too large to read whole, in a real browser (static/js/compliance.js: openExport, fetchExport).

The server spends an export, and tells each owner of a vault it reads from, as soon as it is asked for (GET
.../exports/{id}): it can then never be fetched again. An export larger than the app reads whole (256 MB) can only
be saved through the browser's download service, which a private window, or a page not served over https, does
not have. Held here:

- without that service, an export the server says is larger is never asked for: the auditor is told why, the
  export is not marked fetched, and no owner is told;
- with it, the download is opened first and the same export streams into it (the control);
- when the files listed are the ones chosen and their sizes already say the export is larger, it is refused before
  it is prepared, so no code is asked for either.

The export's real files are small; its size is the server's answer (the prepare's ``bytes``, a listing's ``size``)
made larger on its way to the page. Waits are on state, never on time.
"""
import io
import time
import zipfile

import pytest
from playwright.sync_api import Browser, Page, expect

from _account_change_helpers import psql
from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, outbox, owner_with_vault
from conftest import BASE_URL

pytestmark = pytest.mark.ui

LARGE = 300 * 1024 * 1024
DESK = {"width": 1440, "height": 900}
ERRORS = {}


@pytest.fixture(scope="module")
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        r = olga_c.post(f"/vaults/{vid}/files", files=[("files", ("ledger.txt", b"rows of the ledger", "text/plain"))])
        assert r.status_code in (200, 201), r.text
        case = approved_case(admins, (uma, uma_c, codes), [vid], can_export=True)
        try:
            yield {"uma": uma, "codes": codes, "olga": olga, "vid": vid, "case": case}
        finally:
            forget_cases([case["id"]], [vid])
            forget_grants(uma["id"])
            olga_c.delete_vault(vid)


# What the browser's own blocking of service workers reports as the page loads (its script reads the property it
# blocks), not an error of the page's code.
BLOCKED = "Failed to read the 'serviceWorker' property from 'Navigator'"


def _page(browser: Browser, service_workers: str) -> Page:
    context = browser.new_context(base_url=BASE_URL, viewport=DESK, accept_downloads=True,
                                  service_workers=service_workers)
    page = context.new_page()
    ERRORS[id(page)] = []
    page.on("pageerror", lambda exc: None if str(exc).startswith(BLOCKED) and "/static/js/" not in (exc.stack or "")
            else ERRORS[id(page)].append(str(exc)))
    return page


def _login(page: Page, world):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", world["uma"]["_username"])
    page.fill("#password", world["uma"]["_password"])
    page.click("#login-form button[type=submit]")
    card = page.locator("#login-second-factor")
    expect(card).to_be_visible(timeout=15000)
    card.get_by_role("button", name="Use a recovery code instead").click()
    page.fill("#sf-code-input", world["codes"].pop(0))
    card.locator("button").last.click()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _step_up(page: Page, world):
    modal = page.locator("#stepup-modal.active")
    expect(modal).to_be_visible(timeout=15000)
    modal.get_by_role("button", name="Use a recovery code instead").click()
    modal.locator("#stepup-code-input").fill(world["codes"].pop(0))
    modal.locator("#stepup-password-input").fill(world["uma"]["_password"])
    modal.get_by_role("button", name="Confirm").click()
    expect(page.locator("#stepup-modal.active")).to_have_count(0, timeout=15000)


def _workspace(page: Page, world):
    page.locator("#nav-compliance").click()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)
    page.locator(f'.cmp-case-row[data-case-id="{world["case"]["id"]}"]').click()
    page.locator(".cmp-open-ws").click()
    expect(page.locator(".cmp-ws-export")).to_be_visible(timeout=15000)


def _prepared_as_large(page: Page):
    """The prepare's answer (POST .../exports) says the export is LARGE bytes; the export itself is made."""
    def larger(route):
        if route.request.method != "POST":
            route.continue_()
            return
        answer = route.fetch()
        if answer.status != 201:
            route.fulfill(response=answer)
            return
        body = answer.json()
        body["bytes"] = LARGE
        route.fulfill(response=answer, json=body)
    page.route("**/compliance/cases/*/exports", larger)


def _requests_for_the_archive(page: Page):
    asked = []
    page.on("request", lambda r: r.method == "GET" and "/exports/" in r.url and "/compliance/cases/" in r.url
            and asked.append(r.url))
    return asked


def _exports(case_id):
    """The case's exports as the server keeps them: "status|fetched", oldest first."""
    out = psql("SELECT status || '|' || (fetched_at IS NOT NULL) FROM compliance_exports "
               f"WHERE case_id = '{case_id}' ORDER BY created_at")
    return [row for row in out.splitlines() if row]


def _until(condition, what, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.2)
    raise AssertionError(what)


def _export_notices(case_id):
    return [row for row in outbox(case_id) if row[0] == "export"]


def test_an_export_too_large_to_read_whole_is_never_asked_for_without_a_download_service(browser: Browser, world):
    page = _page(browser, "block")
    try:
        _login(page, world)
        case_id = world["case"]["id"]
        before, notices = _exports(case_id), _export_notices(case_id)
        _prepared_as_large(page)
        asked = _requests_for_the_archive(page)
        _workspace(page, world)
        page.locator(".cmp-ws-export").click()
        sheet = page.locator("#cmp-export-sheet.active")
        sheet.get_by_label("Every file of the case", exact=False).check()
        sheet.locator(".cmp-export-go").click()
        _step_up(page, world)
        expect(page.locator("#toast-container .toast", has_text="too large to save")).to_have_count(1, timeout=15000)
        expect(page.locator("#toast-container .toast", has_text="no owner was told")).to_have_count(1)
        assert asked == [], f"the archive was asked for: {asked}"
        after = _exports(case_id)
        assert len(after) == len(before) + 1 and after[-1] == "ready|false", after
        assert _export_notices(case_id) == notices, "an owner was told of an export that was never fetched"
        assert ERRORS[id(page)] == []
    finally:
        page.context.close()


def test_an_export_too_large_to_read_whole_streams_into_a_download_opened_first(browser: Browser, world):
    page = _page(browser, "allow")
    try:
        _login(page, world)
        case_id = world["case"]["id"]
        notices = _export_notices(case_id)
        _prepared_as_large(page)
        asked = _requests_for_the_archive(page)
        _workspace(page, world)
        page.locator(".cmp-ws-export").click()
        sheet = page.locator("#cmp-export-sheet.active")
        sheet.get_by_label("Every file of the case", exact=False).check()
        sheet.locator(".cmp-export-go").click()
        with page.expect_download(timeout=60000) as got:
            _step_up(page, world)
        with open(got.value.path(), "rb") as fh:
            data = fh.read()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
        assert "SHA256SUMS" in names and any(n.endswith("ledger.txt") for n in names), names
        assert len(asked) == 1, asked
        _until(lambda: _exports(case_id)[-1] == "completed|true", f"not recorded as completed: {_exports(case_id)}")
        assert len(_export_notices(case_id)) == len(notices) + 1
        assert ERRORS[id(page)] == []
    finally:
        page.context.close()


def test_listed_files_too_large_to_read_whole_are_refused_before_the_export_is_prepared(browser: Browser, world):
    page = _page(browser, "block")
    try:
        _login(page, world)
        case_id = world["case"]["id"]
        before = _exports(case_id)

        def sized(route):
            answer = route.fetch()
            body = answer.json()
            for entry in body.get("entries") or []:
                if entry.get("kind") == "file":
                    entry["size"] = LARGE
            route.fulfill(response=answer, json=body)

        page.route(lambda url: "/compliance/cases/" in url and "/tree?vault_id=" in url, sized)
        prepares = []
        page.on("request", lambda r: r.method == "POST" and r.url.endswith("/exports") and prepares.append(r.url))
        _workspace(page, world)
        page.locator(f'.cmp-tree-vault[data-vault-id="{world["vid"]}"] .cmp-tree-btn').click()
        expect(page.locator(".cmp-ws .cmp-file-row").filter(has_text="ledger.txt")).to_have_count(1, timeout=15000)
        page.locator(".cmp-ws-export").click()
        sheet = page.locator("#cmp-export-sheet.active")
        sheet.get_by_label("The files listed now", exact=False).check()
        sheet.locator(".cmp-export-go").click()
        expect(sheet.locator(".alert-error")).to_contain_text("too large to save", timeout=15000)
        expect(page.locator("#stepup-modal.active")).to_have_count(0)
        assert prepares == [], "the export was prepared"
        assert _exports(case_id) == before
        assert ERRORS[id(page)] == []
    finally:
        page.context.close()
