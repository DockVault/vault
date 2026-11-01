"""What the Compliance pages leave after a sign-out, in a real browser (static/js/compliance.js forgetStanding and
forThisSignIn).

After a sign-out nothing of the Compliance pages stays for the next person on the tab. An auditor's case workspace
(with the names of the files it lists) and an owner's Access to my vaults (with a name shown once the vault's
password was given) are taken out of the page at sign-out: the next person who signs in on the same tab and opens
either page sees none of it while their own page loads. An answer the server sends after the sign-out to a request
made before it is drawn for nobody. The owner's vault receipts are forgotten too: no request after the sign-out
carries them, and the name is hidden again until the password is given again. test_ui_owner_unlock.py holds the
owner's unlock itself.

Waits are on state, never on time (the timing rules of the browser tests); a request is held by routing it and let
go by continuing it.
"""
import pytest
from playwright.sync_api import Page, expect

from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, owner_with_vault
from conftest import unique

pytestmark = pytest.mark.ui

PASSWORD = "Vault-Pass-2026!"
HIDDEN = "(name hidden until the vault is unlocked)"


@pytest.fixture(scope="module")
def world(admin):
    """uma, an auditor with a case on two of olga's vaults: one without a password holding a file uma's workspace
    lists by name, and one with a password holding a file uma opened, so olga's page lists it with its name hidden.
    mia is another person who signs in on the same tab."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, plain = owner_with_vault(admin)
        listed = f"{unique('ledger')}.txt"
        up = olga_c.post(f"/vaults/{plain}/files", files=[("files", (listed, b"rows", "text/plain"))])
        assert up.status_code in (200, 201), up.text
        pv = olga_c.create_vault(name=unique("locked"), password=PASSWORD)["id"]
        opened = f"{unique('salaries')}.txt"
        up = olga_c.post(f"/vaults/{pv}/files", files=[("files", (opened, b"the plan", "text/plain"))],
                         headers={"X-Vault-Password": PASSWORD})
        assert up.status_code in (200, 201), up.text
        fid = up.json()["files"][0]["id"]
        mia = admin.create_user()
        case = approved_case(admins, (uma, uma_c, codes), [plain, pv])
        try:
            r = uma_c.post(f"/compliance/cases/{case['id']}/vaults/{pv}/unlock", json={"password": PASSWORD})
            assert r.status_code == 200, r.text
            r = uma_c.get(f"/compliance/cases/{case['id']}/files/{fid}/content",
                          headers={"X-Case-Unlock": f"{pv}={r.json()['receipt']}"})
            assert r.status_code == 200, r.text
            yield {"admins": admins, "uma": uma, "codes": codes, "olga": olga, "mia": mia, "plain": plain, "pv": pv,
                   "case": case, "listed": listed, "opened": opened}
        finally:
            forget_cases([case["id"]], [plain, pv])
            forget_grants(uma["id"])
            olga_c.delete_vault(pv, vault_password=PASSWORD)
            olga_c.delete_vault(plain)


def _sign_in(page: Page, account, codes=None):
    """Sign in on the tab as it is (no reload): the login screen of a first visit, or the one a sign-out left."""
    if page.url in ("", "about:blank"):
        page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    # A two-factor sign-in hides the form for its second step, and a sign-out shows the login screen without it:
    # it is shown again here as the screen's own "Back to sign in" shows it.
    page.evaluate("() => { const f = document.getElementById('login-form');"
                  " if (f && f.style.display === 'none') _sfRestoreLoginForm(); }")
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


def _sign_out(page: Page):
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


class _Held:
    """Requests matching ``glob`` held by the route until let go."""

    def __init__(self, page: Page, glob: str):
        self.page, self.glob, self.routes = page, glob, []
        page.route(glob, lambda route: self.routes.append(route))

    def wait(self, count=1):
        for _ in range(300):
            if len(self.routes) >= count:
                return
            self.page.wait_for_timeout(50)
        raise AssertionError(f"no request to {self.glob} was held")

    def release(self):
        for route in self.routes:
            route.continue_()
        self.routes = []
        self.page.unroute(self.glob)


# Marks, in the page, when the body of an answer whose address holds a given part has been read (by .json() or
# .text(), as the page's own code reads it): what the page does with it runs right after, before the next task.
_WATCH_READS = """(part) => {
    window.__read = window.__read || {};
    window.__read[part] = false;
    if (window.__watchingReads) return;
    window.__watchingReads = true;
    for (const how of ['json', 'text']) {
        const original = Response.prototype[how];
        Response.prototype[how] = function () {
            const url = this.url;
            const read = original.call(this);
            read.then(() => {
                Object.keys(window.__read).forEach((p) => { if (url.includes(p)) window.__read[p] = true; });
            }, () => {});
            return read;
        };
    }
}"""


def _release_and_wait_for_the_read(page: Page, held: "_Held", part: str):
    """Let the held answers go, and come back once the page has read the one to ``part`` and run what follows."""
    page.evaluate(_WATCH_READS, part)
    held.release()
    page.wait_for_function("(p) => window.__read && window.__read[p] === true", arg=part, timeout=15000)
    page.evaluate("() => new Promise((done) => setTimeout(() => setTimeout(done, 0), 0))")


def _unlock_on_my_access(page: Page, world):
    """olga opens Access to my vaults, sees the file opened with its name hidden, and gives the vault's password."""
    page.evaluate("() => window.openMyAccess()")
    dialog = page.locator("#my-access-modal")
    expect(dialog.locator(".my-access-file").filter(has_text=HIDDEN)).to_have_count(1, timeout=15000)
    expect(dialog).not_to_contain_text(world["opened"])
    dialog.locator(".my-access-unlock").click()
    prompt = page.locator("#confirm-modal.active")
    expect(prompt).to_be_visible(timeout=10000)
    prompt.locator("#confirm-modal-input").fill(PASSWORD)
    # Clicked as a person clicks: on the button where it is drawn, so a dialog over it would take the click.
    prompt.locator("#confirm-modal-confirm-btn").click(timeout=10000)
    expect(prompt).to_have_count(0)
    expect(dialog.locator(".my-access-file").filter(has_text=world["opened"])).to_have_count(1, timeout=15000)
    expect(dialog.locator(".my-access-unlock")).to_have_count(0)
    return dialog


def _workspace(page: Page, world):
    """The auditor's workspace of the case, on the vault without a password: its file listed by name."""
    page.locator("#nav-compliance").click()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)
    page.locator(f'.cmp-case-row[data-case-id="{world["case"]["id"]}"]').click()
    page.locator(".cmp-open-ws").click()
    page.locator(f'.cmp-tree-vault[data-vault-id="{world["plain"]}"] .cmp-tree-btn').click()
    expect(page.locator(".cmp-ws .cmp-file-row").filter(has_text=world["listed"])).to_have_count(1, timeout=15000)


def test_the_next_person_on_the_tab_sees_nothing_of_an_auditors_case(page: Page, world):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    bob, _bob_c, bob_codes = world["admins"]["bob"]
    _sign_in(page, world["uma"], world["codes"])
    _workspace(page, world)
    # A new case begun in its sheet, its justification typed and not sent.
    typed = f"Draft justification {unique('why')} of a case not asked for yet."
    page.evaluate("() => window.openNewCaseFor(null)")
    sheet = page.locator("#cmp-new-case.active")
    expect(sheet).to_be_visible(timeout=15000)
    sheet.get_by_placeholder("Why this access is needed", exact=False).fill(typed)
    _sign_out(page)
    root = page.locator("#cmp-root")
    expect(root).to_be_empty()
    expect(page.locator(".cmp-sheet")).to_have_count(0)
    assert not page.evaluate("(t) => Array.from(document.querySelectorAll('textarea, input'))"
                             ".some((n) => (n.value || '').includes(t))", typed)

    # bob, an administrator, signs in on the same tab and opens Compliance; his standing is held on its way.
    held = _Held(page, "**/compliance/me")
    _sign_in(page, bob, bob_codes)
    page.evaluate("() => navigateToSection('compliance')")
    held.wait()
    expect(page.locator("#compliance-section.active")).to_have_count(1)
    assert page.locator("#cmp-root .cmp-ws, #cmp-root .cmp-file-row").count() == 0
    assert world["listed"] not in root.inner_text()
    held.release()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)
    expect(page.locator("#cmp-root .cmp-ws")).to_have_count(0)
    assert errors == []


def test_an_answer_that_comes_after_the_sign_out_is_drawn_for_nobody(page: Page, world):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _sign_in(page, world["uma"], world["codes"])
    _workspace(page, world)
    # The workspace is opened again; its tree is held on its way, the auditor signs out, then it arrives.
    held = _Held(page, "**/compliance/cases/*/tree*")
    page.evaluate("(id) => { window.openCaseWorkspace(id); }", world["case"]["id"])
    held.wait()
    _sign_out(page)
    _release_and_wait_for_the_read(page, held, "/tree")
    assert page.locator("#cmp-root .cmp-ws, #cmp-root .cmp-file-row").count() == 0
    assert world["listed"] not in page.locator("#cmp-root").inner_text()
    assert errors == []


def test_the_owners_page_and_receipts_are_gone_for_the_next_person_on_the_tab(page: Page, world):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    sent = []
    page.on("request", lambda r: "/me/compliance-access" in r.url and sent.append(r.headers.get("x-owner-unlock")))
    _sign_in(page, world["olga"])
    dialog = _unlock_on_my_access(page, world)
    assert sent and sent[-1] and world["pv"] in sent[-1], "the receipt was sent while olga was signed in"
    # Her vault under the review shows its banner.
    page.evaluate("(id) => openVault(id)", world["plain"])
    expect(page.locator("#vault-review-banner")).to_be_visible(timeout=15000)

    # Her page is read again; that answer is held, she signs out, and it arrives after.
    held = _Held(page, "**/me/compliance-access")
    page.evaluate("() => { window.openMyAccess(); }")
    held.wait()
    _sign_out(page)
    _release_and_wait_for_the_read(page, held, "/me/compliance-access")
    expect(page.locator("#my-access-body")).to_be_empty()
    expect(page.locator("#my-access-modal.active")).to_have_count(0)
    expect(page.locator("#vault-review-banner")).to_have_count(0)
    before = len(sent)

    # mia signs in on the same tab and opens her own page; her answers are held on their way.
    held = _Held(page, "**/me/compliance-access")
    _sign_in(page, world["mia"])
    page.evaluate("() => { window.openMyAccess(); }")
    held.wait()
    expect(dialog).to_be_visible()
    assert dialog.locator(".my-access-case, .my-access-file").count() == 0
    body = page.locator("#my-access-body").inner_text()
    for hers in (world["opened"], world["case"]["number"], world["uma"]["_username"]):
        assert hers not in body, hers
    held.release()
    expect(dialog.locator(".my-access-empty")).to_be_visible(timeout=15000)
    _sign_out(page)

    # olga again, on the same tab: the receipt is gone with her sign-out, so the name is hidden until she gives the
    # password again.
    _sign_in(page, world["olga"])
    page.evaluate("() => window.openMyAccess()")
    expect(dialog.locator(".my-access-file").filter(has_text=HIDDEN)).to_have_count(1, timeout=15000)
    expect(dialog.locator(".my-access-unlock")).to_have_count(1)
    assert sent[before:] and not any(sent[before:]), f"no request after the sign-out carries a receipt: {sent}"
    assert errors == []
