"""Shared helpers for the browser tests of what a sign-out hands to the next person on the tab: signing in and
out on the tab as it is, waiting for the page a sign-out puts in place of the one that showed the app, and making
a folder through the page. Imported by the test modules that need them; holds no tests.

After every end of a session that had shown the app, the page replaces itself (static/js/app.js:
_replacePageAfterSignOut) once the sign-out is over: the sign-in screen the next person types into is a new
page's, which holds nothing of the old one (its variables, its listeners, what a test put on its window). A test
that reads the page after a sign-out reads it after the replacement (``replaced`` / ``wait_replaced``), and what
must survive it is put in with ``page.add_init_script`` or kept in the tab's sessionStorage."""
import re
from contextlib import contextmanager

from playwright.sync_api import Page, expect

# Set on the window of the page that is signed out; a page loaded in its place does not have it.
MARK_OLD = "() => { window.__oldPage = true; }"
# The page in place is a new one, and it has run its start (the DOMContentLoaded handler of app.js) to the end.
NEW_AND_LOADED = "() => !window.__oldPage && document.readyState === 'complete' && typeof logout === 'function'"


def mark_old(page: Page):
    """Mark the page as it is now, so that ``wait_replaced`` can tell the page put in its place."""
    page.evaluate(MARK_OLD)


def wait_new_page(page: Page, timeout=15000):
    """Wait until a page marked by ``mark_old`` has been replaced by a new one that has loaded (on whichever screen
    its start chose: the sign-in screen, or the app when the browser holds a session stored since)."""
    page.wait_for_function(NEW_AND_LOADED, timeout=timeout)


def wait_replaced(page: Page, timeout=15000):
    """Wait until a page marked by ``mark_old`` has been replaced by a new one, loaded, on the sign-in screen."""
    wait_new_page(page, timeout)
    expect(page.locator("#login-screen")).to_be_visible(timeout=timeout)
    expect(page.locator("#dashboard-screen")).to_be_hidden()


def still_old(page: Page) -> bool:
    """Whether the page marked by ``mark_old`` is still the one in the tab (it was not replaced)."""
    return page.evaluate("() => window.__oldPage === true")


def expect_reason(page: Page, reason):
    """The sign-in screen of the new page says why the session ended (``reason``), or says nothing (``None``); either
    way the reason kept for it in the tab's sessionStorage is gone, so it is shown once."""
    note = page.locator("#login-error")
    if reason:
        expect(note).to_be_visible()
        expect(note).to_have_text(reason)
        expect(note).to_have_class(re.compile(r"\balert-warning\b"))
        expect(note).to_have_attribute("role", "alert")
    else:
        expect(note).to_be_hidden()
    assert page.evaluate("() => sessionStorage.getItem('dv_signed_out_reason')") is None


def expect_reason_once(page: Page, reason):
    """``expect_reason``, and a reload of the page then shows it no more."""
    expect_reason(page, reason)
    page.reload()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.wait_for_function("() => document.readyState === 'complete' && typeof logout === 'function'")
    expect(page.locator("#login-error")).to_be_hidden()


@contextmanager
def replaced(page: Page, timeout=15000):
    """Run the block, which ends the session of a page that shows the app, and come back once the page has been
    replaced by a new one on the sign-in screen."""
    mark_old(page)
    yield
    wait_replaced(page, timeout)


def sign_in_on_the_tab(page: Page, account):
    """Sign in on the tab as it is: the login screen of a first visit, or that of the page a sign-out put in place."""
    if page.url in ("", "about:blank"):
        page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", account["_username"])
    page.fill("#password", account["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def sign_out(page: Page):
    """Sign out (logout(), what the Sign out button calls) and come back once the page has been replaced."""
    with replaced(page):
        page.evaluate("() => logout()")


# The two ways a sign-out stands when something of the session that ended comes after it: its call answered, so
# the page has been replaced; or its call still on its way (a slow or unreachable server), so the page signed out
# and emptied stays until it is answered.
ANSWERED = "sign-out answered"
ON_ITS_WAY = "sign-out on its way"
SIGN_OUT_STANDS = [ANSWERED, ON_ITS_WAY]


class HeldSignOut:
    """The page's sign-out (POST /auth/sign-out) held on its way until ``release``: the page stays signed out and is
    not replaced meanwhile."""

    def __init__(self, page: Page):
        self.page, self.routes = page, []
        page.route("**/auth/sign-out", lambda route: self.routes.append(route))

    def wait(self):
        for _ in range(300):
            if self.routes:
                return
            self.page.wait_for_timeout(50)
        raise AssertionError("the sign-out was not sent")

    def release(self):
        """Let the sign-out go on to the server (each call held, then the route taken away)."""
        for route in self.routes:
            route.continue_()
        self.routes = []
        self.page.unroute("**/auth/sign-out")


def sign_out_as(page: Page, how, action=None):
    """Sign out (``action``, logout() by default) with the sign-out ``how`` (ANSWERED or ON_ITS_WAY). ANSWERED: back
    once the page has been replaced; returns None. ON_ITS_WAY: back once the call is held, the page signed out and
    still the one that showed the app; returns the HeldSignOut, whose ``release`` lets the call go (the page is
    replaced then, unless someone signed in on it meanwhile, whose sign-in replaces it at once)."""
    action = action or (lambda: page.evaluate("() => logout()"))
    if how == ANSWERED:
        with replaced(page):
            action()
        return None
    held = HeldSignOut(page)
    mark_old(page)
    action()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    held.wait()
    assert still_old(page), "the page was replaced before its sign-out was answered"
    return held


def new_folder_through_the_page(page: Page, client, vault_id, name):
    """Open the vault from the vault list and make a folder with New folder, as a person does; returns once the
    page's request for it is answered. The folder is read back from the server with ``client``."""
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=15000)
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    page.click("#create-folder-btn")
    prompt = page.locator("#confirm-modal.active")
    expect(prompt).to_be_visible(timeout=10000)
    prompt.locator("#confirm-modal-input").fill(name)
    with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith(f"/vaults/{vault_id}/folders"),
                              timeout=15000) as made:
        prompt.locator("#confirm-modal-confirm-btn").click()
    assert made.value.status in (200, 201), made.value.status
    items = client.get(f"/vaults/{vault_id}/files").json()["items"]
    assert [it["name"] for it in items if it["type"] == "folder"] == [name], items
