"""Shared helpers for the browser tests that sign out: waiting for the page a sign-out puts in place of the one
that showed the app. Imported by the test modules that need them; holds no tests.

After every end of a session that had shown the app, the page replaces itself (static/js/app.js:
_replacePageAfterSignOut): at once, or, with the browser offline, once it is back online. The sign-in screen the
next person types into is a new page's, which holds nothing of the old one (its variables, its listeners, what a
test put on its window). A test that reads the page after a sign-out reads it after the replacement (``replaced``
/ ``wait_replaced``), or reads the page that stays while the browser is offline (``sign_out_as`` with OFFLINE)."""
from contextlib import contextmanager

from playwright.sync_api import Page, expect

# Set on the window of the page that is signed out; a page loaded in its place does not have it.
MARK_OLD = "() => { window.__oldPage = true; }"
# The page in place is a new one, and it has run its start (the DOMContentLoaded handler of app.js) to the end.
NEW_AND_LOADED = "() => !window.__oldPage && document.readyState === 'complete' && typeof logout === 'function'"


def mark_old(page: Page):
    """Mark the page as it is now, so that ``wait_replaced`` can tell the page put in its place."""
    page.evaluate(MARK_OLD)


def still_old(page: Page) -> bool:
    """Whether the page marked by ``mark_old`` is still the one in the tab (it was not replaced)."""
    return page.evaluate("() => window.__oldPage === true")


def wait_replaced(page: Page, timeout=15000):
    """Wait until a page marked by ``mark_old`` has been replaced by a new one, loaded, on the sign-in screen."""
    page.wait_for_function(NEW_AND_LOADED, timeout=timeout)
    expect(page.locator("#login-screen")).to_be_visible(timeout=timeout)
    expect(page.locator("#dashboard-screen")).to_be_hidden()


@contextmanager
def replaced(page: Page, timeout=15000):
    """Run the block, which ends the session of a page that shows the app, and come back once the page has been
    replaced by a new one on the sign-in screen."""
    mark_old(page)
    yield
    wait_replaced(page, timeout)


def sign_out(page: Page):
    """Sign out (logout(), what the Sign out button calls) and come back once the page has been replaced."""
    with replaced(page):
        page.evaluate("() => logout()")


# The two ways a sign-out stands: the browser online, so the page is replaced at once; or offline, so the page
# signed out and emptied stays until the browser is back online.
ONLINE = "browser online"
OFFLINE = "browser offline"
SIGN_OUT_STANDS = [ONLINE, OFFLINE]


def sign_out_as(page: Page, how, action=None):
    """Sign out (``action``, logout() by default) with the browser ``how`` (ONLINE or OFFLINE). ONLINE: back once
    the page has been replaced; returns None. OFFLINE: back with the page signed out and still the one that showed
    the app; returns a function that brings the browser back online and waits for the page to be replaced."""
    action = action or (lambda: page.evaluate("() => logout()"))
    if how == ONLINE:
        with replaced(page):
            action()
        return None
    page.context.set_offline(True)
    mark_old(page)
    action()
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(500)                    # a moment in which a replacement would begin
    assert still_old(page), "the page was replaced with the browser offline"

    def back_online():
        page.context.set_offline(False)
        wait_replaced(page)

    return back_online
