"""Shared helpers for the browser tests that sign out: waiting for the page a sign-out puts in place of the one
that showed the app. Imported by the test modules that need them; holds no tests.

After every end of a session that had shown the app, the page replaces itself (static/js/app.js:
_replacePageAfterSignOut), at once, online or not. The sign-in screen the next person types into is a new page's,
which holds nothing of the old one (its variables, its listeners, what a test put on its window). A test that reads
the page after a sign-out reads it after the replacement (``replaced`` / ``wait_replaced``). With the browser
offline the replacement is the browser's own error page, and the page loaded once it is back online is a new one
on the sign-in screen (``sign_out_as`` with OFFLINE)."""
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


# The two ways a sign-out stands: the browser online, so the page is replaced by a new one on the sign-in screen; or
# offline, so it is replaced all the same, by the browser's own error page, and a new page loads once it is back.
ONLINE = "browser online"
OFFLINE = "browser offline"
SIGN_OUT_STANDS = [ONLINE, OFFLINE]


def _left_old_page(page: Page, seconds=15) -> bool:
    """Whether the page marked by ``mark_old`` has gone (replaced, even by an error page) within ``seconds``."""
    for _ in range(int(seconds * 10)):
        try:
            if not page.evaluate("() => window.__oldPage === true"):
                return True
        except Exception:
            pass                                  # between two documents
        page.wait_for_timeout(100)
    return False


def sign_out_as(page: Page, how, action=None):
    """Sign out (``action``, logout() by default) with the browser ``how`` (ONLINE or OFFLINE), and come back once a
    new page is on the sign-in screen. OFFLINE: the page signed out goes at once all the same, to the browser's
    error page, which holds nothing of the app; back online, the page loaded is a new one. Returns None (kept for
    the callers, which call what it returns when there is something)."""
    action = action or (lambda: page.evaluate("() => logout()"))
    if how == ONLINE:
        with replaced(page):
            action()
        return None
    page.context.set_offline(True)
    mark_old(page)
    action()
    try:
        assert _left_old_page(page), "the page signed out was kept with the browser offline"
        assert page.locator("#dashboard-screen").count() == 0, "the page in the tab still holds the app"
    finally:
        page.context.set_offline(False)
    page.goto("/")
    wait_replaced(page)
    return None
