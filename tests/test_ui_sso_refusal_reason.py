"""A renewal refused because the identity provider no longer vouches for the sign-in, in the browser.

The server refuses "Stay signed in" with a sentence that names the provider (app/services/sso_sign_in.py,
renewal_refusal). The tab signs out through the page's one sign-out path, and the sign-in screen of the page that
replaces it says that sentence, once. The server's side of the refusal has its own tests; here the answer is put in
the server's place, so the page's part is proved for a provider's sentence as it is for the account's own.
"""
import pytest
from playwright.sync_api import Page

from _ui_hand_over import expect_reason_once, mark_old, wait_replaced
from test_ui_session_stay_refused import _login, _warn, _watch_toasts, person  # noqa: F401 -- person is the fixture
from test_ui_sign_out_ends_session import _is_sign_out

pytestmark = pytest.mark.ui

SENTENCE = "Sign in through Contoso again to stay signed in."


def test_a_renewal_the_provider_no_longer_vouches_for_signs_out_with_the_servers_sentence(page: Page, person):
    _login(page, person)
    page.wait_for_load_state("networkidle", timeout=15000)
    _warn(page)
    page.route("**/auth/session/extend", lambda route: route.fulfill(
        status=403, content_type="application/json", body='{"detail": "' + SENTENCE + '"}'))
    toasts = _watch_toasts(page)
    mark_old(page)
    # The refusal ends the session on the server too: the tab's sign-out request goes out before the page does.
    with page.expect_request(_is_sign_out):
        page.click("#session-stay")
    # The page is replaced, and the new one's sign-in screen says why, in the server's words, provider and all.
    wait_replaced(page)
    page.unroute("**/auth/session/extend")
    expect_reason_once(page, SENTENCE)
    assert not [t for t in toasts if "Could not extend" in t], toasts
