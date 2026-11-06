"""The vault list's error, in a real browser (static/js/app.js: loadVaults): when the list cannot be read, the page
says so with the words of the answer as text, never as markup. The answer here is the server's own shape (a JSON
detail), routed so that it carries markup."""
import json

import pytest
from playwright.sync_api import Page, expect

from _ui_hand_over import sign_in_on_the_tab

pytestmark = pytest.mark.ui

DETAIL = 'The list <b id="bold-from-the-answer">could not</b> be read <i id="italic-from-the-answer">now</i>'


@pytest.fixture
def ana(admin):
    user = admin.create_user()
    yield user
    admin.delete_user(user["id"])


def test_a_vault_list_that_cannot_be_read_shows_the_answer_as_text(page: Page, ana):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    sign_in_on_the_tab(page, ana)
    page.route("**/vaults", lambda route: route.fulfill(
        status=500, content_type="application/json", body=json.dumps({"detail": DETAIL}))
        if route.request.method == "GET" else route.continue_())
    page.evaluate("() => loadVaults()")
    alert = page.locator("#vaults-list .alert.alert-error")
    expect(alert).to_have_text(f"Failed to load vaults: {DETAIL}", timeout=15000)
    assert page.locator("#bold-from-the-answer, #italic-from-the-answer").count() == 0
    assert alert.evaluate("(n) => n.children.length") == 0
    assert errors == []
