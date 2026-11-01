"""What a sign-out hands to the next person on the tab, in a real browser (static/js/app.js logout).

A shared tab is handed over at a sign-out: the next person who signs in on it must find nothing of the person
who left that still acts, and nothing that takes what they type.

- A question left open in the shared confirm dialog (showPrompt, showConfirm) is answered as cancelled at the
  sign-out. Closing the dialog alone left its handlers on the dialog's buttons and field, so the next person's
  first answer there went to the question of the person who left as well, and their own question got nothing.
  A question opened while another is still open answers that one as cancelled the same way.
- An answer that comes after the sign-out to a request of the session that ended, refused because that session
  is over, signs nobody out: neither the form the next person is filling in is emptied, nor are they signed out
  once they are in. Only a refusal of the session the tab holds now ends it.

tests/test_ui_compliance_sign_out.py holds the same hand-over for a vault's password asked on Access to my
vaults. Waits are on state, never on time (the timing rules of the browser tests).
"""
import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import signed_in
from _ui_hand_over import new_folder_through_the_page, sign_in_on_the_tab, sign_out
from conftest import unique

pytestmark = pytest.mark.ui


@pytest.fixture
def two(admin):
    """ana, who leaves a question open, and ben, who signs in after her on the same tab and owns a vault."""
    ana = admin.create_user()
    ben = admin.create_user()
    ben_c = signed_in(ben)
    vault = ben_c.create_vault(name=unique("bens"))["id"]
    yield ana, ben, ben_c, vault
    ben_c.delete_vault(vault)
    admin.delete_user(ana["id"])
    admin.delete_user(ben["id"])


# The question ana leaves open, and what a cancel answers it with.
_ASK = {
    "prompt": ("() => { window.__asked = []; showPrompt('A question of the person who leaves.', 'Asked before',"
               " { password: true }).then((v) => window.__asked.push(v)); }", None),
    "confirm": ("() => { window.__asked = []; showConfirm('A question of the person who leaves.', 'Asked before')"
                ".then((v) => window.__asked.push(v)); }", False),
}


@pytest.mark.parametrize("kind", ["prompt", "confirm"])
def test_a_question_left_open_at_a_sign_out_is_cancelled_and_takes_nothing_of_the_next_persons(
        page: Page, two, kind):
    ana, ben, ben_c, vault = two
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    sent = []
    page.on("request", lambda r: r.method != "GET" and sent.append((r.method, r.url, r.post_data or "")))
    sign_in_on_the_tab(page, ana)
    ask, cancelled = _ASK[kind]
    page.evaluate(ask)
    prompt = page.locator("#confirm-modal.active")
    expect(prompt).to_be_visible(timeout=10000)
    if kind == "prompt":
        prompt.locator("#confirm-modal-input").fill("typed by the person who leaves")
    sign_out(page)
    # Answered as cancelled at the sign-out, the dialog closed and its field empty.
    page.wait_for_function("() => window.__asked.length === 1", timeout=5000)
    assert page.evaluate("() => window.__asked") == [cancelled]
    expect(page.locator("#confirm-modal.active")).to_have_count(0)
    assert page.evaluate("() => document.getElementById('confirm-modal-input').value") == ""

    # ben signs in on the same tab and makes a folder: New folder asks its name in the same dialog.
    sign_in_on_the_tab(page, ben)
    name = unique("bens-folder")
    new_folder_through_the_page(page, ben_c, vault, name)
    # ana's question took nothing of his: it was answered once, at the sign-out, and only his own request carried
    # the name he typed.
    assert page.evaluate("() => window.__asked") == [cancelled]
    carrying = [(m, u) for m, u, body in sent if name in body]
    assert len(carrying) == 1 and carrying[0][0] == "POST" and carrying[0][1].endswith(f"/vaults/{vault}/folders"), \
        carrying
    assert errors == []


def test_a_question_opened_while_another_is_open_answers_that_one_as_cancelled(page: Page, two):
    ana, _ben, _ben_c, _vault = two
    sign_in_on_the_tab(page, ana)
    page.evaluate("() => { window.__asked = [];"
                  " showPrompt('The first question.', 'First').then((v) => window.__asked.push(['first', v]));"
                  " showConfirm('The second question.', 'Second').then((v) => window.__asked.push(['second', v])); }")
    page.wait_for_function("() => window.__asked.length === 1", timeout=5000)
    assert page.evaluate("() => window.__asked") == [["first", None]]
    prompt = page.locator("#confirm-modal.active")
    expect(prompt).to_contain_text("The second question.")
    prompt.locator("#confirm-modal-confirm-btn").click()
    page.wait_for_function("() => window.__asked.length === 2", timeout=5000)
    # One click answered the question on the screen, once; the first stays answered as cancelled.
    assert page.evaluate("() => window.__asked") == [["first", None], ["second", True]]
    expect(page.locator("#confirm-modal.active")).to_have_count(0)


class _Held:
    """Requests to ``glob`` held by the route until each is answered, in turn, with a refusal of its session."""

    def __init__(self, page: Page, glob: str):
        self.page, self.routes = page, []
        page.route(glob, lambda route: self.routes.append(route))

    def wait(self, count):
        self.page.wait_for_function("(n) => (window.__probes || []).length >= n", arg=count, timeout=10000)
        for _ in range(200):
            if len(self.routes) >= count:
                return
            self.page.wait_for_timeout(50)
        raise AssertionError("the requests were not held")

    def refuse_next(self):
        self.routes.pop(0).fulfill(status=401, content_type="application/json",
                                   body='{"detail": "Could not validate credentials"}')


# A request through the app's own apiRequest; what it ends with is kept in window.__probes, in order.
_ASK_SERVER = ("(i) => { window.__probes = window.__probes || [];"
               " window.__probes[i] = 'pending';"
               " apiRequest('/hand-over-probe').then(() => { window.__probes[i] = 'answered'; },"
               " (e) => { window.__probes[i] = e.message; }); }")


def _settled(page: Page, i):
    page.wait_for_function("(i) => window.__probes[i] !== 'pending'", arg=i, timeout=10000)
    return page.evaluate("(i) => window.__probes[i]", i)


def test_a_late_refusal_of_the_session_that_ended_signs_nobody_out(page: Page, two):
    ana, ben, _ben_c, _vault = two
    held = _Held(page, "**/hand-over-probe")
    sign_in_on_the_tab(page, ana)
    sent_for = page.evaluate("() => authToken")
    page.evaluate(_ASK_SERVER, 0)
    page.evaluate(_ASK_SERVER, 1)
    held.wait(2)
    assert all(r.request.headers.get("authorization") == f"Bearer {sent_for}" for r in held.routes)
    sign_out(page)

    # ben fills in the form. A refusal of ana's session arrives, and so does one of a request sent with no
    # session at all (the server's own answer): the form keeps what he typed.
    page.fill("#username", ben["_username"])
    page.fill("#password", ben["_password"])
    held.refuse_next()
    assert _settled(page, 0) == "Session expired. Please log in again."
    unrouted = page.evaluate("() => apiRequest('/vaults').then(() => 'answered', (e) => e.message)")
    assert unrouted != "answered", unrouted
    assert page.input_value("#username") == ben["_username"]
    assert page.input_value("#password") == ben["_password"]
    expect(page.locator("#toast-container .toast", has_text="Session expired")).to_have_count(0)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)

    # ben is signed in when the other refusal of ana's session arrives: he stays signed in.
    held.refuse_next()
    assert _settled(page, 1) == "Session expired. Please log in again."
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert page.evaluate("(old) => !!authToken && authToken !== old", sent_for)

    # A refusal of the session the tab holds now still ends it.
    page.unroute("**/hand-over-probe")
    page.route("**/hand-over-probe", lambda route: route.fulfill(
        status=401, content_type="application/json", body='{"detail": "Could not validate credentials"}'))
    page.evaluate(_ASK_SERVER, 2)
    assert _settled(page, 2) == "Session expired. Please log in again."
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    assert page.evaluate("() => authToken") is None
