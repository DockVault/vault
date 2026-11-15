"""What a sign-out hands to the next person on the tab, in a real browser (static/js/app.js logout).

A shared tab is handed over at a sign-out: the next person who signs in on it must find nothing of the person
who left that still acts, and nothing that takes what they type. Once the sign-out is over, the page that showed
the app is replaced by a new one (app.js _replacePageAfterSignOut), and the next person types into that one;
until then, the page signed out and emptied stays, and a sign-in on it replaces it there and then.

- A question left open in the shared confirm dialog (showPrompt, showConfirm) is answered as cancelled at the
  sign-out, and the next person's own question in that dialog, on the new page, gets their answer alone.
  A question opened while another is still open answers that one as cancelled the same way.
- An answer that comes after the sign-out to a request of the session that ended signs nobody out. With the
  sign-out answered, the request belonged to the page that was replaced: its answer reaches nothing, and the next
  person's form and sign-in are untouched. With the sign-out not answered yet, the page stays while the next person
  types: a refusal of the session that ended, or one of a request sent with no session at all, empties nothing of
  the form; their sign-in then replaces the page, and a refusal arriving after that signs them out no more. Only
  a refusal of the session the tab holds now ends it. A sign-out the page still owes then (refused for now, to be
  sent again later) is sent before their sign-in replaces the page, so the session that ended does not stay live.
- After a two-factor sign-in the sign-out leaves the form to sign in with: the second step hid it, and nothing but
  the screen's own "Back to sign in" showed it again.

tests/test_ui_compliance_sign_out.py holds the same hand-over for a vault's password asked on Access to my
vaults. Waits are on state, never on time (the timing rules of the browser tests), but for the moments in which
something must not happen.
"""
import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import signed_in
from _sf_helpers import enroll_totp
from _sign_out_helpers import session_row
from _ui_hand_over import (expect_reason, mark_old, new_folder_through_the_page, replaced, sign_in_on_the_tab,
                           sign_out, still_old, wait_new_page)
from conftest import unique

pytestmark = pytest.mark.ui

SESSION_ENDED = "Your session has ended. Sign in again."


def _is_sign_out(request):
    return request.method == "POST" and request.url.endswith("/auth/sign-out")


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


# The question ana leaves open, and what a cancel answers it with. Each answer is noted in the tab's sessionStorage
# too, which outlives the page the sign-out replaces.
_NOTE = ("(v) => { window.__asked.push(v);"
         " sessionStorage.setItem('probe_asked', JSON.stringify(window.__asked)); }")
_ASK = {
    "prompt": ("() => { window.__asked = []; showPrompt('A question of the person who leaves.', 'Asked before',"
               " { password: true }).then(" + _NOTE + "); }", None),
    "confirm": ("() => { window.__asked = []; showConfirm('A question of the person who leaves.', 'Asked before')"
                ".then(" + _NOTE + "); }", False),
}


def _asked(page: Page):
    return page.evaluate("() => JSON.parse(sessionStorage.getItem('probe_asked') || 'null')")


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
    # Answered as cancelled at the sign-out (noted before the page was replaced); the new page has the dialog
    # closed and its field empty.
    assert _asked(page) == [cancelled]
    expect(page.locator("#confirm-modal.active")).to_have_count(0)
    assert page.evaluate("() => document.getElementById('confirm-modal-input').value") == ""

    # ben signs in on the same tab and makes a folder: New folder asks its name in the same dialog.
    sign_in_on_the_tab(page, ben)
    name = unique("bens-folder")
    new_folder_through_the_page(page, ben_c, vault, name)
    # ana's question took nothing of his: it was answered once, at the sign-out, and only his own request carried
    # the name he typed.
    assert _asked(page) == [cancelled]
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


def _round_trip(page: Page):
    """A request of the page's own, sent and answered, then a few turns of its event loop: whatever the page does
    with an answer that came before is done."""
    page.evaluate("() => fetch('/health').then((r) => r.text())")
    page.evaluate("() => new Promise((done) => setTimeout(() => setTimeout(done, 0), 0))")


def _types(page: Page, account):
    page.fill("#username", account["_username"])
    page.fill("#password", account["_password"])


def _form_kept(page: Page, account):
    assert page.input_value("#username") == account["_username"]
    assert page.input_value("#password") == account["_password"]
    expect(page.locator("#login-error")).to_be_hidden()


def _a_refusal_of_the_session_held_now_ends_it(page: Page):
    """The control: a refusal of the session the tab holds now still ends it, and replaces the page."""
    page.unroute("**/hand-over-probe")
    page.route("**/hand-over-probe", lambda route: route.fulfill(
        status=401, content_type="application/json", body='{"detail": "Could not validate credentials"}'))
    with replaced(page):
        page.evaluate(_ASK_SERVER, 2)
    assert page.evaluate("() => authToken") is None
    expect_reason(page, SESSION_ENDED)


def test_a_late_refusal_of_the_session_that_ended_signs_nobody_out_once_the_page_is_replaced(page: Page, two):
    """The sign-out is answered, so the page is replaced: the requests of the session that ended belonged to the
    page that is gone, and their refusals, let go while the next person types and after they are in, reach
    nothing."""
    ana, ben, _ben_c, _vault = two
    sign_outs = []
    page.context.on("request", lambda r: _is_sign_out(r) and sign_outs.append(r))
    held = _Held(page, "**/hand-over-probe")
    sign_in_on_the_tab(page, ana)
    sent_for = page.evaluate("() => authToken")
    page.evaluate(_ASK_SERVER, 0)
    page.evaluate(_ASK_SERVER, 1)
    held.wait(2)
    assert all(r.request.headers.get("authorization") == f"Bearer {sent_for}" for r in held.routes)
    sign_out(page)
    assert page.evaluate("() => window.__probes === undefined"), "the new page holds a request of the old one"

    # ben fills in the form, and a refusal of ana's session is let go: it reaches nothing of his form.
    _types(page, ben)
    held.refuse_next()
    _round_trip(page)
    _form_kept(page, ben)
    assert page.evaluate("() => window.__probes === undefined")
    mark_old(page)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert still_old(page), "the new page was replaced again at the sign-in"
    signed_in_as = page.evaluate("() => authToken")
    assert signed_in_as and signed_in_as != sent_for

    # ben is signed in when the other refusal of ana's session is let go: he stays signed in, on the same page.
    held.refuse_next()
    _round_trip(page)
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert still_old(page)
    assert page.evaluate("() => authToken") == signed_in_as
    assert len(sign_outs) == 1, f"{len(sign_outs)} sign-outs sent"
    _a_refusal_of_the_session_held_now_ends_it(page)


def test_a_late_refusal_of_the_session_that_ended_signs_nobody_out_while_the_sign_out_is_on_its_way(
        page: Page, two):
    """The sign-out is not answered yet, so the page signed out stays while the next person types: a refusal of
    the session that ended, and one of a request sent with no session at all, leave their form as it is. Their
    sign-in replaces the page there and then, and the new page opens their session; the other refusal of the
    session that ended, let go after that, reaches nothing."""
    ana, ben, _ben_c, _vault = two
    sign_outs = []
    page.route("**/auth/sign-out", lambda route: sign_outs.append(route))
    held = _Held(page, "**/hand-over-probe")
    sign_in_on_the_tab(page, ana)
    sent_for = page.evaluate("() => authToken")
    page.evaluate(_ASK_SERVER, 0)
    page.evaluate(_ASK_SERVER, 1)
    held.wait(2)
    assert all(r.request.headers.get("authorization") == f"Bearer {sent_for}" for r in held.routes)
    mark_old(page)
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    for _ in range(200):
        if sign_outs:
            break
        page.wait_for_timeout(50)
    assert len(sign_outs) == 1 and sign_outs[0].request.headers.get("authorization") == f"Bearer {sent_for}"
    assert still_old(page), "the page was replaced before its sign-out was answered"

    # ben fills in the form on the page that stays. A refusal of ana's session arrives (to a call made before her
    # session ended: it never settles on this page, app.js apiRequest), and so does one of a request sent with no
    # session at all (the server's own answer): the form keeps what he typed.
    _types(page, ben)
    held.refuse_next()
    _round_trip(page)
    assert page.evaluate("() => window.__probes[0]") == "pending", "the answer of the ended session settled"
    unrouted = page.evaluate("() => apiRequest('/vaults').then(() => 'answered', (e) => e.message)")
    assert unrouted != "answered", unrouted
    _form_kept(page, ben)
    assert still_old(page)

    # His sign-in replaces the page there and then: the new page opens his session, holding nothing of the old one.
    page.click("#login-form button[type=submit]")
    wait_new_page(page)
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    signed_in_as = page.evaluate("() => authToken")
    assert signed_in_as and signed_in_as != sent_for
    assert page.evaluate("() => window.__probes === undefined"), "the new page holds a request of the old one"

    # The other refusal of ana's session, and ana's sign-out answered at last: ben stays signed in, on that page.
    mark_old(page)
    held.refuse_next()
    sign_outs.pop().continue_()
    page.unroute("**/auth/sign-out")
    for _ in range(200):
        if session_row(sent_for) == "f|t":
            break
        page.wait_for_timeout(50)
    assert session_row(sent_for) == "f|t", "ana's session was not ended once her sign-out went through"
    _round_trip(page)
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert still_old(page), "the page was replaced after the next person's sign-in"
    assert page.evaluate("() => authToken") == signed_in_as
    _a_refusal_of_the_session_held_now_ends_it(page)


def test_a_sign_out_still_owed_when_the_next_person_signs_in_is_sent_before_the_page_is_replaced(page: Page, two):
    """ana's sign-out is answered 503 with a Retry-After longer than the test waits, so the page that stays owes it
    and would send it again only when that wait is over. ben signs in on that page first: his sign-in replaces it,
    and before that the page sends ana's sign-out again (two in all, both with her token), so her session is ended
    on the server rather than left live with the page that owed it."""
    ana, ben, _ben_c, _vault = two
    sent = []

    def refuse_first(route):
        sent.append(route.request.headers.get("authorization"))
        if len(sent) == 1:
            route.fulfill(status=503, content_type="application/json", headers={"Retry-After": "120"},
                          body='{"detail": "Service Unavailable"}')
        else:
            route.continue_()

    page.route("**/auth/sign-out", refuse_first)
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    mark_old(page)
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    for _ in range(200):
        if sent:
            break
        page.wait_for_timeout(50)
    assert sent == [f"Bearer {token}"], sent
    page.wait_for_timeout(500)                    # the 503's answer has been had: the page owes the sign-out
    assert still_old(page), "the page was replaced though its sign-out was refused for now"
    assert session_row(token) == "t|f"

    _types(page, ben)
    page.click("#login-form button[type=submit]")
    wait_new_page(page)
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("(old) => !!authToken && authToken !== old", token)
    for _ in range(200):
        if session_row(token) == "f|t":
            break
        page.wait_for_timeout(50)
    assert sent == [f"Bearer {token}"] * 2, f"{len(sent)} sign-outs sent for ana's session"
    assert session_row(token) == "f|t", "ana's session was left live when ben's sign-in replaced the page"


def test_after_a_two_factor_sign_in_the_sign_out_leaves_a_form_to_sign_in_with(page: Page, admin):
    eve = admin.create_user()
    _secret, codes = enroll_totp(eve, signed_in(eve))
    ben = admin.create_user()
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", eve["_username"])
        page.fill("#password", eve["_password"])
        page.click("#login-form button[type=submit]")
        card = page.locator("#login-second-factor")
        expect(card).to_be_visible(timeout=15000)
        expect(page.locator("#login-form")).to_be_hidden()
        card.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#sf-code-input", codes.pop(0))
        card.locator("button").last.click()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        sign_out(page)
        # The form is there again, empty, and the second step's card is gone.
        expect(page.locator("#login-form")).to_be_visible()
        expect(page.locator("#username")).to_have_value("")
        expect(page.locator("#password")).to_have_value("")
        expect(card).to_be_hidden()
        assert card.inner_html() == ""
        sign_in_on_the_tab(page, ben)
    finally:
        admin.delete_user(eve["id"])
        admin.delete_user(ben["id"])
