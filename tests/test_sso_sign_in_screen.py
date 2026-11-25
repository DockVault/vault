"""The sign-in screen's part of single sign-on (static/js/app.js with static/js/sso.js), and where its sentences point.

The provider buttons stand under a heading that names them. A link to one of the app's views, opened while signed
out, goes to the provider and comes back to that view. A link, a test or a confirmation that comes back to a page with
no session says that nothing was done. A sign-in that finds no linked account names both ways in, and the sentences
that send a person to Your account name a place the page has under that name.

The page's own functions run in Node on the small document of tests/js/mini_dom.js, against stand-ins for the server
(the server's side has its own tests).
"""
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "static" / "index.html"


class _ItemText(HTMLParser):
    """The text of the element with one id, and of every element inside it."""

    def __init__(self, element_id):
        super().__init__()
        self.element_id, self.depth, self.text = element_id, 0, []

    def handle_starttag(self, tag, attrs):
        if self.depth:
            self.depth += 1
        elif dict(attrs).get("id") == self.element_id:
            self.depth = 1

    def handle_endtag(self, tag):
        if self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if self.depth:
            self.text.append(data)


def _text_of(element_id: str) -> str:
    parser = _ItemText(element_id)
    parser.feed(INDEX.read_text(encoding="utf-8"))
    return " ".join("".join(parser.text).split())


def test_the_profile_menu_names_the_dialog_it_opens_as_the_sentences_name_it():
    """Sentences of the sign-in and of the account send people "under Your account". The profile menu's item that
    opens that dialog is called the same, and the dialog's title and its single sign-on section say so too."""
    assert _text_of("settings-btn") == "Your account"
    html = INDEX.read_text(encoding="utf-8")
    dialog = html[html.index('<div id="user-settings-modal"'):]
    assert re.search(r"<h3>[^<]*<svg[^>]*><use[^>]*/></svg>\s*Your account</h3>", dialog[:600]), dialog[:600]
    assert '<h4 class="us-section-title">Single sign-on</h4>' in dialog


# --------------------------------------------------------------------------- the page's own functions, in Node

APP_JS = ROOT / "static" / "js" / "app.js"
SSO_JS = ROOT / "static" / "js" / "sso.js"
# The sign-in screen's single sign-on, as shipped; a name that is not in app.js is left out (and its test fails on
# what the page does, not on a missing name).
_SHIPPED = ("_el", "_showReasonNote", "_showLoginError", "_signInOriginElsewhere", "_addressFixable", "_noteSignInOrigin",
            "_ssoReturnTo", "_initSsoSignIn", "_ssoStartHandOut", "_ssoOnSignInScreen", "_ssoSignInBackToASignedInPage",
            "_ssoResume")
_STATE = ("_hashForSignIn", "_passwordStage")
_CONSTANTS = ("SSO_BACK_SIGNED_OUT", "_SSO_BACK_OF_A_SESSION")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    if not found:
        return ""
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


def _state(js, name):
    found = re.search(rf"^let {re.escape(name)} = [^;]*;", js, re.M)
    assert found, name
    return found.group(0) + "\n"


def _constant(js, name):
    found = re.search(rf"^const {re.escape(name)} = .*?;\n", js, re.M | re.S)
    return found.group(0) if found else ""


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const form = document.createElement('form'); form.id = 'login-form'; document.body.appendChild(form);
const ssoBox = document.createElement('div'); ssoBox.id = 'sso-sign-in'; ssoBox.style.display = 'none'; form.appendChild(ssoBox);
const originNote = document.createElement('p'); originNote.id = 'login-origin-note'; form.appendChild(originNote);
const loginError = document.createElement('div'); loginError.id = 'login-error'; loginError.style.display = 'none';
document.body.appendChild(loginError);
const store = {};
global.sessionStorage = {
    getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; },
};
const left = [];
global.location = { hash: '', pathname: '/', search: '', origin: 'https://vault.example.org',
                    assign: (u) => { left.push(u); }, replace: (u) => { left.push(u); } };
global.history = { replaceState: () => { global.location.hash = ''; } };
var API_BASE = '/api';
var authToken = null;
var currentUser = null;
const sent = [];
let answers = {};                     // 'METHOD url' -> {status, json}: what the server answers
global.fetch = async (url, options) => {
    const method = (options || {}).method || 'GET';
    let body = null;
    try { body = JSON.parse((options || {}).body); } catch (_) { body = null; }
    sent.push({ method, url, body });
    const a = answers[method + ' ' + url] || { status: 404, json: { detail: 'Not arranged.' } };
    return { ok: a.status >= 200 && a.status < 300, status: a.status, headers: { get: () => null },
             json: async () => a.json };
};
global.apiRequest = async (path) => { throw new Error('Not arranged: ' + path); };
const toasts = [];
function showError(m) { toasts.push(['error', m]); }
function showSuccess(m) { toasts.push(['success', m]); }
function showToast(m, t) { toasts.push([t, m]); }
function openUserSettingsModal() { toasts.push(['opened', 'Your account']); }
function _noteProviderConfirmation() {}
let _passkeyAddConfirmed = false;
const passkey = [];
function _stopPasskeyOffer() { passkey.push('stop'); }
function _passkeyHoldsPage() { passkey.push('hold'); }
function _passkeyLetsGo() { passkey.push('go'); }
async function _passkeySignInAnswer(data, how) { passkey.push('answer:' + how); }
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const settle = async () => { for (let i = 0; i < 20; i += 1) await tick(); };
const note = () => ({ text: loginError.textContent, shown: loginError.style.display !== 'none' });
// A provider's redirect: the page loads with this fragment, and the module takes it out of the address.
const arrive = (hash) => { location.hash = hash; return window.Sso.takeReturn(); };
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(scenario: str, reasons=None):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + f"const REASONS = {json.dumps(reasons or {})};\n"
              + "".join(_state(js, n) for n in _STATE) + "".join(_constant(js, n) for n in _CONSTANTS)
              + "".join(_function(js, n) for n in _SHIPPED)
              + SSO_JS.read_text(encoding="utf-8")
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _server_reasons() -> dict:
    """What GET /auth/sso/reasons answers: the server's own sentences."""
    from app.services import sso_sign_in as sso
    return dict(sso.REASON_TEXTS)


def test_a_sign_in_with_no_account_linked_names_both_ways_in():
    """The provider's sign-in worked and no account here is linked to it: the default rule (only invited or linked
    people), or an account whose address the vault never confirmed. The person may well have an account here, and an
    invitation for an address in use is refused: the sentence names the link from Your account first, and an
    invitation for whoever has no account. One sentence for every such refusal, so it says nothing of whether an
    account exists."""
    reasons = _server_reasons()
    said = reasons["no_account"]
    assert "no account here is linked to it" in said
    assert "sign in to it the way you usually do" in said
    assert "link your organisation's sign-in under Your account (Single sign-on)" in said
    assert said.endswith("Otherwise ask an administrator to invite you.")
    assert "no account for you here" not in said
    got = _node(r"""
answers['GET /api/auth/sso/reasons'] = { status: 200, json: { reasons: REASONS } };
await _ssoOnSignInScreen(arrive('#sso-error=no_account'));
out(note());
""", reasons)
    assert got == {"text": said, "shown": True}


def test_a_sign_in_with_no_account_linked_names_the_accounts_your_account_cannot_link():
    """Your account refuses the link for an account with no password anybody can type (one a provider made at a first
    sign-in, or one that signs in only through providers), and for an administrator's or auditor's account when the
    provider's people hold no password; it says to ask an administrator. The sign-in page's sentence names that
    exception beside the link, so such a person is not sent to a page that only refuses them."""
    from app.api import sso_router
    said = _server_reasons()["no_account"]
    assert ("link your organisation's sign-in under Your account (Single sign-on); if your account has no password "
            "of its own, or the link is refused there, ask an administrator.") in said
    assert "no password of its own" in sso_router.NO_PASSWORD_TO_LINK_TEXT
    assert sso_router.NO_PASSWORD_TO_LINK_TEXT.endswith("Ask an administrator.")
    assert said.endswith("Otherwise ask an administrator to invite you.")


TWO = [{"id": "11111111-1111-4111-8111-111111111111", "label": "Company sign-in", "kind": "oidc", "icon": "microsoft",
        "order": 1},
       {"id": "22222222-2222-4222-8222-222222222222", "label": "Contractors", "kind": "oidc", "icon": "generic",
        "order": 2}]


def test_the_provider_buttons_stand_under_a_heading_that_names_the_group():
    """The buttons carry the administrator's name for each provider and no verb: a heading before them says what they
    do, and names the group they form for a screen reader (index.html's role and aria-labelledby). With no provider
    the box, and its heading, are not shown."""
    got = _node(r"""
_initSsoSignIn({ methods: { providers: PROVIDERS } });
const kids = ssoBox.children.map((c) => [c.localName, c.id, c.textContent, c.className]);
const heading = document.getElementById('sso-sign-in-heading');
const buttons = ssoBox.querySelectorAll('button').map((b) => b.textContent);
const shown = ssoBox.style.display !== 'none';
_initSsoSignIn({ methods: { providers: [] } });
out({ kids, heading: heading && heading.textContent, buttons, shown,
      after: { shown: ssoBox.style.display !== 'none', heading: document.getElementById('sso-sign-in-heading') === null,
               children: ssoBox.children.length } });
""".replace("PROVIDERS", json.dumps(TWO)))
    assert got["shown"] is True and got["heading"] == "Sign in with your organisation"
    assert got["kids"][0][:3] == ["p", "sso-sign-in-heading", "Sign in with your organisation"]
    assert "sso-sign-in-heading" in got["kids"][0][3].split()
    assert got["buttons"] == ["Company sign-in", "Contractors"]
    assert [k[0] for k in got["kids"]] == ["p", "button", "button"]          # the heading first, then the buttons
    assert got["after"] == {"shown": False, "heading": True, "children": 0}
    html = INDEX.read_text(encoding="utf-8")
    box = re.search(r'<div id="sso-sign-in"[^>]*>', html).group(0)
    assert 'role="group"' in box and 'aria-labelledby="sso-sign-in-heading"' in box, box
    # The divider beside the heading is drawn in the colour every skin gives its hairlines.
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")
    rule = re.search(r"\.sso-sign-in-heading::before, \.sso-sign-in-heading::after \{([^}]*)\}", css)
    assert rule and "border-top: 1px solid var(--surface-3)" in rule.group(1), rule
    for skin in ("theme.css", "ui-v2.css"):
        assert "--surface-3:" in (ROOT / "static" / "css" / skin).read_text(encoding="utf-8"), skin


def _start_body(loaded_with: str, *, set_after_drawing: bool = False, hand_out: bool = False) -> dict:
    """What the page sends to start a provider's sign-in when it was loaded at /<loaded_with> signed out."""
    return _node(r"""
const first = PROVIDERS[0].id;
answers['POST /api/auth/sso/' + first + '/start'] = { status: 200, json: { authorization_url: 'https://idp.example.org/a' } };
answers['GET /api/auth/policy'] = { status: 200, json: {} };
if (!AFTER) _hashForSignIn = LOADED;
if (HAND_OUT) {
    _ssoStartHandOut(first);
} else {
    _initSsoSignIn({ methods: { providers: PROVIDERS } });
    if (AFTER) _hashForSignIn = LOADED;          // the page's hash was kept after the buttons were drawn
    ssoBox.querySelectorAll('button')[0].click();
}
await settle();
const start = sent.find((s) => s.method === 'POST');
out({ body: start ? start.body : null, left });
""".replace("PROVIDERS", json.dumps(TWO)).replace("LOADED", json.dumps(loaded_with))
                 .replace("AFTER", "true" if set_after_drawing else "false")
                 .replace("HAND_OUT", "true" if hand_out else "false"))


@pytest.mark.parametrize("hand_out", [False, True], ids=["button", "hand-out link"])
def test_a_link_the_signed_out_page_was_opened_at_goes_to_the_provider_and_back(hand_out):
    """A link to one of the app's own views (Your account, from a notice or an email) opened while signed out: a
    sign-in through a provider leaves the page, so the start names the view (with its '#', the form the server keeps)
    and the provider's answer brings the page back to it. Read at the click: the page keeps the hash after the
    buttons are drawn, as often as not."""
    got = _start_body("#profile", hand_out=hand_out)
    assert got["body"]["return_to"] == "#profile" and set(got["body"]) == {"verifier_hash", "return_to"}, got
    assert got["left"] == ["https://idp.example.org/a"]
    if not hand_out:
        assert _start_body("#users", set_after_drawing=True)["body"]["return_to"] == "#users"


@pytest.mark.parametrize("loaded_with", ["", "#activity?q=x", "#vault/abc", "#sso=x", "#profile2"])
def test_anything_but_one_of_the_apps_own_views_is_not_sent(loaded_with):
    """The server keeps a view on its list and turns anything else into Vaults; the page sends nothing else (an
    Activity search is not on the list)."""
    got = _start_body(loaded_with)
    assert got["body"] is not None and set(got["body"]) == {"verifier_hash"}, got


def test_the_pages_list_of_views_is_the_servers():
    from app.core import sso_state
    js = APP_JS.read_text(encoding="utf-8")
    body = _function(js, "_ssoReturnTo")
    listed = re.search(r"const allowed = \[([^\]]*)\];", body)
    assert listed, body
    assert tuple(re.findall(r"'([^']*)'", listed.group(1))) == sso_state.RETURN_TO


BACK_SIGNED_OUT = ("Your session ended while you were at your organisation's sign-in, so nothing was linked, tested or "
                   "confirmed. Sign in and start again.")


@pytest.mark.parametrize("fragment", ["#sso-linked=abc", "#sso-test=abc", "#sso-stepup=abc"])
def test_a_link_test_or_confirmation_back_to_a_page_with_no_session_says_nothing_was_done(fragment):
    """The provider sends the browser back with a link, a test or a confirmation the signed-in session started. The
    page has no session any more (none stored, or the stored one was refused at the load): the code can be claimed
    only by the session that started it, so nothing was done, and the sign-in screen says so."""
    got = _node(r"""
answers['GET /api/auth/sso/reasons'] = { status: 200, json: { reasons: REASONS } };
// No session stored: the page shows the sign-in screen with what came back.
await _ssoOnSignInScreen(arrive(FRAGMENT));
const none = note();
loginError.textContent = ''; loginError.style.display = 'none';
// A session stored and refused at the load: the sign-out writes no reason, then what came back is looked at.
authToken = null; currentUser = null;
await _ssoResume(arrive(FRAGMENT));
const refused = note();
out({ none, refused, sent: sent.filter((s) => s.method === 'POST').length, toasts });
""".replace("FRAGMENT", json.dumps(fragment)), _server_reasons())
    assert got["none"] == {"text": BACK_SIGNED_OUT, "shown": True}, got
    assert got["refused"] == {"text": BACK_SIGNED_OUT, "shown": True}, got
    assert got["sent"] == 0 and got["toasts"] == []


def test_a_sign_in_or_a_refusal_back_to_a_page_with_no_session_is_not_told_its_session_ended():
    """A stored session refused at the load leaves the sign-in screen up: a sign-in's code or a refusal that came back
    is taken as the sign-in screen takes it (here a code with no proof in this tab, then a refusal), never as a link,
    a test or a confirmation the session lost."""
    got = _node(r"""
answers['GET /api/auth/sso/reasons'] = { status: 200, json: { reasons: REASONS } };
await _ssoResume(arrive('#sso=abc'));
const code = note();
await _ssoResume(arrive('#sso-error=no_account'));
const resumed = note();
await _ssoOnSignInScreen(arrive('#sso-error=busy'));
out({ code, resumed, refused: note(), posts: sent.filter((s) => s.method === 'POST').length });
""", _server_reasons())
    assert got["code"] == {"text": "That sign-in did not come back to the tab that started it. Start again.",
                           "shown": True}
    assert got["resumed"] == {"text": _server_reasons()["no_account"], "shown": True}
    assert got["refused"] == {"text": _server_reasons()["busy"], "shown": True}
    assert got["posts"] == 0
    assert BACK_SIGNED_OUT not in (got["code"]["text"], got["resumed"]["text"])


_START_HERE = r"""
answers['GET /api/auth/sso/reasons'] = { status: 200, json: { reasons: REASONS } };
answers['POST /api/auth/sso/p-1/start'] = { status: 200, json: { authorization_url: 'https://idp.example.org/a' } };
await window.Sso.startSignIn('p-1', INVITED ? { invitation: 'inv-token' } : {});
const kept = store.dv_sso_flow;
"""


def test_an_invitation_accepted_through_a_provider_where_the_stored_session_was_refused_is_finished():
    """The invitation page offers its providers whatever session the browser stores. The provider sends the browser
    back, and the load checks the stored session first: refused (it had run out), the sign-in screen is up, and the
    sign-in this tab started is finished there with this tab's proof, as on the sign-in screen, so the invited account
    is made. A refusal the provider's answer brought back is said in the server's words."""
    got = _node(_START_HERE.replace("INVITED", "true") + r"""
answers['POST /api/auth/finish'] = { status: 200, json: { access_token: 'new-token' } };
// The stored session was refused at the load: its sign-out leaves the sign-in screen up, and no session.
authToken = null; currentUser = null;
await _ssoResume(arrive('#sso=code-1'));
const finished = sent.filter((s) => s.method === 'POST' && s.url === '/api/auth/finish').map((s) => s.body);
await window.Sso.startSignIn('p-1', { invitation: 'inv-token' });
await _ssoResume(arrive('#sso-error=no_account'));
out({ finished, kept: JSON.parse(kept), raw: kept, passkey, refused: note(), toasts });
""", _server_reasons())
    # The flow names an invitation, never its token.
    assert got["kept"]["purpose"] == "sign_in" and got["kept"]["invitation"] is True
    assert "inv-token" not in got["raw"]
    assert got["finished"] == [{"code": "code-1", "verifier": got["kept"]["verifier"]}]
    assert "answer:provider" in got["passkey"]
    assert got["refused"] == {"text": _server_reasons()["no_account"], "shown": True}
    assert got["toasts"] == []


@pytest.mark.parametrize("invited", [True, False])
def test_a_sign_in_that_comes_back_to_a_page_already_signed_in_says_nothing_was_done(invited):
    """The stored session is good: the page opens it, and the code that came back is not claimed for the account
    signed in here (the invitation stays unaccepted, and no account is made). The person is told so, and how to do it
    again, never left to believe it went through."""
    got = _node(_START_HERE.replace("INVITED", json.dumps(invited)) + r"""
authToken = 'stored'; currentUser = { id: 'u-1', username: 'alice' };
await _ssoResume(arrive('#sso=code-1'));
out({ posts: sent.filter((s) => s.method === 'POST').map((s) => s.url), toasts, note: note() });
""", _server_reasons())
    assert got["posts"] == ["/api/auth/sso/p-1/start"]          # nothing was claimed
    told = ("Your organisation's sign-in came back to this page, which is already signed in as alice, so "
            + ("your invitation was not accepted and no account was made. To accept it, choose Logout in your "
               "profile menu (top-right), then open your invitation link again and accept it through your "
               "organisation's sign-in." if invited else
               "nothing was done with it. To sign in as someone else, choose Logout in your profile menu (top-right) "
               "first, then sign in again."))
    assert got["toasts"] == [["warning", told]]
    assert got["note"] == {"text": "", "shown": False}


def test_the_boot_hands_what_came_back_to_the_session_check_and_then_to_the_resume():
    """With a stored session the load checks it first, then hands what came back to _ssoResume, whichever way the
    check went: a refused session leaves the sign-in screen up, where a sign-in this tab started is finished."""
    js = APP_JS.read_text(encoding="utf-8")
    assert "enterAuthedSession().then(() => _ssoResume(ssoBack))" in js


# --------------------------------------------------------------------------- a page opened at another address

THERE = "https://vault.example.test"


@pytest.mark.parametrize("here, told", [
    ({"origin": "http://localhost:8200", "hostname": "localhost", "protocol": "http:"}, True),
    ({"origin": "https://vault.example.test:8443", "hostname": "vault.example.test", "protocol": "https:"}, True),
    # No passkey and no provider's sign-in can work at an IP address or a name over plain http: that address is no
    # fix for the vault's, and nothing points there.
    ({"origin": "http://192.168.1.20:8200", "hostname": "192.168.1.20", "protocol": "http:"}, False),
    ({"origin": "https://[fd00::1]:8443", "hostname": "[fd00::1]", "protocol": "https:"}, False),
    ({"origin": "http://vault.lan", "hostname": "vault.lan", "protocol": "http:"}, False),
], ids=["localhost", "a name over https", "an IP address", "an IPv6 address", "a name over http"])
def test_a_page_opened_at_another_address_says_who_can_fix_the_vaults_address(here, told):
    """The vault's address (the first ALLOWED_HOSTS entry) may be the wrong one, as on a vault set up on another port
    with a bare host name: the page then sends people to an address where nothing answers. The note says what to
    tell the administrator, where the address the page was opened at could be the vault's."""
    got = _node(r"""
Object.assign(location, PAGE_AT);
_noteSignInOrigin({ methods: { passkeys: true, origin: VAULT_AT } }, ['a passkey']);
const elsewhere = { text: originNote.textContent, hidden: originNote.hidden,
                    link: originNote.querySelector('a') && originNote.querySelector('a').href };
_noteSignInOrigin({ methods: { passkeys: true, origin: location.origin } }, ['a passkey']);
out({ elsewhere, same: { text: originNote.textContent, hidden: originNote.hidden } });
""".replace("PAGE_AT", json.dumps(here)).replace("VAULT_AT", json.dumps(THERE)))
    said = f"Signing in with a passkey works at {THERE}. Open the vault there to use it."
    if told:
        said += (f" If nothing answers there, tell your administrator: the vault's address is set to {THERE}, and you "
                 f"opened it at {here['origin']}.")
    assert got["elsewhere"] == {"text": said, "hidden": False, "link": THERE + "/"}
    assert got["same"] == {"text": "", "hidden": True}
