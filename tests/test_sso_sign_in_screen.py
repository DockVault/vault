"""The sign-in screen's part of single sign-on (static/js/app.js with static/js/sso.js), and where its sentences point.

The page's own functions run in Node on the small document of tests/js/mini_dom.js, against stand-ins for the server
(the server's side has its own tests). What is proved here: the sentences that send a person to Your account name a
place the page has under that name.
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
_SHIPPED = ("_el", "_showReasonNote", "_showLoginError", "_signInOriginElsewhere", "_noteSignInOrigin", "_ssoReturnTo",
            "_initSsoSignIn", "_ssoStartHandOut", "_ssoOnSignInScreen", "_ssoResume")
_STATE = ("_hashForSignIn", "_passwordStage")


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
              + "".join(_state(js, n) for n in _STATE) + "".join(_function(js, n) for n in _SHIPPED)
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
