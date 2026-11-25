"""Your account's two-factor section (static/js/app.js, renderAccount2FA and account2FADisable).

GET /users/me/second-factor says whether an authenticator app is in use (``enrolled``), how many recovery codes are
left, whether the account has a password somebody can type (``password_to_type``) and how many usable passkeys it
holds (``passkeys``). A passkey is a second factor: the sign-in asks for it. An account whose only factor is a passkey
must not read that two-factor authentication is off, and turning the authenticator app off must not promise a sign-in
with the password only while passkeys still confirm it is the person.

Under Your account, an account that holds a factor (a passkey) gives it before it adds an authenticator app: the
set-up (POST /users/me/second-factor/totp/enroll) and the acknowledgement of the recovery codes each answer 403
second_factor_required, and each spends a confirmation of its own. The set-up asks for it and sends the request once
more, and never shows a refusal's object as "[object Object]".

The page's own functions run in Node on the small document of tests/js/mini_dom.js, against a stand-in for the
server (the server's side has its own tests).
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"
# Your account's two-factor section, as shipped; a name that is not in app.js is left out (and its test fails on what
# the page does, not on a missing name).
_SHIPPED = ("_el", "_sfError", "renderAccount2FA", "account2FASetup", "_account2FAPasskeys", "account2FADisable",
            "renderEnrollmentWizard")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    if not found:
        return ""
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const body = document.createElement('div'); body.id = 'us-2fa-body'; document.body.appendChild(body);
const API_BASE = 'https://vault.example.test';
let authToken = 'token-of-alice';
const asked = [];
let answers = {};
global.apiRequest = async (path, options) => {
    const method = (options || {}).method || 'GET';
    asked.push({ path, method });
    const key = method + ' ' + path;
    const answer = Object.prototype.hasOwnProperty.call(answers, key) ? answers[key]
        : new Error('Not arranged: ' + key);
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer() : answer;
};
// window.confirm, as the page asks it: what it asked, and the answer the test gives.
const confirms = [];
let confirmAnswer = false;
global.confirm = (message) => { confirms.push(message); return confirmAnswer; };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const STATE = (more) => Object.assign({ enrolled: false, method: null, status: 'not_setup', awaiting_acknowledge: false,
    recovery_codes_remaining: 0, password_to_type: true, passkeys: 0 }, more || {});
const said = () => body.querySelectorAll('p').map((p) => p.textContent);
const buttons = () => body.querySelectorAll('button').map((b) => b.textContent);
const button = (text) => body.querySelectorAll('button').find((b) => b.textContent === text);
const out = (value) => console.log(JSON.stringify(value));
// The server, at the set-up's own requests: each request in order, and the answers given to them in order.
const sent = [];
let replies = [];
const reply = (status, data) => ({ ok: status >= 200 && status < 300, status,
    json: async () => JSON.parse(JSON.stringify(data)), clone: () => reply(status, data) });
global.fetch = async (url, init) => {
    init = init || {};
    sent.push({ url: String(url).replace(API_BASE, ''), headers: Object.assign({}, init.headers),
                body: init.body ? JSON.parse(init.body) : null });
    const next = replies.shift();
    if (!next) throw new Error('Not arranged: ' + url);
    return reply(next[0], next[1]);
};
// The step-up dialog: what it was asked for, and the receipts the person's answers give (null: declined).
const stepUps = [];
let receipts = [];
async function requestStepUpReceipt(action, methods) {
    stepUps.push({ action, methods });
    return receipts.shift() || null;
}
const settle = async () => { for (let i = 0; i < 20; i++) await tick(); };
const STEP_UP = { detail: { second_factor_required: true, action: 'account.second_factor', reason: 'step_up_required',
                            methods: ['passkey'] } };
const ENROLL = { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', qr_svg: '' };
"""


def page_node(scenario: str):
    """Runs ``scenario`` after the shipped functions of Your account's two-factor section, and returns what it
    printed last."""
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + "".join(_function(js, n) for n in _SHIPPED)
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_an_account_whose_only_second_factor_is_a_passkey_reads_that_two_factor_authentication_is_on():
    got = page_node(r"""
const seen = {};
for (const [name, state] of Object.entries({
        one: STATE({ passkeys: 1 }),
        three: STATE({ passkeys: 3 }),
        no_password: STATE({ passkeys: 1, password_to_type: false }),
        none: STATE(),
        older_server: (() => { const s = STATE(); delete s.passkeys; return s; })() })) {
    answers['GET /users/me/second-factor'] = state;
    await renderAccount2FA();
    seen[name] = { said: said(), buttons: buttons() };
}
out(seen);
""")
    on = "Two-factor authentication is on (passkey)."
    for name in ("one", "three"):
        assert got[name] == {"said": [on + " You can add an authenticator app as well."],
                             "buttons": ["Add an authenticator app"]}, got[name]
    # An account with no password anybody can type is not offered the set-up here (the server refuses it under
    # Your account), so it is not told that it can add one.
    assert got["no_password"] == {"said": [on], "buttons": []}, got["no_password"]
    # With no passkey (or a server that does not say), the section is as it was.
    off = "Two-factor authentication is off. Add an authenticator app for a second sign-in factor."
    for name in ("none", "older_server"):
        assert got[name] == {"said": [off], "buttons": ["Set up two-factor"]}, got[name]


def test_an_account_with_an_authenticator_app_and_passkeys_reads_both():
    got = page_node(r"""
const seen = {};
for (const [name, state] of Object.entries({
        two: STATE({ enrolled: true, method: 'totp', status: 'active', recovery_codes_remaining: 7, passkeys: 2 }),
        one: STATE({ enrolled: true, method: 'totp', status: 'active', recovery_codes_remaining: 1, passkeys: 1 }),
        none: STATE({ enrolled: true, method: 'totp', status: 'active', recovery_codes_remaining: 10 }) })) {
    answers['GET /users/me/second-factor'] = state;
    await renderAccount2FA();
    seen[name] = { said: said(), buttons: buttons() };
}
out(seen);
""")
    assert got["two"]["said"] == ["Two-factor authentication is on (authenticator app and 2 passkeys). 7 recovery "
                                  "codes remaining."], got["two"]
    assert got["one"]["said"] == ["Two-factor authentication is on (authenticator app and 1 passkey). 1 recovery code "
                                  "remaining."], got["one"]
    assert got["none"]["said"] == ["Two-factor authentication is on (authenticator app). 10 recovery codes "
                                   "remaining."], got["none"]
    for seen in got.values():
        assert seen["buttons"] == ["Regenerate recovery codes", "Turn off"], seen


def test_turning_the_authenticator_app_off_says_what_still_confirms_it_is_you():
    """The removal takes the authenticator app and its recovery codes only: passkeys stay and are still asked for.
    An account with no password of its own does not sign in with a password after it; one with a password and no
    passkey does."""
    got = page_node(r"""
const seen = {};
for (const [name, state] of Object.entries({
        passkeys: STATE({ enrolled: true, status: 'active', recovery_codes_remaining: 4, passkeys: 2 }),
        provider: STATE({ enrolled: true, status: 'active', recovery_codes_remaining: 4, password_to_type: false }),
        password: STATE({ enrolled: true, status: 'active', recovery_codes_remaining: 4 }) })) {
    answers['GET /users/me/second-factor'] = state;
    await renderAccount2FA();
    confirms.length = 0;
    button('Turn off').click();
    await tick();
    seen[name] = confirms.slice();
}
out({ seen, deleted: asked.filter((a) => a.method === 'DELETE').length });
""")
    seen = got["seen"]
    assert seen["passkeys"] == ["Turn off the authenticator app? Your passkeys stay, and still confirm it is you."]
    assert seen["provider"] == ["Turn off two-factor authentication? You will sign in through your organisation's "
                                "sign-in without a second factor from this vault."]
    assert seen["password"] == ["Turn off two-factor authentication? You will sign in with your password only."]
    assert not any("password only" in m for m in seen["passkeys"] + seen["provider"])
    assert got["deleted"] == 0            # every question was answered No


ENROLL_URL = "/users/me/second-factor/totp/enroll"
CONFIRM_URL = "/users/me/second-factor/totp/confirm"
ACK_URL = "/users/me/second-factor/recovery/acknowledge"


def test_an_account_that_holds_a_passkey_adds_an_authenticator_app_after_its_second_factor_each_time_asked():
    got = page_node(r"""
replies = [[403, STEP_UP], [200, ENROLL], [200, { recovery_codes: ['aaaa-bbbb', 'cccc-dddd'] }], [403, STEP_UP],
           [200, { enrolled: true, method: 'totp' }]];
receipts = ['receipt-1', 'receipt-2'];
let completed = 0;
const box = document.createElement('div'); body.appendChild(box);
const texts = [];
renderEnrollmentWizard(box, { token: authToken, password: 'pw', onComplete: () => { completed++; } });
await settle();
texts.push(box.textContent);
box.querySelector('#sf-enroll-code').value = '123456';
box.querySelectorAll('button').find((b) => b.textContent === 'Continue').click();
await settle();
texts.push(box.textContent);
box.querySelector('#sf-ack-cb').checked = true;
box.querySelectorAll('button').find((b) => b.textContent === 'Finish').click();
await settle();
texts.push(box.textContent);
out({ sent, stepUps, completed, texts });
""")
    assert [s["url"] for s in got["sent"]] == [ENROLL_URL, ENROLL_URL, CONFIRM_URL, ACK_URL, ACK_URL], got["sent"]
    assert [s["headers"].get("X-Second-Factor") for s in got["sent"]] == [None, "receipt-1", None, None, "receipt-2"]
    # The request sent again is the same request: its token, and the password typed for the set-up.
    assert all(s["headers"]["Authorization"] == "Bearer token-of-alice" for s in got["sent"]), got["sent"]
    assert got["sent"][0]["body"] == got["sent"][1]["body"] == {"current_password": "pw"}
    # Asked twice: each route spends a confirmation of its own.
    assert got["stepUps"] == [{"action": "account.second_factor", "methods": ["passkey"]}] * 2
    assert "Scan this QR code" in got["texts"][0] and "Save your recovery codes" in got["texts"][1], got["texts"]
    assert got["completed"] == 1
    assert not any("[object Object]" in text for text in got["texts"]), got["texts"]


def test_a_declined_second_factor_says_what_the_set_up_needs_and_sends_nothing_more():
    got = page_node(r"""
const seen = {};
// Declined at the start.
replies = [[403, STEP_UP]];
receipts = [null];
let box = document.createElement('div'); body.replaceChildren(box);
renderEnrollmentWizard(box, { token: authToken, password: 'pw', onComplete: () => {} });
await settle();
seen.start = { sent: sent.length, said: box.querySelectorAll('.alert').map((a) => a.textContent),
               back: box.querySelectorAll('a').map((a) => a.textContent) };
// Declined at the recovery codes: the button can be pressed again.
sent.length = 0;
replies = [[200, ENROLL], [200, { recovery_codes: ['aaaa-bbbb'] }], [403, STEP_UP]];
receipts = [null];
box = document.createElement('div'); body.replaceChildren(box);
renderEnrollmentWizard(box, { token: authToken, password: 'pw', onComplete: () => {} });
await settle();
box.querySelector('#sf-enroll-code').value = '123456';
box.querySelectorAll('button').find((b) => b.textContent === 'Continue').click();
await settle();
box.querySelector('#sf-ack-cb').checked = true;
const finish = box.querySelectorAll('button').find((b) => b.textContent === 'Finish');
finish.click();
await settle();
seen.ack = { sent: sent.map((s) => s.url), said: box.querySelectorAll('.alert').map((a) => a.textContent),
             disabled: !!finish.disabled };
out({ seen, stepUps: stepUps.length, text: body.textContent });
""")
    start, ack = got["seen"]["start"], got["seen"]["ack"]
    assert start["sent"] == 1 and start["said"] == ["This needs your second factor first."], start
    assert start["back"] == ["\u2190 Back"], start
    assert ack["sent"] == [ENROLL_URL, CONFIRM_URL, ACK_URL], ack
    assert ack["said"] == ["This needs your second factor first."] and ack["disabled"] is False, ack
    assert got["stepUps"] == 2
    assert "[object Object]" not in got["text"]


@pytest.mark.parametrize("where", ["start", "code", "codes"])
def test_a_structured_refusal_shows_its_sentence(where):
    """A refusal whose detail is {reason, message} shows the message, at every step of the set-up."""
    got = page_node(r"""
const refusal = [409, { detail: { reason: 'something', message: 'The words of the refusal.' } }];
replies = WHERE === 'start' ? [refusal]
    : WHERE === 'code' ? [[200, ENROLL], refusal]
    : [[200, ENROLL], [200, { recovery_codes: ['aaaa-bbbb'] }], refusal];
const box = document.createElement('div'); body.replaceChildren(box);
renderEnrollmentWizard(box, { token: authToken, password: 'pw', onComplete: () => {} });
await settle();
if (WHERE !== 'start') {
    box.querySelector('#sf-enroll-code').value = '123456';
    box.querySelectorAll('button').find((b) => b.textContent === 'Continue').click();
    await settle();
}
if (WHERE === 'codes') {
    box.querySelector('#sf-ack-cb').checked = true;
    box.querySelectorAll('button').find((b) => b.textContent === 'Finish').click();
    await settle();
}
out({ said: box.querySelectorAll('.alert').filter((a) => a.style.display !== 'none').map((a) => a.textContent),
      stepUps: stepUps.length });
""".replace("WHERE", json.dumps(where)))
    assert got == {"said": ["The words of the refusal."], "stepUps": 0}, got


def test_a_sign_in_held_for_the_set_up_asks_for_no_second_factor_here():
    """At a sign-in held for the set-up the account's factor is asked where the sign-in is held, never here: an
    answer that asks for one is shown, and nothing is sent again."""
    got = page_node(r"""
replies = [[403, STEP_UP]];
const box = document.createElement('div'); body.replaceChildren(box);
renderEnrollmentWizard(box, { preAuthToken: 'held-1', password: 'pw' });
await settle();
out({ sent: sent.map((s) => [s.url, s.headers.Authorization, s.headers['X-Second-Factor'] || null]),
      stepUps: stepUps.length, text: box.textContent });
""")
    assert got["sent"] == [[ENROLL_URL, "Bearer held-1", None]] and got["stepUps"] == 0, got
    assert "[object Object]" not in got["text"]
