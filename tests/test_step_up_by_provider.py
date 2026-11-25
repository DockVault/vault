"""The web app's step-up dialog meets the password part with a fresh sign-in at the organisation's provider.

The server offers the method ``idp_reauth`` for an account with no password anybody can type (app/core/step_up_methods.py,
app/services/sso_sign_in.py reauth_allowed), never for a compliance step. The dialog (static/js/app.js,
requestStepUpReceipt and _buildStepUpBody) then names the provider instead of asking for a password nobody could
give, and starts the fresh sign-in there for this very action. The page comes back from the provider with the
confirmation staged at the server (POST /users/me/identities/reauth/finish, two minutes, this session and this
action, once): _ssoResume notes it and says what to do, and the step-up of the action done again asks for its
receipt with ``password_method: 'idp_reauth'`` and no password. A method the server did not list is never offered.

Driven in Node against the shipped functions, on the small document of tests/js/mini_dom.js.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"
_SHIPPED = ("_el", "_sfError", "_stepUpSettle", "_noteProviderConfirmation", "_providerConfirmationFor",
            "_stepUpMeetsFactor", "_stepUpByProvider", "requestStepUpReceipt", "_buildProviderStepUp",
            "_buildStepUpBody", "_ssoResume")
_STATE = ("_stepUpResolve", "_stepUpDrawn", "_stepUpAsks", "_providerConfirmation")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    assert found, name
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


def _state(js, name):
    found = re.search(rf"^let {re.escape(name)} = [^;]*;", js, re.M)
    assert found, name
    return found.group(0) + "\n"


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const modal = document.createElement('div'); modal.id = 'stepup-modal'; document.body.appendChild(modal);
const modalBody = document.createElement('div'); modalBody.id = 'stepup-modal-body'; modal.appendChild(modalBody);
var API_BASE = '/api';
var authToken = 'the-token';
var currentUser = { id: 'me', username: 'dana' };
const opened = [], toasts = [], posted = [], started = [], asked = [];
let answers = [];                        // what the step-up route answers, in turn: {ok, status, json}, or {unreachable}
let providers = [{ id: 'p-1', label: 'Contoso' }];
function openModal(id) { opened.push(id); }
function closeModal() { opened.push('closed'); _stepUpSettle(null); }
function showToast(message, type, duration) { toasts.push([message, type, duration]); }
function showSuccess(message) { toasts.push([message, 'success']); }
function showError(message) { toasts.push([message, 'error']); }
function openUserSettingsModal() { opened.push('account'); }
global.fetch = async (url, options) => {
    posted.push({ url, body: JSON.parse((options || {}).body || 'null') });
    const answer = answers.shift() || { ok: false, json: { detail: 'Nothing was arranged.' } };
    if (answer.unreachable) throw new TypeError('Failed to fetch');
    return { ok: answer.ok, status: answer.status || (answer.ok ? 200 : 403), json: async () => answer.json };
};
window.Sso = {
    confirmers: async () => { asked.push('confirmers'); return providers; },
    startConfirm: async (...args) => { started.push(args); },
    resume: async (back) => back,
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const byId = (id) => document.getElementById(id);
const shown = (id) => { const el = byId(id); return !!el && el.style.display !== 'none'; };
// The dialog's buttons in the order they stand in it (the small document lists a selector's matches in the order
// they were made, and the provider's buttons are made after the others, when its list has been read).
const inOrder = (el, found) => { el.children.forEach((c) => { if (c.localName === 'button') found.push(c); inOrder(c, found); }); return found; };
const buttons = () => inOrder(modalBody, []).map((b) => b.textContent);
const press = (text) => inOrder(modalBody, []).find((b) => b.textContent === text).click();
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + "".join(_state(js, n) for n in _STATE) + "".join(_function(js, n) for n in _SHIPPED)
              + "(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_dialog_offers_the_provider_by_name_and_no_password_field_when_the_server_lists_it():
    got = _node(r"""
const pending = requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
await tick(); await tick();
const before = { opened: opened.slice(), password: !!byId('stepup-password-input'), code: !!byId('stepup-code-input'),
                 how: byId('stepup-provider-how').textContent, buttons: buttons(),
                 noAutofocus: modal.hasAttribute('data-no-autofocus') };
document.querySelector('.stepup-provider-btn').click();
await tick();
out({ before, started, posted: posted.length, asked });
""")
    before = got["before"]
    assert before["opened"] == ["stepup-modal"] and before["password"] is False and before["code"] is False
    assert before["buttons"] == ["Confirm with Contoso", "Cancel"]
    assert "This page goes there and you come back here afterwards" in before["how"]
    assert "within two minutes: it goes through without a password." in before["how"]
    assert before["noAutofocus"] is True                     # a stray Enter does not leave the page
    # The fresh sign-in starts at the provider for this very action, and the page says its name on the way back.
    assert got["started"] == [["p-1", "vault.delete", "step-up", "Contoso"]]
    assert got["posted"] == 0 and got["asked"] == ["confirmers"]


def test_a_dialog_the_server_did_not_offer_the_provider_for_asks_for_the_password_as_before():
    got = _node(r"""
_noteProviderConfirmation('compliance.case.request', 120, 'Contoso');      // even one noted for this action
requestStepUpReceipt('compliance.case.request', ['totp', 'recovery', 'password']);
await tick(); await tick();
const seen = { password: !!byId('stepup-password-input'), code: !!byId('stepup-code-input'),
               providers: !!byId('stepup-providers'), buttons: buttons() };
byId('stepup-code-input').value = '123456';
byId('stepup-password-input').value = 'pw';
press('Confirm');
await tick();
out({ seen, asked, body: posted[0].body });
""")
    assert got["seen"] == {"password": True, "code": True, "providers": False, "buttons": ["Cancel", "Confirm"]}
    assert got["asked"] == []
    assert got["body"] == {"action": "compliance.case.request", "method": "totp", "code": "123456", "password": "pw"}


def test_a_confirmation_noted_for_the_action_is_not_spent_where_the_server_asks_for_the_password_alone():
    """The account has a password again, or the provider was turned off, within the two minutes: the step-up of the
    same action lists the password alone. The tab spends nothing and asks for the password, with no word of the
    provider."""
    got = _node(r"""
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
requestStepUpReceipt('vault.delete', ['password']);
await tick(); await tick();
const error = document.querySelector('#stepup-modal-body .alert-error');
out({ posted: posted.length, opened, asked, password: !!byId('stepup-password-input'),
      providers: !!byId('stepup-providers'), confirmed: !!byId('stepup-provider-confirmed'),
      error: error ? error.textContent : null, buttons: buttons() });
""")
    assert got == {"posted": 0, "opened": ["stepup-modal"], "asked": [], "password": True, "providers": False,
                   "confirmed": False, "error": "", "buttons": ["Cancel", "Confirm"]}


def test_signing_out_forgets_the_confirmation_the_tab_holds():
    """Sign-out (logout) forgets the confirmation with the rest of the session, before anything else it does may stop
    it: the next person on the tab never spends it."""
    from _js_source import strip_comments
    body = _function(strip_comments(APP_JS.read_text(encoding="utf-8")), "logout")
    before, found, _after = body.partition("\n    _providerConfirmation = null;\n")
    assert found, "logout does not forget the confirmation at its own level"
    assert not re.search(r"^    return\b", before, re.M)


def test_back_from_the_provider_the_action_done_again_passes_without_a_password_and_once():
    got = _node(r"""
await _ssoResume({ kind: 'confirmed', action: 'vault.delete', then: 'step-up', label: 'Contoso', expiresIn: 120 });
const toast = toasts.slice();
answers = [{ ok: true, json: { receipt: 'the-receipt' } }];
const receipt = await requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
const first = { receipt, opened: opened.slice(), body: posted[0].body, url: posted[0].url };
// Spent: the next step-up of the same action offers the provider again.
requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
await tick(); await tick();
out({ toast, first, again: { opened: opened.slice(), buttons: buttons(), posted: posted.length } });
""")
    message, kind, duration = got["toast"][0]
    assert kind == "success" and duration >= 15000
    assert message == ("You confirmed it is you with Contoso. Now do what you were doing again, within two minutes: "
                       "it goes through without a password.")
    first = got["first"]
    assert first["receipt"] == "the-receipt" and first["opened"] == []          # no dialog at all
    assert first["url"] == "/api/auth/second-factor/step-up"
    assert first["body"] == {"action": "vault.delete", "password_method": "idp_reauth"}
    assert got["again"] == {"opened": ["stepup-modal"], "buttons": ["Confirm with Contoso", "Cancel"], "posted": 1}


@pytest.mark.parametrize("how", ["another action", "it ran out"])
def test_a_confirmation_counts_only_for_its_own_action_and_while_it_lasts(how):
    got = _node(r"""
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
if ('%s' === 'it ran out') _providerConfirmation.until = Date.now() - 1;
const action = '%s' === 'another action' ? 'share.create' : 'vault.delete';
requestStepUpReceipt(action, ['idp_reauth', 'password']);
await tick(); await tick();
out({ posted: posted.length, buttons: buttons(), opened });
""" % (how, how))
    assert got == {"posted": 0, "buttons": ["Confirm with Contoso", "Cancel"], "opened": ["stepup-modal"]}


def test_a_confirmation_the_server_no_longer_holds_opens_the_dialog_with_its_sentence():
    got = _node(r"""
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
answers = [{ ok: false, json: { detail: "Confirm with your organisation's sign-in first, then try again." } }];
requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
await tick(); await tick(); await tick();
const error = document.querySelector('#stepup-modal-body .alert-error');
out({ opened, error: error.textContent, shown: error.style.display, buttons: buttons(), left: _providerConfirmation });
""")
    assert got["opened"] == ["stepup-modal"] and got["left"] is None
    assert got["error"] == "Confirm with your organisation's sign-in first, then try again." and got["shown"] == "block"
    assert got["buttons"] == ["Confirm with Contoso", "Cancel"]


@pytest.mark.parametrize("answer, said", [
    ({"ok": False, "status": 429, "json": {"detail": "Too many attempts; please wait a few minutes."}},
     "Too many attempts; please wait a few minutes."),
    ({"ok": False, "status": 503, "json": {"detail": "Service temporarily unavailable."}},
     "Service temporarily unavailable."),
    ({"ok": False, "status": 503, "json": {"detail": "The vault is busy with this right now. Try again in a moment."}},
     "The vault is busy with this right now. Try again in a moment."),
    ({"unreachable": True}, "Could not reach the server. Please try again."),
], ids=["rate limit", "limiter down", "busy", "no answer"])
def test_a_confirmation_the_server_did_not_judge_is_kept_and_the_dialog_tries_it_again(answer, said):
    """The rate limit, a limiter or a lock wait that cannot answer, or no answer at all: the server refused before it
    looked at the confirmation (or never had the request), so it still holds it. The tab keeps it too, and the dialog
    opens on it with the server's sentence; Confirm tries again with it, and no new trip to the provider is asked
    for."""
    got = _node(r"""
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
answers = [%s];
const pending = requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
await tick(); await tick(); await tick();
const error = document.querySelector('#stepup-modal-body .alert-error');
const seen = { opened: opened.slice(), error: error.textContent, shown: error.style.display, kept: !!_providerConfirmation,
               providers: !!byId('stepup-providers'), password: !!byId('stepup-password-input'),
               note: byId('stepup-provider-confirmed') && byId('stepup-provider-confirmed').textContent,
               buttons: inOrder(modalBody, []).filter((b) => b.style.display !== 'none').map((b) => b.textContent) };
answers = [{ ok: true, json: { receipt: 'the-receipt' } }];
press('Confirm');
const receipt = await pending;
out({ seen, receipt, bodies: posted.map((p) => p.body), left: _providerConfirmation, started });
""" % json.dumps(answer))
    seen = got["seen"]
    assert seen["opened"] == ["stepup-modal"] and seen["kept"] is True
    assert seen["error"] == said and seen["shown"] == "block"
    assert seen["providers"] is False and seen["password"] is False
    assert seen["note"] == "You confirmed it is you with Contoso. Select Confirm to try again."
    assert seen["buttons"] == ["Cancel", "Confirm"]
    assert got["receipt"] == "the-receipt" and got["left"] is None and got["started"] == []
    assert got["bodies"] == [{"action": "vault.delete", "password_method": "idp_reauth"}] * 2


def test_a_second_factor_asked_too_is_given_here_with_the_confirmation_in_place_of_the_password():
    got = _node(r"""
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
const methods = ['totp', 'recovery', 'idp_reauth', 'password'];
// Before the confirmation: the provider first; the code is asked for when the page is back.
_providerConfirmation = null;
requestStepUpReceipt('vault.delete', methods);
await tick(); await tick();
const before = { code: !!byId('stepup-code-input'), how: byId('stepup-provider-how').textContent };
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
const pending = requestStepUpReceipt('vault.delete', methods);
await tick();
const during = { code: !!byId('stepup-code-input'), password: !!byId('stepup-password-input'),
                 note: byId('stepup-provider-confirmed').textContent, again: shown('stepup-provider-again') };
// A wrong code: the confirmation stands, and the person may also confirm again from here.
answers = [{ ok: false, json: { detail: 'That code is not valid.' } },
           { ok: true, json: { receipt: 'the-receipt' } }];
byId('stepup-code-input').value = '000000';
press('Confirm');
await tick(); await tick();
const wrong = { error: document.querySelector('#stepup-modal-body .alert-error').textContent,
                again: shown('stepup-provider-again'), still: !!_providerConfirmation };
byId('stepup-code-input').value = '123456';
press('Confirm');
const receipt = await pending;
out({ before, during, wrong, receipt, bodies: posted.map((p) => p.body), left: _providerConfirmation });
""")
    assert got["before"]["code"] is False and got["before"]["how"].endswith(
        "once you have given your second factor here.")
    assert got["during"] == {"code": True, "password": False, "again": False,
                             "note": "You confirmed it is you with Contoso. Now give your second factor."}
    assert got["wrong"] == {"error": "That code is not valid.", "again": True, "still": True}
    assert got["receipt"] == "the-receipt" and got["left"] is None
    assert got["bodies"] == [
        {"action": "vault.delete", "method": "totp", "code": "000000", "password_method": "idp_reauth"},
        {"action": "vault.delete", "method": "totp", "code": "123456", "password_method": "idp_reauth"}]


def test_with_no_provider_that_can_confirm_the_dialog_says_so_and_offers_nothing_that_cannot_work():
    got = _node(r"""
providers = [];
requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
await tick(); await tick();
out({ said: byId('stepup-providers').textContent, buttons: buttons(), password: !!byId('stepup-password-input') })
""")
    assert got["said"].startswith("Your organisation's sign-in cannot confirm you right now.")
    assert got["buttons"] == ["Cancel"] and got["password"] is False


def test_a_start_the_server_refuses_is_said_in_the_dialog():
    got = _node(r"""
window.Sso.startConfirm = async () => { throw new Error('This step asks for your account\'s own password.'); };
requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']);
await tick(); await tick();
const go = document.querySelector('.stepup-provider-btn');
go.click();
await tick(); await tick();
const error = document.querySelector('#stepup-modal-body .alert-error');
out({ error: error.textContent, shown: error.style.display, disabled: go.disabled });
""")
    assert got == {"error": "This step asks for your account's own password.", "shown": "block", "disabled": False}


def test_the_add_passkey_and_unlink_returns_are_not_taken_for_a_step_up():
    got = _node(r"""
var _passkeyAddConfirmed = false;
window.Sso.unlinkConfirmed = async () => {};
await _ssoResume({ kind: 'confirmed', action: 'account.second_factor', then: 'add-passkey', label: '', expiresIn: 120 });
await _ssoResume({ kind: 'confirmed', action: 'sso.identity.unlink', then: 'unlink:i-1', label: '', expiresIn: 120 });
out({ left: _providerConfirmation, toasts });
""")
    assert got == {"left": None, "toasts": []}


def test_a_step_up_asked_for_while_a_confirmation_is_spent_keeps_its_dialog_and_both_settle():
    """The confirmation is being spent at the server when another gated action asks for its own step-up. The server
    turns the confirmation down: the later dialog stays on screen and settles when the person closes it, and the
    earlier one gives way at once. Neither is left waiting for ever."""
    got = _node(r"""
_noteProviderConfirmation('vault.delete', 120, 'Contoso');
let release;
global.fetch = (url, options) => {
    posted.push({ url, body: JSON.parse((options || {}).body || 'null') });
    return new Promise((resolve) => { release = () => resolve({ ok: false, json: async () => ({
        detail: "Confirm with your organisation's sign-in first, then try again." }) }); });
};
const settled = { a: 'waiting', b: 'waiting' };
requestStepUpReceipt('vault.delete', ['idp_reauth', 'password']).then((r) => { settled.a = r; });
await tick();
requestStepUpReceipt('share.create', ['totp', 'recovery']).then((r) => { settled.b = r; });
await tick(); await tick();
release();
await tick(); await tick(); await tick();
const after = { a: settled.a, b: settled.b, code: !!byId('stepup-code-input'), providers: !!byId('stepup-providers'),
                opened: opened.slice() };
closeModal();
await tick();
out({ after, closed: { a: settled.a, b: settled.b }, posted: posted.map((p) => p.body) });
""")
    assert got["after"] == {"a": None, "b": "waiting", "code": True, "providers": False,
                            "opened": ["stepup-modal"]}
    assert got["closed"] == {"a": None, "b": None}
    assert got["posted"] == [{"action": "vault.delete", "password_method": "idp_reauth"}]
