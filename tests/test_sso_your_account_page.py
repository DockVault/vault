"""The single sign-on part of Your account (static/js/sso.js, renderAccount and the unlink after a confirmation at
the provider): what it draws from GET /users/me/identities, which buttons it offers and what it says in their place,
the confirmations it asks before an unlink, and what it does with the unlink's answer.

Driven in Node against the shipped module, on the small document of tests/js/mini_dom.js, with the server's answers
stood in for (the server's side has its own tests: tests/test_sso_identities_list.py). Offline."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "static" / "js" / "sso.js"

PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const section = document.createElement('div'); section.id = 'us-identities-section'; document.body.appendChild(section);
const bodyEl = document.createElement('div'); bodyEl.id = 'us-identities-body'; section.appendChild(bodyEl);
const store = {};
global.sessionStorage = {
    getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; },
};
const left = [];
global.location = { hash: '', pathname: '/', search: '', assign: (u) => { left.push(u); }, replace: (u) => { left.push(u); } };
global.history = { replaceState: () => {} };
global.API_BASE = '/api';
// The page's clock, frozen: a date the list gives is before or after it whatever day the test runs on.
const NOW = Date.parse('2026-11-20T10:00:00Z');
Date.now = () => NOW;
const asked = [], confirms = [], successes = [], errors = [], logouts = [];
let answers = {};                      // 'METHOD path' -> what apiRequest answers (an Error is thrown; a function is called)
let confirmAnswers = [];               // what the person answers each confirmation, in turn; yes once they run out
global.apiRequest = async (path, options) => {
    const method = (options || {}).method || 'GET';
    asked.push(method + ' ' + path);
    const key = method + ' ' + path;
    let answer = Object.prototype.hasOwnProperty.call(answers, key) ? answers[key] : new Error('Not arranged: ' + key);
    if (typeof answer === 'function') answer = answer();
    if (answer instanceof Error) throw answer;
    return answer;
};
global.showConfirm = async (message, title, input, label) => {
    confirms.push({ message, title, label });
    return confirmAnswers.length ? confirmAnswers.shift() : true;
};
global.showSuccess = (m) => { successes.push(m); };
global.showError = (m) => { errors.push(m); };
global.logout = (how, reason) => { logouts.push({ how: how === undefined ? null : how, reason: reason }); };
global._el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const settle = async () => { for (let i = 0; i < 20; i += 1) await tick(); };
const refused = (status, reason, message) => Object.assign(new Error(message), { status, reason });
const page = () => ({
    rows: document.querySelectorAll('.identity-row').map((row) => ({
        id: row.dataset.identityId,
        text: row.textContent,
        unlink: row.querySelectorAll('button').map((b) => b.textContent),
        refused: row.querySelectorAll('.identity-unlink-refused').map((e) => [e.textContent, e.dataset.reason]),
    })),
    links: document.querySelectorAll('.identity-link').map((b) => b.textContent),
    linkRefused: document.querySelectorAll('.identity-link-refused').map((e) => e.textContent),
    shown: section.style.display !== 'none',
    text: bodyEl.textContent,
});
const button = (text) => document.querySelectorAll('button').find((b) => b.textContent === text);
const out = (value) => console.log(JSON.stringify(value));
const LIST = '/users/me/identities';
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (PRELUDE + MODULE.read_text(encoding="utf-8") + "\n(async () => {\n" + scenario
              + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


PRIVILEGED = ("An administrator's or auditor's account keeps a local password, so it cannot be linked to a provider "
              "whose people sign in without one.")


def test_a_provider_the_server_says_cannot_be_linked_gets_its_sentence_and_no_link_button():
    """An administrator and a provider whose people hold no password: the page says why in place of the Link
    button, so nobody is told that their password stops or is sent to the provider for a link that is refused."""
    got = _node(r"""
answers['GET ' + LIST] = { identities: [], email: null, providers: [
    { id: 'p-none', label: 'No password', icon: 'generic', linked: false, ends_password: false, reauth: false,
      link_refusal: { reason: 'privileged_on_password_less', message: 'PRIVILEGED' } },
    { id: 'p-keeps', label: 'Keeps', icon: 'generic', linked: false, ends_password: false, reauth: false,
      link_refusal: null }] };
answers['POST /users/me/identities/p-keeps/start'] = { authorization_url: 'https://idp.example.test/authorize' };
await window.Sso.renderAccount();
const drawn = page();
button('Link Keeps').click();
await settle();
out({ drawn, confirms, asked, left });
""".replace("PRIVILEGED", PRIVILEGED.replace("'", "\\'")))
    drawn = got["drawn"]
    assert drawn["shown"] is True
    assert drawn["links"] == ["Link Keeps"]
    assert drawn["linkRefused"] == ["No password: " + PRIVILEGED]
    assert "stop working" not in drawn["text"]
    # The provider that can be linked starts as before, with no question about a password.
    assert got["confirms"] == []
    assert "POST /users/me/identities/p-keeps/start" in got["asked"]
    assert not [a for a in got["asked"] if "p-none" in a]
    assert got["left"] == ["https://idp.example.test/authorize"]


NO_PASSWORD = ("Your account has no password of its own, so another provider cannot be linked to it from here. Ask an "
               "administrator.")


def test_an_account_that_cannot_link_from_this_session_is_told_why_and_not_sent_to_link_instead_of_a_code():
    """Where no provider can be linked from here, the box about the email address does not tell the person to link
    their organisation's sign-in above instead; where one can, it does."""
    got = _node(r"""
const email = { address: 'alice@example.test', can_send_code: false, factor_here: true };
answers['GET ' + LIST] = { identities: [], email, providers: [
    { id: 'p-1', label: 'Contoso', icon: 'generic', linked: false, ends_password: false, reauth: false,
      link_refusal: { reason: 'no_password', message: 'NO_PASSWORD' } }] };
await window.Sso.renderAccount();
const refusedOnly = page();
answers['GET ' + LIST].providers.push({ id: 'p-2', label: 'Fabrikam', icon: 'generic', linked: false,
    ends_password: false, reauth: false, link_refusal: null });
await window.Sso.renderAccount();
out({ refusedOnly, oneLinkable: page() });
""".replace("NO_PASSWORD", NO_PASSWORD))
    refused_only, one = got["refusedOnly"], got["oneLinkable"]
    assert refused_only["links"] == []
    assert refused_only["linkRefused"] == ["Contoso: " + NO_PASSWORD]
    assert "This vault sends no email" in refused_only["text"]
    assert "Link your organisation's sign-in above instead" not in refused_only["text"]
    assert one["links"] == ["Link Fabrikam"] and one["linkRefused"] == ["Contoso: " + NO_PASSWORD]
    assert "Link your organisation's sign-in above instead" in one["text"]


def _identity(**extra):
    fields = {"id": "i-1", "provider_id": "p-1", "provider": "Contoso", "email": None, "display_name": None,
              "linked_at": "2026-10-01T10:00:00Z", "linked_by": "self", "last_sign_in_at": "2026-11-19T10:00:00Z",
              "unlink_asks_provider": False, "provider_can_confirm": True, "unlink_refusal": None,
              "this_session": False, "restores_password": False, "due_at": None}
    fields.update(extra)
    return fields


def _list(*identities):
    return json.dumps({"identities": list(identities), "providers": [], "email": None})


SIGNED_OUT_HERE = ("You signed in this time through Contoso, so unlinking it also signs you out here and wherever you "
                   "signed in through it.")
SIGNED_OUT = ("You unlinked Contoso, which this session came through, so you were signed out. Sign in again another "
              "way.")


def test_unlinking_the_provider_this_session_came_through_says_so_first_and_signs_out_with_a_sentence():
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
answers['DELETE /users/me/identities/i-1'] = { removed: true, sessions_ended: 1, ended_this_session: true };
await window.Sso.renderAccount();
button('Unlink').click();
await settle();
out({ confirms, logouts, successes, asked });
""".replace("LISTED", _list(_identity(this_session=True))))
    assert len(got["confirms"]) == 1 and got["confirms"][0]["message"].endswith(SIGNED_OUT_HERE), got["confirms"]
    assert got["logouts"] == [{"how": None, "reason": SIGNED_OUT}]
    assert got["successes"] == []
    # The list is not read again: its answer would be the 401 of a session that has ended.
    assert got["asked"] == ["GET /users/me/identities", "DELETE /users/me/identities/i-1"]


def test_an_identity_this_session_did_not_come_through_is_unlinked_as_before():
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
answers['DELETE /users/me/identities/i-1'] = { removed: true, sessions_ended: 0, ended_this_session: false };
await window.Sso.renderAccount();
button('Unlink').click();
await settle();
out({ confirms, logouts, successes, asked });
""".replace("LISTED", _list(_identity())))
    assert got["confirms"][0]["message"] == "Unlink Contoso? You will no longer sign in through it."
    assert got["logouts"] == [] and got["successes"] == ["Unlinked."]
    assert got["asked"] == ["GET /users/me/identities", "DELETE /users/me/identities/i-1", "GET /users/me/identities"]


def test_an_unlink_confirmed_at_the_provider_names_it_and_signs_out_when_it_ended_this_session():
    """The provider confirms the unlink with a fresh sign-in there: the page leaves for it with the provider's name
    kept for its return, and the unlink done on the return signs out with the same sentence."""
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
answers['POST /users/me/identities/p-1/reauth'] = { authorization_url: 'https://idp.example.test/authorize' };
await window.Sso.renderAccount();
button('Unlink').click();
await settle();
const flow = JSON.parse(store.dv_sso_flow);
answers['DELETE /users/me/identities/i-1'] = { removed: true, sessions_ended: 2, ended_this_session: true };
asked.length = 0;
await window.Sso.unlinkConfirmed('i-1', flow.label);
await settle();
out({ confirms, logouts, asked, flow: { label: flow.label, then: flow.then }, left });
""".replace("LISTED", _list(_identity(this_session=True, unlink_asks_provider=True))))
    assert got["confirms"][0]["message"].endswith(SIGNED_OUT_HERE), got["confirms"]
    assert got["flow"] == {"label": "Contoso", "then": "unlink:i-1"}
    assert got["left"] == ["https://idp.example.test/authorize"]
    assert got["logouts"] == [{"how": None, "reason": SIGNED_OUT}]
    assert got["asked"] == ["DELETE /users/me/identities/i-1"]


def test_the_page_back_from_the_provider_hands_the_providers_name_to_the_unlink():
    source = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert "await Sso.unlinkConfirmed(out.then.slice('unlink:'.length), out.label);" in source


MAY_HOLD_A_PASSWORD = (' Your account may then hold a password again, but has none yet: ask an administrator for a reset '
                       'link, or use "Forgot your password?" on the sign-in page where it is shown.')
UNLINKED_PASSWORD_BACK = ('Unlinked. Your account may hold a password again and has none yet: ask an administrator for a '
                          'reset link, or use "Forgot your password?" on the sign-in page where it is shown.')


def test_an_unlink_that_gives_the_account_its_password_back_says_so_before_and_after():
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
answers['DELETE /users/me/identities/i-1'] = { removed: true, sessions_ended: 0, may_set_password: true,
                                               ended_this_session: false };
await window.Sso.renderAccount();
button('Unlink').click();
await settle();
const direct = { confirms: confirms.slice(), successes: successes.slice() };
confirms.length = 0; successes.length = 0;
await window.Sso.unlinkConfirmed('i-1', 'Contoso');
await settle();
out({ direct, confirmed: { successes }, logouts });
""".replace("LISTED", _list(_identity(restores_password=True))))
    assert got["direct"]["confirms"][0]["message"] == ("Unlink Contoso? You will no longer sign in through it."
                                                       + MAY_HOLD_A_PASSWORD)
    assert got["direct"]["successes"] == [UNLINKED_PASSWORD_BACK]
    assert got["confirmed"]["successes"] == [UNLINKED_PASSWORD_BACK]
    assert got["logouts"] == []


def test_an_unlink_confirmed_at_the_provider_that_gives_the_password_back_says_so_before_it_leaves():
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
answers['POST /users/me/identities/p-1/reauth'] = { authorization_url: 'https://idp.example.test/authorize' };
await window.Sso.renderAccount();
button('Unlink').click();
await settle();
out({ confirms });
""".replace("LISTED", _list(_identity(restores_password=True, unlink_asks_provider=True))))
    assert got["confirms"][0]["message"].endswith("asks you to sign in there once more first." + MAY_HOLD_A_PASSWORD)


def test_each_identity_says_who_it_is_at_the_provider_and_one_whose_unlink_is_refused_says_why_instead():
    """Who stands on the account at the provider (the name and the address it gave when it was linked) is shown, so a
    wrong one shows. Where the unlink would be refused whatever the provider says, its sentence is shown in place of
    the button, so nobody is sent to the provider for an unlink refused on their return."""
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
await window.Sso.renderAccount();
out({ page: page(), asked });
""".replace("LISTED", _list(
        _identity(display_name="Alice Corp", email="alice@corp.example"),
        _identity(id="i-2", provider_id="p-2", provider="Fabrikam", unlink_asks_provider=True,
                  unlink_refusal={"reason": "no_way_in_left", "message": "X"}))))
    first, second = got["page"]["rows"]
    assert "as Alice Corp, alice@corp.example · Linked " in first["text"]
    assert first["unlink"] == ["Unlink"] and first["refused"] == []
    assert second["unlink"] == [] and second["refused"] == [["X", "no_way_in_left"]]
    assert "as " not in second["text"].split("Linked")[0]                 # no name, no address: nothing said
    assert got["asked"] == ["GET /users/me/identities"]
    assert not [a for a in got["asked"] if a.endswith("/reauth")]


def test_an_identity_with_only_an_address_or_only_a_name_says_that_one():
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
await window.Sso.renderAccount();
out(page());
""".replace("LISTED", _list(_identity(email="alice@corp.example"),
                            _identity(id="i-2", provider_id="p-2", provider="Fabrikam", display_name="Alice Corp"))))
    first, second = got["rows"]
    assert "as alice@corp.example · Linked " in first["text"]
    assert "as Alice Corp · Linked " in second["text"]


def test_an_identity_with_a_sign_in_due_says_by_when_and_one_whose_day_has_passed_says_so():
    """The notices that a sign-in through a provider is due open Your account: the row says by when, or that the day
    has passed and what to do."""
    got = _node(r"""
answers['GET ' + LIST] = LISTED;
await window.Sso.renderAccount();
out(page());
""".replace("LISTED", _list(
        _identity(due_at="2026-12-01T09:30:00Z"),
        _identity(id="i-2", provider_id="p-2", provider="Fabrikam", due_at="2026-11-01T09:30:00Z"),
        _identity(id="i-3", provider_id="p-3", provider="Northwind"))))
    due, passed, none = got["rows"]
    assert due["text"].endswith("last signed in Nov 19, 2026 · sign in through it by Dec 1, 2026Unlink"), due
    assert "its time ran out on Nov 1, 2026: sign out and sign in through it" in passed["text"]
    assert "sign in through it by" not in passed["text"]
    assert "sign in through it by" not in none["text"] and "ran out" not in none["text"]
