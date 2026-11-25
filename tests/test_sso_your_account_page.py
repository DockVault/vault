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
