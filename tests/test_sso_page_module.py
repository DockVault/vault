"""The page's single sign-on module (static/js/sso.js), run by Node against stand-ins for the browser: what it
takes from the address when a provider sends the browser back, the proof it keeps for the tab and forgets, the
addresses it will follow, the sentence it shows for a reason, and what a signed-in page claims. Offline."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r"""
const { webcrypto } = require('crypto');
const store = {};
const left = [];
const asked = [];
const replaced = [];
let answers = {};                                    // path -> what apiRequest answers (an Error is thrown)
let fetched = {};                                    // url -> {ok, json}
global.sessionStorage = {
    getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; },
};
global.location = { hash: '', pathname: '/', search: '', assign: (u) => { left.push(u); } };
global.history = { replaceState: (s, t, url) => { replaced.push(url); global.location.hash = ''; } };
global.window = { crypto: webcrypto, location: global.location };
global.crypto = webcrypto;
global.document = { getElementById: () => null };
global.API_BASE = '/api';
global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET', body: (options || {}).body ? JSON.parse(options.body) : null });
    const answer = answers[path];
    if (answer instanceof Error) throw answer;
    return answer;
};
global.fetch = async (url, options) => {
    asked.push({ path: url, method: (options || {}).method || 'GET', body: (options || {}).body ? JSON.parse(options.body) : null });
    const answer = fetched[url] || { ok: false, json: {} };
    return { ok: answer.ok, json: async () => answer.json };
};
const sha = async (text) => Buffer.from(await webcrypto.subtle.digest('SHA-256', Buffer.from(text))).toString('hex');
const flow = () => (store.dv_sso_flow ? JSON.parse(store.dv_sso_flow) : null);
const arrive = (hash) => { global.location.hash = hash; return window.Sso.takeReturn(); };
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(body: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    module = (ROOT / "static" / "js" / "sso.js").read_text(encoding="utf-8")
    script = PRELUDE + module + "\n(async () => {\n" + body + "\n})().catch((e) => { console.error(e); process.exit(1); });\n"
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_only_a_fragment_of_single_sign_on_is_taken_and_it_leaves_the_address_at_once():
    got = _node(r"""
const seen = [];
for (const hash of ['#sso=abc-DEF_1.2~3', '#sso-error=no_account', '#sso-linked=c1', '#sso-test=c2', '#sso-stepup=c3',
                    '#sso=code&return_to=profile', '', '#profile', '#activity?q=sso=1', '#sso=', '#sso=a b',
                    '#sso=<script>', '#sso-other=x', '#xsso=abc', '#a#sso=abc', '#sso=abc&return_to=../evil', '#sso=abc&x=1',
                    '#sso=' + 'a'.repeat(201)]) {
    replaced.length = 0;
    const back = arrive(hash);
    seen.push([hash.slice(0, 30), back && back.kind, back && back.value.slice(0, 20), back && back.returnTo, replaced.slice()]);
}
out(seen);
""")
    assert got[:6] == [
        ["#sso=abc-DEF_1.2~3", "sso", "abc-DEF_1.2~3", "", ["/"]],
        ["#sso-error=no_account", "sso-error", "no_account", "", ["/"]],
        ["#sso-linked=c1", "sso-linked", "c1", "", ["/"]],
        ["#sso-test=c2", "sso-test", "c2", "", ["/"]],
        ["#sso-stepup=c3", "sso-stepup", "c3", "", ["/"]],
        ["#sso=code&return_to=profile", "sso", "code", "profile", ["/"]],
    ]
    # Anything else is not single sign-on's: left in the address for whoever it belongs to, and nothing is read.
    assert all(row[1:] == [None, None, None, []] for row in got[6:]), got[6:]


def test_the_tabs_proof_is_made_kept_for_the_tab_and_forgotten_when_the_page_comes_back():
    got = _node(r"""
fetched['/api/auth/sso/p-1/start'] = { ok: true, json: { authorization_url: 'https://idp.example.org/auth?x=1' } };
await window.Sso.startSignIn('p-1', { returnTo: 'profile' });
const kept = flow();
const sent = asked[0].body;
const back = arrive('#sso=the-code');
out({ kept: { purpose: kept.purpose, provider: kept.provider, length: kept.verifier.length,
              shape: /^[A-Za-z0-9_-]+$/.test(kept.verifier), fresh: Date.now() - kept.at < 5000 },
      sent, hashOf: await sha(kept.verifier), left, after: flow(),
      back: { kind: back.kind, same: back.flow.verifier === kept.verifier, purpose: back.flow.purpose },
      again: arrive('#sso=the-code').flow });
""")
    assert got["kept"] == {"purpose": "sign_in", "provider": "p-1", "length": 43, "shape": True, "fresh": True}
    assert got["sent"] == {"verifier_hash": got["hashOf"], "return_to": "profile"} and len(got["hashOf"]) == 64
    assert got["left"] == ["https://idp.example.org/auth?x=1"]
    assert got["after"] is None                       # forgotten the moment the page came back
    assert got["back"] == {"kind": "sso", "same": True, "purpose": "sign_in"}
    assert got["again"] is None                       # read once: a second arrival finds no proof


def test_a_proof_is_new_every_time_and_a_stale_or_broken_one_is_not_used():
    got = _node(r"""
fetched['/api/auth/sso/p-1/start'] = { ok: true, json: { authorization_url: 'https://idp.example.org/auth' } };
await window.Sso.startSignIn('p-1');
const first = flow().verifier;
await window.Sso.startSignIn('p-1');
const second = flow().verifier;
const stale = Object.assign(flow(), { at: Date.now() - 16 * 60 * 1000 });
store.dv_sso_flow = JSON.stringify(stale);
const old = arrive('#sso=c').flow;
const leftovers = [];
for (const raw of ['not json', '[]', '{}', '{"purpose":"sign_in"}', '{"verifier":5,"purpose":"sign_in","at":1}',
                   JSON.stringify({ verifier: 'v', purpose: 'sign_in' }),
                   JSON.stringify({ verifier: 5, purpose: 'sign_in', at: Date.now() }),
                   JSON.stringify({ verifier: 'v', purpose: 7, at: Date.now() }), 'null']) {
    store.dv_sso_flow = raw;
    leftovers.push([arrive('#sso=c').flow, flow()]);
}
out({ differ: first !== second, old, leftovers });
""")
    assert got == {"differ": True, "old": None, "leftovers": [[None, None]] * 9}


def test_an_address_is_followed_only_when_it_is_https_or_on_this_computer():
    got = _node(r"""
const tried = [];
for (const url of ['https://idp.example.org/a', 'http://localhost:8200/x', 'http://127.0.0.1:9/x', 'http://[::1]:9/x',
                   'http://idp.example.org/a', 'javascript:alert(1)', 'data:text/html,x', '//idp.example.org/a',
                   '/relative', '', null, 'ftp://idp.example.org/a', 'https://']) {
    fetched['/api/auth/sso/p-1/start'] = { ok: true, json: { authorization_url: url } };
    left.length = 0;
    let said = '';
    try { await window.Sso.startSignIn('p-1'); } catch (e) { said = e.message; }
    tried.push([String(url), left.slice(), said, flow() === null]);
}
out(tried);
""")
    for url, left, said, forgotten in got[:4]:
        assert len(left) == 1 and left[0].startswith(url[:12]) and said == "" and not forgotten, url
    for url, left, said, forgotten in got[4:]:
        assert left == [] and said and forgotten, url          # nothing opened, the proof not left behind


def test_a_start_the_server_refuses_says_the_servers_sentence_and_leaves_no_proof():
    got = _node(r"""
const said = [];
for (const json of [{ detail: { reason: 'no_public_address', message: 'Single sign-on needs the vault\'s public address.' } },
                    { detail: 'Too many sign-in starts. Try again later.' }, {}, null]) {
    fetched['/api/auth/sso/p-1/start'] = { ok: false, json };
    try { await window.Sso.startSignIn('p-1', { invitation: 'inv-token' }); } catch (e) { said.push([e.message, flow()]); }
}
out({ said, body: asked[0].body.invitation, left });
""")
    assert got["said"] == [
        ["Single sign-on needs the vault's public address.", None],
        ["Too many sign-in starts. Try again later.", None],
        ["This sign-in could not be started. Try again in a moment.", None],
        ["This sign-in could not be started. Try again in a moment.", None]]
    assert got["body"] == "inv-token" and got["left"] == []


def test_a_reason_is_said_in_the_servers_words_and_an_unknown_one_in_general_words():
    got = _node(r"""
fetched['/api/auth/sso/reasons'] = { ok: true, json: { reasons: { no_account: 'No account is linked to this sign-in.', empty: '' } } };
const texts = [];
for (const code of ['no_account', 'made_up', 'empty', 'constructor', '__proto__', 'toString'])
    texts.push(await window.Sso.reasonText(code));
const asks = asked.filter((a) => a.path === '/api/auth/sso/reasons').length;
out({ texts, asks });
""")
    general = "Single sign-on did not finish. Try again."
    assert got == {"texts": ["No account is linked to this sign-in.", general, general, general, general, general],
                   "asks": 1}
    # The list could not be read: the general sentence, and the next reason asks again.
    got = _node(r"""
const first = await window.Sso.reasonText('no_account');
fetched['/api/auth/sso/reasons'] = { ok: true, json: { reasons: { no_account: 'No account.' } } };
out([first, await window.Sso.reasonText('no_account')]);
""")
    assert got == [general, "No account."]


def test_a_signed_in_page_claims_what_came_back_with_the_tabs_proof():
    got = _node(r"""
const results = [];
async function round(start, hash, path, answer) {
    asked.length = 0;
    left.length = 0;
    await start();
    const verifier = flow().verifier;
    answers[path] = answer;
    const back = arrive(hash);
    const result = await window.Sso.resume(back);
    const claim = asked[asked.length - 1];
    results.push({ result, started: asked[0], claimPath: claim.path, code: claim.body.code,
                   withProof: claim.body.verifier === verifier, hashSent: asked[0].body.verifier_hash === await sha(verifier) });
}
answers['/users/me/identities/p-1/start'] = { authorization_url: 'https://idp.example.org/a' };
await round(() => window.Sso.startLink('p-1'), '#sso-linked=c-link', '/users/me/identities/finish', { linked: true });
answers['/admin/sso/providers/p-1/test/start'] = { authorization_url: 'https://idp.example.org/a' };
await round(() => window.Sso.startTest('p-1'), '#sso-test=c-test', '/admin/sso/providers/p-1/test/finish',
            { tested: true, summary: { outcome: 'ok' } });
answers['/users/me/identities/p-1/reauth'] = { authorization_url: 'https://idp.example.org/a' };
await round(() => window.Sso.startConfirm('p-1', 'account.second_factor', 'add-passkey'), '#sso-stepup=c-up',
            '/users/me/identities/reauth/finish', { staged: true, action: 'account.second_factor' });
await round(() => window.Sso.startLink('p-1'), '#sso-linked=c-ends', '/users/me/identities/finish',
            { linked: true, password_stopped: true });
out(results);
""")
    link, test, confirm, ends = got
    assert link["result"] == {"kind": "linked", "passwordStopped": False} and link["claimPath"] == "/users/me/identities/finish"
    # A link that ended the account's password says so, for the page to tell the person.
    assert ends["result"] == {"kind": "linked", "passwordStopped": True}
    assert link["started"]["path"] == "/users/me/identities/p-1/start" and link["started"]["method"] == "POST"
    assert test["result"] == {"kind": "tested", "provider": "p-1", "summary": {"outcome": "ok"}}
    assert test["claimPath"] == "/admin/sso/providers/p-1/test/finish"
    assert confirm["result"] == {"kind": "confirmed", "action": "account.second_factor", "then": "add-passkey"}
    assert confirm["started"]["body"]["action"] == "account.second_factor"
    for one, code in ((link, "c-link"), (test, "c-test"), (confirm, "c-up")):
        assert one["code"] == code and one["withProof"] is True and one["hashSent"] is True


def test_what_came_back_to_another_tab_or_for_another_purpose_is_not_claimed():
    got = _node(r"""
const results = [];
// No flow in this tab at all.
results.push(await window.Sso.resume(arrive('#sso-linked=c1')));
// A flow of another purpose: a sign-in's proof never claims a link, a link's never a test.
fetched['/api/auth/sso/p-1/start'] = { ok: true, json: { authorization_url: 'https://idp.example.org/a' } };
await window.Sso.startSignIn('p-1');
results.push(await window.Sso.resume(arrive('#sso-linked=c1')));
answers['/users/me/identities/p-1/start'] = { authorization_url: 'https://idp.example.org/a' };
await window.Sso.startLink('p-1');
results.push(await window.Sso.resume(arrive('#sso-test=c1')));
// A sign-in's code on a page that is signed in: nothing is done with it.
await window.Sso.startSignIn('p-1');
results.push(await window.Sso.resume(arrive('#sso=c1')));
results.push(await window.Sso.resume(null));
// A refusal: its sentence.
fetched['/api/auth/sso/reasons'] = { ok: true, json: { reasons: { already_linked: 'That identity is linked to another account.' } } };
results.push(await window.Sso.resume(arrive('#sso-error=already_linked')));
// The claim itself refused: the server's sentence.
await window.Sso.startLink('p-1');
answers['/users/me/identities/finish'] = new Error('This did not come back to the tab and session that started it. Start again.');
results.push(await window.Sso.resume(arrive('#sso-linked=c1')));
out({ results, claims: asked.filter((a) => /finish$/.test(a.path)).length });
""")
    wrong_tab = {"kind": "error", "message": "That did not come back to the tab that started it. Start again."}
    assert got["results"] == [
        wrong_tab, wrong_tab, wrong_tab, None, None,
        {"kind": "error", "message": "That identity is linked to another account."},
        {"kind": "error", "message": "This did not come back to the tab and session that started it. Start again."}]
    assert got["claims"] == 1                          # only the last one reached the server


def test_a_start_that_fails_for_a_signed_in_person_leaves_no_proof_behind():
    got = _node(r"""
const said = [];
answers['/users/me/identities/p-1/start'] = new Error('Sign in with your password before adding a sign-in method.');
try { await window.Sso.startLink('p-1'); } catch (e) { said.push([e.message, flow()]); }
answers['/users/me/identities/p-1/start'] = {};
try { await window.Sso.startLink('p-1'); } catch (e) { said.push([e.message, flow()]); }
out({ said, left });
""")
    assert got == {"said": [["Sign in with your password before adding a sign-in method.", None],
                            ["This could not be started. Try again in a moment.", None]], "left": []}


def test_without_a_secure_page_nothing_is_started():
    got = _node(r"""
global.window.crypto = undefined;
const before = window.Sso.available();
let said = '';
try { await window.Sso.startSignIn('p-1'); } catch (e) { said = e.message; }
out({ before, said, asked: asked.length, flow: flow() });
""")
    assert got == {"before": False, "said": "Single sign-on needs a secure page (https).", "asked": 0, "flow": None}


def test_after_a_sign_out_only_an_address_the_page_would_open_is_followed():
    """The provider logout a sign-out answer names: https anywhere, http on this computer, and nothing else. The page
    is replaced (Back does not return to the page that showed the app); for any other address the caller stays."""
    got = _node(r"""
const went = [];
global.location.replace = (u) => { went.push(u); };
const tried = ['https://idp.example.org/logout?id_token_hint=x', 'http://localhost:8080/logout', 'http://127.0.0.1/o',
               'http://idp.example.org/logout', 'javascript:alert(1)', 'data:text/html,x', 'not an address', '', null,
               'ftp://idp.example.org/x', '//idp.example.org/logout'];
const said = tried.map((address) => window.Sso.leaveToSignOut(address));
out({ said, went, assigned: left });
""")
    assert got["said"] == [True, True, True, False, False, False, False, False, False, False, False]
    assert got["went"] == ["https://idp.example.org/logout?id_token_hint=x", "http://localhost:8080/logout",
                           "http://127.0.0.1/o"]
    assert got["assigned"] == []            # replaced, never added to the history


def test_no_text_of_the_pages_or_the_server_is_garbled():
    """Text saved once in another encoding and again as UTF-8 shows as two wrong characters where one was meant (a
    multiplication sign as a close button, a warning sign in a log line). None of those pairs is in any page, script,
    style sheet or server module."""
    marks = ("Ã—", "Ã\u0097", "â€", "âš", "Â ")
    found = []
    for base, patterns in (("static", ("*.html", "*.js", "*.css")), ("app", ("*.py",))):
        for pattern in patterns:
            for path in sorted((ROOT / base).rglob(pattern)):
                text = path.read_text(encoding="utf-8", errors="replace")
                found += [(path.relative_to(ROOT).as_posix(), mark.encode("unicode_escape").decode()) for mark in marks
                          if mark in text]
    assert found == [], found
