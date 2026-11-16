"""How the session warning ends a session, offline (static/js/session-watch.js run in Node with small stand-ins).

"Stay signed in" refused with a 401 takes the token of another tab's renewal of the same person's full sign-in,
and nothing else: not another account's token signed in since in another tab, not the same person's new sign-in
since (a tab signed out and never told signs out; the same sign-in is told by the id every sign-in carries, else
by its time), not a temporary credential's (it carries its owner's id as sub). Refused with a 403, nothing is taken: the server's sentence is said. A renewal
that comes back after the tab signed out is ended on the server. A refusal of any request of the session signs
the tab out once: a second refusal neither signs out again nor writes over the first reason. A 401 says that the
session ran out only when it was ending anyway and the server did not say it ended the session itself. The
warning's own check at zero hands a refusal of the account to the same path, and gives up on an answer that
never comes rather than leave the count standing at zero.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

PRELUDE = r"""
const fs = require('fs');
const vm = require('vm');
const NOW = Math.floor(Date.now() / 1000);
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/=+$/, '')
    .replace(/\+/g, '-').replace(/\//g, '_');
// A token whose last 24 characters (what the page tells tokens apart by) carry its own name.
const token = (claims, name) => 'h.' + b64(claims) + '.' + name.padStart(40, '-');
const person = { sub: '7', username: 'ana', is_temporary: false, iat: NOW - 600, exp: NOW + 3000 };
const mine = token(person, 'mine');
const renewed = token({ ...person, iat: NOW, exp: NOW + 3600, auth_time: NOW - 600 }, 'renewed');
const store = new Map();
globalThis.window = globalThis;
globalThis.storage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)),
                       removeItem: (k) => store.delete(k) };
const els = {};
const listeners = {};
const elementFor = (id) => els[id] || (els[id] = {
    id, className: '', textContent: '', style: {}, disabled: false, attrs: {},
    setAttribute(k, v) { this.attrs[k] = v; },
    classList: { set: new Set(), add(c) { this.set.add(c); }, remove(c) { this.set.delete(c); },
                 contains(c) { return this.set.has(c); } },
    addEventListener(type, fn) { listeners[id + ':' + type] = fn; },
    querySelector: () => null,
});
globalThis.document = { getElementById: elementFor, addEventListener: () => {}, hidden: false };
const aborts = [];
const intervals = [];
// A check's give-up timer is kept to be fired by hand.
globalThis.setTimeout = (fn, ms) => { if (ms === 15000) aborts.push(fn); return 0; };
globalThis.clearTimeout = () => {};
globalThis.setInterval = (fn) => { intervals.push(fn); return 1; };
globalThis.clearInterval = () => {};
globalThis.API_BASE = '';
globalThis.authToken = mine;
store.set('authToken', mine);
let logouts = 0;
// The page's sign-out shows the reason it is given on the sign-in screen (and hands it to the page that replaces it).
globalThis.logout = (how, reason) => {
    logouts += 1;
    authToken = null;
    if (reason) elementFor('login-error').textContent = reason;
};
const toasts = [];
globalThis.showError = (m) => toasts.push(['error', m]);
globalThis.showSuccess = (m) => toasts.push(['success', m]);
globalThis._tellOtherTabsRenewed = () => {};
const sent = [];
const answer = (status, body) => ({ status, ok: status >= 200 && status < 300,
    headers: { get: () => null }, json: async () => body, text: async () => JSON.stringify(body) });
let route = () => Promise.reject(new Error('no answer set'));
globalThis.fetch = (url, opts) => {
    sent.push({ url, method: (opts && opts.method) || 'GET',
                bearer: ((opts && opts.headers) || {}).Authorization || '' });
    return route(url, opts);
};
vm.runInThisContext(fs.readFileSync('static/js/session-watch.js', 'utf8'), { filename: 'session-watch.js' });
const settle = async () => { for (let i = 0; i < 10; i += 1) await new Promise((r) => setImmediate(r)); };
const note = () => elementFor('login-error').textContent;
// Press "Stay signed in" on the open warning.
const stay = async () => {
    SessionWatch.armAt(Date.now() + 30000);
    SessionWatch.show();
    await listeners['session-stay:click']();
    await settle();
};
// The count reaches zero: the warning's own check.
const atZero = async () => {
    SessionWatch.armAt(Date.now() - 1000);
    intervals.length = 0;
    SessionWatch.show();
    intervals[intervals.length - 1]();
    await settle();
};
const out = (o) => console.log(JSON.stringify(o));
"""


def _node(body: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=PRELUDE + "(async () => {\n" + body + "\n})();", capture_output=True,
                          text=True, encoding="utf-8", timeout=60, cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


ENDED = "Your session has ended. Sign in again."
RAN_OUT = "Your session ended because nobody chose to stay signed in. Sign in again."


def test_a_401_takes_the_same_persons_renewed_sign_in():
    out = _node("""
store.set('authToken', renewed);
route = () => Promise.resolve(answer(401, { detail: 'Session has been terminated. Please login again.' }));
await stay();
out({ taken: authToken === renewed, logouts, note: note() });
""")
    assert out == {"taken": True, "logouts": 0, "note": ""}


@pytest.mark.parametrize("theirs", [
    "{ ...person, is_temporary: true, username: 'tmp-ana-1' }",     # a temporary credential: its owner's id as sub
    "{ ...person, is_temporary: true }",                              # the same name, and still temporary
    "{ ...person, username: 'ben' }",                                 # another name under the same id
    "{ ...person, sub: '8', username: 'ben' }",                       # another account signed in since
    "{ ...person, exp: NOW - 5 }",                                    # one that has run out
    "{ ...person, iat: NOW }",                                        # a new sign-in of the same person since
])
def test_a_401_takes_no_other_token_and_signs_out_saying_the_session_ended(theirs):
    out = _node(f"""
store.set('authToken', token({theirs}, 'theirs'));
route = () => Promise.resolve(answer(401, {{ detail: 'Session has been terminated. Please login again.' }}));
await stay();
out({{ held: authToken, logouts, note: note() }})
""")
    assert out == {"held": None, "logouts": 1, "note": ENDED}


# This tab's own token is already a renewal (its sign-in at NOW - 600, made at NOW - 60). Another tab renews the
# same sign-in again: taken. A token whose sign-in time is this token's own making time is another sign-in: not.
@pytest.mark.parametrize("theirs,taken", [
    ("{ ...person, iat: NOW, exp: NOW + 3600, auth_time: NOW - 600 }", True),
    ("{ ...person, iat: NOW, exp: NOW + 3600, auth_time: NOW - 60 }", False),
])
def test_a_tab_whose_token_is_a_renewal_takes_the_next_renewal_of_the_same_sign_in(theirs, taken):
    out = _node(f"""
const again = token({{ ...person, iat: NOW - 60, exp: NOW + 3000, auth_time: NOW - 600 }}, 'again');
const theirs = token({theirs}, 'theirs');
authToken = again;
store.set('authToken', theirs);
route = () => Promise.resolve(answer(401, {{ detail: 'Session has been terminated. Please login again.' }}));
await stay();
out({{ taken: authToken === theirs, logouts }});
""")
    assert out == {"taken": taken, "logouts": 0 if taken else 1}


# Sign-ins carry an id of their own, which every renewal keeps: the same sign-in is told by it, and only by it when
# either token carries one (two sign-ins may share a time: an identity provider's session, or the same second).
@pytest.mark.parametrize("mine_id,theirs_id,theirs_auth,taken", [
    ("'s-1'", "'s-1'", "NOW - 600", True),        # a renewal of this sign-in
    ("'s-1'", "'s-2'", "NOW - 600", False),       # another sign-in at the same time
    ("'s-1'", "undefined", "NOW - 600", False),   # a token without the id, at the same time
    ("undefined", "'s-2'", "NOW - 600", False),   # this tab's token from before the id; theirs a new sign-in
    ("undefined", "undefined", "NOW - 600", True),    # neither carries one: told by the time of the sign-in
])
def test_the_same_sign_in_is_told_by_its_id(mine_id, theirs_id, theirs_auth, taken):
    out = _node(f"""
const own = token({{ ...person, sign_in_id: {mine_id} }}, 'own');
const theirs = token({{ ...person, iat: NOW, exp: NOW + 3600, auth_time: {theirs_auth}, sign_in_id: {theirs_id} }}, 'theirs');
authToken = own;
store.set('authToken', theirs);
route = () => Promise.resolve(answer(401, {{ detail: 'Session has been terminated. Please login again.' }}));
await stay();
out({{ taken: authToken === theirs, logouts }});
""")
    assert out == {"taken": taken, "logouts": 0 if taken else 1}


def test_a_403_takes_nothing_and_says_the_servers_sentence():
    out = _node("""
store.set('authToken', renewed);
route = () => Promise.resolve(answer(403, { detail: 'This sign-in has reached its renewal limit. Sign in again.' }));
await stay();
out({ held: authToken, logouts, note: note() });
""")
    assert out == {"held": None, "logouts": 1, "note": "This sign-in has reached its renewal limit. Sign in again."}


def test_a_renewal_that_comes_back_after_the_sign_out_is_ended_on_the_server():
    out = _node("""
let release;
route = (url) => url.endsWith('/auth/session/extend')
    ? new Promise((r) => { release = () => r(answer(200, { access_token: renewed })); })
    : Promise.resolve(answer(200, {}));
SessionWatch.armAt(Date.now() + 30000);
SessionWatch.show();
const pressed = listeners['session-stay:click']();
authToken = null;                       // the person signs out while the answer is on its way
release();
await pressed; await settle();
const ended = sent.filter((s) => s.url.endsWith('/auth/sign-out'));
out({ held: authToken, ended: ended.map((s) => s.bearer === 'Bearer ' + renewed) });
""")
    assert out == {"held": None, "ended": [True]}


@pytest.mark.parametrize("detail,ending,said", [
    ("Invalid authentication credentials", True, RAN_OUT),        # the token ran out at the end of its count
    ("", True, RAN_OUT),
    ("Session has been terminated. Please login again.", True, ENDED),   # ended on the server in its last seconds
    ("User not found", True, ENDED),                             # the account deleted in its last seconds
    ("Invalid authentication credentials", False, ENDED),        # far from its end: it did not run out
])
def test_a_401_says_it_ran_out_only_when_it_was_ending_and_not_ended_on_the_server(detail, ending, said):
    out = _node(f"""
SessionWatch.armAt(Date.now() + ({'1000' if ending else '3600000'}));
const done = await SessionWatch.refusedSession(mine, 401, {json.dumps(detail)});
out({{ done, logouts, note: note() }});
""")
    assert out == {"done": True, "logouts": 1, "note": said}


def test_a_401_of_a_request_takes_the_same_persons_renewed_sign_in():
    out = _node("""
store.set('authToken', renewed);
SessionWatch.armAt(Date.now() + 1000);
const done = await SessionWatch.refusedSession(mine, 401, 'Session has been terminated. Please login again.');
out({ done, taken: authToken === renewed, logouts });
""")
    assert out == {"done": True, "taken": True, "logouts": 0}


def test_the_session_is_signed_out_once_and_the_first_reason_stays():
    out = _node("""
const first = await SessionWatch.refusedSession(mine, 403, 'User account is locked');
const second = await SessionWatch.refusedSession(mine, 401, 'Invalid authentication credentials');
out({ first, second, logouts, note: note() });
""")
    assert out == {"first": True, "second": False, "logouts": 1, "note": "User account is locked"}


def test_the_check_at_zero_signs_out_on_a_refusal_of_the_account():
    out = _node("""
route = () => Promise.resolve(answer(403, { detail: 'User account is locked' }));
await atZero();
out({ held: authToken, logouts, note: note(), armed: SessionWatch.remaining() });
""")
    assert out == {"held": None, "logouts": 1, "note": "User account is locked", "armed": 0}


def test_the_check_at_zero_takes_the_same_persons_renewed_sign_in():
    out = _node("""
store.set('authToken', renewed);
route = () => Promise.resolve(answer(401, { detail: 'Session has been terminated. Please login again.' }));
await atZero();
out({ taken: authToken === renewed, logouts });
""")
    assert out == {"taken": True, "logouts": 0}


def test_the_check_at_zero_gives_up_on_an_answer_that_never_comes():
    out = _node("""
route = (url, opts) => new Promise((_, refuse) => {
    if (opts && opts.signal) opts.signal.addEventListener('abort', () => refuse(new Error('given up')));
});
await atZero();
const before = aborts.length;
aborts.forEach((fire) => fire());
await settle();
out({ timers: before, held: authToken === mine, logouts, left: SessionWatch.remaining() });
""")
    assert out["timers"] >= 1 and out["held"] is True and out["logouts"] == 0
    assert 25 <= out["left"] <= 30, out


def test_a_refusal_while_this_tabs_renewal_is_on_its_way_waits_for_it():
    out = _node("""
let release;
route = (url) => url.endsWith('/auth/session/extend')
    ? new Promise((r) => { release = () => r(answer(200, { access_token: renewed })); })
    : Promise.resolve(answer(200, {}));
SessionWatch.armAt(Date.now() + 30000);
SessionWatch.show();
const pressed = listeners['session-stay:click']();
// The renewal has ended the old session on the server: a poll sent meanwhile is refused.
let decided = null;
const refused = SessionWatch.refusedSession(mine, 401, 'Session has been terminated. Please login again.')
    .then((v) => { decided = v; });
await settle();
const before = { decided, logouts };
release();
await pressed; await refused; await settle();
const ended = sent.filter((s) => s.url.endsWith('/auth/sign-out')).length;
out({ before, decided, held: authToken === renewed, logouts, ended });
""")
    assert out == {"before": {"decided": None, "logouts": 0}, "decided": True, "held": True, "logouts": 0,
                   "ended": 0}
