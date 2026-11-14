"""How the session warning ends a session, offline (static/js/session-watch.js run in Node with small stand-ins).

"Stay signed in" refused with a 401 takes the token of another tab's renewal of the same person's full sign-in,
and nothing else: not another account's token signed in since in another tab, not a temporary credential's (it
carries its owner's id as sub). Refused with a 403, nothing is taken: the server's sentence is said. A renewal
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
// The note is written 400 ms after a sign-out: at once here. A check's give-up timer is kept to be fired by hand.
globalThis.setTimeout = (fn, ms) => { if (ms === 400) fn(); else if (ms === 15000) aborts.push(fn); return 0; };
globalThis.clearTimeout = () => {};
globalThis.setInterval = (fn) => { intervals.push(fn); return 1; };
globalThis.clearInterval = () => {};
globalThis.API_BASE = '';
globalThis.authToken = mine;
store.set('authToken', mine);
let logouts = 0;
globalThis.logout = () => { logouts += 1; authToken = null; };
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
])
def test_a_401_takes_no_other_token_and_signs_out_saying_the_session_ended(theirs):
    out = _node(f"""
store.set('authToken', token({theirs}, 'theirs'));
route = () => Promise.resolve(answer(401, {{ detail: 'Session has been terminated. Please login again.' }}));
await stay();
out({{ held: authToken, logouts, note: note() }})
""")
    assert out == {"held": None, "logouts": 1, "note": ENDED}


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
const done = SessionWatch.refusedSession(mine, 401, {json.dumps(detail)});
out({{ done, logouts, note: note() }});
""")
    assert out == {"done": True, "logouts": 1, "note": said}


def test_a_401_of_a_request_takes_the_same_persons_renewed_sign_in():
    out = _node("""
store.set('authToken', renewed);
SessionWatch.armAt(Date.now() + 1000);
const done = SessionWatch.refusedSession(mine, 401, 'Session has been terminated. Please login again.');
out({ done, taken: authToken === renewed, logouts });
""")
    assert out == {"done": True, "taken": True, "logouts": 0}


def test_the_session_is_signed_out_once_and_the_first_reason_stays():
    out = _node("""
const first = SessionWatch.refusedSession(mine, 403, 'User account is locked');
const second = SessionWatch.refusedSession(mine, 401, 'Invalid authentication credentials');
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
