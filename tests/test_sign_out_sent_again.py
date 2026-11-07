"""A sign-out the server did not answer is sent again while the page lives (static/js/app.js: _endServerSession,
_sendSignOut, _signOutAgain, _retryAfterMs and the page's "online" listener), run under Node: the shipped functions
lifted out verbatim, a fetch whose answers each test chooses, and timers on a clock the test moves.

Held here: a call that did not reach the server is sent again as soon as the browser is back online; one refused
by the sign-out's rate limit (429) or a server error is sent again after the wait the server asks for (Retry-After,
in seconds or as a date, between one second and five minutes), or else after a wait that doubles from 15 seconds
to five minutes; an answer the server gave (the session ended, or a token it will not take) ends it; nothing is sent
again once the token has run out; and the browser coming back online while a call is on its way sends no second
one. tests/test_ui_sign_out_ends_session.py holds the same in a real browser, on a running stack (back online, and
after Retry-After).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """One top-level function of app.js, verbatim, up to its closing brace."""
    start = JS.index(f"\nfunction {name}(") + 1
    return JS[start:JS.index("\n}\n", start) + 3]


def _line(head: str) -> str:
    start = JS.index("\n" + head) + 1
    return JS[start:JS.index("\n", start) + 1]


def _block(head: str) -> str:
    """A top-level statement that starts with ``head``, up to its closing line."""
    start = JS.index("\n" + head) + 1
    return JS[start:JS.index("\n});\n", start) + 5]


SHIPPED = "".join(_line(f"const {name} =") for name in (
    "SIGN_OUT_WAIT_MS", "SIGN_OUT_RETRY_FIRST_MS", "SIGN_OUT_RETRY_MOST_MS", "_preferenceSaves", "_signOutsOwed",
)) + "".join(_fn(name) for name in (
    "_endServerSession", "_sendSignOut", "_signOutAgain", "_retryAfterMs", "_tokenClaims",
)) + _block("window.addEventListener('online',")

HARNESS = """
let now = 1700000000000;
const realNow = Date.now;
Date.now = () => now;
let timers = [];
const setTimeout = (fn, ms) => { const t = { at: now + ms, fn }; timers.push(t); return t; };
const clearTimeout = (t) => { timers = timers.filter((x) => x !== t); };
const listeners = {};
const window = { addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); } };
const API_BASE = '';
const _tellOtherTabsSignedOut = () => {};
const sent = [];
let answers = [];
const fetch = (url, init) => {
  sent.push({ at: now - START, url, auth: init.headers.Authorization, keepalive: init.keepalive });
  const a = answers.length ? answers.shift() : { status: 200 };
  if (a === 'offline') return Promise.reject(new TypeError('Failed to fetch'));
  if (a === 'pending') return new Promise(() => {});
  return Promise.resolve({ status: a.status, headers: { get: (k) => (k === 'Retry-After' ? (a.retryAfter ?? null) : null) } });
};
const START = now;
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/=+$/, '').replace(/\\+/g, '-').replace(/\\//g, '_');
const tokenFor = (claims) => b64({ alg: 'HS256' }) + '.' + b64(claims) + '.signature';
const settle = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
async function advance(ms) {
  const end = now + ms;
  for (;;) {
    timers.sort((a, b) => a.at - b.at);
    const t = timers[0];
    if (!t || t.at > end) break;
    timers.shift();
    now = t.at;
    t.fn();
    await settle();
  }
  now = end;
  await settle();
}
const online = async () => { (listeners.online || []).forEach((fn) => fn()); await settle(); };
const report = () => ({ sent: sent.map((s) => s.at), owed: _signOutsOwed.size, timers: timers.length });
"""


def _run(script: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=HARNESS + SHIPPED + "\n(async () => {\n" + script + "\n})();\n",
                          capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


TOKEN = "const token = tokenFor({ sub: 'u', session_token: 's', exp: Math.floor((now + 3600000) / 1000) });\n"


def test_a_sign_out_sent_while_offline_is_sent_again_when_the_browser_is_back_online():
    out = _run(TOKEN + """
answers = ['offline', { status: 200 }];
_endServerSession(token);
await settle();
const first = report();
await advance(4000);
await online();
const after = report();
await advance(600000);
console.log(JSON.stringify({ first, after, end: report(), auth: sent.map((s) => s.auth), kept: sent.every((s) => s.keepalive) }));
""")
    assert out["first"] == {"sent": [0], "owed": 1, "timers": 1}
    assert out["after"] == {"sent": [0, 4000], "owed": 0, "timers": 0}
    assert out["end"]["sent"] == [0, 4000]
    assert out["kept"] is True and set(out["auth"]) == {out["auth"][0]} and out["auth"][0].startswith("Bearer ")


@pytest.mark.parametrize("retry_after, wait", [("2", 2000), ("0", 1000), ("99999", 300000), ("soon", 15000),
                                               (None, 15000), ("date+3", 3000)])
def test_a_refused_sign_out_is_sent_again_after_the_wait_the_server_asks_for(retry_after, wait):
    value = "new Date(now + 3000).toUTCString()" if retry_after == "date+3" else json.dumps(retry_after)
    for status in (429, 503, 502, 408):
        out = _run(TOKEN + f"""
answers = [{{ status: {status}, retryAfter: {value} }}, {{ status: 200 }}];
_endServerSession(token);
await settle();
await advance(600000);
console.log(JSON.stringify(report()));
""")
        assert out == {"sent": [0, wait], "owed": 0, "timers": 0}, (status, retry_after, out)


def test_without_a_wait_asked_for_the_wait_doubles_from_15_seconds_to_5_minutes():
    out = _run(TOKEN + """
answers = Array(9).fill('offline');
_endServerSession(token);
await settle();
await advance(2000000);
console.log(JSON.stringify(report()));
""")
    gaps = [b - a for a, b in zip(out["sent"], out["sent"][1:])]
    assert gaps[:7] == [15000, 30000, 60000, 120000, 240000, 300000, 300000], gaps


@pytest.mark.parametrize("status", [200, 401, 400, 404])
def test_an_answer_the_server_gave_is_not_sent_again(status):
    out = _run(TOKEN + f"""
answers = [{{ status: {status} }}];
_endServerSession(token);
await settle();
await online();
await advance(600000);
console.log(JSON.stringify(report()));
""")
    assert out == {"sent": [0], "owed": 0, "timers": 0}


def test_nothing_is_sent_again_once_the_token_has_run_out():
    out = _run("""
const token = tokenFor({ sub: 'u', session_token: 's', exp: Math.floor((now + 20000) / 1000) });
answers = Array(9).fill('offline');
_endServerSession(token);
await settle();
await advance(600000);
await online();
console.log(JSON.stringify(report()));
""")
    # Tried at once, again after 15 s (before it ran out), and at 45 s (after): that failure is the last.
    assert out == {"sent": [0, 15000, 45000], "owed": 0, "timers": 0}


def test_the_browser_back_online_while_a_call_is_on_its_way_sends_no_second_one():
    out = _run(TOKEN + """
answers = ['pending'];
_endServerSession(token);
await settle();
await online();
await online();
console.log(JSON.stringify(report()));
""")
    assert out["sent"] == [0]
