"""When the web app's live socket tries again, run as shipped.

The socket's section of ``static/js/app.js`` (from ``let appSocket = null;`` to the end of ``ensureAppSocket``) is
lifted verbatim and run under Node with a stand-in WebSocket and recorded timers. A socket the server refused for
too many connections (close code 4429) tries again after a minute and nothing opens it sooner; any other close tries
again after five seconds; signing out, or a direct connect, clears the wait. The server's side is in
tests/test_monitor_feed.py and, live, tests/test_api_websocket.py.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _section() -> str:
    start = APP.index("let appSocket = null;")
    head = APP.index("function ensureAppSocket() {", start)
    return APP[start:APP.index("\n}\n", head) + 3]


HARNESS = r"""
const timers = [];
let nextTimer = 1;
global.setTimeout = (fn, ms) => { const t = { id: nextTimer++, fn, ms, live: true }; timers.push(t); return t.id; };
global.clearTimeout = (id) => { for (const t of timers) if (t.id === id) t.live = false; };
const sockets = [];
class FakeSocket {
    constructor(url) { this.url = url; this.readyState = FakeSocket.CONNECTING; this.sent = []; sockets.push(this); }
    send(data) { this.sent.push(data); }
    close() { this.readyState = FakeSocket.CLOSED; }
}
FakeSocket.CONNECTING = 0; FakeSocket.OPEN = 1; FakeSocket.CLOSING = 2; FakeSocket.CLOSED = 3;
global.WebSocket = FakeSocket;
global.CustomEvent = class { constructor(type, init) { this.type = type; this.detail = init && init.detail; } };
global.window = { location: { protocol: 'http:', host: 'vault.test' }, dispatchEvent() { return true; } };
let authToken = 'token';
let currentUser = null;
const isScopedTemp = false;
"""

SCENARIOS = r"""
const live = () => timers.filter(t => t.live).map(t => t.ms);
function closeCurrent(event) {          // the server closes the current socket
    const ws = sockets[sockets.length - 1];
    ws.readyState = FakeSocket.CLOSED;
    if (event === undefined) ws.onclose(); else ws.onclose(event);
}
const out = { pending_when_fired: [] };
function fire() {                        // the pending timer runs; how many were pending is checked in Python
    const due = timers.filter(t => t.live);
    out.pending_when_fired.push(due.length);
    if (due.length) { due[0].live = false; due[0].fn(); }
}

connectAppSocket();
closeCurrent({ code: 4429 });
out.refused_timers = live();
const before = sockets.length;
ensureAppSocket(); ensureAppSocket();
out.ensure_during_wait = sockets.length - before;
fire();
out.after_the_minute = sockets.length - before;
closeCurrent({ code: 1000 });
out.after_a_normal_close = live();
ensureAppSocket();                       // a normal close leaves navigation free to reopen at once
out.ensure_after_normal = sockets.length - before;

out.other_closes = {};
for (const [name, event] of [['1000', { code: 1000 }], ['1006', { code: 1006 }], ['none', undefined],
                              ['1008', { code: 1008 }]]) {
    connectAppSocket();
    closeCurrent(event);
    out.other_closes[name] = live();
}

connectAppSocket();
closeCurrent({ code: 4429 });
closeAppSocket();                        // signing out clears the wait
out.after_sign_out = live();
let n = sockets.length;
ensureAppSocket();
out.ensure_after_sign_out = sockets.length - n;

connectAppSocket();
closeCurrent({ code: 4429 });
connectAppSocket();                      // signing in again connects at once and clears the wait
out.connect_during_wait_timers = live();
sockets[sockets.length - 1].readyState = FakeSocket.CLOSED;
n = sockets.length;
ensureAppSocket();
out.ensure_after_connect = sockets.length - n;

process.stdout.write(JSON.stringify(out));
"""


def _run(section: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=HARNESS + section + SCENARIOS, capture_output=True, text=True,
                          encoding="utf-8", timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


def test_a_refused_socket_waits_a_minute_and_any_other_close_five_seconds():
    out = _run(_section())
    # Refused: exactly one timer, a minute away, and navigation opens nothing meanwhile.
    assert out["refused_timers"] == [60000], out
    assert out["ensure_during_wait"] == 0, out
    # When the minute is up, the one timer pending is that minute's.
    assert out["pending_when_fired"] == [1], out
    # When the minute is up, one socket is made.
    assert out["after_the_minute"] == 1, out
    # Any other close (or a close with no event) tries again after five seconds.
    assert out["after_a_normal_close"] == [5000], out
    assert out["other_closes"] == {"1000": [5000], "1006": [5000], "none": [5000], "1008": [5000]}, out
    assert out["ensure_after_normal"] == 2, out
    # Signing out clears the wait and its timer; a connect does too, and leaves no timer behind.
    assert out["after_sign_out"] == [] and out["ensure_after_sign_out"] == 1, out
    assert out["connect_during_wait_timers"] == [] and out["ensure_after_connect"] == 1, out


def test_the_lifted_section_is_the_whole_socket_section():
    section = _section()
    for name in ("function scheduleAppSocketReconnect(", "function connectAppSocket(", "function closeAppSocket(",
                 "function ensureAppSocket(", "const APP_SOCKET_REFUSED_CLOSE = 4429;"):
        assert section.count(name) == 1, name
