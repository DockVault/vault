"""When a held token arrived, offline (static/js/session-watch.js run in Node with small stand-ins).

A token whose arrival on this device is stored is timed from it. A token with none stored (the first load after
an upgrade, which kept no arrival) is armed at once as if it had just arrived, then corrected from the server:
the time it has left is the token's exp against the Date of a /users/me answer, carried onto this device's
clock, and the arrival that implies is stored so a reload agrees. Until the server has answered, the arrival
stored is marked a guess and the next load asks again. The correction gives way to any arming made meanwhile,
and when the server does not answer the local arming stands.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

# A device clock two hours ahead of the server's; a token issued ten minutes ago (on the server's clock) for
# thirty minutes. The page's timers are inert: only the deadline is read.
PRELUDE = r"""
const fs = require('fs');
const vm = require('vm');
const REAL = Date.now();
const SKEW = 2 * 3600 * 1000;
Date.now = () => REAL + SKEW;
const serverNowMs = Math.floor(REAL / 1000) * 1000;
const iat = Math.floor(REAL / 1000) - 600;
const exp = iat + 1800;
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/=+$/, '');
const token = 'h.' + b64({ sub: '1', iat, exp }) + '.sig-of-the-token-for-the-test';
const store = new Map();
globalThis.window = globalThis;
globalThis.storage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)),
                       removeItem: (k) => store.delete(k) };
globalThis.document = { getElementById: () => null, addEventListener: () => {}, hidden: false };
globalThis.setTimeout = () => 0; globalThis.clearTimeout = () => {};
globalThis.setInterval = () => 0; globalThis.clearInterval = () => {};
globalThis.API_BASE = '';
globalThis.authToken = token;
const asked = [];
let answer = () => Promise.resolve({ ok: true, status: 200,
    headers: { get: (h) => (h.toLowerCase() === 'date' ? new Date(serverNowMs).toUTCString() : null) } });
globalThis.fetch = (url, opts) => { asked.push(url); return answer(url, opts); };
vm.runInThisContext(fs.readFileSync('static/js/session-watch.js', 'utf8'), { filename: 'session-watch.js' });
const settle = () => new Promise((r) => setImmediate(r));
// A reload: the page's script runs again over the same storage.
const reload = () => vm.runInThisContext(fs.readFileSync('static/js/session-watch.js', 'utf8'), { filename: 'session-watch.js' });
const stored = () => store.get('authTokenAt') || null;
"""


def _node(body: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=PRELUDE + "(async () => {\n" + body + "\n})();", capture_output=True,
                          text=True, encoding="utf-8", timeout=60, cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_token_with_no_stored_arrival_is_timed_by_the_server_and_its_arrival_stored():
    out = _node("""
SessionWatch.armFromToken(token);
const before = SessionWatch.remaining();
await settle(); await settle();
const after = SessionWatch.remaining();
const arrival = Number(stored().split(':')[0]);
// A reload: the stored arrival is read, nothing is asked.
const askedBefore = asked.length;
SessionWatch.armFromToken(token);
console.log(JSON.stringify({ before, after, again: SessionWatch.remaining(), asked: askedBefore,
    askedAgain: asked.length - askedBefore, arrivalAgo: Math.round((Date.now() - arrival) / 1000) }));
""")
    assert out["before"] == 1800            # armed at once as if just arrived
    assert out["asked"] == 1                # then asked the server
    assert 1198 <= out["after"] <= 1199, out   # twenty minutes left by the server, a second early at most
    assert 599 <= out["arrivalAgo"] <= 602, out
    assert out["askedAgain"] == 0 and 1198 <= out["again"] <= 1199, out


def test_a_stored_arrival_is_used_and_nothing_is_asked():
    out = _node("""
store.set('authTokenAt', (Date.now() - 300 * 1000) + ':' + token.slice(-24));
SessionWatch.armFromToken(token);
await settle(); await settle();
console.log(JSON.stringify({ left: SessionWatch.remaining(), asked: asked.length }));
""")
    assert out["asked"] == 0
    assert 1499 <= out["left"] <= 1500, out


def test_no_answer_from_the_server_keeps_the_local_arming():
    out = _node("""
answer = () => Promise.reject(new Error('offline'));
SessionWatch.armFromToken(token);
await settle(); await settle();
const offline = SessionWatch.remaining();
SessionWatch.disarm(); store.clear();
answer = () => Promise.resolve({ ok: false, status: 503, headers: { get: () => null } });
SessionWatch.armFromToken(token);
await settle(); await settle();
console.log(JSON.stringify({ offline, refused: SessionWatch.remaining() }));
""")
    assert out == {"offline": 1800, "refused": 1800}


def test_an_arming_made_meanwhile_wins_over_the_correction():
    out = _node("""
let release;
answer = () => new Promise((r) => { release = () => r({ ok: true, status: 200,
    headers: { get: () => new Date(serverNowMs).toUTCString() } }); });
SessionWatch.armFromToken(token);
SessionWatch.armAt(Date.now() + 61000);       // the warning armed by hand, as a test or a renewal does
release();
await settle(); await settle();
const byHand = SessionWatch.remaining();
// And a correction for a token no longer held changes nothing.
SessionWatch.disarm(); store.clear();
SessionWatch.armFromToken(token);
globalThis.authToken = 'another.token.value';
release();
await settle(); await settle();
console.log(JSON.stringify({ byHand, swapped: SessionWatch.remaining() }));
""")
    assert out["byHand"] == 61, out
    assert out["swapped"] == 1800, out


def test_a_guess_the_server_did_not_confirm_is_asked_about_again_on_the_next_load():
    out = _node("""
answer = () => Promise.reject(new Error('offline'));
SessionWatch.armFromToken(token);
await settle(); await settle();
const guessed = stored();
SessionWatch.armFromToken(token);            // the same load: not asked twice
await settle(); await settle();
const askedOnThisLoad = asked.length;
answer = () => Promise.resolve({ ok: true, status: 200,
    headers: { get: (h) => (h.toLowerCase() === 'date' ? new Date(serverNowMs).toUTCString() : null) } });
reload();
SessionWatch.armFromToken(token);
await settle(); await settle();
const confirmed = stored();
const left = SessionWatch.remaining();
reload();
SessionWatch.armFromToken(token);            // confirmed now: a later load asks nothing
await settle(); await settle();
console.log(JSON.stringify({ guessed, askedOnThisLoad, asked: asked.length, confirmed, left }));
""")
    assert out["guessed"].startswith("~"), out
    assert out["askedOnThisLoad"] == 1, out
    assert out["asked"] == 2, out
    assert not out["confirmed"].startswith("~"), out
    assert 1198 <= out["left"] <= 1199, out
