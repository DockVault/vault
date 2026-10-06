"""The download worker keeps a slot the page has finished writing for a minute, then lets it go.

For a small file the page can finish writing before the browser's request for the slot reaches the worker;
the slot must wait for that request (test_ui_download_sink_late_request.py drives that order in a browser).
It must not wait for ever either: a page that finishes and whose request never comes would otherwise leave
its slot, and the bytes written into it, in the worker for as long as the worker lives. The bound is one
minute (SLOT_TTL_MS), kept two ways: a timer set when the page finishes, and a sweep of stale slots on every
request the worker answers.

The browser tests cannot wait a minute on a real worker, so the SHIPPED worker (static/js/download-sw.js, run
as is) is driven here under Node, in a context of its own whose clock and timers the test moves: the page's
messages and the browser's requests are handed to the worker's own listeners.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "static" / "js" / "download-sw.js"
MINUTE_MS = 60_000

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
let now = 1000000;
const timers = [];
const listeners = {};
const worker = {
    self: {
        addEventListener: (type, fn) => { listeners[type] = fn; },
        skipWaiting: () => {},
        clients: { claim: async () => {} },
        location: { origin: 'https://vault.example' },
    },
    setTimeout: (fn, ms) => { timers.push({ fn, ms, due: now + ms, done: false }); return timers.length; },
    Date: { now: () => now },
    Response: class { constructor(body, init) { this.body = body; this.status = (init && init.status) || 200; } },
    ReadableStream, URL,
};
new vm.Script(fs.readFileSync(process.argv[2], 'utf8'), { filename: 'download-sw.js' })
    .runInNewContext(worker);

// Runs every timer due by `now`, in order, as the event loop would.
const runDue = () => {
    for (const t of timers.slice().sort((a, b) => a.due - b.due)) {
        if (!t.done && t.due <= now) { t.done = true; t.fn(); }
    }
};
const advance = (ms) => { now += ms; runDue(); };

const open = (id) => {
    const port = { posted: [], onmessage: null, postMessage(m) { this.posted.push(m); } };
    listeners.message({ data: { type: 'dv-sink-open', id, filename: id + '.bin', size: 3,
                                mime: 'application/octet-stream' }, ports: [port] });
    return port;
};
const write = (port, ...bytes) => port.onmessage({ data: { type: 'chunk', bytes: new Uint8Array(bytes).buffer } });
const finish = (port) => port.onmessage({ data: { type: 'done' } });
const giveUp = (port) => port.onmessage({ data: { type: 'abort', reason: 'gave up' } });
const ask = async (id) => {
    let response = null;
    listeners.fetch({ request: { url: 'https://vault.example/__dv_sink__/' + id },
                      respondWith: (r) => { response = r; } });
    if (!response) return { status: null };
    if (response.status !== 200) return { status: response.status };
    const reader = response.body.getReader();
    const got = [];
    try {
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            got.push(...value);
        }
    } catch (e) {
        return { status: 200, bytes: got, failed: true };
    }
    return { status: 200, bytes: got, failed: false };
};

const out = {};
(async () => {
    // A finished slot is kept until a minute after it finished ...
    let p = open('kept');
    write(p, 1, 2, 3);
    advance(5000);                       // written over a while: the minute counts from the end
    finish(p);
    out.timers_at_finish = timers.filter(t => !t.done).map(t => t.ms);
    advance(59999);
    await ask('another');                // its sweep counts the minute from the end too
    out.just_before = await ask('kept');

    // ... and gone a minute after it finished, when its request never came.
    p = open('gone');
    write(p, 4, 5, 6);
    finish(p);
    advance(60000);
    out.at_the_minute = await ask('gone');

    // A slot the page gave up on is kept and let go the same way (its request fails the download).
    p = open('failed');
    write(p, 7);
    giveUp(p);
    out.timers_at_abort = timers.filter(t => !t.done).map(t => t.ms);
    advance(59999);
    out.failed_just_before = await ask('failed');
    p = open('failed-gone');
    giveUp(p);
    advance(60000);
    out.failed_at_the_minute = await ask('failed-gone');

    // The sweep on each request lets a stale finished slot go even when its timer has not run (a worker
    // the browser suspended), and keeps one that is exactly a minute old.
    p = open('swept');
    write(p, 8);
    finish(p);
    now += 60000;                        // the clock moves, no timer runs
    await ask('someone-else');
    out.swept_at_the_minute = await ask('swept');
    p = open('swept-later');
    write(p, 9);
    finish(p);
    now += 60001;
    await ask('someone-else-again');
    out.swept_after_the_minute = await ask('swept-later');

    // A slot opened again under the same id after the first was taken is not removed by the first
    // one's timer.
    p = open('reused');
    write(p, 1);
    finish(p);
    out.first_taken = (await ask('reused')).status;
    p = open('reused');
    write(p, 2);
    advance(60000);                      // the first slot's timer runs; the second is still being written
    finish(p);
    out.second = await ask('reused');
    process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""


def _run() -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the worker's own code must not be skipped"
    done = subprocess.run([node, "-", str(WORKER)], input=HARNESS, capture_output=True, text=True,
                          encoding="utf-8", timeout=60, cwd=str(ROOT), env=dict(os.environ))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def seen():
    return _run()


def test_the_minute_is_the_workers_own_constant():
    source = WORKER.read_text(encoding="utf-8")
    assert source.count("const SLOT_TTL_MS = 60_000;") == 1


def test_finishing_sets_one_timer_of_a_minute(seen):
    assert seen["timers_at_finish"] == [MINUTE_MS]
    assert MINUTE_MS in seen["timers_at_abort"]


def test_a_finished_slot_is_kept_until_the_minute_is_up(seen):
    assert seen["just_before"] == {"status": 200, "bytes": [1, 2, 3], "failed": False}


def test_a_finished_slot_whose_request_never_came_is_gone_at_the_minute(seen):
    assert seen["at_the_minute"] == {"status": 404}


def test_a_slot_the_page_gave_up_on_fails_its_download_and_goes_at_the_minute(seen):
    assert seen["failed_just_before"]["status"] == 200 and seen["failed_just_before"]["failed"] is True
    assert seen["failed_at_the_minute"] == {"status": 404}


def test_each_request_sweeps_slots_older_than_a_minute(seen):
    assert seen["swept_at_the_minute"] == {"status": 200, "bytes": [8], "failed": False}
    assert seen["swept_after_the_minute"] == {"status": 404}


def test_an_old_timer_does_not_remove_a_new_slot_under_the_same_id(seen):
    assert seen["first_taken"] == 200
    assert seen["second"] == {"status": 200, "bytes": [2], "failed": False}
