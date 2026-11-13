"""The download worker answers every download as plain bytes to save, whatever type the file was stored with.

The worker gives a download an address of the vault's own origin and answers it with the file's bytes as the page
writes them. A stored MIME type is whatever its uploader claimed; answered under it, a file stored as a script or a
page would be a script or a page of this origin to anything that named that address. A browser saves the download
under the name the worker gives it, so the type is not needed: the answer is always ``application/octet-stream``,
an attachment, with sniffing off.

The SHIPPED worker (static/js/download-sw.js, run as is) is driven here under Node: the page's message and the
browser's request are handed to the worker's own listeners, and the answer's headers are read from the response
it makes.
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

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const listeners = {};
const worker = {
    self: {
        addEventListener: (type, fn) => { listeners[type] = fn; },
        skipWaiting: () => {},
        clients: { claim: async () => {} },
        location: { origin: 'https://vault.example' },
    },
    setTimeout: () => 0,
    Date,
    Response: class { constructor(body, init) { this.body = body; this.status = (init && init.status) || 200;
                                                 this.headers = (init && init.headers) || {}; } },
    ReadableStream, URL,
};
new vm.Script(fs.readFileSync(process.argv[2], 'utf8'), { filename: 'download-sw.js' })
    .runInNewContext(worker);

const answer = async (id, message) => {
    const port = { onmessage: null, postMessage() {} };
    listeners.message({ data: { type: 'dv-sink-open', id, ...message }, ports: [port] });
    port.onmessage({ data: { type: 'chunk', bytes: new Uint8Array([1, 2, 3]).buffer } });
    port.onmessage({ data: { type: 'done' } });
    let response = null;
    listeners.fetch({ request: { url: 'https://vault.example/__dv_sink__/' + id },
                      respondWith: (r) => { response = r; } });
    const got = [];
    const reader = response.body.getReader();
    for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        got.push(...value);
    }
    return { status: response.status, headers: response.headers, bytes: got };
};

(async () => {
    const out = [];
    for (const [i, message] of JSON.parse(process.argv[3]).entries()) out.push(await answer('slot-' + i, message));
    process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""

# What the page says of the file it is about to write: its name, its size, and the type it was stored with.
MESSAGES = [
    {"filename": "code.js", "size": 3, "mime": "text/javascript"},
    {"filename": "code.mjs", "size": 3, "mime": "application/javascript"},
    {"filename": "page.html", "size": 3, "mime": "text/html"},
    {"filename": "holiday.png", "size": 3, "mime": "application/xhtml+xml"},
    {"filename": "drawing.svg", "size": 3, "mime": "image/svg+xml"},
    {"filename": "look.css", "size": 3, "mime": "text/css"},
    {"filename": "module.wasm", "size": 3, "mime": "application/wasm"},
    {"filename": "contract.pdf", "size": 3, "mime": "application/pdf"},
    {"filename": "case-7-export.zip", "size": None, "mime": "application/zip"},
    {"filename": "sealed.bin", "size": 3, "mime": "application/octet-stream"},
    {"filename": "untyped", "size": 3},
    {"filename": "odd", "size": 3, "mime": "not a type"},
]


@pytest.fixture(scope="module")
def answers():
    node = shutil.which("node")
    assert node, "Node is required: the worker's own code must not be skipped"
    done = subprocess.run([node, "-", str(WORKER), json.dumps(MESSAGES)], input=HARNESS, capture_output=True,
                          text=True, encoding="utf-8", timeout=60, cwd=str(ROOT), env=dict(os.environ))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    got = json.loads(done.stdout)
    assert len(got) == len(MESSAGES)
    return got


@pytest.mark.parametrize("index", range(len(MESSAGES)),
                         ids=[m.get("mime", "untyped").replace(" ", "-") for m in MESSAGES])
def test_a_download_is_answered_as_plain_bytes_to_save(answers, index):
    message, got = MESSAGES[index], answers[index]
    assert got["status"] == 200 and got["bytes"] == [1, 2, 3]
    headers = got["headers"]
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Disposition"] == f'attachment; filename="{message["filename"]}"'
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    assert headers.get("Content-Length") == (None if message["size"] is None else "3")
    # Nothing else is said about the answer: no second type, nothing that lets it be shown in place.
    assert sorted(headers) == sorted(["Content-Type", "Content-Disposition", "X-Content-Type-Options",
                                      "Cache-Control"] + ([] if message["size"] is None else ["Content-Length"]))


def test_the_worker_takes_no_type_from_the_page():
    source = WORKER.read_text(encoding="utf-8")
    assert source.count("const SINK_CONTENT_TYPE = 'application/octet-stream';") == 1
    assert source.count("'Content-Type': SINK_CONTENT_TYPE,") == 1 and source.count("'Content-Type'") == 1
    assert "data.mime" not in source and "slot.mime" not in source


def test_the_page_gives_the_worker_plain_bytes_as_the_type():
    # A browser can run the worker of an earlier release for the first download after an upgrade, and that worker
    # answered under the type the page gave it. So the page gives it no stored type either.
    source = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert source.count("type: 'dv-sink-open'") == 1
    assert source.count("{ type: 'dv-sink-open', id, filename, size, mime: 'application/octet-stream' }") == 1
