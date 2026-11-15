"""A download stops everywhere when the session ends, and every request of a download carries its abort.

The page ends a session and is replaced a moment later; a download of the person who signed out must not land in the
browser's downloads in that moment. These tests run the SHIPPED code, lifted verbatim from ``static/js/app.js``, under
Node, each guard on its own:

- a download asked for on a page that has ended a session asks for nothing;
- a file read in full after the session ended is not saved;
- no download tray is drawn on a page that has ended a session;
- no download is opened in the browser when the session ends while its streaming sink is being opened;
- the re-fetches after a streaming attempt that could not go ahead, and the resumed read of a zero-knowledge stream,
  carry the download's abort, so the sign-out stops them too.

Each test has its control: the same run on a page whose session has not ended does download, draw and open.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(head: str) -> str:
    start = APP.index(head)
    return APP[start:APP.index("\n}\n", start) + 3]


def _object(head: str) -> str:
    start = APP.index(head)
    return APP[start:APP.index("\n};\n", start) + 4]


DOWNLOAD = _function("async function _downloadFile(fileId, fileName) {")
SINK = _function("async function dvOpenDownloadSink({ filename, size, mime }) {")
ZK_STREAM = _function("async function zkTryStreamedDownload(")
TRAY = _object("const downloadProgress = {")


def _node(script: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8",
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


# What _downloadFile calls, stood in for: every request, the controller the download made, and what was saved.
DOWNLOAD_STAGE = r"""
const MAX_BUFFERED_DOWNLOAD_BYTES = 1000;
const API_BASE = '', authToken = 't';
let _sinkUnavailableReason = null;
let controller = null;
class AbortController extends globalThis.AbortController {
    constructor() { super(); controller = this; }
}
const state = { currentVault: { id: 'V', has_password: false }, currentFiles: [{ id: 'f', size: 10 }],
                downloadSink: 'buffered' };
const said = [], fetched = [], events = [];
let zk = false, zkStreamArgs = null, endWhileRead = false;
const showError = (m) => said.push('error: ' + m), showInfo = (m) => said.push('info: ' + m),
      showSuccess = (m) => said.push('ok: ' + m);
const formatBytes = (n) => n + ' B';
const isZkVault = () => zk;
const fetch = async (url, opts) => {
    fetched.push({ url, signal: opts ? opts.signal : undefined });
    return { ok: true, headers: { get: () => null }, body: { cancel: async () => {} } };
};
const dvTryStandardStreamedDownload = async () => false;
const zkTryStreamedDownload = async (...args) => { zkStreamArgs = args; return false; };
const zkFileKeyVersion = () => 1;
const zkMaybeDecryptResponse = async () => { if (endWhileRead) _pageEnded = true; return { bytes: true }; };
const readResponseWithProgress = async () => { if (endWhileRead) _pageEnded = true; return { bytes: true }; };
const isCodedCryptoError = () => false, safeMessageForCode = () => '';
const downloadProgress = { start: () => 1, update() {}, done() {} };
let _pageEnded = false;
const _downloadsOfThisSession = new Set();
const window = { URL: { createObjectURL: () => { events.push('address made'); return 'blob:x'; },
                        revokeObjectURL() {} } };
const document = {
    createElement: (tag) => ({ tag, click() { events.push('saved'); } }),
    body: { appendChild() {}, removeChild() {} },
};
const run = async (setup) => {
    said.length = 0; fetched.length = 0; events.length = 0; controller = null; zkStreamArgs = null;
    _pageEnded = false; endWhileRead = false; zk = false; state.downloadSink = 'buffered';
    setup();
    await _downloadFile('f', 'hers.txt');
    return {
        fetches: fetched.length,
        allCarryTheAbort: fetched.length > 0 && fetched.every((f) => !!controller && f.signal === controller.signal),
        zkStreamGotTheController: zkStreamArgs ? zkStreamArgs[5] === controller : null,
        events: [...events], said: [...said], tracked: _downloadsOfThisSession.size,
    };
};
const finish = (out) => process.stdout.write(JSON.stringify(out), () => process.exit(0));
"""


def _downloads(cases: str):
    return _node(DOWNLOAD_STAGE + DOWNLOAD + "(async () => { finish({" + cases + "}); })()"
                 ".catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });\n")


def test_a_download_asked_for_on_a_page_that_ended_a_session_asks_for_nothing():
    out = _downloads("""
        ended: await run(() => { _pageEnded = true; }),
        control: await run(() => {}),
    """)
    assert out["ended"] == {"fetches": 0, "allCarryTheAbort": False, "zkStreamGotTheController": None,
                            "events": [], "said": [], "tracked": 0}, out["ended"]
    # The control: on a page whose session goes on, the same call asks for the file and saves it.
    assert out["control"]["fetches"] == 1 and out["control"]["events"] == ["address made", "saved"], out["control"]


def test_a_file_read_in_full_after_the_session_ended_is_not_saved():
    out = _downloads("""
        standard: await run(() => { endWhileRead = true; }),
        zeroKnowledge: await run(() => { endWhileRead = true; zk = true; }),
        control: await run(() => {}),
        zeroKnowledgeControl: await run(() => { zk = true; }),
    """)
    for kind in ("standard", "zeroKnowledge"):
        got = out[kind]
        assert got["fetches"] == 1, (kind, got)               # the read did happen, the session ended during it
        assert got["events"] == [], (kind, got)               # no address made, nothing clicked
        assert not any(s.startswith("ok:") for s in got["said"]), (kind, got)
    for kind in ("control", "zeroKnowledgeControl"):
        assert out[kind]["events"] == ["address made", "saved"], (kind, out[kind])


def test_the_re_fetches_after_a_streaming_attempt_that_could_not_go_ahead_carry_the_downloads_abort():
    """Streaming is asked for and cannot go ahead (nothing written): a small file is fetched again for a buffered read.
    That second request is stopped by the same abort as the first, which the sign-out pulls."""
    out = _downloads("""
        standard: await run(() => { state.downloadSink = 'streaming'; }),
        zeroKnowledge: await run(() => { state.downloadSink = 'streaming'; zk = true; }),
    """)
    for kind in ("standard", "zeroKnowledge"):
        got = out[kind]
        assert got["fetches"] == 2, (kind, got)               # the first request, and the re-fetch
        assert got["allCarryTheAbort"] is True, (kind, got)
        assert got["events"] == ["address made", "saved"], (kind, got)
    # The zero-knowledge streaming attempt is handed the download's controller for its own requests.
    assert out["zeroKnowledge"]["zkStreamGotTheController"] is True, out["zeroKnowledge"]


SINK_STAGE = r"""
const DV_SINK_CLAIM_WAIT_MS = 60000;
const showError = () => {};
let _pageEnded = false, endWhileOpening = false;
const appended = [];
const document = {
    createElement: (tag) => ({ tag, style: {}, remove() {} }),
    body: { appendChild: (node) => { appended.push(node.tag + ' ' + node.src); } },
};
// The download worker: it answers the page's request for a sink a moment later, as a browser's does.
const dvSinkWorker = async () => ({
    postMessage: (msg, ports) => {
        setTimeout(() => {
            if (endWhileOpening) _pageEnded = true;
            ports[0].postMessage({ type: 'dv-sink-ready', url: '/dv-sink/' + msg.id, reportsTaken: true });
        }, 20);
    },
});
const open = async (setup) => {
    appended.length = 0; _pageEnded = false; endWhileOpening = false;
    setup();
    const sink = await dvOpenDownloadSink({ filename: 'hers.txt', size: 10, mime: 'text/plain' });
    return { sink: sink === null ? null : typeof sink, appended: appended.length };
};
(async () => {
    const out = {
        endedWhileOpening: await open(() => { endWhileOpening = true; }),
        control: await open(() => {}),
    };
    process.stdout.write(JSON.stringify(out), () => process.exit(0));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def test_no_download_is_opened_in_the_browser_when_the_session_ends_while_its_sink_opens():
    out = _node(SINK + SINK_STAGE)
    assert out["endedWhileOpening"] == {"sink": None, "appended": 0}, out
    # The control: the same opening, the session going on, does open the download (one hidden frame).
    assert out["control"] == {"sink": "object", "appended": 1}, out


TRAY_STAGE = r"""
let _dlSeq = 0;
let _pageEnded = false;
const formatBytes = (n) => n + ' B';
const appended = [];
const make = (tag) => {
    const node = { tag, id: '', className: '', textContent: '', title: '', style: {}, children: [],
                   classList: { add() {}, remove() {} }, setAttribute() {}, addEventListener() {},
                   appendChild(c) { this.children.push(c); }, append(...cs) { this.children.push(...cs); },
                   remove() {} };
    return node;
};
const document = {
    getElementById: () => null,
    createElement: make,
    body: { appendChild: (node) => { appended.push(node.id || node.tag); } },
};
const draw = (ended) => {
    appended.length = 0; _pageEnded = ended; downloadProgress.rows.clear();
    downloadProgress.start('hers.txt', () => {});
    return [...appended];
};
process.stdout.write(JSON.stringify({ ended: draw(true), control: draw(false) }), () => process.exit(0));
"""


def test_a_page_that_ended_a_session_draws_no_download_tray():
    out = _node(TRAY + TRAY_STAGE)
    assert out["ended"] == [], out
    # The control: on a page whose session goes on, the first download draws the tray into the page.
    assert out["control"] == ["download-tray"], out


ZK_STAGE = r"""
const API_BASE = '';
const ZK_RESUME_ATTEMPTS = 3;
const isCodedCryptoError = () => false;
const zkDownloadHeaders = () => ({ Authorization: 'Bearer t' });
const zkResolveKey = async () => ({ dek: 'k', context: 'c' });
const sinkLog = [];
const dvOpenDownloadSink = async () => ({ write() { sinkLog.push('write'); }, done() { sinkLog.push('done'); },
                                         abort(r) { sinkLog.push('abort ' + r); } });
let reads = 0;
// The stream breaks once, after a record was handed over (a dropped connection): the read is resumed from there.
const lib = {
    decryptStreamV2: async (stream, declared, dek, context, onPiece) => {
        reads += 1;
        onPiece(new Uint8Array(1));
        if (reads === 1) throw new Error('the connection dropped');
    },
    _peekStream: async (body) => ({ head: new Uint8Array(28), stream: body }),
    _inspectV2Header: () => 'UNSUPPORTED',
    v2ContentResumeOffset: (head, declared, records) => ({ totalPlaintext: 10, offset: 28 + records * 5, done: false }),
};
const eccLib = () => lib;
const fetched = [];
const fetch = async (url, opts) => {
    fetched.push({ url, range: opts && opts.headers && opts.headers.Range, signal: opts ? opts.signal : undefined });
    return { status: 206, body: {} };
};
const headers = { 'Content-Length': '100', 'ETag': '"e1"', 'Content-Type': 'application/octet-stream' };
const response = { headers: { get: (n) => headers[n] || null }, body: {} };
(async () => {
    const ctl = new AbortController();
    const result = await zkTryStreamedDownload(response, { id: 'V' }, 1, 'f', 'hers.bin', ctl);
    process.stdout.write(JSON.stringify({
        result, reads, sink: sinkLog,
        resumes: fetched.map((f) => ({ range: f.range, carriesTheAbort: f.signal === ctl.signal })),
    }), () => process.exit(0));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def test_a_resumed_zero_knowledge_read_carries_the_downloads_abort():
    out = _node(ZK_STREAM + ZK_STAGE)
    # The control: the stream did break and was resumed with a range request, and the download completed.
    assert out["result"] is True and out["reads"] == 2, out
    assert out["sink"] == ["write", "write", "done"], out
    assert out["resumes"] == [{"range": "bytes=33-", "carriesTheAbort": True}], out
