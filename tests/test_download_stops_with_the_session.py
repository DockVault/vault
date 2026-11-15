"""A download stops with the session: nothing of it reaches the browser's downloads after a sign-out.

When a session ends on the page (logout) every download of that session is aborted and the page is marked ended
(``_pageEnded``). These tests RUN the shipped code, lifted verbatim from ``static/js/app.js``, under Node, each guard
on its own: a download asked for on an ended page, a read that ends after the sign-out, the download tray, the
streaming sink opened while the session ends, the buffered re-fetch after a streaming attempt that could not go on,
and the resumed read of a zero-knowledge stream. Each leg has its control: the same run with the session still open
goes through, so a leg cannot pass by the stand-in page doing nothing.
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
PROGRESS = _object("const downloadProgress = {")


def _node(script: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8",
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


def _main(body: str) -> str:
    return ("(async () => {\n" + body + "\n})().then((out) => { process.stdout.write(JSON.stringify(out)); "
            "process.exit(0); }).catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });\n")


# ---- _downloadFile ---------------------------------------------------------------------------------------------

DOWNLOAD_STAGE = r"""
const MAX_BUFFERED_DOWNLOAD_BYTES = 1024 * 1024;
const API_BASE = '', authToken = 't';
let _sinkUnavailableReason = null;
const state = { currentVault: { id: 'V', has_password: false }, currentFiles: [{ id: 'f', size: 4 }],
                downloadSink: 'buffered' };
const said = [], fetched = [], saved = [], made = [];
const showError = (m) => said.push('error: ' + m), showInfo = (m) => said.push('info: ' + m),
      showSuccess = (m) => said.push('ok: ' + m);
const formatBytes = (n) => n + ' B';
let zk = false;
const isZkVault = () => zk;
// The download's own controller, watched (the one logout aborts).
let controller = null;
class AbortController extends globalThis.AbortController { constructor() { super(); controller = this; } }
// The server's answer; a request whose signal is aborted is refused, as a browser refuses it.
const fetch = async (url, opts) => {
    if (opts && opts.signal && opts.signal.aborted) { const e = new Error('aborted'); e.name = 'AbortError'; throw e; }
    fetched.push({ url, signal: !!(opts && opts.signal), own: !!(opts && opts.signal && controller
                                                                && opts.signal === controller.signal) });
    return { ok: true, headers: { get: () => null }, body: { cancel: async () => {} } };
};
let duringStream = null;
const dvTryStandardStreamedDownload = async () => { if (duringStream) duringStream(); return false; };
const zkTryStreamedDownload = async () => { if (duringStream) duringStream(); return false; };
const zkFileKeyVersion = () => 1;
const zkMaybeDecryptResponse = async () => new Blob([new Uint8Array([1, 2, 3, 4])]);
const isCodedCryptoError = () => false, safeMessageForCode = () => '';
const downloadProgress = { start: () => 1, update() {}, done() {} };
let duringRead = null;
const readResponseWithProgress = async () => { if (duringRead) duringRead(); return new Blob([new Uint8Array([1, 2, 3, 4])]); };
let _pageEnded = false;
const _downloadsOfThisSession = new Set();
const window = { URL: { createObjectURL: (b) => { made.push(b.size); return 'blob:x'; }, revokeObjectURL() {} } };
const document = { createElement: () => ({ click() { saved.push('clicked'); } }), body: { appendChild() {}, removeChild() {} } };
const leg = async (setup) => {
    said.length = 0; fetched.length = 0; saved.length = 0; made.length = 0; controller = null;
    _pageEnded = false; _downloadsOfThisSession.clear(); duringRead = null; duringStream = null;
    zk = false; state.downloadSink = 'buffered';
    setup();
    await _downloadFile('f', 'ana.bin');
    return { fetched: fetched.map((f) => ({ signal: f.signal, own: f.own })), made: made.length, saved: saved.length,
             said: [...said], kept: _downloadsOfThisSession.size };
};
"""


def _download(body: str):
    return _node(DOWNLOAD_STAGE + DOWNLOAD + _main(body))


def test_a_download_asked_for_on_a_page_that_ended_its_session_asks_for_nothing():
    """Download pressed on a page whose session has ended: no request, no message, nothing kept or saved."""
    out = _download("return { ended: await leg(() => { _pageEnded = true; }), open: await leg(() => {}) };")
    assert out["ended"] == {"fetched": [], "made": 0, "saved": 0, "said": [], "kept": 0}, out["ended"]
    # The control: with the session open the same download is asked for and saved.
    assert len(out["open"]["fetched"]) == 1 and out["open"]["saved"] == 1, out["open"]


def test_a_file_whose_read_ends_after_the_sign_out_is_not_saved():
    """The file is read in full only after the session ended: no object address is made and nothing is clicked."""
    out = _download("return { ended: await leg(() => { duringRead = () => { _pageEnded = true; }; }),\n"
                    "         open: await leg(() => {}) };")
    assert len(out["ended"]["fetched"]) == 1, out["ended"]
    assert out["ended"]["made"] == 0 and out["ended"]["saved"] == 0, out["ended"]
    assert not any(m.startswith("ok:") for m in out["ended"]["said"]), out["ended"]
    assert out["open"]["made"] == 1 and out["open"]["saved"] == 1, out["open"]


@pytest.mark.parametrize("zero_knowledge", [False, True], ids=["standard", "zero-knowledge"])
def test_the_buffered_fetch_after_a_streaming_attempt_is_stopped_with_the_download(zero_knowledge):
    """A streaming attempt that cannot go on falls back to fetching the file again: that request carries the
    download's own abort, so a download stopped meanwhile (its Cancel, or the end of the session) fetches nothing
    more and saves nothing."""
    zk = "true" if zero_knowledge else "false"
    out = _download(
        "const go = (extra) => leg(() => { zk = " + zk + "; state.downloadSink = 'streaming'; extra(); });\n"
        "return { open: await go(() => {}),\n"
        "         stopped: await go(() => { duringStream = () => controller.abort(); }) };")
    # Both requests of the download carry its own signal.
    assert out["open"]["fetched"] == [{"signal": True, "own": True}, {"signal": True, "own": True}], out["open"]
    assert out["open"]["saved"] == 1, out["open"]
    # Stopped during the streaming attempt: the re-fetch is refused, and nothing is saved.
    assert out["stopped"]["fetched"] == [{"signal": True, "own": True}], out["stopped"]
    assert out["stopped"]["made"] == 0 and out["stopped"]["saved"] == 0, out["stopped"]
    assert not any(m.startswith("ok:") for m in out["stopped"]["said"]), out["stopped"]


# ---- the download tray -----------------------------------------------------------------------------------------

TRAY_STAGE = r"""
let _pageEnded = false, _dlSeq = 0;
const formatBytes = (n) => n + ' B';
const appended = [];
const el = (tag) => {
    const node = { tag, id: '', className: '', children: [], style: {}, textContent: '',
                   classList: { add() {}, remove() {} }, setAttribute() {}, addEventListener() {},
                   appendChild(c) { node.children.push(c); return c; }, append(...cs) { node.children.push(...cs); },
                   remove() {} };
    return node;
};
const document = {
    getElementById: (id) => appended.find((n) => n.id === id) || null,
    createElement: el,
    body: { appendChild: (n) => { appended.push(n); return n; } },
};
"""


def test_a_page_that_ended_its_session_draws_no_download_tray():
    """A download still settling when the session ended starts its row on no tray of the page: nothing is added to
    the page's body."""
    out = _node(TRAY_STAGE + PROGRESS + _main(
        "_pageEnded = true;\n"
        "downloadProgress._tray(); downloadProgress.start('ana.bin', () => {});\n"
        "const ended = appended.map((n) => n.id || n.tag);\n"
        "_pageEnded = false;\n"
        "downloadProgress.start('ana.bin', () => {});\n"
        "return { ended, open: appended.map((n) => n.id || n.tag) };"))
    assert out["ended"] == [], out
    # The control: on a page with its session the tray is added once, and holds the row.
    assert out["open"] == ["download-tray"], out


# ---- the streaming sink ----------------------------------------------------------------------------------------

SINK_STAGE = r"""
let _pageEnded = false;
const DV_SINK_CLAIM_WAIT_MS = 1000;
const showError = () => {};
const frames = [];
const document = { createElement: (tag) => ({ tag, style: {}, remove() {} }),
                   body: { appendChild: (n) => { frames.push(n.src); return n; } } };
// The download sink's worker: it answers that the download is ready. endDuring: the session ends while the page
// waits for that answer.
let endDuring = false;
const worker = { postMessage(message, ports) {
    if (endDuring) _pageEnded = true;
    ports[0].postMessage({ type: 'dv-sink-ready', url: '/dv-sink/' + message.id, reportsTaken: true });
} };
const dvSinkWorker = async () => worker;
const leg = async (during) => {
    _pageEnded = false; frames.length = 0; endDuring = during;
    const sink = await dvOpenDownloadSink({ filename: 'ana.bin', size: 4, mime: 'text/plain' });
    return { sink: sink === null ? null : typeof sink.write, frames: frames.length };
};
"""


def test_a_sink_whose_handshake_ends_after_the_sign_out_starts_no_download():
    """The session ends while the page waits for the sink's worker to say the download is ready: the page opens no
    download in the browser (no frame) and gives the caller no sink to write into."""
    out = _node(SINK_STAGE + SINK + _main("return { ended: await leg(true), open: await leg(false) };"))
    assert out["ended"] == {"sink": None, "frames": 0}, out
    # The control: with the session open the frame that starts the download is added and a sink is given back.
    assert out["open"] == {"sink": "function", "frames": 1}, out


# ---- the resumed read of a zero-knowledge stream ---------------------------------------------------------------

ZK_STAGE = r"""
const API_BASE = '', ZK_RESUME_ATTEMPTS = 3;
const zkDownloadHeaders = () => ({ 'Authorization': 'Bearer t' });
const isCodedCryptoError = () => false;
const zkResolveKey = async () => ({ dek: 'k', context: 'c' });
const sinkSaid = [];
const dvOpenDownloadSink = async () => ({ write() { sinkSaid.push('write'); }, done() { sinkSaid.push('done'); },
                                          abort(reason) { sinkSaid.push('abort ' + reason); } });
// The read breaks once, as a network does, after one record; beforeBreak runs just before.
let reads = 0, beforeBreak = null;
const lib = {
    _peekStream: async (body) => ({ head: 'H', stream: body }),
    _inspectV2Header: () => 'UNSUPPORTED',
    v2ContentResumeOffset: (head, declared, records) => ({ totalPlaintext: 64, offset: 40 * records, done: false }),
    decryptStreamV2: async (stream, declared, dek, context, onPiece) => {
        reads += 1;
        onPiece(new Uint8Array([1]));
        if (reads === 1) { if (beforeBreak) beforeBreak(); throw new Error('network'); }
    },
};
const eccLib = () => lib;
const asked = [];
const fetch = async (url, opts) => {
    if (opts && opts.signal && opts.signal.aborted) { const e = new Error('aborted'); e.name = 'AbortError'; throw e; }
    asked.push({ range: opts.headers.Range, signal: !!opts.signal });
    return { status: 206, body: {} };
};
const response = { body: {}, headers: { get: (n) => ({ 'Content-Length': '100', 'ETag': '"e1"',
                                                     'Content-Type': 'application/octet-stream' })[n] || null } };
const leg = async (stopDuringRead) => {
    reads = 0; asked.length = 0; sinkSaid.length = 0;
    const ctl = new AbortController();
    beforeBreak = stopDuringRead ? () => ctl.abort() : null;
    const result = await zkTryStreamedDownload(response, { id: 'V' }, 1, 'f', 'ana.bin', ctl);
    return { result, asked: [...asked], sink: [...sinkSaid] };
};
"""


def test_the_resumed_read_of_a_zero_knowledge_stream_is_stopped_with_the_download():
    """A zero-knowledge download streamed into the browser breaks off and is resumed from where it stopped: the
    resuming request carries the download's abort. Stopped meanwhile, nothing more is asked for and the download in
    the browser is failed, not finished."""
    out = _node(ZK_STAGE + ZK_STREAM + _main("return { open: await leg(false), stopped: await leg(true) };"))
    # The control: the read is resumed from the record it stopped at, with the download's signal, and finishes.
    assert out["open"]["result"] is True, out["open"]
    assert out["open"]["asked"] == [{"range": "bytes=40-", "signal": True}], out["open"]
    assert out["open"]["sink"] == ["write", "write", "done"], out["open"]
    # Stopped during the read: no resumed request goes out, and the download is failed.
    assert out["stopped"]["result"] == "failed", out["stopped"]
    assert out["stopped"]["asked"] == [], out["stopped"]
    assert out["stopped"]["sink"] == ["write", "abort reconnect-failed"], out["stopped"]
