"""Four guards in the upload path, each RUN with its condition true and false.

Each of these had a pin already, and each pin was a count-and-order check on the source: the guarded
line present exactly once, in its place. Every one of them stayed green with `if (false)` written on
the line above -- the string intact, the count one, the order unchanged, the behaviour dead. A pin on
the shape of code is a smoke alarm; it is not the claim. The claim is made here by lifting the
shipped code verbatim into the same Node harness that already drives the send loop, and DRIVING it:

* the zero-knowledge over-threshold guard in ``uploadFiles`` -- a file the uploader's context could
  never download again is refused BEFORE anything is sealed, and the rest of the drop still goes;
* the refused-entry filter in ``uploadFiles`` -- a refused entry leaves the batch WITH the
  destructive step it carried, so a refused overwrite cannot delete the original it will not replace;
* the per-chunk MAC persist in ``_run`` -- each frame's MAC is on disk BEFORE its bytes go out;
* the MAC-mismatch restart in ``_reopenPipelined`` -- a resume handed a different file, or a frame
  the record cannot vouch for, becomes a NEW attempt under a new token, never a continuation.
"""
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

from _js_source import strip_comments  # noqa: E402
from test_upload_tray_controls import _method, _node, _serve  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "static" / "js" / "app.js"


def _function(js: str, head: str) -> str:
    """One top-level function, verbatim, from its head to its closing `}` at column 0."""
    start = js.index(head)
    return js[start:js.index("\n}\n", start) + 3]


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


# ---- uploadFiles: the over-threshold guard and the refused-entry filter --------------------------------

UPLOAD_FILES = """
const API_BASE = '';
const MAX_BUFFERED_DOWNLOAD_BYTES = 100;
const formatBytes = (n) => n + ' B';
const said = [];
const showError = (m) => said.push(m);
const enqueued = [];
const state = { currentVault: { id: 'V', zk: true }, currentFolderId: null, currentFiles: [], downloadSink: 'buffered',
                canWriteCurrentVault: true };
const isZkVault = (v) => !!(v && v.zk);
const zkGetCurrentDekVersion = async () => 1;
const zkGetVaultDek = async () => 'dek';
const zkNewObjId = () => 'obj-' + (zkNewObjId.n = (zkNewObjId.n || 0) + 1);
const zkNewBlobId = () => 'blob';
const zkUploadNameCandidates = async () => ['bi'];
const isCodedCryptoError = () => false, safeMessageForCode = () => '';
const sealed = [];                                 // every name the library was asked to seal
const lib = { ZK_CONTENT_WRITE_V2: true,
    nameBlindIndex: async (name) => 'bi:' + name,
    encryptName: async (name) => { sealed.push(name); return 'enc:' + name; },
    encryptFile: async () => new Uint8Array(1) };
const eccLib = () => lib;
let answer = { action: 'skip' };                  // the user's answer to a same-name question
const resolveUploadConflict = async () => answer;
const uploadManager = { items: new Map(), _samePlace: () => true, _holdsName: () => true,
    _sameNameRows: () => [], _knownFrom: (rows) => ({ rows }),
    enqueueNamed(list, place) { enqueued.push(...list.map(e => ({ name: e.name, size: e.file.size,
        sealedFrameByFrame: !!e.zkPlain, refusedButQueued: !e.zkPlain, replaces: e.replaces || null }))); } };
class File { constructor(parts, name, opts) { this.name = name; this.size = parts.reduce((n, p) => n + (p.byteLength || p.size || 0), 0); this.type = (opts || {}).type || ''; }
    slice() { return this; } async arrayBuffer() { return new ArrayBuffer(this.size); } }
const file = (name, size) => ({ name, size, type: '', arrayBuffer: async () => new ArrayBuffer(size) });
%s
const drop = async (files, setup) => {
    said.length = 0; enqueued.length = 0; sealed.length = 0; answer = { action: 'skip' };
    state.downloadSink = 'buffered'; state.currentFiles = []; lib.ZK_CONTENT_WRITE_V2 = true;
    if (setup) setup();
    await uploadFiles(files);
    return { said: said.slice(), enqueued: enqueued.slice(), sealed: sealed.slice() };
};
(async () => {
    const out = {};
%s
    process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def _upload_files(scenarios: str) -> dict:
    js = _js()
    lifted = "".join(_function(js, h) for h in (
        "async function uploadFiles(files) {", "function zkUploadDecision(size, sink, threshold) {",
        "function uniqueUploadName(name, existing) {"))
    return _node(UPLOAD_FILES % (lifted, scenarios))


def test_a_file_the_uploaders_context_could_never_download_is_refused_before_anything_is_sealed():
    out = _upload_files("""
    // A context that cannot stream a download: the big file is refused, the small one goes.
    out.buffered = await drop([file('big.bin', 1000), file('small.bin', 50)]);
    // A streaming context: the same drop is unrestricted.
    out.streaming = await drop([file('big.bin', 1000), file('small.bin', 50)], () => { state.downloadSink = 'streaming'; });
    // The policy is not known: refused too, with the wording that asks for a retry, not the browser blamed.
    out.unknown = await drop([file('big.bin', 1000)], () => { state.downloadSink = undefined; });
    """)
    b = out["buffered"]
    # (mutation: `if (false)` on the line above the guard -> the big file is enqueued, sealed frame
    # by frame, and this round's first medium is back -> red.)
    assert [e["name"] for e in b["enqueued"]] == ["small.bin"], b
    assert b["enqueued"][0]["sealedFrameByFrame"] is True
    assert len(b["said"]) == 1 and "too large to download in this context" in b["said"][0], b
    # Nothing of the refused file was sealed: not its name, and it never reached the uploader.
    assert b["sealed"] == ["small.bin"], b
    s = out["streaming"]
    assert [e["name"] for e in s["enqueued"]] == ["big.bin", "small.bin"] and s["said"] == [], s
    u = out["unknown"]
    assert u["enqueued"] == [] and len(u["said"]) == 1 and "download policy is known" in u["said"][0], u


def test_a_refused_entry_leaves_the_batch_with_the_destructive_step_it_carried():
    out = _upload_files("""
    // 'big.bin' already exists as file F; the user answers "replace". The entry carries the delete
    // of F. It is then refused (over the threshold in a buffered context) -- and must leave WITH
    // that delete, or the uploader would remove F for a file that will never replace it.
    out.refusedOverwrite = await drop([file('big.bin', 1000), file('small.bin', 50)], () => {
        state.currentFiles = [{ id: 'F', name: 'big.bin', type: 'file' }];
        answer = { action: 'overwrite' };
    });
    // The same answer for a file that is NOT refused: the step travels with the entry to the uploader.
    out.keptOverwrite = await drop([file('big.bin', 1000)], () => {
        state.currentFiles = [{ id: 'F', name: 'big.bin', type: 'file' }];
        state.downloadSink = 'streaming';
        answer = { action: 'overwrite' };
    });
    """)
    r = out["refusedOverwrite"]
    # (mutation: `if (false)` on the line above the filter -> the refused entry is enqueued,
    # unsealed, with `replaces.deleteId === 'F'` -> red.)
    assert [e["name"] for e in r["enqueued"]] == ["small.bin"], r
    assert all(e["replaces"] is None for e in r["enqueued"]), r
    assert not any(e["refusedButQueued"] for e in r["enqueued"]), r
    k = out["keptOverwrite"]
    assert len(k["enqueued"]) == 1 and k["enqueued"][0]["replaces"]["deleteId"] == "F", k


# ---- _run: each frame's MAC is persisted BEFORE its chunk is sent ------------------------------------

def test_each_chunks_frame_macs_are_on_disk_before_its_bytes_go_out():
    js = _js()
    seal = _method(js, "async _sealUploadChunk(it, index) {")
    frames = _function(js, "function zkUploadChunkFrames(index, totalFrames, framesPerChunk) {")
    out = _serve(frames + """
    const ZK_FRAMES_PER_UPLOAD_CHUNK = 2;
    um._openZkStream = async () => {};
    // The real sealer, fed by a writer session that returns one MAC per frame.
    um._sealUploadChunk = (function () { return { """ + seal + """ }; })()._sealUploadChunk;
    const persisted = [];                        // what the record held, each time it was written
    um._persistResume = async (it) => { persisted.push({ at: log.length, macs: it.frameMacs.slice() }); };
    const stream = { totalChunks: 6, header: () => new Uint8Array(28),
        sealFrame: async (f) => ({ mac: 'mac' + f, frame: new Uint8Array(4) }) };
    // Three chunks of two frames each; nothing on the server yet.
    const it = sent('z', 'z-sess', { isZk: true, zkPipelined: true, zkStream: stream, frameMacs: [],
        clientFileId: 'obj', totalChunks: 3, chunkSize: 8, received: new Set(), lastPut: null, replaces: null });
    fresh(it);
    server.puts = [0, 1, 2].map(i => ({ ok: true, status: 200, json: async () => ({ complete: i === 2, bytes_received: 10 }) }));
    await um._run('z');
    out.puts = log.filter(e => e.startsWith('PUT ')).map(e => log.indexOf(e));
    out.persisted = persisted;
    out.status = row('z').status;
    out.macs = it.frameMacs;
    """)
    assert out["status"] == "done", out
    assert out["macs"] == ["mac0", "mac1", "mac2", "mac3", "mac4", "mac5"]
    # (mutation: `if (false)` on the line above the persist -> nothing is ever persisted -> red.
    #  mutation: persist AFTER the PUT -> the record written before chunk i's PUT lacks chunk i's
    #  MACs -> red.)
    assert len(out["puts"]) == 3
    for i, put_at in enumerate(out["puts"]):
        before = [p for p in out["persisted"] if p["at"] <= put_at]
        assert before, "chunk %d went out with no record written first" % i
        held = before[-1]["macs"]
        want = ["mac%d" % f for f in range(2 * i, 2 * i + 2)]
        assert held[2 * i:2 * i + 2] == want, "chunk %d went out before its MACs were on disk: %r" % (i, held)


# ---- _reopenPipelined: a different file becomes a new attempt, never a continuation --------------------

REOPEN = """
const API_BASE = '';
const said = [], log = [];
const showError = (m) => said.push(m);
const isCodedCryptoError = (e) => !!(e && e.code), safeMessageForCode = () => 'coded';
const zkGetVaultDek = async () => 'dek';
const ZK_FRAMES_PER_UPLOAD_CHUNK = 2;
let held = [];                                    // what the server says it holds
const fetch = async (url) => { log.push('GET ' + url); return { ok: true, json: async () => ({ received_chunks: held }) }; };
// The writer session for a given file: its frame MACs are a function of the file's bytes.
const lib = { resumeContentV2Encryption: async (file, dek, ctx, st) => ({ totalChunks: 6, blobId: 'blob-' + file.bytes,
    frameMac: async (f) => file.bytes + ':' + f }) };
const eccLib = () => lib;
%s
const um = {
    _vaultHeaders() { return {}; },
    _restartAsNewAttempt(it, file) { log.push('restart'); this.restarted = { it: it.id, file: file.bytes }; },
    _start(it) { log.push('start'); this.started = it.id; },
%s
};
const attempt = async (fileBytes, serverHeld, record) => {
    said.length = 0; log.length = 0; um.restarted = null; um.started = null; held = serverHeld;
    const it = { id: 'r', vaultId: 'V', sessionId: 'old-sess', clientFileId: 'obj', zkKeyVersion: 1,
        zkResume: record, received: new Set(), needsServerSync: true };
    await um._reopenPipelined(it, { size: 100, bytes: fileBytes });
    return { log: log.slice(), restarted: um.restarted, started: um.started, said: said.slice(),
             continued: !!it.zkStream, received: [...it.received], blobId: it.blobId || null };
};
// The record a first attempt on file 'A' left: its MACs, for all six frames.
const recordOfA = () => ({ totalPlaintext: 100, frameMacs: [0, 1, 2, 3, 4, 5].map(f => 'A:' + f) });
(async () => {
    const out = {};
%s
    process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def _reopen(scenarios: str) -> dict:
    js = _js()
    frames = _function(js, "function zkUploadChunkFrames(index, totalFrames, framesPerChunk) {")
    return _node(REOPEN % (frames, _method(js, "async _reopenPipelined(it, file) {"), scenarios))


def test_a_resume_handed_a_different_file_becomes_a_new_attempt_and_never_continues_under_the_old_token():
    out = _reopen("""
    // The same file the record was made from: every held frame checks out; the upload continues.
    out.same = await attempt('A', [0, 1], recordOfA());
    // A DIFFERENT file of the same size: the held frames do not check out -> a new attempt.
    out.edited = await attempt('B', [0, 1], recordOfA());
    // The same file, but a held frame the record cannot vouch for (no MAC stored): a new attempt.
    const partial = recordOfA(); partial.frameMacs[3] = undefined;
    out.unvouched = await attempt('A', [0, 1], partial);
    // A different size: a new attempt, before the server is even asked.
    out.resized = await attempt('A', [0], { totalPlaintext: 99, frameMacs: recordOfA().frameMacs });
    // Nothing held yet: nothing to check, so the record's file continues.
    out.nothingHeld = await attempt('B', [], recordOfA());
    """)
    s = out["same"]
    assert s["started"] == "r" and s["restarted"] is None and s["continued"] is True, s
    assert s["received"] == [0, 1] and s["blobId"] == "blob-A", s
    # (mutation: `if (false)` on the line above the restart inside the frame loop -> the edited file
    # CONTINUES under the old token with the server's frames of the other file -> red.)
    for key in ("edited", "unvouched"):
        r = out[key]
        assert r["restarted"] == {"it": "r", "file": "A" if key == "unvouched" else "B"}, (key, r)
        assert r["started"] is None and r["continued"] is False and r["received"] == [], (key, r)
        assert r["log"][-1] == "restart" and r["log"].count("start") == 0, (key, r)
    rs = out["resized"]
    assert rs["restarted"] == {"it": "r", "file": "A"} and rs["log"] == ["restart"], rs
    n = out["nothingHeld"]
    assert n["started"] == "r" and n["restarted"] is None, n


# ---- the smoke alarms: the shape, on code with every comment gone ------------------------------------

def test_the_four_guarded_lines_are_where_they_were_on_comment_free_code():
    # The claim above is behavioural. This only says the lines still exist ONCE each, on code with
    # block and trailing comments gone too -- so a line commented out at the end of another cannot
    # satisfy it. It is a smoke alarm beside the driven tests, never the guard.
    js = _js()
    up = strip_comments(_function(js, "async function uploadFiles(files) {"))
    assert up.count("if (zkUploadDecision(entry.file.size, state.downloadSink, MAX_BUFFERED_DOWNLOAD_BYTES) === 'refuse') {") == 1
    assert up.count("if (refused.size) toUpload = toUpload.filter(e => !refused.has(e));") == 1
    run = strip_comments(_method(js, "async _run(id) {"))
    assert run.count("await this._persistResume(it);") == 1
    assert run.index("buf = await this._sealUploadChunk(it, i);") < run.index("await this._persistResume(it);") \
        < run.index("method: 'PUT',")
    reopen = strip_comments(_method(js, "async _reopenPipelined(it, file) {"))
    assert reopen.count("return await this._restartAsNewAttempt(it, file);") == 2


# ---- the stripper the smoke alarms stand on -------------------------------------------------------------

def test_the_comment_stripper_removes_every_kind_of_comment_and_nothing_else():
    src = ("const a = 'https://x/y'; // trailing\n"
           "/* block\n   spanning */ const b = `t ${ fn('/*not*/') } u`;\n"
           "const re = /\/\/[^/]*\/\*/g; // a regex holding both comment openers\n"
           "// whole line\n"
           "const c = \"//\";\n")
    out = strip_comments(src)
    # Strings, templates and regular expressions are untouched -- a `//` inside them is not a comment.
    assert "'https://x/y'" in out and "`t ${ fn('/*not*/') } u`" in out and "/\/\/[^/]*\/\*/g" in out
    assert '"//"' in out
    # Every comment is gone, and the line count is the file's.
    assert "trailing" not in out and "block" not in out and "spanning" not in out and "whole line" not in out
    assert "regex holding" not in out
    assert out.count("\n") == src.count("\n")


def test_the_stripped_application_still_parses_and_holds_no_comment():
    # Run on the real file: what is left is JavaScript Node can parse (so no string or regular
    # expression was cut through), with no comment opener outside a string left in it.
    import re
    import shutil
    import subprocess
    import tempfile
    src = _js()
    out = strip_comments(src)
    assert out.count("\n") == src.count("\n")
    assert not re.search(r"^\s*//", out, re.M)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(out)
    try:
        node = shutil.which("node")
        assert node, "Node is required"
        r = subprocess.run([node, "--check", f.name], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr[-1500:]
    finally:
        Path(f.name).unlink(missing_ok=True)
