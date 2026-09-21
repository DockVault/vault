"""Every place a download refuses a file too large to buffer, RUN, one at a time.

A file over the in-memory ceiling must never be pulled whole into the tab. ``_downloadFile`` refuses
it in four places: before any request when streaming is not going to be tried; on the Standard
branch and on the zero-knowledge branch, each when a streaming attempt comes back "not possible
here"; and once more as a backstop before the buffered read. Three of those four conditions are the
same text, so counting them -- or counting calls to the refusal -- says nothing about any ONE of
them: every site can be dead and a count still comes out right.

So the shipped function is lifted out of ``app.js`` verbatim and run under Node, once per site, with
a file over the ceiling and one under it. Over: the refusal is shown, the body already in hand is
cancelled, nothing further is fetched, and nothing is saved. Under: the download goes on to a save.
The source half then holds each site to its own stretch of the function.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "static" / "js" / "app.js"

CONDITION = "if (_fsize > MAX_BUFFERED_DOWNLOAD_BYTES) {"
PRE_FETCH = "if (state.downloadSink !== 'streaming' && _fsize > MAX_BUFFERED_DOWNLOAD_BYTES) {"


def _download_src(js: str) -> str:
    start = js.index("async function _downloadFile(fileId, fileName) {")
    return js[start:js.index("\n}\n", start) + 3]


def _code(src: str) -> str:
    return "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("//"))


HARNESS = """
const MAX_BUFFERED_DOWNLOAD_BYTES = 100;
const API_BASE = '', authToken = 't';
let _sinkUnavailableReason = null;
const said = [], fetched = [];
let cancelled = 0, saved = 0, zk = false, streamAnswer = false, duringFetch = null;
const state = { currentVault: { id: 'V', has_password: false }, currentFiles: [], downloadSink: 'streaming' };
const showError = (m) => said.push('error'), showInfo = () => {}, showSuccess = () => {};
const formatBytes = (n) => n + ' B';
const isZkVault = () => zk;
const fetch = async (url) => { fetched.push(url); if (duringFetch) duringFetch();
    return { ok: true, body: { cancel: async () => { cancelled++; } } }; };
const dvTryStandardStreamedDownload = async () => streamAnswer;
const zkTryStreamedDownload = async () => streamAnswer;
const zkFileKeyVersion = () => 1;
const zkMaybeDecryptResponse = async () => ({ plaintext: true });
const isCodedCryptoError = () => false, safeMessageForCode = () => '';
const downloadProgress = { start: () => 1, update() {}, done() {} };
const readResponseWithProgress = async () => ({ bytes: true });
const window = { URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} } };
const document = { createElement: () => ({ click() { saved++; } }), body: { appendChild() {}, removeChild() {} } };
%s
const leg = async (setup) => {
    said.length = 0; fetched.length = 0; cancelled = 0; saved = 0; duringFetch = null; streamAnswer = false;
    state.downloadSink = 'streaming'; zk = false;
    setup();
    await _downloadFile('f', 'big.bin');
    return { refused: said.length, fetches: fetched.length, cancelled, saved };
};
const both = async (setup) => ({
    over: await leg(() => { state.currentFiles = [{ id: 'f', size: 1000 }]; setup(); }),
    under: await leg(() => { state.currentFiles = [{ id: 'f', size: 50 }]; setup(); }),
});
(async () => {
    const out = {
        // Streaming is not going to be tried at all: refused before ANY request.
        preFetch: await both(() => { state.downloadSink = 'buffered'; }),
        // A streaming attempt that comes back "not possible here", on each kind of vault.
        standard: await both(() => { zk = false; }),
        zeroKnowledge: await both(() => { zk = true; }),
        // The backstop: the policy says "streaming" when the first guard looks, and no longer does
        // by the time the branches are chosen (it is re-read from the server while the app runs),
        // so neither streaming branch is taken and nothing above has refused.
        backstop: await both(() => { duringFetch = () => { state.downloadSink = 'buffered'; }; }),
    };
    process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def test_each_of_the_four_refusals_refuses_a_file_over_the_ceiling_and_lets_a_small_one_through():
    node = shutil.which("node")
    assert node, "Node is required: the shipped download path must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    done = subprocess.run([node, "-"], input=HARNESS % _download_src(js), capture_output=True, text=True,
                          encoding="utf-8", timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness ended without writing its result"
    out = json.loads(done.stdout)

    # (mutation: `false &&` in front of the first guard -> the file is fetched and saved -> red.)
    assert out["preFetch"]["over"] == {"refused": 1, "fetches": 0, "cancelled": 0, "saved": 0}, out["preFetch"]
    assert out["preFetch"]["under"] == {"refused": 0, "fetches": 1, "cancelled": 0, "saved": 1}, out["preFetch"]

    # The streaming attempt spent the first body. Over the ceiling it is cancelled and NOTHING more
    # is fetched; under it, the body is fetched again for the buffered read, and the file is saved.
    # (mutation: `false &&` in front of THAT branch's condition -> a second fetch and a save -> red.)
    for branch in ("standard", "zeroKnowledge"):
        assert out[branch]["over"] == {"refused": 1, "fetches": 1, "cancelled": 1, "saved": 0}, (branch, out[branch])
        assert out[branch]["under"] == {"refused": 0, "fetches": 2, "cancelled": 0, "saved": 1}, (branch, out[branch])

    # (mutation: `false &&` in front of the backstop -> the over-size file is read whole and saved -> red.)
    assert out["backstop"]["over"] == {"refused": 1, "fetches": 1, "cancelled": 1, "saved": 0}, out["backstop"]
    assert out["backstop"]["under"] == {"refused": 0, "fetches": 1, "cancelled": 0, "saved": 1}, out["backstop"]


def test_each_refusal_is_one_whole_condition_in_its_own_stretch_of_the_function():
    # The source half, on comment-stripped code. Three of the four conditions are the same text, so
    # "exactly once" is asked of each site's OWN stretch -- between that branch's anchors -- never of
    # the function as a whole, where the answer is three whatever any one site does.
    code = _code(_download_src(APP_JS.read_text(encoding="utf-8")))
    assert code.count(PRE_FETCH) == 1
    std, zk_at = code.index("dvTryStandardStreamedDownload("), code.index("zkTryStreamedDownload(")
    # The two RE-fetches for a buffered read (the first request is `let response = ...`).
    refetches = [m.start() for m in re.finditer(r"(?<!let )response = await fetch\(", code)]
    buffered = code.index("let blob;")
    assert len(refetches) == 2 and code.index(PRE_FETCH) < std < refetches[0] < zk_at < refetches[1] < buffered
    stretches = {"standard": code[std:refetches[0]], "zero-knowledge": code[zk_at:refetches[1]],
                 "backstop": code[refetches[1]:buffered]}
    for name, stretch in stretches.items():
        assert stretch.count(CONDITION) == 1, f"the {name} refusal is not exactly one whole condition"
        assert "false &&" not in stretch and "&& false" not in stretch
        # The refusal it guards is right behind it, and ends the download.
        after = stretch[stretch.index(CONDITION):]
        assert after.index("_refuseTooLarge();") < after.index("return;")
    # Nothing else in the function tests the size: four sites, and these are they.
    assert code.count("_fsize > MAX_BUFFERED_DOWNLOAD_BYTES") == 4
