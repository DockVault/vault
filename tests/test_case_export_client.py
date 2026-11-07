"""A case export in the page, around a sign-out (static/js/compliance.js: fetchExport, fetchInto, stopExport), run
under Node with the shipped functions lifted out verbatim and the download, the request and the body's read
answered when the test chooses.

Held here: an export too large to read whole asks for the archive only once a download to write it into is open,
and is refused without one; a sign-out while that download is being opened closes it and asks for nothing; a
sign-out stops an export on its way (its request and its download); an archive read after a sign-out is never
handed over; without a sign-out it is (the control). tests/test_ui_case_export_download.py holds the same in a real
browser, on a running stack.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "compliance.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    for head in (f"\n    async function {name}(", f"\n    function {name}("):
        if head in JS:
            start = JS.index(head) + 1
            return JS[start:JS.index("\n    }\n", start) + 7]
    raise AssertionError(f"{name} is gone")


def _line(head: str) -> str:
    start = JS.index("\n    " + head) + 1
    return JS[start:JS.index("\n", start) + 1]


SHIPPED = _line("let EXPORTING") + "".join(_fn(n) for n in (
    "problem", "readWholeMost", "tooLargeToSave", "stopExport", "fetchExport", "fetchInto"))

HARNESS = """
let signIns = 0;
let WS = { c: { id: 'case-1', number: '7' } };
const calls = { cmp: 0, clicks: 0, ok: [], sinkAborts: [], signal: null };
const MAX_BUFFERED_DOWNLOAD_BYTES = 256 * 1024 * 1024;
const formatBytes = (n) => n + ' B';
let sinkAnswer = null;
const dvOpenDownloadSink = () => new Promise((resolve) => { sinkAnswer = resolve; });
const aSink = () => ({ abort: (why) => calls.sinkAborts.push(why) });
let cmpAnswer = null;
const cmp = (path, opts) => { calls.cmp++; calls.signal = opts.signal; return new Promise((resolve, reject) => { cmpAnswer = { resolve, reject }; }); };
const caseUnlockHeader = () => ({});
let streamed = false;
const dvTryStandardStreamedDownload = async () => streamed;
const plural = (n, word) => n + ' ' + word;
const ok = (text) => calls.ok.push(text);
const el = (tag) => ({ tag, click() { calls.clicks++; }, remove() {} });
const document = { body: { appendChild() {} } };
const URL = { createObjectURL: () => 'blob:x', revokeObjectURL() {} };
const tick = () => new Promise((r) => setTimeout(r, 0));
// What forgetStanding does with an export at a sign-out.
const signOut = () => { signIns += 1; stopExport(); };
const outcome = (p) => Promise.race([
  p.then(() => 'done', (e) => 'threw: ' + (e.reason || e.message)),
  new Promise((r) => setTimeout(() => r('pending'), 50)),
]);
const LARGE = { export_id: 'e-large', bytes: 300 * 1024 * 1024, files: 2 };
const SMALL = { export_id: 'e-small', bytes: 10, files: 1 };
"""


def _node(script: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=HARNESS + SHIPPED + "\n(async () => {\n" + script
                          + "\nprocess.exit(0);\n})();\n",
                          capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_large_export_without_a_download_is_refused_and_never_asked_for():
    out = _node("""
const p = fetchExport(LARGE);
await tick();
sinkAnswer(null);
const got = await outcome(p);
console.log(JSON.stringify({ got, cmp: calls.cmp, exporting: EXPORTING }));
""")
    assert out == {"got": "threw: no_download_service", "cmp": 0, "exporting": None}


def test_a_large_export_is_asked_for_once_its_download_is_open_and_streams_into_it():
    out = _node("""
streamed = true;
const p = fetchExport(LARGE);
await tick();
const before = calls.cmp;
sinkAnswer(aSink());
await tick();
cmpAnswer.resolve({ ok: true });
const got = await outcome(p);
console.log(JSON.stringify({ before, got, cmp: calls.cmp, ok: calls.ok.length, aborts: calls.sinkAborts }));
""")
    assert out == {"before": 0, "got": "done", "cmp": 1, "ok": 1, "aborts": []}


def test_a_sign_out_while_the_download_opens_closes_it_and_asks_for_nothing():
    out = _node("""
const p = fetchExport(LARGE);
await tick();
signOut();
sinkAnswer(aSink());
const got = await outcome(p);
console.log(JSON.stringify({ got, cmp: calls.cmp, aborts: calls.sinkAborts, clicks: calls.clicks, ok: calls.ok.length }));
""")
    assert out == {"got": "done", "cmp": 0, "aborts": ["signed-out"], "clicks": 0, "ok": 0}


def test_a_sign_out_stops_an_export_on_its_way_and_its_download():
    out = _node("""
const p = fetchExport(LARGE);
await tick();
sinkAnswer(aSink());
await tick();
const asked = calls.cmp;
signOut();
console.log(JSON.stringify({ asked, aborted: calls.signal.aborted, aborts: calls.sinkAborts, exporting: EXPORTING }));
""")
    assert out == {"asked": 1, "aborted": True, "aborts": ["signed-out"], "exporting": None}


@pytest.mark.parametrize("signed_out", [True, False])
def test_an_archive_read_after_a_sign_out_is_never_handed_over(signed_out):
    out = _node(f"""
const p = fetchExport(SMALL);
await tick();
let read;
cmpAnswer.resolve({{ ok: true, blob: () => new Promise((resolve) => {{ read = resolve; }}) }});
await tick();
if ({json.dumps(signed_out)}) signOut();
read({{}});
const got = await outcome(p);
console.log(JSON.stringify({{ got, clicks: calls.clicks, ok: calls.ok.length, aborted: calls.signal.aborted }}));
""")
    if signed_out:
        assert out == {"got": "done", "clicks": 0, "ok": 0, "aborted": True}
    else:         # the control: handed over, once
        assert out == {"got": "done", "clicks": 1, "ok": 1, "aborted": False}
