"""A file saved from the page is never handed to the browser under the type its uploader claimed.

A stored MIME type is whatever the uploading browser sent, and an object address (``blob:``) carries the vault's
origin. The page saves a file it has read whole by pointing a link at such an address. A browser that honours the
link's ``download`` attribute saves it; one that does not opens it, and under a page's type what it opens is a page
of this origin. So the address is made under a type a browser only saves, and the file keeps the name the link
gives it.

These tests run the SHIPPED code, lifted verbatim from ``static/js/app.js``, under Node: the download of a file
whose answer came under a page's or a script's type, on a Standard vault and on a zero-knowledge one. The last
test holds every object address the web app makes, in every script, to a form that has been looked at.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from _js_source import strip_comments

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "static" / "js"
APP = (JS / "app.js").read_text(encoding="utf-8")
BYTES = "application/octet-stream"


def _function(head: str) -> str:
    start = APP.index(head)
    return APP[start:APP.index("\n}\n", start) + 3]


DOWNLOAD = _function("async function _downloadFile(fileId, fileName) {")
READ = _function("async function readResponseWithProgress(response, onProgress) {")

STAGE = r"""
const MAX_BUFFERED_DOWNLOAD_BYTES = 1024 * 1024;
const API_BASE = '', authToken = 't';
let _sinkUnavailableReason = null;
const state = { currentVault: { id: 'V', has_password: false }, currentFiles: [{ id: 'f', size: 4 }],
                downloadSink: 'buffered' };
const said = [];
const showError = (m) => said.push('error: ' + m), showInfo = () => {}, showSuccess = (m) => said.push('ok: ' + m);
const formatBytes = (n) => n + ' B';
let zk = false, answerType = '';
const isZkVault = () => zk;
const CONTENT = [60, 104, 49, 62];
// The server's answer: its bytes, under the type the file was stored with.
const fetch = async () => {
    const pieces = [{ done: false, value: new Uint8Array(CONTENT) }, { done: true }];
    return { ok: true, headers: { get: (name) => name === 'Content-Type' ? answerType : null },
             body: { getReader: () => ({ read: async () => pieces.shift() }) } };
};
const dvTryStandardStreamedDownload = async () => false, zkTryStreamedDownload = async () => false;
const zkFileKeyVersion = () => 1;
// What decrypting in the page gives back: a blob under the answer's type, as the shipped code makes it.
const zkMaybeDecryptResponse = async () => new Blob([new Uint8Array(CONTENT)], { type: answerType });
const isCodedCryptoError = () => false, safeMessageForCode = () => '';
const downloadProgress = { start: () => 1, update() {}, done() {} };
const made = [], events = [];
const window = { URL: {
    createObjectURL: (blob) => { made.push(blob); events.push('made'); return 'blob:https://vault/' + made.length; },
    revokeObjectURL: (url) => { events.push('revoked ' + url); },
} };
const document = {
    createElement: (tag) => {
        const link = { tag, click() { events.push('clicked ' + link.href + ' saving ' + link.download); } };
        return link;
    },
    body: { appendChild() { events.push('added'); }, removeChild() { events.push('removed'); } },
};
"""

RUN = r"""
const run = async (type, zeroKnowledge, name) => {
    made.length = 0; events.length = 0; said.length = 0; zk = zeroKnowledge; answerType = type;
    await _downloadFile('f', name);
    return { made: made.map((blob) => blob.type),
             bytes: made.length ? Array.from(new Uint8Array(await made[0].arrayBuffer())) : null,
             events: [...events], said: [...said] };
};
(async () => {
    const out = [];
    for (const [type, zeroKnowledge, name] of CASES) out.push(await run(type, zeroKnowledge, name));
    process.stdout.write(JSON.stringify(out));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""

# (the type the answer came under, a zero-knowledge vault?, the file's name)
CASES = [
    ("application/xhtml+xml", False, "holiday.png"),
    ("text/html", False, "page.html"),
    ("image/svg+xml", False, "drawing.svg"),
    ("text/javascript", False, "code.js"),
    ("application/x-thing+xml", False, "clip.mp4"),
    ("application/pdf", False, "contract.pdf"),
    ("image/png", False, "holiday.png"),
    ("", False, "unnamed"),
    ("application/xhtml+xml", True, "holiday.png"),
    ("text/html", True, "page.html"),
    ("application/octet-stream", True, "sealed.bin"),
]


def _node(script: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8",
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def saved():
    return _node(STAGE + READ + DOWNLOAD + "const CASES = " + json.dumps(CASES) + ";\n" + RUN)


def test_the_harness_reads_the_answer_under_the_type_it_came_with():
    """The control: the shipped reader does give the blob the answer's type, so the test below cannot pass by the
    stand-in page losing the type on the way."""
    out = _node(STAGE + READ + "(async () => { answerType = 'application/xhtml+xml';\n"
                "const blob = await readResponseWithProgress(await fetch(), () => {});\n"
                "process.stdout.write(JSON.stringify({ type: blob.type, size: blob.size })); })();\n")
    assert out == {"type": "application/xhtml+xml", "size": 4}


@pytest.mark.parametrize("index", range(len(CASES)), ids=[f"{t or 'untyped'}{' zk' if z else ''}" for t, z, _ in CASES])
def test_a_saved_file_is_handed_over_as_plain_bytes_under_its_own_name(saved, index):
    _type, _zk, name = CASES[index]
    got = saved[index]
    assert got["said"] == ["ok: File downloaded successfully"], got
    # One address, of a type a browser only saves, with every byte of the file behind it.
    assert got["made"] == [BYTES], got
    assert got["bytes"] == [60, 104, 49, 62]
    # Made, clicked under the file's own name, and withdrawn in the same breath.
    assert got["events"] == ["made", "added", f"clicked blob:https://vault/1 saving {name}", "removed",
                             "revoked blob:https://vault/1"], got


# ---- every object address the web app makes ------------------------------------------------------------------------

# By script, what each address is made from. Only three are made from a blob as it came:
#   activity.js   the activity export, whose type the server fixes itself (CSV or NDJSON);
#   app.js        a picture of the mail editor, which the server types from the picture's own bytes when an
#                 administrator uploads it, and the recovery kit, which the page builds itself as JSON.
# Every other one is re-made under a type the page chose: none takes the type a file was stored with.
OBJECT_ADDRESSES = {
    "activity.js": ["blob"],
    "app.js": [
        "await resp.blob()",
        "blob",
        "new Blob([blob], { type: 'application/octet-stream' })",
        "new Blob([blob], { type: _previewBlobType('image', type, ext) })",
        "new Blob([blob], {\n                type: isPdf ? 'application/pdf' : _previewBlobType(tag, type, ext) })",
    ],
    "public-link.js": ['new Blob([blob], { type: "application/octet-stream" })'],
}


def _addresses(path: Path):
    return re.findall(r"URL\.createObjectURL\((.*?)\);", strip_comments(path.read_text(encoding="utf-8")), flags=re.S)


def test_every_object_address_the_web_app_makes_is_one_of_the_known_ones():
    found = {path.name: _addresses(path) for path in sorted(JS.glob("*.js"))}
    assert {name: made for name, made in found.items() if made} == OBJECT_ADDRESSES
    # Nothing makes one by another spelling of the call.
    for path in sorted(JS.glob("*.js")):
        code = strip_comments(path.read_text(encoding="utf-8"))
        assert code.count("createObjectURL") == len(OBJECT_ADDRESSES.get(path.name, [])), path.name


def test_the_three_made_from_a_blob_as_it_came_are_never_a_stored_file():
    app = strip_comments(APP)
    activity = strip_comments((JS / "activity.js").read_text(encoding="utf-8"))
    # The recovery kit: built by the page, as JSON, on the line before.
    assert ("const blob = new Blob([JSON.stringify(kit, null, 2)], { type: 'application/json' });\n"
            "    const url = URL.createObjectURL(blob);") in app
    # A picture of the mail editor: the answer of the mail pictures' own route.
    thumb = app[app.index("async function buildImageThumb(res) {"):]
    thumb = thumb[:thumb.index("\n}\n")]
    assert thumb.count("fetch(") == 1 and "fetch(`${API_BASE}/email/resources/${res.id}`" in thumb
    assert "URL.createObjectURL(await resp.blob())" in thumb
    # The activity export: the answer of the export route.
    export = activity[activity.index("async function exportEvents(fmt) {"):]
    export = export[:export.index("URL.createObjectURL(blob)")]
    assert export.count("fetch(") == 1 and "fetch(`${API_BASE}/activity/export?${p.toString()}`" in export
    assert export.count("const blob = ") == 1 and "const blob = await resp.blob();" in export
