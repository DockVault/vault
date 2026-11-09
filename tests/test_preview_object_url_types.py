"""The file preview never mints an object URL under the type the uploader sent.

A stored MIME type is whatever the uploading browser claimed. An object URL (``blob:``) carries this
vault's origin, and a tab that opens one as a page of its own runs it with none of the page's
Content-Security-Policy. So a picture stored as ``application/xhtml+xml`` or ``image/svg+xml`` would
run its script with this origin and could read the sign-in token. The preview therefore re-mints
every image, video and audio blob under a type that cannot be a page, shows an SVG from a ``data:``
address (an opaque origin), and never turns text into a URL at all.

These tests run the SHIPPED code, lifted verbatim from ``static/js/app.js``, under Node: the type
rule on its own, and the whole ``openFilePreview`` against a stand-in page over every combination of
stored type, extension, vault kind and size. Opening the preview's address in a tab of its own is
the UI lane (``test_ui_preview_object_urls.py``).
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _block(head: str, end: str) -> str:
    start = APP.index(head)
    return APP[start:APP.index(end, start) + len(end)]


TYPE_RULE = (_block("const _PREVIEW_TYPE_BY_EXT = {", "\n};\n")
             + _block("function _previewBlobType(kind, type, ext) {", "\n}\n")
             + _block("function _previewAsSvg(type, ext) {", "\n}\n"))
PREVIEW = _block("async function openFilePreview(", "\nfunction closeFilePreview(")[:-len("\nfunction closeFilePreview(")]
CLOSE = _block("function closeFilePreview() {", "\n}\n")

# A type the preview may mint: a PDF, a download-only type, or an image, video or audio type with
# nothing in it a browser could run as a page.
INERT = re.compile(r"^(?:application/pdf|application/octet-stream|(?:image|video|audio)/[a-z0-9.+-]+)$")
ACTIVE = re.compile(r"svg|xml|html")


def _node(body: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8",
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


def _inert(t: str) -> bool:
    return bool(INERT.match(t)) and not ACTIVE.search(t)


# ---- the type rule on its own --------------------------------------------------------------------

CASES = [
    # (kind, stored type, extension) -> the type the object URL is minted under
    (("image", "image/png", "png"), "image/png"),
    (("image", "IMAGE/JPEG; charset=binary", "jpg"), "image/jpeg"),
    (("image", "application/xhtml+xml", "png"), "image/png"),
    (("image", "text/html", "jpg"), "image/jpeg"),
    (("image", "image/svg+xml", "png"), "image/png"),
    (("image", "image/svg", "gif"), "image/gif"),
    (("image", "image/x-thing+xml", "dat"), "application/octet-stream"),
    (("image", "image/pngé", "png"), "image/png"),
    (("image", "image/png,text/html", "png"), "image/png"),
    (("image", "", "bmp"), "image/bmp"),
    (("image", "", "svg"), "application/octet-stream"),
    (("image", "image/avif", "avif"), "image/avif"),
    (("image", "image/avif; q=1", "bin"), "image/avif"),
    (("video", "video/mp4", "mp4"), "video/mp4"),
    (("video", "video/x-matroska", "mkv"), "video/x-matroska"),
    (("video", "application/xhtml+xml", "webm"), "video/webm"),
    (("video", "image/png", "mov"), "video/quicktime"),
    (("video", "text/html", "png"), "application/octet-stream"),
    (("audio", "audio/flac", "flac"), "audio/flac"),
    (("audio", "text/html", "mp3"), "audio/mpeg"),
    (("audio", "audio/x-thing+xml", "wav"), "audio/wav"),
    (("audio", "audio/ogg ,text/xsl", "ogg"), "application/octet-stream"),
]


def test_the_minted_type_is_never_one_a_browser_can_run_as_a_page():
    out = _node(TYPE_RULE + "process.stdout.write(JSON.stringify("
                + json.dumps([list(c) for c, _ in CASES])
                + ".map(([k, t, e]) => _previewBlobType(k, t, e))));")
    assert out == [want for _, want in CASES]
    assert all(_inert(t) for t in out), out


def test_only_an_svg_type_or_an_untyped_svg_name_is_drawn_as_svg():
    cases = [(("image/svg+xml", "svg"), True), (("IMAGE/SVG+XML; x=1", "png"), True), (("", "svg"), True),
             (("application/octet-stream", "svg"), True), (("image/png", "svg"), False),
             (("image/jpeg", "svg"), False), (("image/png", "png"), False), (("", "png"), False)]
    out = _node(TYPE_RULE + "process.stdout.write(JSON.stringify("
                + json.dumps([list(c) for c, _ in cases]) + ".map(([t, e]) => _previewAsSvg(t, e))));")
    assert out == [want for _, want in cases]


# ---- the whole preview, every combination --------------------------------------------------------

LIFTED = "\n".join([
    TYPE_RULE,
    _block("function _blobToDataUrl(blob) {", "\n}\n"),
    _block("const MEDIA_PREVIEW_MAX_BYTES", ";"),
    _block("const SVG_PREVIEW_MAX_BYTES", ";"),
    _block("const TEXT_PREVIEW_WINDOW_BYTES", ";"),
    _block("const LARGE_MEDIA_EXTS = new Set([", "]);"),
    _block("const WINDOWABLE_TEXT_EXTS = new Set([", "]);"),
    _block("const RENDERABLE_PREVIEW_EXTS = new Set([", "]);"),
    PREVIEW,
    CLOSE,
])

STAGE = r"""
const minted = [], srcs = [], fetched = []; let branch = null, _previewUrl = null;
class El {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.attrs = {};
    const cls = new Set(); this.classList = { add: (c) => cls.add(c), remove: (c) => cls.delete(c),
    contains: (c) => cls.has(c) }; this._src = ''; this.textContent = ''; }
  set src(v) { this._src = v; srcs.push([this.tagName, String(v).slice(0, 80)]); }
  get src() { return this._src; }
  setAttribute(k, v) { this.attrs[k] = v; } append(...c) { this.children.push(...c); }
  appendChild(c) { this.children.push(c); } replaceChildren(...c) { this.children = c; }
}
const bodyEl = new El('div');
global.document = { getElementById: (id) => id === 'file-preview-body' ? bodyEl : new El('x'),
                    createElement: (t) => new El(t) };
global.FileReader = class { readAsDataURL(b) { b.arrayBuffer().then((buf) => {
  this.result = 'data:' + b.type + ';base64,' + Buffer.from(buf).toString('base64'); this.onload(); }); } };
URL.createObjectURL = (b) => { minted.push(b.type); return 'blob:https://vault/' + minted.length; };
URL.revokeObjectURL = () => {};
global.navigator = { pdfViewerEnabled: true };
const API_BASE = 'https://vault', authToken = 't';
const state = { currentVault: { id: 'v1', has_password: false, type: 'standard' }, currentFiles: [] };
const isZkVault = (v) => v && v.type === 'zero_knowledge';
const zkFileKeyVersion = () => 1;
async function zkMaybeDecryptResponse(resp) { return resp.blob(); }
function _renderPreviewTooLarge() { branch = 'too-large'; }
function _renderPdfNotInline() { branch = 'pdf-not-inline'; }
async function _renderTextWindow() { branch = 'text-window'; }
function _buildRenderablePreview() { branch = 'renderable'; return new El('div'); }
const buildZoomControls = () => ({ el: new El('div') }), setupImageZoom = () => {}, iconSvg = () => '';
const isCodedCryptoError = () => false, safeMessageForCode = () => '', downloadFile = () => {};
const failures = [];
console.error = (...a) => failures.push(a.map(String).join(' '));
async function run(name, mime, size, zk, bytes) {
  minted.length = 0; srcs.length = 0; fetched.length = 0; branch = null; failures.length = 0;
  state.currentVault.type = zk ? 'zero_knowledge' : 'standard';
  state.currentFiles = [{ id: 'f', size }];
  global.fetch = async (u) => { fetched.push(u); return { ok: true,
    blob: async () => new Blob([bytes], { type: String(mime).replace(/[^\x20-\x7e]/g, '') }) }; };
  await openFilePreview('f', name, mime);
  return { name, mime, size, zk, branch, minted: [...minted], srcs: srcs.map((s) => s.join(' ')),
           fetched: fetched.length, failures: [...failures] };
}
"""


def _walk(script: str):
    return _node(LIFTED + STAGE + "(async () => {\n" + script + "\n})().catch((e) => { console.log(String(e && e.stack)); process.exit(1); });")


MIMES = ["", "image/png", "IMAGE/PNG", "image/svg+xml", "image/svg", "IMAGE/SVG+XML; charset=utf-8",
         "application/xhtml+xml", "text/html", "text/xml", "application/xml", "multipart/x-mixed-replace",
         "image/png,text/html", "image/pngé", "image/png\u0000", "video/mp4", "video/html",
         "audio/x-thing+xml", "application/pdf", "text/plain", "application/octet-stream", "image/avif",
         "video/x-matroska", "audio/mp4", "image/x-foo+xml", "text/html; x=pdf", "application/x-pdf+xml",
         "image/vnd.microsoft.icon", "text/xsl", "audio/ogg ,text/xsl", "image/heic", "image/tiff"]
EXTS = ["png", "svg", "html", "xhtml", "xml", "mp4", "mp3", "pdf", "txt", "bin", "avif", "webm", None]
PAGE = '<html xmlns="http://www.w3.org/1999/xhtml"><script>document.title="ran"</script></html>'


def test_no_combination_mints_an_address_a_browser_could_run_as_a_page():
    rows = _walk(
        f"const MIMES = {json.dumps(MIMES)}, EXTS = {json.dumps(EXTS)}, PAGE = {json.dumps(PAGE)};\n"
        "const rows = [];\n"
        "for (const zk of [false, true]) for (const big of [false, true]) for (const mime of MIMES) for (const ext of EXTS) {\n"
        "  const size = big ? 3 * 1024 * 1024 : PAGE.length;\n"
        "  rows.push(await run(ext ? 'file.' + ext : 'file', mime, size, zk, big ? Buffer.alloc(size, 'a') : Buffer.from(PAGE)));\n"
        "}\n"
        "process.stdout.write(JSON.stringify(rows));")
    assert len(rows) == 2 * 2 * len(MIMES) * len(EXTS)
    bad = []
    for r in rows:
        assert not r["failures"], r
        bad += [(r["name"], r["mime"], t) for t in r["minted"] if not _inert(t)]
        bad += [(r["name"], r["mime"], s[:60]) for s in r["srcs"]
                if " data:" in s and not s.split(" ", 1)[1].startswith("data:image/svg+xml;")]
        bad += [(r["name"], r["mime"], s[:60]) for s in r["srcs"]
                if not (s.split(" ", 1)[1].startswith(("blob:https://vault/", "data:image/svg+xml;")))]
    assert not bad, bad[:20]
    # The walk reached every kind of preview, so the property above is not vacuous.
    assert {r["branch"] for r in rows} >= {None, "renderable"}
    tags = {s.split(" ", 1)[0] for r in rows for s in r["srcs"]}
    assert tags == {"img", "video", "audio", "iframe"}, tags
    assert any(s.startswith("img data:image/svg+xml;") for r in rows for s in r["srcs"])


def test_each_kind_still_shows_and_is_minted_under_its_own_type():
    out = _walk(
        "const b = Buffer.from('x'); const o = {};\n"
        "o.png = await run('a.png', 'image/png', 1, false, b);\n"
        "o.pageAsPng = await run('a.png', 'application/xhtml+xml', 1, false, b);\n"
        "o.svg = await run('a.svg', 'image/svg+xml', 1, false, b);\n"
        "o.pngNamedSvg = await run('a.svg', 'image/png', 1, false, b);\n"
        "o.zkSvg = await run('a.svg', '', 1, true, b);\n"
        "o.mp4 = await run('a.mp4', 'application/xhtml+xml', 1, false, b);\n"
        "o.mp3 = await run('a.mp3', 'audio/mpeg', 1, false, b);\n"
        "o.pdf = await run('a.pdf', 'application/x-pdf+xml', 1, false, b);\n"
        "o.text = await run('a.txt', 'text/html', 1, false, b);\n"
        "o.none = await run('a.bin', 'application/xhtml+xml', 1, false, b);\n"
        "process.stdout.write(JSON.stringify(o));")
    assert out["png"]["minted"] == ["image/png"] and out["png"]["srcs"] == ["img blob:https://vault/1"]
    assert out["pageAsPng"]["minted"] == ["image/png"]
    assert out["svg"]["minted"] == [] and out["svg"]["srcs"][0].startswith("img data:image/svg+xml;base64,")
    assert out["pngNamedSvg"]["minted"] == ["image/png"]
    assert out["zkSvg"]["minted"] == [] and out["zkSvg"]["srcs"][0].startswith("img data:image/svg+xml;")
    assert out["mp4"]["minted"] == ["video/mp4"] and out["mp4"]["srcs"][0].startswith("video blob:")
    assert out["mp3"]["minted"] == ["audio/mpeg"] and out["mp3"]["srcs"][0].startswith("audio blob:")
    assert out["pdf"]["minted"] == ["application/pdf"] and out["pdf"]["srcs"][0].startswith("iframe blob:")
    assert out["text"]["minted"] == [] and out["text"]["srcs"] == []
    assert out["none"]["minted"] == [] and out["none"]["srcs"] == []


def test_a_large_svg_is_offered_as_a_download_and_never_copied_into_an_address():
    out = _walk(
        "const big = 21 * 1024 * 1024, o = {};\n"
        "o.listed = await run('a.svg', 'image/svg+xml', big, false, Buffer.from('x'));\n"
        "state.currentFiles = [];\n"
        "o.unlisted = await (async () => { minted.length = 0; srcs.length = 0; fetched.length = 0; branch = null;\n"
        "  global.fetch = async () => ({ ok: true, blob: async () => new Blob([Buffer.alloc(big)], { type: 'image/svg+xml' }) });\n"
        "  await openFilePreview('f', 'a.svg', 'image/svg+xml');\n"
        "  return { branch, srcs: [...srcs], fetched: 1 }; })();\n"
        "o.pngNamedSvg = await run('a.svg', 'image/png', big, false, Buffer.from('x'));\n"
        "process.stdout.write(JSON.stringify(o));")
    # Listed at its size: refused before anything is fetched.
    assert out["listed"]["branch"] == "too-large" and out["listed"]["fetched"] == 0
    # Its size unknown until fetched (a zero-knowledge listing, say): refused before the copy.
    assert out["unlisted"]["branch"] == "too-large" and out["unlisted"]["srcs"] == []
    # A picture that is not an SVG keeps the media limit, not the SVG one.
    assert out["pngNamedSvg"]["branch"] is None and out["pngNamedSvg"]["minted"] == ["image/png"]


def test_closing_the_preview_drops_what_it_drew():
    out = _walk(
        "await run('a.svg', 'image/svg+xml', 1, false, Buffer.from('x'));\n"
        "const before = bodyEl.children.length; bodyEl.classList.add('preview-has-image');\n"
        "closeFilePreview();\n"
        "process.stdout.write(JSON.stringify({ before, after: bodyEl.children.length,\n"
        "  image: bodyEl.classList.contains('preview-has-image') }));")
    assert out == {"before": 1, "after": 0, "image": False}


def test_every_object_url_in_the_preview_takes_a_type_of_its_own():
    """A new mint added to the preview must take one of the two typed forms, never the bytes' own."""
    args = re.findall(r"URL\.createObjectURL\((.*?)\);", PREVIEW, flags=re.S)
    allowed = {
        "new Blob([blob], { type: _previewBlobType('image', type, ext) })",
        "new Blob([blob], {\n                type: isPdf ? 'application/pdf' : _previewBlobType(tag, type, ext) })",
    }
    assert len(args) == 2 and set(args) == allowed, args
