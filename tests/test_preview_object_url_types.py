"""The file preview never mints an object URL under the type the uploader sent.

A stored MIME type is whatever the uploading browser claimed. An object URL (``blob:``) carries this
vault's origin, and a tab that opens one as a page of its own runs it with none of the page's
Content-Security-Policy. So a picture stored as ``application/xhtml+xml`` or ``image/svg+xml`` would
run its script with this origin and could read the sign-in token. The preview therefore re-mints
every image, video and audio blob under a type that cannot be a page, shows an SVG from a ``data:``
address (an opaque origin), and never turns text into a URL at all.

The type rule runs under Node, lifted verbatim from ``static/js/app.js``; the source pins hold the
preview to that rule. Opening the preview's address in a tab of its own is the UI lane
(``test_ui_preview_object_urls.py``).
"""
import json
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
             + _block("function _previewBlobType(kind, type, ext) {", "\n}\n"))
PREVIEW = _block("async function openFilePreview(", "\nfunction closeFilePreview(")


def _node(body: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8",
                          timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


CASES = [
    # (kind, stored type, extension) -> the type the object URL is minted under
    (("image", "image/png", "png"), "image/png"),
    (("image", "IMAGE/JPEG; charset=binary", "jpg"), "image/jpeg"),
    (("image", "application/xhtml+xml", "png"), "image/png"),
    (("image", "text/html", "jpg"), "image/jpeg"),
    (("image", "image/svg+xml", "png"), "image/png"),
    (("image", "image/svg", "gif"), "image/gif"),
    (("image", "image/x-thing+xml", "dat"), "application/octet-stream"),
    (("image", "", "bmp"), "image/bmp"),
    (("image", "", "svg"), "application/octet-stream"),
    (("video", "video/mp4", "mp4"), "video/mp4"),
    (("video", "application/xhtml+xml", "webm"), "video/webm"),
    (("video", "image/png", "mov"), "video/quicktime"),
    (("video", "text/html", "png"), "application/octet-stream"),
    (("audio", "audio/flac", "flac"), "audio/flac"),
    (("audio", "text/html", "mp3"), "audio/mpeg"),
    (("audio", "audio/x-thing+xml", "wav"), "audio/wav"),
]


def test_the_minted_type_is_never_one_a_browser_can_run_as_a_page():
    out = _node(TYPE_RULE + "process.stdout.write(JSON.stringify("
                + json.dumps([list(c) for c, _ in CASES])
                + ".map(([k, t, e]) => _previewBlobType(k, t, e))));")
    assert out == [want for _, want in CASES]
    for got in out:
        assert not any(word in got for word in ("svg", "xml", "html")), got


def test_the_preview_mints_no_object_url_under_the_stored_type():
    # Every object URL the preview makes wraps the bytes in a new Blob with a type of its own.
    mints = PREVIEW.count("URL.createObjectURL(")
    assert mints >= 2, "the preview no longer makes object URLs here; move these pins with it"
    assert PREVIEW.count("URL.createObjectURL(new Blob([blob], {") == mints
    assert "URL.createObjectURL(blob)" not in PREVIEW
    # Images, video and audio take the type rule; a PDF only ever application/pdf.
    assert "_previewBlobType('image', type, ext)" in PREVIEW
    assert "isPdf ? 'application/pdf' : _previewBlobType(tag, type, ext)" in PREVIEW


def test_an_svg_is_shown_from_a_data_address_and_text_never_becomes_a_url():
    assert "img.src = await _blobToDataUrl(new Blob([blob], { type: 'image/svg+xml' }));" in PREVIEW
    assert "type.includes('svg') || ext === 'svg'" in PREVIEW
    # The text branch reads the bytes into a <pre>; no object URL is minted before the branches.
    text_branch = PREVIEW[PREVIEW.index("if (isText && blob.size"):PREVIEW.index("} else if (isImg) {")]
    assert "createObjectURL" not in text_branch
    before = PREVIEW[:PREVIEW.index("if (isText && blob.size")]
    assert "createObjectURL" not in before
