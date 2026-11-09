"""What a compliance case shows a file under (app/api/compliance_router.py _content_type, static/js/compliance.js).

The case viewer draws a file from an object address, and that address can be opened in a tab of its own, with the
vault's origin. So the server serves every type a browser would run as a page (HTML, XHTML, SVG and every XML type)
as text, and the viewer re-makes each picture, video and sound under a type of its own kind that no browser opens as
a page, whatever type the uploader claimed. test_ui_compliance.py opens such an address in a browser.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import compliance_router as cr  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
COMPLIANCE_JS = ROOT / "static" / "js" / "compliance.js"
TEXT = "text/plain; charset=utf-8"


@pytest.mark.parametrize("stored", [
    "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml",
    "image/x-thing+xml", "video/x-thing+xml", "audio/x-thing+xml", "application/rss+xml", "application/vnd.x+xml",
    "image/xml", "IMAGE/X-THING+XML", "image/x-thing+xml; charset=utf-8", "text/xsl", "application/xslt+xml",
    "application/xml-dtd", "text/vtt", "multipart/x-mixed-replace", "text/javascript", "application/javascript",
])
def test_a_type_a_browser_would_run_is_served_as_text(stored):
    assert cr._content_type(stored) == TEXT


@pytest.mark.parametrize("stored, served", [
    ("image/png", "image/png"), ("image/jpeg", "image/jpeg"), ("video/mp4", "video/mp4"),
    ("audio/mpeg", "audio/mpeg"), ("application/pdf", "application/pdf"), ("text/plain", "text/plain"),
    (None, "application/octet-stream"), ("not a type", "application/octet-stream"),
])
def test_other_types_are_served_as_stored_once_made_safe(stored, served):
    assert cr._content_type(stored) == served


def _lift(js: str, name: str) -> str:
    start = js.index("    function " + name + "(")
    return js[start:js.index("\n    }\n", start) + 7]


_TYPES = [
    # (kind, the answer's type, the type the address is made under)
    ("image", "image/png", "image/png"),
    ("image", "image/jpeg; charset=x", "image/jpeg"),
    ("image", "IMAGE/WEBP", "image/webp"),
    ("image", "image/x-thing+xml", "application/octet-stream"),
    ("image", "image/svg+xml", "application/octet-stream"),
    ("image", "image/x-html", "application/octet-stream"),
    ("image", "text/html", "application/octet-stream"),
    ("image", "application/xhtml+xml", "application/octet-stream"),
    ("image", "image/pngé", "application/octet-stream"),
    ("image", "image/png ,text/html", "application/octet-stream"),
    ("image", "", "application/octet-stream"),
    ("video", "video/mp4", "video/mp4"),
    ("video", "video/x-thing+xml", "application/octet-stream"),
    ("video", "image/png", "application/octet-stream"),
    ("audio", "audio/mpeg", "audio/mpeg"),
    ("audio", "audio/x-thing+xml", "application/octet-stream"),
    ("audio", "audio/ogg ,text/xsl", "application/octet-stream"),
]


def test_the_viewer_makes_each_address_under_a_type_of_its_kind_that_is_never_a_page():
    node = shutil.which("node")
    assert node, "Node is required: the shipped page code must not be skipped"
    helper = _lift(COMPLIANCE_JS.read_text(encoding="utf-8"), "viewerBlobType")
    cases = json.dumps([[kind, answer] for kind, answer, _ in _TYPES])
    script = helper + "\nprocess.stdout.write(JSON.stringify(" + cases + ".map(([k, t]) => viewerBlobType(k, t))));\n"
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    got = json.loads(done.stdout)
    assert got == [made for _, _, made in _TYPES]


def test_every_address_the_compliance_page_makes_has_a_type_it_chose():
    """No object address is made from an answer's blob as it came: each is re-made under the viewer's checked type,
    or under the one fixed type that route always answers with."""
    js = COMPLIANCE_JS.read_text(encoding="utf-8")
    calls = re.findall(r"URL\.createObjectURL\((.*?)\);", js)
    assert calls, "the viewer no longer makes object addresses: update this test"
    allowed = (
        re.compile(r"^new Blob\(\[blob\], \{ type: viewerBlobType\('image', type\) \}\)$"),
        re.compile(r"^new Blob\(\[blob\], \{ type: viewerBlobType\(type\.startsWith\('video/'\) \? 'video' : "
                   r"'audio', type\) \}\)$"),
        re.compile(r"^new Blob\(\[blob\], \{ type: 'application/pdf' \}\)$"),
        re.compile(r"^new Blob\(\[blob\], \{ type: 'application/zip' \}\)$"),
    )
    for call in calls:
        assert any(p.match(call) for p in allowed), call
    assert len(calls) == 4, calls
