"""What a preview answer carries (GET /vaults/{id}/files/{fid}/preview), offline.

A preview is shown, never run: HTML, XHTML, SVG and every XML type are served as plain text, every other
type as the stored one made safe, and both the whole-file and the ranged answer carry a sandboxing
Content-Security-Policy and nosniff. A download keeps its stored type and no such policy.
"""
import ast
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("stored", [
    "text/html", "text/html; charset=utf-8", "TEXT/HTML", "application/xhtml+xml", "image/svg+xml",
    "image/svg+xml; charset=utf-8", "text/xml", "application/xml", "application/rss+xml", "application/atom+xml",
    "application/mathml+xml", "text/xsl", "application/xslt+xml", "multipart/x-mixed-replace",
    "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript",
])
def test_types_a_browser_would_run_are_previewed_as_plain_text(stored):
    assert api._preview_media_type(stored) == "text/plain; charset=utf-8"


@pytest.mark.parametrize("stored,served", [
    ("image/png", "image/png"), ("application/pdf", "application/pdf"), ("text/plain", "text/plain"),
    ("video/mp4", "video/mp4"), ("text/markdown", "text/markdown"), ("", "application/octet-stream"),
    ("text/html\r\nX-Injected: 1", "application/octet-stream"),
])
def test_other_types_are_previewed_as_stored_and_made_safe(stored, served):
    assert api._preview_media_type(stored) == served


def test_the_preview_headers_sandbox_and_forbid_sniffing():
    assert api._PREVIEW_HEADERS == {"Content-Security-Policy": "default-src 'none'; sandbox",
                                    "X-Content-Type-Options": "nosniff"}


def _serve_file():
    for node in ast.walk(ast.parse(SOURCE)):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_serve_file":
            return ast.unparse(node)
    raise AssertionError("no _serve_file")


def test_both_answers_of_a_preview_carry_the_headers_and_the_preview_type():
    body = _serve_file()
    # The ranged answer and the whole-file answer: each headers dict adds the preview headers, and each
    # response picks the preview's type when it is a preview.
    assert body.count("**(_PREVIEW_HEADERS if is_preview else {})") == 2
    assert body.count("_preview_media_type(mime_type) if is_preview else _safe_media_type(mime_type)") == 2
    assert "media_type=_safe_media_type(mime_type)," not in body.replace(" ", "")
