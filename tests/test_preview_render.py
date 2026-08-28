"""Unit tests for the safe file-preview renderer (app/core/preview_render.py).

Pure module tests -- no app/db imports, so they run in the offline lane. They pin the security
contract of the "Render" preview: Markdown/HTML/source render to a sanitized, CSP-locked document,
and every active-content vector (script, event handler, javascript:/data: link, iframe, object,
form, style, svg) is neutralized.
"""
import re

import pytest

from app.core.preview_render import (
    MAX_PREVIEW_CHARS,
    render_preview_document,
    sanitize_preview_html,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- sanitizer

def test_script_and_event_handlers_are_stripped():
    out = sanitize_preview_html(
        '<p onclick="x()">hi</p><script>alert(1)</script><img src=x onerror=alert(2)>'
    )
    assert "<script" not in out and "onclick" not in out and "onerror" not in out
    assert "alert(1)" not in out  # script CONTENT discarded, not left as text
    assert "<p" in out  # the benign paragraph survives


@pytest.mark.parametrize("bad", [
    '<iframe src="https://evil"></iframe>',
    '<object data="x"></object>',
    '<embed src="x">',
    '<form action="https://evil"><input></form>',
    '<style>body{background:url(https://evil)}</style>',
    '<svg onload="alert(1)"><circle/></svg>',
    '<math><mtext></mtext></math>',
    '<link rel="stylesheet" href="https://evil">',
    '<base href="https://evil">',
    '<meta http-equiv="refresh" content="0;url=https://evil">',
])
def test_dangerous_elements_are_dropped(bad):
    out = sanitize_preview_html(bad + "<p>keep</p>")
    for tag in ("iframe", "object", "embed", "<form", "<style", "onload", "<svg", "<math",
                "<link", "<base", "<meta"):
        assert tag not in out.lower(), (bad, out)
    assert "<p>keep</p>" in out


def test_link_schemes_are_narrowed_to_web_and_mail():
    assert 'href="https://ok.com"' in sanitize_preview_html('<a href="https://ok.com">x</a>')
    assert 'href="mailto:a@b.com"' in sanitize_preview_html('<a href="mailto:a@b.com">x</a>')
    # javascript:, data:, and relative/other hrefs are dropped (the anchor text stays).
    for href in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
                 "vbscript:x", "page.html", "#frag"):
        out = sanitize_preview_html(f'<a href="{href}">x</a>')
        assert "href=" not in out, (href, out)
        assert ">x</a>" in out


def test_images_allow_only_inline_data_uris():
    # a data: image survives (renders inline; the CSP also permits only data:)
    out = sanitize_preview_html('<img src="data:image/png;base64,iVBOR" alt="q">')
    assert 'src="data:image/png;base64,iVBOR"' in out and 'alt="q"' in out
    # an external image loses its src (shows alt), so no external request is ever made
    ext = sanitize_preview_html('<img src="https://evil.com/track.png" alt="a">')
    assert "https://evil.com" not in ext and "<img" in ext


def test_style_and_id_attributes_are_stripped_but_class_survives():
    out = sanitize_preview_html('<span class="k" style="position:fixed" id="x">t</span>')
    assert 'class="k"' in out and "style=" not in out and "id=" not in out


def test_sanitize_is_idempotent():
    raw = '<p>hi</p><script>x</script><a href="https://ok">l</a>'
    once = sanitize_preview_html(raw)
    assert sanitize_preview_html(once) == once


# --------------------------------------------------------------------------- documents

def _csp(doc):
    m = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', doc)
    return m.group(1) if m else ""


def test_document_is_csp_locked_and_scriptless():
    doc, kind = render_preview_document("# Title\n\ntext", "readme.md")
    assert kind == "markdown"
    csp = _csp(doc)
    assert "default-src 'none'" in csp
    assert "img-src data:" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "<script" not in doc.lower()
    assert "<h1>" in doc  # markdown actually rendered


def test_markdown_xss_is_neutralized_in_the_document():
    doc, _ = render_preview_document(
        "# Hi\n\n<script>steal()</script>\n\n[c](javascript:alert(1))\n\n<img src=x onerror=alert(1)>",
        "note.md",
    )
    assert "<script" not in doc.lower()
    assert "javascript:" not in doc.lower()
    assert "onerror" not in doc.lower()
    assert "steal()" not in doc  # the script body is discarded, not shown as text


def test_code_is_highlighted_with_classes_and_a_stylesheet():
    doc, kind = render_preview_document("def f(x):\n    return x + 1\n", "sample.py")
    assert kind == "code"
    assert 'class="highlight"' in doc
    assert ".highlight" in doc  # the Pygments stylesheet is embedded
    assert "<script" not in doc.lower()


def test_html_file_is_rendered_sanitized():
    doc, kind = render_preview_document(
        "<h2>Doc</h2><script>x</script><iframe src=//evil></iframe><b>bold</b>", "page.html"
    )
    assert kind == "html"
    assert "<h2>Doc</h2>" in doc and "<b>bold</b>" in doc
    assert "<script" not in doc.lower() and "<iframe" not in doc.lower()


@pytest.mark.parametrize("name,expect", [
    ("a.md", "markdown"), ("a.markdown", "markdown"),
    ("a.html", "html"), ("a.htm", "html"),
    ("a.py", "code"), ("a.js", "code"), ("a.rs", "code"), ("Dockerfile", "code"),
    ("a.txt", "text"), ("a.log", "text"), ("noext", "text"),
])
def test_kind_detection(name, expect):
    _, kind = render_preview_document("x = 1", name)
    assert kind == expect


def test_kind_override_is_honoured():
    _, kind = render_preview_document("plain", "weird.bin", kind="markdown")
    assert kind == "markdown"


def test_oversized_input_is_truncated_not_dropped():
    big = "A" * (MAX_PREVIEW_CHARS + 10_000)
    doc, kind = render_preview_document(big, "big.txt")
    assert "truncated" in doc.lower()
    # only up to the ceiling of A's is emitted (plus the surrounding document)
    assert doc.count("A") <= MAX_PREVIEW_CHARS + 5


def test_empty_and_none_input_are_safe():
    for val in ("", None):
        doc, kind = render_preview_document(val, "x.md")
        assert "Content-Security-Policy" in doc and "<script" not in doc.lower()
