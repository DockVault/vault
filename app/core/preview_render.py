"""Safe in-vault rendering of Markdown, HTML, and source files for the file preview.

This is the security spine of the "Render" preview toggle, the sibling of
:mod:`app.core.email_sanitize`. It renders a Standard-vault text file to HTML for display inside a
**fully sandboxed, CSP-locked iframe** in the browser. Three independent controls stack, so a miss in
any one is not sufficient on its own:

  1. **Allowlist sanitization (this module).** Markdown/Pygments output, and a raw ``.html`` file's
     body, are always passed back through :func:`sanitize_preview_html` (an ``nh3`` ammonia binding).
     Unknown tags/attributes are dropped, ``<script>``/``<style>``/``<iframe>``/``<object>``/... and
     their CONTENT are discarded, event handlers and ``javascript:`` URLs are stripped.
  2. **A locked ``<meta>`` CSP** baked into the returned document: ``default-src 'none'`` (no scripts,
     no fetch, no fonts, no frames), ``img-src data:`` (inline data-URI images only -- NO external
     image loads, so a rendered file cannot phone home or leak the reader's IP), ``style-src
     'unsafe-inline'`` (for the trusted stylesheet this module emits), ``base-uri``/``form-action``
     ``'none'``.
  3. The caller renders the document in an ``<iframe sandbox="" srcdoc=...>`` -- an empty sandbox, so
     scripts never execute and the frame has an opaque origin, even for content the sanitizer somehow
     let through.

Only the file BODY is untrusted and sanitized; the surrounding document (the ``<meta>`` CSP and the
``<style>`` block, including the Pygments stylesheet) is generated here and appended AFTER
sanitization, so it is trusted by construction. The module depends only on ``nh3``, ``markdown``,
``Pygments`` and the standard library, so its unit tests run with no application or database imports.
"""

from __future__ import annotations

import html as _html
from typing import Optional, Tuple

import nh3

# ------------------------------------------------------------------------------------------------
# Allowlist (preview-specific -- distinct from the email allowlist)
# ------------------------------------------------------------------------------------------------

#: Tags allowed in rendered preview output. Structural + formatting + tables + links + images, plus
#: the ``<pre>``/``<span>``/``<div>`` that Markdown fenced code and Pygments highlighting emit.
PREVIEW_ALLOWED_TAGS: set[str] = {
    "p", "br", "hr", "span", "div",
    "strong", "b", "em", "i", "u", "s", "del", "ins", "mark", "sub", "sup", "small",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "dl", "dt", "dd",
    "blockquote", "pre", "code", "kbd", "samp", "var",
    "a", "img",
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col",
}

#: Per-tag attribute allowlist. ``class`` is permitted only on the elements Pygments/Markdown tag
#: with token classes (``span``/``pre``/``code``/``div``/``table``/``td``): a class name is an inert
#: string that only selects one of the TRUSTED rules this module emits -- it can carry no behaviour.
#: ``img`` may carry ``src`` (the CSP restricts it to ``data:`` -- external image loads are refused,
#: see module docstring), plus ``alt``/dimensions. No ``style``, ``id``, ``on*`` or ``srcset``.
PREVIEW_ALLOWED_ATTRIBUTES: dict[str, set[str]] = {
    "a": {"href", "title"},
    "img": {"src", "alt", "width", "height"},
    "span": {"class"},
    "pre": {"class"},
    "code": {"class"},
    "div": {"class"},
    "table": {"class"},
    "td": {"class", "colspan", "rowspan"},
    "th": {"class", "colspan", "rowspan", "scope"},
    "col": {"span"},
    "colgroup": {"span"},
}

#: URL schemes allowed on any surviving URL attribute. ``data:`` is permitted for INLINE images only
#: (the CSP's ``img-src data:`` is what actually gates it); a ``data:``/``javascript:`` link is
#: additionally inert because the whole frame runs with an EMPTY sandbox (no script execution).
PREVIEW_URL_SCHEMES: set[str] = {"http", "https", "mailto", "data"}

#: Tags whose CONTENT is discarded entirely, so a stripped ``<script>`` cannot leave its body behind
#: as visible text, and an unknown-but-dangerous container cannot smuggle content through.
PREVIEW_CLEAN_CONTENT_TAGS: set[str] = {
    "script", "style", "title", "noscript", "template", "iframe", "object", "embed",
    "applet", "form", "svg", "math", "link", "meta", "base",
}

#: Hard ceiling on input rendered, independent of the endpoint's own file-size gate. Rendering is for
#: readable text, not multi-megabyte blobs; a larger input is truncated with a visible note.
MAX_PREVIEW_CHARS: int = 512 * 1024

#: Content-Security-Policy embedded in the returned document. No script/fetch/font/frame of any kind;
#: inline styles for the trusted stylesheet below; images only from inline ``data:`` URIs.
_PREVIEW_CSP: str = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)

#: Trusted base stylesheet for the iframe document (readable typography; wraps long lines; adapts to
#: the reader's colour scheme). Emitted verbatim into a ``<style>`` AFTER sanitization.
_BASE_CSS: str = """
:root{color-scheme:light dark}
html,body{margin:0}
body.dv-preview{padding:16px;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1f2937;background:#ffffff;word-wrap:break-word;overflow-wrap:anywhere}
@media (prefers-color-scheme:dark){body.dv-preview{color:#e5e7eb;background:#0f172a}}
.dv-preview a{color:#2563eb}
@media (prefers-color-scheme:dark){.dv-preview a{color:#60a5fa}}
.dv-preview img{max-width:100%;height:auto}
.dv-preview pre{white-space:pre-wrap;word-break:break-word;padding:12px;border-radius:6px;background:#f3f4f6;overflow-x:auto}
@media (prefers-color-scheme:dark){.dv-preview pre{background:#1e293b}}
.dv-preview code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:0.92em}
.dv-preview :not(pre)>code{background:#f3f4f6;padding:1px 4px;border-radius:4px}
@media (prefers-color-scheme:dark){.dv-preview :not(pre)>code{background:#1e293b}}
.dv-preview table{border-collapse:collapse}
.dv-preview th,.dv-preview td{border:1px solid #d1d5db;padding:4px 8px}
@media (prefers-color-scheme:dark){.dv-preview th,.dv-preview td{border-color:#334155}}
.dv-preview blockquote{margin:0 0 0 0;padding:0 12px;border-left:3px solid #d1d5db;color:#6b7280}
"""

# Extensions that select each render path. Kept small and explicit.
_MARKDOWN_EXTS = {"md", "markdown", "mkd", "mdown"}
_HTML_EXTS = {"html", "htm", "xhtml"}
# Everything else with a recognised source extension goes to the highlighter; the lexer is chosen by
# filename with a graceful fallback, so this set only decides WHETHER to highlight, not how.
_CODE_EXTS = {
    "py", "pyw", "js", "mjs", "cjs", "ts", "tsx", "jsx", "css", "scss", "less", "json", "jsonc",
    "xml", "yml", "yaml", "toml", "ini", "cfg", "conf", "sh", "bash", "zsh", "ps1", "bat",
    "c", "h", "cpp", "cc", "hpp", "cs", "java", "kt", "go", "rs", "rb", "php", "pl", "lua",
    "sql", "r", "swift", "scala", "clj", "ex", "exs", "erl", "hs", "dockerfile", "makefile",
    "diff", "patch", "csv", "tsv", "properties", "gradle", "vue", "svelte", "proto", "graphql",
}


def _detect_kind(filename: str, override: Optional[str]) -> str:
    if override in ("markdown", "html", "code", "text"):
        return override
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    base = filename.lower()
    if ext in _MARKDOWN_EXTS:
        return "markdown"
    if ext in _HTML_EXTS:
        return "html"
    if ext in _CODE_EXTS or base in ("dockerfile", "makefile"):
        return "code"
    return "text"


def _attribute_filter(tag: str, attr: str, value: str) -> Optional[str]:
    """Per-tag, per-attribute final gate (nh3 calls this for each surviving attribute).

    Splits the ``data:`` scheme by element so ``data:`` reaches ONLY ``<img src>`` (inline images),
    never a link: a ``data:text/html`` link, once clicked, would open a document that does NOT inherit
    this frame's ``<meta>`` CSP (only the sandbox), so an image inside it could still be fetched
    externally. Links are narrowed to real web/mail URLs; an ``<img>`` keeps only a ``data:`` src (any
    external src is dropped, so the tag shows its alt text -- the CSP ``img-src data:`` is the belt).
    """
    v = value.strip().lower()
    if tag == "a" and attr == "href":
        return value if v.startswith(("http://", "https://", "mailto:")) else None
    if attr == "src":
        return value if v.startswith("data:") else None
    return value


def sanitize_preview_html(raw: Optional[str]) -> str:
    """Allowlist-sanitize rendered HTML for display in the sandboxed preview iframe.

    Idempotent. Drops every tag/attribute not on the preview allowlist, discards the CONTENT of
    active-content tags, strips comments, forces ``rel`` on links, and applies
    :func:`_attribute_filter` for the per-tag ``data:`` split. This is the authoritative control; the
    CSP and the empty iframe sandbox are defence-in-depth on top of it.
    """
    if not raw:
        return ""
    return nh3.clean(
        raw,
        tags=PREVIEW_ALLOWED_TAGS,
        attributes=PREVIEW_ALLOWED_ATTRIBUTES,
        url_schemes=PREVIEW_URL_SCHEMES,
        clean_content_tags=PREVIEW_CLEAN_CONTENT_TAGS,
        link_rel="noopener noreferrer nofollow",
        strip_comments=True,
        attribute_filter=_attribute_filter,
    )


def _truncated(text: str) -> Tuple[str, bool]:
    if len(text) > MAX_PREVIEW_CHARS:
        return text[:MAX_PREVIEW_CHARS], True
    return text, False


def _render_markdown_body(text: str) -> str:
    import markdown  # imported lazily so a stripped-down build without the dep fails only here
    # Base extensions only: fenced code, tables, sane lists. No extension that executes or embeds.
    # markdown passes raw HTML through by default -- which is exactly why the output is sanitized.
    rendered = markdown.markdown(
        text, extensions=["fenced_code", "tables", "sane_lists"], output_format="html",
    )
    return sanitize_preview_html(rendered)


def _render_code_body(text: str, filename: str) -> Tuple[str, str]:
    """Return ``(sanitized_highlighted_html, trusted_pygments_css)``."""
    from pygments import highlight
    from pygments.formatters import HtmlFormatter
    from pygments.lexers import TextLexer, get_lexer_for_filename, guess_lexer
    from pygments.util import ClassNotFound

    lexer = None
    try:
        lexer = get_lexer_for_filename(filename, stripnl=False)
    except (ClassNotFound, Exception):
        lexer = None
    if lexer is None:
        try:
            lexer = guess_lexer(text)
        except (ClassNotFound, Exception):
            lexer = TextLexer()
    formatter = HtmlFormatter(nowrap=False, cssclass="highlight", wrapcode=True)
    body = highlight(text, lexer, formatter)
    # Pygments emits only <div class="highlight"><pre><span class="..">; sanitize anyway so a
    # pathological lexer output can never carry anything but allowlisted tags/classes.
    css = HtmlFormatter(cssclass="highlight").get_style_defs(".highlight")
    return sanitize_preview_html(body), css


def _render_text_body(text: str) -> str:
    # Escaped plain text in a <pre>; the escape means even this fallback path emits no live markup.
    return "<pre>" + _html.escape(text, quote=False) + "</pre>"


def _build_document(body_html: str, extra_css: str, *, truncated: bool) -> str:
    note = ""
    if truncated:
        note = ('<p style="opacity:.7;font-style:italic">Preview truncated -- '
                'download the file to see all of it.</p>')
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{_PREVIEW_CSP}\">"
        f"<style>{_BASE_CSS}{extra_css}</style></head>"
        f"<body class=\"dv-preview\">{note}{body_html}</body></html>"
    )


def render_preview_document(
    text: str, filename: str, kind: Optional[str] = None
) -> Tuple[str, str]:
    """Render ``text`` (the plaintext of a file named ``filename``) to a complete, self-contained,
    CSP-locked HTML document for the sandboxed preview iframe.

    Returns ``(document_html, resolved_kind)`` where ``resolved_kind`` is one of
    ``markdown``/``html``/``code``/``text``. ``kind`` may force a path; otherwise it is chosen from
    the filename. Never raises on ordinary input (a render/highlight failure degrades to escaped
    plain text).
    """
    resolved = _detect_kind(filename or "", kind)
    text = text or ""
    text, truncated = _truncated(text)
    extra_css = ""
    try:
        if resolved == "markdown":
            body = _render_markdown_body(text)
        elif resolved == "html":
            body = sanitize_preview_html(text)
        elif resolved == "code":
            body, extra_css = _render_code_body(text, filename or "file.txt")
        else:
            body = _render_text_body(text)
    except Exception:
        # Any renderer failure falls back to safe escaped text rather than surfacing an error or,
        # worse, unsanitized output.
        body = _render_text_body(text)
        extra_css = ""
        resolved = "text"
    return _build_document(body, extra_css, truncated=truncated), resolved
