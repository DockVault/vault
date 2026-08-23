"""Authoritative sanitization and rendering for admin-authored HTML email.

This module is the security spine of the Email Studio. It runs at three points:

  * client-side (a lightweight guard in the browser, for UX only — never trusted);
  * server-side ON SAVE (``sanitize_email_html`` stores only the cleaned result, and
    ``detect_malicious`` decides whether the raw input was hostile enough to reject and raise a
    security event); and
  * server-side BEFORE SEND (the stored body is re-checked and re-sanitized, so even a body
    tampered with directly in the database on a running deployment cannot carry active content out
    in a message).

It deliberately depends only on ``nh3`` (a Rust *ammonia* binding) and the standard library, so its
unit tests run with no application or database imports. Everything the studio persists or sends
passes through :func:`sanitize_email_html` first; the render helpers only ever operate on
already-sanitized HTML.

Design rules that the tests pin:
  * Allowlist, not denylist — unknown tags/attributes are dropped, not escaped.
  * ``<img>`` never carries a ``src`` at rest. Images are referenced ONLY by a ``data-resource-id``
    UUID; the real bytes are resolved at render/send time (a ``cid:`` inline part when sending, an
    admin-only URL when previewing). No filesystem path or URL to a resource is ever stored.
  * No inline CSS (``style``/``class`` are stripped) — a curated inline-style allowlist is a
    documented future enhancement; v1 is tags-only.
  * Dynamic personalization uses ``{{ token }}`` markers substituted per recipient at render time;
    values are HTML-escaped; unknown tokens are left as literal text (harmless post-sanitize).
"""

from __future__ import annotations

import html as _html
import re
import uuid as _uuid
from datetime import datetime, timezone
from typing import Callable, Iterable, NamedTuple, Optional

import nh3

# --------------------------------------------------------------------------------------------------
# Allowlist
# --------------------------------------------------------------------------------------------------

#: Tags an admin may use in an email body. Structural + basic formatting + tables + links + images.
ALLOWED_TAGS: set[str] = {
    "p", "br", "hr", "span", "div",
    "strong", "b", "em", "i", "u", "s", "sub", "sup", "small",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li",
    "blockquote", "pre", "code",
    "a", "img",
    "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption",
}

#: Per-tag attribute allowlist. Note ``img`` may ONLY carry ``data-resource-id`` (+ alt/dimensions):
#: no ``src``/``srcset`` survives sanitization, so a stored template can never point at a URL.
ALLOWED_ATTRIBUTES: dict[str, set[str]] = {
    "a": {"href", "title"},
    "img": {"data-resource-id", "alt", "width", "height"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan", "scope"},
    "table": {"border", "cellpadding", "cellspacing"},
}

#: Only these URL schemes are allowed on ``<a href>``. javascript:, data:, vbscript:, etc. are
#: dropped by nh3 because they are not listed.
ALLOWED_URL_SCHEMES: set[str] = {"http", "https", "mailto"}

#: Tags whose *content* is discarded entirely (not just the tag), so a stripped ``<script>`` cannot
#: leave its body behind as visible text.
CLEAN_CONTENT_TAGS: set[str] = {"script", "style", "title", "noscript", "template"}


def sanitize_email_html(raw: Optional[str]) -> str:
    """Return an allowlist-sanitized copy of ``raw`` safe to store and to send.

    Idempotent: ``sanitize(sanitize(x)) == sanitize(x)``. Never raises on ordinary input.
    """
    if not raw:
        return ""
    return nh3.clean(
        raw,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_URL_SCHEMES,
        clean_content_tags=CLEAN_CONTENT_TAGS,
        link_rel="noopener noreferrer",
        strip_comments=True,
    )


# --------------------------------------------------------------------------------------------------
# Malicious-content detection (the "raise a security event and reject" signal)
# --------------------------------------------------------------------------------------------------

# Patterns that mark input as clearly hostile rather than merely messy. sanitize_email_html (nh3)
# is the AUTHORITATIVE control that neutralizes all of these; these patterns are a BEST-EFFORT
# signal used only to distinguish "admin pasted a disallowed but benign tag" (sanitize silently)
# from "someone is injecting active content" (reject + raise a security event). They match on an
# ACTUAL tag or an attribute-context scheme, never on escaped text (`&lt;script&gt;`) or a prose
# mention (`use the vbscript: prefix`), so a legitimate template that merely displays such strings
# is not falsely rejected. Some obfuscations (entity-encoded scheme letters) are intentionally left
# to nh3 rather than widened here, because widening reliably produces false positives.
_URL_ATTR = r"(?:href|src|action|formaction|xlink:href)\s*=\s*['\"]?\s*"
_MALICIOUS_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("script_tag", re.compile(r"<\s*/?\s*script\b", re.IGNORECASE)),
    # `[\s/]` catches both `<a onclick=` and the HTML5 slash-delimited `<a/onclick=`. The between
    # scan is BOUNDED ({0,300}, not `*?`) so the match stays O(n): an unbounded lazy `[^>]*?` is
    # O(n^2) on adversarial input like "<a<a<a…" (no '>' to anchor), enough to pin a worker for
    # minutes at the 1 MB body cap. A real handler sits within a few attributes of the tag name, so
    # 300 chars is generous; nh3 strips anything this misses regardless.
    ("event_handler", re.compile(r"<[a-z][^>]{0,300}?[\s/]on[a-z]+\s*=", re.IGNORECASE)),
    ("js_uri", re.compile(_URL_ATTR + r"javascript:", re.IGNORECASE)),
    ("vbscript_uri", re.compile(_URL_ATTR + r"vbscript:", re.IGNORECASE)),
    ("data_html_uri", re.compile(_URL_ATTR + r"data\s*:\s*text/html", re.IGNORECASE)),
    ("iframe", re.compile(r"<\s*iframe\b", re.IGNORECASE)),
    ("object_embed", re.compile(r"<\s*(?:object|embed|applet)\b", re.IGNORECASE)),
    ("form", re.compile(r"<\s*form\b", re.IGNORECASE)),
    ("meta_or_base", re.compile(r"<\s*(?:meta|base)\b", re.IGNORECASE)),
    ("external_style", re.compile(r"<\s*(?:link|style)\b", re.IGNORECASE)),
    ("svg_or_math", re.compile(r"<\s*(?:svg|math)\b", re.IGNORECASE)),
    ("srcdoc", re.compile(r"\bsrcdoc\s*=", re.IGNORECASE)),
)


# The subset of patterns that indicate an ACTUAL injection / active-content attempt, as opposed to
# markup that is merely disallowed-but-harmless in v1 (an inline <style> block, a <meta>, a <form>,
# a bare <svg>). The hostile subset drives reject + a security event; the rest are simply stripped by
# the sanitizer, so an admin pasting ordinary marketing-email HTML is cleaned, not accused.
_HOSTILE_REASONS = frozenset({
    "script_tag", "event_handler", "js_uri", "vbscript_uri", "data_html_uri",
    "iframe", "object_embed", "srcdoc",
})


def detect_malicious(raw: Optional[str]) -> list[str]:
    """Return ALL flagged pattern names found in ``raw`` (empty means clean) — both the genuinely
    hostile ones and the merely-disallowed ones. See :func:`hostile_reasons` for the subset that
    should trigger rejection + a security event.

    BEST-EFFORT signal, not the security boundary — sanitize_email_html is what actually neutralizes
    content. Runs on the RAW input, so it sees exactly what the author or a tamperer supplied.
    Deliberately conservative (matches real tags / attribute-context schemes) to avoid flagging a
    template that merely displays such strings as text.
    """
    if not raw:
        return []
    return [name for name, pattern in _MALICIOUS_PATTERNS if pattern.search(raw)]


def hostile_reasons(raw: Optional[str]) -> list[str]:
    """The genuinely-hostile subset of :func:`detect_malicious` — an actual script tag, event
    handler, javascript:/vbscript:/data:text/html URL, iframe, object/embed, or srcdoc. This is what
    the save/send paths reject and raise a security event on. A benign-but-unsupported tag (a
    <style> block, <meta>, <form>, bare <svg>) is NOT hostile: the sanitizer strips it silently."""
    return [r for r in detect_malicious(raw) if r in _HOSTILE_REASONS]


# --------------------------------------------------------------------------------------------------
# Dynamic personalization tokens
# --------------------------------------------------------------------------------------------------

class DynamicAction(NamedTuple):
    token: str
    label: str
    sample: str


#: The catalog offered by the editor's "Add Dynamic Action" dropdown and accepted by the renderer.
#: Future server-minted values (e.g. ``{{otp}}``) slot in here without touching the render loop.
DYNAMIC_ACTIONS: tuple[DynamicAction, ...] = (
    DynamicAction("current_date", "Current date", "2026-08-23"),
    DynamicAction("current_time", "Current time", "14:05"),
    DynamicAction("current_datetime", "Current date & time", "2026-08-23 14:05"),
    DynamicAction("user.username", "Recipient username", "jsmith"),
    DynamicAction("user.email", "Recipient email", "jsmith@example.com"),
    DynamicAction("user.display_name", "Recipient display name", "J. Smith"),
    DynamicAction("vault.name", "Vault / brand name", "Secure Vault"),
)

_KNOWN_TOKENS: set[str] = {a.token for a in DYNAMIC_ACTIONS}
_TOKEN_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


def token_context(
    *,
    recipient: Optional[dict] = None,
    brand_name: str = "",
    now: Optional[datetime] = None,
) -> dict[str, str]:
    """Build the substitution map for one recipient. Missing recipient fields render empty."""
    recipient = recipient or {}
    now = now or datetime.now(timezone.utc)   # UTC, tz-aware (utcnow() is deprecated in 3.12+)
    username = str(recipient.get("username") or "")
    return {
        "current_date": now.strftime("%Y-%m-%d"),
        "current_time": now.strftime("%H:%M"),
        "current_datetime": now.strftime("%Y-%m-%d %H:%M"),
        "user.username": username,
        "user.email": str(recipient.get("email") or ""),
        "user.display_name": str(recipient.get("display_name") or username),
        "vault.name": str(brand_name or ""),
    }


def substitute_tokens(sanitized_html: str, context: dict[str, str]) -> str:
    """Replace ``{{ known_token }}`` with the HTML-escaped context value.

    Operates on ALREADY-sanitized HTML. Unknown tokens are left verbatim (they are inert text after
    sanitization). Values are HTML-escaped so a recipient field can never inject markup.
    """
    if not sanitized_html:
        return ""

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in context:
            # quote=True escapes " and ' too, so a value substituted inside a quoted attribute
            # (title=, alt=, href="…/{{token}}") cannot break out and inject new attributes. The
            # render helpers ALSO re-sanitize after substitution, but escaping here keeps the
            # intended value intact instead of relying on the second pass to strip a breakout.
            return _html.escape(context[key], quote=True)
        return match.group(0)

    return _TOKEN_RE.sub(repl, sanitized_html)


def substitute_tokens_plain(text: str, context: dict[str, str]) -> str:
    """Substitute ``{{ token }}`` in a PLAIN-TEXT context (e.g. an email subject line).

    Unlike :func:`substitute_tokens`, values are inserted verbatim (NOT HTML-escaped), because the
    result is a header/plain text, not HTML. Unknown tokens are left literal. The caller is
    responsible for control-char/header-injection validation of the result (a subject with a token
    that expands to a newline must be rejected before it reaches an email header)."""
    if not text:
        return ""

    def repl(match: "re.Match[str]") -> str:
        key = match.group(1)
        return context[key] if key in context else match.group(0)

    return _TOKEN_RE.sub(repl, text)


# Control characters that must never reach an email header (CR/LF are the header-injection vector).
_CONTROL_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


def render_subject(subject: Optional[str], context: dict[str, str]) -> str:
    """Render an email subject: substitute tokens, then STRIP any control characters from the
    RESULT. This is the header-safe entry point — a recipient field that expands to a CR/LF (a
    username is not control-char-validated at its own boundary) cannot inject an email header.
    Use this for BOTH the editor preview and the send path, so no caller can forget the check."""
    return _CONTROL_RE.sub("", substitute_tokens_plain(subject or "", context))


def unknown_tokens(raw_or_sanitized: str) -> list[str]:
    """Tokens present in the text that are not in the known catalog (for a non-blocking save warning)."""
    if not raw_or_sanitized:
        return []
    seen: list[str] = []
    for match in _TOKEN_RE.finditer(raw_or_sanitized):
        key = match.group(1)
        if key not in _KNOWN_TOKENS and key not in seen:
            seen.append(key)
    return seen


# --------------------------------------------------------------------------------------------------
# Image resolution (UUID -> cid: on send, admin URL on preview; dangling refs are dropped)
# --------------------------------------------------------------------------------------------------

_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_RESOURCE_ID_RE = re.compile(r'data-resource-id\s*=\s*"([^"]*)"', re.IGNORECASE)


def _canonical_uuid(value: str) -> Optional[str]:
    """Canonical lowercase-hyphenated UUID string, or None if ``value`` is not a UUID.

    Canonicalizing (rather than a raw string compare) means an id written in any accepted UUID form
    — uppercase, ``urn:uuid:…``, ``{…}`` braces, or hyphen-less hex — both DEDUPES correctly and is
    looked up against the database in the form the database stores. Anything that is not a UUID
    (including an attempt to smuggle extra attributes or markup inside the attribute value) returns
    None, and the image is dropped.
    """
    try:
        return str(_uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def extract_resource_ids(sanitized_html: str) -> list[str]:
    """Every valid resource UUID (canonicalized, deduped, ordered) referenced by an ``<img>``."""
    if not sanitized_html:
        return []
    out: list[str] = []
    for tag in _IMG_TAG_RE.findall(sanitized_html):
        m = _RESOURCE_ID_RE.search(tag)
        if not m:
            continue
        canonical = _canonical_uuid(m.group(1))
        if canonical and canonical not in out:
            out.append(canonical)
    return out


def _rewrite_images(sanitized_html: str, src_for: Callable[[str], Optional[str]]) -> str:
    """Rewrite each ``<img>``: inject ``src=src_for(canonical_uuid)`` when it resolves, else drop.

    ``src_for`` is called with the CANONICAL uuid string and returns the src, or ``None`` to drop.
    An ``<img>`` with no valid ``data-resource-id`` is always dropped — a stored template can only
    ever surface an image the studio knows about, and never an external URL.
    """
    if not sanitized_html:
        return ""

    def repl(match: "re.Match[str]") -> str:
        tag = match.group(0)
        rid_match = _RESOURCE_ID_RE.search(tag)
        canonical = _canonical_uuid(rid_match.group(1)) if rid_match else None
        if not canonical:
            return ""
        src = src_for(canonical)
        if not src:
            return ""
        # Drop the data-resource-id and inject the resolved src, so the rendered output carries only
        # the resolved reference (a cid: part on send — no UUID appears in the message at all).
        # nh3 guarantees the tag carries no src of its own. A FUNCTION replacement (not an f-string
        # literal) is used so a backslash or a "\g"/"\1" sequence in `src` can never be interpreted
        # by re.sub as a regex backreference.
        escaped = _html.escape(src, quote=True)
        stripped = _RESOURCE_ID_RE.sub("", tag)
        stripped = re.sub(r"\s{2,}", " ", stripped)          # tidy the gap the removed attr left
        return re.sub(r"^<img\b", lambda _m: f'<img src="{escaped}"', stripped,
                      count=1, flags=re.IGNORECASE)

    return _IMG_TAG_RE.sub(repl, sanitized_html)


class InlineImage(NamedTuple):
    cid: str
    resource_id: str
    content_type: str
    data: bytes


def render_for_preview(
    raw_body: Optional[str],
    *,
    context: dict[str, str],
    resource_exists: Callable[[str], bool],
    resource_url: Callable[[str], str],
) -> str:
    """Sanitize + personalize + resolve images to admin-only URLs, for the editor's render pane.

    Never raises a security event (it runs live as the admin types); it simply shows the sanitized
    result, which visibly strips anything unsafe.
    """
    clean = sanitize_email_html(raw_body)
    personalized = substitute_tokens(clean, context)
    # Re-sanitize AFTER substitution: a recipient/token value can never introduce an attribute,
    # tag, or URL scheme the allowlist forbids, even though it was inserted post-sanitization.
    personalized = sanitize_email_html(personalized)

    def src_for(rid: str) -> Optional[str]:
        return resource_url(rid) if resource_exists(rid) else None

    return _rewrite_images(personalized, src_for)


def render_for_send(
    stored_body: Optional[str],
    *,
    context: dict[str, str],
    load_resource: Callable[[str], Optional[tuple[str, bytes]]],
    cid_prefix: str = "img",
) -> tuple[str, list[InlineImage]]:
    """Produce the final HTML + inline image parts for one recipient.

    ``load_resource(uuid)`` returns ``(content_type, bytes)`` for a known image or ``None``. The
    caller re-runs :func:`detect_malicious` on ``stored_body`` first and refuses to send when it is
    non-empty. Images become ``cid:`` references backed by the returned :class:`InlineImage` parts;
    unresolved references are dropped. No resource URL or path appears in the output.
    """
    clean = sanitize_email_html(stored_body)
    personalized = substitute_tokens(clean, context)
    # Re-sanitize AFTER substitution (see render_for_preview): this is the "sanitized again before
    # send" guarantee made real — a value substituted into a URL attribute cannot introduce a
    # javascript: scheme, and a value in a quoted attribute cannot inject an event handler.
    personalized = sanitize_email_html(personalized)

    attachments: list[InlineImage] = []
    by_id: dict[str, InlineImage] = {}

    def src_for(rid: str) -> Optional[str]:
        if rid in by_id:
            return f"cid:{by_id[rid].cid}"
        loaded = load_resource(rid)
        if not loaded:
            return None
        content_type, data = loaded
        # A positional cid, NOT the resource UUID — the UUID never appears in the sent message.
        cid = f"{cid_prefix}{len(attachments)}"
        inline = InlineImage(cid=cid, resource_id=rid, content_type=content_type, data=data)
        attachments.append(inline)
        by_id[rid] = inline
        return f"cid:{cid}"

    final_html = _rewrite_images(personalized, src_for)
    return final_html, attachments


def render_plaintext_fallback(final_html: str) -> str:
    """A crude text/plain alternative: drop tags, unescape entities, collapse blank runs.

    Not a full HTML-to-text conversion — just enough that a text-only client sees readable content
    instead of raw markup.
    """
    if not final_html:
        return ""
    text = re.sub(r"(?i)<\s*br\s*/?>", "\n", final_html)
    text = re.sub(r"(?i)</\s*(p|div|h[1-6]|li|tr)\s*>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = _html.unescape(text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
