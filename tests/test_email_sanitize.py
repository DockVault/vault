"""Unit tests for the Email Studio sanitization/rendering core (app.core.email_sanitize).

Pure: needs only nh3 + the module under test, no database or running deployment. These pin the
security guarantees the rest of the feature depends on — an allowlist that drops active content,
image references that only ever surface as UUIDs (never a stored src/path), personalization values
that stay inert in BOTH text and attribute context, and dangling references that vanish instead of
leaking.
"""

import pytest

from app.core import email_sanitize as es

pytestmark = pytest.mark.unit

_UUID_A = "11111111-1111-1111-1111-111111111111"
_UUID_B = "22222222-2222-2222-2222-222222222222"


# --------------------------------------------------------------------------------------------------
# sanitize_email_html — allowlist
# --------------------------------------------------------------------------------------------------

def test_sanitize_empty_and_none():
    assert es.sanitize_email_html("") == ""
    assert es.sanitize_email_html(None) == ""


def test_sanitize_keeps_allowed_formatting():
    raw = "<h1>Hi</h1><p>Hello <strong>world</strong> and <em>you</em></p><ul><li>a</li><li>b</li></ul>"
    out = es.sanitize_email_html(raw)
    for frag in ("<h1>", "Hello", "<strong>world</strong>", "<em>you</em>", "<ul>", "<li>a</li>"):
        assert frag in out


def test_sanitize_strips_script_tag_and_content():
    out = es.sanitize_email_html("<p>ok</p><script>alert('x')</script>")
    assert "<script" not in out.lower()
    assert "alert" not in out          # content of script is discarded, not left as text
    assert "<p>ok</p>" in out


@pytest.mark.parametrize("raw", [
    '<img src="x" onerror="alert(1)">',
    '<div onclick="steal()">hi</div>',
    '<a href="#" onmouseover="x">y</a>',
])
def test_sanitize_strips_event_handlers(raw):
    out = es.sanitize_email_html(raw).lower()
    assert "onerror" not in out and "onclick" not in out and "onmouseover" not in out


def test_sanitize_strips_javascript_href():
    out = es.sanitize_email_html('<a href="javascript:alert(1)">click</a>')
    assert "javascript:" not in out.lower()


@pytest.mark.parametrize("tag", ["iframe", "object", "embed", "form", "style", "link", "meta", "base", "svg", "math"])
def test_sanitize_strips_dangerous_tags(tag):
    out = es.sanitize_email_html(f"<p>keep</p><{tag}>bad</{tag}>").lower()
    assert f"<{tag}" not in out
    assert "<p>keep</p>" in out


def test_sanitize_img_drops_src_keeps_resource_id():
    out = es.sanitize_email_html(
        f'<img src="http://evil.example/x.png" data-resource-id="{_UUID_A}" alt="a">')
    assert "src=" not in out                       # no src survives at rest
    assert "evil.example" not in out
    assert f'data-resource-id="{_UUID_A}"' in out
    assert 'alt="a"' in out


def test_sanitize_strips_style_and_class():
    out = es.sanitize_email_html('<p style="background:url(http://evil)" class="x">hi</p>')
    assert "style=" not in out.lower()
    assert "class=" not in out.lower()
    assert "hi" in out


def test_sanitize_forces_link_rel():
    out = es.sanitize_email_html('<a href="https://example.com">x</a>')
    assert 'rel="noopener noreferrer"' in out
    assert 'href="https://example.com"' in out


@pytest.mark.parametrize("raw,keep_href", [
    ('<a href="https://ok.example">x</a>', True),
    ('<a href="http://ok.example">x</a>', True),
    ('<a href="mailto:a@b.example">x</a>', True),
    ('<a href="tel:+15551234">x</a>', False),
    ('<a href="ftp://f.example">x</a>', False),
    ('<a href="data:text/html,<b>x">y</a>', False),
    ('<a href="JavaScript:alert(1)">x</a>', False),
])
def test_sanitize_link_scheme_allowlist(raw, keep_href):
    out = es.sanitize_email_html(raw)
    assert ("href=" in out) is keep_href           # allowed schemes keep href, others lose it
    assert ">x</a>" in out or ">y</a>" in out       # link text always survives


def test_sanitize_is_idempotent():
    for raw in [
        f'<p>Hi <a href="https://a.example">l</a> <img data-resource-id="{_UUID_A}"></p><script>x</script>',
        '<table><tr><td>a</td><th scope="col">b</th></tr></table>',
        '<p>ampersand &amp; entity &lt;x&gt; kept</p>',
    ]:
        once = es.sanitize_email_html(raw)
        assert es.sanitize_email_html(once) == once


# --------------------------------------------------------------------------------------------------
# detect_malicious
# --------------------------------------------------------------------------------------------------

def test_detect_clean_html_is_empty():
    assert es.detect_malicious("<p>Hello <strong>there</strong></p>") == []
    assert es.detect_malicious("") == []
    assert es.detect_malicious(None) == []


@pytest.mark.parametrize("raw,reason", [
    ("<script>alert(1)</script>", "script_tag"),
    ('<div onclick="x">y</div>', "event_handler"),
    ('<a/onclick="x">y</a>', "event_handler"),          # HTML5 slash-delimited handler
    ('<a href="javascript:alert(1)">x</a>', "js_uri"),
    ('<a href="vbscript:msgbox">x</a>', "vbscript_uri"),
    ('<a href="data:text/html,<b>x">y</a>', "data_html_uri"),
    ("<iframe src=//x></iframe>", "iframe"),
    ("<object data=x></object>", "object_embed"),
    ("<form action=/x>", "form"),
    ("<meta http-equiv=refresh>", "meta_or_base"),
    ("<style>body{}</style>", "external_style"),
    ("<svg onload=1>", "svg_or_math"),
    ('<iframe srcdoc="<b>x">', "srcdoc"),
    ("<ScRiPt>alert(1)</ScRiPt>", "script_tag"),        # case-insensitive
    ("<IFRAME src=x>", "iframe"),
])
def test_detect_flags_hostile_patterns(raw, reason):
    assert reason in es.detect_malicious(raw)


@pytest.mark.parametrize("raw", [
    "<p>To escape a tag write &lt;script&gt; in your text.</p>",   # escaped text, not a real tag
    "<p>Set the <code>vbscript:</code> prefix on legacy hosts.</p>",  # prose mention, not an attr
    "<p>A data:text/html URL is a scheme worth knowing.</p>",
])
def test_detect_does_not_false_positive_on_escaped_text_or_prose(raw):
    # detect_malicious gates rejection + a security event, so a legitimate template that merely
    # displays these strings must not be refused.
    assert es.detect_malicious(raw) == []


@pytest.mark.parametrize("hostile", [
    "<script>x</script>", '<div onclick="x">y</div>', '<a href="javascript:x">y</a>',
    "<iframe src=x></iframe>", '<img src=x onerror="x">', '<a href="vbscript:x">y</a>',
])
def test_hostile_reasons_flags_real_injection(hostile):
    assert es.hostile_reasons(hostile)


@pytest.mark.parametrize("benign", [
    "<style>.x{color:red}</style>", "<meta http-equiv=refresh>", "<form action=/x>x</form>",
    "<svg width=1></svg>", "<table><tr><td>c</td></tr></table>",
])
def test_hostile_reasons_excludes_benign_but_unsupported_markup(benign):
    # These are stripped by the sanitizer, not treated as an attack — no reject, no security event.
    assert es.hostile_reasons(benign) == []


def test_render_subject_strips_control_chars_from_substituted_value():
    ctx = es.token_context(recipient={"username": "eve\r\nBcc: attacker@evil.example"})
    out = es.render_subject("Hi {{user.username}}", ctx)
    assert "\r" not in out and "\n" not in out          # no header injection possible
    assert out == "Hi eveBcc: attacker@evil.example"


def test_detect_malicious_is_linear_not_quadratic_on_adversarial_input():
    # The bounded event_handler scan must not blow up on "<a<a<a…" (no '>' anchor). A quadratic
    # scan would take minutes at this size; the bounded one is well under a second.
    import time
    payload = "<a" * 120000   # ~240 KB
    start = time.perf_counter()
    es.detect_malicious(payload)
    assert time.perf_counter() - start < 2.0


# --------------------------------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------------------------------

def test_substitute_known_tokens_text_context():
    ctx = es.token_context(recipient={"username": "jsmith", "email": "j@x.example"},
                           brand_name="Acme Vault")
    out = es.substitute_tokens("Hi {{user.username}} &lt;{{user.email}}&gt; via {{vault.name}}", ctx)
    assert "jsmith" in out and "j@x.example" in out and "Acme Vault" in out
    assert "{{user.username}}" not in out


def test_substitute_escapes_recipient_value_text_context():
    ctx = es.token_context(recipient={"username": "<script>evil</script>", "email": "a@b.example"})
    out = es.substitute_tokens("Hello {{user.username}}", ctx)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_substitute_in_quoted_attribute_cannot_break_out():
    # A token placed inside a quoted attribute must not let a recipient value inject a new attribute.
    # Would FAIL with quote=False (the pre-fix behavior).
    clean = es.sanitize_email_html('<a href="https://x.example" title="Hi {{user.username}}">c</a>')
    ctx = es.token_context(recipient={"username": 'evil" onmouseover="alert(1)'})
    out = es.substitute_tokens(clean, ctx)
    assert 'onmouseover="' not in out              # no live handler (the breakout quote is escaped)
    assert "&quot;" in out or "&#34;" in out        # the recipient's " was escaped


def test_render_send_neutralizes_token_url_scheme_injection():
    # A token that forms an entire URL value must not smuggle a javascript: scheme past the allowlist.
    # Would FAIL without the post-substitution re-sanitize.
    body = '<a href="{{user.username}}">click</a>'
    ctx = es.token_context(recipient={"username": "javascript:alert(document.domain)"})
    html, _ = es.render_for_send(body, context=ctx, load_resource=lambda r: None)
    assert "javascript:" not in html.lower()


def test_render_preview_neutralizes_attribute_injection():
    body = '<a href="https://x.example" title="Hi {{user.display_name}}">c</a>'
    ctx = es.token_context(recipient={"display_name": 'x" onmouseover="alert(1)'})
    out = es.render_for_preview(body, context=ctx,
                                resource_exists=lambda r: False, resource_url=lambda r: "")
    assert 'onmouseover="' not in out
    assert "alert(1)" in out                       # the value survives as inert text


def test_unknown_tokens_left_literal_and_reported():
    text = "Hi {{user.username}} {{totally_unknown}} {{another.bad}}"
    ctx = es.token_context(recipient={"username": "j"})
    out = es.substitute_tokens(text, ctx)
    assert "{{totally_unknown}}" in out            # left as literal, harmless text
    assert set(es.unknown_tokens(text)) == {"totally_unknown", "another.bad"}


def test_token_whitespace_inside_braces_substitutes():
    ctx = es.token_context(recipient={"username": "jo"})
    assert "jo" in es.substitute_tokens("Hi {{  user.username  }}", ctx)


def test_substitute_tokens_plain_does_not_html_escape():
    # A subject is a header, not HTML: values go in verbatim (no &amp;), unknown tokens stay literal.
    ctx = es.token_context(recipient={"username": "A & B <co>"})
    out = es.substitute_tokens_plain("Welcome {{user.username}} {{unknown}}", ctx)
    assert out == "Welcome A & B <co> {{unknown}}"
    assert es.substitute_tokens_plain("", ctx) == ""


def test_token_context_fields():
    present = es.token_context(recipient={"username": "u", "display_name": "Display N"})
    assert present["user.display_name"] == "Display N"
    missing = es.token_context(recipient={"username": "u"})
    assert missing["user.display_name"] == "u"     # falls back to username
    empty = es.token_context(recipient={})
    assert empty["user.username"] == "" and empty["user.email"] == "" and empty["user.display_name"] == ""


# --------------------------------------------------------------------------------------------------
# resource id extraction + image resolution
# --------------------------------------------------------------------------------------------------

def test_extract_resource_ids_valid_only_canonical():
    html = (f'<img data-resource-id="{_UUID_A}"><img data-resource-id="not-a-uuid">'
            f'<img data-resource-id="{_UUID_B}"><img data-resource-id="{_UUID_A}">')
    clean = es.sanitize_email_html(html)
    ids = es.extract_resource_ids(clean)
    assert ids == [_UUID_A, _UUID_B]               # deduped, ordered, invalid dropped


def test_resource_id_case_insensitive_dedup():
    # The same UUID written in different case is ONE resource, not two.
    html = f'<img data-resource-id="{_UUID_A.upper()}"><img data-resource-id="{_UUID_A}">'
    clean = es.sanitize_email_html(html)
    assert es.extract_resource_ids(clean) == [_UUID_A]
    out, atts = es.render_for_send(clean, context=es.token_context(),
                                   load_resource=lambda r: ("image/png", b"P"))
    assert len(atts) == 1                           # one attachment, both imgs share the cid
    assert out.count(f"cid:{atts[0].cid}") == 2


def test_render_preview_resolves_and_drops():
    body = (f'<p>a</p><img data-resource-id="{_UUID_A}"><img data-resource-id="{_UUID_B}">'
            '<script>alert(1)</script>')
    ctx = es.token_context()
    exists = {_UUID_A}  # B is dangling
    out = es.render_for_preview(
        body, context=ctx,
        resource_exists=lambda rid: rid in exists,
        resource_url=lambda rid: f"/email/resources/{rid}")
    assert f'src="/email/resources/{_UUID_A}"' in out
    assert _UUID_B not in out                       # dangling reference dropped entirely, no remnant
    assert "data-resource-id" not in out            # resolved img keeps only the src, not the raw id
    assert "<script" not in out.lower()


def test_render_preview_escapes_resource_url():
    # A resource_url containing a quote must be escaped in the injected src (defensive).
    body = f'<img data-resource-id="{_UUID_A}">'
    out = es.render_for_preview(body, context=es.token_context(),
                                resource_exists=lambda r: True,
                                resource_url=lambda r: '/x?a="b')
    assert 'src="/x?a="b"' not in out
    assert "&quot;" in out


def test_render_send_two_distinct_resources():
    body = f'<img data-resource-id="{_UUID_A}"><img data-resource-id="{_UUID_B}">'
    store = {_UUID_A: ("image/png", b"AAA"), _UUID_B: ("image/gif", b"BBB")}
    html, atts = es.render_for_send(body, context=es.token_context(),
                                    load_resource=lambda r: store.get(r))
    assert len(atts) == 2
    assert {a.content_type for a in atts} == {"image/png", "image/gif"}
    assert {a.data for a in atts} == {b"AAA", b"BBB"}
    assert atts[0].cid != atts[1].cid
    assert f"cid:{atts[0].cid}" in html and f"cid:{atts[1].cid}" in html


def test_render_send_produces_cid_and_dedups():
    body = f'<p>Hi {{{{user.username}}}}</p><img data-resource-id="{_UUID_A}"><img data-resource-id="{_UUID_A}">'
    ctx = es.token_context(recipient={"username": "jo"})
    store = {_UUID_A: ("image/png", b"\x89PNG-bytes")}
    html, attachments = es.render_for_send(body, context=ctx, load_resource=lambda rid: store.get(rid))
    assert "Hi jo" in html
    assert len(attachments) == 1                    # one part even though the image appears twice
    cid = attachments[0].cid
    assert html.count(f"cid:{cid}") == 2
    assert attachments[0].content_type == "image/png"
    assert attachments[0].data == b"\x89PNG-bytes"
    assert "/email/resources/" not in html          # never a URL/path to the resource
    assert _UUID_A not in html                       # the UUID itself never appears in sent HTML


def test_render_send_drops_unresolved_image():
    body = f'<img data-resource-id="{_UUID_A}"><img data-resource-id="{_UUID_B}">'
    html, attachments = es.render_for_send(
        body, context=es.token_context(),
        load_resource=lambda rid: ("image/png", b"x") if rid == _UUID_A else None)
    assert len(attachments) == 1
    assert _UUID_B not in html


@pytest.mark.parametrize("bad", [
    "not-a-uuid",
    '"><script>',
    "",
])
def test_crafted_resource_id_yields_no_image_no_src(bad):
    clean = es.sanitize_email_html(f'<img data-resource-id="{bad}">')
    assert es.extract_resource_ids(clean) == []
    html, atts = es.render_for_send(
        clean, context=es.token_context(), load_resource=lambda r: ("image/png", b"x"))
    assert "<img" not in html and atts == []
    assert "onerror" not in html.lower() and "<script" not in html.lower()


def test_attribute_injection_beside_resource_id_is_stripped_uuid_still_resolves():
    # An attacker appending an extra attribute to the id value can't survive: nh3 splits it off and
    # strips it (onerror is not allowlisted), leaving a clean UUID that resolves normally.
    raw = f'<img data-resource-id="{_UUID_A}" onerror="alert(1)">'
    clean = es.sanitize_email_html(raw)
    assert "onerror" not in clean.lower()
    html, atts = es.render_for_send(
        clean, context=es.token_context(), load_resource=lambda r: ("image/png", b"x"))
    assert len(atts) == 1 and "onerror" not in html.lower()


def test_raw_src_image_cannot_survive_to_send():
    # A raw <img src="..."> has its src stripped by sanitize and, lacking a valid resource id, is
    # dropped at render — so no external URL can ride out in a message.
    body = '<img src="http://evil.example/track.gif">'
    html, attachments = es.render_for_send(
        body, context=es.token_context(), load_resource=lambda rid: None)
    assert "evil.example" not in html
    assert attachments == []


def test_render_send_resanitizes_tampered_body():
    # Defense-in-depth: a body tampered with directly in the DB cannot carry active content out.
    body = '<p>hi</p><script>steal()</script><div onclick="x()">z</div><a href="javascript:1">l</a>'
    html, atts = es.render_for_send(body, context=es.token_context(), load_resource=lambda r: None)
    low = html.lower()
    assert "<script" not in low and "onclick" not in low and "javascript:" not in low
    assert "steal" not in html


def test_render_preview_resanitizes_tampered_body():
    body = '<p>hi</p><script>steal()</script>'
    out = es.render_for_preview(body, context=es.token_context(),
                                resource_exists=lambda r: False, resource_url=lambda r: "")
    assert "<script" not in out.lower() and "steal" not in out


# --------------------------------------------------------------------------------------------------
# entity-encoded payloads + plaintext fallback + catalog
# --------------------------------------------------------------------------------------------------

def test_entity_encoded_script_stays_inert_and_unflagged():
    raw = "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert es.detect_malicious(raw) == []           # escaped text, not a real tag
    out = es.sanitize_email_html(raw)
    assert "<script" not in out.lower()             # not decoded into a live tag
    assert "&lt;script&gt;" in out                  # preserved as visible text


def test_plaintext_fallback_conversions():
    txt = es.render_plaintext_fallback("<h1>Title</h1><p>Hello<br>world</p><p>bye</p>")
    assert "<" not in txt
    assert txt == "Title\nHello\nworld\nbye"


def test_plaintext_fallback_unescapes_entities():
    assert es.render_plaintext_fallback("<p>a &amp; b</p>") == "a & b"


def test_dynamic_actions_catalog_shape():
    tokens = {a.token for a in es.DYNAMIC_ACTIONS}
    assert {"current_date", "user.username", "user.email", "vault.name"} <= tokens
    for a in es.DYNAMIC_ACTIONS:
        assert a.token and a.label and a.sample and a.group


def test_dynamic_action_groups_cover_every_token_in_order():
    groups = es.dynamic_action_groups()
    names = [g["group"] for g in groups]
    # the expected groups appear, and in declaration order
    assert names == ["Recipient", "Sender", "Branding", "Date & time", "Automated action"]
    grouped_tokens = {a["token"] for g in groups for a in g["actions"]}
    assert grouped_tokens == {a.token for a in es.DYNAMIC_ACTIONS}     # no token dropped/duplicated
    # the new useful tokens are present
    assert {"sender.from_name", "sender.from_email", "vault.url", "current_year",
            "action.link", "action.code", "action.expires"} <= grouped_tokens


def test_token_context_has_every_catalog_key_and_never_none():
    ctx = es.token_context()          # all inputs omitted
    for a in es.DYNAMIC_ACTIONS:
        assert a.token in ctx                     # every catalog key is present
        assert isinstance(ctx[a.token], str)      # a string (empty when the input was omitted), never None


def test_substitute_escapes_attribute_breakout_at_substitution_time():
    # Pin the substitute-TIME escape (quote=True) independently of the later re-sanitize: a token value
    # in a quoted attribute cannot break out and add an event handler.
    out = es.substitute_tokens('<a title="{{sender.from_name}}">x</a>',
                               {"sender.from_name": 'a" onmouseover="alert(1)'})
    assert "&quot;" in out                        # the quote was HTML-escaped at substitution time
    assert 'onmouseover="alert' not in out        # so it never became a real quoted attribute
    assert '" onmouseover' not in out             # no literal quote closes the title attribute


def test_token_context_populates_new_groups():
    ctx = es.token_context(
        recipient={"username": "jo", "email": "jo@x.test"},
        brand_name="Acme Vault", vault_url="https://v.example.com",
        sender={"from_name": "Acme", "from_email": "no-reply@x.test"},
        action={"link": "https://v.example.com/i/abc", "code": "123456", "expires": "in 1 hour"})
    assert ctx["sender.from_name"] == "Acme" and ctx["sender.from_email"] == "no-reply@x.test"
    assert ctx["vault.url"] == "https://v.example.com"
    assert ctx["action.link"].endswith("/i/abc") and ctx["action.code"] == "123456"
    assert ctx["action.expires"] == "in 1 hour"
    assert ctx["current_year"].isdigit() and len(ctx["current_year"]) == 4


def test_new_tokens_substitute_and_escape_in_send():
    # the new tokens render through the full send path, and a hostile value stays inert (escaped).
    body = '<p>Hi {{user.username}} — <a href="{{action.link}}">open</a> · {{sender.from_name}}</p>'
    ctx = es.token_context(recipient={"username": "jo"},
                           sender={"from_name": 'Ops"><script>x</script>'},
                           action={"link": "https://v.example.com/i/abc"})
    html, _ = es.render_for_send(body, context=ctx, load_resource=lambda r: None)
    assert "jo" in html and "https://v.example.com/i/abc" in html
    assert "<script" not in html.lower()          # the hostile from_name value can't inject markup
