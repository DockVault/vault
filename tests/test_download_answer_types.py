"""A file that can be fetched by its address without signing in is never answered under a type a browser runs.

A stored MIME type is whatever its uploader claimed. A public file link's download address needs no sign-in, so any
page can name it: as the source of a script, a style sheet, a frame. Answered under the uploader's type, a file
stored as a script would then run as part of the vault's own origin, where a policy of "scripts from this origin
only" lets it through. So that answer goes out under the stored type only when a browser neither runs nor applies
that type, and as plain bytes otherwise; it is an attachment, sniffing is off, and it carries a policy under which
nothing runs if it is ever opened as a page.

Pinned here, offline:

- the rule itself (app/api/api_server.py _browser_runs, _download_media_type), over every kind of type a browser
  runs or applies, in odd spellings, and over the types that must stay as they are;
- that there is one list of those types: a compliance case's content route reads the same one;
- the real download handler, run against a stand-in database and stored file: the headers of its answer;
- the source: the public download takes its type from that rule and nothing else, and the one route that still
  answers with the stored type as it is needs a signed-in user (a bearer header no page's markup can send).

tests/test_ui_public_link_native_download.py and tests/test_api_public_links_native.py check the download itself
against a running deployment.
"""
import ast
import types
import uuid
from pathlib import Path

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.api import compliance_router as cr  # noqa: E402
from app.core import rate_limiter as R  # noqa: E402
from app.core.transfer_admission import TransferAdmission  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api"
BYTES = "application/octet-stream"
TEXT = "text/plain; charset=utf-8"
NOTHING_RUNS = "default-src 'none'; sandbox"

# The JavaScript MIME types of the WHATWG MIME Sniffing standard, written out here on their own so that dropping one
# from the server's list is seen.
JAVASCRIPT = [
    "application/ecmascript", "application/javascript", "application/x-ecmascript", "application/x-javascript",
    "text/ecmascript", "text/javascript", "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "text/jscript", "text/livescript",
    "text/x-ecmascript", "text/x-javascript",
]

RUN = JAVASCRIPT + [
    # scripts, in other spellings
    "TEXT/JAVASCRIPT", "Text/JavaScript", " text/javascript ", "text/javascript; charset=utf-8",
    "text/javascript ;charset=utf-8", "APPLICATION/X-JAVASCRIPT; CHARSET=UTF-8", 'text/javascript; x="y"',
    "text/javascript1.8", "application/javascript1.7", "application/x-jscript", "text/vbscript", "text/vbs",
    # what a page applies when it names it
    "text/css", "TEXT/CSS", "text/css; charset=utf-8", "application/wasm", "Application/Wasm",
    "application/webbundle", "text/vtt", "text/xsl", "text/xslt", "application/xslt+xml",
    # pages
    "text/html", "TEXT/HTML", "text/html; charset=utf-8", "text/html;charset=utf-7", "application/xhtml+xml",
    "image/svg+xml", "IMAGE/SVG+XML", "image/svg+xml; charset=utf-8", "multipart/x-mixed-replace",
    "multipart/x-mixed-replace; boundary=frame",
    # every XML type
    "text/xml", "application/xml", "application/xml; charset=utf-8", "application/rss+xml", "application/atom+xml",
    "application/vnd.mozilla.xul+xml", "application/mathml+xml", "image/x-thing+xml", "video/x-thing+xml",
    "audio/x-thing+xml", "APPLICATION/X-THING+XML", "x-made-up/xml", "application/xml-dtd",
    "application/xml-external-parsed-entity", "text/xml-external-parsed-entity",
    # an XML type known only by its shape, with a parameter after it, and named anywhere else in the value
    "application/rss+xml; charset=utf-8", "application/atom+xml ;charset=utf-8", "X-Made-Up/XML ; q=1",
    'image/png; x="application/rss+xml"', 'image/png; x="a, x-made-up/xml "', 'video/mp4; note="image/x-thing+xml"',
    # a type one browser lays out as XML though it has no XML shape
    "text/rdf", "TEXT/RDF; charset=utf-8", 'video/mp4; x="text/rdf"',
    # every stream of parts: each part is laid out under the type the part names
    "multipart/mixed", "multipart/mixed; boundary=part", "Multipart/Byteranges; boundary=part", "multipart/related",
    'multipart/related; type="application/x-thing"', "multipart/form-data; boundary=part",
    'image/png; x="multipart/mixed"',
    # a listed type named anywhere in the value
    'image/png; x="text/html"', 'text/plain; note="application/javascript"', 'image/png; type="text/css"',
    'video/webm; codecs="vp8, text/javascript"', "application/octet-stream; kind=javascript",
]

KEPT = [
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/x-icon", "video/mp4", "video/webm",
    'video/webm; codecs="vp8, opus"', "audio/mpeg", "audio/ogg", "application/pdf", "text/plain",
    "text/plain; charset=utf-8", "text/csv", "text/markdown", "application/zip", "application/gzip",
    "application/x-tar", "font/woff2", "application/octet-stream", "message/rfc822",
    # JSON is data: a script element and a module both refuse it, and a JSON module is only parsed
    "application/json", "application/ld+json", "application/manifest+json", "text/json",
    # office documents: "xml" is in their names, and they are not XML types
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel", "application/msword", "application/vnd.oasis.opendocument.text",
    # a name that ends in "script" is not a script language a browser runs
    "application/postscript", "application/typescript", "text/x-shellscript", "text/x-python",
]

GARBAGE = [
    None, "", "   ", "not a type", "/", "text/", "/html", "text/html\r\nX-Injected: 1", "text/html\x00",
    "text/javascript\n", "текст/html", "text/htmlé", "text/plain,text/javascript", "text/plain, text/html",
    "text/javascript,", "text/plain;;", "text/plain; charset", 'text/plain; x="a', "a" * 300,
    "text/html " + "x" * 300,
]


# ---- the rule ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("stored", RUN)
def test_a_type_a_browser_runs_or_applies_is_sent_as_plain_bytes(stored):
    assert S._browser_runs(S._safe_media_type(stored)) is True
    assert S._download_media_type(stored) == BYTES


@pytest.mark.parametrize("stored", KEPT)
def test_a_type_a_browser_only_shows_or_saves_is_sent_as_stored(stored):
    assert S._browser_runs(stored) is False
    assert S._download_media_type(stored) == stored


@pytest.mark.parametrize("stored", GARBAGE)
def test_a_value_that_is_not_a_type_is_sent_as_plain_bytes(stored):
    assert S._download_media_type(stored) == BYTES


def test_the_list_holds_every_javascript_type_of_the_standard_and_changes_only_on_purpose():
    """The list, written out a second time: a type taken off it, or put on it, has to be taken off or put on
    here too. Several of its types are also caught by a rule beside it (an XML type by its shape, a script by its
    language's name), so a type could leave the list without any answer above changing."""
    assert len(JAVASCRIPT) == len(set(JAVASCRIPT)) == 16
    assert S._BROWSER_RUN_TYPES == set(JAVASCRIPT) | {
        "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml", "application/xml-dtd",
        "text/rdf", "multipart/x-mixed-replace",
        "text/css", "text/xsl", "text/xslt", "application/xslt+xml", "text/vtt", "application/wasm",
        "application/webbundle",
        "text/vbscript", "text/vbs",
    }
    assert S._SCRIPT_LANGUAGE_NAMES == ("javascript", "ecmascript", "jscript", "livescript", "vbscript")
    assert S._BROWSER_RUN_SHAPES == ("/xml", "+xml", "multipart/")


@pytest.mark.parametrize("subtype", ["xml", "rss+xml", "x-thing+xml", "vnd.example.record+xml"])
@pytest.mark.parametrize("kind", ["application", "text", "image", "video", "audio", "x-made-up"])
def test_every_xml_type_has_the_shape_the_rule_looks_for(kind, subtype):
    """An XML type is one whose subtype is xml or ends in +xml. The rule looks for what such a type always has in
    it, anywhere in the stored value, so no way of writing one around it is left."""
    xml = f"{kind}/{subtype}"
    for stored in (xml, xml.upper(), f"{xml}; charset=utf-8", f"{xml} ;charset=utf-8", f'image/png; x="{xml}"',
                   f'image/png; x="a, {xml} "', f"text/plain; a='; b=\"', {xml} \""):
        assert S._safe_media_type(stored) == stored.strip(), "the value must be one that can be stored and sent"
        assert S._download_media_type(stored) == BYTES, stored
        assert cr._content_type(stored) == TEXT, stored


def test_no_answer_of_the_rule_is_ever_one_a_browser_runs():
    """Whatever is stored, what comes out is plain bytes or a type the rule itself calls safe, and it never
    names a page's type: the header middleware puts the application's own page policy on an answer that does,
    in place of the answer's own."""
    for stored in RUN + KEPT + GARBAGE:
        sent = S._download_media_type(stored)
        assert sent == BYTES or not S._browser_runs(sent), stored
        assert "text/html" not in sent.lower(), stored


# ---- one list -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("stored", RUN)
def test_a_case_shows_the_same_types_as_text(stored):
    assert cr._content_type(stored) == TEXT


@pytest.mark.parametrize("stored", KEPT)
def test_a_case_shows_the_other_types_as_stored(stored):
    assert cr._content_type(stored) == stored


def test_the_case_route_keeps_no_list_of_its_own():
    assert not hasattr(cr, "_ACTIVE_TYPES")
    source = (API / "compliance_router.py").read_text(encoding="utf-8")
    body = _function(ast.parse(source), "_content_type")
    assert sorted(_name(c.func) for c in _calls(body)) == ["_browser_runs", "_safe_media_type"]
    # No set or tuple of type names is written out in that module any more.
    for literal in ("text/html", "application/xhtml+xml", "image/svg+xml", "text/javascript"):
        assert f'"{literal}"' not in source, literal


# ---- the real handler: the headers of its answer -------------------------------------------------------------------

ADDRESS = "192.0.2.10"
PIECES = [b"a" * 1000, b"b" * 500]


class _Store:
    def __init__(self):
        self.data = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.data:
            return None
        self.data[key] = value.encode()
        return True

    def get(self, key):
        return self.data.get(key)

    def delete(self, key):
        return 1 if self.data.pop(key, None) is not None else 0


class _Rows:
    def __init__(self, row):
        self._row = row

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._row


class _DB:
    def __init__(self, link, file_row):
        self.link, self.file_row = link, file_row

    def query(self, model, *more):
        return _Rows({S.PublicLink: self.link, S.File: self.file_row}.get(model))

    def execute(self, statement, *args, **kwargs):
        return types.SimpleNamespace(rowcount=1)

    def add(self, obj):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


class _Stored:
    def __init__(self, name, mime_type):
        self.name, self.mime_type = name, mime_type
        self.total_length = sum(len(p) for p in PIECES)

    def chunks(self):
        yield from PIECES

    def close(self):
        pass


class _Request:
    headers = {}

    async def is_disconnected(self):
        return False


@pytest.fixture
def answer(monkeypatch):
    """Run the real download handler for a file stored as (name, type) and return what it sent: its status, its
    headers as the client receives them, and its body."""
    R._cb_record_success()
    monkeypatch.setattr(R.rate_limiter, "redis", _Store(), raising=False)
    monkeypatch.setattr(R.rate_limiter, "check_rate_limit", lambda *a, **k: (True, 0, 0))
    monkeypatch.setattr(S, "get_client_ip", lambda request: ADDRESS)
    monkeypatch.setattr(S.note_link_policy, "public_file_links_enabled", lambda blob: True)
    monkeypatch.setattr(S, "folder_ancestry", lambda db, vault_id, folder_id: [])
    vault = types.SimpleNamespace(id=uuid.uuid4(), type="standard", password_hash=None)
    monkeypatch.setattr(S, "_publiclink_resolve_live", lambda db, link: (vault, object()))
    monkeypatch.setattr(S, "PermissionService", lambda db: object())
    monkeypatch.setattr(S, "AuditLogger", lambda db: types.SimpleNamespace(log_action=lambda **row: None))
    monkeypatch.setattr(S, "transfer_admission", TransferAdmission(limit=2, max_waiting=0, wait_seconds=0))

    def run(name, mime_type, by="header"):
        file_id = uuid.uuid4()
        token = "tok-" + uuid.uuid4().hex
        link = types.SimpleNamespace(
            id=uuid.uuid4(), token_hash=S._publiclink_token_hash(token), revoked=False, expires_at=None,
            max_uses=1, use_count=1, download_count=0, bytes_served=0, target_type="file",
            target_file_id=file_id, target_folder_id=None)
        db = _DB(link, types.SimpleNamespace(id=file_id, folder_id=None, password_hash=None))
        stored = _Stored(name, mime_type)

        class _Service:
            def __init__(self, db, permissions):
                pass

            def _open_stored_file(self, file, vault_, file_id_, whole=True):
                return stored

        monkeypatch.setattr(S, "VaultService", _Service)
        grant = S._publiclink_issue_grant(link.id, ADDRESS)
        how = {"x_download_grant": grant, "grant": None} if by == "header" else \
              {"x_download_grant": None, "grant": grant}

        async def go():
            response = await S.download_public_link(token, file_id, _Request(), db, **how)
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
            [start] = [m for m in sent if m["type"] == "http.response.start"]
            headers = {}
            for key, value in start["headers"]:
                assert key.decode().lower() not in headers, "a header was sent twice"
                headers[key.decode().lower()] = value.decode()
            body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
            return types.SimpleNamespace(status=start["status"], headers=headers, body=body, response=response)

        return run_coroutine(go())

    return run


RUN_AS_STORED = [
    ("code.js", "text/javascript"), ("code.js", "application/javascript; charset=utf-8"),
    ("code.mjs", "TEXT/JAVASCRIPT"), ("look.css", "text/css"), ("module.wasm", "application/wasm"),
    ("page.html", "text/html"), ("page.xhtml", "application/xhtml+xml"), ("picture.png", "image/svg+xml"),
    ("clip.mp4", "video/x-thing+xml"), ("feed.xml", "application/rss+xml"), ("sheet.xsl", "text/xsl"),
    ("cues.vtt", "text/vtt"), ("picture.png", 'image/png; x="text/html"'),
    ("picture.png", 'image/png; x="application/rss+xml"'), ("feed.xml", "application/rss+xml ; charset=utf-8"),
    ("notes.rdf", "text/rdf"), ("saved.mht", "multipart/related; boundary=part"),
]


@pytest.mark.parametrize("by", ["header", "query"])
@pytest.mark.parametrize("name, stored", RUN_AS_STORED)
def test_the_public_download_of_a_file_stored_under_such_a_type_is_plain_bytes_to_save(answer, name, stored, by):
    got = answer(name, stored, by=by)
    assert got.status == 200 and got.body == b"".join(PIECES)
    assert got.headers["content-type"] == BYTES
    assert got.headers["content-disposition"].startswith(f'attachment; filename="{name}"')
    assert got.headers["x-content-type-options"] == "nosniff"
    assert got.headers["content-security-policy"] == NOTHING_RUNS


@pytest.mark.parametrize("name, stored, sent", [
    ("contract.pdf", "application/pdf", "application/pdf"),
    ("photo.jpg", "image/jpeg", "image/jpeg"),
    ("notes.txt", "text/plain", "text/plain; charset=utf-8"),
    ("data.json", "application/json", "application/json"),
    ("report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ("blob.bin", None, BYTES),
])
def test_any_other_public_download_keeps_its_type_and_is_guarded_the_same_way(answer, name, stored, sent):
    got = answer(name, stored)
    assert got.status == 200 and got.body == b"".join(PIECES)
    assert got.headers["content-type"] == sent
    assert got.headers["content-disposition"].startswith(f'attachment; filename="{name}"')
    assert got.headers["x-content-type-options"] == "nosniff"
    assert got.headers["content-security-policy"] == NOTHING_RUNS


@pytest.mark.parametrize("stored", ["text/html", 'image/png; x="text/html"', "text/javascript", "application/pdf"])
def test_the_header_middleware_leaves_the_answers_own_policy_in_place(answer, stored):
    """The application's middleware gives an HTML answer the policy of its own pages, in place of whatever the
    answer carried. A download is never HTML once the rule has typed it, so its own policy is what goes out."""
    from starlette.requests import Request

    got = answer("file.bin", stored)
    path = "/public-links/aToken/download/" + str(uuid.uuid4())
    request = Request({"type": "http", "method": "GET", "path": path, "raw_path": path.encode(),
                       "query_string": b"grant=g", "headers": [(b"host", b"vault.example")],
                       "client": (ADDRESS, 5000), "server": ("vault.example", 80), "scheme": "http",
                       "root_path": ""})

    async def call_next(_request):
        return got.response

    out = run_coroutine(S.SecurityHeadersMiddleware(app=None).dispatch(request, call_next))
    assert out.headers["Content-Security-Policy"] == NOTHING_RUNS
    assert out.headers["X-Content-Type-Options"] == "nosniff"
    assert out.headers["Referrer-Policy"] == "strict-origin"
    assert out.headers.getlist("Content-Security-Policy") == [NOTHING_RUNS]


# ---- the source ---------------------------------------------------------------------------------------------------

def _function(tree, name):
    found = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert len(found) == 1, f"{name}: {len(found)} definitions"
    return found[0]


def _calls(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def _name(func):
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None


def _server():
    return ast.parse((API / "api_server.py").read_text(encoding="utf-8"))


def test_the_public_download_takes_its_type_from_the_rule_and_nothing_else():
    serve = _function(_server(), "_serve_public_link_download")
    # One response, typed by the one variable, which is assigned once, from the rule, given the stored type.
    responses = [c for c in _calls(serve) if any(k.arg == "media_type" for k in c.keywords)]
    assert [ast.unparse(c) for c in responses] == [
        "_ClosingStreamingResponse(file_streamer(), media_type=media_type, headers=headers, on_close=finish)"]
    assigned = [n for n in ast.walk(serve) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "media_type" for t in n.targets)]
    assert [ast.unparse(n) for n in assigned] == ["media_type = _download_media_type(mime_type)"]
    stored = [n for n in ast.walk(serve) if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "mime_type" for t in n.targets)]
    assert [ast.unparse(n) for n in stored] == ["mime_type = download.mime_type"]
    # The stored type reaches nothing else, and no other typing helper is used here.
    used = [n for n in ast.walk(serve) if isinstance(n, ast.Name) and n.id == "mime_type"
            and isinstance(n.ctx, ast.Load)]
    assert len(used) == 1
    assert "_safe_media_type" not in {_name(c.func) for c in _calls(serve)}
    # Its headers say so too, by name: an attachment, sniffing off, a policy under which nothing runs.
    [headers] = [n for n in ast.walk(serve) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "headers" for t in n.targets)]
    given = {k.value: ast.unparse(v) for k, v in zip(headers.value.keys, headers.value.values)}
    assert given["Content-Disposition"] == "_content_disposition(file_name)"
    assert given["X-Content-Type-Options"] == "'nosniff'"
    assert given["Content-Security-Policy"] == "_NOTHING_RUNS_POLICY"
    assert S._NOTHING_RUNS_POLICY == NOTHING_RUNS


def test_the_rule_reads_the_one_list():
    tree = _server()
    rule = _function(tree, "_download_media_type")
    assert sorted(_name(c.func) for c in _calls(rule)) == ["_browser_runs", "_safe_media_type"]
    listed = [n for n in ast.walk(_function(tree, "_browser_runs"))
              if isinstance(n, ast.Name) and n.id == "_BROWSER_RUN_TYPES"]
    assert len(listed) == 1


# Every answer of the API that is given a type, by the expression that types it. A stored type appears in three
# of them only: behind the rule (the public download), behind the case route's use of the same list, and as it is
# on the signed-in download. A new answer typed from a stored value shows up here as a line nobody has looked at.
TYPED_ANSWERS = {
    "api_server.py": sorted([
        "'application/javascript'",                                       # the download worker's own script
        "'text/csv; charset=utf-8' if format == 'csv' else 'application/x-ndjson'",   # the activity export
        "_BRAND_ASSET_MEDIA.get(ext, 'application/octet-stream')",        # a brand picture, typed by the server
        "media_type",                                                     # the public download: the rule
        "_safe_media_type(mime_type)", "_safe_media_type(mime_type)",     # the signed-in download, whole and ranged
    ]),
    "compliance_router.py": sorted(["media", "media", "'application/zip'"]),
    "email_studio_router.py": ["r.content_type"],                         # a picture typed by the server on upload
    "user_management_api.py": ["'application/json'"] * 4,
}


def _typed_answers(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return sorted(ast.unparse(k.value) for c in _calls(tree) for k in c.keywords if k.arg == "media_type")


def test_every_typed_answer_of_the_api_is_one_of_the_known_ones():
    found = {p.name: _typed_answers(p) for p in sorted(API.glob("*.py"))}
    assert {name: typed for name, typed in found.items() if typed} == TYPED_ANSWERS


def test_the_two_pictures_typed_by_the_server_take_no_type_from_their_uploader():
    """The answers above that hold stored bytes and do not go through the rule: each is a picture an administrator
    uploaded, typed by the server from the picture's own bytes."""
    from app.api import email_studio_router as mail

    # A picture of the mail editor (signed-in administrators only): one of four picture types, none of them run.
    kinds = {kind for _magic, kind in mail._IMAGE_MAGIC} | {mail._sniff_image(b"RIFF\x00\x00\x00\x00WEBP")}
    assert kinds == {"image/png", "image/jpeg", "image/gif", "image/webp"}
    assert not any(S._browser_runs(kind) for kind in kinds)
    for not_a_picture in (b"", b"<svg xmlns='http://www.w3.org/2000/svg'/>", b"<!doctype html>", b"let x = 1;"):
        assert mail._sniff_image(not_a_picture) is None
    upload = _function(ast.parse((API / "email_studio_router.py").read_text(encoding="utf-8")), "upload_resource")
    typed = [ast.unparse(n) for n in ast.walk(upload) if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "content_type" for t in n.targets)]
    assert typed == ["content_type = _sniff_image(data)"]
    stored = [k for c in _calls(upload) if _name(c.func) == "EmailResource" for k in c.keywords
              if k.arg == "content_type"]
    assert [ast.unparse(k.value) for k in stored] == ["content_type"]

    # A brand picture (anyone may fetch it: it is on the sign-in page): typed by its extension, which the server
    # chose from the picture's bytes. An SVG is the one type among them a browser runs, so the answer carries a
    # policy under which nothing does, with sniffing off.
    assert {kind for kind in S._BRAND_ASSET_MEDIA.values() if S._browser_runs(kind)} == {"image/svg+xml"}
    [served] = [c for c in _calls(_function(_server(), "get_brand_asset")) if _name(c.func) == "FileResponse"]
    [headers] = [k.value for k in served.keywords if k.arg == "headers"]
    given = {k.value: v.value for k, v in zip(headers.keys, headers.values)}
    assert given["X-Content-Type-Options"] == "nosniff"
    policy = [part.strip() for part in given["Content-Security-Policy"].split(";")]
    assert "default-src 'none'" in policy and "sandbox" in policy
    assert not any(part.startswith(("script-src", "allow-scripts")) for part in policy)


def test_the_stored_type_goes_out_as_it_is_only_to_a_signed_in_user():
    tree = _server()
    callers = sorted(
        fn.name for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        for c in _calls(fn) if _name(c.func) == "_safe_media_type")
    # (nested functions are walked with the function they are in, so a caller is named once per call it makes)
    assert callers == ["_download_media_type", "download_file", "download_file"]
    signed_in = _function(tree, "download_file")
    defaults = dict(zip([a.arg for a in signed_in.args.args][-len(signed_in.args.defaults):],
                        [ast.unparse(d) for d in signed_in.args.defaults]))
    assert defaults["current_user"] == "Depends(get_current_user)"
    # ... and that user comes from a bearer header, which a page's markup cannot send.
    current = _function(tree, "get_current_user")
    credentials = dict(zip([a.arg for a in current.args.args][-len(current.args.defaults):],
                           [ast.unparse(d) for d in current.args.defaults]))
    assert "Depends(security)" in credentials.values()
    assert isinstance(S.security, S.HTTPBearer)
    # The case route's two answers are typed by its own use of the list.
    case = ast.parse((API / "compliance_router.py").read_text(encoding="utf-8"))
    media = [n for n in ast.walk(_function(case, "case_file_content")) if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "media" for t in n.targets)]
    assert [ast.unparse(n) for n in media] == ["media = _content_type(download.mime_type)"]
