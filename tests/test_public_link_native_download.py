"""The link page hands a public file to the browser to download itself, offline.

A Download click redeems the link for a single-use grant and then navigates to the download address
with the grant in its query: an ordinary request the browser saves as the server's Content-Disposition
says, never a fetch into the page and a blob (which held the whole file in the page's memory and which
in-app browsers often cannot save). What that rests on, pinned here:

- the route takes the grant from the query as well as from the X-Download-Grant header, and serves
  both the same way; a refusal of the query form is a small page the browser can show, the header
  form keeps its JSON body;
- a prefetch, prerender or preview is refused before the grant is looked at;
- an address that holds a secret is served with a referrer policy that sends the origin alone, so the
  page's own requests (its redeem, the download) never repeat its token in a Referer;
- the page's script downloads by navigation, holds no grant between clicks, and never builds a blob.

tests/test_ui_public_link_native_download.py checks it in a browser against a running deployment.
"""
import re
from pathlib import Path

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
PAGE_JS = (ROOT / "static" / "js" / "public-link.js").read_text(encoding="utf-8")


# ---- the route: two ways to present the grant ----------------------------------------------------

@pytest.fixture
def served(monkeypatch):
    calls = []
    outcome = {"refuse": None}

    async def fake_serve(token, file_id, request, db, presented_grant):
        calls.append(presented_grant)
        if outcome["refuse"] is not None:
            raise outcome["refuse"]
        return "the file"

    monkeypatch.setattr(S, "_serve_public_link_download", fake_serve)

    def call(header=None, query=None, refuse=None):
        outcome["refuse"] = refuse
        calls.clear()
        result = run_coroutine(S.download_public_link("tok", "fid", None, None,
                                                      x_download_grant=header, grant=query))
        return result, list(calls)

    return call


def test_the_query_grant_and_the_header_grant_are_served_alike(served):
    assert served(query="g-query") == ("the file", ["g-query"])
    assert served(header="g-header") == ("the file", ["g-header"])
    assert served(header="g-header", query="g-query") == ("the file", ["g-header"])  # the header wins


def test_no_grant_at_all_is_served_as_the_header_form(served):
    with pytest.raises(HTTPException) as refused:
        served(refuse=HTTPException(status_code=404, detail="This file is not available."))
    assert refused.value.status_code == 404


@pytest.mark.parametrize("status, headers, title", [
    (404, None, "This file could not be downloaded"),
    (429, {"Retry-After": "17"}, "Too many requests"),
    (503, {"Retry-After": "5"}, "The server is busy"),
])
def test_a_refused_query_download_is_a_page_the_browser_can_show(served, status, headers, title):
    page, calls = served(query="g", refuse=HTTPException(status_code=status, detail="x", headers=headers))
    assert calls == ["g"]
    assert page.status_code == status
    assert page.media_type == "text/html"
    body = page.body.decode()
    assert f"<title>{title}</title>" in body and "<h1 " in body and "go back to the link page" in body.lower()
    assert "<script" not in body.lower() and "href=" not in body.lower()
    assert page.headers["Cache-Control"] == "no-store"
    assert page.headers["X-Robots-Tag"] == "noindex, nofollow"
    for name, value in (headers or {}).items():
        assert page.headers[name] == value


def test_a_refused_header_download_keeps_its_json_body(served):
    with pytest.raises(HTTPException) as refused:
        served(header="g", refuse=HTTPException(status_code=404, detail="This file is not available."))
    assert refused.value.detail == "This file is not available."


# ---- a request made ahead of the person spends nothing -------------------------------------------

class _Headers(dict):
    def get(self, name, default=None):
        return super().get(name.lower(), default)


class _Request:
    def __init__(self, **headers):
        self.headers = _Headers({k.lower().replace("_", "-"): v for k, v in headers.items()})


@pytest.mark.parametrize("headers", [
    {"Sec-Purpose": "prefetch"}, {"Sec-Purpose": "prefetch;prerender"}, {"Purpose": "prefetch"},
    {"X-Purpose": "preview"}, {"X-Moz": "prefetch"}, {"Sec-Purpose": "Prefetch"},
])
def test_a_prefetch_or_preview_is_recognised(headers):
    assert S._publiclink_is_speculative(_Request(**headers)) is True


@pytest.mark.parametrize("headers", [{}, {"Sec-Fetch-Dest": "document"}, {"Sec-Purpose": ""}])
def test_the_persons_own_request_is_not(headers):
    assert S._publiclink_is_speculative(_Request(**headers)) is False


def test_a_speculative_request_is_refused_before_the_grant_is_looked_at(monkeypatch):
    seen = []
    monkeypatch.setattr(S, "_publiclink_consume_grant", lambda *a, **k: seen.append(a) or True)
    monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.10")

    async def go():
        await S._serve_public_link_download("tok", "fid", _Request(sec_purpose="prefetch"), None, "g")

    with pytest.raises(HTTPException) as refused:
        run_coroutine(go())
    assert refused.value.status_code == 404 and seen == []


def test_the_speculative_check_comes_before_the_rate_limit_and_the_database():
    import inspect

    src = inspect.getsource(S._serve_public_link_download)
    code = "\n".join(line for line in src.splitlines() if not line.strip().startswith("#"))
    check = code.index("if _publiclink_is_speculative(request):")
    assert code.count("if _publiclink_is_speculative(request):") == 1
    assert check < code.index("_rl.check_rate_limit(") < code.index("_publiclink_consume_grant(")


# ---- the referrer policy of an address that holds a secret ---------------------------------------

@pytest.mark.parametrize("path, query", [
    ("/p/aToken", ""), ("/l/aToken", ""), ("/u/aToken", ""),
    ("/public-links/aToken/redeem", ""), ("/public-links/aToken/download/fid", "grant=g"),
    ("/note-links/aToken/redeem", ""), ("/receivers/aToken/upload-session", ""),
    ("/invites/aToken", ""), ("/reset/aToken", ""), ("/", "invite=aToken"), ("/", "reset=aToken"),
])
def test_an_address_that_holds_a_secret_sends_the_origin_alone(path, query):
    assert S._referrer_policy(path, query) == "strict-origin"


@pytest.mark.parametrize("path, query", [
    ("/", ""), ("/vaults", "page=2"), ("/public-links", ""), ("/public-links/1234/revoke", ""),
    ("/static/js/public-link.js", "v=1"), ("/note-links", ""),
])
def test_any_other_address_keeps_the_default(path, query):
    assert S._referrer_policy(path, query) == "strict-origin-when-cross-origin"


def _policy_through_the_middleware(path, query=b""):
    from starlette.requests import Request
    from starlette.responses import HTMLResponse

    mw = S.SecurityHeadersMiddleware(app=None)
    request = Request({"type": "http", "method": "GET", "path": path, "raw_path": path.encode(),
                       "query_string": query, "headers": [(b"host", b"vault.example")],
                       "client": ("198.51.100.20", 5000), "server": ("vault.example", 80), "scheme": "http",
                       "root_path": ""})

    async def call_next(_request):
        return HTMLResponse("<!doctype html><title>x</title>")

    return run_coroutine(mw.dispatch(request, call_next)).headers["Referrer-Policy"]


def test_the_middleware_sets_the_policy_from_the_address():
    assert _policy_through_the_middleware("/p/aToken") == "strict-origin"
    assert _policy_through_the_middleware("/public-links/aToken/download/fid", b"grant=g") == "strict-origin"
    assert _policy_through_the_middleware("/", b"invite=aToken") == "strict-origin"
    assert _policy_through_the_middleware("/") == "strict-origin-when-cross-origin"


# ---- the page's script ----------------------------------------------------------------------------

def _code(js):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", js, flags=re.S)


def test_the_page_downloads_by_navigation_and_never_into_its_own_memory():
    code = _code(PAGE_JS)
    for gone in ("createObjectURL", ".blob(", "X-Download-Grant", "arrayBuffer", "pendingGrant",
                 "a.download", "window.open("):
        assert gone not in code, gone
    # One download address, with the grant in its query, opened by a link the click makes and removes.
    assert code.count('"?grant=" + encodeURIComponent(grant)') == 1
    start = code[code.index("function startDownload("):code.index("function refusedText(")]
    assert "a.href = downloadAddress(fileId, grant);" in start
    assert start.index("document.body.appendChild(a);") < start.index("a.click();") < start.index("a.remove();")
    # The only fetches are the redeems; the download is the grant's single request.
    assert code.count("fetch(") == 1 and 'fetch("/public-links/" + encodeURIComponent(token) + "/redeem"' in code


def test_a_download_click_redeems_for_real_then_starts_the_download():
    code = _code(PAGE_JS)
    body = code[code.index("function download(fileId, btn) {"):code.index("function fileRow(")]
    assert body.count("redeem(false)") == 1 and "redeem(true)" not in body
    assert body.count("startDownload(fileId, data.grant);") == 1
    assert body.index("redeem(false)") < body.index("startDownload(fileId, data.grant);")
    # The listing and the unlock only ever peek.
    rest = code.replace(body, "")
    assert "redeem(false)" not in rest and rest.count("redeem(true)") == 2
