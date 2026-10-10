"""The page's Content-Security-Policy lets no form be sent by the browser itself, offline.

``form-action 'none'``: every form on the served pages is sent by script, whose submit handler stops the
browser's own submission, so the browser never needs to send one. A form that escapes its handler (scripts
off, a script that never loaded, injected markup) then sends nothing, to this origin or any other.

Pinned here: the header the middleware sets on an HTML response, over http and over https (TLS in the server
or at a trusted proxy), carries exactly one form-action directive, and it is 'none'; and every form on every
served page has a submit handler in the page's own scripts that calls preventDefault, so nothing the pages do
relies on the browser sending a form.
tests/test_csp_form_action_live.py and tests/test_ui_forms_before_the_app_loads.py check it in a browser.
"""
import pathlib
import re

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"


def _csp_for_html(scheme="http", headers=(), peer="198.51.100.20"):
    from starlette.requests import Request
    from starlette.responses import HTMLResponse
    from app.api import api_server as A

    mw = A.SecurityHeadersMiddleware(app=None)
    request = Request({"type": "http", "method": "GET", "path": "/", "raw_path": b"/", "query_string": b"",
                       "headers": [(b"host", b"vault.example"), *headers], "client": (peer, 5000),
                       "server": ("vault.example", 443 if scheme == "https" else 80), "scheme": scheme,
                       "root_path": ""})

    async def call_next(_request):
        return HTMLResponse("<!doctype html><title>x</title>")

    response = run_coroutine(mw.dispatch(request, call_next))
    return response.headers["Content-Security-Policy"]


@pytest.fixture
def trusted_proxy(monkeypatch):
    from app.core import net_utils
    monkeypatch.setattr(net_utils.settings, "trusted_proxies", "10.0.0.0/8", raising=False)
    monkeypatch.setattr(net_utils.settings, "trust_all_proxies", False, raising=False)
    net_utils._trusted_networks.cache_clear()
    yield
    net_utils._trusted_networks.cache_clear()


# How the page reaches the browser: plain http; https with TLS in the server; and https ended at a trusted
# reverse proxy, which says so in X-Forwarded-Proto (the way production serves it). Over https the policy
# gains upgrade-insecure-requests, which shows the https branch ran.
TRANSPORTS = {
    "http": ({}, False),
    "https in the server": ({"scheme": "https"}, True),
    "https at a trusted proxy": ({"headers": ((b"x-forwarded-proto", b"https"),), "peer": "10.0.0.5"}, True),
}


@pytest.mark.parametrize("transport", list(TRANSPORTS))
def test_the_page_lets_the_browser_send_no_form(trusted_proxy, transport):
    request, https = TRANSPORTS[transport]
    directives = [d.strip() for d in _csp_for_html(**request).split(";")]
    assert ("upgrade-insecure-requests" in directives) is https, directives
    form_action = [d for d in directives if d.split(" ", 1)[0] == "form-action"]
    assert form_action == ["form-action 'none'"], directives


PAGES = sorted(p.name for p in STATIC.glob("*.html"))


def _forms(html):
    return re.findall(r"<form\b[^>]*\bid=\"([^\"]+)\"", html)


def _scripts(html):
    """The page's own scripts, as its markup loads them."""
    names = re.findall(r"<script\b[^>]*\bsrc=\"/static/(js/[^\"?]+)", html)
    return "\n".join((STATIC / n).read_text(encoding="utf-8") for n in names)


def test_the_pages_and_their_forms_are_all_seen():
    assert {"index.html", "note-link.html", "public-link.html"} <= set(PAGES)
    total = 0
    for page in PAGES:
        html = (STATIC / page).read_text(encoding="utf-8")
        assert len(_forms(html)) == len(re.findall(r"<form\b", html, re.I)), f"{page}: a form has no id"
        total += len(_forms(html))
    assert total >= 19, total
    # No script builds a form in markup either: every form is in a page's own HTML.
    for js in sorted((STATIC / "js").glob("*.js")):
        assert not re.search(r"<form\b", js.read_text(encoding="utf-8"), re.I), js.name


def _handler_prevents_default(js, form_id):
    """Whether the scripts bind a submit handler to ``form_id`` that calls preventDefault: the handler is
    found from the form's id (directly, or through the variable the element is held in), and is either an
    inline function or a named one, whose opening lines must call preventDefault."""
    for m in re.finditer(r"(?:document\.)?(?:getElementById|\$)\(\s*['\"]" + re.escape(form_id) + r"['\"]\s*\)", js):
        window = js[m.start():m.start() + 2500]
        held = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*$", js[max(0, m.start() - 60):m.start()])
        binders = [r"^(?:document\.)?(?:getElementById|\$)\([^)]*\)\s*\??\.addEventListener\(\s*['\"]submit['\"]\s*,\s*"]
        if held:
            binders.append(r"\b" + re.escape(held.group(1)) + r"\s*\??\.addEventListener\(\s*['\"]submit['\"]\s*,\s*")
        for binder in binders:
            b = re.search(binder, window, re.M)
            if not b:
                continue
            rest = window[b.end():]
            named = re.match(r"(\w+)\s*\)", rest)
            if named:
                fn = re.search(r"function\s+" + re.escape(named.group(1)) + r"\s*\([^)]*\)\s*\{", js)
                body = _block(js, fn.end()) if fn else ""
            else:
                inline = re.match(r"(?:async\s+)?(?:function\s*)?\(?\s*\w*\s*\)?\s*(?:=>)?\s*\{", rest)
                body = _block(rest, inline.end()) if inline else ""
            if "preventDefault()" in body[:300]:
                return True
    return False


def _block(text, start):
    """The text of the block that opens just before ``start``, up to its matching closing brace."""
    depth = 1
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start:i]
    return text[start:]


@pytest.mark.parametrize("page", PAGES)
def test_every_form_is_sent_by_script_that_stops_the_browser(page):
    html = (STATIC / page).read_text(encoding="utf-8")
    js = _scripts(html)
    missing = [f for f in _forms(html) if not _handler_prevents_default(js, f)]
    assert not missing, f"{page}: forms with no script submit handler that calls preventDefault: {missing}"
    assert not re.search(r"\.submit\(\s*\)|requestSubmit|createElement\(\s*['\"]form", js), \
        f"{page}: a script sends a form through the browser"


def test_the_handler_check_flags_a_form_without_one():
    """The instrument, checked against a control."""
    js = ("document.getElementById('a-form').addEventListener('submit', (e) => { e.preventDefault(); go(); });\n"
          "const f = document.getElementById('b-form');\nif (f) f.addEventListener('submit', sendB);\n"
          "function sendB(e) {\n    e.preventDefault();\n}\n"
          "document.getElementById('c-form').addEventListener('submit', (e) => { go(); });\n"
          "document.getElementById('d-form').addEventListener('click', (e) => { e.preventDefault(); });\n"
          "const g = document.getElementById('f-form');\ng.addEventListener('submit', sendF);\n"
          "function sendF(e) {\n    send();\n}\nfunction later(e) { e.preventDefault(); }\n")
    assert [_handler_prevents_default(js, f) for f in ("a-form", "b-form", "c-form", "d-form", "e-form",
                                                        "f-form")] == [True, True, False, False, False, False]
