"""The page's Content-Security-Policy lets no form be sent by the browser itself, offline.

``form-action 'none'``: every form on the served pages is sent by script, whose submit handler stops the
browser's own submission, so the browser never needs to send one. A form that escapes its handler (scripts
off, a script that never loaded, injected markup) then sends nothing, to this origin or any other.

Pinned here: the header the middleware sets on an HTML response, over http and over https (TLS in the server
or at a trusted proxy), carries exactly one form-action directive, and it is 'none'; and every form on every
served page, and every form a script makes (an invitation's or a reset's password, a vault's password in the
Activity page or a compliance case, a search in a case), has a submit handler whose first statement calls its
event's preventDefault (nothing before it that could return, wait or throw), so nothing the pages do relies on
the browser sending a form.
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
    # No script writes a form as markup either; a form a script makes element by element is checked below.
    for js in sorted((STATIC / "js").glob("*.js")):
        assert not re.search(r"<form\b", js.read_text(encoding="utf-8"), re.I), js.name


def _stops_the_browser_first(body, param):
    """Whether a submit handler's first statement is its event's preventDefault() (``param``: the event's name in
    the handler). Anything before it could leave the handler with the browser's own submission still to come: a
    return, an await, a call that throws; and a call on some paths only, or in a callback, may never run."""
    code = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.S)
    first = re.match(r"\s*" + re.escape(param) + r"\s*\.\s*preventDefault\s*\(\s*\)\s*;", code) if param else None
    return first is not None


def _handler_prevents_default(js, form_id):
    """Whether the scripts bind a submit handler to ``form_id`` that calls preventDefault first: the handler is
    found from the form's id (directly, or through the variable the element is held in), and is either an
    inline function or a named one, whose first statement must be its event's preventDefault(). Never another
    form's handler: one bound directly is bound on the lookup itself, and a variable's binding counts only before
    the name is declared again."""
    submit = r"\s*\??\.addEventListener\(\s*['\"]submit['\"]\s*,\s*"
    for m in re.finditer(r"(?:document\.)?(?:getElementById|\$)\(\s*['\"]" + re.escape(form_id) + r"['\"]\s*\)", js):
        window = js[m.start():m.start() + 2500]
        held = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*$", js[max(0, m.start() - 60):m.start()])
        bindings = [re.match(r"(?:document\.)?(?:getElementById|\$)\([^)]*\)" + submit, window)]
        if held:
            name = re.escape(held.group(1))
            again = re.search(r"\b(?:const|let|var)\s+" + name + r"\b", window)
            bindings.append(re.search(r"\b" + name + submit, window[:again.start()] if again else window))
        for b in bindings:
            if not b:
                continue
            rest = window[b.end():]
            named = re.match(r"(\w+)\s*\)", rest)
            if named:
                fn = re.search(r"function\s+" + re.escape(named.group(1)) + r"\s*\(\s*(\w*)[^)]*\)\s*\{", js)
                body, param = (_block(js, fn.end()), fn.group(1)) if fn else ("", "")
            else:
                inline = re.match(_INLINE, rest)
                body, param = (_block(rest, inline.end()), inline.group(1)) if inline else ("", "")
            if _stops_the_browser_first(body, param):
                return True
    return False


# An inline handler's opening, up to its body's brace: ``(e) => {``, ``async (e) => {``, ``function (e) {``, with the
# event's name captured.
_INLINE = r"(?:async\s+)?(?:function\s*)?\(?\s*(\w*)\s*\)?\s*(?:=>)?\s*\{"


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


# Handler bodies, and whether each stops the browser's own submission before anything else: (event name, body).
FIRST_STATEMENT = [
    (("e", " e.preventDefault(); go(); "), True),
    (("ev", "\n    // nothing is sent by the browser\n    ev.preventDefault();\n    send();\n"), True),
    (("e", "\n    /* first */ e . preventDefault ( ) ;\n"), True),
    # A return before it: the browser sends the form on that path.
    (("e", "\n    if (!input.value) return;\n    e.preventDefault();\n"), False),
    (("e", "\n    const q = box.value.trim();\n    if (!q) { return; }\n    e.preventDefault();\n"), False),
    # An await before it: the handler has returned to the browser by then.
    (("e", "\n    await ready();\n    e.preventDefault();\n"), False),
    # A statement before it, which could throw.
    (("e", "\n    const data = read(form);\n    e.preventDefault();\n"), False),
    # On some paths only, or in a callback that may never run.
    (("e", "\n    if (busy) e.preventDefault();\n"), False),
    (("e", "\n    busy && e.preventDefault();\n"), False),
    (("e", "\n    setTimeout(() => e.preventDefault());\n"), False),
    # Another object's, the global event's, or none at all.
    (("e", "\n    other.preventDefault();\n"), False),
    (("", "\n    event.preventDefault();\n"), False),
    (("e", "\n    e.preventDefault\n"), False),
    (("e", ""), False),
]


@pytest.mark.parametrize("handler,stops", FIRST_STATEMENT)
def test_a_handler_stops_the_browser_only_with_its_first_statement(handler, stops):
    body, param = handler[1], handler[0]
    assert _stops_the_browser_first(body, param) is stops


def test_both_checks_need_preventdefault_before_anything_else():
    """A handler that returns, awaits or does anything else first is flagged, by id and when a script makes the form,
    inline or named, however short the handler; and a form is never credited with another form's handler, bound
    on a later line or through a variable of the same name declared again."""
    js = ("document.getElementById('a-form').addEventListener('submit', (e) => {\n"
          "    if (!x) return;\n    e.preventDefault();\n});\n"
          "document.getElementById('b-form').addEventListener('submit', async (e) => {\n"
          "    await ready();\n    e.preventDefault();\n});\n"
          "const c = document.getElementById('c-form');\nc.addEventListener('submit', sendC);\n"
          "function sendC(e) {\n    if (!ok) return;\n    e.preventDefault();\n}\n"
          "document.getElementById('d-form').addEventListener('submit', function (ev) {\n"
          "    ev.preventDefault();\n});\n"
          "const form = document.getElementById('e-form');\n"
          "function later() {\n    const form = document.getElementById('f-form');\n"
          "    form.addEventListener('submit', (e) => {\n        e.preventDefault();\n    });\n}\n"
          "document.getElementById('g-form').hidden = false;\n"
          "document.getElementById('h-form').addEventListener('submit', (e) => {\n    e.preventDefault();\n});\n")
    assert [_handler_prevents_default(js, f) for f in ("a-form", "b-form", "c-form", "d-form", "e-form", "f-form",
                                                        "g-form", "h-form")] == [
        False, False, False, True, False, True, False, True]
    made = ("function mk(tag) {\n    return document.createElement(tag);\n}\n"
            "function one() {\n    const a = mk('form');\n"
            "    a.addEventListener('submit', async (e) => {\n        const q = a.value;\n        if (!q) return;\n"
            "        e.preventDefault();\n        await go(q);\n    });\n}\n"
            "function two() {\n    const b = mk('form');\n    b.addEventListener('submit', sendB);\n}\n"
            "function sendB(e) {\n    await ready();\n    e.preventDefault();\n}\n"
            "function three() {\n    const c = mk('form');\n"
            "    c.addEventListener('submit', async (e) => {\n        e.preventDefault();\n"
            "        if (!c.value) return;\n"
            "        await go();\n    });\n}\n"
            "function four() {\n    const d = mk('form');\n    {\n        const d = mk('form');\n"
            "        d.addEventListener('submit', (e) => {\n            e.preventDefault();\n        });\n    }\n}\n")
    forms = _made_forms(made)
    assert [held for _, held in forms] == ["a", "b", "c", "d", "d"]
    assert [_made_form_prevents_default(made, start, held) for start, held in forms] == [
        False, False, True, False, True]


# --------------------------------------------------------------------------------------------------
# Forms a script makes element by element: no id in a page's markup, so the checks above never see them.
# --------------------------------------------------------------------------------------------------

def _element_makers(js):
    """The script's own functions that make an element of the tag they are given, such as el(tag, cls, text)."""
    makers = set()
    for m in re.finditer(r"function\s+(\w+)\s*\(\s*(\w+)[^)]*\)\s*\{", js):
        if re.search(r"createElement\(\s*" + re.escape(m.group(2)) + r"\s*\)", _block(js, m.end())):
            makers.add(m.group(1))
    return makers


def _made_forms(js):
    """(position, the variable that holds it or None) of each form the script makes: through
    document.createElement('form') or one of its own element makers called with 'form'."""
    makers = {"createElement"} | _element_makers(js)
    out = []
    for m in re.finditer(r"\b(\w+)\(\s*['\"]form['\"]\s*[,)]", js):
        if m.group(1) in makers:
            held = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:document\.)?$", js[max(0, m.start() - 80):m.start()])
            out.append((m.start(), held.group(1) if held else None))
    return out


def _made_form_prevents_default(js, start, held):
    """Whether the form made at ``start`` and held in ``held`` is given, in the block that makes it, a submit
    handler whose first statement is its event's preventDefault()."""
    if held is None:
        return False
    block = _block(js, start)
    again = re.search(r"\b(?:const|let|var)\s+" + re.escape(held) + r"\b", block)
    block = block[:again.start()] if again else block      # past it, the name holds another form
    for b in re.finditer(r"\b" + re.escape(held) + r"\s*\??\.addEventListener\(\s*['\"]submit['\"]\s*,\s*", block):
        rest = block[b.end():]
        inline = re.match(_INLINE, rest)
        named = re.match(r"(\w+)\s*\)", rest)
        if inline:
            body, param = _block(rest, inline.end()), inline.group(1)
        elif named:
            fn = re.search(r"function\s+" + re.escape(named.group(1)) + r"\s*\(\s*(\w*)[^)]*\)\s*\{", js)
            body, param = (_block(js, fn.end()), fn.group(1)) if fn else ("", "")
        else:
            body, param = "", ""
        if _stops_the_browser_first(body, param):
            return True
    return False


SCRIPTS = sorted(p.name for p in (STATIC / "js").glob("*.js"))


@pytest.mark.parametrize("script", SCRIPTS)
def test_every_form_a_script_makes_is_sent_by_its_own_handler(script):
    js = (STATIC / "js" / script).read_text(encoding="utf-8")
    missing = [js.count("\n", 0, start) + 1 for start, held in _made_forms(js)
               if not _made_form_prevents_default(js, start, held)]
    assert not missing, (f"{script}: forms made on these lines have no submit handler that calls "
                         f"preventDefault: {missing}")


def test_the_forms_scripts_make_are_all_seen():
    """The scan finds the element makers and the forms made through them in the scripts that make some."""
    made = {}
    for script in SCRIPTS:
        js = (STATIC / "js" / script).read_text(encoding="utf-8")
        made[script] = len(_made_forms(js))
    # The invitation and the reset password forms (app.js), a vault's password in the Activity page and in a
    # compliance case (activity.js), and a vault's password and the file search in a case (compliance.js).
    assert made["app.js"] >= 2 and made["activity.js"] >= 2 and made["compliance.js"] >= 2, made
    for script, maker in (("app.js", "_el"), ("activity.js", "el"), ("compliance.js", "el")):
        assert maker in _element_makers((STATIC / "js" / script).read_text(encoding="utf-8")), script


def test_the_made_form_check_flags_a_form_without_a_handler():
    """The instrument, checked against a control."""
    js = ("function mk(tag, cls) {\n    const n = document.createElement(tag);\n    return n;\n}\n"
          "function hide(id) { byId(id).hidden = true; }\n"
          "function one() {\n    const a = mk('form', 'x');\n"
          "    a.addEventListener('submit', async (e) => {\n        e.preventDefault();\n        await go();\n    });\n}\n"
          "function two() {\n    const b = mk('form');\n    b.addEventListener('submit', (e) => { go(); });\n}\n"
          "function three() {\n    const c = document.createElement('form');\n    return c;\n}\n"
          "function four() {\n    box.append(mk('form'));\n}\n"
          "function five() {\n    const d = mk('form');\n    d.addEventListener('click', (e) => { e.preventDefault(); });\n}\n"
          "function six() {\n    const f = mk('form');\n    f.addEventListener('submit', sendF);\n}\n"
          "function sendF(e) {\n    e.preventDefault();\n}\n"
          "function seven() {\n    const g = mk('form');\n}\n"
          "function eight() {\n    g.addEventListener('submit', (e) => { e.preventDefault(); });\n    hide('form');\n}\n")
    assert _element_makers(js) == {"mk"}
    forms = _made_forms(js)
    assert [held for _, held in forms] == ["a", "b", "c", None, "d", "f", "g"]
    assert [_made_form_prevents_default(js, start, held) for start, held in forms] == [
        True, False, False, False, False, True, False]
