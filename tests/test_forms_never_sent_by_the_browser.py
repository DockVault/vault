"""The browser never sends a form of the web app itself.

Every form in static/index.html is sent by app.js (or activity.js) with fetch. app.js loads at the
end of <body>, so on a slow load the sign-in screen is usable before its handlers are bound; a form
with no method then went out as a GET with what was typed (username and password) in the address,
and from there into the browser history and a reverse proxy's access log.

Two things keep it out, both pinned here without a browser:

- static/js/auth-boot.js, a synchronous script in <head> that runs before the first form is parsed,
  puts a capture-phase submit listener on the document that calls preventDefault() and nothing
  else, so the browser never sends a form while the forms' own handlers still run. It is run here in
  Node against a stand-in document, for a plain load and for the invitation and password-reset
  links (where the script returns early from its screen choice).
- every <form> says method="post", so with scripts off nothing typed goes into an address.

tests/test_ui_forms_before_the_app_loads.py drives the same thing in a real browser.
"""
import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from test_upload_tray_controls import _node

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
AUTH_BOOT = ROOT / "static" / "js" / "auth-boot.js"


class _Page(HTMLParser):
    """Records each <form> start tag and each <script src> with where it sits."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_head = False
        self.forms = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "head":
            self.in_head = True
        elif tag == "body":
            self.in_head = False
        elif tag == "form":
            self.forms.append(a)
        elif tag == "script" and a.get("src"):
            self.scripts.append({"src": a["src"], "attrs": a, "in_head": self.in_head,
                                 "forms_before": len(self.forms)})

    def handle_endtag(self, tag):
        if tag == "head":
            self.in_head = False


def _page():
    p = _Page()
    p.feed(INDEX)
    p.close()
    return p


def test_every_form_on_the_page_says_post():
    page = _page()
    # The parser saw every form the file has (no form hidden from it by odd markup).
    assert len(page.forms) == len(re.findall(r"<form\b", INDEX, re.IGNORECASE))
    assert len(page.forms) >= 17
    without = [f.get("id") for f in page.forms if (f.get("method") or "").lower() != "post"]
    assert without == [], f"forms the browser would send as a GET: {without}"
    # None of them names somewhere else to send to.
    assert [f.get("id") for f in page.forms if "action" in f] == []


def test_the_guard_script_loads_in_head_before_any_form():
    page = _page()
    boot = [s for s in page.scripts if s["src"].split("?")[0] == "/static/js/auth-boot.js"]
    assert len(boot) == 1, boot
    s = boot[0]
    assert s["in_head"], "auth-boot.js must load in <head>"
    assert s["forms_before"] == 0
    # Synchronous: a deferred or async script would run after the forms are already usable.
    assert not {"defer", "async", "type"} & set(s["attrs"]), s["attrs"]
    # app.js, which binds the handlers, still comes after every form.
    app = [x for x in page.scripts if x["src"].split("?")[0] == "/static/js/app.js"]
    assert len(app) == 1 and app[0]["forms_before"] == len(page.forms)


_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const src = fs.readFileSync(%(path)s, 'utf8');
const out = {};
for (const search of ['', '?invite=abc', '?reset=def']) {
  const listeners = [];
  const attrs = {};
  const store = { getItem: () => 'cached-token' };
  const sandbox = {
    document: {
      addEventListener: (type, fn, opt) => listeners.push({ type, fn, opt }),
      documentElement: { setAttribute: (k, v) => { attrs[k] = v; } },
    },
    location: { search },
    localStorage: store,
    sessionStorage: store,
  };
  vm.runInNewContext(src, sandbox, { filename: 'auth-boot.js' });
  const submit = listeners.filter(l => l.type === 'submit').map(l => {
    const calls = [];
    l.fn({
      type: 'submit',
      preventDefault: () => calls.push('preventDefault'),
      stopPropagation: () => calls.push('stopPropagation'),
      stopImmediatePropagation: () => calls.push('stopImmediatePropagation'),
    });
    const capture = l.opt === true || (typeof l.opt === 'object' && l.opt !== null && l.opt.capture === true);
    return { capture, calls };
  });
  out[search || 'plain'] = { types: listeners.map(l => l.type), submit, attrs };
}
process.stdout.write(JSON.stringify(out));
"""


def test_the_guard_stops_the_browser_sending_and_nothing_else_on_every_load():
    out = _node(_HARNESS % {"path": json.dumps(str(AUTH_BOOT))})
    assert set(out) == {"plain", "?invite=abc", "?reset=def"}
    for load, seen in out.items():
        # Exactly one submit listener, on the document, in the capture phase, so it runs before any
        # form's own listener whatever that one does.
        assert seen["submit"] == [{"capture": True, "calls": ["preventDefault"]}], (load, seen)
    # The screen choice is unchanged by the guard: the links still win, a cached token still waits.
    assert out["plain"]["attrs"] == {"data-auth": "pending"}
    assert out["?invite=abc"]["attrs"] == {"data-invite": "1"}
    assert out["?reset=def"]["attrs"] == {"data-reset": "1"}
