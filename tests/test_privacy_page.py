"""The Privacy page and the links to it, offline (static/recording.html, static/js/recording.js, and the link pages).

The page at /recording is titled Privacy. Under the title, one line names the operator's own privacy policy when
an address for it is set (GET /legal, its privacy_policy field): only a same-origin path or an http(s) address,
checked as brand.js checks the brand's addresses, opened in a new tab. With no address the line stays hidden.
Then "What this vault records" and the notice as before. Every link page links to it as "Privacy".
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
LINK_PAGES = ("upload-link.html", "public-link.html", "note-link.html")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(js: str) -> str:
    return re.sub(r"/\*.*?\*/|(?<![:\"'\\])//[^\n]*", "", js, flags=re.S)


def _function(code: str, opener: str) -> str:
    """The function that ``opener`` starts, up to its matching closing brace."""
    start = code.index(opener)
    depth = 0
    for i in range(code.index("{", start), len(code)):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        if depth == 0:
            return code[start:i + 1]
    raise AssertionError(f"no end for {opener}")


PAGE = _read(STATIC / "recording.html")
SCRIPT = _code(_read(STATIC / "js" / "recording.js"))


# --------------------------------------------------------------------------- the page

def test_the_page_is_titled_privacy_and_keeps_the_notice_under_its_own_heading():
    assert "<title>Privacy</title>" in PAGE and PAGE.count("<h1") == 1 and "<h1>Privacy</h1>" in PAGE
    h1 = PAGE.index("<h1>Privacy</h1>")
    policy = PAGE.index('id="privacy-policy"')
    records = PAGE.index('<h2 class="records-h">What this vault records</h2>')
    always = PAGE.index('id="always"')
    assert h1 < policy < records < always < PAGE.index('id="levels-section"')
    assert "What this vault records</h1>" not in PAGE and "<title>What this vault records" not in PAGE


def test_the_policy_line_is_empty_and_hidden_until_an_address_is_set():
    line = re.search(r'<p class="lead policy-line" id="privacy-policy" hidden></p>', PAGE)
    assert line, "the policy line must start empty and hidden"


def test_the_path_stays_recording():
    router = _read(ROOT / "app" / "api" / "recording_notice_router.py")
    assert '@router.get("/recording"' in router


# --------------------------------------------------------------------------- the links to it

@pytest.mark.parametrize("name", LINK_PAGES)
def test_each_link_page_links_to_it_as_privacy(name):
    html = _read(STATIC / name)
    assert html.count('href="/recording"') == 1
    assert '<p class="meta recording-link"><a href="/recording" target="_blank" rel="noopener">Privacy</a></p>' in html
    assert "What this vault records" not in html


# --------------------------------------------------------------------------- where the address comes from

def test_the_address_is_read_from_the_public_legal_route():
    info = _read(ROOT / "app" / "routers" / "info.py")
    assert '@router.get("/legal"' in info and '"privacy_policy":' in info
    policy = _function(SCRIPT, "async function loadPolicy()")
    assert policy.count("fetch(") == 1 and "fetch('/legal'" in policy
    assert "url = safeUrl(j && j.privacy_policy);" in policy
    # The name it gives comes from /branding (fetched once for the page).
    assert "const name = policyOwner(b);" in policy
    assert SCRIPT.count("fetch('/branding'") == 1


def test_the_policy_names_the_company_only_when_the_vault_named_one():
    """company_name defaults to the product's own name. A vault that renamed only its app must not credit the
    product with its policy: the company's name counts only when it is set and is not the built-in default."""
    owner = _function(SCRIPT, "function policyOwner(b)")
    assert "if (company && company !== DEFAULT_COMPANY_NAME) return company;" in owner
    assert "return typeof b.app_name === 'string' ? b.app_name.trim() : '';" in owner
    assert owner.index("return company;") < owner.index("b.app_name")
    default = re.search(r"const DEFAULT_COMPANY_NAME = '([^']*)';", SCRIPT).group(1)
    branding = _read(ROOT / "app" / "config" / "branding.py")
    built_in = re.search(r'company_name: str = Field\(\s*default="([^"]*)"', branding).group(1)
    assert default == built_in == "DockVault"


# --------------------------------------------------------------------------- the address check

def test_the_address_check_is_brand_js_check():
    brand = _function(_code(_read(STATIC / "js" / "brand.js")), "function safeUrl(u)")
    ours = _function(SCRIPT, "function safeUrl(u)")
    for line in ("if (/[\\\\\\u0000-\\u001F]/.test(s)) return null;",
                 "if (s.charAt(0) === '/' && s.charAt(1) !== '/') return s;",
                 "if (/^https?:\\/\\//i.test(s)) return s;",
                 "if (typeof u !== 'string') return null;",
                 "if (!s) return null;"):
        assert line in brand and line in ours, line
    # Nothing else lets an address through.
    assert ours.count("return s;") == 2


def _mirror(script: str):
    """The check, run with the script's own two patterns (JavaScript and Python read them the same way)."""
    body = _function(script, "function safeUrl(u)")
    control = re.search(r"if \(/(.+?)/\.test\(s\)\) return null;", body).group(1)
    web = re.search(r"if \(/(.+?)/i\.test\(s\)\) return s;", body).group(1)

    def check(u):
        if not isinstance(u, str):
            return None
        s = u.strip()
        if not s or re.search(control, s):
            return None
        if s[0] == "/" and s[1:2] != "/":
            return s
        return s if re.search(web, s, re.I) else None
    return check


@pytest.mark.parametrize("address, kept", [
    ("https://example.com/privacy", True), ("HTTP://example.com/p", True), ("/privacy-policy", True),
    ("  https://example.com/privacy  ", True),
    ("javascript:alert(1)", False), ("data:text/html,x", False), ("//evil.example/p", False),
    ("/\\evil.example/p", False), ("/\t/evil.example", False), ("ftp://example.com/p", False),
    ("example.com/privacy", False), ("", False), ("   ", False), (None, False),
])
def test_the_check_keeps_only_a_same_origin_path_or_an_http_address(address, kept):
    assert (_mirror(SCRIPT)(address) is not None) is kept


# --------------------------------------------------------------------------- absent when empty, and text only

def test_with_no_address_the_line_stays_hidden():
    policy = _function(SCRIPT, "async function loadPolicy()")
    # Every way out before the line is touched: a refused answer, a failed fetch, no address or an unsafe one.
    stop = policy.index("if (!url) return;")
    assert "if (!r.ok) return;" in policy and "} catch (_) { return; }" in policy
    assert stop < policy.index("byId('privacy-policy')") < policy.index("line.hidden = false;")
    # Nothing else on the page shows the line.
    assert SCRIPT.count("privacy-policy") == 1


def test_the_line_is_built_as_text_and_opens_the_policy_in_a_new_tab():
    policy = _function(SCRIPT, "async function loadPolicy()")
    assert "const link = el('a', null, " in policy and "link.href = url;" in policy
    assert "link.target = '_blank';" in policy and "link.rel = 'noopener';" in policy
    assert ("line.replaceChildren(name ? `${name}\u2019s privacy policy: ` : 'Privacy policy: ', link);"
            in policy)
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", SCRIPT)


def test_the_policy_line_loads_beside_the_notice_not_after_it():
    # A notice that fails to load still leaves the operator's policy on the page.
    tail = SCRIPT[SCRIPT.rindex("loadPolicy();"):]
    assert tail.replace(" ", "").replace("\n", "") == "loadPolicy();load();})();"
