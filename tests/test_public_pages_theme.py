"""The public pages in the app's own theme, offline (static/upload-link.html, public-link.html, note-link.html and
recording.html).

Each page loads the shared token file, the shared stylesheet and the script that picks light or dark before the
first paint, and has no inline style or script, so the app's content security policy serves it unchanged. The
stylesheets are built on the tokens only, and the token file is the app skin's own. The card pages carry the brand
header brand.js fills (logo, name, then the page kind) and the "powered by" line, and their scripts write the
deployment's name as text only.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"

CARD_PAGES = {"upload-link.html": "Upload files", "public-link.html": "Shared files", "note-link.html": "Shared note"}
PAGES = [*CARD_PAGES, "recording.html"]

SINKS = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _page(name: str) -> str:
    return _read(STATIC / name)


def _code(text: str) -> str:
    """Script or stylesheet text without its comments."""
    return re.sub(r"/\*.*?\*/|(?<![:\"'\\])//[^\n]*", "", text, flags=re.S)


def _css(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _head(html: str) -> str:
    return html[:html.index("</head>")]


def _scripts(html: str):
    return re.findall(r'<script src="/static/(js/[^"?]+)', html)


# --------------------------------------------------------------------------- what each page loads

@pytest.mark.parametrize("name", PAGES)
def test_each_page_loads_the_theme_script_then_the_tokens_then_the_shared_stylesheet(name):
    head = _head(_page(name))
    theme = re.search(r'<script src="/static/js/public-theme\.js\?v=\d{8}[a-z]"></script>', head)
    tokens = re.search(r'<link rel="stylesheet" href="/static/css/tokens\.css\?v=\d{8}[a-z]">', head)
    shared = re.search(r'<link rel="stylesheet" href="/static/css/public-page\.css\?v=\d{8}[a-z]">', head)
    assert theme and tokens and shared, name
    # The theme is set before anything paints: in <head>, neither deferred nor async, ahead of the stylesheets.
    assert theme.start() < tokens.start() < shared.start(), name
    assert head.count("public-theme.js") == 1 and head.count("public-page.css") == 1, name
    # brand.js fills the header, the favicon and "powered by", as it does in the app.
    assert head.count('<script src="/static/js/brand.js?v=') == 1, name


@pytest.mark.parametrize("name", PAGES)
def test_no_page_has_an_inline_style_or_script(name):
    html = _page(name)
    assert "<style" not in html and " style=" not in html, name
    assert len(re.findall(r"<script\b", html)) == len(re.findall(r'<script src="/static/js/[^"]+"', html)), name
    assert re.search(r"\son[a-z]+=", html) is None and "javascript:" not in html, name


@pytest.mark.parametrize("name", PAGES)
def test_every_file_a_page_loads_is_served_from_static_with_a_cache_buster(name):
    html = _page(name)
    loaded = re.findall(r'(?:src|href)="/static/([^"?]+)(\?v=[^"]*)?"', html)
    assert loaded, name
    for path, version in loaded:
        if path.endswith((".js", ".css")):
            assert (STATIC / path).is_file(), f"{name}: /static/{path} is missing"
            assert re.fullmatch(r"\?v=\d{8}[a-z]", version or ""), f"{name}: /static/{path} has no ?v="
        elif path.startswith("assets/"):
            assert (STATIC / path).is_file(), f"{name}: /static/{path} is missing"
    # Nothing from another origin.
    assert not re.search(r'(?:src|href)="(?:https?:)?//', _head(html)), name


def test_the_policy_these_routes_get_lets_same_origin_scripts_styles_and_fonts_run():
    # The pages are served as files (FileResponse) under the app's one policy for HTML responses.
    source = _read(ROOT / "app" / "api" / "api_server.py")
    block = source[source.index("csp_directives = ["):source.index("]", source.index("csp_directives = ["))]
    directives = re.findall(r'"([a-z-]+-src [^"]*)"', block)
    by_name = {d.split(" ", 1)[0]: d.split(" ")[1:] for d in directives}
    assert by_name["script-src"] == ["'self'"]
    assert "'self'" in by_name["style-src"] and "'self'" in by_name["font-src"]
    for page in ("upload-link.html", "public-link.html", "note-link.html"):
        assert f'"{page}")' in source, page
    router = _read(ROOT / "app" / "api" / "recording_notice_router.py")
    assert '@router.get("/recording"' in router and '"recording.html")' in router


# --------------------------------------------------------------------------- the card pages' header

@pytest.mark.parametrize("name", CARD_PAGES)
def test_each_card_page_has_the_brand_header_the_kind_and_powered_by(name):
    html = _page(name)
    assert '<body class="pp-card-page">' in html
    head = html[html.index('<header class="pp-head">'):html.index("</header>")]
    assert re.search(r'<img src="/static/assets/logo-small\.png" alt="" data-brand-logo>', head)
    assert head.count("data-brand-name>DockVault</span>") == 1 and 'class="pp-name"' in head
    assert f'<p class="pp-kind">{CARD_PAGES[name]}</p>' in head
    # The old line that held the name and the kind together is gone.
    assert 'class="brand"' not in html
    powered = html[html.index('id="powered-by"'):]
    powered = powered[:powered.index("</p>")]
    assert "data-powered-by-link" in powered and "<span data-powered-by-name>DockVault</span>" in powered
    assert 'target="_blank" rel="noopener noreferrer"' in powered
    # The Privacy link, then "powered by", at the foot of the card.
    assert html.index('class="meta recording-link"') < html.index('id="powered-by"')


def test_the_page_scripts_write_the_name_into_the_header_as_text():
    upload = _code(_read(STATIC / "js" / "upload-link.js"))
    assert '$("brand").textContent = info.brand;' in upload
    assert 'document.title = info.brand + " · Upload files";' in upload
    assert 'class="pp-name" id="brand" data-brand-name' in _page("upload-link.html")
    for script in ("public-link.js", "note-link.js"):
        code = _code(_read(STATIC / "js" / script))
        assert code.count('document.querySelector(".pp-name")') == 1, script
        assert "brand.textContent = data.brand;" in code, script
        assert 'querySelector(".brand")' not in code, script


def test_brand_js_runs_without_the_app_shell():
    # It reads only the hooks the public pages carry, and each lookup is guarded or a query over all matches.
    brand = _code(_read(STATIC / "js" / "brand.js"))
    assert "getElementById('powered-by')" in brand and "if (!el) return;" in brand
    assert "querySelectorAll('[data-brand-name]')" in brand and "querySelectorAll('[data-brand-logo]')" in brand


@pytest.mark.parametrize("name", PAGES)
def test_no_script_a_public_page_loads_writes_markup_as_a_string(name):
    for script in _scripts(_page(name)):
        code = _code(_read(STATIC / script))
        assert not SINKS.search(code), f"{name}: {script} writes markup as a string"


# --------------------------------------------------------------------------- the theme script

def test_the_theme_script_takes_the_saved_choice_else_the_system_preference():
    code = _code(_read(STATIC / "js" / "public-theme.js"))
    assert code.count("localStorage") == 1
    saved = code[code.index("function saved()"):code.index("function system()")]
    # The storage read is guarded: blocked storage leaves the system preference in charge.
    assert saved.index("try {") < saved.index("localStorage.getItem('theme')") < saved.index("catch (_)")
    assert "t === 'light' || t === 'dark' ? t : null" in saved
    assert "matchMedia('(prefers-color-scheme: dark)')" in code
    assert "root.setAttribute('data-theme', saved() || system());" in code
    assert "document.documentElement" in code and not SINKS.search(code)


# --------------------------------------------------------------------------- the stylesheets

def _defined(*texts):
    return {m for t in texts for m in re.findall(r"(--[\w-]+)\s*:", _css(t))}


@pytest.mark.parametrize("sheet", ["public-page.css", "recording.css"])
def test_the_stylesheets_use_the_tokens_and_no_palette_values(sheet):
    css = _css(_read(STATIC / "css" / sheet))
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b(?![\w-])", css), f"{sheet}: a hex colour instead of a token"
    assert not re.search(r"\b(?:rgba?|hsla?)\(", css), f"{sheet}: a colour value instead of a token"
    assert "prefers-color-scheme" not in css, f"{sheet}: the theme comes from data-theme, set by public-theme.js"
    tokens = _read(STATIC / "css" / "tokens.css")
    shared = _read(STATIC / "css" / "public-page.css")
    used = set(re.findall(r"var\((--[\w-]+)", css))
    assert used, sheet
    undefined = used - _defined(tokens, shared, _read(STATIC / "css" / sheet))
    assert not undefined, f"{sheet}: tokens that no loaded stylesheet defines: {sorted(undefined)}"


def test_links_are_on_the_brand_tone_not_the_browsers_blue():
    css = _css(_read(STATIC / "css" / "public-page.css"))
    assert re.search(r"(?m)^a \{ color: var\(--brand-secondary\);", css)
    assert re.search(r"\[data-theme=\"dark\"\] \{[^}]*color-scheme: dark;", css)


def test_the_hidden_class_wins_over_the_field_rules():
    # The upload page hides its code label and field with the class; a label or input rule must not show them.
    css = _css(_read(STATIC / "css" / "public-page.css"))
    assert ".hidden { display: none !important; }" in css


def test_the_card_has_the_sign_in_cards_brand_rule():
    css = _css(_read(STATIC / "css" / "public-page.css"))
    card = css[css.index(".pp-card-page .card {"):]
    card = card[:card.index("}")]
    assert "border-top: 2px solid var(--brand-secondary);" in card and "background: var(--surface-0);" in card


def _block(text: str, opener: str) -> str:
    start = text.index(opener)
    return text[start:text.index("\n}", start) + 2]


def test_the_token_file_is_the_app_skins_own():
    tokens = _read(STATIC / "css" / "tokens.css")
    skin = _read(STATIC / "css" / "ui-v2.css")
    for opener in (":root {", '[data-theme="dark"] {'):
        assert _block(tokens, opener) == _block(skin, opener), f"tokens.css and ui-v2.css differ in {opener}"
    faces = lambda text: re.findall(r"(?m)^@font-face \{[^\n]*\}$", text)  # noqa: E731
    assert faces(tokens) and faces(tokens) == faces(skin)
