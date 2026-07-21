"""
Static-asset supply-chain guard (no live server needed).

The vault UI must not load any resource (script/stylesheet) from an external
origin — a compromised/tampered CDN response would execute in the vault's own
origin (Semgrep `html.security.audit.missing-integrity`). All assets are
vendored under /static (fonts, JS, CSS), matching the project's air-gapped /
self-hosted posture. These tests read the repo files directly, so they run
without a running vault container.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


@pytest.fixture(scope="session", autouse=True)
def _require_running_container():
    """Override the suite-wide live-container guard for this module.

    These are pure static-file checks — they need no running vault, so they must
    run even when the container is down (exactly the moment a broken/tampered
    vendored asset would otherwise slip through unnoticed)."""
    return None


# The customer-facing page actually served by app/api/api_server.py: GET / serves
# static/index.html (the dual-skin SPA shell). Any external-origin
# <script src>/<link href> here is a supply-chain risk (executes in the vault
# origin), so it must be self-hosted. Plain anchors (e.g. the "powered by"
# link) are navigation, not loaded resources. (The first-run /setup wizard —
# the only page that used inline scripts — was removed.)
LIVE_HTML = [STATIC / "index.html"]
# The authoritative CSP is the response header set in app/api/api_server.py (the meta tag
# in index.html is a belt-and-braces copy); its script-src must not allow-list
# any external origin.
API_SERVER = ROOT / "app/api/api_server.py"


def _read(p: Path) -> str:
    assert p.exists(), f"expected static asset missing: {p}"
    return p.read_text(encoding="utf-8", errors="ignore")


@pytest.mark.parametrize("page", LIVE_HTML, ids=lambda p: p.name)
def test_live_page_loads_no_external_resources(page):
    """No <script src>/<link href> may point at an external http(s) origin."""
    html = _read(page)
    external = re.findall(r'<(?:script|link)\b[^>]*?(?:src|href)\s*=\s*"(https?://[^"]+)"', html)
    assert external == [], f"{page.name} loads external resources (supply-chain risk): {external}"


def test_index_has_no_meta_csp_header_is_authoritative():
    """The <meta> CSP was removed: the server sends a COMPLETE CSP header on every text/html
    response (checked by test_server_side_csp_* below), so a weaker <meta> duplicate was only a
    maintenance hazard. index.html must not declare a <meta> CSP."""
    html = _read(STATIC / "index.html")
    assert not re.search(r'http-equiv="Content-Security-Policy"', html), \
        "index.html must NOT declare a <meta> CSP (rely on the complete response-header CSP)"


def test_form_group_option_labels_exempt_from_block_uppercase():
    """Checkbox/radio OPTION labels (`.flex` / `.checkbox-label`) must be exempt from every
    `.form-group label { display:block; ...uppercase }` base rule, or their flex `gap` goes inert
    and the option text is forced uppercase (the cramp UIP2 fixed). Any `.form-group label` rule
    that sets display:block or text-transform:uppercase must carry :not(.flex):not(.checkbox-label);
    `.checkbox-label` must be defined as a flex row in each skin."""
    css_dir = ROOT / "static" / "css"
    for name in ("components.css", "ui-v2.css", "redesign.css"):
        css = _read(css_dir / name)
        for m in re.finditer(r'([^{}]*\.form-group label[^{}]*)\{([^}]*)\}', css):
            sel, body = m.group(1), m.group(2)
            forces = re.search(r'display\s*:\s*block', body) or re.search(r'text-transform\s*:\s*uppercase', body)
            if forces:
                assert ":not(.flex)" in sel and ":not(.checkbox-label)" in sel, \
                    f"{name}: a `.form-group label` block/uppercase rule doesn't exempt option labels: {sel.strip()[:90]!r}"
    for skin in ("ui-v2.css", "redesign.css"):
        s = _read(css_dir / skin)
        assert "label.checkbox-label" in s and re.search(r'\.checkbox-label[^{]*\{[^}]*display\s*:\s*flex', s), \
            f"{skin} must define .checkbox-label as a display:flex row"


def test_share_tag_colour_is_a_swatch_picker():
    """The share-tag colour control is a swatch picker (named swatches + a custom <input type=color>),
    not a plain text box that accepts the bare word 'indigo' (UIP3). The hidden #share-tag-color the
    save path reads is kept, wired by setShareTagColor (mirrors the Groups colour editor)."""
    html = _read(STATIC / "index.html")
    assert '<input type="hidden" id="share-tag-color"' in html, \
        "share-tag-color must be a hidden input the save path reads"
    assert 'id="share-tag-color-swatches"' in html and 'id="share-tag-color-custom"' in html, \
        "share-tag colour must offer named swatches + a custom <input type=color> picker"
    assert 'type="text" id="share-tag-color"' not in html, "the plain colour text box must be gone"
    appjs = _read(STATIC / "js" / "app.js")
    assert "function setShareTagColor" in appjs and "share-tag-color-swatches" in appjs, \
        "setShareTagColor must wire the swatch picker"


def test_share_tag_lifetime_hints_and_no_minute_coercion():
    """Share-tag lifetime shows live `(~N days)` hints and unified "Maximum" terminology (UIP4),
    and saveShareTag must NOT silently coerce an empty/0 lifetime to 1 minute (the old `|| 1` that
    expired every share in a minute) — it validates inline instead."""
    html = _read(STATIC / "index.html")
    appjs = _read(STATIC / "js" / "app.js")
    assert 'id="share-tag-max-lifetime-days"' in html and 'id="share-tag-default-lifetime-days"' in html, \
        "the Lifetime inputs need day-hint spans"
    assert 'id="share-tag-editor-error"' in html, "an inline error element is needed for validation"
    assert ">Ceiling<" not in html and "Cap (blank" not in html, \
        "terminology unified to 'Maximum' (no Ceiling/Cap)"
    assert "function shareTagDaysHint" in appjs and "updateShareTagLifetimeHints" in appjs, \
        "the day-hint helpers must exist"
    # The footgun coercion must be gone.
    assert "share-tag-max-lifetime') || 1" not in appjs and "share-tag-default-lifetime') || 1" not in appjs, \
        "saveShareTag must not coerce an empty/0 lifetime to 1 minute"


def test_sharing_copy_no_stale_zk_caveat():
    """UIP5: the ZK card must not tell admins to leave zero-knowledge off 'until the browser-crypto
    vault UI is in use' (that UI ships), while keeping the accurate web-only note; and the
    create-share audience label keeps the security-relevant 'internal' qualifier (matching the
    tag editor)."""
    html = _read(STATIC / "index.html")
    assert "browser-crypto vault UI is in use" not in html, "the stale ZK 'not ready' caveat must be removed"
    assert "web-only (they are not exposed over SFTP)" in html, "keep the accurate ZK web-only note"
    appjs = _read(STATIC / "js" / "app.js")
    assert "Anyone internal with the link" in appjs, \
        "the create-modal audience label must keep the 'internal' qualifier"


def test_share_tag_editor_a11y_grouping():
    """UIP6 (core): the share-tag editor's ambiguous number inputs get UNIQUE accessible names via
    aria-label (no more three identical "Default"s), the checkbox groups are role=group with a
    labelling header, and the user-search fields are combobox/listbox — so a screen reader
    announces each field unambiguously. (Full keyboard nav / aria-expanded is UIP6b.)"""
    html = _read(STATIC / "index.html")
    for lab in ("Lifetime maximum", "Lifetime default", "Recipients maximum", "Recipients default",
                "Downloads maximum", "Downloads default"):
        assert f'aria-label="{lab}' in html, f"missing unique aria-label for {lab!r}"
    for legend in ("share-tag-audiences-legend", "share-tag-capabilities-legend", "share-tag-whomay-legend"):
        assert f'aria-labelledby="{legend}"' in html and f'id="{legend}"' in html, \
            f"checkbox group label {legend} missing (role=group + aria-labelledby)"
    assert html.count('role="combobox"') >= 2 and html.count('role="listbox"') >= 2, \
        "the user-search autocompletes must be combobox + listbox"


def test_share_tag_user_search_combobox_keyboard_nav():
    """UIP6b: the allowed/blocked user-search autocompletes are live comboboxes — result rows are
    role=option with ids, aria-expanded toggles, aria-activedescendant tracks a highlight, and a
    keydown handler drives ArrowUp/Down/Enter/Escape navigation."""
    appjs = _read(STATIC / "js" / "app.js")
    assert "function _tagUserKeydown" in appjs and "function _setTagUserActive" in appjs, \
        "combobox keyboard-nav helpers must exist"
    assert "aria-activedescendant" in appjs and "'ArrowDown'" in appjs and "'ArrowUp'" in appjs, \
        "arrow-key navigation with aria-activedescendant must be wired"
    assert "setAttribute('role', 'option')" in appjs, "result rows must be role=option"
    assert "aria-expanded" in appjs, "the combobox must toggle aria-expanded"
    assert "addEventListener('keydown', (e) => _tagUserKeydown(" in appjs, \
        "the search inputs must wire the keydown handler"


def test_served_frontend_has_no_inline_event_handlers():
    """No inline `on*=` HTML handler ATTRIBUTE may appear in the served frontend: the page CSP
    (script-src 'self', no unsafe-inline) blocks them, which spammed the console and left the
    handler dead (the toast × before this fix). Property assignments (`el.onclick = ...`) and
    addEventListener are CSP-safe and allowed."""
    files = [STATIC / "index.html"] + sorted((STATIC / "js").glob("*.js"))
    for f in files:
        bad = re.findall(r'<[^>]*\son[a-z]+\s*=\s*"[^"]*"', _read(f))
        assert not bad, f"{f.name} has inline on*= handler attribute(s) (CSP-blocked): {bad[:3]}"
    # the toast close button is wired programmatically (not via an inline onclick).
    appjs = _read(STATIC / "js" / "app.js")
    assert "toast-close" in appjs and "addEventListener('click'" in appjs, \
        "the toast close button must be wired via addEventListener"


def test_server_side_csp_script_src_is_self_only():
    """The response-header CSP in app/api/api_server.py must not allow-list a CDN either."""
    src = _read(API_SERVER)
    # The script-src directive is a single string literal in the csp_directives list.
    m = re.search(r'"(script-src[^"]*)"', src)
    assert m, "app/api/api_server.py must declare a script-src CSP directive"
    script_src = m.group(1)
    assert "http://" not in script_src and "https://" not in script_src, \
        f"server-side script-src still allow-lists an external origin: {script_src!r}"
    assert "jsdelivr" not in script_src


def test_server_side_csp_script_src_has_no_unsafe_inline():
    """The header CSP script-src must NOT allow 'unsafe-inline': the setup wizard — the only
    page that needed inline scripts — was removed, so the SPA (self-hosted scripts + its own
    strict meta CSP) runs fine under script-src 'self' with no inline-script XSS surface."""
    src = _read(API_SERVER)
    m = re.search(r'"(script-src[^"]*)"', src)
    assert m, "app/api/api_server.py must declare a script-src CSP directive"
    script_src = m.group(1)
    assert "unsafe-inline" not in script_src, \
        f"header script-src must not allow-list 'unsafe-inline': {script_src!r}"


if __name__ == "__main__":  # allow: python test_static_selfhosted_assets.py
    raise SystemExit(pytest.main([__file__, "-v"]))
