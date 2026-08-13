"""
Theme surface-palette guards (no live server needed).

The background picker is defined in FIVE places that must agree — the client
list (static/js/theme.js), the swatch buttons (static/index.html), the surface
ramps in BOTH skins (static/css/ui-v2.css, static/css/redesign.css) and the
server-side preference allowlist (app/api/api_server.py). A name present in
some but not all of them fails silently: the picker either shows a swatch that
does nothing, or accepts a choice the server drops on the next device.

On top of that consistency check these tests pin the two properties that make
the Console ramps read as a designed family rather than eight hand-picked
swatches:

  1. page -> card is the LARGEST lightness step in every dark ramp. It is the
     boundary that decides whether a card reads as an object sitting on the
     page, so it must not be the faintest one (it was, before this suite).
  2. every tinted option carries roughly the same chroma, so switching the
     background changes WHICH way the surface is tinted, not HOW MUCH.
     `graphite` is the single deliberate exception: the no-tint option.

Measurements are in OKLCH, not HSL. HSL saturation is meaningless at these
lightnesses — #14171c is RGB(20,23,28), a spread of 8/255, yet HSL calls it
16.7% "saturated" — so an HSL-based assertion would pass on a palette that
looks flat gray. OKLCH chroma tracks what the eye actually sees.
"""
import math
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
UI_V2 = ROOT / "static/css/ui-v2.css"
REDESIGN = ROOT / "static/css/redesign.css"
THEME_JS = ROOT / "static/js/theme.js"
INDEX_HTML = ROOT / "static/index.html"
API_SERVER = ROOT / "app/api/api_server.py"

# `slate` is the default and carries no [data-bg] attribute: its ramp lives in
# :root / the bare [data-theme="dark"] block, so it never appears as a
# [data-bg="slate"] selector and is excluded where selectors are parsed.
DEFAULT_BG = "slate"


# --------------------------------------------------------------------------
# colour helpers (OKLCH)
# --------------------------------------------------------------------------
_M1 = ((0.4122214708, 0.5363325363, 0.0514459929),
       (0.2119034982, 0.6806995451, 0.1073969566),
       (0.0883024619, 0.2817188376, 0.6299787005))
_M2 = ((0.2104542553, 0.7936177850, -0.0040720468),
       (1.9779984951, -2.4285922050, 0.4505937099),
       (0.0259040371, 0.7827717662, -0.8086757660))


def _oklch(hex_colour: str):
    """sRGB hex -> (L, C, H). L is perceptual lightness, C is chroma."""
    h = hex_colour.lstrip("#")
    assert len(h) == 6, f"expected a 6-digit hex colour, got {hex_colour!r}"

    def lin(c):
        c = int(c, 16) / 255.0
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    rgb = [lin(h[i:i + 2]) for i in (0, 2, 4)]
    lms = [sum(_M1[i][j] * v for j, v in enumerate(rgb)) for i in range(3)]
    lms = [math.copysign(abs(v) ** (1 / 3), v) for v in lms]
    L, a, b = [sum(_M2[i][j] * v for j, v in enumerate(lms)) for i in range(3)]
    return L, math.hypot(a, b), math.degrees(math.atan2(b, a)) % 360


def _read(p: Path) -> str:
    assert p.exists(), f"expected source file missing: {p}"
    return p.read_text(encoding="utf-8", errors="ignore")


def _ramps(css: str, dark: bool):
    """Parse `[data-bg="x"] { --surface-0:...; }` blocks into {name: [s0..s4]}."""
    prefix = r'\[data-theme="dark"\]' if dark else ""
    pattern = re.compile(
        prefix + r'\[data-bg="([a-z]+)"\]\s*\{([^}]*)\}'
    )
    out = {}
    for name, body in pattern.findall(css):
        if not dark and '[data-theme="dark"]' in css[:css.index(body)].rsplit("\n", 1)[-1]:
            continue  # a dark block matched by the light (prefix-less) pattern
        surfaces = dict(re.findall(r"--surface-(\d):\s*(#[0-9a-fA-F]{6})", body))
        if len(surfaces) == 5:
            out[name] = [surfaces[str(i)] for i in range(5)]
    return out


def _light_ramps(css: str):
    """Light blocks only — the dark ones carry a [data-theme="dark"] prefix."""
    out = {}
    for line in css.splitlines():
        m = re.match(r'\s*\[data-bg="([a-z]+)"\]\s*\{(.*)\}', line)
        if not m:
            continue
        name, body = m.group(1), m.group(2)
        surfaces = dict(re.findall(r"--surface-(\d):\s*(#[0-9a-fA-F]{6})", body))
        if len(surfaces) == 5:
            out[name] = [surfaces[str(i)] for i in range(5)]
    return out


def _dark_ramps(css: str):
    out = {}
    for line in css.splitlines():
        m = re.match(
            r'\s*\[data-theme="dark"\]\[data-bg="([a-z]+)"\]\s*\{(.*)\}', line
        )
        if not m:
            continue
        name, body = m.group(1), m.group(2)
        surfaces = dict(re.findall(r"--surface-(\d):\s*(#[0-9a-fA-F]{6})", body))
        if len(surfaces) == 5:
            out[name] = [surfaces[str(i)] for i in range(5)]
    return out


def _default_dark_ramp(css: str):
    """slate's dark ramp: the bare [data-theme="dark"] { ... } block."""
    m = re.search(r'\[data-theme="dark"\]\s*\{(.*?)\}', css, re.S)
    assert m, "no bare [data-theme=dark] block found"
    surfaces = dict(re.findall(r"--surface-(\d):\s*(#[0-9a-fA-F]{6})", m.group(1)))
    assert len(surfaces) == 5, f"expected 5 surface tokens, got {sorted(surfaces)}"
    return [surfaces[str(i)] for i in range(5)]


# --------------------------------------------------------------------------
# the five sources
# --------------------------------------------------------------------------
def _js_backgrounds():
    m = re.search(r"const BACKGROUNDS\s*=\s*\[([^\]]*)\]", _read(THEME_JS))
    assert m, "BACKGROUNDS array not found in theme.js"
    return set(re.findall(r"'([a-z]+)'", m.group(1)))


def _html_backgrounds():
    return set(re.findall(r'class="bg-swatch"\s+data-bg="([a-z]+)"', _read(INDEX_HTML)))


def _server_backgrounds():
    src = _read(API_SERVER)
    m = re.search(r'"background":\s*\{(.*?)\}', src, re.S)
    assert m, "_PREF_ALLOWED['background'] not found in api_server.py"
    return set(re.findall(r'"([a-z]+)"', m.group(1)))


# --------------------------------------------------------------------------
# 1. the five sources agree
# --------------------------------------------------------------------------
def test_background_option_set_is_consistent_across_all_five_sources():
    js = _js_backgrounds()
    html = _html_backgrounds()
    server = _server_backgrounds()
    # CSS selectors never name the default, so add it back for comparison.
    v2 = set(_light_ramps(_read(UI_V2))) | {DEFAULT_BG}
    v1 = set(_light_ramps(_read(REDESIGN))) | {DEFAULT_BG}

    assert js, "no backgrounds parsed from theme.js"
    assert js == html, (
        f"theme.js and index.html disagree: only in JS={js - html}, "
        f"only in HTML={html - js}"
    )
    assert js == server, (
        f"theme.js and the server allowlist disagree: only in JS={js - server}, "
        f"only on server={server - js} — a value missing server-side is dropped "
        f"on save, so the choice will not follow the user to another device"
    )
    assert js == v2, (
        f"theme.js and ui-v2.css disagree: only in JS={js - v2}, only in CSS={v2 - js} "
        f"— a JS name with no CSS block renders an inert swatch"
    )
    assert js == v1, (
        f"theme.js and redesign.css disagree: only in JS={js - v1}, only in CSS={v1 - js} "
        f"— the Classic skin would silently fall back to slate for that choice"
    )


def test_every_background_has_both_a_light_and_a_dark_ramp_in_both_skins():
    for path in (UI_V2, REDESIGN):
        css = _read(path)
        light, dark = set(_light_ramps(css)), set(_dark_ramps(css))
        assert light == dark, (
            f"{path.name}: light/dark ramp sets differ — "
            f"light-only={light - dark}, dark-only={dark - light}"
        )


def test_new_options_are_present():
    """ocean and ember were added alongside the recalibration; pin them so a
    partial revert cannot quietly drop one from a subset of the five sources."""
    for name in ("ocean", "ember"):
        assert name in _js_backgrounds(), f"{name} missing from theme.js"
        assert name in _html_backgrounds(), f"{name} missing from index.html"
        assert name in _server_backgrounds(), f"{name} missing from the allowlist"
        assert name in _light_ramps(_read(UI_V2)), f"{name} missing from ui-v2.css"
        assert name in _dark_ramps(_read(UI_V2)), f"{name} missing dark ramp in ui-v2.css"
        assert name in _light_ramps(_read(REDESIGN)), f"{name} missing from redesign.css"
        assert name in _dark_ramps(_read(REDESIGN)), f"{name} missing dark ramp in redesign.css"


# --------------------------------------------------------------------------
# 2. surface hierarchy — the property that makes a card read as an object
# --------------------------------------------------------------------------
def _console_dark_ramps():
    css = _read(UI_V2)
    ramps = _dark_ramps(css)
    ramps[DEFAULT_BG] = _default_dark_ramp(css)
    return ramps


# Ordering note: --surface-0 is the CARD and --surface-1 is the PAGE, so the
# page -> card step is index 1 -> index 0, not 0 -> 1.
_CARD, _PAGE, _HOVER, _BORDER, _DIVIDER = 0, 1, 2, 3, 4


@pytest.mark.parametrize("name", sorted(_console_dark_ramps()))
def test_page_to_card_is_the_largest_step_in_every_console_dark_ramp(name):
    ramp = _console_dark_ramps()[name]
    L = [_oklch(c)[0] for c in ramp]
    steps = {
        "page->card": L[_CARD] - L[_PAGE],
        "card->hover": L[_HOVER] - L[_CARD],
        "hover->border": L[_BORDER] - L[_HOVER],
        "border->divider": L[_DIVIDER] - L[_BORDER],
    }
    biggest = max(steps, key=steps.get)
    assert biggest == "page->card", (
        f"{name}: the page->card step ({steps['page->card']:.4f}) is not the "
        f"largest — {biggest} is ({steps[biggest]:.4f}). Cards must separate "
        f"from the page more decisively than a divider separates from a border, "
        f"or the layout reads flat. Steps: "
        + ", ".join(f"{k}={v:.4f}" for k, v in steps.items())
    )


@pytest.mark.parametrize("name", sorted(_console_dark_ramps()))
def test_page_to_card_separation_clears_the_flat_threshold(name):
    """Guards the regression this palette fixed: every ramp previously sat at
    dL ~0.040, which is where cards stop reading as distinct surfaces."""
    ramp = _console_dark_ramps()[name]
    d = _oklch(ramp[_CARD])[0] - _oklch(ramp[_PAGE])[0]
    assert d >= 0.055, (
        f"{name}: page->card lightness delta {d:.4f} is below the 0.055 floor; "
        f"cards will not read as objects sitting on the page"
    )


@pytest.mark.parametrize("name", sorted(_console_dark_ramps()))
def test_console_dark_ramp_ascends_from_page_to_divider(name):
    """page < card < hover < border < divider — a ramp that doubles back
    inverts hover/border affordances."""
    ramp = _console_dark_ramps()[name]
    order = [ramp[_PAGE], ramp[_CARD], ramp[_HOVER], ramp[_BORDER], ramp[_DIVIDER]]
    L = [_oklch(c)[0] for c in order]
    assert all(L[i] < L[i + 1] for i in range(4)), (
        f"{name}: dark ramp is not monotonically lighter "
        f"page->divider: {[f'{x:.4f}' for x in L]}"
    )


def test_console_light_ramps_descend_from_white():
    """In light mode the card is white and every later surface steps down."""
    css = _read(UI_V2)
    for name, ramp in _light_ramps(css).items():
        order = [ramp[_CARD], ramp[_PAGE], ramp[_HOVER], ramp[_BORDER], ramp[_DIVIDER]]
        L = [_oklch(c)[0] for c in order]
        assert all(L[i] > L[i + 1] for i in range(4)), (
            f"{name}: light ramp is not monotonically darker "
            f"card->divider: {[f'{x:.4f}' for x in L]}"
        )


# --------------------------------------------------------------------------
# 3. family calibration — same amount of tint, different direction
# --------------------------------------------------------------------------
NEUTRAL_OPTION = "graphite"


def test_tinted_backgrounds_are_actually_tinted():
    """The complaint this palette answers: the page read as flat gray. Chroma
    below ~0.014 is where a dark surface stops looking tinted at all."""
    ramps = _console_dark_ramps()
    for name, ramp in ramps.items():
        if name == NEUTRAL_OPTION:
            continue
        c = _oklch(ramp[_PAGE])[1]
        assert c >= 0.015, (
            f"{name}: page chroma {c:.4f} is below 0.015 — it will read as "
            f"neutral gray rather than a tinted surface"
        )


def test_neutral_option_stays_neutral():
    """`graphite` is the deliberate no-tint choice; it must not drift into a hue."""
    ramp = _console_dark_ramps()[NEUTRAL_OPTION]
    c = _oklch(ramp[_PAGE])[1]
    assert c < 0.008, (
        f"{NEUTRAL_OPTION}: page chroma {c:.4f} is too high for the option that "
        f"exists specifically to offer no tint"
    )


def test_tinted_backgrounds_share_one_chroma():
    """Switching background should change the hue, not how saturated the app
    feels. Before this palette the spread was 2.6x (0.0107 warm .. 0.0274 navy)."""
    ramps = _console_dark_ramps()
    chroma = {
        n: _oklch(r[_PAGE])[1] for n, r in ramps.items() if n != NEUTRAL_OPTION
    }
    spread = max(chroma.values()) / min(chroma.values())
    assert spread <= 1.75, (
        f"tinted chroma spread is {spread:.2f}x (limit 1.75x): "
        + ", ".join(f"{n}={c:.4f}" for n, c in sorted(chroma.items()))
        + " — options should differ in hue, not in how tinted they are"
    )


def test_background_options_cover_distinct_hues():
    """Two options that land on the same hue are redundant to a user. Before
    this palette three of six sat inside 229-265 deg."""
    ramps = _console_dark_ramps()
    hues = sorted(
        (_oklch(r[_PAGE])[2], n)
        for n, r in ramps.items() if n != NEUTRAL_OPTION
    )
    for (h1, n1), (h2, n2) in zip(hues, hues[1:]):
        assert h2 - h1 >= 15.0, (
            f"{n1} ({h1:.0f} deg) and {n2} ({h2:.0f} deg) are only "
            f"{h2 - h1:.0f} deg apart — they will look like the same choice"
        )


# --------------------------------------------------------------------------
# 4. the accent must actually reach the UI
# --------------------------------------------------------------------------
def test_brand_glow_is_consumed_by_the_console_skin():
    """--brand-glow is defined per accent per theme. If nothing reads it the
    accent never tints a surface and the definitions are dead weight (which was
    the case: 14 definitions, 0 uses)."""
    css = _read(UI_V2)
    definitions = len(re.findall(r"--brand-glow\s*:", css))
    uses = len(re.findall(r"var\(--brand-glow\)", css))
    assert definitions > 0, "no --brand-glow definitions found in ui-v2.css"
    assert uses > 0, (
        f"ui-v2.css defines --brand-glow {definitions} times but never reads it; "
        f"the selected accent cannot tint any surface"
    )


def test_selected_nav_item_is_accent_tinted():
    """The rail's active row is where the Console skin is allowed to show the
    accent, per its own 'accent only on selected/interactive states' rule."""
    css = _read(UI_V2)
    m = re.search(r"\.sidebar-item\.active\s*\{(.*?)\}", css, re.S)
    assert m, ".sidebar-item.active rule not found in ui-v2.css"
    assert "var(--brand-glow)" in m.group(1), (
        "the active sidebar item does not reference --brand-glow, so choosing "
        "an accent leaves the navigation entirely neutral"
    )


def test_content_region_is_not_painted_with_the_card_surface():
    """The region cards sit in must not be the card colour.

    `.main-content` is defined once in the shared base stylesheet and inherited
    by both skins. While it was painted --surface-0 every card sat on a backdrop
    of exactly its own fill, leaving a 1px border as the only thing separating
    them — which is why the layout read flat regardless of how the surface ramp
    was tuned. It must stay transparent (page shows through) or explicitly take
    the page surface, never the card surface.
    """
    css = _read(ROOT / "static/css/components.css")
    m = re.search(r"^\.main-content\s*\{(.*?)^\}", css, re.S | re.M)
    assert m, ".main-content rule not found in components.css"
    body = m.group(1)
    bg = re.findall(r"^\s*background(?:-color)?:\s*([^;]+);", body, re.M)
    assert bg, ".main-content declares no background"
    value = bg[-1].strip()
    assert "--surface-0" not in value, (
        f".main-content is painted {value!r}, which is the CARD surface; cards "
        f"would be indistinguishable from the region around them"
    )
    assert value in {"transparent", "var(--surface-1)"}, (
        f".main-content background is {value!r}; expected transparent (let the "
        f"page show through) or var(--surface-1) (the page surface)"
    )


def test_every_accent_defines_a_glow_in_both_themes():
    """A missing glow for one accent would silently fall back to another
    accent's tint on the active nav row."""
    css = _read(UI_V2)
    accents = set(re.findall(r'\[data-accent="([a-z]+)"\]', css))
    assert accents, "no [data-accent] blocks found"
    for accent in sorted(accents):
        for prefix in ("", r'\[data-theme="dark"\]'):
            block = re.search(
                prefix + rf'\[data-accent="{accent}"\]\s*\{{(.*?)\}}', css, re.S
            )
            assert block, f"no {'dark' if prefix else 'light'} block for accent {accent}"
            assert "--brand-glow" in block.group(1), (
                f"accent {accent} ({'dark' if prefix else 'light'}) defines no "
                f"--brand-glow"
            )
