"""The people chip (static/js/people.js, static/css/people.css): its colours read, and its code builds DOM.

Twelve colours per theme, each a background and a text colour. A person's chip keeps one of them by a hash of
the account's id, so every pair must read: WCAG AA for normal text is a contrast of 4.5:1 or better, checked
here from the stylesheet's own tokens for the light theme and the dark one. The library builds its elements
with createElement and textContent; it never assigns innerHTML.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "static" / "css" / "people.css").read_text(encoding="utf-8")
JS = (ROOT / "static" / "js" / "people.js").read_text(encoding="utf-8")


def _luminance(hex_colour: str) -> float:
    r, g, b = (int(hex_colour[i:i + 2], 16) / 255 for i in (1, 3, 5))

    def lin(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _tokens(block: str) -> dict:
    return dict(re.findall(r"--(person-[0-9a-z]+-(?:bg|fg)):\s*(#[0-9a-fA-F]{6})", block))


def _blocks():
    light = CSS.split(":root {", 1)[1].split("}", 1)[0]
    dark = CSS.split('[data-theme="dark"] {', 1)[1].split("}", 1)[0]
    return {"light": _tokens(light), "dark": _tokens(dark)}


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_every_colour_pair_reads_at_aa_in_its_theme(theme):
    tokens = _blocks()[theme]
    names = sorted({k.rsplit("-", 1)[0] for k in tokens})
    assert len(names) == 13, names  # twelve colours and the grey of a deleted or unlinked account
    for name in names:
        ratio = _contrast(tokens[f"{name}-bg"], tokens[f"{name}-fg"])
        assert ratio >= 4.5, f"{theme} {name}: {ratio:.2f}"


def test_both_themes_define_the_same_tokens():
    blocks = _blocks()
    assert set(blocks["light"]) == set(blocks["dark"])


def test_the_library_builds_dom_and_never_assigns_markup():
    assert "innerHTML" not in JS and "insertAdjacentHTML" not in JS and "outerHTML" not in JS
    assert "createElement" in JS and "textContent" in JS


def test_the_initials_are_drawn_from_an_attribute_so_a_chip_reads_as_the_name_alone():
    assert ".person-avatar::before { content: attr(data-initials); }" in CSS
    assert "data-initials" in JS


def test_the_colour_is_keyed_on_the_id_not_the_name():
    # The hash takes the id; the chip adds a colour class only when it has one.
    assert "colourIndex(p.id)" in JS
    assert "colourIndex(username)" not in JS and "colourIndex(shown)" not in JS
