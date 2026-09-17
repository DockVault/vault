"""The admin security banner renders the deployment's own vulnerability verdict safely: textContent
only, a hard length cap, and no link -- the matrix text behind it is untrusted (main is fetched), so
markup or an escape in a title or version must be inert.

Pinned from source (the SPA runs in the browser, not the offline lane); the live render is a UI check.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _js_function(js, name):
    """The source of `function name(...) {...}` up to the next top-level `function ` declaration.
    renderSecurityBanner is written immediately before renderUpdateStatus, so this bounds it exactly
    without brace-matching through template literals."""
    start = js.index("function %s(" % name)
    nxt = js.index("\nfunction ", start + 1)
    return js[start:nxt]


def test_security_banner_renders_via_textcontent_capped_and_linkless():
    body = _js_function((ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8"),
                        "renderSecurityBanner")
    assert "textContent" in body                                  # the sink
    assert "innerHTML" not in body and "insertAdjacentHTML" not in body  # never HTML
    assert "href" not in body                                     # no link from matrix content
    assert ".slice(0," in body                                    # a length cap is applied
    assert "sec.secure !== false" in body                         # shown only on a concrete insecure verdict


def test_the_security_banner_element_carries_no_anchor():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    i = html.index('id="security-banner"')
    segment = html[i:i + 400]
    assert "security-banner-text" in segment
    assert "<a " not in segment   # no link element inside the security banner


def test_update_status_render_invokes_the_security_banner():
    body = _js_function((ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8"),
                        "renderUpdateStatus")
    assert "renderSecurityBanner(us)" in body
