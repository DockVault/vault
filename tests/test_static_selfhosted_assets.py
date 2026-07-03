"""
Static-asset supply-chain guard (no live server needed).

The vault dashboard used to pull Chart.js from `cdn.jsdelivr.net` with no
Subresource Integrity — a compromised/tampered CDN response would execute in the
vault's own origin (Semgrep `html.security.audit.missing-integrity`). The fix
vendors Chart.js locally (matching the project's air-gapped / self-hosted asset
posture — the admin panel vendors Leaflet + this same Chart.js build) and drops
the CDN origin from the page CSP. These tests read the repo files directly, so
they run without a running vault container.
"""
import re
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "static"


@pytest.fixture(scope="session", autouse=True)
def _require_running_container():
    """Override the suite-wide live-container guard for this module.

    These are pure static-file checks — they need no running vault, so they must
    run even when the container is down (exactly the moment a broken/tampered
    vendored asset would otherwise slip through unnoticed)."""
    return None

# The customer-facing product dashboards. Any external-CDN <script>/<link> here
# is a supply-chain risk (executes in the vault origin), so they must be self-hosted.
DASHBOARD_HTML = STATIC / "dashboard_new.html"
# The authoritative CSP is the response header set in api_server.py (the meta tag
# is a belt-and-braces copy); its script-src must also drop the CDN origin.
API_SERVER = Path(__file__).resolve().parent.parent / "api_server.py"


def _read(p: Path) -> str:
    assert p.exists(), f"expected static asset missing: {p}"
    return p.read_text(encoding="utf-8", errors="ignore")


def test_dashboard_has_no_external_resource_urls():
    """No src=/href= may point at an external http(s) origin — all self-hosted."""
    html = _read(DASHBOARD_HTML)
    external = re.findall(r'(?:src|href)\s*=\s*"(https?://[^"]+)"', html)
    assert external == [], f"dashboard loads external resources (supply-chain risk): {external}"


def test_dashboard_chartjs_is_self_hosted():
    """Chart.js must be referenced from the local /static path, not a CDN."""
    html = _read(DASHBOARD_HTML)
    assert 'src="/static/js/chart.umd.min.js"' in html, "dashboard must load the vendored chart.js"
    # The comprehensive "no external origin" guard is test_dashboard_has_no_external_resource_urls;
    # here we only pin that the specific former CDN (jsdelivr) is gone (no broad "cdn." substring —
    # that would false-fail on benign text like a comment mentioning a CDN).
    assert "jsdelivr" not in html, "the former jsdelivr CDN reference must be gone from the dashboard"


def test_dashboard_csp_script_src_is_self_only():
    """The page CSP must not allow-list any external script origin."""
    html = _read(DASHBOARD_HTML)
    m = re.search(r'Content-Security-Policy"\s+content="([^"]+)"', html)
    assert m, "dashboard must declare a Content-Security-Policy meta tag"
    csp = m.group(1)
    script_src = next((d for d in csp.split(";") if d.strip().startswith("script-src")), "")
    assert script_src, "CSP must declare a script-src directive"
    # only 'self' / 'unsafe-inline' style keywords — no scheme/host source expressions
    assert "http://" not in script_src and "https://" not in script_src, \
        f"script-src still allow-lists an external origin: {script_src.strip()!r}"
    assert "jsdelivr" not in script_src


def test_server_side_csp_script_src_is_self_only():
    """The response-header CSP in api_server.py must not allow-list a CDN either."""
    src = _read(API_SERVER)
    # The script-src directive is a single string literal in the csp_directives list.
    m = re.search(r'"(script-src[^"]*)"', src)
    assert m, "api_server.py must declare a script-src CSP directive"
    script_src = m.group(1)
    assert "http://" not in script_src and "https://" not in script_src, \
        f"server-side script-src still allow-lists an external origin: {script_src!r}"
    assert "jsdelivr" not in script_src


def test_vendored_chartjs_is_complete_and_correct_version():
    """The vendored file must be a complete Chart.js v4.4.0 (the version the page expects)."""
    js = STATIC / "js" / "chart.umd.min.js"
    data = _read(js)
    assert len(data) > 100_000, "vendored chart.js looks truncated"
    assert "Chart.js v4.4.0" in data, "vendored chart.js is not the expected 4.4.0 build"


if __name__ == "__main__":  # allow: python test_static_selfhosted_assets.py
    raise SystemExit(pytest.main([__file__, "-v"]))
