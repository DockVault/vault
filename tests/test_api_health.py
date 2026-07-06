"""Health, version, and static entrypoints — all public (no auth)."""
import requests


def test_health_ok(base_url):
    r = requests.get(f"{base_url}/health", timeout=10)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("healthy", "degraded")
    assert body["database"] == "connected"
    assert "redis" in body


def test_api_info(base_url):
    r = requests.get(f"{base_url}/api", timeout=10)
    assert r.status_code == 200
    body = r.json()
    assert "version" in body
    assert "status" in body


def test_root_serves_ui(base_url):
    r = requests.get(f"{base_url}/", timeout=10)
    assert r.status_code == 200
    # Either the SPA HTML or a JSON status payload, depending on setup state.
    assert r.text.strip()


def test_setup_page_removed(base_url):
    # The first-run setup wizard was removed — its inline scripts were the only thing
    # keeping 'unsafe-inline' load-bearing on the header CSP. /setup no longer exists.
    r = requests.get(f"{base_url}/setup", timeout=10)
    assert r.status_code == 404


def test_static_app_js_served(base_url):
    r = requests.get(f"{base_url}/static/js/app.js", timeout=10)
    assert r.status_code == 200
    assert "generateTempCreds" in r.text
