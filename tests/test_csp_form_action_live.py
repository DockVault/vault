"""Every page the vault serves lets the browser send no form, on a running stack.

The page's Content-Security-Policy says ``form-action 'none'`` (every form is sent by script); this reads the
header off each served page. The browser half (scripts off, the sign-in sends nothing; with the directive
taken out it would go out) is in tests/test_ui_forms_before_the_app_loads.py, and the offline pins are in
tests/test_csp_form_action.py.
"""
import pytest
import requests

from conftest import BASE_URL

pytestmark = pytest.mark.integration

PAGES = ["/", "/l/not-a-real-token-0000000000", "/p/not-a-real-token-0000000000",
         "/u/not-a-real-token-0000000000", "/recording"]


@pytest.mark.parametrize("path", PAGES)
def test_the_page_lets_the_browser_send_no_form(path):
    r = requests.get(f"{BASE_URL}{path}", timeout=30)
    assert r.status_code == 200 and "text/html" in r.headers.get("content-type", ""), (r.status_code, path)
    directives = [d.strip() for d in r.headers.get("Content-Security-Policy", "").split(";")]
    assert [d for d in directives if d.startswith("form-action")] == ["form-action 'none'"], directives


def test_a_refused_download_page_lets_the_browser_send_no_form():
    # The page a browser shows when a public file link's download is refused (a grant that was used, or
    # one that never was) is an HTML page of the vault's too, with the same policy.
    r = requests.get(f"{BASE_URL}/public-links/not-a-real-token-0000000000/download/"
                     "00000000-0000-4000-8000-000000000000?grant=not-a-real-grant", timeout=30)
    assert r.status_code == 404 and "text/html" in r.headers.get("content-type", ""), r.status_code
    directives = [d.strip() for d in r.headers.get("Content-Security-Policy", "").split(";")]
    assert [d for d in directives if d.startswith("form-action")] == ["form-action 'none'"], directives
    assert "script-src 'self'" in directives and "<form" not in r.text and "<script" not in r.text
