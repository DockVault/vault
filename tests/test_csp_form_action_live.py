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
