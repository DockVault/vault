"""The page completes a link the server hands over without its address, run as shipped under Node.

With no public address configured (ALLOWED_HOSTS) the server never builds a link on a request's Host header, so an
invitation's or a reset link comes back relative; the page shows it whole, built on its own address, for the
administrator to copy. A link the server built on the configured address is shown as it came.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function() -> str:
    start = APP.index("function _linkFromThisPage(link) {")
    return APP[start:APP.index("\n}\n", start) + 3]


def test_a_relative_link_is_completed_from_the_pages_own_address_and_an_absolute_one_kept():
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = ("const window = { location: { origin: 'https://vault.lan:8443' } };\n" + _function() + """
process.stdout.write(JSON.stringify([
    _linkFromThisPage('/?invite=abc'),
    _linkFromThisPage('/?reset=xyz'),
    _linkFromThisPage('https://vault.example.com/?invite=abc'),
    _linkFromThisPage('http://localhost:8200/?reset=xyz'),
    _linkFromThisPage(''),
    _linkFromThisPage(undefined),
]));""")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == [
        "https://vault.lan:8443/?invite=abc", "https://vault.lan:8443/?reset=xyz",
        "https://vault.example.com/?invite=abc", "http://localhost:8200/?reset=xyz", "", None]


def test_both_places_that_show_a_handed_over_link_complete_it():
    assert "_lastInviteLink = _linkFromThisPage(res.invite_url) || res.token;" in APP
    modal = APP[APP.index("function _showResetLinkModal(link, username, ttlMinutes) {"):]
    assert modal.split("\n")[1].strip() == "link = _linkFromThisPage(link);"
