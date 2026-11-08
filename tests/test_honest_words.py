"""The interface and the code say what is true today.

Three promises had outlived what was built. The share dialog's "view only" option said recipients could preview
but not download; a view-only share's recipient sees the item's name and size and cannot open it, because the
preview reads through the download path. The seeded "Confidential (Read)" tag said recipients could read. The log
access page listed two log components with a "coming soon" badge that the server cannot serve, and a help text
said allow-lists were "managed via the API for now". The security monitor's docstring promised email and webhook
delivery of alerts, which does not exist.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_the_view_only_option_says_what_a_recipient_can_do():
    html = _read("static/index.html")
    assert "recipients can preview but not download" not in html
    assert "View only (recipients see the item's name and size; they cannot open or download it)" in html


def test_the_seeded_confidential_tag_says_what_a_recipient_can_do():
    src = _read("app/api/api_server.py")
    assert "recipients can read but not download" not in src
    assert "recipients see names and sizes; they cannot open or download the files" in src


def test_the_view_only_test_describes_the_behaviour_it_tests():
    doc = _read("tests/test_api_share_viewonly.py").split('"""')[1]
    assert "preview" not in doc.split("denies")[0], doc
    assert "cannot open the files" in doc


def test_log_access_offers_only_what_the_deployment_serves():
    js = _read("static/js/app.js")
    assert "coming soon" not in js
    assert ".filter(c => serveable.includes(c))" in js


def test_no_text_on_the_page_defers_to_the_api_for_now():
    html = _read("static/index.html")
    assert "managed via the API for now" not in html
    assert "set through the tag's API, not on this page" in html


def test_the_security_monitor_promises_no_delivery_it_lacks():
    src = _read("app/services/security_monitor.py")
    doc = src.split('"""')[1]
    assert "Email notifications" not in doc and "Webhook notifications" not in doc
    assert "no email or webhook delivery" in doc
    assert "TODO: Send email" not in src and "TODO: Send webhook" not in src
