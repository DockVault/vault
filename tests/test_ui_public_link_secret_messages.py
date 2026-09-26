"""UI — the anonymous link pages say which secret was wrong, and the upload page asks its question
without a stale "Starting…" left underneath.

The server's replies are stubbed with page.route, so no real link, tag or setting is involved: these
pages choose the wording from the reply's secret_kind alone, and a stub states that kind exactly.
The first reply says a secret is needed; every later one says the secret was wrong."""
import json

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

WORDING = {
    "password": "That password is incorrect. Please try again.",
    "pin": "That PIN is incorrect. Please try again.",
}


def _stub(page: Page, pattern: str, kind: str):
    calls = []

    def handler(route):
        calls.append(route.request.url)
        error = "secret_required" if len(calls) == 1 else "wrong_secret"
        route.fulfill(status=401, content_type="application/json",
                      body=json.dumps({"detail": {"error": error, "secret_kind": kind}}))

    page.route(pattern, handler)
    return calls


@pytest.mark.parametrize("kind", ["password", "pin"])
def test_the_file_link_page_names_the_wrong_secret(page: Page, kind):
    calls = _stub(page, "**/public-links/*/redeem", kind)
    page.goto("/p/stubbedtoken0123456789")
    expect(page.locator("#secret-form")).to_be_visible(timeout=10000)
    expect(page.locator("#secret-error")).to_be_hidden()
    page.fill("#secret-input", "12345678")
    page.click("#secret-submit")
    expect(page.locator("#secret-error")).to_have_text(WORDING[kind], timeout=10000)
    assert len(calls) >= 2, "the wrong-secret reply was never requested, so nothing was tested"


@pytest.mark.parametrize("kind", ["password", "pin"])
def test_the_note_link_page_names_the_wrong_secret(page: Page, kind):
    calls = _stub(page, "**/note-links/*/redeem", kind)
    page.goto("/l/stubbedtoken0123456789")
    expect(page.locator("#secret-form")).to_be_visible(timeout=10000)
    page.fill("#secret-input", "12345678")
    page.click("#secret-submit")
    expect(page.locator("#secret-error")).to_have_text(WORDING[kind], timeout=10000)
    assert len(calls) >= 2


@pytest.mark.parametrize("kind", ["password", "pin"])
def test_the_upload_page_asks_for_the_secret_without_a_stale_status(page: Page, tmp_path, kind):
    calls = _stub(page, "**/receivers/*/upload-session", kind)
    sample = tmp_path / "notes.txt"
    sample.write_text("hello\n", encoding="utf-8")
    page.goto("/u/stubbedtoken0123456789")
    expect(page.locator("#upload-btn")).to_be_visible(timeout=10000)
    page.set_input_files("#file-input", str(sample))
    page.click("#upload-btn")
    # The page stops to ask. The question is on screen, and "Starting…" is gone, not left under it.
    expect(page.locator("#secret-input")).to_be_visible(timeout=10000)
    label = "PIN" if kind == "pin" else "password"
    expect(page.locator("#secret-label")).to_have_text(f"This link is protected. Enter the {label}.")
    expect(page.locator("#msg")).to_be_hidden()
    # A wrong secret names what was wrong.
    page.fill("#secret-input", "12345678")
    page.click("#upload-btn")
    expect(page.locator("#msg")).to_have_text(WORDING[kind], timeout=10000)
    assert len(calls) >= 2
