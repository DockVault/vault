"""A streamed download whose request reaches the download worker after the page has finished.

The page opens a slot in the download worker, points a hidden frame at it, writes the file into the
slot and says it is done. For a small file all of that can happen before the frame's request has
reached the worker. A worker that drops the slot as soon as the page is done answers that request
with 404: no download starts, and the page has already told the user it is downloading.

These tests make that order certain rather than hoping for it. The frame is held back until the
page has finished writing and the worker has had a round trip after the page's last message, and
only then let go. The download must start with every byte, the slot must serve exactly one request,
and a download whose request never comes must be reported to the user instead of passing silently.
The usual order for a large file, the request first, is held the other way round, so the report is
made only when it is true.

The page clock is installed so the wait for a request that never comes (a minute) can be skipped
over; it runs at normal speed otherwise.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from playwright.sync_api import expect

from conftest import ApiClient, BASE_URL, unique
from test_ui_e2e import _create_zk_vault_via_ui, _login

pytestmark = pytest.mark.ui

# Longer than the page's wait for the browser's request, so its timer is due.
PAST_THE_CLAIM_WAIT_MS = 61_000

HOLD_SINK_FRAMES = """() => {
    window.__errors = [];
    const showErrorBefore = window.showError;
    window.showError = function (message) {
        window.__errors.push(String(message));
        return showErrorBefore.apply(this, arguments);
    };
    window.__heldSinkFrames = [];
    const body = document.body;
    const append = body.appendChild;
    window.__appendToBody = (el) => append.call(body, el);
    body.appendChild = function (el) {
        if (el && el.tagName === 'IFRAME' && String(el.src).includes('/__dv_sink__/')) {
            window.__heldSinkFrames.push(el);
            return el;
        }
        return append.call(this, el);
    };
}"""

# downloadFile() resolves once the page has written the whole file and told the worker it is
# done. The frame is still held. A round trip to the same worker afterwards means the worker has
# had its turn at what the page sent before the frame's request can exist.
FINISH_WHILE_HELD = """async ([fid, name]) => {
    await downloadFile(fid, name);
    const frames = window.__heldSinkFrames.splice(0);
    await new Promise((resolve, reject) => {
        const channel = new MessageChannel();
        const timer = setTimeout(() => reject(new Error('the worker did not answer')), 5000);
        channel.port1.onmessage = () => { clearTimeout(timer); resolve(); };
        _sinkWorker.postMessage({ type: 'dv-sink-open', id: 'round-trip-' + Math.random().toString(36).slice(2),
                                  filename: 'round-trip', size: 0, mime: 'text/plain' }, [channel.port2]);
    });
    window.__releasable = frames;
    return { held: frames.length, src: frames.map(f => f.src), errors: window.__errors.slice() };
}"""

RELEASE = """() => { for (const f of window.__releasable) window.__appendToBody(f); }"""

# The other order, the usual one for a large file: the browser asks for the download while the page
# is still writing. The page's 'done' is held back until the download has started.
HOLD_DONE = """() => {
    window.__errors = [];
    const showErrorBefore = window.showError;
    window.showError = function (message) {
        window.__errors.push(String(message));
        return showErrorBefore.apply(this, arguments);
    };
    window.__heldDone = [];
    const post = MessagePort.prototype.postMessage;
    window.__postOnPort = (port, message) => post.call(port, message);
    MessagePort.prototype.postMessage = function (message, transfer) {
        if (message && message.type === 'done') {
            window.__heldDone.push(this);
            return;
        }
        return post.call(this, message, transfer);
    };
}"""

RELEASE_DONE = """() => {
    const ports = window.__heldDone.splice(0);
    for (const port of ports) window.__postOnPort(port, { type: 'done' });
    return ports.length;
}"""

FETCH_AGAIN = """async (src) => {
    const r = await fetch(src);
    return { controlled: !!navigator.serviceWorker.controller, status: r.status, text: await r.text() };
}"""


def _body(size: int, tag: str) -> bytes:
    seed = hashlib.sha256(tag.encode()).digest()
    out = bytearray()
    while len(out) < size:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return bytes(out[:size])


def _open_vault(page, vault_id: str) -> None:
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    expect(page.locator(".file-name[data-file-id]").first).to_be_visible(timeout=15000)


def _new_file_id(client, vault_id: str, before: set, page) -> str:
    for _ in range(60):
        items = client.get(f"/vaults/{vault_id}/files").json()["items"]
        new = [i["id"] for i in items if i["type"] == "file" and i["id"] not in before]
        if new:
            return new[0]
        page.wait_for_timeout(500)
    raise AssertionError("the upload never landed")


@pytest.fixture
def owner(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True}).raise_for_status()
    user = admin.create_user(role="admin")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    yield user, client
    admin.delete_user(user["id"])


def _page_with_a_file(browser, owner, kind: str, body: bytes, name: str):
    """A logged-in page with the clock installed, the vault open, and one file in it."""
    user, client = owner
    context = browser.new_context(base_url=BASE_URL, accept_downloads=True)
    page = context.new_page()
    page.clock.install()
    _login(page, user["_username"], user["_password"])
    if kind == "zero_knowledge":
        vault_id = _create_zk_vault_via_ui(page, client, "late-request-passphrase-1")
        page.click('.sidebar-item[data-section="vaults"]')
        page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        page.set_input_files("#file-upload-input", files=[
            {"name": name, "mimeType": "application/octet-stream", "buffer": body}])
        file_id = _new_file_id(client, vault_id, set(), page)
    else:
        vault_id = client.create_vault(name=unique("late-request"))["id"]
        client.post(f"/vaults/{vault_id}/files",
                    files=[("files", (name, body, "application/octet-stream"))]).raise_for_status()
        file_id = _new_file_id(client, vault_id, set(), page)
    _open_vault(page, vault_id)
    assert page.evaluate("state.downloadSink") == "streaming", (
        "these tests are about the streaming sink, which this deployment does not use")
    return context, page, vault_id, file_id


@pytest.mark.parametrize("kind", ["zero_knowledge", "standard"])
def test_a_download_whose_request_arrives_after_the_page_finished_still_starts(browser, owner, kind):
    body = _body(1024, f"late-{kind}")
    name = f"late-{kind}.bin"
    context, page, vault_id, file_id = _page_with_a_file(browser, owner, kind, body, name)
    try:
        page.evaluate(HOLD_SINK_FRAMES)
        held = page.evaluate(FINISH_WHILE_HELD, [file_id, name])
        assert held["held"] == 1, f"expected one sink frame, got {held}"
        assert not held["errors"], held["errors"]

        with page.expect_download(timeout=15000) as info:
            page.evaluate(RELEASE)
        download = info.value
        assert download.failure() is None, download.failure()
        assert download.suggested_filename == name
        assert Path(download.path()).read_bytes() == body, "the download is not the file"

        again = page.evaluate(FETCH_AGAIN, held["src"][0])
        assert again["controlled"], "the page is not controlled by the worker, so this proves nothing"
        assert (again["status"], again["text"]) == (404, "no such download"), (
            f"a second request for a slot already taken must find nothing, got {again}")

        # Past the page's wait for the request: the download started, so nothing may be reported.
        page.clock.fast_forward(PAST_THE_CLAIM_WAIT_MS)
        page.wait_for_timeout(200)
        assert page.evaluate("window.__errors") == []
    finally:
        context.close()
        owner[1].delete_vault(vault_id)


@pytest.mark.parametrize("kind", ["zero_knowledge", "standard"])
def test_a_download_the_browser_asks_for_before_the_page_finished_is_not_reported(browser, owner, kind):
    body = _body(1024, f"early-{kind}")
    name = f"early-{kind}.bin"
    context, page, vault_id, file_id = _page_with_a_file(browser, owner, kind, body, name)
    try:
        page.evaluate(HOLD_DONE)
        with page.expect_download(timeout=15000) as info:
            page.evaluate("([fid, name]) => downloadFile(fid, name)", [file_id, name])
        download = info.value
        assert page.evaluate(RELEASE_DONE) == 1, "the page never said it was done"
        assert download.failure() is None, download.failure()
        assert Path(download.path()).read_bytes() == body, "the download is not the file"

        page.clock.fast_forward(PAST_THE_CLAIM_WAIT_MS)
        page.wait_for_timeout(200)
        assert page.evaluate("window.__errors") == []
    finally:
        context.close()
        owner[1].delete_vault(vault_id)


def test_a_download_whose_request_never_comes_is_reported(browser, owner):
    body = _body(1024, "never")
    name = "never-asked-for.bin"
    context, page, vault_id, file_id = _page_with_a_file(browser, owner, "standard", body, name)
    try:
        page.evaluate(HOLD_SINK_FRAMES)
        held = page.evaluate(FINISH_WHILE_HELD, [file_id, name])
        assert held["held"] == 1, f"expected one sink frame, got {held}"
        assert not held["errors"], "nothing is wrong yet: the browser has a minute to ask"

        page.clock.fast_forward(PAST_THE_CLAIM_WAIT_MS)
        page.wait_for_timeout(200)
        errors = page.evaluate("window.__errors")
        assert errors == [f'"{name}" did not start downloading. Try again.'], errors
    finally:
        context.close()
        owner[1].delete_vault(vault_id)
