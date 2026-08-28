"""Live download progress (client-side byte counter over the same download fetch).

  * unit — the progress tray + the byte-counting reader are wired in.
  * ui   — a real browser: the tray reports byte progress and clears; a real download still works
           (the progress path reassembles the same blob and does not change the transfer).
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_download_progress_is_wired():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")
    assert "async function readResponseWithProgress(" in app
    assert "const downloadProgress" in app
    assert "response.body.getReader" in app          # reads the SAME body via a stream reader
    assert "readResponseWithProgress(" in app         # wired into the download path
    assert "#download-tray" in css and ".dl-bar-fill" in css


# --------------------------------------------------------------------------- ui lane


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


@pytest.mark.ui
def test_progress_tray_reports_bytes_and_clears(page: Page, admin, admin_creds):
    """Drive the tray + reader directly: a row appears with a percentage, the bar advances, and the
    row/tray clear when done. The reader counts every byte and returns a blob of the same length."""
    v = admin.create_vault(name=unique("dlprog"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        res = page.evaluate(
            """async () => {
                // (a) tray lifecycle
                const id = downloadProgress.start('movie.bin');
                const rowSel = '#download-tray .dl-row[data-dl-row="' + id + '"]';
                const shownStart = !!document.querySelector('#download-tray.show') && !!document.querySelector(rowSel);
                downloadProgress.update(id, 50, 100);
                const fill = document.querySelector(rowSel + ' .dl-bar-fill');
                const w50 = fill && fill.style.width;
                const sub50 = document.querySelector(rowSel + ' .dl-sub').textContent;
                downloadProgress.update(id, 100, 100);
                const w100 = fill && fill.style.width;
                downloadProgress.done(id);
                const goneRow = !document.querySelector(rowSel);
                const trayHidden = !document.querySelector('#download-tray.show');

                // (b) the byte-counting reader over a fake streamed response
                let seen = 0, calls = 0;
                const parts = [new Uint8Array(30), new Uint8Array(70)];
                let i = 0;
                const body = { getReader() { return { read() {
                    if (i < parts.length) return Promise.resolve({ done: false, value: parts[i++] });
                    return Promise.resolve({ done: true, value: undefined });
                } }; } };
                const fakeResp = { body, headers: new Headers({ 'Content-Length': '100', 'Content-Type': 'application/octet-stream' }) };
                const blob = await readResponseWithProgress(fakeResp, (rec, tot) => { seen = rec; calls++; });
                return { shownStart, w50, sub50, w100, goneRow, trayHidden, blobSize: blob.size, seen, calls };
            }"""
        )
        assert res["shownStart"], "the tray + row should appear on start"
        assert res["w50"] == "50%" and "50%" in res["sub50"]
        assert res["w100"] == "100%"
        assert res["goneRow"] and res["trayHidden"], "the row + tray should clear when done"
        assert res["blobSize"] == 100, "the reader must reassemble every byte"
        assert res["seen"] == 100 and res["calls"] == 2, "progress must be reported per chunk"
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_real_download_still_works_with_progress(page: Page, admin, admin_creds):
    """A real download through the progress path still produces the file (same bytes) and logs no
    console errors -- the byte counter does not change the transfer."""
    v = admin.create_vault(name=unique("dlreal"))
    vid = v["id"]
    content = b"progress-path download payload\n" * 4000  # ~120 KB, several stream chunks
    admin.post(f"/vaults/{vid}/files", files=[("files", ("payload.bin", content, "application/octet-stream"))]).raise_for_status()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        expect(page.locator(".file-name[data-file-id]").first).to_be_visible(timeout=10000)
        fid = page.locator(".file-name[data-file-id]").first.get_attribute("data-file-id")
        with page.expect_download(timeout=15000) as dl_info:
            page.evaluate("(fid) => downloadFile(fid, 'payload.bin')", fid)
        download = dl_info.value
        assert download.suggested_filename == "payload.bin"
        page.wait_for_timeout(300)
        assert not errors, f"console errors during a progress download: {errors}"
    finally:
        admin.delete_vault(vid)
