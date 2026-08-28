"""Upload bug fixes: concurrent same-name detection + a flicker-free upload tray.

  * unit — the in-flight conflict seed and the keyed-reconcile render helpers are wired in.
  * ui   — a real browser:
      - a same-name upload that is still IN FLIGHT (or just finished, still in the tray) is
        detected and opens the keep-both/replace/rename conflict prompt, instead of silently
        uploading a second copy (the reported "same file uploaded twice");
      - a single-file re-upload of a name already in the folder prompts (multi-file always did);
      - the upload tray patches in place, so a control button (Resume) keeps its identity across a
        progress tick instead of being recreated every chunk (the reported Resume-button flicker).
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_upload_fixes_are_wired():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    # (1) the conflict check also treats an in-flight upload's name as taken.
    assert "uploadManager.items.values()" in app
    assert "existing.add(it.fileName)" in app
    # (2) the tray render is a keyed in-place reconcile (no per-chunk full rebuild).
    for fn in ("_controlSig(", "_buildControls(", "_patchRow(", "_buildRow(", "_renderSub("):
        assert fn in app, fn
    # the reconcile keys rows and rebuilds controls only on a status change.
    assert "data-up-row" in app
    assert "row._sig" in app


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
def test_in_flight_same_name_opens_the_conflict_prompt(page: Page, admin, admin_creds):
    """A pick of a name that is CURRENTLY UPLOADING into this folder must prompt, not silently
    add a second copy. Old behaviour: the name was only checked against the loaded file list, so an
    in-flight (or just-finished) name was invisible and a second copy uploaded silently."""
    v = admin.create_vault(name=unique("uprace"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        # Seed a synthetic in-flight upload of "race.txt" (a name NOT in the loaded list), then
        # "pick" the same-named file. The conflict resolver must open its modal.
        page.evaluate(
            """() => {
                uploadManager.items.set('inflight_race', {
                    id: 'inflight_race', vaultId: state.currentVault.id,
                    folderId: state.currentFolderId || null, fileName: 'race.txt',
                    totalSize: 5, totalChunks: 1, chunkSize: 5, received: new Set(),
                    status: 'uploading', cancelled: false, isZk: false });
                const f = new File([new Blob(['hello'])], 'race.txt', { type: 'text/plain' });
                uploadFiles([f]);  // not awaited: it parks on the conflict modal
            }"""
        )
        expect(page.locator("#upload-conflict-modal")).to_be_visible(timeout=8000)
        expect(page.locator("#uc-name")).to_have_text("race.txt")
        # Skip it so nothing actually uploads, and the in-flight synthetic item is left alone.
        page.locator("#uc-skip").click()
        expect(page.locator("#upload-conflict-modal")).to_be_hidden()
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_single_file_reupload_of_an_existing_name_prompts(page: Page, admin, admin_creds):
    """A single-file re-upload of a name already in the folder opens the conflict prompt (the
    reported gap: a multi-file batch prompted but a single file could silently overwrite)."""
    v = admin.create_vault(name=unique("upsingle"))
    vid = v["id"]
    name = unique("doc") + ".txt"
    # Put the name in the folder up front, so the loaded listing already contains it.
    admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"original", "text/plain"))]).raise_for_status()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        expect(page.locator(f'.file-name[data-file-id]')).to_be_visible(timeout=10000)
        # Pick a SINGLE file with the same name.
        page.set_input_files("#file-upload-input",
                             files=[{"name": name, "mimeType": "text/plain", "buffer": b"replacement"}])
        expect(page.locator("#upload-conflict-modal")).to_be_visible(timeout=8000)
        expect(page.locator("#uc-name")).to_have_text(name)
        page.locator("#uc-skip").click()
        expect(page.locator("#upload-conflict-modal")).to_be_hidden()
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_replace_on_an_in_flight_name_cancels_it_not_duplicates(page: Page, admin, admin_creds):
    """Choosing "Replace" on a name that is still UPLOADING cancels that in-flight upload and
    uploads the new file in its place, instead of adding a second copy of the same name (which
    would race the first and both land -- the exact bug via the Replace affordance)."""
    v = admin.create_vault(name=unique("uprepl"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        page.evaluate(
            """() => {
                uploadManager.items.set('inflight_dup', {
                    id: 'inflight_dup', vaultId: state.currentVault.id,
                    folderId: state.currentFolderId || null, fileName: 'dup.txt',
                    totalSize: 5, totalChunks: 1, chunkSize: 5, received: new Set(),
                    status: 'uploading', cancelled: false, isZk: false, sessionId: null });
                const f = new File([new Blob(['hello'])], 'dup.txt', { type: 'text/plain' });
                uploadFiles([f]);
            }"""
        )
        expect(page.locator("#upload-conflict-modal")).to_be_visible(timeout=8000)
        page.check('input[name="uc-action"][value="overwrite"]')
        page.click("#uc-confirm")
        # The in-flight synthetic upload is cancelled (removed), not left to double up.
        page.wait_for_function("() => !uploadManager.items.has('inflight_dup')", timeout=8000)
        assert page.evaluate("() => !uploadManager.items.has('inflight_dup')")
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_tray_control_survives_a_progress_tick(page: Page, admin, admin_creds):
    """The upload tray patches in place: a control button keeps its identity across a render that
    only changed progress, instead of being destroyed and recreated every chunk (the flicker). The
    old render re-set tray.innerHTML each call, so the same button was a different node each tick."""
    v = admin.create_vault(name=unique("upflick"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        res = page.evaluate(
            """() => {
                // A paused item shows a Resume button. Render, note the button node + bar width,
                // advance progress WITHOUT a status change, render again.
                const it = { id: 'flick', vaultId: 'v', folderId: null, isZk: false,
                    file: new Blob(['x']), fileName: 'big.bin', totalSize: 100, totalChunks: 10,
                    chunkSize: 10, received: new Set([0, 1]), status: 'paused', cancelled: false };
                uploadManager.items.set('flick', it);
                uploadManager.render();
                const sel = '#upload-tray .up-row[data-up-row="flick"] button[data-up-action="resume"]';
                const b1 = document.querySelector(sel);
                const fill = document.querySelector('#upload-tray .up-row[data-up-row="flick"] .up-bar-fill');
                const w1 = fill && fill.style.width;
                it.received.add(2); it.received.add(3);   // a progress tick, still paused
                uploadManager.render();
                const b2 = document.querySelector(sel);
                const w2 = fill && fill.style.width;
                uploadManager.items.delete('flick');
                uploadManager.render();
                return { hadButton: !!b1, sameNode: b1 === b2, w1, w2 };
            }"""
        )
        assert res["hadButton"], "a paused upload should show a Resume button"
        assert res["sameNode"], "the Resume button was recreated on a progress tick (flicker)"
        assert res["w1"] != res["w2"], "the progress bar should still update in place"
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_no_console_errors_rendering_the_tray(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uperr"))
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"])
        page.evaluate(
            """() => {
                const mk = (id, status) => ({ id, vaultId: 'v', folderId: null, isZk: false,
                    file: new Blob(['x']), fileName: id + '.bin', totalSize: 10, totalChunks: 2,
                    chunkSize: 5, received: new Set([0]), status, cancelled: false });
                ['queued','uploading','paused','completing','done','error'].forEach((s, i) => {
                    const it = mk('row' + i, s); if (s === 'error') it.error = 'boom';
                    uploadManager.items.set('row' + i, it);
                });
                uploadManager.render();
                // flip a couple of statuses and re-render (exercise the control-signature rebuild).
                uploadManager.items.get('row1').status = 'paused';
                uploadManager.render();
                [...uploadManager.items.keys()].forEach(k => uploadManager.items.delete(k));
                uploadManager.render();
            }"""
        )
        page.wait_for_timeout(300)
        assert not errors, f"console errors while rendering the tray: {errors}"
    finally:
        admin.delete_vault(v["id"])
