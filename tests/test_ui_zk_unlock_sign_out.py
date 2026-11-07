"""An unlock of the account key that finishes after a sign-out, in a real browser (static/js/app.js: logout,
_zkUnlockOnce, zkEnsureUnlocked).

The first person answers the passphrase prompt; while the key is derived from it (a fraction of a second to
several seconds), they sign out, and the next person signs in on the same tab. The next person's first unlock is
their own: it asks the server for their envelope (here they have none, so it says so) and does not join the first
one's. The first one's derivation then ends, and its key is not kept. The derivation is held by the test (the
page's own one is wrapped, and let go when the test says).

An unlock that a sign-out ends never comes back, and neither do the transfers waiting on it: the first person's
downloads of a zero-knowledge vault, waiting at the passphrase prompt when they sign out, hold the five places the
page gives transfers (static/js/transfer_gate.js). The sign-out frees those places, so the next person's own
download and upload start.

Waits are on state, never on time, but for the moments after which something must not happen.
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from _ui_hand_over import sign_in_on_the_tab
from conftest import BASE_URL
from test_ui_e2e import _create_zk_vault_via_ui, _login, _u
from test_ui_zk_key_proof import PASSPHRASE, _keyed, zk  # noqa: F401 (zk is a fixture)

pytestmark = pytest.mark.ui

# The page's own derivation of the key from the passphrase, held until window.__letDerive() is called.
HOLD_DERIVE = """() => {
    const lib = eccLib();
    const derive = lib.decryptPrivateEnvelope.bind(lib);
    lib.decryptPrivateEnvelope = (...args) => new Promise((resolve, reject) => {
        window.__letDerive = () => derive(...args).then((v) => { window.__derived = true; resolve(v); }, reject);
    });
}"""


def _set_up_key(page: Page):
    """The standalone "Set up encryption key": it leaves the key registered and unlocked."""
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    page.click("#encryption-key-setup-btn")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
    page.click("#confirm-modal-confirm-btn")
    for _ in range(2):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", PASSPHRASE)
        page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
    page.locator("#encryption-key-modal .close-modal-btn").first.click()
    expect(page.locator("#encryption-key-modal")).to_be_hidden(timeout=5000)


def test_an_unlock_that_ends_after_a_sign_out_keeps_no_key_for_the_next_person(browser, zk):
    ada, _ada_c = zk()
    ben, _ben_c = zk()
    page = browser.new_context(base_url=BASE_URL).new_page()
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _login(page, ada["_username"], ada["_password"])
        _set_up_key(page)
        page.evaluate("() => zkResetKeys()")                    # locked: the next step asks for the passphrase
        assert page.evaluate("() => zkState.privateKey === null")
        page.evaluate(HOLD_DERIVE)
        page.evaluate("() => { window.__first = 'running'; zkEnsureUnlocked().then("
                      "() => { window.__first = 'unlocked'; }, (e) => { window.__first = 'failed: ' + e.message; }); }")
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=10000)
        page.fill("#confirm-modal-input", PASSPHRASE)
        page.click("#confirm-modal-confirm-btn")
        page.wait_for_function("() => typeof window.__letDerive === 'function'", timeout=10000)

        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        sign_in_on_the_tab(page, ben)
        # ben's first unlock is his own: he has no key, and it says so at once.
        page.evaluate("() => { window.__bens = 'running'; zkEnsureUnlocked().then("
                      "() => { window.__bens = 'unlocked'; }, (e) => { window.__bens = 'failed: ' + e.message; }); }")
        page.wait_for_function("() => window.__bens !== 'running'", timeout=10000)
        assert page.evaluate("() => window.__bens") == "failed: No encryption key is set up for your account."

        page.evaluate("() => window.__letDerive()")
        page.wait_for_function("() => window.__derived === true", timeout=30000)
        page.wait_for_timeout(1500)                           # the moment in which the key would be kept
        assert page.evaluate("() => zkState.privateKey === null"), "the first person's key was kept for the next"
        assert page.evaluate("() => window.__first") == "running", "the first person's unlock said something"
        # ben's next step still has no key: it asks the server again, and is told he has none.
        page.evaluate("() => { window.__bens = 'running'; zkEnsureUnlocked().then("
                      "() => { window.__bens = 'unlocked'; }, (e) => { window.__bens = 'failed: ' + e.message; }); }")
        page.wait_for_function("() => window.__bens !== 'running'", timeout=10000)
        assert page.evaluate("() => window.__bens") == "failed: No encryption key is set up for your account."
        assert errors == []
    finally:
        page.context.close()


NEW_PASSPHRASE = "another-Passphrase-456"
RECOVERY_PASSPHRASE = "recovery-Passphrase-789"

# The page's own wrap of the key under a new passphrase (its derivation), held until window.__letWrap() is called.
HOLD_WRAP = """() => {
    const lib = eccLib();
    for (const name of ['encryptPrivateKey', 'encryptPrivateKeyV1']) {
        if (typeof lib[name] !== 'function') continue;
        const wrap = lib[name].bind(lib);
        lib[name] = (...args) => new Promise((resolve, reject) => {
            window.__letWrap = () => wrap(...args).then((v) => { window.__wrapped = true; resolve(v); }, reject);
        });
    }
}"""

# Every message the page shows from now on.
WATCH_MESSAGES = """() => {
    window.__shown = [];
    new MutationObserver((records) => records.forEach((r) => r.addedNodes.forEach((n) => {
        if (n.classList && n.classList.contains('toast')) window.__shown.push(n.className + ': ' + n.textContent);
    }))).observe(document.getElementById('toast-container'), { childList: true });
}"""


def _open_key_dialog(page: Page):
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)


def _answer(page: Page, *answers):
    for text in answers:
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=15000)
        page.fill("#confirm-modal-input", text)
        page.click("#confirm-modal-confirm-btn")


def test_a_passphrase_change_that_ends_after_a_sign_out_leaves_the_next_person_their_dialog(browser, zk):
    """The first person changes their passphrase and signs out while the key is wrapped under the new one; the next
    person (who has a key of their own) opens the encryption key dialog: its Change passphrase and Export recovery
    key buttons are theirs to use, not turned off by the first person's change. The change then ends without a
    word to the next person, stores nothing, and keeps no key."""
    ada, ada_c = zk()
    ben, ben_c = zk()
    _keyed(ben_c)
    page = browser.new_context(base_url=BASE_URL).new_page()
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    try:
        _login(page, ada["_username"], ada["_password"])
        _set_up_key(page)
        stored = ada_c.get("/ecc/keys/private").json()["encrypted_private_key"]
        _open_key_dialog(page)
        page.evaluate(HOLD_WRAP)
        page.click("#encryption-key-change-passphrase-btn")
        _answer(page, PASSPHRASE, NEW_PASSPHRASE, NEW_PASSPHRASE)
        page.wait_for_function("() => typeof window.__letWrap === 'function'", timeout=30000)
        expect(page.locator("#encryption-key-change-passphrase-btn")).to_be_disabled()   # while it runs

        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        sign_in_on_the_tab(page, ben)
        page.evaluate(WATCH_MESSAGES)
        _open_key_dialog(page)
        expect(page.locator("#encryption-key-change-passphrase-btn")).to_be_visible()
        expect(page.locator("#encryption-key-change-passphrase-btn")).to_be_enabled()
        expect(page.locator("#encryption-key-export-recovery-btn")).to_be_enabled()

        page.evaluate("() => window.__letWrap()")
        page.wait_for_function("() => window.__wrapped === true", timeout=30000)
        page.wait_for_timeout(1500)                           # the moment in which it would be stored or said
        assert page.evaluate("() => window.__shown") == [], "the first person's change spoke to the next person"
        assert page.evaluate("() => zkState.privateKey === null"), "the first person's key was kept for the next"
        expect(page.locator("#encryption-key-change-passphrase-btn")).to_be_enabled()
        assert ada_c.get("/ecc/keys/private").json()["encrypted_private_key"] == stored
        assert errors == []
    finally:
        page.context.close()


def test_a_recovery_key_export_that_ends_after_a_sign_out_downloads_nothing(browser, zk):
    """The first person exports a recovery key and signs out while it is wrapped under the recovery passphrase: no
    kit lands in the browser's downloads after they have gone, nothing is said to the next person, and the export
    button is not left turned off."""
    ada, _ada_c = zk()
    page = browser.new_context(base_url=BASE_URL, accept_downloads=True).new_page()
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    downloads = []
    page.on("download", lambda d: downloads.append(d.suggested_filename))
    try:
        _login(page, ada["_username"], ada["_password"])
        _set_up_key(page)
        _open_key_dialog(page)
        expect(page.locator("#encryption-key-export-recovery-btn")).to_be_visible(timeout=10000)
        page.evaluate(HOLD_WRAP)
        page.click("#encryption-key-export-recovery-btn")
        _answer(page, PASSPHRASE, RECOVERY_PASSPHRASE, RECOVERY_PASSPHRASE)
        page.wait_for_function("() => typeof window.__letWrap === 'function'", timeout=30000)

        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.evaluate(WATCH_MESSAGES)
        page.evaluate("() => window.__letWrap()")
        page.wait_for_function("() => window.__wrapped === true", timeout=30000)
        page.wait_for_timeout(1500)                           # the moment in which the kit would be handed over
        assert downloads == [], "a recovery kit landed in the downloads after the sign-out"
        assert page.evaluate("() => window.__shown") == []
        assert page.evaluate("() => document.getElementById('encryption-key-export-recovery-btn').disabled") is False
        assert errors == []
    finally:
        page.context.close()


# How many transfers run, and how many wait for a place (static/js/transfer_gate.js: five places).
GATE = "() => [transferGate.active, transferGate.waiting]"


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=15000)
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)


def _files(client, vault_id):
    return [i for i in client.get(f"/vaults/{vault_id}/files").json()["items"] if i["type"] == "file"]


def test_transfers_waiting_for_the_key_at_a_sign_out_leave_the_next_person_room(browser, zk):
    """The first person's key locks, as it does after a time without use, and they download six files of their
    zero-knowledge vault: five wait at the passphrase prompt, each in one of the five places the page gives
    transfers, and the sixth waits for a place. They sign out at the prompt. The places are free again and nothing
    waits: the next person signs in on the tab, and a download and an upload in a vault of their own start and
    finish. None of the first person's six ends, and none of them begins a download after the sign-out.

    Each of the five hands the browser its download as it begins, before it asks for the key (the file is streamed
    into it as it is decrypted), so the browser holds five downloads of the first person when they sign out; nothing
    is written into them, since the key never comes."""
    ada, ada_c = zk("admin")
    ben, ben_c = zk("admin")
    page = browser.new_context(base_url=BASE_URL, accept_downloads=True).new_page()
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    landed = []
    page.on("download", lambda d: landed.append(d.suggested_filename))
    zk_vault = own_vault = None
    try:
        _login(page, ada["_username"], ada["_password"])
        zk_vault = _create_zk_vault_via_ui(page, ada_c, PASSPHRASE)
        _open_vault(page, zk_vault)
        page.set_input_files("#file-upload-input", files=[
            {"name": f"{_u('waits')}-{i}.txt", "mimeType": "text/plain", "buffer": b"x" * 100} for i in range(5)])
        for _ in range(120):
            if len(_files(ada_c, zk_vault)) == 5:
                break
            page.wait_for_timeout(250)
        assert len(_files(ada_c, zk_vault)) == 5, "the first person's five files were not uploaded"
        page.wait_for_function("() => (state.currentFiles || []).filter((f) => f.type === 'file').length === 5 "
                               "&& transferGate.active === 0 && transferGate.waiting === 0", timeout=30000)
        ids = page.evaluate("() => state.currentFiles.filter((f) => f.type === 'file').map((f) => f.id)")
        assert page.evaluate("() => state.downloadSink") == "streaming", "the stack does not stream downloads"
        # The key locks (the page's own lock after a time without use), and six downloads start at once: the five
        # files, and the first one again.
        page.evaluate("(ids) => { zkIdleLock(); window.__firsts = []; ids.concat([ids[0]]).forEach((id, n) => "
                      "downloadFile(id, 'first-' + n + '.txt').then(() => window.__firsts.push('ended'), "
                      "(e) => window.__firsts.push('failed: ' + e.message))); }", ids)
        assert page.evaluate("() => zkState.privateKey === null")
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=15000)
        page.wait_for_function("() => transferGate.active === 5 && transferGate.waiting === 1", timeout=15000)
        # The browser has the five downloads: each of the five asked for the key right after handing it its download.
        for _ in range(300):
            if len(landed) == 5:
                break
            page.wait_for_timeout(50)
        assert sorted(landed) == [f"first-{n}.txt" for n in range(5)], landed
        assert page.evaluate(GATE) == [5, 1]

        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        assert page.evaluate(GATE) == [0, 0], "the sign-out left the places of the transfers waiting for the key taken"
        before = len(landed)

        own_vault = ben_c.create_vault(name=_u("own"))["id"]
        sent = ben_c.post(f"/vaults/{own_vault}/files",
                          files=[("files", ("theirs.txt", b"the next person's file", "text/plain"))])
        assert sent.status_code in (200, 201), sent.text
        fid = _files(ben_c, own_vault)[0]["id"]
        sign_in_on_the_tab(page, ben)
        _open_vault(page, own_vault)
        with page.expect_download(timeout=20000) as got:
            page.locator(f'button[data-action="download"][data-id="{fid}"]:visible').first.click()
        assert Path(got.value.path()).read_bytes() == b"the next person's file"
        page.set_input_files("#file-upload-input", files=[
            {"name": "uploaded.txt", "mimeType": "text/plain", "buffer": b"the next person's upload"}])
        for _ in range(120):
            if any(f["name"] == "uploaded.txt" for f in _files(ben_c, own_vault)):
                break
            page.wait_for_timeout(250)
        assert any(f["name"] == "uploaded.txt" for f in _files(ben_c, own_vault)), "the next person's upload never ran"

        page.wait_for_timeout(1500)                           # the moment in which a first person's download would end
        assert landed[before:] == ["theirs.txt"], landed
        assert page.evaluate("() => window.__firsts") == [], "a download of the first person ended for the next"
        assert errors == []
    finally:
        page.context.close()
        if own_vault:
            ben_c.delete_vault(own_vault)
        if zk_vault:
            ada_c.delete_vault(zk_vault)
