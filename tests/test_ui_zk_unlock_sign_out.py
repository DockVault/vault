"""An unlock of the account key that finishes after a sign-out, in a real browser (static/js/app.js: logout,
_zkUnlockOnce, zkEnsureUnlocked).

The first person answers the passphrase prompt; while the key is derived from it (a fraction of a second to
several seconds), they sign out, and the next person signs in on the same tab. The next person's first unlock is
their own: it asks the server for their envelope (here they have none, so it says so) and does not join the first
one's. The first one's derivation then ends, and its key is not kept. The derivation is held by the test (the
page's own one is wrapped, and let go when the test says).

Waits are on state, never on time, but for the moment after the derivation ends in which the key must not be kept.
"""
import pytest
from playwright.sync_api import Page, expect

from _ui_hand_over import sign_in_on_the_tab
from conftest import BASE_URL
from test_ui_e2e import _login
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
