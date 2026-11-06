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
from test_ui_zk_key_proof import PASSPHRASE, zk  # noqa: F401 (zk is a fixture)

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
