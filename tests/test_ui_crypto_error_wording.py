"""What the user is actually told, in a real browser, when a crypto operation fails.

The offline suite proves the module raises the right code and the seam maps it to the right
sentence. Neither proves the two are WIRED together, and the wiring is where the original defect
lived: the code was always distinguishable in principle, and the interface still said "wrong
passphrase".

So this drives the shipped page and reads the rendered text.
"""

import json
import uuid

import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient

pytestmark = [pytest.mark.ui, pytest.mark.crypto_compatibility]


def _login(page: Page, username: str, password: str) -> None:
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def signed_in(page: Page, admin_creds) -> Page:
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def _unlock_message(page: Page, envelope: str) -> str:
    """Serve `envelope` as the account's stored key, then run the real unlock and report what the
    user would be shown. The passphrase prompt is stubbed to a fixed answer so the flow reaches
    decryption without human input."""
    page.route(
        "**/ecc/keys/private",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"has_keypair": True, "encrypted_private_key": envelope}),
        ),
    )
    return page.evaluate(
        """async (pass) => {
            window.showPrompt = async () => pass;
            zkState.privateKey = null;
            try { await zkEnsureUnlocked(); return '<<no error>>'; }
            catch (e) { return e && e.message ? e.message : String(e); }
        }""",
        "any-passphrase",
    )


_UNSUPPORTED = json.dumps({
    "v": 99, "kdf": "PBKDF2-SHA256", "cipher": "AES-256-GCM", "iter": 600000,
    "salt": "A" * 43 + "=", "iv": "AAAAAAAAAAAAAAAA", "ct": "A" * 44,
})
_DAMAGED = "{ this is not an envelope"


def test_an_envelope_from_a_newer_build_is_not_reported_as_a_wrong_passphrase(
    signed_in: Page,
) -> None:
    """The headline property of the whole contract, checked where it actually matters.

    The passphrase is not involved: the envelope is well formed and this build simply cannot read
    it. Being told the passphrase is wrong sends the user to retype one that is right, then to a
    recovery kit they do not need -- and the message this replaced went further and told them to
    re-register, which the server refuses with a 409 and which would orphan every wrapped vault
    key if it did not.
    """
    message = _unlock_message(signed_in, _UNSUPPORTED)

    assert message != "<<no error>>"
    low = message.lower()
    assert "passphrase" not in low, f"still blames the passphrase: {message!r}"
    assert "newer version" in low, message
    assert "update" in low, message
    # Re-registration may only appear as a prohibition. The old wording recommended it.
    assert "do not re-register" in low, message
    assert low.count("re-register") == 1, f"re-registration mentioned as advice: {message!r}"


def test_a_damaged_envelope_and_a_newer_one_do_not_share_a_sentence(signed_in: Page) -> None:
    """They were one sentence before. Telling them apart is the point: one means restore from a
    recovery kit, the other means change nothing and update the deployment."""
    damaged = _unlock_message(signed_in, _DAMAGED)
    signed_in.unroute("**/ecc/keys/private")
    newer = _unlock_message(signed_in, _UNSUPPORTED)

    assert damaged != newer, "a damaged key and a newer one still read identically"
    assert "passphrase" not in damaged.lower(), damaged
    assert "recovery" in damaged.lower(), damaged


def test_a_genuine_wrong_passphrase_still_says_so(signed_in: Page, admin) -> None:
    """The negative tests above would pass on a build that never mentioned passphrases at all.
    This is the control that keeps them honest."""
    page = signed_in
    real = page.evaluate(
        """async () => {
            const lib = eccLib();
            const kp = await lib.generateKeypair();
            const pem = await lib.exportPrivateKeyPEM(kp.privateKey);
            return JSON.stringify(await lib.encryptPrivateKey(pem, 'the-right-passphrase'));
        }"""
    )
    message = _unlock_message(page, real)  # the stub answers with a DIFFERENT passphrase

    assert message != "<<no error>>"
    assert "passphrase" in message.lower(), f"a real wrong passphrase must say so: {message!r}"


def test_the_page_console_carries_no_platform_detail(signed_in: Page) -> None:
    """A support conversation is conducted from what the console shows."""
    page = signed_in
    seen: list[str] = []
    page.on("console", lambda m: seen.append(f"{m.type}:{m.text}") if m.type == "error" else None)

    _unlock_message(page, _DAMAGED)
    page.wait_for_timeout(300)

    for line in seen:
        for leak in ("DOMException", "OperationError", "InvalidCharacterError", "    at "):
            assert leak not in line, f"platform detail reached the production console: {line}"
