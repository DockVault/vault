"""Source-pinned wiring of the owner-encrypted re-copy into the SPA (LINK-TOKENS part b UX).

The behaviour (wrap at creation with the public key only, "Show link again" client-decrypt, the
no-keypair and post-rotation messages) is a UI/live-lane test; here we pin the wiring in app.js:
creation shows the token first then best-effort saves the blob using the PUBLIC key (no unlock), the
Shared cards offer "Show link again" only when a re-copy exists, and the confirmed UX strings are used.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

APPJS = Path(__file__).resolve().parents[1] / "static" / "js" / "app.js"


def _js():
    return APPJS.read_text(encoding="utf-8")


def test_creation_wraps_with_the_public_key_only_no_unlock_prompt():
    js = _js()
    save = js[js.index("async function _saveLinkReCopy("):js.index("function _setLinkReCopyNote(")]
    assert "/ecc/keys/public" in save and "/ecc/keys/private" not in save   # public key only -> no unlock
    assert "wrapLinkTokenV2(link.token" in save
    assert "linkId: link.id" in save and "ownerId" in save                  # AAD bound to (link, owner)
    assert "/token-copy" in save and "method: 'PUT'" in save


def test_show_again_unlocks_and_decrypts_client_side_with_an_honest_rotation_message():
    js = _js()
    show = js[js.index("async function _showLinkAgain("):js.index("function copyNoteLinkUrl(")]
    assert "zkEnsureUnlocked()" in show and "unwrapLinkTokenV2(" in show     # client-side decrypt
    assert "Re-copy unavailable after your key change — create a new link" in show   # S2 rotation string


def test_the_no_keypair_and_not_saved_notes_use_the_confirmed_strings():
    js = _js()
    assert "Set up your encryption key to be able to see links again." in js  # no-keypair UX
    assert "Re-copy not saved" in js                                          # quiet best-effort failure


def test_creation_shows_the_token_before_it_tries_to_save_the_recopy():
    js = _js()
    for value_set, kind in (("_npEl('note-public-link-value').value = url;", "note"),
                            ("_pflEl('pfl-link-value').value = url;", "public")):
        assert value_set in js
        after = js[js.index(value_set):]
        save_call = "_saveLinkReCopy('%s', link)" % kind
        assert save_call in after[:400], "the re-copy save must come AFTER the token is shown"


def test_both_owner_cards_offer_show_again_only_when_a_recopy_exists():
    js = _js()
    assert js.count("if (l.has_token_copy) {") == 2                          # note card + file card
    assert "_showLinkAgain('note', l.id, '/l/')" in js
    assert "_showLinkAgain('public', l.id, '/p/')" in js
    # the broken plaintext "Copy link" (token is no longer listed) is gone from the note card
    assert "copyNoteLinkUrl(l))" not in js
