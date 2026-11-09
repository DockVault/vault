"""The browser's copy of an upload link's address names the address it is of.

An upload link's address can be replaced, so the copy the owner's browser stores carries the SHA-256 of the
address it was made from; the server refuses a copy of an address the link no longer has. Here the page's own
save routine runs in a signed-in browser with the key calls stood in for, and the request it sends is read.
A file or note link's address is never replaced, and its copy carries no such name.
"""
import hashlib

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

SAVE_AND_CAPTURE = """async ([kind, token]) => {
    const sent = [];
    const realRequest = window.apiRequest, realLib = window.eccLib;
    window.apiRequest = async (url, opts) => {
        if (url === '/ecc/keys/public') return { has_keypair: true, public_key: 'stand-in' };
        sent.push({ url, method: opts && opts.method, body: opts && opts.body ? JSON.parse(opts.body) : null });
        return { stored: true };
    };
    window.eccLib = () => ({ importPublicKeyPEM: async () => ({}), wrapLinkTokenV2: async () => 'blob' });
    try {
        const result = await _saveLinkReCopy(kind, { id: 'link-1', token, owner_id: 'owner-1' });
        return { result, sent };
    } finally {
        window.apiRequest = realRequest;
        window.eccLib = realLib;
    }
}"""


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def test_an_upload_links_copy_carries_the_hash_of_its_address(page: Page, person):
    _login(page, person)
    token = "Upl0ad-address_with-ünïcode-é"
    out = page.evaluate(SAVE_AND_CAPTURE, ["receiver", token])
    assert out["result"] == {"saved": True}, out
    [put] = out["sent"]
    assert put["url"] == "/receivers/link-1/token-copy" and put["method"] == "PUT"
    assert put["body"] == {"token_enc": "blob", "token_hash": hashlib.sha256(token.encode()).hexdigest()}


@pytest.mark.parametrize("kind,path", [("public", "/public-links/link-1/token-copy"),
                                       ("note", "/note-links/link-1/token-copy")])
def test_a_file_or_note_links_copy_names_no_address(page: Page, person, kind, path):
    _login(page, person)
    out = page.evaluate(SAVE_AND_CAPTURE, [kind, "some-address"])
    [put] = out["sent"]
    assert put["url"] == path and put["body"] == {"token_enc": "blob"}
