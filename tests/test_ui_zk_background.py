"""What the web app does for zero-knowledge vaults on its own, in real browsers (static/js/zk-background.js).

* A manager who holds a direct vault's key and opens it sets up the key check its current epoch lacks (an epoch made
  before key proofs): at once while the key is unlocked, with no prompt; while it is locked, once the opening's own
  passphrase prompt (for the vault's sealed name) is answered, so the opening asks once and nothing asks again; and
  only once per vault and epoch for the page. An unlock after the vault was closed sets nothing up.
* A team vault, whose key check is its team key, is never set up this way.
* A bulk share of ten, of a standard vault and of a zero-knowledge one while locked, never has more than four of
  its requests in flight, and the locked one asks for the passphrase once.
"""

from __future__ import annotations

import time

import pytest
from playwright.sync_api import Page, expect

from conftest import BASE_URL, ApiClient, unique
from test_ui_e2e import _create_zk_vault_via_ui, _login
from test_ui_zk_key_proof import PASSPHRASE, _keyed, _psql, _wait_for, zk  # noqa: F401 (zk is a fixture)
from test_ui_zk_rekey_notice import _create_team_vault_via_ui, _open_vault

pytestmark = pytest.mark.ui

# Counts the passphrase prompts, the key-check setups (PUT .../key-proof) and, once __holdShares is set, the
# requests of a share in flight at once (its /ecc/ requests and its POST .../permissions), each held 150 ms so
# that requests not held back overlap.
COUNTERS = """() => {
    window.__prompts = 0; window.__setups = 0; window.__inflight = 0; window.__maxInflight = 0;
    window.__shareRequests = 0;
    const prompt = showPrompt;
    showPrompt = (...a) => { window.__prompts++; return prompt(...a); };
    const original = window.fetch;
    window.fetch = async (url, opts) => {
        const u = String(url);
        const method = String((opts && opts.method) || 'GET').toUpperCase();
        if (method === 'PUT' && /\\/key-proof$/.test(u)) window.__setups++;
        const share = (method === 'POST' && /\\/permissions$/.test(u)) || /\\/ecc\\//.test(u);
        if (!window.__holdShares || !share) return original(url, opts);
        window.__inflight++; window.__shareRequests++;
        window.__maxInflight = Math.max(window.__maxInflight, window.__inflight);
        try { await new Promise(r => setTimeout(r, 150)); return await original(url, opts); }
        finally { window.__inflight--; }
    };
}"""


def _source(vid: str) -> str:
    return _psql(f"SELECT coalesce(string_agg(source, ','), '') FROM vault_key_proofs WHERE vault_id = '{vid}'")


def _counts(page: Page) -> tuple:
    return tuple(page.evaluate("() => [window.__prompts, window.__setups]"))


def _answer_prompt(page: Page) -> None:
    expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=10000)
    page.fill("#confirm-modal-input", PASSPHRASE)
    page.click("#confirm-modal-confirm-btn")


def _forget_key_check(vid: str) -> None:
    """As a vault made before key proofs: its epoch has no key check."""
    _psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{vid}'")


def test_opening_a_direct_vault_sets_up_its_key_check_once_and_asks_at_most_once(browser, zk):
    owner, co = zk()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    other = None
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)      # leaves the key unlocked
        assert _source(vid) == "create"
        _forget_key_check(vid)
        page.evaluate(COUNTERS)
        _open_vault(page, vid)
        _wait_for(lambda: _source(vid) == "bootstrap", "the key check set up on opening")
        assert _counts(page) == (0, 1)

        # Once for the page: gone again and the vault opened again, nothing is set up (the next key change does it).
        _forget_key_check(vid)
        _open_vault(page, vid)
        time.sleep(3)
        assert _counts(page) == (0, 1) and _source(vid) == ""

        # Another page, with the key locked: the opening asks for the passphrase (the vault's name is sealed), and
        # the key check is set up once that is answered, with no prompt of its own.
        other = browser.new_context(base_url=BASE_URL)
        page2 = other.new_page()
        _login(page2, owner["_username"], owner["_password"])
        page2.evaluate(COUNTERS)
        assert page2.evaluate("() => zkKeyUnlocked()") is False
        page2.click('.sidebar-item[data-section="vaults"]')
        page2.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page2.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        _answer_prompt(page2)
        expect(page2.locator("#vault-view-section")).to_be_visible(timeout=10000)
        _wait_for(lambda: _source(vid) == "bootstrap", "the key check set up after the opening's unlock")
        time.sleep(2)
        assert _counts(page2) == (1, 1)
        _open_vault(page2, vid)
        time.sleep(2)
        assert _counts(page2) == (1, 1)
    finally:
        ctx.close()
        if other is not None:
            other.close()
        if vid:
            co.delete_vault(vid)


def test_an_unlock_after_the_vault_was_closed_sets_up_nothing(browser, zk):
    owner, co = zk()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)
        _open_vault(page, vid)                     # its key check is there: nothing to set up
        page.evaluate(COUNTERS)
        _forget_key_check(vid)
        page.evaluate("() => zkResetKeys()")
        # The vault seen again while the key is locked: the setup waits for an unlock, and asks nothing.
        page.evaluate("() => refreshZkRekeyNotice()")
        assert _counts(page) == (0, 0)
        page.evaluate("() => closeVault()")
        page.evaluate("() => { window.__unlock = zkEnsureUnlocked().then(() => 'ok', e => String(e)); }")
        _answer_prompt(page)
        assert page.evaluate("() => window.__unlock") == "ok"
        time.sleep(3)
        assert _counts(page) == (1, 0) and _source(vid) == ""
        # The control: opened again, now unlocked, it is set up.
        _open_vault(page, vid)
        _wait_for(lambda: _source(vid) == "bootstrap", "the key check set up on opening")
        assert _counts(page) == (1, 1)
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)


def test_a_team_vault_is_never_set_up_on_opening(browser, zk):
    owner, co = zk()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        first = _create_zk_vault_via_ui(page, co, PASSPHRASE)  # sets up and unlocks the key
        co.delete_vault(first)
        vid = _create_team_vault_via_ui(page, co)
        page.evaluate(COUNTERS)
        _open_vault(page, vid)
        time.sleep(3)
        assert _counts(page) == (0, 0)
        assert page.evaluate("async (v) => (await zkVaultKeyStatus(v)).keys.key_proof.state", vid) == "team"
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)


def _people(admin, tag: str, n: int = 10) -> list:
    """n accounts whose usernames share ``tag``, so the share picker's search finds them all, each with a client."""
    out = []
    for i in range(n):
        person = admin.create_user(username=f"{tag}_{i}")
        c = ApiClient()
        c.login(person["_username"], person["_password"])
        out.append((person, c))
    return out


def _pick_and_share(page: Page, tag: str, ids: list) -> None:
    page.click('[data-vault-tab="permissions"]')
    page.click("#add-permission-btn")
    expect(page.locator("#vault-grant-modal")).to_be_visible(timeout=5000)
    page.fill("#vault-grant-search", tag)
    for uid in ids:
        page.wait_for_selector(f'#vault-grant-list input[value="{uid}"]', timeout=8000)
        page.check(f'#vault-grant-list input[value="{uid}"]')
    page.evaluate("() => { window.__holdShares = true; }")
    page.click("#vault-grant-confirm")


def test_a_bulk_share_of_ten_has_at_most_four_requests_in_flight(browser, admin, admin_creds):
    tag = unique("bulk")
    people = _people(admin, tag)
    vault = admin.create_vault()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.evaluate(COUNTERS)
        _open_vault(page, vault["id"])
        _pick_and_share(page, tag, [p["id"] for p, _ in people])
        expect(page.locator("#vault-grant-modal")).to_be_hidden(timeout=30000)
        assert page.evaluate("() => [window.__shareRequests, window.__maxInflight]") == [10, 4]
        members = {str(m.get("user_id")) for m in admin.get(f"/vaults/{vault['id']}/permissions").json()}
        assert {p["id"] for p, _ in people} <= members
    finally:
        ctx.close()
        admin.delete_vault(vault["id"])
        for p, _ in people:
            admin.delete_user(p["id"])


def test_a_locked_bulk_share_of_ten_zero_knowledge_asks_once_with_at_most_four_in_flight(browser, admin, zk):
    owner, co = zk()
    tag = unique("zkbulk")
    people = _people(admin, tag)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        for _, c in people:
            _keyed(c)
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)
        _open_vault(page, vid)
        page.evaluate("() => zkResetKeys()")
        page.evaluate(COUNTERS)
        _pick_and_share(page, tag, [p["id"] for p, _ in people])
        _answer_prompt(page)
        expect(page.locator("#vault-grant-modal")).to_be_hidden(timeout=60000)
        assert page.evaluate("() => window.__prompts") == 1
        most = page.evaluate("() => window.__maxInflight")
        assert 2 <= most <= 4, most
        assert _psql(f"SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vid}' AND is_active") == "11"
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)
        for p, _ in people:
            admin.delete_user(p["id"])
