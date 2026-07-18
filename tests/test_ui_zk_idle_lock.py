"""UI — ZK passphrase browser-exposure hardening.

Three surfaces:
- the admin `zk_idle_lock_minutes` control on the Zero-Knowledge Vaults settings card;
- the `autocomplete` guard on the reused passphrase prompt input (`#confirm-modal-input`), set
  per-use so a password prompt is marked one-time-code (not saved by a password manager);
- the client idle auto-lock logic (arm when a key is unlocked + policy on; drop the key on fire).
"""
import time

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _wait_until(pred, msg, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise AssertionError(msg)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_sftp_settings(page: Page):
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "GET"
    ):
        page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.click('.tab-btn[data-tab="sftp"]')
    expect(page.locator("#settings-tab-sftp")).to_be_visible()


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def test_zk_idle_lock_card_round_trips(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"zk_idle_lock_minutes": 0})
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_sftp_settings(page)

        box = page.locator("#setting-zk-idle-lock-minutes")
        expect(box).to_be_visible()
        expect(box).to_have_value("0")

        box.fill("20")
        # Poll the authoritative store, re-clicking Save if a cold-browser click doesn't fire the
        # PUT (the field keeps its value, so a retry is idempotent).
        saved = lambda: admin.get("/settings").json().get("zk_idle_lock_minutes") == 20
        for _ in range(3):
            page.click("#save-all-settings-btn")
            try:
                _wait_until(saved, "retry", timeout=5)
                break
            except AssertionError:
                continue
        assert saved(), "zk_idle_lock_minutes did not persist after Save"

        page.reload()
        _open_sftp_settings(page)
        expect(page.locator("#setting-zk-idle-lock-minutes")).to_have_value("20")
    finally:
        admin.put("/settings", json={"zk_idle_lock_minutes": 0})


def test_passphrase_prompt_autocomplete_guard(page: Page):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()  # app.js loaded

    # A password prompt marks the reused input as a one-time code (manager won't save it).
    # (Dismiss via the modal's document-level Escape handler — the buttons sit behind the
    # pre-login overlay and aren't clickable there, but the autocomplete attributes are set.)
    page.evaluate("() => { window.__p = showPrompt('msg', 'title', { password: true }); }")
    expect(page.locator("#confirm-modal-input")).to_have_attribute("autocomplete", "one-time-code")
    expect(page.locator("#confirm-modal-input")).to_have_attribute("type", "password")
    assert page.get_attribute("#confirm-modal-input", "spellcheck") == "false"
    page.keyboard.press("Escape")

    # A plain text prompt resets it (no one-time-code marker, text input).
    page.evaluate("() => { window.__p = showPrompt('msg', 'title', {}); }")
    expect(page.locator("#confirm-modal-input")).to_have_attribute("autocomplete", "off")
    expect(page.locator("#confirm-modal-input")).to_have_attribute("type", "text")
    page.keyboard.press("Escape")


def test_zk_idle_lock_client_logic(page: Page):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()

    result = page.evaluate(
        """() => {
            // policy on but no key unlocked -> nothing armed
            zkResetKeys();
            setZkIdleLockMinutes(10);
            const armedNoKey = _zkIdleTimer;
            // a key is unlocked -> the countdown arms
            zkState.privateKey = { fake: true };
            setZkIdleLockMinutes(10);
            const armedWithKey = !!_zkIdleTimer;
            // firing the lock drops the key and clears the timer
            zkIdleLock();
            const keyAfter = zkState.privateKey;
            const timerAfter = _zkIdleTimer;
            // policy 0 disables even with a key present
            zkState.privateKey = { fake: true };
            setZkIdleLockMinutes(0);
            const armedZero = _zkIdleTimer;
            zkResetKeys();
            return { armedNoKey, armedWithKey, keyAfter, timerAfter, armedZero };
        }"""
    )
    assert result["armedNoKey"] is None, "armed a timer with no key unlocked"
    assert result["armedWithKey"] is True, "did not arm the idle timer when a key is unlocked"
    assert result["keyAfter"] is None, "idle lock did not drop the in-memory key"
    assert result["timerAfter"] is None, "idle lock left a timer running"
    assert result["armedZero"] is None, "armed a timer when the policy is 0 (disabled)"
