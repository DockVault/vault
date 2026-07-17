"""Temporary-credential generate modal UX.

A temp credential is a whole-account credential (web + API + SFTP), so the wording no longer says
"SFTP". A recoverable server error (e.g. a password-protected vault whose password wasn't supplied)
must keep the modal OPEN and show the error inline instead of closing it and dropping all the
operator's entered scope/note state. Enabling least-privilege scoping points the operator at where
the "create more credentials" ability moved.
"""
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_temp_modal(page: Page):
    page.click('[data-section="temp-creds"]')
    page.click("#generate-temp-creds-btn")
    expect(page.locator("#generate-temp-creds-modal")).to_be_visible(timeout=8000)


def test_modal_wording_is_whole_account_not_sftp_only(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_temp_modal(page)
    subtitle = page.locator("#generate-temp-creds-modal .modal-body > p.text-secondary").first
    txt = subtitle.inner_text()
    assert "SFTP" in txt and ("web" in txt.lower() or "API" in txt)  # all surfaces named
    assert "one-time SFTP credentials" not in txt  # the old SFTP-only framing is gone


def test_scoping_reveals_cancreate_moved_hint(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_temp_modal(page)
    hint = page.locator("#tc-cancreate-moved-hint")
    legacy = page.locator("#tc-legacy-cancreate-group")
    expect(hint).to_be_hidden()
    expect(legacy).to_be_visible()
    page.check("#tc-scope-enable")
    expect(hint).to_be_visible()      # the relocated control is pointed to
    expect(legacy).to_be_hidden()     # the coarse legacy checkbox is hidden under scoping


def test_missing_vault_password_keeps_modal_open_with_inline_error(page: Page, admin, admin_creds):
    # a password-protected vault; minting a cred scoped to it WITHOUT its password is a recoverable 400
    v = admin.create_vault(name="pw-vault", password="Sup3r-Secret-PW-9!")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        # selected-vaults mode (default); pick the password vault, leave its password box empty
        pick = page.locator(f'.tc-vault-pick[value="{v["id"]}"]')
        expect(pick).to_be_visible(timeout=8000)
        pick.check()
        # the per-vault password field is labelled for the whole vault, not "SFTP"
        pw = page.locator(f'.tc-vault-pw[data-vault="{v["id"]}"]')
        expect(pw).to_have_attribute("placeholder", re.compile(r"password-protected vault"))
        page.click("#generate-temp-creds-form button[type=submit]")
        # the modal must NOT close on the recoverable error — the error shows inline
        err = page.locator("#temp-cred-error")
        expect(err).to_be_visible(timeout=8000)
        expect(err).to_contain_text("password")
        expect(page.locator("#generate-temp-creds-modal")).to_be_visible()
        # and the entered scope state survived (the vault is still picked)
        expect(pick).to_be_checked()
    finally:
        admin.delete_vault(v["id"], vault_password="Sup3r-Secret-PW-9!")
