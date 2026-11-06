"""Settings -> Storage shows what legal holds keep after a deletion ("Kept for cases"), in a real browser.

Kept bytes are on the deployment's disk and count toward its storage limit, but in no vault's size, so the storage
panel says so beside its totals
(static/js/compliance.js, renderKeptForCases, fed by GET /storage/stats' kept_for_cases). A kept row and the hold
that keeps it are written straight into the database here (a vault id nothing else uses), and removed after.
"""
import uuid

import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import in_api_container, psql

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def kept_row(admin_creds):
    """One kept file of 4096 bytes on a vault id of its own, under a hold that stands (so the purge leaves it)."""
    vault_id, case_id, file_id = (str(uuid.uuid4()) for _ in range(3))
    admin_id = psql(f"SELECT id FROM users WHERE username = '{admin_creds['username']}'")
    psql("INSERT INTO compliance_cases (id, status, purpose, legal_basis, justification_enc, owner_note_enc, "
         "auditor_id, auditor_username, requested_at, created_at, updated_at) VALUES "
         f"('{case_id}', 'hold_only', 'other', 'legal_obligation', 'cenc1:x', 'cenc1:x', '{admin_id}', "
         f"'{admin_creds['username']}', now(), now(), now())")
    psql(f"INSERT INTO legal_hold_vaults (case_id, vault_id, placed_by_username, placed_at) "
         f"VALUES ('{case_id}', '{vault_id}', '{admin_creds['username']}', now())")
    psql("INSERT INTO held_files (id, vault_id, storage_path, size_bytes, kept_at, kept_reason) VALUES "
         f"('{file_id}', '{vault_id}', '{vault_id}/{file_id}.enc', 4096, now(), 'deleted')")
    try:
        yield file_id
    finally:
        psql(f"DELETE FROM held_files WHERE id = '{file_id}'")
        psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE case_id = '{case_id}'")
        psql(f"DELETE FROM compliance_cases WHERE id = '{case_id}'")
        in_api_container("from app.core import legal_hold_marker\nlegal_hold_marker.check_at_start()\n")


def test_the_storage_panel_says_what_is_kept_for_cases(page: Page, admin_creds, kept_row):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    files = int(psql("SELECT count(*) FROM held_files"))
    assert files >= 1
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="storage"]')
    line = page.locator("#storage-stat-kept")
    expect(line).to_be_visible(timeout=10000)
    expect(line).to_contain_text(f"Kept for cases: {files} file" + ("" if files == 1 else "s"))
    expect(line).to_contain_text("counted in the deployment's storage limit, in no vault's size")
    # The line sits right after the allocated figure it qualifies.
    assert page.evaluate("() => document.getElementById('storage-stat-allocated').nextElementSibling.id") == \
        "storage-stat-kept"
    assert errors == []
