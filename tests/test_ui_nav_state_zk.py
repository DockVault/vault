"""A zero-knowledge vault's folder names must never be written to sessionStorage.

`state.currentPath` holds each breadcrumb entry's CLIENT-DECRYPTED folder name, and saveNavState
persists the path to sessionStorage['dv_nav'] so a reload restores the folder. For a ZK vault that
plaintext would land on disk, defeating the vault's promise (the server never sees these names).
The persisted path now drops the labels for a ZK vault -- the ids still restore the folder and drive
the clickable breadcrumb. A standard vault, whose names are already server-known, keeps them.

Driven directly through the real saveNavState / navPathForStorage in a live browser (no folder
navigation or crypto flow), so it is deterministic rather than a flaky end-to-end ZK dance.
"""
import json

import pytest
from playwright.sync_api import Page

pytestmark = pytest.mark.ui

_SECRET_A = "top-secret-folder-name"
_SECRET_B = "another-confidential-folder"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    page.wait_for_selector("#dashboard-screen", timeout=15000)


def _save_nav(page: Page, vault_type: str) -> dict:
    """Set a synthetic in-folder state on the given vault type, run the real saveNavState, and
    return the parsed dv_nav that was persisted."""
    return page.evaluate(
        """(args) => {
            const [vaultType, a, b] = args;
            if (typeof state === 'undefined' || typeof saveNavState !== 'function') {
                return {error: 'app globals not reachable'};
            }
            sessionStorage.removeItem('dv_nav');
            state.currentVault = { id: 'v-test', type: vaultType };
            state.currentFolderId = 'f2';
            state.currentPath = [{ id: 'f1', name: a }, { id: 'f2', name: b }];
            saveNavState();
            return JSON.parse(sessionStorage.getItem('dv_nav') || 'null');
        }""",
        [vault_type, _SECRET_A, _SECRET_B],
    )


def test_zero_knowledge_folder_names_are_not_persisted(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    nav = _save_nav(page, "zero_knowledge")
    assert nav and not nav.get("error"), nav
    blob = json.dumps(nav)
    # The folder ids still restore the view...
    assert "f1" in blob and "f2" in blob, nav
    assert nav.get("folderId") == "f2", nav
    # ...but the decrypted names must NOT be on disk.
    assert _SECRET_A not in blob, f"ZK folder name leaked to sessionStorage: {blob}"
    assert _SECRET_B not in blob, f"ZK folder name leaked to sessionStorage: {blob}"
    for entry in nav["path"]:
        assert "name" not in entry or not entry["name"], entry


def test_standard_vault_keeps_its_breadcrumb_labels(page: Page, admin_creds):
    """Standard-vault folder names are already server-known, so the fuller breadcrumb is preserved."""
    _login(page, admin_creds["username"], admin_creds["password"])
    nav = _save_nav(page, "standard")
    assert nav and not nav.get("error"), nav
    blob = json.dumps(nav)
    assert _SECRET_A in blob and _SECRET_B in blob, f"standard breadcrumb labels were dropped: {blob}"


def test_nav_path_helper_strips_only_for_zero_knowledge(page: Page, admin_creds):
    """The pure helper, exercised directly: ZK -> ids only; standard -> unchanged."""
    _login(page, admin_creds["username"], admin_creds["password"])
    result = page.evaluate(
        """() => {
            if (typeof navPathForStorage !== 'function') return {error: 'helper not reachable'};
            const path = [{ id: 'a', name: 'secret' }];
            return { zk: navPathForStorage(path, true), std: navPathForStorage(path, false) };
        }"""
    )
    assert not result.get("error"), result
    assert result["zk"] == [{"id": "a"}], result
    assert result["std"] == [{"id": "a", "name": "secret"}], result
