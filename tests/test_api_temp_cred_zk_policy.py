"""ZK-vault-in-temp-credential admin policy (temp_cred_allow_zk_vaults).

Under DENY, a zero-knowledge vault may not be in a temp credential's scope: the scoped mint paths
(self-service + delegated child) reject it 400 server-side, and the admin-for-user unrestricted mint
is refused when the target owns any ZK vault. Under ALLOW (default) behavior is unchanged. Exercised
via a normal admin account and a delegated temp-credential session.
"""
import os
import subprocess
import uuid

import pytest

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _psql(sql):
    subprocess.run(["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _zk_vault(admin):
    """A vault flipped to zero_knowledge in the DB (real ZK creation needs client crypto)."""
    v = admin.create_vault(name=_u("zk"))
    _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{v['id']}';")
    return v["id"]


def _deny(admin):
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": False})


def _allow(admin):
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": True})


def _mint_scoped(client, vault_ids):
    caps = ["vault.see_info"]
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
    return client.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vid, "caps": caps} for vid in vault_ids]})


@pytest.fixture
def restore_zk_policy(admin):
    before = admin.get("/settings").json()
    yield
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": bool(before.get("temp_cred_allow_zk_vaults", True))})


# --- scoped self-service mint --------------------------------------------------------------------

def test_deny_rejects_zk_in_scope_self_service(admin, restore_zk_policy):
    _deny(admin)
    vid = _zk_vault(admin)
    try:
        r = _mint_scoped(admin, [vid])
        assert r.status_code == 400 and "zero-knowledge" in r.text.lower(), r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_allow_default_permits_zk_in_scope(admin, restore_zk_policy):
    _allow(admin)
    vid = _zk_vault(admin)
    try:
        r = _mint_scoped(admin, [vid])
        assert r.status_code == 200, r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


# --- unrestricted + all-vaults mints also reach ZK, so the deny must cover them -----------------

def _mint_unscoped(client):
    return client.post("/auth/temp-credentials", json={"validity_minutes": 60})


def _mint_all(client):
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info"], "temp": {}}
    return client.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all"})


def test_deny_rejects_unscoped_mint_when_owner_has_zk(admin, restore_zk_policy):
    _deny(admin)
    vid = _zk_vault(admin)
    try:
        r = _mint_unscoped(admin)  # unrestricted whole-account cred reaches ZK -> rejected under deny
        assert r.status_code == 400 and "zero-knowledge" in r.text.lower(), r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_deny_rejects_all_vaults_mint_when_owner_has_zk(admin, restore_zk_policy):
    _deny(admin)
    vid = _zk_vault(admin)
    try:
        r = _mint_all(admin)  # 'all vaults' reaches ZK -> rejected under deny
        assert r.status_code == 400 and "zero-knowledge" in r.text.lower(), r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_deny_permits_unscoped_mint_when_owner_has_no_zk(admin, restore_zk_policy):
    """Deny must not over-block: a normal account with no ZK vault can still mint an unscoped cred."""
    _deny(admin)
    r = _mint_unscoped(admin)  # admin owns no ZK vault here (tests clean up their flipped vaults)
    assert r.status_code == 200, r.text


# --- delegated child (temp session) re-checks the policy at mint ---------------------------------

def test_allow_permits_zk_for_delegated_child(admin, restore_zk_policy):
    _allow(admin)
    vid = _zk_vault(admin)
    try:
        pcaps = ["vault.see_info"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": True}}
        parent = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": pscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]}).json()
        pc = admin.clone_anonymous()
        pc.login(parent["temp_username"], parent["credential"])
        cscope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": pcaps, "temp": {}}
        r = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]})
        assert r.status_code == 200, r.text  # allow -> a delegated child may include a ZK vault
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_deny_rejects_zk_for_delegated_child(admin, restore_zk_policy):
    _allow(admin)  # allow first so the parent can legitimately hold the ZK vault
    vid = _zk_vault(admin)
    try:
        pcaps = ["vault.see_info"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": True}}
        parent = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": pscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]}).json()
        pc = admin.clone_anonymous()
        pc.login(parent["temp_username"], parent["credential"])
        _deny(admin)  # now deny; the child mint must re-check and reject
        cscope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": pcaps, "temp": {}}
        r = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]})
        assert r.status_code == 400 and "zero-knowledge" in r.text.lower(), r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


# --- admin-for-user unrestricted mint: blocked when the target owns a ZK vault under deny ---------

def _admin_for_user(admin, user_id):
    # the endpoint's body model requires user_id (in addition to the path param) + validity_minutes
    return admin.post(f"/api/user-management/users/{user_id}/temp-credentials",
                      json={"user_id": str(user_id), "validity_minutes": 60})


def test_admin_for_user_blocked_when_target_owns_zk_under_deny(admin, restore_zk_policy):
    me = admin.get("/users/me").json()["id"]
    _deny(admin)
    vid = _zk_vault(admin)  # owned by admin (the target here)
    try:
        r = _admin_for_user(admin, me)
        assert r.status_code == 400 and "zero-knowledge" in r.text.lower(), r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_admin_for_user_allowed_when_target_owns_no_zk_under_deny(admin, temp_user, restore_zk_policy):
    _deny(admin)
    r = _admin_for_user(admin, temp_user["id"])  # temp_user owns no vaults
    assert r.status_code == 200, r.text


def test_admin_for_user_allowed_when_policy_allows(admin, restore_zk_policy):
    me = admin.get("/users/me").json()["id"]
    _allow(admin)
    vid = _zk_vault(admin)
    try:
        r = _admin_for_user(admin, me)  # allow policy -> unchanged even though the target owns a ZK vault
        assert r.status_code == 200, r.text
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)
