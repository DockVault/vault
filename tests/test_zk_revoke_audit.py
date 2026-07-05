"""Legacy /ecc member-key revoke: authorization + owner-guard + audit trail.

``DELETE /ecc/vaults/{id}/members/{user_id}`` deactivates a member's wrapped DEK without
rotating the vault key. It must be gated exactly like a rekey or a plain permission change
(owner / global admin / Manager) — NOT merely "the caller holds a key for the vault" — and it
must never be usable to lock the vault OWNER out of their own vault. Separately, every /ecc key
mutation must now leave an audit row (the plane wrote none before, a forensic blind spot).

Direct (non-hierarchical) zero-knowledge vaults; opaque stub wraps the server never unwraps.
"""
import contextlib

from conftest import (
    ensure_ecc_keypair, create_zk_vault,
    ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB, ApiClient,
)


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _grant_direct(admin, vid, target_id, target_client, level="read"):
    """Give ``target`` a wrapped DEK for a direct ZK vault plus an authz row at ``level``."""
    ensure_ecc_keypair(target_client)
    admin.post(f"/ecc/vaults/{vid}/members", json={
        "user_id": str(target_id),
        "wrapped_dek": ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ZK_EPHEMERAL_STUB,
    }).raise_for_status()
    admin.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(target_id), "level": level}).raise_for_status()


def _has_key(client, vid) -> bool:
    return client.get(f"/ecc/vaults/{vid}/keys").json().get("has_access") is True


# --- revoke authorization + owner-guard --------------------------------------

def test_non_manager_key_holder_cannot_revoke(admin, temp_user, temp_user_client):
    """A plain member who HOLDS a key but is not a Manager gets 403. The previous gate (any
    active-key holder) would have let them deactivate another member's key."""
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    victim = admin.create_user(role="user")
    victim_client = ApiClient()
    victim_client.login(victim["_username"], victim["_password"])
    try:
        _grant_direct(admin, vid, temp_user["id"], temp_user_client)  # non-manager, holds a key
        _grant_direct(admin, vid, victim["id"], victim_client)
        assert _has_key(temp_user_client, vid) is True                # really holds a key
        # A key-holding non-manager must be refused — not because they lack a key, but scope.
        r = temp_user_client.delete(f"/ecc/vaults/{vid}/members/{victim['id']}")
        assert r.status_code == 403, r.text
        assert _has_key(victim_client, vid) is True                   # victim untouched
    finally:
        admin.delete_vault(vid)
        admin.delete_user(victim["id"])


def test_cannot_revoke_vault_owner(admin, temp_user, temp_user_client):
    """A legitimate Manager still cannot revoke the OWNER's key — that would permanently lock
    the vault's guaranteed key-holder out with no self-rescue."""
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        # Make temp_user a real Manager so the 400 is the owner-guard, not an authz failure.
        _grant_direct(admin, vid, temp_user["id"], temp_user_client, level="manage")
        r = temp_user_client.delete(f"/ecc/vaults/{vid}/members/{admin.user['id']}")
        assert r.status_code == 400, r.text
        assert _has_key(admin, vid) is True                            # owner still holds a key
    finally:
        admin.delete_vault(vid)


def test_manager_can_revoke_plain_member(admin, temp_user, temp_user_client):
    """The owner (a Manager) can still revoke a plain member's key -> 200, key deactivated."""
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        _grant_direct(admin, vid, temp_user["id"], temp_user_client)
        assert _has_key(temp_user_client, vid) is True
        r = admin.delete(f"/ecc/vaults/{vid}/members/{temp_user['id']}")
        assert r.status_code == 200, r.text
        assert _has_key(temp_user_client, vid) is False
    finally:
        admin.delete_vault(vid)


def test_cannot_revoke_owner_via_noncanonical_uuid(admin, temp_user, temp_user_client):
    """The owner-guard must fire even when the owner's id is given in a non-canonical form
    (uppercase / hyphen-less). The path is coerced to a UUID, so an uppercase id can't skip
    the guard while the DB still normalizes it and matches the owner's rows."""
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        _grant_direct(admin, vid, temp_user["id"], temp_user_client, level="manage")  # a real Manager
        owner_upper = str(admin.user["id"]).upper()
        assert owner_upper != str(admin.user["id"])                       # genuinely non-canonical
        r = temp_user_client.delete(f"/ecc/vaults/{vid}/members/{owner_upper}")
        assert r.status_code == 400, r.text                              # owner-guard fires, not bypassed
        assert _has_key(admin, vid) is True                              # owner still holds their key
    finally:
        admin.delete_vault(vid)


def test_manager_cannot_revoke_peer_manager(admin, temp_user, temp_user_client):
    """A Manager cannot deactivate a PEER Manager's key (owner/admin-only), matching the
    standard DELETE /vaults/{id}/permissions route. The owner still can."""
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    manager_b = admin.create_user(role="user")
    manager_b_client = ApiClient()
    manager_b_client.login(manager_b["_username"], manager_b["_password"])
    try:
        _grant_direct(admin, vid, temp_user["id"], temp_user_client, level="manage")   # Manager A
        _grant_direct(admin, vid, manager_b["id"], manager_b_client, level="manage")   # Manager B
        # Manager A may not unseat peer Manager B.
        r = temp_user_client.delete(f"/ecc/vaults/{vid}/members/{manager_b['id']}")
        assert r.status_code == 403, r.text
        assert _has_key(manager_b_client, vid) is True                   # B untouched
        # The owner CAN revoke a manager.
        assert admin.delete(f"/ecc/vaults/{vid}/members/{manager_b['id']}").status_code == 200
        assert _has_key(manager_b_client, vid) is False
    finally:
        admin.delete_vault(vid)
        admin.delete_user(manager_b["id"])


# --- audit trail for /ecc mutations ------------------------------------------

def _audit_rows(admin, action, resource_id):
    rows = admin.get("/audit/log", params={"action": action, "limit": 2000}).json()
    return [r for r in rows if r.get("resource_id") == str(resource_id)]


def test_grant_and_revoke_write_audit_rows(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        _grant_direct(admin, vid, temp_user["id"], temp_user_client)
        assert admin.delete(f"/ecc/vaults/{vid}/members/{temp_user['id']}").status_code == 200

        granted = _audit_rows(admin, "zk_member_key_granted", vid)
        assert granted, "grant wrote no audit row"
        assert any((r.get("details") or {}).get("target_user_id") == str(temp_user["id"]) for r in granted)

        revoked = _audit_rows(admin, "zk_member_key_revoked", vid)
        assert revoked, "revoke wrote no audit row"
        assert any((r.get("details") or {}).get("target_user_id") == str(temp_user["id"]) for r in revoked)
    finally:
        admin.delete_vault(vid)


def test_rekey_writes_audit_row(admin):
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        # Direct rekey — the owner is the only member, re-wrap their DEK to the new epoch.
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]),
                             "wrapped_dek": ZK_WRAPPED_DEK_STUB,
                             "ephemeral_public_key": ZK_EPHEMERAL_STUB}],
        })
        assert r.status_code == 200, r.text
        rows = _audit_rows(admin, "zk_vault_rekeyed", vid)
        assert rows, "rekey wrote no audit row"
        assert any((row.get("details") or {}).get("to_version") == 2 for row in rows)
    finally:
        admin.delete_vault(vid)
