"""Offboarding: deactivating a user blacklists their zero-knowledge vault keys.

A zero-knowledge vault can only be rekeyed by a client that holds the DEK (the server has none),
so a departing user can't be auto-rekeyed server-side. Instead, deactivating a user immediately
BLACKLISTS their wrapped-DEK rows (server-mediated key retrieval stops at once), and each affected
vault surfaces as 'rekey owed' so a manager can do the manual DEK rotation for forward secrecy.
"""
import contextlib

from conftest import ensure_ecc_keypair, create_zk_vault, ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB, ApiClient

UM = "/api/user-management"


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _grant_direct(admin, vid, target_id, target_client):
    ensure_ecc_keypair(target_client)
    admin.post(f"/ecc/vaults/{vid}/members", json={
        "user_id": str(target_id), "wrapped_dek": ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ZK_EPHEMERAL_STUB,
    }).raise_for_status()
    admin.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(target_id), "level": "read"}).raise_for_status()


def test_deactivation_blacklists_zk_keys_and_flags_rekey_owed(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        _grant_direct(admin, vid, temp_user["id"], temp_user_client)
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False   # nothing owed yet

        # Deactivate the member -> their DEK rows are blacklisted; the vault now owes a rekey.
        r = admin.post(f"{UM}/users/{temp_user['id']}/toggle-active")
        assert r.status_code == 200 and r.json()["is_active"] is False, r.text
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is True

        # Reactivating does NOT restore ZK access — the blacklist persists (needs a manager re-grant).
        assert admin.post(f"{UM}/users/{temp_user['id']}/toggle-active").json()["is_active"] is True
        c2 = ApiClient()
        c2.login(temp_user["_username"], temp_user["_password"])
        assert c2.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False

        # A manager rekey (mints a new epoch) clears the owed flag.
        rk = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]),
                             "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}],
        })
        assert rk.status_code == 200, rk.text
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False
    finally:
        admin.delete_vault(vid)


# NOTE: PUT /api/user-management/users/{id} (update_user) ALSO blacklists on is_active=false, but
# that endpoint currently returns 401 for every request (a pre-existing decorator bug unrelated to
# offboarding — the admin UI deactivates via toggle-active, which is the path exercised above), so
# it has no HTTP test here. The blacklist call is in place for when that endpoint is fixed.


def test_owner_deactivation_does_not_blacklist_owner_key(admin):
    """OWNER CARVE-OUT: deactivating a user who OWNS a ZK vault must NOT blacklist their own
    key — that would brick the vault (a sole owner is the last DEK-holder). Their key survives
    and reactivation restores access; the vault owes no rekey."""
    owner2 = admin.create_user(role="user")
    oc = ApiClient()
    oc.login(owner2["_username"], owner2["_password"])
    with _zk_enabled(admin):
        v = create_zk_vault(oc)   # owner2 is the OWNER of this vault
    vid = v["id"]
    try:
        assert oc.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
        assert admin.post(f"{UM}/users/{owner2['id']}/toggle-active").json()["is_active"] is False
        assert admin.post(f"{UM}/users/{owner2['id']}/toggle-active").json()["is_active"] is True
        oc2 = ApiClient()
        oc2.login(owner2["_username"], owner2["_password"])
        body = oc2.get(f"/ecc/vaults/{vid}/keys").json()
        assert body["has_access"] is True         # owner key survived the deactivation
        assert body["rekey_owed"] is False         # nothing was blacklisted, nothing owed
    finally:
        admin.delete_vault(vid)
        admin.delete_user(owner2["id"])


def test_blacklist_sweeps_all_vaults_and_spares_bystanders(admin, temp_user, temp_user_client):
    """The blacklist is fleet-wide (every vault the departing member holds) but must not touch a
    co-member's key (no over-reach)."""
    bystander = admin.create_user(role="user")
    bc = ApiClient()
    bc.login(bystander["_username"], bystander["_password"])
    with _zk_enabled(admin):
        va = create_zk_vault(admin)
        vb = create_zk_vault(admin)
    vida, vidb = va["id"], vb["id"]
    try:
        _grant_direct(admin, vida, temp_user["id"], temp_user_client)
        _grant_direct(admin, vidb, temp_user["id"], temp_user_client)
        _grant_direct(admin, vida, bystander["id"], bc)   # co-member in vault A only

        admin.post(f"{UM}/users/{temp_user['id']}/toggle-active").raise_for_status()
        # BOTH of the departing member's vaults now owe a rekey.
        assert admin.get(f"/ecc/vaults/{vida}/keys").json()["rekey_owed"] is True
        assert admin.get(f"/ecc/vaults/{vidb}/keys").json()["rekey_owed"] is True
        # The bystander co-member's key is untouched (no over-reach).
        assert bc.get(f"/ecc/vaults/{vida}/keys").json()["has_access"] is True
    finally:
        admin.delete_vault(vida)
        admin.delete_vault(vidb)
        admin.delete_user(bystander["id"])


def test_hierarchical_offboarding_requires_team_rotation(admin, temp_user, temp_user_client):
    """Offboarding a hierarchical (team-mode) member flags rekey owed, and — unlike a direct
    vault — a DEK-only rotation does NOT clear it: a full team-keypair rotation is required."""
    from test_zk_team_key import _create_hier_vault, _grant_team, _routine_rotate, _team_rotate
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False
        admin.post(f"{UM}/users/{temp_user['id']}/toggle-active").raise_for_status()
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is True
        # A cheap DEK-only rotation is refused while a team rotation is owed.
        assert _routine_rotate(admin, vid, 1).status_code == 400
        # A team-keypair rotation clears it.
        assert _team_rotate(admin, vid, 1, None, [admin.user["id"]]).status_code == 200
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False
    finally:
        admin.delete_vault(vid)
