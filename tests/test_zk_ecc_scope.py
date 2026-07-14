"""Temp-credential scope is enforced on the /ecc zero-knowledge key mutators.

A scoped temporary credential (even one minted from an admin) must not be able to drive ZK key
mutations on a vault it lacks the `vault.change_permissions` capability for — the /ecc plane must
honour the same per-vault scope as the standard permission-edit routes. The hardened auth already
ATTACHES the scope to the principal; here we prove the mutators CHECK it.
"""
import contextlib
import uuid

from conftest import create_zk_vault, ZK_WRAPPED_DEK_STUB, ZK_EPHEMERAL_STUB


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _scoped_client(admin, caps, vault_id):
    """A temp credential in selected-vault mode granted `caps` on `vault_id` only."""
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": caps}],
    }).json()
    c = admin.clone_anonymous()
    c.login(body["temp_username"], body["credential"])
    return c


def test_ecc_mutators_enforce_temp_credential_scope(admin):
    with _zk_enabled(admin):
        vz = create_zk_vault(admin)
    vid = vz["id"]
    try:
        uid = str(uuid.uuid4())

        # Out-of-scope: granted the vault but WITHOUT vault.change_permissions.
        ro = _scoped_client(admin, ["vault.see_info", "vault.see_files"], vid)
        assert ro.delete(f"/ecc/vaults/{vid}/members/{uid}").status_code == 403
        assert ro.post(f"/ecc/vaults/{vid}/members",
                       json={"user_id": uid, "wrapped_dek": "x", "ephemeral_public_key": "y"}).status_code == 403
        assert ro.post(f"/ecc/vaults/{vid}/rekey",
                       json={"from_version": 1, "to_version": 2, "member_keys": []}).status_code == 403
        assert ro.post(f"/ecc/vaults/{vid}/retire-version").status_code == 403

        # In-scope: same vault WITH vault.change_permissions -> the scope gate passes (retire is a
        # safe no-op on an empty vault). Isolates the capability as the deciding factor.
        mgr = _scoped_client(admin, ["vault.see_info", "vault.see_files", "vault.change_permissions"], vid)
        assert mgr.post(f"/ecc/vaults/{vid}/retire-version").status_code == 200

        # And an unrestricted admin can still rotate the key end-to-end (in-scope manager -> 200).
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]),
                             "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}],
        })
        assert r.status_code == 200, r.text
    finally:
        admin.delete_vault(vid)


def test_ecc_reads_confined_to_scoped_vaults(admin):
    """A scoped temp cred confined to vault A must not read vault B's wrapped DEK or member
    roster via /ecc, even though its creator (admin) owns B — parity with GET /vaults/{B}."""
    with _zk_enabled(admin):
        va = create_zk_vault(admin)   # granted to the cred
        vb = create_zk_vault(admin)   # NOT granted; admin (the creator) owns it
    vida, vidb = va["id"], vb["id"]
    try:
        # see_permissions is required to read the member roster (see the read-capability test below).
        cred = _scoped_client(admin, ["vault.see_info", "vault.see_files", "vault.see_permissions"], vida)
        # In-scope vault A: the cred can still read its own DEK + roster.
        assert cred.get(f"/ecc/vaults/{vida}/keys").status_code == 200
        assert cred.get(f"/ecc/vaults/{vida}/member-keys").status_code == 200
        # Out-of-scope vault B: confined (403), matching the standard read path.
        assert cred.get(f"/ecc/vaults/{vidb}/keys").status_code == 403
        assert cred.get(f"/ecc/vaults/{vidb}/member-keys").status_code == 403
        assert cred.get(f"/vaults/{vidb}").status_code in (403, 404)   # parity
    finally:
        admin.delete_vault(vida)
        admin.delete_vault(vidb)


def test_ecc_reads_require_view_capability(admin):
    """A scoped temp cred needs the view capability, not just vault membership: reading the wrapped
    DEK needs vault.see_files, the member roster needs vault.see_permissions (or change_permissions),
    and the cross-account public-key lookup needs a permissions-management cap so it isn't a
    has-a-keypair enumeration oracle any scoped credential could sweep."""
    with _zk_enabled(admin):
        vz = create_zk_vault(admin)
    vid = vz["id"]
    try:
        target = str(uuid.uuid4())

        # Granted the vault but with NO capabilities: membership alone must not unlock the reads.
        nocaps = _scoped_client(admin, [], vid)
        assert nocaps.get(f"/ecc/vaults/{vid}/keys").status_code == 403          # needs see_files
        assert nocaps.get(f"/ecc/vaults/{vid}/member-keys").status_code == 403   # needs see_permissions
        assert nocaps.get(f"/ecc/users/{target}/public-key").status_code == 403  # not a sharer

        # see_files unlocks the DEK read but NOT the roster (a permission surface).
        rf = _scoped_client(admin, ["vault.see_info", "vault.see_files"], vid)
        assert rf.get(f"/ecc/vaults/{vid}/keys").status_code == 200
        assert rf.get(f"/ecc/vaults/{vid}/member-keys").status_code == 403

        # change_permissions makes the cred a legitimate sharer -> the public-key lookup is allowed,
        # AND it may read the wrapped DEK: the ZK add-member SHARE flow reads /keys to re-wrap the DEK
        # for a recipient, so a manage-permissions cred (even without see_files) must be able to.
        mgr = _scoped_client(admin, ["vault.see_info", "vault.change_permissions"], vid)
        assert mgr.get(f"/ecc/users/{target}/public-key").status_code == 200
        assert mgr.get(f"/ecc/vaults/{vid}/keys").status_code == 200
    finally:
        admin.delete_vault(vid)


def test_ecc_public_key_scope_all_mode(admin):
    """has_scoped_vault_cap's 'all' vault-access-mode branch: an all-mode scoped cred is a sharer
    (may look up a public key) only if change_permissions is in its default caps."""
    with _zk_enabled(admin):
        vz = create_zk_vault(admin)
    vid = vz["id"]
    try:
        target = str(uuid.uuid4())

        def _all_mode(caps):
            scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
                     "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
            body = admin.post("/auth/temp-credentials", json={
                "validity_minutes": 60, "scope": scope, "vault_access_mode": "all",
            }).json()
            c = admin.clone_anonymous()
            c.login(body["temp_username"], body["credential"])
            return c

        # all-mode WITHOUT change_permissions -> not a sharer -> 403 on the public-key oracle.
        assert _all_mode(["vault.see_files"]).get(f"/ecc/users/{target}/public-key").status_code == 403
        # all-mode WITH change_permissions -> sharer -> 200.
        assert _all_mode(["vault.change_permissions"]).get(f"/ecc/users/{target}/public-key").status_code == 200
    finally:
        admin.delete_vault(vid)
