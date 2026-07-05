"""Abuse-resistance for the /ecc key-management plane: rate-limiting + public-key scoping.

The zero-knowledge key endpoints must not be usable as a brute-force / key-enumeration engine:
keypair registration is throttled per user, and looking up ANOTHER user's public key is limited
to callers who could legitimately share a vault (own/manage one, or admin) so it isn't a
has-a-keypair oracle any authenticated account can sweep.
"""
from conftest import ensure_ecc_keypair, ApiClient


def test_register_public_key_is_rate_limited(admin, temp_user, temp_user_client):
    """A fresh user sending many registrations trips the per-user throttle (429). The invalid
    body 400s each time, but the rate check runs first, so the burst is still counted."""
    codes = []
    for _ in range(25):
        r = temp_user_client.post("/ecc/keys/register", json={"public_key": "not-a-real-key"})
        codes.append(r.status_code)
        if r.status_code == 429:
            break
    assert 429 in codes, f"register was never throttled: {codes}"
    assert codes[0] != 429, "throttled on the very first request"
    assert codes.index(429) >= 10, f"throttled implausibly early: {codes}"


def test_public_key_lookup_scoped_to_managers(admin, temp_user, temp_user_client, temp_vault):
    """Resolving another user's public key is restricted to vault MANAGERS (owner / manage /
    admin). A plain read-only MEMBER is not enough — that manager-vs-member boundary is the
    whole point of the scoping, so it is pinned explicitly."""
    ensure_ecc_keypair(admin)                                        # target holds real key material
    admin_id = admin.user["id"]
    # (1) No vault relationship at all -> 403.
    assert temp_user_client.get(f"/ecc/users/{admin_id}/public-key").status_code == 403
    # (2) A read-only MEMBER (manage_permission False) is still not a sharer -> 403.
    admin.post(f"/vaults/{temp_vault['id']}/permissions",
               json={"user_id": str(temp_user["id"]), "level": "read"}).raise_for_status()
    assert temp_user_client.get(f"/ecc/users/{admin_id}/public-key").status_code == 403
    # (3) A Manager (manage_permission True) is a potential sharer -> allowed, real key returned.
    mgr = admin.create_user(role="user")
    mgr_client = ApiClient()
    mgr_client.login(mgr["_username"], mgr["_password"])
    admin.post(f"/vaults/{temp_vault['id']}/permissions",
               json={"user_id": str(mgr["id"]), "level": "manage"}).raise_for_status()
    try:
        body = mgr_client.get(f"/ecc/users/{admin_id}/public-key")
        assert body.status_code == 200, body.text
        assert body.json().get("has_keypair") is True and body.json().get("public_key")
    finally:
        admin.delete_user(mgr["id"])
    # (4) An admin may always look up.
    assert admin.get(f"/ecc/users/{temp_user['id']}/public-key").status_code == 200
