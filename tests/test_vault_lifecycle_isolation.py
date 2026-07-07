"""Regression tests for vault lifecycle & multi-tenant isolation.

vault deletion is owner-or-admin only — a read-only member must not destroy a
vault. favoriting requires READ access (no cross-tenant existence oracle).
server-side key rotation still works on a standard vault (the ZK guard must not
over-block).
"""


def test_readonly_member_cannot_delete_vault(admin, temp_user, temp_user_client):
    v = admin.create_vault()
    try:
        admin.post(f"/vaults/{v['id']}/permissions", json={"user_id": temp_user["id"], "level": "read"})
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200  # read confirmed
        # the read-only member must NOT be able to delete the whole vault
        assert temp_user_client.post(f"/vaults/{v['id']}/delete").status_code == 403
        # ...and it must still exist
        assert admin.get(f"/vaults/{v['id']}").status_code == 200
    finally:
        admin.delete_vault(v["id"])  # owner/admin CAN delete (also verifies the happy path)


def test_favorite_requires_read_access(admin, temp_user, temp_user_client):
    v = admin.create_vault()  # NOT shared to temp_user
    try:
        # no access -> uniform 404 (was a 200 existence-oracle + unauthorized write)
        assert temp_user_client.put(f"/vaults/{v['id']}/favorite").status_code == 404
        # a non-existent vault returns the same 404, so 200-vs-404 leaks nothing
        assert temp_user_client.put("/vaults/00000000-0000-0000-0000-000000000000/favorite").status_code == 404
        # once granted read, favoriting works (not over-blocked)
        admin.post(f"/vaults/{v['id']}/permissions", json={"user_id": temp_user["id"], "level": "read"})
        assert temp_user_client.put(f"/vaults/{v['id']}/favorite").status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_rotate_key_works_on_standard_vault(admin):
    v = admin.create_vault()
    try:
        assert admin.post(f"/vaults/{v['id']}/rotate-key").status_code == 200
    finally:
        admin.delete_vault(v["id"])
