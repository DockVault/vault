"""Regression lock: cross-tenant access to the vault file-plane must be 403, never 500.

The finding was that authorization on these routes rested on an implicit exception path, so a
non-member got an HTTP 500 rather than a clean 403. It is already remediated: every route resolves
the vault through VaultService.get_vault() -> require_vault_permission, which raises an audited
PermissionDeniedError for a non-member, mapped to 403 by both a per-route `except PermissionDeniedError`
and a global AuthorizationError handler. This test pins 403-not-500 so a future refactor that removed
either mapping (regressing a stranger back to 500) fails loudly. No live data ever leaked; this guards
the status contract, which is the load-bearing signal that authz is explicit.
"""
import uuid


def test_cross_tenant_file_plane_is_403_not_500(admin, temp_user, temp_user_client):
    v = admin.create_vault()            # passwordless standard vault; temp_user is not a member
    vid = v["id"]
    fake = uuid.uuid4()                 # a UUID path param; authz denies before any file lookup
    try:
        checks = [
            ("PATCH /vaults/{id}",            temp_user_client.patch(f"/vaults/{vid}", json={"description": "x"})),
            ("GET /vaults/{id}/files",        temp_user_client.get(f"/vaults/{vid}/files")),
            ("GET .../files/{id}/download",   temp_user_client.get(f"/vaults/{vid}/files/{fake}/download")),
            ("POST .../files/{id}/delete",    temp_user_client.post(f"/vaults/{vid}/files/{fake}/delete")),
            ("PUT /vaults/{id}/password",     temp_user_client.put(f"/vaults/{vid}/password", json={"new_password": "x"})),
        ]
        for label, r in checks:
            # 403 exactly — not 500 (the finding), and not 200 (would be a real cross-tenant breach).
            assert r.status_code == 403, f"{label}: expected 403, got {r.status_code}: {r.text}"
    finally:
        admin.delete_vault(vid)
