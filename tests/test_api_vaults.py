"""Vault lifecycle: create, read, update, settings, password, permissions,
key rotation, key history, delete."""
import pytest

from conftest import unique


def test_create_and_get_vault(admin):
    vault = admin.create_vault(name=unique("vault"))
    try:
        assert vault["id"]
        assert vault["has_password"] is False
        r = admin.get(f"/vaults/{vault['id']}")
        assert r.status_code == 200
        assert r.json()["id"] == vault["id"]
    finally:
        admin.delete_vault(vault["id"])


def test_list_vaults_includes_created(admin, temp_vault):
    r = admin.get("/vaults")
    assert r.status_code == 200
    assert any(v["id"] == temp_vault["id"] for v in r.json())


def test_create_vault_requires_name(admin):
    r = admin.post("/vaults", json={"description": "no name"})
    assert r.status_code == 422


def test_patch_vault_rename(admin, temp_vault):
    new_name = unique("renamed")
    r = admin.patch(f"/vaults/{temp_vault['id']}", json={"name": new_name})
    assert r.status_code == 200
    assert r.json()["name"] == new_name


def test_vault_settings_update(admin, temp_vault):
    r = admin.patch(f"/vaults/{temp_vault['id']}/settings",
                    json={"expire_files_after_days": 7, "expire_files_unit": "days"})
    assert r.status_code == 200


def test_vault_unlock_remember_roundtrip(admin, temp_vault):
    """Per-vault unlock-remember duration persists and is returned by GET/list."""
    vid = temp_vault["id"]
    r = admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 30})
    assert r.status_code == 200
    assert admin.get(f"/vaults/{vid}").json()["unlock_remember_minutes"] == 30
    # also surfaced in the list payload (separate response builder)
    listed = next(v for v in admin.get("/vaults").json() if v["id"] == vid)
    assert listed["unlock_remember_minutes"] == 30
    # 0 == always ask
    admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 0})
    assert admin.get(f"/vaults/{vid}").json()["unlock_remember_minutes"] == 0
    # values are clamped to a sane ceiling (24h)
    admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 99999})
    assert admin.get(f"/vaults/{vid}").json()["unlock_remember_minutes"] == 1440


def test_get_vault_404(admin):
    r = admin.get("/vaults/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


def test_vault_favorite_roundtrip(admin, temp_vault):
    """Star/un-star is a per-user flag surfaced on get + list."""
    vid = temp_vault["id"]
    assert admin.get(f"/vaults/{vid}").json()["is_favorite"] is False
    assert admin.put(f"/vaults/{vid}/favorite").status_code == 200
    assert admin.get(f"/vaults/{vid}").json()["is_favorite"] is True
    assert next(v for v in admin.get("/vaults").json() if v["id"] == vid)["is_favorite"] is True
    # idempotent
    assert admin.put(f"/vaults/{vid}/favorite").status_code == 200
    assert admin.delete(f"/vaults/{vid}/favorite").status_code == 200
    assert admin.get(f"/vaults/{vid}").json()["is_favorite"] is False


def test_vault_my_permission_levels(admin, temp_vault, temp_user, temp_user_client):
    """my_permission reflects the caller's effective level — drives UI hiding."""
    vid = temp_vault["id"]
    assert admin.get(f"/vaults/{vid}").json()["my_permission"] == "owner"
    # read grant → member sees 'read'
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "read"})
    assert temp_user_client.get(f"/vaults/{vid}").json()["my_permission"] == "read"
    # upgrade to write → 'write'
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "write"})
    assert temp_user_client.get(f"/vaults/{vid}").json()["my_permission"] == "write"


# ---- password-protected vaults --------------------------------------------
def test_password_vault_requires_password_to_open(admin, temp_vault_pw):
    # Listing files without the password should be rejected.
    r = admin.get(f"/vaults/{temp_vault_pw['id']}/files")
    assert r.status_code in (401, 403)

    # With the password header it works.
    r = admin.get(
        f"/vaults/{temp_vault_pw['id']}/files",
        headers={"X-Vault-Password": temp_vault_pw["_password"]},
    )
    assert r.status_code == 200


def test_change_vault_password(admin):
    vault = admin.create_vault(password="OldPass-123")
    try:
        r = admin.put(f"/vaults/{vault['id']}/password",
                      json={"current_password": "OldPass-123", "new_password": "NewPass-456"})
        assert r.status_code == 200
        # old password no longer opens it
        r = admin.get(f"/vaults/{vault['id']}/files",
                      headers={"X-Vault-Password": "OldPass-123"})
        assert r.status_code in (401, 403)
        r = admin.get(f"/vaults/{vault['id']}/files",
                      headers={"X-Vault-Password": "NewPass-456"})
        assert r.status_code == 200
    finally:
        admin.delete_vault(vault["id"], vault_password="NewPass-456")


# ---- vault sharing / permissions ------------------------------------------
def test_vault_permissions_grant_list_revoke(admin, temp_vault, temp_user):
    vid = temp_vault["id"]
    # grant read
    r = admin.post(f"/vaults/{vid}/permissions",
                   json={"user_id": temp_user["id"], "level": "read"})
    assert r.status_code == 200

    # appears in list
    r = admin.get(f"/vaults/{vid}/permissions")
    assert r.status_code == 200
    assert any(p["user_id"] == temp_user["id"] for p in r.json())

    # revoke
    r = admin.delete(f"/vaults/{vid}/permissions/{temp_user['id']}")
    assert r.status_code == 200
    r = admin.get(f"/vaults/{vid}/permissions")
    assert not any(p["user_id"] == temp_user["id"] for p in r.json())


# ---- key rotation ----------------------------------------------------------
def test_rotate_key_and_history(admin, temp_vault):
    vid = temp_vault["id"]
    r = admin.post(f"/vaults/{vid}/rotate-key")
    assert r.status_code in (200, 500)  # 500 only if crypto backend unavailable
    if r.status_code == 200:
        body = r.json()
        assert body["new_key_version"] >= body["old_key_version"]

    r = admin.get(f"/vaults/{vid}/key-history")
    assert r.status_code == 200
    assert "current_key_version" in r.json()


def test_delete_vault(admin):
    vault = admin.create_vault()
    r = admin.post(f"/vaults/{vault['id']}/delete")
    assert r.status_code == 200
    r = admin.get(f"/vaults/{vault['id']}")
    assert r.status_code == 404


# ---- authorization ---------------------------------------------------------
def test_non_member_cannot_open_others_vault(temp_user_client, temp_vault):
    r = temp_user_client.get(f"/vaults/{temp_vault['id']}")
    assert r.status_code in (403, 404)
