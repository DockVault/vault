"""Endpoint-permission groups and per-user grants/revokes."""

import os
import subprocess
import uuid

from conftest import ApiClient, unique, create_zk_vault


_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _db(sql):
    result = subprocess.run(
        [
            "docker", "exec", _DB_CONTAINER,
            "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _granted(admin, user_id):
    response = admin.get(f"/permissions/users/{user_id}")
    assert response.status_code == 200, response.text
    return set(response.json()["granted_groups"])


def test_list_permission_groups_is_exactly_the_grantable_surface(admin):
    response = admin.get("/permissions/groups")
    assert response.status_code == 200
    groups = response.json()
    names = {group["name"] for group in groups}
    assert "AUDIT_VIEW" in names
    assert "DASHBOARD_VIEW" in names
    assert "USER_MANAGE" in names
    assert "VAULT_PERMISSIONS" in names
    assert names.isdisjoint({"SYSTEM_HEALTH", "AUTH_LOGIN"})


def test_non_admin_cannot_list_groups(temp_user_client):
    assert temp_user_client.get("/permissions/groups").status_code == 403


def test_get_user_permissions(admin, temp_user):
    response = admin.get(f"/permissions/users/{temp_user['id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == temp_user["id"]
    assert "granted_groups" in body
    assert "permissions" in body


def test_grant_adds_transitive_dependencies_and_revoke_cascades(admin, temp_user):
    user_id = temp_user["id"]
    revoked = admin.delete(f"/permissions/users/{user_id}/revoke/VAULT_VIEW")
    assert revoked.status_code == 200, revoked.text

    granted = admin.post(
        f"/permissions/users/{user_id}/grant",
        json={"endpoint_group": "FILE_DOWNLOAD"},
    )
    assert granted.status_code == 200, granted.text
    assert granted.json()["granted_groups"] == [
        "VAULT_VIEW", "FILE_VIEW", "FILE_DOWNLOAD",
    ]
    assert {"VAULT_VIEW", "FILE_VIEW", "FILE_DOWNLOAD"} <= _granted(admin, user_id)

    cascaded = admin.delete(f"/permissions/users/{user_id}/revoke/FILE_VIEW")
    assert cascaded.status_code == 200, cascaded.text
    assert {
        "FILE_VIEW", "FILE_DOWNLOAD", "FILE_UPLOAD", "FILE_DELETE", "FOLDER_MANAGE",
    } <= set(cascaded.json()["revoked_groups"])
    assert {
        "FILE_VIEW", "FILE_DOWNLOAD", "FILE_UPLOAD", "FILE_DELETE", "FOLDER_MANAGE",
    }.isdisjoint(_granted(admin, user_id))


def test_vault_permission_grant_cannot_escalate_to_user_directory(admin, temp_user):
    user_id = temp_user["id"]
    assert admin.delete(
        f"/permissions/users/{user_id}/revoke/VAULT_VIEW"
    ).status_code == 200
    assert admin.delete(
        f"/permissions/users/{user_id}/revoke/USER_VIEW"
    ).status_code == 200

    response = admin.post(
        f"/permissions/users/{user_id}/grant",
        json={"endpoint_group": "VAULT_PERMISSIONS"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["granted_groups"] == ["VAULT_VIEW", "VAULT_PERMISSIONS"]
    groups = _granted(admin, user_id)
    assert {"VAULT_VIEW", "VAULT_PERMISSIONS"} <= groups
    assert "USER_VIEW" not in groups


def test_runtime_gate_fails_closed_when_legacy_row_lacks_dependencies(
    admin, temp_user, temp_user_client
):
    user_id = temp_user["id"]
    vault = temp_user_client.create_vault()
    try:
        assert admin.delete(
            f"/permissions/users/{user_id}/revoke/VAULT_VIEW"
        ).status_code == 200
        _db(
            "INSERT INTO user_endpoint_permissions "
            "(id,user_id,endpoint_group,granted_at) VALUES "
            f"('{uuid.uuid4()}','{user_id}','FILE_DOWNLOAD',now())"
        )

        file_id = uuid.uuid4()
        path = f"/vaults/{vault['id']}/files/{file_id}/download"
        assert temp_user_client.get(path).status_code == 403

        repaired = admin.post(
            f"/permissions/users/{user_id}/grant",
            json={"endpoint_group": "FILE_DOWNLOAD"},
        )
        assert repaired.status_code == 200, repaired.text
        assert temp_user_client.get(path).status_code == 404
    finally:
        admin.delete_vault(vault["id"])


def test_non_grantable_and_unknown_groups_are_rejected(admin, temp_user):
    for group in ("SYSTEM_HEALTH", "AUTH_LOGIN", "NOT_A_REAL_GROUP"):
        response = admin.post(
            f"/permissions/users/{temp_user['id']}/grant",
            json={"endpoint_group": group},
        )
        assert response.status_code == 400


def test_non_admin_cannot_grant(temp_user_client, temp_user):
    response = temp_user_client.post(
        f"/permissions/users/{temp_user['id']}/grant",
        json={"endpoint_group": "VAULT_VIEW"},
    )
    assert response.status_code == 403


def test_user_can_view_own_permissions(temp_user_client, temp_user):
    response = temp_user_client.get(f"/permissions/users/{temp_user['id']}")
    assert response.status_code == 200


def test_dashboard_toggle_is_a_real_runtime_guard(admin, temp_user, temp_user_client):
    user_id = temp_user["id"]
    assert admin.delete(
        f"/permissions/users/{user_id}/revoke/DASHBOARD_VIEW"
    ).status_code == 200
    assert temp_user_client.get("/api/dashboard/stats").status_code == 403

    granted = admin.post(
        f"/permissions/users/{user_id}/grant",
        json={"endpoint_group": "DASHBOARD_VIEW"},
    )
    assert granted.status_code == 200, granted.text
    assert temp_user_client.get("/api/dashboard/stats").status_code == 200


def test_audit_permission_exists_and_controls_own_activity(admin, temp_user, temp_user_client):
    user_id = temp_user["id"]
    assert temp_user_client.get(
        f"/api/user-management/users/{user_id}/activity"
    ).status_code == 200
    assert admin.delete(
        f"/permissions/users/{user_id}/revoke/AUDIT_VIEW"
    ).status_code == 200
    assert temp_user_client.get(
        f"/api/user-management/users/{user_id}/activity"
    ).status_code == 403


def test_temp_admin_cannot_use_permission_admin_surface(admin, temp_user):
    created = admin.post(
        "/auth/temp-credentials",
        json={"note": unique("permission-temp-admin")},
    )
    assert created.status_code == 200, created.text
    credential = created.json()
    temp_admin = ApiClient()
    try:
        temp_admin.login(credential["temp_username"], credential["credential"])
        assert temp_admin.get("/permissions/groups").status_code == 403
        assert temp_admin.post(
            f"/permissions/users/{temp_user['id']}/grant",
            json={"endpoint_group": "VAULT_VIEW"},
        ).status_code == 403
    finally:
        admin.post(f"/temp-creds/{credential['temp_username']}/delete")


def test_permission_change_rolls_back_when_audit_insert_fails(admin, temp_user):
    user_id = temp_user["id"]
    install_failure = """
        CREATE OR REPLACE FUNCTION test_permission_audit_failure()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.action IN ('GRANT_PERMISSION', 'REVOKE_PERMISSION') THEN
                RAISE EXCEPTION 'injected permission audit failure';
            END IF;
            RETURN NEW;
        END;
        $$;
        DROP TRIGGER IF EXISTS test_permission_audit_failure ON audit_logs;
        CREATE TRIGGER test_permission_audit_failure
        BEFORE INSERT ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION test_permission_audit_failure();
    """
    remove_failure = """
        DROP TRIGGER IF EXISTS test_permission_audit_failure ON audit_logs;
        DROP FUNCTION IF EXISTS test_permission_audit_failure();
    """

    # Use a dependency-free group so the rollback assertion is exact.
    initial = admin.delete(
        f"/permissions/users/{user_id}/revoke/DASHBOARD_VIEW"
    )
    assert initial.status_code == 200, initial.text
    assert "DASHBOARD_VIEW" not in _granted(admin, user_id)

    try:
        _db(install_failure)
        failed_grant = admin.post(
            f"/permissions/users/{user_id}/grant",
            json={"endpoint_group": "DASHBOARD_VIEW"},
        )
        assert failed_grant.status_code == 500, failed_grant.text
        assert "DASHBOARD_VIEW" not in _granted(admin, user_id)

        _db(remove_failure)
        granted = admin.post(
            f"/permissions/users/{user_id}/grant",
            json={"endpoint_group": "DASHBOARD_VIEW"},
        )
        assert granted.status_code == 200, granted.text
        assert "DASHBOARD_VIEW" in _granted(admin, user_id)

        _db(install_failure)
        failed_revoke = admin.delete(
            f"/permissions/users/{user_id}/revoke/DASHBOARD_VIEW"
        )
        assert failed_revoke.status_code == 500, failed_revoke.text
        assert "DASHBOARD_VIEW" in _granted(admin, user_id)
    finally:
        _db(remove_failure)


def test_zk_permissions_report_member_encryption_key_status(admin):
    """A4: GET /vaults/{id}/permissions surfaces each ZK member's encryption-key status so the UI can
    flag 'Pending encryption key setup'. Also pins A2's server premise — a KEYLESS member CAN be
    granted a zero-knowledge vault via POST /vaults/{id}/permissions (the authz row is created without
    a wrapped key; the key follows once they set one up)."""
    from conftest import ensure_ecc_keypair
    zk_before = admin.get("/settings").json().get("zero_knowledge_enabled")
    admin.put("/settings", json={"zero_knowledge_enabled": True})  # create_zk_vault needs it enabled
    vz = create_zk_vault(admin)                   # owner (admin) already holds an encryption keypair
    keyless = admin.create_user(role="user")      # a fresh account has no ECC keypair
    keyed = admin.create_user(role="user")
    keyed_client = ApiClient()
    keyed_client.login(keyed["_username"], keyed["_password"])
    ensure_ecc_keypair(keyed_client)              # this member has a keypair (no wrapped DEK needed)
    try:
        # A2 server premise: granting a KEYLESS user a ZK vault succeeds (authz row, no key).
        g1 = admin.post(f"/vaults/{vz['id']}/permissions",
                        json={"user_id": keyless["id"], "level": "read"})
        assert g1.status_code in (200, 201), g1.text
        g2 = admin.post(f"/vaults/{vz['id']}/permissions",
                        json={"user_id": keyed["id"], "level": "read"})
        assert g2.status_code in (200, 201), g2.text

        rows = admin.get(f"/vaults/{vz['id']}/permissions").json()
        by_id = {str(r["user_id"]): r for r in rows}
        km = by_id[str(keyless["id"])]
        assert km["pending_key_setup"] is True and km["has_encryption_key"] is False, km
        ky = by_id[str(keyed["id"])]
        assert ky["pending_key_setup"] is False and ky["has_encryption_key"] is True, ky
    finally:
        admin.delete_user(keyless["id"])
        admin.delete_user(keyed["id"])
        admin.post(f"/vaults/{vz['id']}/delete")
        admin.put("/settings", json={"zero_knowledge_enabled": bool(zk_before)})


def test_standard_vault_permissions_have_null_key_status(admin):
    """A4: a standard (non-ZK) vault reports has_encryption_key=null / pending_key_setup=false — the
    key-status flag is not applicable when there are no per-member encryption keys."""
    v = admin.create_vault()
    member = admin.create_user(role="user")
    try:
        g = admin.post(f"/vaults/{v['id']}/permissions",
                       json={"user_id": member["id"], "level": "read"})
        assert g.status_code in (200, 201), g.text
        rows = admin.get(f"/vaults/{v['id']}/permissions").json()
        km = next(r for r in rows if str(r["user_id"]) == str(member["id"]))
        assert km["has_encryption_key"] is None
        assert km["pending_key_setup"] is False
    finally:
        admin.delete_user(member["id"])
        admin.post(f"/vaults/{v['id']}/delete")
