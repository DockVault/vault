"""Regression tests for the auth/access-control hardening.

an admin-minted temporary credential keeps role==ADMIN, so before the fix it
could reach admin-plane mutators gated by bare require_admin (grant/revoke, role change,
group/user CRUD, ssh-key management, brand). Every such mutator now sits behind
require_interactive_admin (or an equivalent temp-session gate) and MUST return 403 for a temp
session — while a real interactive admin is unaffected. Also covers (monitoring metrics
admin-only) and (generic login error, no account-state enumeration).
"""
import pytest

from conftest import ApiClient, BASE_URL, unique


@pytest.fixture
def temp_admin_client(admin):
    """A logged-in client backed by an admin-minted NULL-scope temp credential (the default,
    which keeps the admin role and previously bypassed @require_endpoint_permission)."""
    r = admin.post("/auth/temp-credentials", json={"note": "r1-regression"})
    assert r.status_code == 200, r.text
    tc = r.json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    sess = c.get("/auth/session").json()
    assert sess.get("is_temp_session") is True and sess.get("role") == "admin", sess
    return c


def test_temp_admin_cannot_grant_permission(temp_admin_client, temp_user):
    r = temp_admin_client.post(
        f"/permissions/users/{temp_user['id']}/grant", json={"endpoint_group": "USER_MANAGE"}
    )
    assert r.status_code == 403


def test_temp_admin_cannot_change_role_via_user_management(temp_admin_client, temp_user):
    # The require_interactive_admin gate here was a no-op until user_management_api's own
    # get_current_user was taught to set _is_temp_session.
    r = temp_admin_client.patch(
        f"/api/user-management/users/{temp_user['id']}/role", json={"new_role": "admin"}
    )
    assert r.status_code == 403


def test_temp_admin_cannot_create_user(temp_admin_client):
    r = temp_admin_client.post(
        "/users",
        json={
            "username": unique("resc"),
            "email": f"{unique('resc')}@example.com",
            "password": "Passw0rd!23",
            "role": "admin",
        },
    )
    assert r.status_code == 403


def test_temp_admin_cannot_update_or_delete_user(temp_admin_client, temp_user):
    uid = temp_user["id"]
    assert temp_admin_client.patch(f"/users/{uid}", json={"role": "admin"}).status_code == 403
    assert temp_admin_client.put(f"/api/user-management/users/{uid}", json={"role": "admin"}).status_code == 403
    # cross-user password reset must also be denied
    assert temp_admin_client.patch(f"/users/{uid}", json={"password": "N3wPassw0rd!"}).status_code == 403
    assert temp_admin_client.post(f"/users/{uid}/delete").status_code == 403


def test_temp_admin_cannot_toggle_account_state(temp_admin_client, temp_user):
    uid = temp_user["id"]
    assert temp_admin_client.post(f"/api/user-management/users/{uid}/toggle-active").status_code == 403
    assert temp_admin_client.post(f"/api/user-management/users/{uid}/toggle-locked").status_code == 403


def test_temp_admin_cannot_manage_groups(temp_admin_client):
    assert temp_admin_client.post("/groups", json={"name": unique("grp")}).status_code == 403


def test_temp_admin_cannot_plant_ssh_key_on_another_user(temp_admin_client, temp_user):
    r = temp_admin_client.post(
        f"/users/{temp_user['id']}/ssh-keys",
        json={
            "name": "x",
            "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForTestingOnly00000000000000000 x",
        },
    )
    assert r.status_code == 403


def test_temp_admin_cannot_mint_credentials_for_user(temp_admin_client, temp_user):
    r = temp_admin_client.post(
        f"/api/user-management/users/{temp_user['id']}/temp-credentials", json={}
    )
    assert r.status_code == 403


def test_interactive_admin_still_manages(admin):
    # Guard: the require_interactive_admin swaps must NOT block a real interactive admin.
    r = admin.post("/groups", json={"name": unique("grp-ok")})
    assert r.status_code == 200, r.text
    gid = r.json()["id"]
    assert admin.delete(f"/groups/{gid}").status_code == 200


def test_monitoring_metrics_requires_admin(temp_user_client):
    # instance-wide monitoring aggregates must not be readable by a non-admin.
    assert temp_user_client.get("/api/monitoring/metrics").status_code == 403


def test_login_error_is_generic_for_all_failures(anon, admin_creds):
    # no account-state enumeration via the login error body.
    r1 = anon.post("/auth/login", json={"username": unique("nope"), "password": "x"})
    r2 = anon.post("/auth/login", json={"username": admin_creds["username"], "password": "wrong_zzz"})
    assert r1.status_code == 401 and r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"] == "Invalid username or password"


def test_temp_admin_cannot_inspect_upload_sessions(temp_admin_client):
    # deployment-wide upload/disk maintenance is interactive-admin only.
    assert temp_admin_client.get("/api/maintenance/upload-sessions").status_code == 403


def test_temp_admin_cannot_cleanup_upload_sessions(temp_admin_client):
    # a temp cred must not be able to purge every tenant's in-flight uploads.
    r = temp_admin_client.post("/api/maintenance/upload-sessions/cleanup", params={"idle_minutes": 999999})
    assert r.status_code == 403
