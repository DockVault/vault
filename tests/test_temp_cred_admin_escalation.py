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
    assert temp_admin_client.post(f"/users/{uid}/terminate-sessions").status_code == 403


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


# ---------------------------------------------------------------------------
# Admin-only READ + monitoring-integrity routes that were on bare require_admin.
# A temp admin credential keeps role==ADMIN, so it reached the deployment-wide audit
# trail, security dashboards, settings, groups and user list with no scope enforcement.
# These now require an interactive admin and MUST 403 for any temp session (scoped OR
# NULL-scope), while a real interactive admin is unaffected.
# ---------------------------------------------------------------------------
_ADMIN_ONLY_READ_ROUTES = [
    "/audit/events",
    "/audit/log",
    "/audit/export",
    "/api/security/metrics",
    "/api/security/alerts",
    "/dashboard/stats",
    "/settings",
    "/settings/logs",
    "/zk/unsealed",
    "/groups",
    "/users",
    "/permissions/groups",
    "/api/monitoring/metrics",
]


@pytest.mark.parametrize("path", _ADMIN_ONLY_READ_ROUTES)
def test_temp_admin_denied_admin_only_read_routes(temp_admin_client, path):
    r = temp_admin_client.get(path)
    assert r.status_code == 403, f"GET {path} -> {r.status_code} (expected 403)\n{r.text[:300]}"


def test_temp_admin_cannot_resolve_security_alert(temp_admin_client):
    # a monitoring-integrity WRITE (suppress a security alert) must not be reachable by a temp cred.
    r = temp_admin_client.post("/api/security/alerts/00000000-0000-0000-0000-000000000000/resolve")
    assert r.status_code == 403


def test_temp_admin_cannot_send_test_email(temp_admin_client):
    # a temp credential must not be able to trigger outbound mail via the admin test-email endpoint.
    r = temp_admin_client.post("/settings/test-email")
    assert r.status_code == 403


def test_temp_admin_cannot_read_user_activity(temp_admin_client, temp_user):
    r = temp_admin_client.get(f"/api/security/user-activity/{temp_user['id']}")
    assert r.status_code == 403


@pytest.fixture
def scoped_temp_admin_client(admin):
    """An admin-minted SCOPED temp credential (vaults page only). It carries role==ADMIN but a
    non-null scope; it must be 403 on every admin-plane route just like the NULL-scope one."""
    r = admin.post("/auth/temp-credentials", json={
        "note": unique("r3-scoped"),
        "scope": {"pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_files"]},
        "vault_access_mode": "all",
    })
    assert r.status_code == 200, r.text
    tc = r.json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    sess = c.get("/auth/session").json()
    assert sess.get("is_temp_session") is True and sess.get("is_scoped_temp") is True, sess
    return c


def test_scoped_temp_admin_denied_audit_and_security(scoped_temp_admin_client):
    assert scoped_temp_admin_client.get("/audit/export").status_code == 403
    assert scoped_temp_admin_client.get("/api/security/alerts").status_code == 403
    assert scoped_temp_admin_client.get("/users").status_code == 403


def test_temp_admin_denied_user_directory_and_audit_reads(temp_admin_client, temp_user):
    # A NULL-scope temp admin must ALSO be denied the admin READ surfaces reachable via
    # @require_endpoint_permission(USER_VIEW/AUDIT_VIEW) — the __deny__ gate now applies to legacy
    # (unscoped) temp creds too — plus the un-decorated own-or-admin per-user permission read.
    uid = temp_user["id"]
    for path in [
        "/api/user-management/users",
        f"/api/user-management/users/{uid}",
        "/api/user-management/metrics",
        f"/api/user-management/users/{uid}/activity",
        f"/users/{uid}",                    # api_server GET /users/{id}
        f"/permissions/users/{uid}",        # per-user permission read (another user)
    ]:
        r = temp_admin_client.get(path)
        assert r.status_code == 403, f"GET {path} -> {r.status_code} (expected 403)\n{r.text[:200]}"


def test_temp_admin_denied_active_connections(temp_admin_client):
    # The parallel /api/dashboard router must not expose deployment-wide data to a temp cred.
    assert temp_admin_client.get("/api/dashboard/active-connections").status_code == 403


def test_deactivated_temp_cred_is_401_on_dashboard(admin):
    # A deactivated temp credential must not keep reading /api/dashboard/* — the dashboard router now
    # shares the hardened auth dependency (which rejects a revoked/deactivated temp session), instead
    # of a drifted copy that only checked the token denylist.
    tc = admin.post("/auth/temp-credentials", json={"note": unique("r4-deact")}).json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    # Active: the temp cred can read its own dashboard.
    assert c.get("/api/dashboard/stats").status_code in (200, 304)
    # Deactivate it (revokes the active session).
    assert admin.post(f"/temp-creds/{tc['temp_username']}/deactivate").status_code == 200
    # Now every /api/dashboard/* read is 401 (auth fails before any role/scope check).
    assert c.get("/api/dashboard/stats").status_code == 401
    assert c.get("/api/dashboard/recent-events").status_code == 401
    assert c.get("/api/dashboard/active-connections").status_code == 401


def test_temp_admin_dashboard_stats_is_own_scoped(temp_admin_client):
    # A temp cred's /api/dashboard/stats must be OWN-scoped: the deployment-wide admin branch uniquely
    # sets 'users' and 'active_sessions', so those keys must be absent for a temp credential.
    r = temp_admin_client.get("/api/dashboard/stats")
    assert r.status_code in (200, 304), r.text
    if r.status_code == 200:
        data = r.json()
        assert "users" not in data and "active_sessions" not in data, f"temp cred got deployment-wide stats: {data}"


def test_temp_admin_recent_events_excludes_other_users(admin, temp_admin_client, temp_user):
    # /api/dashboard/recent-events must be OWN-scoped for a temp cred (whose principal is the owning
    # admin) — it must NOT return the full deployment audit trail. Trigger an event owned by ANOTHER
    # user and confirm the interactive admin sees it while the temp admin does not.
    ApiClient().login(temp_user["_username"], temp_user["_password"])  # a login audit event for temp_user
    all_ev = admin.get("/api/dashboard/recent-events?limit=100").json()
    own_ev = temp_admin_client.get("/api/dashboard/recent-events?limit=100").json()
    all_usernames = {e.get("username") for e in all_ev}
    own_usernames = {e.get("username") for e in own_ev}
    assert temp_user["_username"] in all_usernames, "a real admin should see the other user's event"
    assert temp_user["_username"] not in own_usernames, "a temp admin must NOT see another user's audit events"


def test_interactive_admin_still_reads_admin_routes(admin):
    # Guard: the require_interactive_admin swaps must NOT block a real interactive admin.
    assert admin.get("/dashboard/stats").status_code == 200
    assert admin.get("/api/security/alerts").status_code == 200
    assert admin.get("/groups").status_code == 200


def test_null_scope_temp_cred_confined_to_own_subtree(admin, temp_admin_client):
    # A NULL-scope (legacy) temp credential keeps role==ADMIN, but must be confined to its OWN
    # subtree: it must not see or manage temp credentials it did not create (owner decision to
    # confine the legacy "NULL scope = unrestricted" contract). Uses the admin as a control: the
    # real interactive admin still sees/manages the sibling; the NULL-scope temp cred does not.
    sibling = admin.post("/auth/temp-credentials", json={"note": unique("sibling")}).json()
    try:
        # Control: the real admin sees the sibling in the deployment-wide list.
        admin_usernames = {c["temp_username"] for c in admin.get("/temp-creds/list").json()}
        assert sibling["temp_username"] in admin_usernames, "admin should see the sibling (control)"

        # READ confinement: the NULL-scope temp admin must NOT see a credential it didn't create.
        listed = temp_admin_client.get("/temp-creds/list")
        assert listed.status_code in (200, 304), listed.text
        temp_usernames = {c["temp_username"] for c in listed.json()}
        assert sibling["temp_username"] not in temp_usernames, \
            "a NULL-scope temp cred must not see a credential it did not create"

        # MUTATE confinement: nor deactivate/delete it (before the fix the guard was a NULL-scope no-op).
        assert temp_admin_client.post(
            f"/temp-creds/{sibling['temp_username']}/deactivate").status_code == 403
        assert temp_admin_client.post(
            f"/temp-creds/{sibling['temp_username']}/delete").status_code == 403
        # The parallel user-management router endpoint must be confined too (it lists a user's temp
        # creds by id; a legacy temp admin keeps role==ADMIN so the ownership guard alone lets it read).
        admin_id = admin.get("/users/me").json()["id"]
        assert sibling["temp_username"] in {
            c["temp_username"] for c in admin.get(f"/api/user-management/users/{admin_id}/temp-credentials").json()
        }, "admin should see the sibling via the router (control)"
        router_view = temp_admin_client.get(f"/api/user-management/users/{admin_id}/temp-credentials")
        assert router_view.status_code in (200, 304), router_view.text
        assert sibling["temp_username"] not in {c["temp_username"] for c in router_view.json()}, \
            "a NULL-scope temp cred must not enumerate a sibling via the user-management router either"

        # ...and the sibling is still there afterwards (the 403s did not mutate it).
        assert sibling["temp_username"] in {c["temp_username"] for c in admin.get("/temp-creds/list").json()}
    finally:
        admin.post(f"/temp-creds/{sibling['temp_username']}/delete")


def test_null_scope_temp_cred_manages_its_own_children(admin):
    # Confinement stamps the creating session on each child (scoped OR legacy NULL-scope), so a legacy
    # temp cred that can delegate still SEES and MANAGES the credentials it creates (its own subtree is
    # not empty). Without the stamping fix its children would carry a NULL creator it could never match.
    parent = admin.post("/auth/temp-credentials", json={
        "note": unique("parent"), "can_create_temp_credentials": True,
    }).json()
    pc = ApiClient(BASE_URL)
    pc.login(parent["temp_username"], parent["credential"])
    child_r = pc.post("/auth/temp-credentials", json={"note": unique("child")})
    if child_r.status_code != 200:
        pytest.skip(f"a legacy temp cred cannot create children here ({child_r.status_code})")
    child = child_r.json()
    try:
        listed = pc.get("/temp-creds/list")
        assert listed.status_code in (200, 304), listed.text
        assert child["temp_username"] in {c["temp_username"] for c in listed.json()}, \
            "a legacy temp cred must see the child it created"
        # It may manage its own child (deactivate -> 200, not the confinement 403).
        assert pc.post(f"/temp-creds/{child['temp_username']}/deactivate").status_code == 200
    finally:
        admin.post(f"/temp-creds/{child['temp_username']}/delete")


def test_user_view_grant_does_not_permit_reading_another_users_record(admin, temp_user):
    # IDOR guard: granting the (admin-default) USER_VIEW permission to a non-admin must NOT let them
    # read ANOTHER user's record — the catalog's requires_ownership flag is display-only, so the
    # handler enforces own-or-admin. The user may still read their OWN record.
    other = admin.create_user(role="user")
    try:
        g = admin.post(f"/permissions/users/{temp_user['id']}/grant", json={"endpoint_group": "USER_VIEW"})
        assert g.status_code == 200, g.text
        c = ApiClient()
        c.login(temp_user["_username"], temp_user["_password"])
        assert c.get(f"/api/user-management/users/{other['id']}").status_code == 403
        assert c.get(f"/api/user-management/users/{temp_user['id']}").status_code == 200
    finally:
        admin.delete_user(other["id"])
