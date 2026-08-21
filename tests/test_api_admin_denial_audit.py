"""Admin-plane and cross-tenant access DENIALS must be audited.

The deployment audited authorised actions but not several refused ones. Two gaps:
  * require_admin / require_interactive_admin (resolved by FastAPI as dependencies, BEFORE the
    endpoint-permission decorator runs) raised 403 with NO audit row, so a non-admin -- or an
    admin-minted temp-credential session -- reaching for an admin function left no trace.
  * the vault membership/authorization 403 (the single chokepoint behind every get_vault caller)
    was likewise unaudited, so cross-tenant vault probing left no trail.

Both now write a best-effort denial row on the refusal path only (the 403 is never masked by an
audit hiccup, and an allowed request writes nothing).
"""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(
        ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _count(action, extra=""):
    return int(_psql_out(f"SELECT count(*) FROM audit_logs WHERE action='{action}'{extra}") or "0")


def _latest(action, field, extra=""):
    return _psql_out(
        f"SELECT {field} FROM audit_logs WHERE action='{action}'{extra} "
        "ORDER BY timestamp DESC LIMIT 1")


# --- admin-role denial (non-admin at an admin dependency) -------------------------------------

def test_nonadmin_admin_denial_is_audited(admin, temp_user_client):
    """A plain user hitting an admin-only endpoint (require_interactive_admin -> require_admin)
    is refused 403 and writes exactly one admin_access_denied row with a 'failure' status."""
    before = _count("admin_access_denied")
    assert temp_user_client.get("/audit/events").status_code == 403
    after = _count("admin_access_denied")
    assert after == before + 1, f"expected one admin-denial row, got {after - before}"
    assert _latest("admin_access_denied", "status") == "failure"
    assert _latest("admin_access_denied", "details->>'reason'") == "admin role required"


def test_temp_admin_interactive_denial_is_audited(admin):
    """An admin-minted TEMP-credential session keeps the admin role but is rejected by
    require_interactive_admin; that refusal must be audited too (privilege-boundary probe)."""
    created = admin.post("/auth/temp-credentials", json={"note": unique("admindenial")})
    assert created.status_code == 200, created.text
    cred = created.json()
    temp_admin = ApiClient()
    try:
        temp_admin.login(cred["temp_username"], cred["credential"])
        before = _count("admin_access_denied")
        assert temp_admin.get("/audit/events").status_code == 403
        after = _count("admin_access_denied")
        assert after == before + 1, f"expected one admin-denial row, got {after - before}"
        assert "interactive" in (_latest("admin_access_denied", "details->>'reason'") or "").lower()
    finally:
        admin.post(f"/temp-creds/{cred['temp_username']}/delete")


# --- cross-tenant vault read denial -----------------------------------------------------------

def test_cross_tenant_vault_read_denial_is_audited(admin, temp_user, temp_user_client):
    """A user with vault-view permission but NO membership of another account's vault is refused
    by require_vault_permission; that denial now writes an access_denied(vault) row."""
    va = admin.create_vault(name=unique("xtenant"))
    uid = temp_user["id"]
    # Ensure the attacker passes the endpoint-permission gate, so the 403 is the vault
    # authorization chokepoint (require_vault_permission), not a missing endpoint group.
    admin.post(f"/permissions/users/{uid}/grant", json={"endpoint_group": "VAULT_VIEW"})
    try:
        before = _count("access_denied", " AND resource_type='vault'")
        assert temp_user_client.get(f"/vaults/{va['id']}/files").status_code == 403
        after = _count("access_denied", " AND resource_type='vault'")
        assert after == before + 1, f"expected one vault-denial row, got {after - before}"
        assert _latest("access_denied", "resource_id", " AND resource_type='vault'") == str(va["id"])
    finally:
        admin.delete(f"/permissions/users/{uid}/revoke/VAULT_VIEW")
        admin.delete_vault(va["id"])


# --- negative control -------------------------------------------------------------------------

def test_allowed_admin_request_writes_no_admin_denial_row(admin):
    """The audit is denial-only: an authorised admin call leaves the admin-denial log untouched."""
    before = _count("admin_access_denied")
    assert admin.get("/audit/events").status_code == 200
    assert _count("admin_access_denied") == before, "an allowed admin request wrote a denial row"
