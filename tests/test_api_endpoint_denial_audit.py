"""An endpoint-permission denial is a high-signal security event and must be audited.

The deployment audited authorised actions but not refused ones -- a defender reviewing the log
after an incident saw who got IN, never who was turned away at a permission gate, which is the
higher-signal half. The central `require_endpoint_permission` decorator now records each 403 it
raises (best-effort, on the denial path only) so those attempts are visible.
"""
import os
import subprocess

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _denial_count():
    return int(_psql_out("SELECT count(*) FROM audit_logs WHERE action='endpoint_permission_denied'") or "0")


def _latest_denial(field):
    return _psql_out(
        f"SELECT {field} FROM audit_logs WHERE action='endpoint_permission_denied' "
        "ORDER BY timestamp DESC LIMIT 1")


def test_endpoint_permission_denial_is_audited(admin, temp_user, temp_user_client):
    """Revoke a group so a guarded call is refused at require_endpoint_permission; the refusal must
    produce exactly one denial audit row naming the required group + reason, with a 'failure' status."""
    uid = temp_user["id"]
    assert admin.delete(f"/permissions/users/{uid}/revoke/DASHBOARD_VIEW").status_code == 200
    try:
        before = _denial_count()
        assert temp_user_client.get("/api/dashboard/stats").status_code == 403
        after = _denial_count()
        assert after == before + 1, f"expected exactly one new denial audit row, got {after - before}"
        assert _latest_denial("status") == "failure"
        assert _latest_denial("details->>'required_group'") == "DASHBOARD_VIEW"
        assert _latest_denial("details->>'reason'") in ("temp_credential_scope", "missing_required_group")
    finally:
        admin.post(f"/permissions/users/{uid}/grant", json={"endpoint_group": "DASHBOARD_VIEW"})


def test_an_allowed_request_writes_no_denial_row(admin):
    """The audit is denial-only: an authorised call (admin bypasses at the role check, before any
    403 site) leaves the denial log untouched."""
    before = _denial_count()
    assert admin.get("/api/dashboard/stats").status_code == 200
    assert _denial_count() == before, "an allowed request wrongly wrote a denial audit row"
