"""A per-vault capability denial is audited, like the endpoint-group denial.

require_vault_cap stacks UNDER require_endpoint_permission, so a scoped credential that can REACH an
endpoint but was not granted its vault capability is refused here -- a gate the endpoint-group denial
audit never sees. That refusal is now recorded (best-effort, denial-path only), so a defender sees a
credential reaching for a vault action it could not perform.
"""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _count():
    return int(_psql_out("SELECT count(*) FROM audit_logs WHERE action='vault_cap_denied'") or "0")


def _latest(field):
    return _psql_out(
        f"SELECT {field} FROM audit_logs WHERE action='vault_cap_denied' ORDER BY timestamp DESC LIMIT 1")


def _endpoint_denial_count():
    return int(_psql_out(
        "SELECT count(*) FROM audit_logs WHERE action='endpoint_permission_denied'") or "0")


def _scoped_client(admin, vid, caps):
    """A temp credential scoped to `vid` with exactly `caps` -- enough to reach the vault, not to do
    everything on it."""
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vid, "caps": caps}]}).json()
    c = ApiClient()
    c.login(body["temp_username"], body["credential"])
    return c


def test_vault_cap_denial_is_audited(admin):
    """A see_info-only credential passes the endpoint gate for the file listing but lacks
    vault.see_files -- the cap gate refuses it, and that refusal is recorded exactly once."""
    v = admin.create_vault(name=unique("vcap"))
    try:
        c = _scoped_client(admin, v["id"], ["vault.see_info"])  # deliberately NOT vault.see_files
        before = _count()
        ep_before = _endpoint_denial_count()
        assert c.get(f"/vaults/{v['id']}/files").status_code == 403
        after = _count()
        assert after == before + 1, f"expected exactly one new vault_cap_denied row, got {after - before}"
        assert _latest("status") == "failure"
        assert _latest("details->>'capability'") == "vault.see_files"
        assert _latest("resource_type") == "vault"
        assert _latest("resource_id") == v["id"]
        # No double-audit: the cap gate is reached only once the endpoint-group gate has passed, so
        # the same request must NOT also write an endpoint_permission_denied row. (Locks the
        # structural guarantee against a future refactor that audits on any downstream 403.)
        assert _endpoint_denial_count() == ep_before, "a cap denial wrongly also wrote an endpoint-group denial"
    finally:
        admin.delete_vault(v["id"])


def test_a_permitted_vault_action_writes_no_cap_denial_row(admin):
    """The audit is denial-only: an action the credential IS granted leaves the log untouched."""
    v = admin.create_vault(name=unique("vcapok"))
    try:
        c = _scoped_client(admin, v["id"], ["vault.see_info"])
        before = _count()
        assert c.get(f"/vaults/{v['id']}").status_code == 200  # vault.see_info is granted
        assert _count() == before, "a permitted action wrongly wrote a cap-denial row"
    finally:
        admin.delete_vault(v["id"])
