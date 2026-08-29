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


def _assert_cap_denied(admin, client, vault_id, method, path, cap, **kwargs):
    """A credential that reaches `path` but lacks `cap` is refused by the cap gate (403) and the
    refusal is recorded as vault_cap_denied for that exact capability -- proving it is the CAP gate
    that stopped it, not the endpoint-group gate (which would write endpoint_permission_denied)."""
    before = _count()
    resp = getattr(client, method.lower())(path, **kwargs)
    assert resp.status_code == 403, f"{method} {path} without {cap} should be 403, got {resp.status_code}"
    assert _count() == before + 1, f"{cap} denial was not audited exactly once"
    assert _latest("details->>'capability'") == cap
    assert _latest("resource_id") == vault_id


def test_destructive_vault_caps_are_denied_without_the_capability(admin):
    """The four most destructive vault capabilities -- change_info, change_password, change_expiry and
    delete -- are load-bearing gates with, until now, no test asserting a credential lacking them is
    refused. A regression that drops one of these decorators would let a credential handed to a
    contractor change or destroy a vault. Each is checked with a positive control so the denials
    can't pass vacuously, and the vault is confirmed intact afterwards.
    """
    v = admin.create_vault(name=unique("vdestroy"))
    try:
        # Holds a read capability and NONE of the four destructive ones.
        c = _scoped_client(admin, v["id"], ["vault.see_info"])
        vid = v["id"]

        # Positive control: the granted capability works, so a blanket-403 (e.g. a wholly broken
        # credential) can't make these denials pass for the wrong reason.
        assert c.get(f"/vaults/{vid}").status_code == 200

        _assert_cap_denied(admin, c, vid, "PATCH", f"/vaults/{vid}",
                           "vault.change_info", json={"name": unique("nope")})
        _assert_cap_denied(admin, c, vid, "PUT", f"/vaults/{vid}/password",
                           "vault.change_password", json={"new_password": "irrelevant-not-applied"})
        _assert_cap_denied(admin, c, vid, "PATCH", f"/vaults/{vid}/settings",
                           "vault.change_expiry", json={})
        _assert_cap_denied(admin, c, vid, "POST", f"/vaults/{vid}/rotate-key",
                           "vault.rotate_key", json={})
        _assert_cap_denied(admin, c, vid, "POST", f"/vaults/{vid}/delete",
                           "vault.delete", json={})

        # The vault survived every attempt.
        assert admin.get(f"/vaults/{vid}").status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_cap_denial_on_no_request_endpoint_records_client_ip(admin):
    """The client IP is recorded even when the denied endpoint declares no `request` parameter.

    `GET /vaults/{id}/group-access` (list_vault_group_access) is gated by require_vault_cap
    ("vault.see_permissions") but takes only (vault_id, current_user, db) -- no `request`. The
    earlier audit helper hunted for a Request in the decorator's kwargs and so logged a NULL IP on
    every such endpoint. A pure-ASGI middleware now stamps the trusted-proxy client IP into a
    contextvar once per request, and the helper reads it from there, so the denial row carries the
    IP regardless of the endpoint's signature.
    """
    v = admin.create_vault(name=unique("vcapip"))
    try:
        c = _scoped_client(admin, v["id"], ["vault.see_info"])  # lacks vault.see_permissions
        before = _count()
        assert c.get(f"/vaults/{v['id']}/group-access").status_code == 403
        assert _count() == before + 1, "the no-request endpoint's cap denial was not audited"
        assert _latest("details->>'capability'") == "vault.see_permissions"
        assert _latest("resource_id") == v["id"]
        ip = _latest("ip_address")
        # psql -tA prints a SQL NULL as the empty string; require a real address, not the empty
        # string (the pre-change NULL) nor client_ip's "unknown" no-peer fallback.
        assert ip and ip != "unknown", f"expected a real client IP on the denial row, got {ip!r}"
    finally:
        admin.delete_vault(v["id"])
