"""A refused key rotation is a high-signal event and must leave an audit trace.

`POST /vaults/{id}/rotate-key` refuses (a Standard vault's content is encrypted under a key derived
from the deployment secret, not the vault key, so rotating it would re-key nothing). But an operator
reaches for key rotation precisely when they believe a key is compromised -- one of the highest-signal
events the product can capture -- and until now the refusal wrote nothing, so a defender reviewing the
audit log after an incident saw the assertion nowhere. The refusal now records the attempt (changing
no vault key state), and the key-history endpoint says plainly that rotation is unsupported.
"""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _audit_rows(admin, action, limit=500):
    return admin.get("/audit/log", params={"action": action, "limit": limit}).json()


def _row_for(admin, action, vault_id, limit=500):
    rows = _audit_rows(admin, action, limit)
    if isinstance(rows, dict):
        rows = rows.get("items", rows.get("logs", []))
    return next((r for r in rows if str(r.get("resource_id")) == str(vault_id)), None)


def test_standard_refusal_is_audited(admin):
    """The core case: refusing a Standard-vault rotation writes a refused-rotation audit row."""
    v = admin.create_vault(name=unique("rka"))
    try:
        assert admin.post(f"/vaults/{v['id']}/rotate-key").status_code == 501
        row = _row_for(admin, "vault_key_rotation", v["id"])
        assert row is not None, "the refused standard-vault rotation was not audited"
        assert row.get("status") == "refused", row
        assert (row.get("details") or {}).get("reason") == "standard_not_supported", row
    finally:
        admin.delete_vault(v["id"])


def test_refusal_audits_but_still_mutates_no_key_state(admin):
    """The audit row is the only new effect: the vault's key version and history are untouched."""
    v = admin.create_vault(name=unique("rkm"))
    try:
        before = admin.get(f"/vaults/{v['id']}/key-history").json()
        for _ in range(3):
            assert admin.post(f"/vaults/{v['id']}/rotate-key").status_code == 501
        after = admin.get(f"/vaults/{v['id']}/key-history").json()
        assert after["current_key_version"] == before["current_key_version"]
        assert len(after["history"]) == len(before["history"])
    finally:
        admin.delete_vault(v["id"])


def test_zero_knowledge_refusal_is_audited(admin):
    """The wrong-vault-type refusal is a rotation attempt too, and is recorded with its own reason."""
    v = admin.create_vault(name=unique("rkzk"))
    _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{v['id']}';")
    try:
        assert admin.post(f"/vaults/{v['id']}/rotate-key").status_code == 400
        row = _row_for(admin, "vault_key_rotation", v["id"])
        assert row is not None, "the zero-knowledge rotation refusal was not audited"
        assert (row.get("details") or {}).get("reason") == "zero_knowledge", row
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{v['id']}';")
        admin.delete_vault(v["id"])


def test_non_owner_rotation_attempt_is_audited_when_it_reaches_the_owner_check(admin):
    """A non-owner reaching for another account's key rotation is an access denial worth recording.
    A stranger who is refused earlier (404, or blocked by an endpoint cap) writes nothing here, which
    is correct; only an attempt that reaches the owner check produces the access-denied row."""
    v = admin.create_vault(name=unique("rkno"))
    u = admin.create_user(role="user")
    c = ApiClient()
    try:
        c.login(u["_username"], u["_password"])
        r = c.post(f"/vaults/{v['id']}/rotate-key")
        assert r.status_code in (403, 404), r.text
        assert r.status_code != 501, "a non-owner learned this vault exists / is supported"
        # Only assert the audit row on the path that actually reaches the in-handler owner check.
        if r.status_code == 403 and "vault owner" in r.text.lower():
            row = _row_for(admin, "access_denied", v["id"])
            assert row is not None, "a non-owner rotate attempt that hit the owner check was not audited"
    finally:
        admin.delete_user(u["id"])
        admin.delete_vault(v["id"])


def test_key_history_states_rotation_is_unsupported(admin):
    """The permanently-empty history is now labeled by-design, not left looking broken."""
    v = admin.create_vault(name=unique("rkh"))
    try:
        r = admin.get(f"/vaults/{v['id']}/key-history")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("rotation_supported") is False, body
        assert "not supported" in (body.get("note") or "").lower()
    finally:
        admin.delete_vault(v["id"])
