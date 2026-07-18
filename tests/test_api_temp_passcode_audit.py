"""Audit trail for temporary vault passcodes.

Minting a passcode, redeeming it, and a failed redemption each write an audit event
(`temp_passcode_minted` / `temp_passcode_used` / `temp_passcode_failed`) recording the vault and the
temp credential — but NEVER the passcode plaintext. Exercises both the normal-account mint path and a
temp-credential session's redemption.
"""
import json
import uuid

import pytest

_PW = "Sup3r-Secret-PW-9!"


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def restore_policy(admin):
    keys = ("temp_passcodes_enabled", "temp_passcode_one_time_default", "temp_passcode_single_vault_only")
    before = admin.get("/settings").json()
    yield
    admin.put("/settings", json={k: before[k] for k in keys if k in before})


def _pw_vault_with_file(admin):
    v = admin.create_vault(name=_u("av"), password=_PW)
    content = b"secret-bytes-" + uuid.uuid4().hex.encode()
    r = admin.post(f"/vaults/{v['id']}/files",
                   files=[("files", (_u("f") + ".txt", content, "text/plain"))],
                   headers={"X-Vault-Password": _PW})
    r.raise_for_status()
    return v["id"], r.json()["files"][0]["id"]


_CAPS = ["vault.see_info", "vault.see_files", "file.download"]


def _mint(admin, selected_vaults, same_for_all=False):
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": _CAPS, "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": selected_vaults, "passcode_same_for_all": same_for_all}).json()
    return body


def _audit_rows(admin, action, limit=500):
    return admin.get("/audit/log", params={"action": action, "limit": limit}).json()


def _all_audit_json(admin, limit=500):
    return json.dumps(admin.get("/audit/log", params={"limit": limit}).json())


def test_mint_emits_minted_audit_without_secret(admin, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": True})
    v1 = admin.create_vault(name=_u("m1"), password=_PW)["id"]
    v2 = admin.create_vault(name=_u("m2"), password=_PW)["id"]
    try:
        body = _mint(admin, [
            {"vault_id": v1, "caps": _CAPS, "password": _PW, "issue_passcode": True},
            {"vault_id": v2, "caps": _CAPS, "password": _PW, "issue_passcode": True},
        ], same_for_all=True)
        secret = body["passcodes"][0]["passcode"]

        rows = _audit_rows(admin, "temp_passcode_minted")
        mine = next((r for r in rows if v1 in json.dumps(r.get("details") or {})), None)
        assert mine is not None, "no temp_passcode_minted audit row for this mint"
        d = mine["details"]
        assert d["count"] == 2 and d["same_for_all"] is True
        vault_ids = {e["vault_id"] for e in d["vaults"]}
        assert {v1, v2} <= vault_ids
        assert mine["status"] == "success"

        # the passcode plaintext must not appear anywhere in the audit log
        assert secret not in _all_audit_json(admin), "passcode leaked into the audit log"
    finally:
        admin.delete_vault(v1, vault_password=_PW)
        admin.delete_vault(v2, vault_password=_PW)


def test_redeem_used_and_failed_audit(admin, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid = _pw_vault_with_file(admin)
    try:
        body = _mint(admin, [{"vault_id": vid, "caps": _CAPS, "password": _PW, "issue_passcode": True}])
        secret = body["passcodes"][0]["passcode"]
        tc = admin.clone_anonymous()
        tc.login(body["temp_username"], body["credential"])

        # success -> temp_passcode_used
        assert tc.get(f"/vaults/{vid}/files/{fid}/download",
                      headers={"X-Vault-Passcode": secret}).status_code == 200
        used = next((r for r in _audit_rows(admin, "temp_passcode_used") if r.get("resource_id") == vid), None)
        assert used is not None and used["status"] == "success"
        assert used["details"].get("temp_credential_id")

        # wrong passcode -> temp_passcode_failed(reason=wrong)
        assert tc.get(f"/vaults/{vid}/files/{fid}/download",
                      headers={"X-Vault-Passcode": "totally-wrong-zzz"}).status_code in (400, 401, 403)
        failed = next((r for r in _audit_rows(admin, "temp_passcode_failed")
                       if r.get("resource_id") == vid and (r.get("details") or {}).get("reason") == "wrong"), None)
        assert failed is not None and failed["status"] == "failure"

        assert secret not in _all_audit_json(admin), "passcode leaked into the audit log"
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_disabled_redemption_is_audited(admin, restore_policy):
    """The kill-switch path (feature disabled after mint) records a failed redemption with reason=disabled."""
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid = _pw_vault_with_file(admin)
    try:
        body = _mint(admin, [{"vault_id": vid, "caps": _CAPS, "password": _PW, "issue_passcode": True}])
        secret = body["passcodes"][0]["passcode"]
        tc = admin.clone_anonymous()
        tc.login(body["temp_username"], body["credential"])

        admin.put("/settings", json={"temp_passcodes_enabled": False})  # kill-switch
        assert tc.get(f"/vaults/{vid}/files/{fid}/download",
                      headers={"X-Vault-Passcode": secret}).status_code in (400, 401, 403)
        failed = next((r for r in _audit_rows(admin, "temp_passcode_failed")
                       if r.get("resource_id") == vid and (r.get("details") or {}).get("reason") == "disabled"), None)
        assert failed is not None, "disabled redemption was not audited"
    finally:
        admin.put("/settings", json={"temp_passcodes_enabled": True})
        admin.delete_vault(vid, vault_password=_PW)
