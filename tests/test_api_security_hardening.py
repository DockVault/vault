"""Security hardening batch: a missing vault answers 404 not 500 (F-R001-001); opening a chunked
upload session requires WRITE (F-R015-002); the account.second_factor OTP requirement can't be
disabled (R018-INFO-1); an admin's login-attempt override is bounded (R018-INFO-2); the response
carries no Server header (F-R015-008)."""
import uuid

import pytest

from conftest import ApiClient, BASE_URL, unique, create_zk_vault, ZK_ENC_NAME_STUB
from _sf_helpers import enrolled_admin, step_up_receipt

pytestmark = pytest.mark.integration


def test_missing_vault_is_404_not_500(admin):
    fake = uuid.uuid4()
    assert admin.get(f"/vaults/{fake}/files").status_code == 404
    assert admin.get(f"/vaults/{fake}/files/{uuid.uuid4()}/download").status_code == 404
    assert admin.post(f"/vaults/{fake}/files/{uuid.uuid4()}/delete").status_code == 404
    assert admin.patch(f"/vaults/{fake}", json={"name": "x"}).status_code == 404
    assert admin.put(f"/vaults/{fake}/password",
                     json={"password": "New-Strong-Pass-1234"}).status_code == 404
    # get-file-info + rename had a local `except Exception` catch-all that swallowed VaultNotFoundError
    # into a 500 before it reached the global 404 mapper (F-R001-001 follow-up); both must 404 too.
    assert admin.get(f"/vaults/{fake}/files/{uuid.uuid4()}/info").status_code == 404
    assert admin.put(f"/vaults/{fake}/files/{uuid.uuid4()}/rename",
                     json={"new_name": "x.txt"}).status_code == 404
    # Same catch-all pattern on settings / upload / folder create+delete (found by a full file-plane
    # sweep) — all must 404 on a nonexistent vault, not 500.
    assert admin.patch(f"/vaults/{fake}/settings", json={"description": "x"}).status_code == 404
    assert admin.post(f"/vaults/{fake}/files",
                      files=[("files", ("a.txt", b"x", "text/plain"))]).status_code == 404
    assert admin.post(f"/vaults/{fake}/folders", json={"name": "f"}).status_code == 404
    assert admin.post(f"/vaults/{fake}/folders/{uuid.uuid4()}/delete").status_code == 404


def test_readonly_member_cannot_open_upload_session(admin, temp_user, temp_user_client):
    v = admin.create_vault()
    vid = v["id"]
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "read"})
    try:
        assert temp_user_client.get(f"/vaults/{vid}/files").status_code == 200  # read confirmed
        body = {"file_name": "member.bin", "total_size": 1024, "total_chunks": 1,
                "chunk_size": 1024 * 1024, "mime_type": "application/octet-stream"}
        # A read-only member must not even OPEN an upload session (was 200; /complete refused later).
        r = temp_user_client.post(f"/vaults/{vid}/uploads", json=body)
        assert r.status_code == 403, r.text
        # The owner (write) can still open one with the same body — proving the 403 is the write gate.
        ro = admin.post(f"/vaults/{vid}/uploads", json=body)
        assert ro.status_code == 200, ro.text
    finally:
        admin.delete_vault(vid)


def test_account_second_factor_otp_cannot_be_disabled(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        # Single-action endpoint.
        r = c.put("/second-factor/actions/account.second_factor", json={"require_otp": False},
                  headers={"X-Second-Factor": step_up_receipt(
                      c, action="account.second_factor", recovery_codes=codes)})
        assert r.status_code == 400, r.text
        # Bulk endpoint — the whole batch is rejected.
        rb = c.put("/second-factor/actions",
                   json={"actions": [{"key": "account.second_factor", "require_otp": False}]},
                   headers={"X-Second-Factor": step_up_receipt(
                       c, action="account.second_factor", recovery_codes=codes)})
        assert rb.status_code == 400, rb.text
        # BYPASS regression: a falsy-but-not-False JSON value (0, "", []) must NOT slip the bulk guard.
        # The items are raw dicts, so an identity `is False` check would let these through yet store
        # bool(x) == False — flipping the gate off. Each must be refused, on BOTH endpoints.
        for bad in (0, "", []):
            # BULK: raw dicts (untyped list), so every falsy value reaches the guard -> 400.
            rz = c.put("/second-factor/actions",
                       json={"actions": [{"key": "account.second_factor", "require_otp": bad}]},
                       headers={"X-Second-Factor": step_up_receipt(
                           c, action="account.second_factor", recovery_codes=codes)})
            assert rz.status_code == 400, f"bulk require_otp={bad!r} bypassed the guard: {rz.text}"
            # SINGLE: typed Optional[bool], so 0 coerces to False and the guard rejects it (400), while
            # "" / [] fail model validation first (422). Both mean the request is REFUSED and OTP is
            # left required -- the key property is that neither disables it.
            rs = c.put("/second-factor/actions/account.second_factor", json={"require_otp": bad},
                       headers={"X-Second-Factor": step_up_receipt(
                           c, action="account.second_factor", recovery_codes=codes)})
            assert rs.status_code in (400, 422), f"single require_otp={bad!r} was not refused: {rs.text}"
        # After every rejected attempt the EFFECTIVE requirement is still on.
        acts = c.get("/second-factor/actions").json()["actions"]
        gate = next(a for a in acts if a["key"] == "account.second_factor")
        assert gate["require_otp"] is True, gate
        # The guard is specific: a different action can still be turned off.
        ok = c.put("/second-factor/actions/vault.delete", json={"require_otp": False},
                   headers={"X-Second-Factor": step_up_receipt(
                       c, action="account.second_factor", recovery_codes=codes)})
        assert ok.status_code == 200, ok.text
    finally:
        admin.delete_user(ta["id"])


def test_login_attempt_override_is_bounded(admin):
    before = admin.get("/settings").json()
    try:
        # An admin override above the login ceiling (1000) is refused; within range is accepted.
        assert admin.put("/settings", json={"max_login_attempts": 5000}).status_code == 400
        assert admin.put("/settings", json={"max_login_attempts": 800}).status_code == 200
        # The other groups keep their higher ceiling (the login cap is group-specific).
        assert admin.put("/settings", json={"rate_limit_vault_attempts": 5000}).status_code == 200
    finally:
        admin.put("/settings", json={
            "max_login_attempts": before.get("max_login_attempts", 0) or 0,
            "rate_limit_vault_attempts": before.get("rate_limit_vault_attempts", 0) or 0})


def test_no_server_header(admin):
    r = admin.get("/health")
    assert r.status_code == 200
    assert "server" not in {k.lower() for k in r.headers.keys()}, dict(r.headers)


def test_zk_vault_reseal_rejects_future_epoch(admin):
    # A ZK vault-name re-seal (PATCH /vaults/{id}) must not pin the name to a DEK epoch ahead of the
    # vault's current one (no member holds a key for it yet -> the name would be undecryptable). This
    # mirrors the guard already on the file/folder rename path.
    before = admin.get("/settings").json().get("zero_knowledge_enabled", False)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    zk = create_zk_vault(admin, name=unique("zk"))
    vid = zk["id"]
    try:
        # A fresh vault sits at epoch 1; sealing the name at a far-future epoch is refused as a 400,
        # not stored (and not a 500 from a downstream DataError).
        r = admin.patch(f"/vaults/{vid}",
                        json={"enc_name": ZK_ENC_NAME_STUB, "name_key_version": 999})
        assert r.status_code == 400, r.text
        assert "epoch" in r.json().get("detail", "").lower(), r.text
        # A re-seal at the current epoch (1) is accepted, proving the 400 is the epoch guard and not a
        # blanket rejection of the re-seal.
        ok = admin.patch(f"/vaults/{vid}",
                         json={"enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1})
        assert ok.status_code == 200, ok.text
    finally:
        admin.delete_vault(vid)
        admin.put("/settings", json={"zero_knowledge_enabled": bool(before)})
