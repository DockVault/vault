"""Security hardening batch: a missing vault answers 404 not 500 (F-R001-001); opening a chunked
upload session requires WRITE (F-R015-002); the account.second_factor OTP requirement can't be
disabled (R018-INFO-1); an admin's login-attempt override is bounded (R018-INFO-2); the response
carries no Server header (F-R015-008)."""
import uuid

import pytest

from conftest import ApiClient, BASE_URL, unique
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
