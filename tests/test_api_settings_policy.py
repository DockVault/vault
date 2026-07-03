"""Admin Settings validation for the SFTP-auth + zero-knowledge policy keys.

PUT /settings is a generic key/value store, but two keys drive real enforcement
and must not silently accept bad data:

  * zero_knowledge_enabled         -> bool   (read by _zk_enabled; a string would
                                              coerce truthy and silently allow ZK)
  * sftp_require_temp_cred_groups  -> list of EXISTING group ids (read by the SFTP
                                              auth gate, which fails open on ids it
                                              can't resolve, so a typo would do
                                              nothing and look "applied")

These tests pin that validation plus the GET round-trip. They also confirm the
store stays generic for unrelated keys. Admin-only.
"""
import uuid

import pytest

from conftest import unique


@pytest.fixture
def restore_policy_settings(admin):
    """Snapshot the two policy keys and restore them after the test so a run
    can't leave the shared deployment with a stray policy."""
    before = admin.get("/settings").json()
    yield
    admin.put("/settings", json={
        "zero_knowledge_enabled": bool(before.get("zero_knowledge_enabled", False)),
        "sftp_require_temp_cred_groups": list(before.get("sftp_require_temp_cred_groups") or []),
    })


def test_zero_knowledge_enabled_round_trip(admin, restore_policy_settings):
    assert admin.put("/settings", json={"zero_knowledge_enabled": True}).status_code == 200
    assert admin.get("/settings").json().get("zero_knowledge_enabled") is True
    assert admin.put("/settings", json={"zero_knowledge_enabled": False}).status_code == 200
    assert admin.get("/settings").json().get("zero_knowledge_enabled") is False


@pytest.mark.parametrize("bad", ["true", 1, 0, "yes", None, []])
def test_zero_knowledge_enabled_rejects_non_bool(admin, restore_policy_settings, bad):
    r = admin.put("/settings", json={"zero_knowledge_enabled": bad})
    assert r.status_code == 400, f"expected 400 for {bad!r}, got {r.status_code}: {r.text}"


def test_sftp_groups_round_trip_with_real_group(admin, restore_policy_settings):
    gid = admin.post("/groups", json={"name": unique("hs")}).json()["id"]
    try:
        assert admin.put("/settings", json={"sftp_require_temp_cred_groups": [gid]}).status_code == 200
        assert admin.get("/settings").json().get("sftp_require_temp_cred_groups") == [gid]
    finally:
        admin.put("/settings", json={"sftp_require_temp_cred_groups": []})
        admin.delete(f"/groups/{gid}")


def test_sftp_groups_rejects_unknown_id(admin, restore_policy_settings):
    ghost = str(uuid.uuid4())  # well-formed UUID, but not a real group
    r = admin.put("/settings", json={"sftp_require_temp_cred_groups": [ghost]})
    assert r.status_code == 400, r.text


def test_sftp_groups_rejects_bad_shape(admin, restore_policy_settings):
    assert admin.put("/settings", json={"sftp_require_temp_cred_groups": "not-a-list"}).status_code == 400
    assert admin.put("/settings", json={"sftp_require_temp_cred_groups": [123]}).status_code == 400
    assert admin.put("/settings", json={"sftp_require_temp_cred_groups": ["not-a-uuid"]}).status_code == 400


def test_settings_write_is_admin_only(anon):
    r = anon.put("/settings", json={"zero_knowledge_enabled": True})
    assert r.status_code in (401, 403)


def test_unrelated_settings_keys_still_merge(admin, restore_policy_settings):
    """Validation must not turn the generic store into a whitelist: an unrelated
    key still saves and merges (and the merge keeps the policy keys intact)."""
    probe = unique("probe")
    assert admin.put("/settings", json={"app_description": probe}).status_code == 200
    data = admin.get("/settings").json()
    assert data.get("app_description") == probe
