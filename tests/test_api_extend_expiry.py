"""Extending an expiry (POST /shares|public-links|note-links|receivers/{id}/extend).

The maker or an administrator moves the expiry later, within the type's ceiling counted from the creation,
later than now and than the current expiry; recorded with the dates; anyone else gets the uniform 404; a
revoked thing cannot be extended.
"""
import os
import subprocess
from datetime import datetime, timedelta

import pytest

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

_MB = 1024 * 1024
DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


def _iso(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"


def _parse(iso):
    return datetime.fromisoformat(iso.replace("Z", ""))


@pytest.fixture
def sharing_on(admin):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    yield
    admin.put("/settings", json={"sharing_enabled": before})


def test_a_share_is_extended_within_its_tags_ceiling_and_recorded(admin, admin_creds, sharing_on):
    tag = admin.post("/share-tags", json={"name": unique("ext"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 10 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    owner = admin.create_user(role="user")
    other = admin.create_user(role="user")
    co = ApiClient(); co.login(owner["_username"], owner["_password"])
    cx = ApiClient(); cx.login(other["_username"], other["_password"])
    v = co.create_vault(name=unique("ext"))
    try:
        share = co.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "anyone_internal", "lifetime_minutes": 24 * 60}).json()
        before = _parse(share["expires_at"])
        # Later, within the ceiling: accepted, the dict comes back with the new expiry and the ceiling.
        r = co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(before + timedelta(days=3))})
        assert r.status_code == 200, r.text
        assert _parse(r.json()["expires_at"]) == (before + timedelta(days=3)).replace(microsecond=0)
        assert r.json()["ceiling"] and _parse(r.json()["ceiling"]) > before
        # Not earlier than now or than the current expiry; not past the ceiling (the message names the latest date).
        assert co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(before)}).status_code == 400
        assert co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() - timedelta(hours=1))}).status_code == 400
        over = co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(days=20))})
        assert over.status_code == 400 and "no later than" in over.text
        assert co.post(f"/shares/{share['id']}/extend", json={"expires_at": "not a date"}).status_code == 400
        # Someone else: the uniform 404. An administrator: allowed, and the record says so.
        assert cx.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(before + timedelta(days=5))}).status_code == 404
        r = admin.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(before + timedelta(days=5))})
        assert r.status_code == 200, r.text
        rows = _psql("SELECT details::text FROM audit_logs WHERE action='share_extended' "
                     f"AND details::text LIKE '%{share['id']}%' ORDER BY timestamp")
        assert rows.count("\n") + 1 == 2 and '"by_admin": true' in rows and '"new_expiry"' in rows
        # A revoked share cannot be extended.
        assert co.post(f"/shares/{share['id']}/revoke").status_code == 200
        assert co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(before + timedelta(days=6))}).status_code == 400
    finally:
        co.delete_vault(v["id"])
        admin.delete_user(owner["id"]); admin.delete_user(other["id"])


def test_an_upload_link_and_a_public_link_are_extended_within_their_tags(admin):
    settings_before = admin.get("/settings").json()
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50,
                                 "public_file_links_enabled": True})
    v = admin.create_vault(name=unique("extl"))
    try:
        rtag = admin.post("/receiver-tags", json={"name": unique("rt"), "min_token_len": 6, "require_secret": "none",
                                                  "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                                  "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
        rec = admin.post("/receivers", json={"tag_id": rtag["id"], "max_total_bytes": 10 * _MB, "ttl_hours": 24}).json()
        was = _parse(rec["expires_at"])
        r = admin.post(f"/receivers/{rec['id']}/extend", json={"expires_at": _iso(was + timedelta(hours=24))})
        assert r.status_code == 200, r.text
        assert _parse(r.json()["expires_at"]) == (was + timedelta(hours=24)).replace(microsecond=0)
        over = admin.post(f"/receivers/{rec['id']}/extend", json={"expires_at": _iso(was + timedelta(hours=96))})
        assert over.status_code == 400 and "no later than" in over.text
        assert int(_psql(f"SELECT count(*) FROM audit_logs WHERE action='receiver_extended' AND details::text LIKE '%{rec['id']}%'")) == 1

        fid = admin.post(f"/vaults/{v['id']}/files", files=[("files", ("a.txt", b"x", "text/plain"))]).json()["files"][0]["id"]
        ltag = admin.post("/note-link-tags", json={"name": unique("lt"), "auto_enroll_new_users": True,
                                                   "allowed_targets": ["file", "folder", "note"],
                                                   "default_ttl_hours": 24, "max_ttl_hours": 48})
        if ltag.status_code != 200:
            pytest.skip(f"no link tag here: {ltag.status_code} {ltag.text[:100]}")
        link = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file", "target_file_id": fid,
                                                  "tag_id": ltag.json()["id"], "ttl_hours": 24})
        assert link.status_code == 200, link.text
        lwas = _parse(link.json()["expires_at"])
        r = admin.post(f"/public-links/{link.json()['id']}/extend", json={"expires_at": _iso(lwas + timedelta(hours=12))})
        assert r.status_code == 200, r.text
        over = admin.post(f"/public-links/{link.json()['id']}/extend", json={"expires_at": _iso(lwas + timedelta(hours=48))})
        assert over.status_code == 400 and "no later than" in over.text
        assert admin.post(f"/public-links/{link.json()['id']}/revoke").status_code == 200
        assert admin.post(f"/public-links/{link.json()['id']}/extend", json={"expires_at": _iso(lwas + timedelta(hours=1))}).status_code == 400
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={k: settings_before.get(k) for k in
                                     ("public_receivers_enabled", "public_receiver_user_cap", "public_file_links_enabled")})


def test_a_temporary_credential_cannot_extend(admin, sharing_on):
    tag = admin.post("/share-tags", json={"name": unique("tmp"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True}).json()
    v = admin.create_vault(name=unique("tmpx"))
    try:
        share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal", "lifetime_minutes": 60}).json()
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info", "vault.see_files"], "temp": {}}
        tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30, "scope": scope,
                                                        "vault_access_mode": "all", "selected_vaults": []})
        assert tc.status_code == 200, tc.text   # the test is not optional: a credential is minted here
        t = ApiClient(); t.login(tc.json()["temp_username"], tc.json()["credential"])
        assert t.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(hours=2))}).status_code in (403, 404)
    finally:
        admin.delete_vault(v["id"])
