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
        assert set(r.json()) == {"id", "expires_at", "ceiling"}, r.json()   # nothing of the maker's share
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


def test_an_administrator_who_extends_another_persons_note_link_gets_no_content(admin):
    settings_before = admin.get("/settings").json()
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    owner = admin.create_user(role="user")
    co = ApiClient(); co.login(owner["_username"], owner["_password"])
    try:
        tag = admin.post("/note-link-tags", json={"name": unique("nl"), "min_token_len": 6, "require_secret": "none",
                                                  "auto_enroll_new_users": True, "allowed_targets": ["note"],
                                                  "default_ttl_hours": 24, "max_ttl_hours": 72})
        if tag.status_code != 200:
            pytest.skip(f"no note-link tag here: {tag.status_code} {tag.text[:100]}")
        note = co.post("/notes", json={"title": "salary review", "body": "PRIVATE-BODY the door code"}).json()
        link = co.post("/note-links", json={"note_id": note["id"], "tag_id": tag.json()["id"], "ttl_hours": 24})
        assert link.status_code in (200, 201), link.text
        was = _parse(link.json()["expires_at"])
        # An administrator may move the expiry, and learns nothing of the note from the answer.
        r = admin.post(f"/note-links/{link.json()['id']}/extend", json={"expires_at": _iso(was + timedelta(hours=1))})
        assert r.status_code == 200, r.text
        assert set(r.json()) == {"id", "expires_at", "ceiling"}, r.json()
        assert "PRIVATE-BODY" not in r.text and "salary" not in r.text
        # The maker gets their own view back, body included.
        r = co.post(f"/note-links/{link.json()['id']}/extend", json={"expires_at": _iso(was + timedelta(hours=2))})
        assert r.status_code == 200, r.text
        assert r.json()["body"].startswith("PRIVATE-BODY") and r.json()["ceiling"]
    finally:
        admin.delete_user(owner["id"])
        admin.put("/settings", json={k: settings_before.get(k) for k in
                                     ("public_note_links_enabled", "public_note_link_user_cap")})


def test_a_share_whose_maker_lost_the_vault_cannot_be_extended(admin, sharing_on):
    tag = admin.post("/share-tags", json={"name": unique("lost"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 10 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    maker = admin.create_user(role="user")
    cm = ApiClient(); cm.login(maker["_username"], maker["_password"])
    v = admin.create_vault(name=unique("lostv"))
    try:
        assert admin.post(f"/vaults/{v['id']}/permissions", json={"user_id": maker["id"], "level": "read"}).status_code == 200
        share = cm.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "anyone_internal", "lifetime_minutes": 24 * 60})
        assert share.status_code == 200, share.text
        later = _iso(_parse(share.json()["expires_at"]) + timedelta(days=2))
        assert admin.delete(f"/vaults/{v['id']}/permissions/{maker['id']}").status_code == 200
        # Neither the maker nor an administrator can lengthen a share its maker could not make today.
        r = cm.post(f"/shares/{share.json()['id']}/extend", json={"expires_at": later})
        assert r.status_code == 400 and "no longer has access" in r.text, r.text
        r = admin.post(f"/shares/{share.json()['id']}/extend", json={"expires_at": later})
        assert r.status_code == 400 and "no longer has access" in r.text, r.text
    finally:
        admin.delete_vault(v["id"])
        admin.delete_user(maker["id"])


def test_an_expired_share_stays_expired_and_a_locked_lifetime_or_a_widened_type_does_not_move(admin, sharing_on):
    tag = admin.post("/share-tags", json={"name": unique("exp"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 2 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    locked = admin.post("/share-tags", json={"name": unique("lock"), "allowed_audiences": ["anyone_internal"],
                                             "max_recipients_cap": 10, "auto_enroll_new_users": True, "allow_custom": False,
                                             "max_lifetime_minutes": 10 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    v = admin.create_vault(name=unique("expv"))
    try:
        share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal", "lifetime_minutes": 24 * 60}).json()
        # The type is widened afterwards: the share keeps the ceiling it was made under.
        assert admin.patch(f"/share-tags/{tag['id']}", json={"max_lifetime_minutes": 20 * 24 * 60}).status_code == 200
        r = admin.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(days=10))})
        assert r.status_code == 400 and "no later than" in r.text, r.text
        r = admin.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(hours=36))})
        assert r.status_code == 200, r.text
        # Past its expiry, untouched by anyone, it stays expired.
        _psql(f"UPDATE shares SET expires_at = now() - interval '1 minute' WHERE id = '{share['id']}'")
        r = admin.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(hours=40))})
        assert r.status_code == 400 and "active share" in r.text, r.text
        # A type whose makers cannot choose a lifetime gives them no extension either.
        fixed = admin.post("/shares", json={"vault_id": v["id"], "tag_id": locked["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal"}).json()
        r = admin.post(f"/shares/{fixed['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(days=3))})
        assert r.status_code == 400 and "sets the lifetime" in r.text, r.text
    finally:
        admin.delete_vault(v["id"])


def test_a_long_extension_needs_the_second_factor_of_an_enrolled_account(admin, sharing_on):
    from _sf_helpers import enroll_totp, step_up_receipt
    tag = admin.post("/share-tags", json={"name": unique("far"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 90 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    maker = admin.create_user(role="user")
    cm = ApiClient(); cm.login(maker["_username"], maker["_password"])
    v = cm.create_vault(name=unique("farv"))
    try:
        _secret, codes = enroll_totp(maker, cm)
        share = cm.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "anyone_internal", "lifetime_minutes": 24 * 60}).json()
        # Within a week: nothing asked of the same enrolled account.
        r = cm.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(days=3))})
        assert r.status_code == 200, r.text
        far = _iso(datetime.utcnow() + timedelta(days=30))
        r = cm.post(f"/shares/{share['id']}/extend", json={"expires_at": far})
        assert r.status_code == 403 and "step_up_required" in r.text, r.text
        r = cm.post(f"/shares/{share['id']}/extend", json={"expires_at": far},
                    headers={"X-Second-Factor": step_up_receipt(cm, action="link.extend_long", recovery_codes=codes)})
        assert r.status_code == 200, r.text
        assert _parse(r.json()["expires_at"]) == _parse(far)
    finally:
        cm.delete_vault(v["id"])
        admin.delete_user(maker["id"])


def test_every_item_carries_its_extend_ceiling_and_a_refusal_reads_as_a_date(admin, sharing_on):
    """The share, public link, note link and upload link dicts carry extend_ceiling (creation plus the tag's
    maximum) so the web app can offer only dates the server accepts; a refusal names the ceiling as a person
    reads it, not as an ISO string."""
    import re
    settings_before = admin.get("/settings").json()
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50,
                                 "public_file_links_enabled": True})
    stag = admin.post("/share-tags", json={"name": unique("ceil"), "allowed_audiences": ["anyone_internal"],
                                           "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                           "max_lifetime_minutes": 7 * 24 * 60, "default_lifetime_minutes": 24 * 60}).json()
    v = admin.create_vault(name=unique("ceil"))
    try:
        share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": stag["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal"}).json()
        listed = admin.get("/shares").json()
        mine = next(s for s in (listed if isinstance(listed, list) else listed.get("shares", [])) if s["id"] == share["id"])
        created = _parse(mine["created_at"])
        assert mine["extend_ceiling"], mine
        assert _parse(mine["extend_ceiling"]) == (created + timedelta(days=7)).replace(microsecond=0)
        # The week the dialog used to suggest is past this ceiling: refused, and the refusal reads as a date.
        over = admin.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(_parse(mine["expires_at"]) + timedelta(days=7))})
        assert over.status_code == 400, over.text
        assert re.search(r"no later than \d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC\.", over.json()["detail"]), over.text
        assert not re.search(r"\d{4}-\d{2}-\d{2}T", over.json()["detail"])   # no raw timestamp
        # The ceiling itself is accepted.
        ok = admin.post(f"/shares/{share['id']}/extend", json={"expires_at": mine["extend_ceiling"] + "Z"})
        assert ok.status_code == 200, ok.text

        rtag = admin.post("/receiver-tags", json={"name": unique("rt"), "min_token_len": 6, "require_secret": "none",
                                                  "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                                  "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
        rec = admin.post("/receivers", json={"tag_id": rtag["id"], "max_total_bytes": 10 * _MB, "ttl_hours": 24}).json()
        rec_listed = next(r for r in admin.get("/receivers").json()["receivers"] if r["id"] == rec["id"])
        assert _parse(rec_listed["extend_ceiling"]) == (_parse(rec_listed["created_at"]) + timedelta(hours=72)).replace(microsecond=0)
        assert rec_listed["files_in_vault"] == 0

        fid = admin.post(f"/vaults/{v['id']}/files", files=[("files", ("a.txt", b"x", "text/plain"))]).json()["files"][0]["id"]
        ltag = admin.post("/note-link-tags", json={"name": unique("lt"), "auto_enroll_new_users": True,
                                                   "allowed_targets": ["file", "folder", "note"],
                                                   "default_ttl_hours": 24, "max_ttl_hours": 48})
        if ltag.status_code != 200:
            pytest.skip(f"no link tag here: {ltag.status_code} {ltag.text[:100]}")
        link = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file", "target_file_id": fid,
                                                  "tag_id": ltag.json()["id"], "ttl_hours": 24}).json()
        link_listed = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link["id"])
        assert _parse(link_listed["extend_ceiling"]) == (_parse(link_listed["created_at"]) + timedelta(hours=48)).replace(microsecond=0)

        note = admin.post("/notes", json={"title": unique("n"), "body": "ceiling"}).json()
        nlink = admin.post("/note-links", json={"note_id": note["id"], "tag_id": ltag.json()["id"], "ttl_hours": 24})
        if nlink.status_code == 200:
            nl = next(l for l in admin.get("/note-links").json()["links"] if l["id"] == nlink.json()["id"])
            assert _parse(nl["extend_ceiling"]) == (_parse(nl["created_at"]) + timedelta(hours=48)).replace(microsecond=0)
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={k: settings_before.get(k) for k in
                                     ("public_receivers_enabled", "public_receiver_user_cap", "public_file_links_enabled")})


def test_an_administrator_who_extends_a_users_public_or_upload_link_gets_only_the_expiry(admin):
    settings_before = admin.get("/settings").json()
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50,
                                 "public_file_links_enabled": True})
    owner = admin.create_user(role="user")
    co = ApiClient(); co.login(owner["_username"], owner["_password"])
    v = co.create_vault(name=unique("adminext"))
    try:
        rtag = admin.post("/receiver-tags", json={"name": unique("rt"), "min_token_len": 6, "require_secret": "none",
                                                  "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                                  "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
        rec = co.post("/receivers", json={"tag_id": rtag["id"], "max_total_bytes": 10 * _MB, "ttl_hours": 24,
                                          "label": "Client returns"})
        assert rec.status_code in (200, 201), rec.text
        r = admin.post(f"/receivers/{rec.json()['id']}/extend",
                       json={"expires_at": _iso(_parse(rec.json()["expires_at"]) + timedelta(hours=1))})
        assert r.status_code == 200, r.text
        assert set(r.json()) == {"id", "expires_at", "ceiling"}, r.json()
        fid = co.post(f"/vaults/{v['id']}/files", files=[("files", ("a.txt", b"x", "text/plain"))]).json()["files"][0]["id"]
        ltag = admin.post("/note-link-tags", json={"name": unique("lt"), "auto_enroll_new_users": True,
                                                   "allowed_targets": ["file", "folder", "note"],
                                                   "default_ttl_hours": 24, "max_ttl_hours": 48})
        if ltag.status_code != 200:
            pytest.skip(f"no link tag here: {ltag.status_code} {ltag.text[:100]}")
        link = co.post("/public-links", json={"vault_id": v["id"], "target_type": "file", "target_file_id": fid,
                                               "tag_id": ltag.json()["id"], "ttl_hours": 24})
        assert link.status_code == 200, link.text
        r = admin.post(f"/public-links/{link.json()['id']}/extend",
                       json={"expires_at": _iso(_parse(link.json()["expires_at"]) + timedelta(hours=1))})
        assert r.status_code == 200, r.text
        assert set(r.json()) == {"id", "expires_at", "ceiling"}, r.json()
    finally:
        co.delete_vault(v["id"])
        admin.delete_user(owner["id"])
        admin.put("/settings", json={k: settings_before.get(k) for k in
                                     ("public_receivers_enabled", "public_receiver_user_cap", "public_file_links_enabled")})


def test_a_link_is_extended_only_while_it_could_still_be_made(admin):
    settings_before = admin.get("/settings").json()
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    try:
        rtag = admin.post("/receiver-tags", json={"name": unique("rr"), "min_token_len": 6, "require_secret": "none",
                                                  "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True,
                                                  "default_ttl_hours": 24, "max_ttl_hours": 72}).json()
        rec = admin.post("/receivers", json={"tag_id": rtag["id"], "max_total_bytes": 10 * _MB, "ttl_hours": 24}).json()
        later = _iso(_parse(rec["expires_at"]) + timedelta(hours=2))
        # Upload links switched off: the feature's own refusal.
        admin.put("/settings", json={"public_receivers_enabled": False})
        r = admin.post(f"/receivers/{rec['id']}/extend", json={"expires_at": later})
        assert r.status_code == 403 and "disabled on this deployment" in r.text, r.text
        admin.put("/settings", json={"public_receivers_enabled": True})
        # The link's type retired: no longer extended.
        assert admin.delete(f"/receiver-tags/{rtag['id']}").status_code in (200, 204)
        r = admin.post(f"/receivers/{rec['id']}/extend", json={"expires_at": later})
        assert r.status_code == 400 and "inactive" in r.text, r.text
    finally:
        admin.put("/settings", json={k: settings_before.get(k) for k in
                                     ("public_receivers_enabled", "public_receiver_user_cap")})
