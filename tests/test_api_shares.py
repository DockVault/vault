"""Share creation + list-mine (POST /shares, GET /shares). No claim/enforcement yet.

Covers the fail-closed create path (sharing off, temp session, no vault access, zero-knowledge vault,
password-protected vault, tag create-allowlist, audience-within-tag, limits-within-caps, target-in-vault)
plus the happy path (limit snapshot + show-once link token) and that GET /shares never leaks the token.
"""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    """Run a small SQL statement in the test DB (deterministic setup that the API doesn't expose)."""
    subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _set_vault_type(vault_id, vtype):
    """Flip a vault's confidentiality type directly (deterministic; avoids the ZK create/ECC setup)."""
    _psql(f"UPDATE vaults SET type='{vtype}' WHERE id='{vault_id}'")


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _permissive_tag(admin, **over):
    """A tag the admin may create with (auto-enroll), all audiences, generous caps."""
    body = {"name": unique("shtag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["users", "departments", "anyone_internal"],
            "max_recipients_cap": 10, "max_downloads_cap": 10, "allow_view_only": True}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _share_body(v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
            "claim_audience": "anyone_internal"}
    body.update(over)
    return body


def test_create_whole_vault_share_and_show_once_token(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin)
    v = admin.create_vault(name=unique("shv"))
    try:
        r = admin.post("/shares", json=_share_body(v, tag))
        assert r.status_code == 200, r.text
        share = r.json()
        assert share["target_type"] == "vault" and share["status"] == "active"
        assert share["has_link"] is True
        assert isinstance(share.get("link_token"), str) and len(share["link_token"]) >= 20  # shown ONCE
        assert share["view_only"] is False and share["max_recipients"] == 10  # tag cap (default clamps to it)
        # GET /shares lists it but NEVER returns the token again
        row = next(s for s in admin.get("/shares").json() if s["id"] == share["id"])
        assert row["has_link"] is True and "link_token" not in row and row["claim_count"] == 0
    finally:
        admin.delete_vault(v["id"])


def test_create_refused_when_sharing_off(admin):
    tag = _permissive_tag(admin)
    v = admin.create_vault(name=unique("shoff"))
    try:
        _enable_sharing(admin, False)
        assert admin.post("/shares", json=_share_body(v, tag)).status_code == 403
    finally:
        _enable_sharing(admin, True)
        admin.delete_vault(v["id"])


def test_zk_and_password_protected_vaults_refused(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin)
    vzk = admin.create_vault(name=unique("shzk"))
    _set_vault_type(vzk["id"], "zero_knowledge")
    r = admin.post("/shares", json=_share_body(vzk, tag))
    assert r.status_code == 400 and "zero-knowledge" in r.text.lower()
    _set_vault_type(vzk["id"], "standard")  # restore so teardown works
    admin.delete_vault(vzk["id"])

    vpw = admin.create_vault(name=unique("shpw"), password="Vault-Secret-123")
    try:
        r = admin.post("/shares", json=_share_body(vpw, tag))
        assert r.status_code == 400 and "password" in r.text.lower()
    finally:
        admin.delete_vault(vpw["id"], vault_password="Vault-Secret-123")


def test_create_allowlist_fail_closed_even_for_admin(admin):
    _enable_sharing(admin, True)
    # a tag NO ONE may create with (auto-enroll off + empty allowlist) — there is no admin bypass
    tag = admin.post("/share-tags", json={"name": unique("locked"), "auto_enroll_new_users": False,
                                          "allowed_audiences": ["anyone_internal"]}).json()
    v = admin.create_vault(name=unique("shlock"))
    try:
        r = admin.post("/shares", json=_share_body(v, tag))
        assert r.status_code == 403 and "not allowed" in r.text.lower()
    finally:
        admin.delete_vault(v["id"])


def test_audience_must_be_allowed_by_tag(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin, allowed_audiences=["users"])  # only the 'users' audience
    u = admin.create_user(role="user")
    v = admin.create_vault(name=unique("shaud"))
    try:
        assert admin.post("/shares", json=_share_body(v, tag, claim_audience="anyone_internal")).status_code == 400
        assert admin.post("/shares", json=_share_body(v, tag, claim_audience="users", audience_user_ids=[])).status_code == 400
        assert admin.post("/shares", json=_share_body(
            v, tag, claim_audience="users",
            audience_user_ids=["00000000-0000-0000-0000-000000000000"])).status_code == 400
        # a valid user-audience share succeeds
        r = admin.post("/shares", json=_share_body(v, tag, claim_audience="users", audience_user_ids=[u["id"]]))
        assert r.status_code == 200 and r.json()["audience_user_ids"] == [u["id"]]
    finally:
        admin.delete_vault(v["id"])
        admin.delete_user(u["id"])


def test_limit_override_within_and_over_cap(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin, max_recipients_cap=3)
    v = admin.create_vault(name=unique("shlim"))
    try:
        r = admin.post("/shares", json=_share_body(v, tag, max_recipients=2))
        assert r.status_code == 200 and r.json()["max_recipients"] == 2
        assert admin.post("/shares", json=_share_body(v, tag, max_recipients=9)).status_code == 400
    finally:
        admin.delete_vault(v["id"])


def test_target_must_belong_to_vault(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin)
    v = admin.create_vault(name=unique("sht"))
    try:
        assert admin.post("/shares", json=_share_body(
            v, tag, target_type="file",
            target_file_id="00000000-0000-0000-0000-000000000000")).status_code == 404
        assert admin.post("/shares", json=_share_body(v, tag, target_type="folder")).status_code == 400
        assert admin.post("/shares", json=_share_body(
            v, tag, target_type="vault",
            target_file_id="00000000-0000-0000-0000-000000000000")).status_code == 400
    finally:
        admin.delete_vault(v["id"])


def test_password_protected_folder_target_refused_and_strict_target(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin)
    v = admin.create_vault(name=unique("shpwf"))
    try:
        r = admin.post(f"/vaults/{v['id']}/folders", json={"name": unique("dir")})
        assert r.status_code == 200, r.text
        body = r.json()
        fid = body.get("id") or (body.get("folder") or {}).get("id")
        assert fid, f"no folder id in {body}"
        # give the folder its OWN password gate; a share must not bypass it (same reason a
        # password-protected vault is refused). The file-target branch mirrors this code.
        _psql(f"UPDATE folders SET password_hash='x' WHERE id='{fid}'")
        r = admin.post("/shares", json=_share_body(v, tag, target_type="folder", target_folder_id=fid))
        assert r.status_code == 400 and "password" in r.text.lower()
        # a folder share must reject a stray file target (strict, like the whole-vault branch)
        _psql(f"UPDATE folders SET password_hash=NULL WHERE id='{fid}'")
        assert admin.post("/shares", json=_share_body(
            v, tag, target_type="folder", target_folder_id=fid,
            target_file_id="00000000-0000-0000-0000-000000000000")).status_code == 400
        # with the password cleared + no stray id, the folder share succeeds
        assert admin.post("/shares", json=_share_body(
            v, tag, target_type="folder", target_folder_id=fid)).status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_creator_without_vault_access_denied(admin, temp_user_client):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin)  # auto-enroll: the non-admin IS tag-allowed, so this isolates the access gate
    v = admin.create_vault(name=unique("shacc"))  # owned by admin; the non-admin has no access
    try:
        assert temp_user_client.post("/shares", json=_share_body(v, tag)).status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_temp_session_cannot_create_or_list_shares(admin):
    _enable_sharing(admin, True)
    tag = _permissive_tag(admin)
    v = admin.create_vault(name=unique("shtmp"))
    try:
        creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
        temp = ApiClient()
        temp.login(creds["temp_username"], creds["credential"])
        assert temp.post("/shares", json=_share_body(v, tag)).status_code == 403
        assert temp.get("/shares").json() == []
    finally:
        admin.delete_vault(v["id"])
