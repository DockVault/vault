"""Live API: public FILE / FOLDER links (secure send, outbound).

Creation is authenticated + step-up-gated (a no-op unless an admin turns require_otp on for
`public_link.create`) + feature-gated (`public_file_links_enabled`, default OFF) + tag-governed
(a note-link tag must list the target kind in `allowed_targets`) + per-user capped (a budget SHARED
with note links) + tighten-only. The URL token is stored HASHED and returned ONCE. Redemption +
download (the anonymous read path) are a later slice, so these tests cover create / list / policy /
revoke / delete / admin-oversight only.
"""
import hashlib
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20)


@pytest.fixture
def files_enabled(admin):
    """Turn public FILE links on for the test, restoring the prior settings after."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_links_enabled",
                                       "public_note_link_user_cap")}
    admin.put("/settings", json={"public_file_links_enabled": True,
                                 "public_note_links_enabled": True,
                                 "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _mk_tag(admin, targets=("file", "folder"), **over):
    payload = {"name": unique("pltag"), "min_token_len": 6, "require_secret": "none",
               "min_pin_len": 4, "password_min_len": 8, "auto_enroll_new_users": True,
               "allowed_targets": list(targets)}
    payload.update(over)
    r = admin.post("/note-link-tags", json=payload)
    r.raise_for_status()
    return r.json()


def _upload(client, vid, name, content=b"hello world"):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text


def _file_id(client, vid, name):
    for it in client.get(f"/vaults/{vid}/files").json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    raise AssertionError(f"file {name} not found")


def _mk_folder(client, vid, name):
    r = client.post(f"/vaults/{vid}/folders", json={"name": name})
    r.raise_for_status()
    return r.json()["folder"]["id"]


# --- feature gate -----------------------------------------------------------------------------------
def test_default_off_and_settings_flag(admin):
    # Default OFF: the settings blob reports the flag, and a create attempt is 403 while off.
    before = admin.get("/settings").json()
    assert "public_file_links_enabled" in before
    admin.put("/settings", json={"public_file_links_enabled": False})
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "a.txt")
        fid = _file_id(admin, v["id"], "a.txt")
        tag = _mk_tag(admin)  # tag creation is unaffected by the master switch
        r = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": tag["id"]})
        assert r.status_code == 403, r.text
    finally:
        admin.delete_vault(v["id"])


# --- create + hashed token --------------------------------------------------------------------------
def test_create_file_link_returns_token_once_and_stores_hash(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "doc.txt", b"file body")
        fid = _file_id(admin, v["id"], "doc.txt")
        tag = _mk_tag(admin, min_token_len=10)
        r = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": tag["id"]})
        assert r.status_code == 200, r.text
        link = r.json()
        assert link["kind"] == "public" and link["target_type"] == "file"
        assert link["secret_kind"] == "none"
        token = link["token"]
        assert len(token) == 10
        assert link["url_path"] == f"/p/{token}"

        # The token is NEVER returned again by the list endpoint.
        mine = {l["id"]: l for l in admin.get("/public-links").json()["links"]}
        assert link["id"] in mine
        row = mine[link["id"]]
        assert "token" not in row and "url_path" not in row
        assert row["target_file_id"] == fid and row["status"] == "active"

        # The DB stores only the sha256 HASH — never the plaintext token.
        want = hashlib.sha256(token.encode()).hexdigest()
        out = _psql(f"SELECT token_hash FROM public_links WHERE id='{link['id']}';")
        assert out.returncode == 0, out.stderr
        assert out.stdout.strip() == want
        # A plaintext-token column must not exist at all.
        cols = _psql("SELECT column_name FROM information_schema.columns "
                     "WHERE table_name='public_links';").stdout
        assert "token_hash" in cols and "\ntoken\n" not in ("\n" + cols)
    finally:
        admin.delete_vault(v["id"])


def test_create_folder_link(admin, files_enabled):
    v = admin.create_vault()
    try:
        folder_id = _mk_folder(admin, v["id"], unique("dir"))
        tag = _mk_tag(admin, targets=("folder",))
        r = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "folder",
                                              "target_folder_id": folder_id, "tag_id": tag["id"]})
        assert r.status_code == 200, r.text
        assert r.json()["target_type"] == "folder" and r.json()["target_folder_id"] == folder_id
    finally:
        admin.delete_vault(v["id"])


# --- tag governs the target kind --------------------------------------------------------------------
def test_tag_must_permit_the_target_kind(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "x.txt")
        fid = _file_id(admin, v["id"], "x.txt")
        # A note-only tag (the safe default) refuses a file link.
        note_only = _mk_tag(admin, targets=("note",))
        r = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": note_only["id"]})
        assert r.status_code == 400, r.text
        # A folder-only tag refuses a FILE link.
        folder_only = _mk_tag(admin, targets=("folder",))
        r2 = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                               "target_file_id": fid, "tag_id": folder_only["id"]})
        assert r2.status_code == 400, r2.text
    finally:
        admin.delete_vault(v["id"])


def test_default_note_link_tags_do_not_permit_files(admin, files_enabled):
    # The seeded Open/Restricted/Confidential tags default to note-only, so they cannot mint file links
    # until an admin opts them in — no deployment wakes up exposing files.
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "y.txt")
        fid = _file_id(admin, v["id"], "y.txt")
        open_tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == "Open")
        assert open_tag["allowed_targets"] == ["note"]
        r = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": open_tag["id"]})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(v["id"])


# --- tighten-only + secrets -------------------------------------------------------------------------
def test_tighten_only_and_strengthen_secret(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "z.txt")
        fid = _file_id(admin, v["id"], "z.txt")
        tag = _mk_tag(admin, min_token_len=12)
        # token below the tag floor -> 400
        r = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": tag["id"],
                                              "token_len": 8})
        assert r.status_code == 400, r.text
        # a tag mandating a password can't be loosened to none -> 400
        ptag = _mk_tag(admin, require_secret="password", password_min_len=8)
        r2 = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                               "target_file_id": fid, "tag_id": ptag["id"],
                                               "secret_kind": "none"})
        assert r2.status_code == 400, r2.text
        # a no-secret tag may be STRENGTHENED with a pin
        otag = _mk_tag(admin)
        r3 = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                               "target_file_id": fid, "tag_id": otag["id"],
                                               "secret_kind": "pin", "pin": "1234"})
        assert r3.status_code == 200 and r3.json()["secret_kind"] == "pin"
    finally:
        admin.delete_vault(v["id"])


# --- ZK / password-protected refusals ---------------------------------------------------------------
def test_password_protected_vault_and_target_refused(admin, files_enabled):
    # A vault with a password refuses public links.
    pv = admin.create_vault(password="VaultPass123")
    try:
        # Upload needs the vault password.
        r = pv and admin.post(f"/vaults/{pv['id']}/files",
                              files=[("files", ("p.txt", b"x", "text/plain"))],
                              headers={"X-Vault-Password": "VaultPass123"})
        assert r.status_code in (200, 201), r.text
        fid = None
        for it in admin.get(f"/vaults/{pv['id']}/files",
                            headers={"X-Vault-Password": "VaultPass123"}).json()["items"]:
            if it.get("name") == "p.txt":
                fid = it["id"]
        tag = _mk_tag(admin)
        rr = admin.post("/public-links", json={"vault_id": pv["id"], "target_type": "file",
                                               "target_file_id": fid, "tag_id": tag["id"]})
        assert rr.status_code == 400, rr.text
    finally:
        admin.delete_vault(pv["id"], vault_password="VaultPass123")


def test_zero_knowledge_vault_refused(admin, files_enabled):
    from conftest import create_zk_vault
    try:
        zk = create_zk_vault(admin, name=unique("zk"))
    except Exception:
        pytest.skip("ZK vault creation unavailable in this environment")
    try:
        tag = _mk_tag(admin, targets=("folder",))
        # No real target needed: the ZK refusal fires before target resolution when a folder id is
        # supplied, but we pass a random one to reach the vault-type gate.
        import uuid as _uuid
        r = admin.post("/public-links", json={"vault_id": zk["id"], "target_type": "folder",
                                              "target_folder_id": str(_uuid.uuid4()), "tag_id": tag["id"]})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(zk["id"])


# --- shared per-user cap (note links + public links) ------------------------------------------------
def test_shared_cap_counts_notes_and_files(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_links_enabled",
                                       "public_note_link_user_cap")}
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True,
                                 "public_note_link_user_cap": 1})
    u = admin.create_user(role="user")
    user = ApiClient(BASE_URL); user.login(u["_username"], u["_password"])
    v = user.create_vault()
    try:
        # One note link fills the shared budget of 1.
        note_id = user.post("/notes", json={"title": "n", "body": "b"}).json()["id"]
        open_tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == "Open")
        n1 = user.post("/note-links", json={"note_id": note_id, "tag_id": open_tag["id"]})
        assert n1.status_code == 200, n1.text
        # A FILE link is now refused (409) — the budget is shared.
        _upload(user, v["id"], "c.txt")
        fid = _file_id(user, v["id"], "c.txt")
        ftag = _mk_tag(admin)
        f1 = user.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": ftag["id"]})
        assert f1.status_code == 409, f1.text
        # Revoking the note frees the shared slot -> the file link now succeeds.
        assert user.post(f"/note-links/{n1.json()['id']}/revoke").status_code == 200
        f2 = user.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                              "target_file_id": fid, "tag_id": ftag["id"]})
        assert f2.status_code == 200, f2.text
        # ...and the reverse direction: the shared budget (now filled by the file link) blocks a NOTE
        # link too — the note-link create must count public file links, not just its own kind.
        note_id = user.post("/notes", json={"title": "n2", "body": "b2"}).json()["id"]
        n2 = user.post("/note-links", json={"note_id": note_id, "tag_id": open_tag["id"]})
        assert n2.status_code == 409, n2.text
    finally:
        user.delete_vault(v["id"])
        admin.delete_user(u["id"])
        admin.put("/settings", json=snap)


# --- owner isolation + revoke/delete ----------------------------------------------------------------
def test_owner_isolation_and_lifecycle(admin, files_enabled):
    v = admin.create_vault()
    u = admin.create_user(role="user")
    other = ApiClient(BASE_URL); other.login(u["_username"], u["_password"])
    try:
        _upload(admin, v["id"], "own.txt")
        fid = _file_id(admin, v["id"], "own.txt")
        tag = _mk_tag(admin)
        link = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                                 "target_file_id": fid, "tag_id": tag["id"]}).json()
        # Someone else's link is invisible and unmanageable.
        assert other.get("/public-links").json()["links"] == []
        assert other.post(f"/public-links/{link['id']}/revoke").status_code == 404
        assert other.delete(f"/public-links/{link['id']}").status_code == 404
        # Owner revokes -> status revoked; then deletes -> gone.
        assert admin.post(f"/public-links/{link['id']}/revoke").status_code == 200
        row = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link["id"])
        assert row["status"] == "revoked" and row["revoked"] is True
        assert admin.delete(f"/public-links/{link['id']}").status_code == 200
        assert all(l["id"] != link["id"] for l in admin.get("/public-links").json()["links"])
    finally:
        admin.delete_user(u["id"])
        admin.delete_vault(v["id"])


# --- policy reader ----------------------------------------------------------------------------------
def test_public_link_policy_reader(admin, files_enabled):
    file_tag = _mk_tag(admin, targets=("file",))
    p = admin.get("/public-link-policy").json()
    assert p["enabled"] is True
    assert isinstance(p["user_cap"], int) and isinstance(p["remaining"], int)
    names = {t["name"] for t in p["tags"]}
    assert file_tag["name"] in names
    row = next(t for t in p["tags"] if t["name"] == file_tag["name"])
    assert "file" in row["targets"]
    # allowlist internals never leak
    for leak in ("allowed_user_ids", "blocked_user_ids", "allowed_department_ids", "auto_enroll_new_users"):
        assert leak not in row, f"leaked {leak}"
    # The default seeded note-only tags must NOT appear (they permit no file/folder target).
    assert "Open" not in names and "Restricted" not in names


def test_policy_off_returns_no_tags(admin):
    before = admin.get("/settings").json().get("public_file_links_enabled")
    admin.put("/settings", json={"public_file_links_enabled": False})
    try:
        p = admin.get("/public-link-policy").json()
        assert p["enabled"] is False and p["tags"] == []
    finally:
        admin.put("/settings", json={"public_file_links_enabled": bool(before)})


# --- admin oversight --------------------------------------------------------------------------------
def test_admin_lists_and_revokes(admin, files_enabled):
    u = admin.create_user(role="user")
    user = ApiClient(BASE_URL); user.login(u["_username"], u["_password"])
    v = user.create_vault()
    try:
        _upload(user, v["id"], "shared.txt")
        fid = _file_id(user, v["id"], "shared.txt")
        tag = _mk_tag(admin)
        link = user.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                                "target_file_id": fid, "tag_id": tag["id"]}).json()
        data = admin.get("/admin/public-links").json()
        row = next((x for x in data["links"] if x["id"] == link["id"]), None)
        assert row is not None and row["owner"] == u["_username"]
        # Admin oversight must never expose a redeemable token or URL.
        assert "token" not in row and "url_path" not in row
        assert data["active_count"] >= 1
        # Admin revoke, then bulk revoke-all.
        assert admin.post(f"/admin/public-links/{link['id']}/revoke").status_code == 200
        link2 = user.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                                 "target_file_id": fid, "tag_id": tag["id"]}).json()
        r = admin.post("/admin/public-links/revoke-all")
        assert r.status_code == 200 and r.json()["revoked_count"] >= 1
        row2 = next(x for x in admin.get("/admin/public-links").json()["links"] if x["id"] == link2["id"])
        assert row2["status"] == "revoked"
    finally:
        user.delete_vault(v["id"])
        admin.delete_user(u["id"])


def test_admin_endpoints_require_admin(admin, files_enabled):
    u = admin.create_user(role="user")
    user = ApiClient(BASE_URL); user.login(u["_username"], u["_password"])
    try:
        assert user.get("/admin/public-links").status_code == 403
        assert user.post("/admin/public-links/revoke-all").status_code == 403
        import uuid as _uuid
        assert user.post(f"/admin/public-links/{_uuid.uuid4()}/revoke").status_code == 403
    finally:
        admin.delete_user(u["id"])


# --- temp session -----------------------------------------------------------------------------------
def test_temp_session_cannot_create(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "t.txt")
        fid = _file_id(admin, v["id"], "t.txt")
        tag = _mk_tag(admin)
        tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
        temp = ApiClient(BASE_URL); temp.login(tc["temp_username"], tc["credential"])
        r = temp.post("/public-links", json={"vault_id": v["id"], "target_type": "file",
                                             "target_file_id": fid, "tag_id": tag["id"]})
        assert r.status_code == 403, r.text
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")
    finally:
        admin.delete_vault(v["id"])
