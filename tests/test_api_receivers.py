"""Live API: receivers (anonymous inbound "upload links") — admin tags, create, policy, lifecycle,
admin oversight. The anonymous UPLOAD path is a separate slice, so these cover the authenticated
half only (create the owner-paid vault, freeze the tighten-only policy, hashed token, revoke/pause).
"""
import hashlib
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_MB = 1024 * 1024


def _psql(sql):
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20)


@pytest.fixture
def receivers_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _mk_tag(admin, kind_floor="standard", **over):
    payload = {"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
               "min_pin_len": 4, "password_min_len": 8, "auto_enroll_new_users": True,
               "kind_floor": kind_floor, "max_total_bytes_cap": 50 * _MB,
               "max_file_bytes_cap": 10 * _MB, "retention_max_days": 30, "retention_default_days": 7}
    payload.update(over)
    r = admin.post("/receiver-tags", json=payload)
    r.raise_for_status()
    return r.json()


def _mk_receiver(admin, tag=None, **over):
    tag = tag or _mk_tag(admin)
    body = {"tag_id": tag["id"], "max_total_bytes": 10 * _MB}
    body.update(over)
    r = admin.post("/receivers", json=body)
    r.raise_for_status()
    return r.json()


# --- feature gate + settings ------------------------------------------------------------------------
def test_default_off_and_settings_flag(admin):
    before = admin.get("/settings").json()
    assert "public_receivers_enabled" in before and "public_receiver_user_cap" in before
    admin.put("/settings", json={"public_receivers_enabled": False})
    tag = _mk_tag(admin)   # tag creation unaffected by the master switch
    r = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB})
    assert r.status_code == 403, r.text


# --- admin tag CRUD ---------------------------------------------------------------------------------
def test_admin_tag_crud_and_validation(admin):
    tag = _mk_tag(admin, retention_default_days=5)
    assert tag["kind_floor"] == "standard" and tag["retention_default_days"] == 5
    # visible in the admin list
    assert any(t["id"] == tag["id"] for t in admin.get("/receiver-tags").json())
    # patch
    p = admin.patch(f"/receiver-tags/{tag['id']}", json={"retention_default_days": 3})
    assert p.status_code == 200 and p.json()["retention_default_days"] == 3
    # invalid patch (default > max) rejected
    bad = admin.patch(f"/receiver-tags/{tag['id']}", json={"retention_default_days": 999})
    assert bad.status_code == 400, bad.text
    # deactivate
    d = admin.delete(f"/receiver-tags/{tag['id']}")
    assert d.status_code == 200 and d.json()["is_active"] is False
    # non-admin blocked
    u = admin.create_user(role="user")
    user = ApiClient(BASE_URL); user.login(u["_username"], u["_password"])
    try:
        assert user.get("/receiver-tags").status_code == 403
        assert user.post("/receiver-tags", json={"name": unique("x")}).status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_seeded_default_tags_present(admin):
    names = {t["name"] for t in admin.get("/receiver-tags").json()}
    assert {"Drop box", "Confidential inbox"} <= names, names


# --- create + hashed token + owner-paid vault -------------------------------------------------------
def test_create_receiver_returns_token_once_and_stores_hash(admin, receivers_enabled):
    tag = _mk_tag(admin, min_token_len=10)
    r = admin.post("/receivers", json={"tag_id": tag["id"], "label": "My drop", "max_total_bytes": 10 * _MB})
    assert r.status_code == 200, r.text
    rec = r.json()
    assert rec["kind"] == "standard" and rec["label"] == "My drop"
    assert rec["max_total_bytes"] == 10 * _MB and rec["retention_days"] == 7
    token = rec["token"]
    assert len(token) == 10 and rec["url_path"] == f"/u/{token}"

    # list never returns the token
    mine = {x["id"]: x for x in admin.get("/receivers").json()["receivers"]}
    assert rec["id"] in mine
    assert "token" not in mine[rec["id"]] and "url_path" not in mine[rec["id"]]

    # DB stores only the sha256 hash
    want = hashlib.sha256(token.encode()).hexdigest()
    out = _psql(f"SELECT token_hash FROM receivers WHERE id='{rec['id']}';")
    assert out.returncode == 0 and out.stdout.strip() == want, out.stderr or out.stdout

    # A dedicated Standard vault was created, owner-paid (size_limit funded by an owner grant).
    vout = _psql(f"SELECT type, size_limit FROM vaults WHERE id='{rec['vault_id']}';")
    assert vout.returncode == 0 and "standard" in vout.stdout and str(10 * _MB) in vout.stdout, vout.stdout
    gout = _psql(f"SELECT granted_bytes FROM vault_storage_grants WHERE vault_id='{rec['vault_id']}';")
    assert str(10 * _MB) in gout.stdout, gout.stdout


# --- policy reader ----------------------------------------------------------------------------------
def test_receiver_policy_reader(admin, receivers_enabled):
    std = _mk_tag(admin, kind_floor="standard")
    p = admin.get("/receiver-policy").json()
    assert p["enabled"] is True and isinstance(p["remaining"], int)
    names = {t["name"] for t in p["tags"]}
    assert std["name"] in names
    row = next(t for t in p["tags"] if t["name"] == std["name"])
    for leak in ("allowed_user_ids", "blocked_user_ids", "allowed_department_ids", "auto_enroll_new_users"):
        assert leak not in row, f"leaked {leak}"
    # confidential-floor tags are hidden in v1
    assert "Confidential inbox" not in names


def test_policy_off_returns_no_tags(admin):
    before = admin.get("/settings").json().get("public_receivers_enabled")
    admin.put("/settings", json={"public_receivers_enabled": False})
    try:
        p = admin.get("/receiver-policy").json()
        assert p["enabled"] is False and p["tags"] == []
    finally:
        admin.put("/settings", json={"public_receivers_enabled": bool(before)})


# --- tighten-only + required size + confidential deferral --------------------------------------------
def test_tighten_only_and_required_size(admin, receivers_enabled):
    tag = _mk_tag(admin, min_token_len=12, max_total_bytes_cap=50 * _MB)
    # token below floor -> 400
    assert admin.post("/receivers", json={"tag_id": tag["id"], "token_len": 8,
                                          "max_total_bytes": 10 * _MB}).status_code == 400
    # total over the cap -> 400
    assert admin.post("/receivers", json={"tag_id": tag["id"], "token_len": 12,
                                          "max_total_bytes": 100 * _MB}).status_code == 400
    # a tag with NO total cap still requires the creator to choose a size
    nocap = _mk_tag(admin, max_total_bytes_cap=None)
    assert admin.post("/receivers", json={"tag_id": nocap["id"]}).status_code == 400


def test_confidential_receiver_deferred(admin, receivers_enabled):
    # A confidential-floor tag can't mint a receiver yet (envelope deferred) -> 400.
    conf = _mk_tag(admin, kind_floor="confidential", require_secret="password", password_min_len=8)
    r = admin.post("/receivers", json={"tag_id": conf["id"], "password": "hunter2x",
                                       "max_total_bytes": 10 * _MB})
    assert r.status_code == 400, r.text
    # asking for confidential kind on a standard tag is likewise refused in v1
    std = _mk_tag(admin)
    r2 = admin.post("/receivers", json={"tag_id": std["id"], "kind": "confidential",
                                        "max_total_bytes": 10 * _MB})
    assert r2.status_code == 400, r2.text


# --- per-user cap -----------------------------------------------------------------------------------
def test_per_user_cap(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 1})
    u = admin.create_user(role="user")
    user = ApiClient(BASE_URL); user.login(u["_username"], u["_password"])
    try:
        tag = _mk_tag(admin, auto_enroll_new_users=True)
        first = user.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 5 * _MB})
        assert first.status_code == 200, first.text
        second = user.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 5 * _MB})
        assert second.status_code == 409, second.text
        assert user.post(f"/receivers/{first.json()['id']}/revoke").status_code == 200
        assert user.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 5 * _MB}).status_code == 200
    finally:
        admin.delete_user(u["id"])
        admin.put("/settings", json=snap)


# --- owner isolation + pause/revoke -----------------------------------------------------------------
def test_owner_isolation_and_pause_revoke(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    u = admin.create_user(role="user")
    other = ApiClient(BASE_URL); other.login(u["_username"], u["_password"])
    try:
        assert other.get("/receivers").json()["receivers"] == []
        assert other.post(f"/receivers/{rec['id']}/revoke").status_code == 404
        assert other.post(f"/receivers/{rec['id']}/pause", json={"paused": True}).status_code == 404
        # pause + resume
        assert admin.post(f"/receivers/{rec['id']}/pause", json={"paused": True}).json()["paused"] is True
        row = next(x for x in admin.get("/receivers").json()["receivers"] if x["id"] == rec["id"])
        assert row["status"] == "paused"
        assert admin.post(f"/receivers/{rec['id']}/pause", json={"paused": False}).json()["paused"] is False
        # revoke
        assert admin.post(f"/receivers/{rec['id']}/revoke").status_code == 200
        row2 = next(x for x in admin.get("/receivers").json()["receivers"] if x["id"] == rec["id"])
        assert row2["status"] == "revoked" and row2["revoked"] is True
    finally:
        admin.delete_user(u["id"])


# --- admin oversight --------------------------------------------------------------------------------
def test_admin_oversight(admin, receivers_enabled):
    u = admin.create_user(role="user")
    user = ApiClient(BASE_URL); user.login(u["_username"], u["_password"])
    try:
        tag = _mk_tag(admin, auto_enroll_new_users=True)
        rec = user.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 5 * _MB}).json()
        data = admin.get("/admin/receivers").json()
        row = next((x for x in data["receivers"] if x["id"] == rec["id"]), None)
        assert row is not None and row["owner"] == u["_username"]
        assert "token" not in row and "url_path" not in row
        assert data["active_count"] >= 1
        assert admin.post(f"/admin/receivers/{rec['id']}/revoke").status_code == 200
        # non-admin blocked
        assert user.get("/admin/receivers").status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_wrapped_vault_is_policy_frozen(admin, receivers_enabled):
    # The receiver's vault is frozen: retention can't be changed and size can't be raised above the
    # receiver's cap through the ordinary vault-settings route, and only READ grants are allowed.
    rec = _mk_receiver(admin, max_total_bytes=10 * _MB)
    vid = rec["vault_id"]
    try:
        # retention change refused
        assert admin.patch(f"/vaults/{vid}/settings",
                           json={"expire_files_after_days": 999}).status_code == 400
        # raising the size above the receiver cap refused
        assert admin.patch(f"/vaults/{vid}/settings",
                           json={"size_limit": 100 * _MB}).status_code == 400
        # a size within the cap is allowed
        assert admin.patch(f"/vaults/{vid}/settings",
                           json={"size_limit": 8 * _MB}).status_code == 200
        # the storage route can't be a backdoor to inflate the receiver vault above its cap
        assert admin.put(f"/vaults/{vid}/storage",
                         json={"granted_bytes": 100 * _MB}).status_code == 400
        # non-read grant refused; read grant allowed
        u = admin.create_user(role="user")
        try:
            w = admin.post(f"/vaults/{vid}/permissions", json={"user_id": u["id"], "level": "write"})
            assert w.status_code == 400, w.text
            r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": u["id"], "level": "read"})
            assert r.status_code in (200, 201), r.text
        finally:
            admin.delete_user(u["id"])
    finally:
        admin.delete_vault(vid)


def test_temp_session_cannot_create(admin, receivers_enabled):
    tag = _mk_tag(admin)
    tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient(BASE_URL); temp.login(tc["temp_username"], tc["credential"])
    try:
        r = temp.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 5 * _MB})
        assert r.status_code == 403, r.text
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")
