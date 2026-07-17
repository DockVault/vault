"""Temporary credentials, including the validity/expiry override feature.

Covers POST /auth/temp-credentials (self), the /temp-creds/* management
routes, and the admin-creates-for-user route under /api/user-management.
"""
from datetime import datetime, timezone
import json
import os
import subprocess
import uuid

import pytest
import requests

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _stored_scope(temp_username):
    """Read the stored per-vault ID scope for a temp credential straight from the DB, so that
    storage normalization and the delegation clamp are asserted at the source. Returns the
    {"files","folders"} dict, or None for a whole-vault (NULL) grant."""
    q = ("SELECT tcva.scope_ids FROM temp_credential_vault_access tcva "
         "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
         f"WHERE tc.temp_username = '{temp_username}';")
    out = subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", q],
        capture_output=True, text=True, timeout=20)
    val = (out.stdout or "").strip()
    return json.loads(val) if val else None


def _u(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _parse(ts: str) -> datetime:
    # The API must emit JS-parseable UTC, i.e. ...Z (not the broken ...+00:00Z).
    assert not ts.endswith("+00:00Z"), f"malformed timestamp: {ts}"
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_create_default_lifetime(admin):
    r = admin.post("/auth/temp-credentials", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["temp_username"].startswith("temp_")
    assert body["credential"]
    assert body["validity_minutes"] == 65
    assert body["total_lifetime_minutes"] == 65


def test_create_with_custom_validity_applies_expiry(admin):
    r = admin.post("/auth/temp-credentials", json={"validity_minutes": 90})
    assert r.status_code == 200
    body = r.json()
    assert body["validity_minutes"] == 90
    created = _parse(body["created_at"])
    expires = _parse(body["expires_at"])
    delta_min = round((expires - created).total_seconds() / 60)
    assert delta_min == 90


def test_create_with_separate_total_lifetime(admin):
    r = admin.post("/auth/temp-credentials",
                   json={"validity_minutes": 30, "total_lifetime_minutes": 120})
    assert r.status_code == 200
    body = r.json()
    assert body["validity_minutes"] == 30
    assert body["total_lifetime_minutes"] == 120


def test_total_lifetime_never_below_validity(admin):
    # If lifetime < validity is requested, the server clamps lifetime up.
    r = admin.post("/auth/temp-credentials",
                   json={"validity_minutes": 100, "total_lifetime_minutes": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["total_lifetime_minutes"] >= body["validity_minutes"]


@pytest.mark.parametrize("bad", [0, -5, 999999])
def test_validity_out_of_range_rejected(admin, bad):
    r = admin.post("/auth/temp-credentials", json={"validity_minutes": bad})
    assert r.status_code == 422


def test_timestamps_are_js_parseable(admin):
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 45}).json()
    for key in ("created_at", "deactivate_at", "expires_at"):
        ts = body[key]
        assert ts.endswith("Z")
        assert not ts.endswith("+00:00Z")
        _parse(ts)  # raises if unparseable


def test_list_contains_new_credential(admin):
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    r = admin.get("/temp-creds/list")
    assert r.status_code == 200
    assert any(c["temp_username"] == body["temp_username"] for c in r.json())


def test_get_password(admin):
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    r = admin.get(f"/temp-creds/{body['temp_username']}/password")
    # password retrieval may be disabled (one-way hashing) -> 404 acceptable
    assert r.status_code in (200, 404)


def test_deactivate_then_login_fails(admin):
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    r = admin.post(f"/temp-creds/{body['temp_username']}/deactivate")
    assert r.status_code == 200
    # a deactivated credential can no longer authenticate -> a clean 401,
    # not a 500 (pin the status so a crash can't masquerade as "rejected")
    anon = admin.clone_anonymous()
    with pytest.raises(requests.HTTPError) as exc_info:
        anon.login(body["temp_username"], body["credential"])
    assert exc_info.value.response.status_code == 401


def test_terminate_sessions(admin):
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    r = admin.post(f"/temp-creds/{body['temp_username']}/terminate-sessions")
    assert r.status_code == 200
    assert "terminated_count" in r.json()


def test_delete_credential(admin):
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    r = admin.post(f"/temp-creds/{body['temp_username']}/delete")
    assert r.status_code == 200
    r = admin.get("/temp-creds/list")
    assert not any(c["temp_username"] == body["temp_username"] for c in r.json())


def test_admin_creates_temp_cred_for_user(admin, temp_user):
    r = admin.post(
        f"/api/user-management/users/{temp_user['id']}/temp-credentials",
        json={"user_id": temp_user["id"], "validity_minutes": 30},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["temp_username"].startswith("temp_")


def test_temp_create_requires_permission(temp_user_client):
    # the default 'user' role is granted TEMP_CREDS_MANAGE (see app/core/api_catalog.py), so a
    # regular non-admin user can mint their own temporary credentials -> 200.
    r = temp_user_client.post("/auth/temp-credentials", json={"validity_minutes": 30})
    assert r.status_code == 200


def _temp_client(admin, **kw):
    """Create a temp credential and return (logged-in ApiClient, create body)."""
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60, **kw}).json()
    client = admin.clone_anonymous()
    client.login(body["temp_username"], body["credential"])
    return client, body


def test_temp_credential_can_list_vaults(admin):
    """Regression: a temp-credential session 500'd on /vaults because
    get_current_user compared a naive last_activity with an aware cutoff."""
    client, _ = _temp_client(admin)
    assert client.get("/vaults").status_code == 200


def test_temp_creds_list_does_not_leak_session_token(admin):
    """The temp-creds list exposes a session's id + ip but NOT its raw, reusable
    session_token — exposing it would allow session hijacking. Regression."""
    _client, body = _temp_client(admin)  # logging in creates an active session
    listed = admin.get("/temp-creds/list").json()
    mine = [c for c in listed if c["temp_username"] == body["temp_username"]]
    assert mine, "created temp credential not found in list"
    sessions = mine[0]["active_sessions"]
    assert sessions, "expected an active session after temp login (else the test is vacuous)"
    for s in sessions:
        assert "session_token" not in s, f"temp-creds list leaks session_token: {sorted(s)}"
        assert "id" in s  # the non-sensitive identifier is still present


def test_note_round_trips_through_create_and_list(admin):
    note = "Vendor X - Q3 audit"
    body = admin.post("/auth/temp-credentials",
                      json={"validity_minutes": 60, "note": note}).json()
    assert body.get("note") == note
    listed = admin.get("/temp-creds/list").json()
    mine = [c for c in listed if c["temp_username"] == body["temp_username"]]
    assert mine and mine[0].get("note") == note


def test_temp_account_cannot_mint_creds_by_default(admin):
    client, _ = _temp_client(admin, can_create_temp_credentials=False)
    r = client.post("/auth/temp-credentials", json={"validity_minutes": 30})
    assert r.status_code == 403


def test_temp_account_can_mint_creds_when_granted(admin):
    client, _ = _temp_client(admin, can_create_temp_credentials=True)
    r = client.post("/auth/temp-credentials", json={"validity_minutes": 30})
    assert r.status_code == 200


# --- Scoped (least-privilege) temp credentials -----------------------------

def _scoped_client(admin, scope, mode="selected", selected=None):
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": mode,
        "selected_vaults": selected or [],
    }).json()
    c = admin.clone_anonymous()
    c.login(body["temp_username"], body["credential"])
    return c, body


def test_scoped_temp_sees_only_granted_vaults_and_caps(admin):
    """selected-mode hides non-granted vaults; capabilities gate actions. The
    creator here is admin, so this also proves the admin bypass is suppressed."""
    va = admin.create_vault(name=_u("scopeA"))
    vb = admin.create_vault(name=_u("scopeB"))
    try:
        caps = ["vault.see_info", "vault.see_files", "file.download"]
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
                 "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
        c, _ = _scoped_client(admin, scope, "selected", [{"vault_id": va["id"], "caps": caps}])
        ids = [v["id"] for v in c.get("/vaults").json()]
        assert va["id"] in ids and vb["id"] not in ids
        assert c.get(f"/vaults/{va['id']}").status_code == 200
        assert c.get(f"/vaults/{vb['id']}").status_code in (403, 404)
        # read-only: upload is not in the cap set
        r = c.post(f"/vaults/{va['id']}/files", files=[("files", ("x.txt", b"hi", "text/plain"))])
        assert r.status_code == 403
    finally:
        admin.delete_vault(va["id"]); admin.delete_vault(vb["id"])


def test_scoped_temp_page_denied(admin):
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": [], "temp": {}}
    c, _ = _scoped_client(admin, scope, "all")
    assert c.get("/temp-creds/list").status_code == 403          # temp_creds page not granted
    assert c.post("/auth/temp-credentials", json={"validity_minutes": 10}).status_code == 403


def test_scoped_delete_cap_required(admin):
    va = admin.create_vault(name=_u("scopedel"))
    try:
        admin.post(f"/vaults/{va['id']}/files", files=[("files", ("d.txt", b"hi", "text/plain"))])
        fid = admin.get(f"/vaults/{va['id']}/files").json()["items"][0]["id"]
        caps = ["vault.see_info", "vault.see_files"]  # no file.delete
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        c, _ = _scoped_client(admin, scope, "selected", [{"vault_id": va["id"], "caps": caps}])
        assert c.post(f"/vaults/{va['id']}/files/{fid}/delete").status_code == 403
    finally:
        admin.delete_vault(va["id"])


def test_download_cap_implies_see_info_not_see_files(admin):
    """Granting file.download implies vault.see_info (open the vault) but NOT vault.see_files
    (listing/enumeration): a 'download this known file' credential can fetch a file by id, but
    cannot enumerate the vault. Listing is granted separately, so download does not leak the whole
    file list as a side effect (least privilege)."""
    va = admin.create_vault(name=_u("dlonly"))
    try:
        admin.post(f"/vaults/{va['id']}/files", files=[("files", ("f.txt", b"hi", "text/plain"))])
        fid = admin.get(f"/vaults/{va['id']}/files").json()["items"][0]["id"]
        caps = ["file.download"]  # ONLY download — see_info is implied; see_files is NOT
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        c, _ = _scoped_client(admin, scope, "selected", [{"vault_id": va["id"], "caps": caps}])
        assert c.get(f"/vaults/{va['id']}").status_code == 200            # see_info implied (open the vault)
        assert c.get(f"/vaults/{va['id']}/files/{fid}/download").status_code == 200  # fetch a KNOWN file by id
        assert c.get(f"/vaults/{va['id']}/files").status_code == 403      # see_files NOT implied -> no enumeration
    finally:
        admin.delete_vault(va["id"])


def test_see_files_still_grants_listing_when_asked(admin):
    """Granting vault.see_files explicitly still allows listing (the browse case is unchanged) —
    the decouple only stops download from IMPLYING it, it doesn't remove the capability."""
    va = admin.create_vault(name=_u("browse"))
    try:
        admin.post(f"/vaults/{va['id']}/files", files=[("files", ("f.txt", b"hi", "text/plain"))])
        caps = ["vault.see_files", "file.download"]  # listing explicitly granted
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        c, _ = _scoped_client(admin, scope, "selected", [{"vault_id": va["id"], "caps": caps}])
        assert c.get(f"/vaults/{va['id']}/files").status_code == 200      # explicit see_files -> can list
    finally:
        admin.delete_vault(va["id"])


def test_selected_mode_zero_vaults_with_vault_scope_rejected(admin):
    # a vault-scoped credential with no vaults selected can access nothing -> rejected
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info"], "temp": {}}
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected", "selected_vaults": []})
    assert r.status_code == 400, r.text


def test_temp_creds_only_credential_needs_no_vaults(admin):
    # a credential scoped ONLY to temp-cred management (no 'vaults' page) is fine with 0 vaults —
    # and must stay fine even though the real UI always sends the default vault caps checked.
    scope = {"v": 1, "pages": ["temp_creds"], "caps": [],
             "vault_caps_default": ["vault.see_info", "vault.see_files", "file.download"],
             "temp": {"view": True, "create": False, "invalidate": False, "clear": False, "delegate": False}}
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected", "selected_vaults": []})
    assert r.status_code == 200, r.text


def test_selected_mode_only_unresolvable_vaults_rejected(admin):
    # a vaults-scoped credential whose selected_vaults are all unusable (bad id / no id) persists
    # no access grant, so it must be rejected like the empty case.
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info"], "temp": {}}
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": "not-a-uuid"}, {}]})
    assert r.status_code == 400, r.text


def test_delegation_intersects_child_scope(admin):
    """A delegated child can never exceed its parent, and the parent can later
    invalidate it (provenance)."""
    va = admin.create_vault(name=_u("scopedeleg"))
    try:
        pcaps = ["vault.see_info", "vault.see_files"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": True}}
        parent, _ = _scoped_client(admin, pscope, "selected", [{"vault_id": va["id"], "caps": pcaps}])
        # child requests MORE than the parent holds -> must be intersected away
        cscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": ["vault.create"],
                  "vault_caps_default": ["vault.see_files", "file.upload"],
                  "temp": {"view": True, "create": True, "invalidate": False, "clear": False, "delegate": False}}
        r = parent.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": va["id"], "caps": ["vault.see_files", "file.upload"]}]})
        assert r.status_code == 200
        eff = r.json().get("scope") or {}
        assert "vault.create" not in eff.get("caps", [])               # parent lacked it
        assert "file.upload" not in eff.get("vault_caps_default", [])   # parent lacked it
        # parent may invalidate its own child (provenance set)
        assert parent.post(f"/temp-creds/{r.json()['temp_username']}/deactivate").status_code == 200
    finally:
        admin.delete_vault(va["id"])


# --- /auth/session nav gating (scoped temp credentials) --------------------

def test_scoped_temp_session_reports_only_permitted_nav_sections(admin):
    """GET /auth/session returns exactly the UI nav sections a scoped temp
    credential may use, derived from the SAME gate the endpoints enforce with, so
    the sidebar can hide the rest. The creator here is admin, proving the fix is
    not defeated by the creator's role."""
    off = {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}

    # vaults-only scope -> ONLY the 'vaults' section (not dashboard/temp-creds/admin pages)
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info"], "temp": off}
    cred = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all"}).json()
    c = admin.clone_anonymous()
    login = c.login(cred["temp_username"], cred["credential"])
    # The login response itself flags a SCOPED temp cred, so the UI can fail closed
    # before the /auth/session probe (admin-owned here => proves no admin bypass).
    assert login["is_temporary"] is True
    assert login["is_scoped_temp"] is True
    r = c.get("/auth/session")
    assert r.status_code == 200
    body = r.json()
    assert body["is_scoped_temp"] is True
    assert body["accessible_sections"] == ["vaults"]

    # dashboard + temp_creds(view) -> those two, in canonical order
    scope2 = {"v": 1, "pages": ["dashboard", "temp_creds"], "caps": [], "vault_caps_default": [],
              "temp": {**off, "view": True}}
    c2, _ = _scoped_client(admin, scope2, "all")
    assert c2.get("/auth/session").json()["accessible_sections"] == ["dashboard", "temp-creds"]

    # temp_creds page WITHOUT the view sub-permission -> section is NOT accessible
    scope3 = {"v": 1, "pages": ["temp_creds"], "caps": [], "vault_caps_default": [], "temp": off}
    c3, _ = _scoped_client(admin, scope3, "all")
    assert c3.get("/auth/session").json()["accessible_sections"] == []


def test_regular_session_is_not_scope_locked(admin):
    """A normal (non-temp) session reports is_scoped_temp False + null sections, so
    the frontend keeps its usual role/permission-based navigation."""
    body = admin.get("/auth/session").json()
    assert body["is_scoped_temp"] is False
    assert body["accessible_sections"] is None


def test_legacy_unscoped_temp_cred_is_not_nav_locked(admin):
    """A temp cred created WITHOUT a scope is legacy/unrestricted: login flags it
    is_temporary True but is_scoped_temp False, and /auth/session returns null
    sections — so the UI does NOT lock it (back-compat)."""
    cred = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    c = admin.clone_anonymous()
    login = c.login(cred["temp_username"], cred["credential"])
    assert login["is_temporary"] is True
    assert login["is_scoped_temp"] is False
    body = c.get("/auth/session").json()
    assert body["is_scoped_temp"] is False
    assert body["accessible_sections"] is None


def test_scoped_session_reports_effective_caps_for_action_gating(admin):
    """/auth/session exposes the scoped cred's effective caps so the UI can gate
    ACTION buttons (upload/delete/create) — not just nav — to match require_cap /
    require_vault_cap. selected-mode: per-vault caps under vault_caps[vault_id]."""
    off = {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}
    va = admin.create_vault(name=_u("capscope"))
    try:
        vcaps = ["vault.see_info", "vault.see_files", "file.download"]  # read-only, no write caps
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": [], "temp": off}
        cred = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": va["id"], "caps": vcaps}]}).json()
        c = admin.clone_anonymous()
        c.login(cred["temp_username"], cred["credential"])
        s = c.get("/auth/session").json()
        assert s["vault_access_mode"] == "selected"
        assert set(s["vault_caps"].get(va["id"], [])) == set(vcaps)
        assert "file.upload" not in s["vault_caps"][va["id"]]   # UI must hide Upload
        assert "file.delete" not in s["vault_caps"][va["id"]]   # UI must hide Delete
        assert s["caps"] == []                                  # no global vault.create -> hide Create Vault
        assert s["temp_perms"]["create"] is False               # hide Generate Temp Creds
    finally:
        admin.delete_vault(va["id"])


def test_scoped_session_reports_mode_all_and_global_caps(admin):
    """mode='all' exposes vault_caps_default (applies to every vault) + global caps
    such as vault.create."""
    off = {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}
    scope = {"v": 1, "pages": ["vaults"], "caps": ["vault.create"],
             "vault_caps_default": ["vault.see_info", "file.upload"], "temp": off}
    c, _ = _scoped_client(admin, scope, "all")
    s = c.get("/auth/session").json()
    assert s["vault_access_mode"] == "all"
    assert "vault.create" in s["caps"]
    assert set(s["vault_caps_default"]) == {"vault.see_info", "file.upload"}


def test_id_scope_stored_and_delegation_clamps(admin):
    """A per-vault ID scope ({files,folders}) is stored NORMALIZED, and a delegated child is clamped
    to the parent's file/folder scope by real folder ancestry (a child can never widen past its
    parent). Covers storage normalization and the delegation clamp at mint time."""
    v = admin.create_vault(name=_u("idscope"))
    try:
        vid = v["id"]
        caps = ["vault.see_files", "file.download"]
        deleg = {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": True}
        # 'temp_creds' page is required for the parent to reach the mint endpoint when it delegates.
        scope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": caps, "temp": deleg}
        # Real ancestry: folder D (root) with a child folder SUB; OUTSIDE is an id not under D.
        D = admin.post(f"/vaults/{vid}/folders", json={"name": _u("D")}).json()["folder"]["id"]
        SUB = admin.post(f"/vaults/{vid}/folders",
                         json={"name": _u("SUB"), "parent_folder_id": D}).json()["folder"]["id"]
        OUTSIDE = str(uuid.uuid4())

        # 1) STORAGE (admin mint): the id scope is normalized (dedup + drop non-uuid).
        _, body = _scoped_client(admin, scope, "selected",
                                 [{"vault_id": vid, "caps": caps,
                                   "scope_ids": {"folders": [D, D, "bad"], "files": []}}])
        assert _stored_scope(body["temp_username"]) == {"files": [], "folders": [D]}

        # a credential that omits scope_ids stays whole-vault (NULL)
        _, body2 = _scoped_client(admin, scope, "selected", [{"vault_id": vid, "caps": caps}])
        assert _stored_scope(body2["temp_username"]) is None

        # 2) DELEGATION: a parent limited to folder D that can delegate...
        parent, _ = _scoped_client(admin, scope, "selected",
                                   [{"vault_id": vid, "caps": caps, "scope_ids": {"folders": [D], "files": []}}])
        child_scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
                       "temp": {"view": False, "create": False, "invalidate": False,
                                "clear": False, "delegate": False}}
        # ...mints a child asking for SUB (a subfolder of D -> kept via ancestry) + an OUTSIDE id
        # (dropped): clamped to the parent.
        r = parent.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": child_scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": caps,
                                 "scope_ids": {"folders": [SUB], "files": [OUTSIDE]}}]})
        assert r.status_code == 200, r.text
        assert _stored_scope(r.json()["temp_username"]) == {"files": [], "folders": [SUB]}

        # a delegated child that OMITS scope_ids INHERITS the parent's (must NOT default to
        # whole-vault / NULL) -- the highest-risk delegation case, through the real mint endpoint.
        r2 = parent.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": child_scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": caps}]})
        assert r2.status_code == 200, r2.text
        assert _stored_scope(r2.json()["temp_username"]) == {"files": [], "folders": [D]}
    finally:
        admin.delete_vault(vid)
