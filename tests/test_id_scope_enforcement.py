"""REST enforcement of an ID-based file/folder scope on temp credentials.

A credential scoped to folder D (its subtree) must not, via any REST surface:
  - enumerate files/folders outside D (the listing hides them),
  - download/act on a file outside D (even by known id),
  - write (upload/create) outside D.
"""
import uuid


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _mkfolder(admin, vid, name, parent=None):
    body = {"name": name}
    if parent:
        body["parent_folder_id"] = parent
    return admin.post(f"/vaults/{vid}/folders", json=body).json()["folder"]["id"]


def _upload(admin, vid, name, folder_id=None, content=b"data"):
    params = {"folder_id": folder_id} if folder_id else {}
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))], params=params)
    assert r.status_code in (200, 201), r.text
    return r


def _file_id(admin, vid, name, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else {}
    for it in admin.get(f"/vaults/{vid}/files", params=params).json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    raise AssertionError(f"file {name} not found in listing")


def _scoped_client(admin, vid, caps, scope_ids):
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vid, "caps": caps, "scope_ids": scope_ids}]}).json()
    c = admin.clone_anonymous()
    c.login(body["temp_username"], body["credential"])
    return c


def test_id_scope_rest_enforcement(admin):
    v = admin.create_vault(name=_u("enf"))
    try:
        vid = v["id"]
        D = _mkfolder(admin, vid, _u("D"))
        OTHER = _mkfolder(admin, vid, _u("OTHER"))
        _upload(admin, vid, "x.txt", folder_id=D)
        _upload(admin, vid, "y.txt", folder_id=OTHER)
        _upload(admin, vid, "r.txt")  # vault root
        X = _file_id(admin, vid, "x.txt", folder_id=D)
        Y = _file_id(admin, vid, "y.txt", folder_id=OTHER)
        R = _file_id(admin, vid, "r.txt")

        caps = ["vault.see_info", "vault.see_files", "file.download", "file.upload",
                "file.delete", "folder.create", "folder.delete"]
        c = _scoped_client(admin, vid, caps, {"folders": [D], "files": []})

        # --- download only within scope ---
        assert c.get(f"/vaults/{vid}/files/{X}/download").status_code == 200          # in D
        assert c.get(f"/vaults/{vid}/files/{Y}/download").status_code == 403          # in OTHER
        assert c.get(f"/vaults/{vid}/files/{R}/download").status_code == 403          # at root

        # --- enumerate only within scope ---
        root_ids = {it["id"] for it in c.get(f"/vaults/{vid}/files").json()["items"]}
        assert D in root_ids                                                          # scoped folder visible
        assert OTHER not in root_ids                                                  # out-of-scope folder hidden
        assert R not in root_ids                                                      # out-of-scope root file hidden
        inD_ids = {it["id"] for it in c.get(f"/vaults/{vid}/files", params={"folder_id": D}).json()["items"]}
        assert X in inD_ids                                                           # in-scope file listed

        # --- write only within scope ---
        assert c.post(f"/vaults/{vid}/files", files=[("files", ("n.txt", b"z", "text/plain"))],
                      params={"folder_id": D}).status_code in (200, 201)              # upload into D ok
        assert c.post(f"/vaults/{vid}/files", files=[("files", ("n2.txt", b"z", "text/plain"))],
                      params={"folder_id": OTHER}).status_code == 403                 # upload into OTHER denied
        assert c.post(f"/vaults/{vid}/files",
                      files=[("files", ("n3.txt", b"z", "text/plain"))]).status_code == 403  # upload to root denied
        assert c.post(f"/vaults/{vid}/files/{Y}/delete").status_code == 403           # delete out-of-scope file denied
        assert c.post(f"/vaults/{vid}/files/{X}/delete").status_code == 200           # delete in-scope file ok
        assert c.post(f"/vaults/{vid}/folders",
                      json={"name": "sub", "parent_folder_id": D}).status_code in (200, 201)  # create in D ok
        assert c.post(f"/vaults/{vid}/folders",
                      json={"name": "sub2", "parent_folder_id": OTHER}).status_code == 403     # create in OTHER denied
        assert c.post(f"/vaults/{vid}/folders/{OTHER}/delete").status_code == 403     # delete out-of-scope folder denied
    finally:
        admin.delete_vault(vid)


def test_id_scope_rename_polymorphic(admin):
    """rename is id-polymorphic (a file OR folder id) and must enforce the scope on whichever."""
    v = admin.create_vault(name=_u("ren"))
    try:
        vid = v["id"]
        D = _mkfolder(admin, vid, _u("D"))
        SUB = _mkfolder(admin, vid, _u("SUB"), parent=D)          # inside the scoped subtree
        OTHER = _mkfolder(admin, vid, _u("OTHER"))
        _upload(admin, vid, "x.txt", folder_id=D)
        _upload(admin, vid, "y.txt", folder_id=OTHER)
        X = _file_id(admin, vid, "x.txt", folder_id=D)
        Y = _file_id(admin, vid, "y.txt", folder_id=OTHER)

        c = _scoped_client(admin, vid, ["vault.see_info", "vault.see_files", "file.rename"],
                           {"folders": [D], "files": []})
        # file rename: in-scope ok, out-of-scope denied
        assert c.put(f"/vaults/{vid}/files/{X}/rename", json={"new_name": "x2.txt"}).status_code == 200
        assert c.put(f"/vaults/{vid}/files/{Y}/rename", json={"new_name": "y2.txt"}).status_code == 403
        # folder rename (same endpoint, folder id): a descendant of D ok, an out-of-scope folder denied
        assert c.put(f"/vaults/{vid}/files/{SUB}/rename", json={"new_name": "sub2"}).status_code == 200
        assert c.put(f"/vaults/{vid}/files/{OTHER}/rename", json={"new_name": "other2"}).status_code == 403
    finally:
        admin.delete_vault(vid)


def test_id_scope_chunked_upload_enforcement(admin):
    """The 6 chunked-upload surfaces. A session keys on user_id, and a temp credential keeps the
    minting admin's user_id, so a scoped credential must not init/resume/finalize/inspect/cancel a
    session whose target folder is outside its scope, nor enumerate it."""
    v = admin.create_vault(name=_u("chunk"))
    try:
        vid = v["id"]
        D = _mkfolder(admin, vid, _u("D"))
        OTHER = _mkfolder(admin, vid, _u("OTHER"))
        c = _scoped_client(admin, vid, ["vault.see_info", "vault.see_files", "file.upload"],
                           {"folders": [D], "files": []})

        # A temp credential keeps the minting admin's user_id, and resume-matching keys on
        # (user_id, file_name, total_size, total_chunks) — so give every init a distinct name to
        # keep these sessions independent (no accidental resume across credentials).
        def init(client, folder_id, name):
            body = {"file_name": name, "total_size": 10, "total_chunks": 1, "chunk_size": 10}
            if folder_id:
                body["folder_id"] = folder_id
            return client.post(f"/vaults/{vid}/uploads", json=body)

        # init: into D ok, into OTHER denied, into root denied
        assert init(c, D, "a.bin").status_code == 200
        assert init(c, OTHER, "b.bin").status_code == 403
        assert init(c, None, "c.bin").status_code == 403

        # cross-credential hijack: admin opens a session targeting OTHER; the scoped credential
        # (scope = D) must not touch it via any surface, nor see it listed.
        r = init(admin, OTHER, "hijack.bin")
        assert r.status_code == 200
        sid = r.json()["session_id"]
        assert c.get(f"/vaults/{vid}/uploads/{sid}").status_code == 403                 # inspect
        assert c.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"0123456789").status_code == 403  # write chunk
        listed = {s["session_id"] for s in c.get(f"/vaults/{vid}/uploads").json()}
        assert sid not in listed                                                        # enumerate
        assert sid in {s["session_id"] for s in admin.get(f"/vaults/{vid}/uploads").json()}
        assert c.delete(f"/vaults/{vid}/uploads/{sid}").status_code == 403              # cancel
        # the session survived the denied cancel (admin can still see it)
        assert sid in {s["session_id"] for s in admin.get(f"/vaults/{vid}/uploads").json()}
    finally:
        admin.delete_vault(vid)


def test_id_scope_no_whole_vault_aggregate_leak(admin):
    """A per-file/folder-scoped credential must not learn whole-vault file COUNT / SIZE via the
    vault metadata endpoints or the dashboard."""
    v = admin.create_vault(name=_u("agg"))
    try:
        vid = v["id"]
        D = _mkfolder(admin, vid, _u("D"))
        _upload(admin, vid, "x.txt", folder_id=D)
        _upload(admin, vid, "r1.txt")   # out-of-scope root files bump the whole-vault counters
        _upload(admin, vid, "r2.txt")
        c = _scoped_client(admin, vid, ["vault.see_info", "vault.see_files", "file.download"],
                           {"folders": [D], "files": []})

        # admin (unscoped) sees the real whole-vault aggregates ...
        av = admin.get(f"/vaults/{vid}").json()
        assert isinstance(av["file_count"], int) and av["file_count"] >= 3
        assert isinstance(av["total_size_bytes"], int)
        # ... the scoped credential sees them suppressed (null), on both get_vault and list_vaults
        cv = c.get(f"/vaults/{vid}").json()
        assert cv["file_count"] is None and cv["total_size_bytes"] is None
        listed = [x for x in c.get("/vaults").json() if x["id"] == vid]
        assert listed and listed[0]["file_count"] is None and listed[0]["total_size_bytes"] is None

        # dashboard: the scoped credential gets no owner-aggregate file count / storage ...
        stats = c.get("/api/dashboard/stats").json()
        assert "files" not in stats and "storage_mb" not in stats
        # ... and no audit-trail feed (it shares the admin's user_id).
        assert c.get("/api/dashboard/recent-events").json() == []
    finally:
        admin.delete_vault(vid)


def test_chunked_resume_is_folder_aware(admin):
    """Resume-matching must respect the requested folder: a scoped credential's legitimate in-scope
    init must not be captured by (and denied via) a same-name/size session another credential opened
    into a different folder."""
    v = admin.create_vault(name=_u("resume"))
    try:
        vid = v["id"]
        D = _mkfolder(admin, vid, _u("D"))
        OTHER = _mkfolder(admin, vid, _u("OTHER"))
        c = _scoped_client(admin, vid, ["vault.see_info", "vault.see_files", "file.upload"],
                           {"folders": [D], "files": []})

        def init(client, folder_id):
            return client.post(f"/vaults/{vid}/uploads", json={
                "file_name": "dup.bin", "total_size": 10, "total_chunks": 1,
                "chunk_size": 10, "folder_id": folder_id})

        admin_sid = init(admin, OTHER).json()["session_id"]                 # admin session in OTHER
        r = init(c, D)                                                      # scoped cred, SAME name/size, into D
        assert r.status_code == 200                                        # not spuriously denied
        assert r.json()["session_id"] != admin_sid                         # a fresh D-session, not the OTHER one
    finally:
        admin.delete_vault(vid)
