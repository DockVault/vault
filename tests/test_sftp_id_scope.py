"""SFTP enforcement of an ID-based file/folder scope on temp credentials.

A credential scoped to folder D (its subtree) sees, over SFTP, a virtual filesystem containing ONLY
its in-scope subtree plus the ancestor folders needed to reach it. Everything outside the scope reads
as non-existent (no listing, stat, download, upload, rename, delete, mkdir, or rmdir).
"""
import contextlib
import os
import uuid

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import ADMIN_USER, ADMIN_PASS, unique  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


pytestmark = pytest.mark.sftp


@contextlib.contextmanager
def sftp_session(username: str, password: str):
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            yield sftp
        finally:
            sftp.close()
    finally:
        transport.close()


def _mkfolder(admin, vid, name, parent=None):
    body = {"name": name}
    if parent:
        body["parent_folder_id"] = parent
    return admin.post(f"/vaults/{vid}/folders", json=body).json()["folder"]


def _upload(admin, vid, name, folder_id=None, content=b"data"):
    params = {"folder_id": folder_id} if folder_id else {}
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))], params=params)
    assert r.status_code in (200, 201), r.text


SFTP_CAPS = ["vault.see_info", "vault.see_files", "file.download", "file.upload",
             "file.delete", "file.rename", "folder.create", "folder.delete"]


def _mint_scoped(admin, vault_id, scope_ids, caps=SFTP_CAPS):
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": caps, "scope_ids": scope_ids}]}).json()
    return body["temp_username"], body["credential"]


@pytest.fixture(autouse=True)
def _need_admin_pw():
    if not ADMIN_PASS:
        pytest.skip("No admin password (set VAULT_ADMIN_PASS)")


def test_sftp_id_scope_enforcement(admin):
    v = admin.create_vault(name=unique("sftpscope"))
    vid, vname = v["id"], v["name"]
    try:
        D = _mkfolder(admin, vid, unique("D"))
        OTHER = _mkfolder(admin, vid, unique("OTHER"))
        dn, on = D["name"], OTHER["name"]
        _upload(admin, vid, "x.txt", folder_id=D["id"], content=b"in-scope")
        _upload(admin, vid, "y.txt", folder_id=OTHER["id"], content=b"out-of-scope")
        _upload(admin, vid, "r.txt")  # root

        user, pw = _mint_scoped(admin, vid, {"folders": [D["id"]], "files": []})

        with sftp_session(user, pw) as sftp:
            # --- listing shows only the in-scope subtree (+ navigable ancestors) ---
            top = set(sftp.listdir(f"/{vname}"))
            assert dn in top                      # scoped folder visible
            assert on not in top                  # out-of-scope folder hidden
            assert "r.txt" not in top             # out-of-scope root file hidden
            assert "x.txt" in set(sftp.listdir(f"/{vname}/{dn}"))   # in-scope file listed
            with pytest.raises(IOError):
                sftp.listdir(f"/{vname}/{on}")    # out-of-scope folder reads as non-existent

            # --- read/stat only within scope ---
            assert sftp.stat(f"/{vname}/{dn}/x.txt").st_size == len(b"in-scope")
            with sftp.open(f"/{vname}/{dn}/x.txt", "rb") as fh:
                assert fh.read() == b"in-scope"
            with pytest.raises(IOError):
                sftp.stat(f"/{vname}/{on}/y.txt")
            with pytest.raises(IOError):
                sftp.open(f"/{vname}/{on}/y.txt", "rb").read()

            # --- write only within scope ---
            with sftp.open(f"/{vname}/{dn}/new.txt", "wb") as fh:
                fh.write(b"written")             # upload into D ok
            with pytest.raises(IOError):
                with sftp.open(f"/{vname}/{on}/z.txt", "wb") as fh:
                    fh.write(b"nope")            # upload into OTHER denied
            with pytest.raises(IOError):
                with sftp.open(f"/{vname}/root.txt", "wb") as fh:
                    fh.write(b"nope")            # upload to vault root denied
            sftp.mkdir(f"/{vname}/{dn}/sub")     # mkdir in D ok
            with pytest.raises(IOError):
                sftp.mkdir(f"/{vname}/{on}/sub") # mkdir in OTHER denied
            sftp.rename(f"/{vname}/{dn}/x.txt", f"/{vname}/{dn}/x2.txt")  # rename in D ok
            with pytest.raises(IOError):
                sftp.rename(f"/{vname}/{on}/y.txt", f"/{vname}/{on}/y2.txt")  # rename in OTHER denied
            with pytest.raises(IOError):
                sftp.remove(f"/{vname}/{on}/y.txt")   # delete out-of-scope file denied
            sftp.remove(f"/{vname}/{dn}/x2.txt")      # delete in-scope file ok
            with pytest.raises(IOError):
                sftp.rmdir(f"/{vname}/{on}")          # rmdir out-of-scope folder denied
    finally:
        admin.delete_vault(vid)


def test_sftp_navigable_ancestor_is_read_only(admin):
    """A folder scoped to nested D (under A) makes A NAVIGABLE (list/stat/cd) but NOT writable:
    an ancestor the holder can only traverse must never accept a write/create/delete."""
    v = admin.create_vault(name=unique("sftpnest"))
    vid, vname = v["id"], v["name"]
    try:
        A = _mkfolder(admin, vid, unique("A"))                 # root
        D = _mkfolder(admin, vid, unique("D"), parent=A["id"]) # A/D  (the scope)
        SIB = _mkfolder(admin, vid, unique("SIB"), parent=A["id"])  # A/SIB (out of scope)
        an, dn, sn = A["name"], D["name"], SIB["name"]
        _upload(admin, vid, "a_local.txt", folder_id=A["id"])  # a file directly in the ancestor A
        _upload(admin, vid, "x.txt", folder_id=D["id"])        # in-scope file

        user, pw = _mint_scoped(admin, vid, {"folders": [D["id"]], "files": []})
        with sftp_session(user, pw) as sftp:
            # A is navigable: listing root shows A (and not SIB — SIB is a root? no, SIB is under A)
            assert an in set(sftp.listdir(f"/{vname}"))
            # listing A shows ONLY the path to the scope (D) — not A's own file, not the sibling folder
            inA = set(sftp.listdir(f"/{vname}/{an}"))
            assert dn in inA
            assert sn not in inA and "a_local.txt" not in inA
            # stat/cd of A and D works (navigable / in scope)
            assert sftp.stat(f"/{vname}/{an}").st_mode is not None
            assert sftp.stat(f"/{vname}/{an}/{dn}").st_mode is not None
            # in-scope ops inside D succeed
            sftp.mkdir(f"/{vname}/{an}/{dn}/sub")
            with sftp.open(f"/{vname}/{an}/{dn}/new.txt", "wb") as fh:
                fh.write(b"ok")
            assert _read(sftp, f"/{vname}/{an}/{dn}/x.txt") == b"data"
            # NAVIGABLE != WRITABLE: no write/create/delete may land ON or IN the ancestor A
            with pytest.raises(IOError):
                sftp.mkdir(f"/{vname}/{an}/sub")               # create in ancestor denied
            with pytest.raises(IOError):
                with sftp.open(f"/{vname}/{an}/into_a.txt", "wb") as fh:
                    fh.write(b"nope")                          # upload into ancestor denied
            with pytest.raises(IOError):
                sftp.remove(f"/{vname}/{an}/a_local.txt")      # delete ancestor's own file denied
            with pytest.raises(IOError):
                sftp.rename(f"/{vname}/{an}/a_local.txt", f"/{vname}/{an}/renamed.txt")  # rename in A denied
            with pytest.raises(IOError):
                sftp.rmdir(f"/{vname}/{an}")                   # delete the ancestor denied
            with pytest.raises(IOError):
                sftp.rmdir(f"/{vname}/{an}/{sn}")              # delete an out-of-scope sibling denied
    finally:
        admin.delete_vault(vid)


def test_sftp_file_scope(admin):
    """A scope of a single FILE X (folders:[]) exposes only X + the navigable folders on its path;
    sibling files are hidden, and the containing folder is navigable but not writable."""
    v = admin.create_vault(name=unique("sftpfile"))
    vid, vname = v["id"], v["name"]
    try:
        A = _mkfolder(admin, vid, unique("A"))
        an = A["name"]
        _upload(admin, vid, "x.txt", folder_id=A["id"], content=b"the-one")
        _upload(admin, vid, "sibling.txt", folder_id=A["id"], content=b"hidden")
        # resolve X's id from the admin listing
        items = admin.get(f"/vaults/{vid}/files", params={"folder_id": A["id"]}).json()["items"]
        X = next(it["id"] for it in items if it["name"] == "x.txt")

        user, pw = _mint_scoped(admin, vid, {"folders": [], "files": [X]})
        with sftp_session(user, pw) as sftp:
            assert an in set(sftp.listdir(f"/{vname}"))         # containing folder navigable
            inA = set(sftp.listdir(f"/{vname}/{an}"))
            assert "x.txt" in inA and "sibling.txt" not in inA  # only the scoped file is visible
            assert _read(sftp, f"/{vname}/{an}/x.txt") == b"the-one"
            with pytest.raises(IOError):
                sftp.open(f"/{vname}/{an}/sibling.txt", "rb").read()   # sibling not downloadable
            with pytest.raises(IOError):
                sftp.stat(f"/{vname}/{an}/sibling.txt")               # sibling not statable
            with pytest.raises(IOError):                              # folder navigable, not writable
                sftp.mkdir(f"/{vname}/{an}/sub")
            with pytest.raises(IOError):
                with sftp.open(f"/{vname}/{an}/into.txt", "wb") as fh:
                    fh.write(b"nope")
    finally:
        admin.delete_vault(vid)


def _read(sftp, path) -> bytes:
    with sftp.open(path, "rb") as fh:
        return fh.read()
