"""Live: an expired file is gone from every read path at once, and the sweep deletes it.

A vault set to "expire files after 1 minute" stamps each upload with a deadline one minute out. Once
it passes, the file must stop being listable, downloadable (whole or ranged), previewable, copyable,
movable, reachable over SFTP, through a public file link or through a share -- immediately, not when
the sweep next runs -- and the web process's sweep must then delete the row and its stored bytes and
record a ``file_expired`` audit row. An upload link's retention is the same setting on its vault.

Waiting a real minute per check would make the module slow and its timing fragile, so the deadline
is moved into the past directly in the database. To prove the read paths hide the file on their own,
the checks run while a psql session holds the file's row lock: the sweep takes rows SKIP LOCKED, so
it cannot delete that one until the lock is released, and the row is still there when every check
has passed. Releasing the lock then lets the sweep (every 60 s) delete it.

ENFORCE_FILE_EXPIRY=false is covered at unit level (tests/test_file_expiry.py): flipping it here
would mean restarting the stack under test.
"""
import os
import subprocess
import time

import pytest

from conftest import ADMIN_PASS, ADMIN_USER, unique

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))

# The sweep runs every 60 s; allow two runs and a margin before calling it missing.
_SWEEP_DEADLINE_SECONDS = 150


def _psql(sql):
    r = subprocess.run(
        ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return (r.stdout or "").strip()


class _ExpiredAndHeld:
    """Move a file's deadline into the past and hold its row lock until released.

    Both happen in one psql session, a statement apart, so the sweep has no window to delete the
    row between them. The UPDATE commits on its own (psql autocommits), so every other session sees
    the file as expired; the lock that follows is an open transaction nothing else can see."""

    def __init__(self, file_id):
        self.file_id = file_id
        self.marker = unique("hold")
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-q",
             "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        script = (
            f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' "
            f"WHERE id = '{self.file_id}';\n"
            f"BEGIN;\n"
            f"SELECT /* {self.marker} */ id FROM files WHERE id = '{self.file_id}' FOR UPDATE;\n")
        self.proc.stdin.write(script.encode())
        self.proc.stdin.flush()
        deadline = time.time() + 30
        while time.time() < deadline:
            held = _psql("SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' "
                         f"AND query LIKE '%{self.marker}%'")
            if held == "1":
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.2)
        self.release()
        raise AssertionError("the holding session never took the row lock")

    def release(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.write(b"ROLLBACK;\n\\q\n")
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None

    def __exit__(self, *exc):
        self.release()


def _wait_until_gone(file_id):
    deadline = time.time() + _SWEEP_DEADLINE_SECONDS
    while time.time() < deadline:
        if _psql(f"SELECT count(*) FROM files WHERE id = '{file_id}'") == "0":
            return True
        time.sleep(2)
    return False


def _upload(client, vid, name, content):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


def _names(client, vid):
    r = client.get(f"/vaults/{vid}/files")
    assert r.status_code == 200, r.text
    return {it["name"] for it in r.json()["items"] if it.get("type") == "file"}


@pytest.fixture
def links_and_sharing(admin):
    before = admin.get("/settings").json()
    keys = ("public_file_links_enabled", "public_note_link_user_cap", "sharing_enabled")
    snap = {k: before.get(k) for k in keys}
    r = admin.put("/settings", json={"public_file_links_enabled": True,
                                     "public_note_link_user_cap": 50, "sharing_enabled": True})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def receivers_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _public_link(admin, vid, fid):
    tag = admin.post("/note-link-tags", json={
        "name": unique("xtag"), "min_token_len": 6, "require_secret": "none", "min_pin_len": 4,
        "password_min_len": 8, "auto_enroll_new_users": True, "allowed_targets": ["file"]})
    assert tag.status_code == 200, tag.text
    r = admin.post("/public-links", json={"vault_id": vid, "target_type": "file",
                                          "target_file_id": fid, "tag_id": tag.json()["id"]})
    return r


def _file_share(admin, vid, fid):
    tag = admin.post("/share-tags", json={
        "name": unique("xtag"), "auto_enroll_new_users": True,
        "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10})
    assert tag.status_code == 200, tag.text
    return admin.post("/shares", json={"vault_id": vid, "tag_id": tag.json()["id"],
                                       "target_type": "file", "target_file_id": fid,
                                       "claim_audience": "anyone_internal"})


@pytest.mark.sftp
def test_an_expired_file_is_gone_from_every_read_path_then_swept(admin, links_and_sharing,
                                                                 temp_user_client):
    paramiko = pytest.importorskip("paramiko")
    if not ADMIN_PASS:
        pytest.skip("No admin password (set VAULT_ADMIN_PASS)")
    v = admin.create_vault()
    vid, vname = v["id"], v["name"]
    try:
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 1, "expire_files_unit": "minutes"})
        assert r.status_code == 200, r.text
        gone_name, kept_name = unique("gone") + ".txt", unique("kept") + ".txt"
        gone_bytes, kept_bytes = b"these bytes outlived their welcome", b"still here"
        fa = _upload(admin, vid, gone_name, gone_bytes)
        fb = _upload(admin, vid, kept_name, kept_bytes)

        # The upload stamped the vault's one-minute retention, in UTC: the deadline is a minute
        # after the row was written, and within a minute of the database's UTC clock -- a deadline
        # written in another zone would be hours off.
        lead = float(_psql(f"SELECT extract(epoch FROM expires_at - created_at) FROM files "
                           f"WHERE id = '{fa}'"))
        assert 45 < lead <= 61, lead
        ahead = float(_psql(f"SELECT extract(epoch FROM expires_at - (now() AT TIME ZONE 'utc')) "
                            f"FROM files WHERE id = '{fa}'"))
        assert 0 < ahead <= 61, ahead
        # The control file keeps a far deadline so it cannot expire during the checks.
        _psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') + interval '1 day' "
              f"WHERE id = '{fb}'")
        blob = _psql(f"SELECT storage_path FROM files WHERE id = '{fa}'")
        assert subprocess.run(["docker", "exec", _API, "test", "-f", f"storage/{blob}"],
                              timeout=30).returncode == 0

        # Reach the file every other way while it is live: a public link, and a claimed share.
        link = _public_link(admin, vid, fa)
        assert link.status_code == 200, link.text
        link = link.json()
        share = _file_share(admin, vid, fa)
        assert share.status_code == 200, share.text
        share = share.json()
        claim = temp_user_client.post("/shares/claim", json={"token": share["link_token"]})
        assert claim.status_code == 200, claim.text
        assert temp_user_client.get(f"/vaults/{vid}/files/{fa}/download").content == gone_bytes

        anon = admin.clone_anonymous()
        with _ExpiredAndHeld(fa):
            # Listing (and so the client-side search over it).
            assert gone_name not in _names(admin, vid) and kept_name in _names(admin, vid)
            # Download, whole and ranged.
            assert admin.get(f"/vaults/{vid}/files/{fa}/download").status_code == 404
            ranged = admin.get(f"/vaults/{vid}/files/{fa}/download", headers={"Range": "bytes=0-3"})
            assert ranged.status_code == 404
            ok = admin.get(f"/vaults/{vid}/files/{fb}/download")
            assert ok.status_code == 200 and ok.content == kept_bytes
            # Metadata and preview.
            assert admin.get(f"/vaults/{vid}/files/{fa}/info").status_code == 404
            assert admin.get(f"/vaults/{vid}/files/{fa}/preview-render").status_code == 404
            # Copy, move and rename have nothing to act on.
            assert admin.post(f"/vaults/{vid}/files/{fa}/copy",
                              json={"dest_vault_id": vid}).status_code == 404
            assert admin.post(f"/vaults/{vid}/files/{fa}/move",
                              json={"dest_vault_id": vid}).status_code == 404
            assert admin.put(f"/vaults/{vid}/files/{fa}/rename",
                             json={"new_name": unique("renamed") + ".txt"}).status_code == 404
            # The public link answers as for a deleted file, and no new link or share can be made.
            for body in ({}, {"peek": True}):
                assert anon.post(f"/public-links/{link['token']}/redeem",
                                 json=body).status_code == 404
            assert _public_link(admin, vid, fa).status_code == 404
            assert _file_share(admin, vid, fa).status_code == 404
            # The share recipient sees nothing, can download nothing, and cannot re-open the claim.
            assert gone_name not in _names(temp_user_client, vid)
            assert temp_user_client.get(f"/vaults/{vid}/files/{fa}/download").status_code == 404
            cards = [c for c in temp_user_client.get("/shares/shared-with-me").json()
                     if c["share_id"] == share["id"]]
            assert cards and cards[0]["target_name"] is None
            again = temp_user_client.post("/shares/claim", json={"token": share["link_token"]})
            assert again.status_code == 403, again.text
            # SFTP: not listed, not stat-able, not openable.
            transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
            transport.banner_timeout = 30
            try:
                transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
                sftp = paramiko.SFTPClient.from_transport(transport)
                listed = sftp.listdir(f"/{vname}")
                assert gone_name not in listed and kept_name in listed
                with pytest.raises(IOError):
                    sftp.stat(f"/{vname}/{gone_name}")
                with pytest.raises(IOError):
                    sftp.open(f"/{vname}/{gone_name}", "rb").read()
                sftp.close()
            finally:
                transport.close()
            # Every refusal above came from the read paths themselves: the row is still here.
            assert _psql(f"SELECT count(*) FROM files WHERE id = '{fa}'") == "1"

        # Released: the sweep deletes the row, its bytes, and what pointed at it, and says so.
        assert _wait_until_gone(fa), "the sweep did not delete the expired file"
        audit = _psql(f"SELECT details::text FROM audit_logs WHERE action = 'file_expired' "
                      f"AND resource_type = 'file' AND resource_id = '{fa}'")
        assert audit and len(audit.splitlines()) == 1, audit
        assert f'"vault_id": "{vid}"' in audit and gone_name not in audit
        assert subprocess.run(["docker", "exec", _API, "test", "-e", f"storage/{blob}"],
                              timeout=30).returncode != 0, "the stored bytes were not removed"
        assert _psql(f"SELECT count(*) FROM public_links WHERE id = '{link['id']}'") == "0"
        assert _psql(f"SELECT count(*) FROM shares WHERE id = '{share['id']}'") == "0"
        assert _psql(f"SELECT count(*) FROM retired_object_ids WHERE id = '{fa}'") == "1"
        # The vault's counters dropped by exactly the expired file; the live one is untouched.
        assert _psql(f"SELECT file_count || '|' || total_size_bytes FROM vaults "
                     f"WHERE id = '{vid}'") == f"1|{len(kept_bytes)}"
        ok = admin.get(f"/vaults/{vid}/files/{fb}/download")
        assert ok.status_code == 200 and ok.content == kept_bytes
    finally:
        admin.delete_vault(vid)


def test_an_upload_link_retention_is_enforced_the_same_way(admin, receivers_enabled):
    tag = admin.post("/receiver-tags", json={
        "name": unique("rtag"), "min_token_len": 6, "require_secret": "none", "min_pin_len": 4,
        "password_min_len": 8, "auto_enroll_new_users": True, "kind_floor": "standard",
        "max_total_bytes_cap": 1024 * 1024, "max_file_bytes_cap": 1024 * 1024,
        "retention_max_days": 30, "retention_default_days": 7})
    assert tag.status_code == 200, tag.text
    rec = admin.post("/receivers", json={"tag_id": tag.json()["id"], "max_total_bytes": 64 * 1024,
                                         "retention_days": 2})
    assert rec.status_code == 200, rec.text
    rec = rec.json()
    vid = rec["vault_id"]
    try:
        anon = admin.clone_anonymous()
        name, content = unique("drop") + ".txt", b"dropped through an upload link"
        opened = anon.post(f"/receivers/{rec['token']}/upload-session",
                           json={"filename": name, "total_size": len(content), "total_chunks": 1})
        assert opened.status_code == 200, opened.text
        sid = opened.json()["session_id"]
        put = anon.put(f"/receivers/{rec['token']}/upload-session/{sid}/chunks/0", data=content,
                       headers={"Content-Type": "application/octet-stream"})
        assert put.status_code == 200, put.text
        done = anon.post(f"/receivers/{rec['token']}/upload-session/{sid}/complete", json={})
        assert done.status_code == 200, done.text
        fid = next(it["id"] for it in admin.get(f"/vaults/{vid}/files").json()["items"]
                   if it.get("name") == name)

        # "Delete uploads after 2 days" stamped a deadline two days after the upload.
        lead = float(_psql(f"SELECT extract(epoch FROM expires_at - created_at) FROM files "
                           f"WHERE id = '{fid}'"))
        assert 2 * 86400 - 60 < lead <= 2 * 86400, lead

        _psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' "
              f"WHERE id = '{fid}'")
        # Gone from the owner's view at once, whether or not the sweep has run yet...
        assert name not in _names(admin, vid)
        assert admin.get(f"/vaults/{vid}/files/{fid}/download").status_code == 404
        # ...and deleted by it, with an audit row naming the upload link's vault.
        assert _wait_until_gone(fid), "the sweep did not delete the expired upload"
        audit = _psql(f"SELECT details->>'vault_id' FROM audit_logs WHERE action = 'file_expired' "
                      f"AND resource_id = '{fid}'")
        assert audit == vid
        assert _psql(f"SELECT file_count FROM vaults WHERE id = '{vid}'") == "0"
    finally:
        admin.post(f"/receivers/{rec['id']}/revoke")
        admin.delete_vault(vid)
