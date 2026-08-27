"""Per-recipient max_downloads on shares.

A share's max_downloads caps how many times EACH recipient may download (per-recipient): the
count is atomically consumed against the recipient's ShareClaim before the bytes are served, so a
recipient is cut off after N and one recipient's downloads never consume another's. An unlimited
share (no max_downloads) is never capped.
"""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("dltag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10, "max_downloads_cap": 100}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _upload(admin, vid, name, content=b"data"):
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text


def _file_id(admin, vid, name):
    for it in admin.get(f"/vaults/{vid}/files").json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    raise AssertionError(f"file {name} not found")


def _claim(client, share):
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def _second_user(admin):
    u = admin.create_user(role="user")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    return u, c


def _dl(client, vid, fid):
    """Status of a download, or -1 if the transfer broke mid-body. A server-side integrity failure
    holds the final piece back, leaving the response short of its promised length, which a
    conforming client surfaces as a broken read rather than a clean status."""
    import requests
    try:
        return client.get(f"/vaults/{vid}/files/{fid}/download").status_code
    except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError):
        return -1


def _dl_failed(client, vid, fid):
    """True when the server did not serve the file: a broken stream (-1) or a 5xx."""
    st = _dl(client, vid, fid)
    return st == -1 or st >= 500


def test_max_downloads_enforced(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dle"))
    try:
        _upload(admin, v["id"], "f.txt", content=b"payload")
        f = _file_id(admin, v["id"], "f.txt")
        _claim(temp_user_client, _make_share(admin, v, _tag(admin), max_downloads=2))
        assert _dl(temp_user_client, v["id"], f) == 200   # 1
        assert _dl(temp_user_client, v["id"], f) == 200   # 2
        assert _dl(temp_user_client, v["id"], f) == 403    # over the cap
    finally:
        admin.delete_vault(v["id"])


def test_max_downloads_is_per_recipient(admin, temp_user_client):
    """Each recipient gets their own budget; one recipient's downloads never consume another's."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlpr"))
    u2, c2 = _second_user(admin)
    try:
        _upload(admin, v["id"], "g.txt", content=b"g")
        g = _file_id(admin, v["id"], "g.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=1)
        _claim(temp_user_client, share)
        _claim(c2, share)
        # each recipient gets exactly one
        assert _dl(temp_user_client, v["id"], g) == 200
        assert _dl(c2, v["id"], g) == 200
        # ...and each is then cut off independently
        assert _dl(temp_user_client, v["id"], g) == 403
        assert _dl(c2, v["id"], g) == 403
    finally:
        admin.delete_user(u2["id"])
        admin.delete_vault(v["id"])


def test_unlimited_share_is_never_capped(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlu"))
    try:
        _upload(admin, v["id"], "u.txt", content=b"u")
        f = _file_id(admin, v["id"], "u.txt")
        _claim(temp_user_client, _make_share(admin, v, _tag(admin)))  # no max_downloads = unlimited
        for _ in range(4):
            assert _dl(temp_user_client, v["id"], f) == 200
    finally:
        admin.delete_vault(v["id"])


def test_download_count_increments_on_claim(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlc"))
    try:
        _upload(admin, v["id"], "c.txt", content=b"c")
        f = _file_id(admin, v["id"], "c.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=5)
        _claim(temp_user_client, share)
        assert _dl(temp_user_client, v["id"], f) == 200
        assert _dl(temp_user_client, v["id"], f) == 200
        cnt = _psql_out(f"SELECT download_count FROM share_claims "
                        f"WHERE share_id='{share['id']}' AND user_id='{temp_user['id']}'")
        assert cnt == "2", f"expected download_count 2, got {cnt!r}"
    finally:
        admin.delete_vault(v["id"])


# --- Refund a capped download when the SERVER fails to serve -------------------------------------
#
# A share's downloads are burned before the bytes are served, so the cap is atomic against
# concurrent GETs. But a stored blob that the server then cannot serve -- a failed at-rest walk, a
# record that will not authenticate, or a whole-file checksum mismatch -- delivers nothing, and the
# recipient must not be charged for a file they never received. The refund is limited to
# server-detected failures on stored bytes, which a client cannot induce, so it can never be used
# to uncap a share by disconnecting (client abandonment stays burned; that asymmetry is the point).

_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _psql_exec(sql):
    subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _count(share_id, user_id):
    return int(_psql_out(f"SELECT download_count FROM share_claims "
                         f"WHERE share_id='{share_id}' AND user_id='{user_id}'") or "-1")


def _corrupt_checksum(file_id):
    """Point the file's recorded checksum at a value its bytes cannot hash to. The download's
    hold-back compares the streamed plaintext against this column and raises ChecksumMismatch with
    the final piece still owed -- a server-side integrity failure discovered mid-stream.

    The checksum is sealed at rest (enc_checksum) and the load event restores the ORIGINAL value from
    it -- which would undo a plaintext-column corruption -- so clear enc_checksum too. With it NULL the
    load event skips decryption and the corrupt plaintext checksum_sha256 is used as-is, reproducing
    the pre-seal wrong-checksum behaviour exactly."""
    _psql_exec(f"UPDATE files SET checksum_sha256='{'0' * 64}', enc_checksum=NULL WHERE id='{file_id}'")


def _truncate_blob(file_id):
    """Chop the tail off the stored blob so the reader rejects it AS IT IS CONSTRUCTED -- the walk
    authenticates the terminal (which binds the record count and total length), so a missing terminal
    fails at open, before any byte is served (the pre-stream path). Keeping the head intact means the
    format is still detected as the current AES-GCM stream rather than falling back to the legacy
    reader. Returns True if the blob was found and truncated."""
    rel = _psql_out(f"SELECT storage_path FROM files WHERE id='{file_id}'")
    if not rel:
        return False
    r = subprocess.run(
        ["docker", "exec", _API, "sh", "-c",
         f"p=\"$(find / -path '*{rel}' -type f 2>/dev/null | head -1)\"; "
         f"[ -n \"$p\" ] || {{ echo miss; exit 0; }}; "
         f"sz=$(stat -c%s \"$p\"); truncate -s $((sz-64)) \"$p\" && echo ok || echo fail"],
        capture_output=True, text=True, timeout=30)
    return (r.stdout or "").strip() == "ok"


def test_server_integrity_failure_refunds_capped_download(admin, temp_user, temp_user_client):
    """A corrupt blob fails the download and returns the burned quota; the recipient's whole budget
    survives for files the server can actually serve."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlrf"))
    try:
        _upload(admin, v["id"], "good.txt", content=b"good-payload")
        _upload(admin, v["id"], "bad.txt", content=b"bad-payload-that-will-be-corrupted")
        good, bad = _file_id(admin, v["id"], "good.txt"), _file_id(admin, v["id"], "bad.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=2)
        _claim(temp_user_client, share)
        sid, uid = share["id"], temp_user["id"]

        _corrupt_checksum(bad)
        assert _dl_failed(temp_user_client, v["id"], bad)    # server failed to serve
        assert _count(sid, uid) == 0                        # burned, then refunded

        # The two downloads the cap promised are still available for a servable file.
        assert _dl(temp_user_client, v["id"], good) == 200
        assert _count(sid, uid) == 1
        assert _dl(temp_user_client, v["id"], good) == 200
        assert _count(sid, uid) == 2
        assert _dl(temp_user_client, v["id"], good) == 403  # cap reached by REAL downloads only
    finally:
        admin.delete_vault(v["id"])


def test_server_failure_before_stream_refunds(admin, temp_user, temp_user_client):
    """The pre-stream path: a blob rejected when the reader is built (nothing served) refunds, and
    the recipient's full budget survives for a servable file."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlrp"))
    try:
        _upload(admin, v["id"], "t.txt", content=b"payload-to-truncate-on-disk " * 512)
        _upload(admin, v["id"], "ok.txt", content=b"servable")
        f = _file_id(admin, v["id"], "t.txt")
        ok = _file_id(admin, v["id"], "ok.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=2)
        _claim(temp_user_client, share)
        sid, uid = share["id"], temp_user["id"]

        if not _truncate_blob(f):
            import pytest
            pytest.skip("could not locate the stored blob to corrupt it")
        assert _dl(temp_user_client, v["id"], f) == 500     # rejected at open, before any byte
        assert _count(sid, uid) == 0                         # burned, then refunded
        # The burn->refund really cycled: the full budget is still there for a servable file.
        assert _dl(temp_user_client, v["id"], ok) == 200
        assert _count(sid, uid) == 1
    finally:
        admin.delete_vault(v["id"])


def test_refund_is_per_recipient(admin, temp_user, temp_user_client):
    """One recipient's server-side failure returns only that recipient's download, not another's."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlri"))
    u2, c2 = _second_user(admin)
    try:
        _upload(admin, v["id"], "s.txt", content=b"shared")
        f = _file_id(admin, v["id"], "s.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=1)
        _claim(temp_user_client, share)
        _claim(c2, share)
        sid = share["id"]

        # u2 spends their single download normally.
        assert _dl(c2, v["id"], f) == 200
        assert _count(sid, u2["id"]) == 1
        assert _dl(c2, v["id"], f) == 403                   # u2 is capped out

        # temp_user hits a corrupt blob: refunded, and u2's spent budget is untouched.
        _corrupt_checksum(f)
        assert _dl_failed(temp_user_client, v["id"], f)
        assert _count(sid, temp_user["id"]) == 0            # refunded
        assert _count(sid, u2["id"]) == 1                   # unchanged
    finally:
        admin.delete_user(u2["id"])
        admin.delete_vault(v["id"])


def _remove_blob(file_id):
    """Unlink the stored blob so it is missing on disk (the DB record stays). The reader's
    existence check then raises the custom FileNotFoundError at open. Returns True if removed."""
    rel = _psql_out(f"SELECT storage_path FROM files WHERE id='{file_id}'")
    if not rel:
        return False
    r = subprocess.run(
        ["docker", "exec", _API, "sh", "-c",
         f"p=\"$(find / -path '*{rel}' -type f 2>/dev/null | head -1)\"; "
         f"[ -n \"$p\" ] && rm -f \"$p\" && echo ok || echo miss"],
        capture_output=True, text=True, timeout=30)
    return (r.stdout or "").strip() == "ok"


def test_missing_blob_refunds(admin, temp_user, temp_user_client):
    """A blob missing on disk is a server-side failure too (nothing to serve): the 404 refunds the
    burn rather than charging the recipient for a file the server no longer has."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlmb"))
    try:
        _upload(admin, v["id"], "gone.txt", content=b"will-be-removed-on-disk")
        _upload(admin, v["id"], "here.txt", content=b"still-here")
        gone = _file_id(admin, v["id"], "gone.txt")
        here = _file_id(admin, v["id"], "here.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=2)
        _claim(temp_user_client, share)
        sid, uid = share["id"], temp_user["id"]

        if not _remove_blob(gone):
            import pytest
            pytest.skip("could not locate the stored blob to remove it")
        assert _dl(temp_user_client, v["id"], gone) == 404   # nothing to serve
        assert _count(sid, uid) == 0                          # burned, then refunded
        assert _dl(temp_user_client, v["id"], here) == 200    # budget survived
        assert _count(sid, uid) == 1
    finally:
        admin.delete_vault(v["id"])


def test_client_disconnect_stays_burned(admin, temp_user, temp_user_client):
    """The asymmetry that is the whole point: a client that disconnects mid-stream stays burned --
    otherwise any client could uncap a capped share by disconnecting. Only server-side failures refund."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dldc"))
    try:
        _upload(admin, v["id"], "big.bin", content=b"Z" * (16 * 1024 * 1024))
        f = _file_id(admin, v["id"], "big.bin")
        share = _make_share(admin, v, _tag(admin), max_downloads=1)
        _claim(temp_user_client, share)
        sid, uid = share["id"], temp_user["id"]

        r = temp_user_client.get(f"/vaults/{v['id']}/files/{f}/download", stream=True)
        assert r.status_code == 200
        next(r.iter_content(chunk_size=4096))           # start the transfer (burn commits)
        assert _count(sid, uid) == 1
        r.close()                                        # client disconnects mid-stream
        # A full round-trip here also gives the server time to run its finally; if a disconnect
        # wrongly refunded, this second download would find budget and return 200 instead of 403.
        assert _dl(temp_user_client, v["id"], f) == 403  # the cap really was spent
        assert _count(sid, uid) == 1
    finally:
        admin.delete_vault(v["id"])


def test_unlimited_share_failure_refunds_nothing(admin, temp_user_client):
    """A server-side failure on an UNLIMITED share burned nothing, so the refund path is a clean
    no-op: the download fails, nothing errors, and the share stays usable."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlun"))
    try:
        _upload(admin, v["id"], "b.txt", content=b"bad")
        _upload(admin, v["id"], "g.txt", content=b"good")
        bad = _file_id(admin, v["id"], "b.txt")
        good = _file_id(admin, v["id"], "g.txt")
        _claim(temp_user_client, _make_share(admin, v, _tag(admin)))   # unlimited (no max_downloads)
        _corrupt_checksum(bad)
        assert _dl_failed(temp_user_client, v["id"], bad)    # fails; refund is a no-op (nothing burned)
        assert _dl(temp_user_client, v["id"], good) == 200   # unlimited share still works
    finally:
        admin.delete_vault(v["id"])
