"""Concurrency hardening: the max_recipients row-lock (claim) and the max_downloads atomic
conditional-increment (download) must hold under REAL concurrent load — never over-admitting past
the recipient cap, never over-serving past the per-recipient download cap.
"""
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, f"psql failed ({_DB}): {r.stderr.strip()}"
    return (r.stdout or "").strip()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("hctag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["anyone_internal"],
                                        "max_recipients_cap": 100, "max_downloads_cap": 100})
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _client_with_token(token):
    """A fresh session sharing an existing user's token — for firing concurrent same-user requests
    without re-logging in (which could supersede sessions)."""
    c = ApiClient()
    c.token = token
    c.session.headers.update({"Authorization": f"Bearer {token}"})
    return c


def test_concurrent_claims_never_exceed_max_recipients(admin):
    """N users race to claim a share with max_recipients=CAP; exactly CAP succeed, the rest 409, and
    the DB holds exactly CAP active claims (the with_for_update recipient-slot guard)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("hcrec"))
    N, CAP = 8, 3
    users = [admin.create_user(role="user") for _ in range(N)]
    try:
        share = _make_share(admin, v, _tag(admin), max_recipients=CAP)
        clients = []
        for u in users:
            c = ApiClient()
            c.login(u["_username"], u["_password"])
            clients.append(c)

        # A Barrier makes the race DETERMINISTIC: each thread warms its connection (so the release
        # isn't gated by TCP setup), then all N block until every thread has arrived and fire the
        # claim together — reliably overlapping the with_for_update slot-lock window.
        barrier = threading.Barrier(N)

        def claim(c):
            c.get("/shares/shared-with-me")  # warm the pooled connection
            barrier.wait(timeout=30)
            return c.post("/shares/claim", json={"token": share["link_token"]}).status_code

        with ThreadPoolExecutor(max_workers=N) as ex:
            codes = list(ex.map(claim, clients))
        succeeded = sum(1 for x in codes if x == 200)
        assert succeeded == CAP, f"expected {CAP} successful claims, got {succeeded}: {codes}"
        assert all(x in (200, 409) for x in codes), f"unexpected status: {codes}"
        n = _psql_out(f"SELECT count(*) FROM share_claims WHERE share_id='{share['id']}' AND revoked=false")
        assert int(n) == CAP, f"DB active-claim count {n} != cap {CAP}"
    finally:
        for u in users:
            admin.delete_user(u["id"])
        admin.delete_vault(v["id"])


def test_concurrent_downloads_never_exceed_max_downloads(admin, temp_user):
    """One recipient fires N concurrent downloads of a share with max_downloads=CAP; exactly CAP
    succeed, the rest 403, and download_count == CAP (the atomic conditional-increment burn)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("hcdl"))
    N, CAP = 8, 3
    try:
        admin.post(f"/vaults/{v['id']}/files",
                   files=[("files", ("f.txt", b"payload-bytes " * 50, "text/plain"))])
        fid = next(it["id"] for it in admin.get(f"/vaults/{v['id']}/files").json()["items"]
                   if it["name"] == "f.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=CAP)

        base = ApiClient()
        base.login(temp_user["_username"], temp_user["_password"])
        assert base.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        # N sessions sharing the SAME recipient token (concurrent downloads against one ShareClaim)
        clients = [_client_with_token(base.token) for _ in range(N)]
        # Barrier + warm-up so all N downloads contend the atomic download_count increment together.
        barrier = threading.Barrier(N)

        def dl(c):
            c.get("/shares/shared-with-me")  # warm the pooled connection
            barrier.wait(timeout=30)
            return c.get(f"/vaults/{v['id']}/files/{fid}/download").status_code

        with ThreadPoolExecutor(max_workers=N) as ex:
            codes = list(ex.map(dl, clients))
        succeeded = sum(1 for x in codes if x == 200)
        assert succeeded == CAP, f"expected {CAP} successful downloads, got {succeeded}: {codes}"
        assert all(x in (200, 403) for x in codes), f"unexpected status: {codes}"
        n = _psql_out(f"SELECT download_count FROM share_claims "
                      f"WHERE share_id='{share['id']}' AND user_id='{temp_user['id']}'")
        assert int(n) == CAP, f"download_count {n} != cap {CAP}"
    finally:
        admin.delete_vault(v["id"])
