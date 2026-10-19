"""Live API: a public file link gives back its use when the server fails before the first byte.

Redeeming a link spends one of its uses, and the download that follows spends its single-use grant.
When the server then cannot start the file, the person received nothing, so the use is given back
and they can try again; the owner's card shows the link as it was, and the audit log says why. Each
failure is made for real in the running deployment: the stored file removed, overwritten, damaged in
its first record, made a directory, or its recorded checksum changed. A client that leaves after the
first byte, and a file that fails after its first byte, keep the use spent. Through all of it a link
capped at N delivers exactly N, with failures and successes at the same time too.

tests/test_public_link_download_refund.py runs the same handler offline, with the busy and the
internal-error cases a running deployment cannot be made to show on demand.
"""
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration

_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
MB = 1024 * 1024
_OCTET = {"Content-Type": "application/octet-stream"}


def _psql(sql, timeout=30):
    result = subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def _in_api(script):
    result = subprocess.run(["docker", "exec", _API_CONTAINER, "sh", "-c", script],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, f"{script!r}: {result.stderr or result.stdout}"
    return result.stdout.strip()


def _clear_open_throttle():
    """The opens of one link from one address are limited to ten a minute. A test that opens one link
    more often than that (each failure and retry is a redeem) clears the count between its phases."""
    keys = subprocess.run(["docker", "exec", _REDIS_CONTAINER, "redis-cli", "--scan", "--pattern",
                           "publiclink_redeem*"], capture_output=True, text=True, timeout=30)
    assert keys.returncode == 0, keys.stderr
    for key in [k for k in keys.stdout.split("\n") if k]:
        subprocess.run(["docker", "exec", _REDIS_CONTAINER, "redis-cli", "DEL", key],
                       capture_output=True, text=True, timeout=30, check=True)


@pytest.fixture
def files_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    r = admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def vault(admin):
    v = admin.create_vault(name=unique("refund"))
    yield v
    admin.delete_vault(v["id"])


def _tag(admin, cap):
    r = admin.post("/note-link-tags", json={
        "name": unique("rftag"), "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "max_uses_cap": cap, "require_secret": "none"})
    assert r.status_code in (200, 201), r.text
    return r.json()


def _upload(admin, vault_id, name, content, chunk_size=None, folder_id=None):
    """Through the resumable path, so a file can be stored as several records (one per chunk)."""
    chunk_size = chunk_size or max(1, len(content))
    total = max(1, (len(content) + chunk_size - 1) // chunk_size)
    body = {"file_name": name, "total_size": len(content), "total_chunks": total,
            "chunk_size": chunk_size, "mime_type": "application/octet-stream"}
    if folder_id:
        body["folder_id"] = folder_id
    init = admin.post(f"/vaults/{vault_id}/uploads", json=body)
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    for i in range(total):
        r = admin.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}",
                      data=content[i * chunk_size:(i + 1) * chunk_size], headers=_OCTET)
        assert r.status_code == 200, r.text
    done = admin.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    return done.json()["id"]


def _folder(admin, vault_id, name):
    r = admin.post(f"/vaults/{vault_id}/folders", json={"name": name})
    assert r.status_code in (200, 201), r.text
    return r.json()["folder"]["id"]


def _link(admin, vault_id, cap, *, file_id=None, folder_id=None):
    body = {"vault_id": vault_id, "tag_id": _tag(admin, cap)["id"], "ttl_hours": 1, "max_uses": cap}
    if file_id:
        body.update(target_type="file", target_file_id=file_id)
    else:
        body.update(target_type="folder", target_folder_id=folder_id)
    r = admin.post("/public-links", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _card(admin, link_id):
    return next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link_id)


def _counts(admin, link_id, use_count, download_count):
    deadline = time.monotonic() + 10
    while True:
        card = _card(admin, link_id)
        if (card["use_count"], card["download_count"]) == (use_count, download_count) \
                or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert (card["use_count"], card["download_count"]) == (use_count, download_count), card
    return card


def _redeem(base_url, token):
    return requests.post(f"{base_url}/public-links/{token}/redeem", json={}, timeout=30)


def _download(base_url, token, file_id, grant, **kw):
    return requests.get(f"{base_url}/public-links/{token}/download/{file_id}",
                        headers={"X-Download-Grant": grant}, timeout=120, **kw)


def _refunds(link_id):
    """The audit rows of uses given back for this link: (status, reason), oldest first."""
    out = _psql("SELECT status || '|' || (details->>'reason') FROM audit_logs "
                "WHERE action = 'public_link_use_refunded' "
                f"AND details->>'public_link_id' = '{link_id}' ORDER BY timestamp")
    return [tuple(line.split("|")) for line in out.splitlines() if line]


class _Blob:
    """The stored file behind one file record, in the API container, with a copy to put back."""

    def __init__(self, file_id):
        self.file_id = file_id
        rel = _psql(f"SELECT storage_path FROM files WHERE id = '{file_id}'")
        assert rel, "the file has no stored blob to break, so a test would check nothing"
        self.path = f"/app/storage/{rel}"
        _in_api(f"cp -p '{self.path}' '{self.path}.keep'")

    def restore(self):
        _in_api(f"rm -rf '{self.path}' && mv '{self.path}.keep' '{self.path}'")


def _remove(blob):
    _in_api(f"rm -f '{blob.path}'")


def _overwrite(blob):
    _in_api(f"n=$(wc -c < '{blob.path}'); head -c \"$n\" /dev/urandom > '{blob.path}.x' "
            f"&& cat '{blob.path}.x' > '{blob.path}' && rm -f '{blob.path}.x'")


def _damage_first_record(blob):
    # The header (28 bytes), the first record's length (4) and nonce (12): byte 100 is ciphertext of
    # record one. The walk reads only lengths and the terminal, so this fails at the first decrypt.
    _in_api("python -c \"import sys; p=sys.argv[1]; f=open(p,'r+b'); f.seek(100); b=f.read(1); "
            "f.seek(100); f.write(bytes([b[0] ^ 1])); f.close()\" " + f"'{blob.path}'")


def _make_a_directory(blob):
    _in_api(f"rm -f '{blob.path}' && mkdir '{blob.path}'")


FAILURES = {
    "the stored file is missing": (_remove, "file_missing"),
    "the stored file cannot be decrypted": (_overwrite, "unreadable"),
    "its first record fails authentication": (_damage_first_record, "unreadable"),
    "a directory stands where the file was": (_make_a_directory, "read_error"),
}


@pytest.mark.parametrize("failure", list(FAILURES))
def test_a_server_failure_before_the_first_byte_gives_back_one_use(admin, base_url, files_enabled,
                                                                   vault, failure):
    break_it, reason = FAILURES[failure]
    content = os.urandom(3 * MB + 5)
    file_id = _upload(admin, vault["id"], unique("rf") + ".bin", content, chunk_size=MB)
    link = _link(admin, vault["id"], 1, file_id=file_id)
    blob = _Blob(file_id)
    try:
        grant = _redeem(base_url, link["token"]).json()["grant"]
        _counts(admin, link["id"], 1, 0)
        break_it(blob)
        failed = _download(base_url, link["token"], file_id, grant)
        assert failed.status_code == 404 and failed.content == b'{"detail":"This file is not available."}'
        assert _refunds(link["id"]) == [("success", reason)]
        card = _counts(admin, link["id"], 0, 0)
        assert card["status"] == "active", "the one-download link did not get its download back"
        # The grant stays used: the same one cannot try again.
        assert _download(base_url, link["token"], file_id, grant).status_code == 404
        assert _refunds(link["id"]) == [("success", reason)]
    finally:
        blob.restore()
    # The person tries again once the file is back, and gets it: exactly one delivery, then used up.
    redeemed = _redeem(base_url, link["token"])
    assert redeemed.status_code == 200, redeemed.text
    got = _download(base_url, link["token"], file_id, redeemed.json()["grant"])
    assert got.status_code == 200 and got.content == content
    assert _counts(admin, link["id"], 1, 1)["status"] == "exhausted"
    assert _redeem(base_url, link["token"]).status_code == 404


def _break_checksum(file_id):
    """Record a checksum the stored bytes do not have. The plaintext column is normally empty and the
    checksum sealed beside it; both are kept and put back."""
    kept = _psql("SELECT coalesce(checksum_sha256, '') || '|' || coalesce(enc_checksum, '') "
                 f"FROM files WHERE id = '{file_id}'")
    plain, sealed = kept.split("|", 1)
    assert plain or sealed, "the file has no recorded checksum to break"
    assert _psql(f"UPDATE files SET checksum_sha256 = repeat('d', 64), enc_checksum = NULL "
                 f"WHERE id = '{file_id}'") == "UPDATE 1"

    def restore():
        def value(text):
            return f"'{text}'" if text else "NULL"
        assert _psql(f"UPDATE files SET checksum_sha256 = {value(plain)}, enc_checksum = {value(sealed)} "
                     f"WHERE id = '{file_id}'") == "UPDATE 1"
    return restore


def test_a_checksum_failure_of_a_one_record_file_gives_back_its_use(admin, base_url, files_enabled, vault):
    # A file of one record is held back whole until its checksum is checked, so the mismatch comes
    # before the first byte: nothing was sent, and the use comes back.
    content = os.urandom(200_000)
    file_id = _upload(admin, vault["id"], unique("sum") + ".bin", content)
    link = _link(admin, vault["id"], 1, file_id=file_id)
    grant = _redeem(base_url, link["token"]).json()["grant"]
    restore = _break_checksum(file_id)
    try:
        assert _download(base_url, link["token"], file_id, grant).status_code == 404
        assert _refunds(link["id"]) == [("success", "checksum_mismatch")]
        _counts(admin, link["id"], 0, 0)
    finally:
        restore()
    got = _download(base_url, link["token"], file_id, _redeem(base_url, link["token"]).json()["grant"])
    assert got.status_code == 200 and got.content == content
    _counts(admin, link["id"], 1, 1)


def test_a_checksum_failure_after_the_first_byte_keeps_the_use_spent(admin, base_url, files_enabled, vault):
    # Several records: the first goes out before the checksum can be known (the last is held back),
    # so the person has part of the file. The response stops short, and the use stays spent.
    content = os.urandom(3 * MB)
    file_id = _upload(admin, vault["id"], unique("late") + ".bin", content, chunk_size=MB)
    link = _link(admin, vault["id"], 2, file_id=file_id)
    grant = _redeem(base_url, link["token"]).json()["grant"]
    restore = _break_checksum(file_id)
    try:
        got = _download(base_url, link["token"], file_id, grant, stream=True)
        assert got.status_code == 200
        received = 0
        with pytest.raises((requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError)):
            for piece in got.iter_content(65536):
                received += len(piece)
        assert 0 < received < len(content), received
    finally:
        restore()
    time.sleep(1)
    assert _refunds(link["id"]) == []
    _counts(admin, link["id"], 1, 0)


def test_a_client_that_leaves_after_the_first_byte_keeps_the_use_spent(admin, base_url, files_enabled,
                                                                        vault):
    content = os.urandom(40 * MB)
    file_id = _upload(admin, vault["id"], unique("left") + ".bin", content, chunk_size=4 * MB)
    link = _link(admin, vault["id"], 2, file_id=file_id)
    grant = _redeem(base_url, link["token"]).json()["grant"]
    # A raw socket, so the test controls exactly how much it reads before it hangs up (over TLS when the
    # deployment serves https, trusting what requests is told to trust).
    url = urlparse(base_url)
    https = url.scheme == "https"
    sock = socket.create_connection((url.hostname, url.port or (443 if https else 80)), timeout=30)
    if https:
        import ssl
        context = ssl.create_default_context(cafile=os.environ.get("REQUESTS_CA_BUNDLE") or None)
        sock = context.wrap_socket(sock, server_hostname=url.hostname)
    try:
        sock.sendall((f"GET /public-links/{link['token']}/download/{file_id} HTTP/1.1\r\n"
                      f"Host: {url.hostname}\r\nX-Download-Grant: {grant}\r\nConnection: close\r\n\r\n").encode())
        got = b""
        while len(got) < 256 * 1024:
            piece = sock.recv(65536)
            assert piece, "the server closed before sending the file"
            got += piece
        assert got.startswith(b"HTTP/1.1 200")
    finally:
        sock.close()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        done = _psql("SELECT count(*) FROM audit_logs WHERE action = 'public_link_download_completed' "
                     f"AND details->>'public_link_id' = '{link['id']}'")
        if done == "1":
            break
        time.sleep(0.3)
    assert done == "1", "the download that was left never recorded how it ended"
    outcome = _psql("SELECT status || '|' || (details->>'outcome') FROM audit_logs "
                    "WHERE action = 'public_link_download_completed' "
                    f"AND details->>'public_link_id' = '{link['id']}'")
    assert outcome in ("failed|disconnected", "failed|incomplete"), outcome
    assert _refunds(link["id"]) == []
    _counts(admin, link["id"], 1, 0)


def test_failures_and_successes_at_once_keep_the_count_exact_and_a_capped_link_delivers_its_cap(
        admin, base_url, files_enabled, vault):
    """A folder link capped at two, with one file that cannot be served and one that can, downloaded by
    eight people at the same time: every failure gives back its use, every success keeps one, and the
    link delivers the good file exactly twice, however the requests interleave."""
    folder_id = _folder(admin, vault["id"], unique("mix"))
    good = os.urandom(300_000)
    good_id = _upload(admin, vault["id"], "good.bin", good, folder_id=folder_id)
    bad_id = _upload(admin, vault["id"], "bad.bin", os.urandom(50_000), folder_id=folder_id)
    cap = 2
    link = _link(admin, vault["id"], cap, folder_id=folder_id)
    blob = _Blob(bad_id)
    _remove(blob)
    start = threading.Barrier(8)

    def attempt(target):
        start.wait(timeout=30)
        redeemed = _redeem(base_url, link["token"])
        if redeemed.status_code != 200:
            return target, "refused", redeemed.status_code
        got = _download(base_url, link["token"], target, redeemed.json()["grant"])
        return target, "downloaded" if got.status_code == 200 else "failed", got.content if \
            got.status_code == 200 else got.status_code

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, [bad_id] * 4 + [good_id] * 4))
        delivered = [r for r in results if r[1] == "downloaded"]
        failed = [r for r in results if r[1] == "failed"]
        assert all(r[0] == good_id and r[2] == good for r in delivered), "a download delivered the wrong bytes"
        assert all(r[0] == bad_id and r[2] == 404 for r in failed)
        assert len(delivered) <= cap
        assert len(_refunds(link["id"])) == len(failed)
        assert all(status == "success" for status, _ in _refunds(link["id"]))
        _counts(admin, link["id"], len(delivered), len(delivered))

        # Then until the link is used up: the good file only, and never more than the cap.
        _clear_open_throttle()
        while True:
            redeemed = _redeem(base_url, link["token"])
            if redeemed.status_code == 404:
                break
            assert redeemed.status_code == 200, redeemed.text
            got = _download(base_url, link["token"], good_id, redeemed.json()["grant"])
            assert got.status_code == 200 and got.content == good
            delivered.append(got)
            assert len(delivered) <= cap, "the link delivered more than its cap"
        assert len(delivered) == cap
        assert _counts(admin, link["id"], cap, cap)["status"] == "exhausted"
    finally:
        blob.restore()
