"""What the download endpoint promises, now that it streams instead of buffering.

The response no longer slices an in-memory copy of the file. Three things follow, and each is
observable from the client:

- the response length comes from the terminal the at-rest walk authenticated, so it is the writer's
  sealed statement of the size rather than the server's opinion;
- a file that fails its structural checks fails before the body exists, as an ordinary error;
- the audit log distinguishes access being granted from the transfer completing, which it did not:
  every download was recorded as a success before its first byte was sent.
"""

import hashlib

import pytest

from conftest import skip_if_container_absent, unique


_OCTET = {"Content-Type": "application/octet-stream"}
MB = 1024 * 1024


def _upload(client, vault_id, name, content, chunk_size=None):
    """Store a file through the resumable path, which is what the browser uses."""
    chunk_size = chunk_size or max(1, len(content))
    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content),
        "total_chunks": total_chunks, "chunk_size": chunk_size,
        "mime_type": "application/octet-stream",
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    for i in range(total_chunks):
        part = content[i * chunk_size:(i + 1) * chunk_size]
        r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=part, headers=_OCTET)
        assert r.status_code == 200, r.text
    done = client.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    return done.json()["id"]


def test_a_download_round_trips_byte_for_byte(admin, temp_vault):
    """The property a user notices. Several sizes, including one that is not a chunk multiple."""
    vid = temp_vault["id"]
    # The resumable upload path refuses a declared size of zero, so an empty file cannot be
    # created through it; the zero-piece case is covered where it can be, against the reader.
    for size in (1, 4096, 3 * MB + 7):
        body = bytes((i * 31 + 7) % 256 for i in range(min(size, 65536)))
        body = (body * (size // len(body) + 1))[:size] if body else b""
        file_id = _upload(admin, vid, unique("rt") + ".bin", body)
        got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
        assert got.status_code == 200, got.text
        assert got.content == body, f"round trip differed at {size} bytes"


def test_the_response_length_is_the_authenticated_one(admin, temp_vault):
    """Content-Length must equal the plaintext size, and be present.

    It comes from the terminal rather than from a buffer, so it is what makes a stream that stops
    early detectable as a short body.
    """
    vid = temp_vault["id"]
    body = b"length-check" * 5000
    file_id = _upload(admin, vid, unique("len") + ".bin", body, chunk_size=MB)

    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code == 200
    assert got.headers.get("Content-Length") == str(len(body))
    assert len(got.content) == len(body)


def test_a_large_download_does_not_cost_the_file_in_memory(admin, temp_vault):
    """The point of the change, measured rather than asserted.

    Before this, a download cost about twice the file: the reader collected every decrypted record
    and joined them, and one copy stayed resident for the whole response. The threshold is loose --
    half the file -- because this distinguishes "scales with the file" from "does not".

    Sampled continuously. An earlier version read memory before and after the request, which
    measures the residue rather than the peak and passed against a build that held the whole file.
    """
    from memory_probe import CgroupSampler

    vid = temp_vault["id"]
    size = 64 * MB
    body = bytes((i * 7 + 3) % 256 for i in range(65536)) * (size // 65536)
    file_id = _upload(admin, vid, unique("big") + ".bin", body, chunk_size=MB)

    with CgroupSampler() as sampler:
        got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    rise = sampler.rise

    assert got.status_code == 200
    assert hashlib.sha256(got.content).hexdigest() == hashlib.sha256(body).hexdigest(), (
        "the download did not return what was stored, so this measured nothing")
    assert rise < size // 2, (
        f"a {size // MB} MB download raised allocated memory by {rise / MB:.1f} MB; the file is "
        "being held rather than streamed")


def test_a_corrupted_stored_file_fails_before_the_body_and_says_nothing_useful(admin, temp_vault):
    """Truncating the blob is caught by the walk, so there is no partial body.

    And the response must not name which check failed: that is an oracle telling whoever damaged
    the blob which of their edits was detected.
    """
    import os
    import subprocess

    vid = temp_vault["id"]
    body = b"corrupt-me" * 5000
    file_id = _upload(admin, vid, unique("bad") + ".bin", body, chunk_size=MB)

    api = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    db = os.environ.get("VAULT_DB_CONTAINER", "vault-db")

    # Ask the database where this exact file lives, rather than guessing from modification times.
    query = f"SELECT storage_path FROM files WHERE id = '{file_id}';"
    found = subprocess.run(
        ["docker", "exec", db, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", query],
        capture_output=True, text=True, timeout=60)
    rel = found.stdout.strip()
    skip_if_container_absent(found, db)
    assert found.returncode == 0 and rel, (
        "could not locate the stored blob, so the corruption below was never applied and this "
        f"test checked nothing: {found.stderr.strip()[:200]}")

    # An absolute size: the container's truncate does not accept a relative one.
    cut = subprocess.run(
        ["docker", "exec", api, "sh", "-c",
         f"f='/app/storage/{rel}'; n=$(wc -c < \"$f\"); truncate -s $((n - 2000)) \"$f\"; "
         f"wc -c < \"$f\""],
        capture_output=True, text=True, timeout=60)
    skip_if_container_absent(cut, api)
    assert cut.returncode == 0 and cut.stdout.strip().isdigit(), (
        "could not truncate the stored blob, so nothing was corrupted and the assertions below "
        f"would pass against an intact file: {cut.stderr.strip()[:200]}")
    assert int(cut.stdout.strip()) < len(body), "the blob was not actually shortened"

    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code >= 400, "a truncated blob was served as a success"
    assert got.content == b"" or len(got.content) < len(body), "a partial body was served"
    text = got.text.lower()
    for leak in ("terminal", "record", "chunk", "trailing", "decrypt"):
        assert leak not in text, f"the response named the failing check: {got.text[:200]}"


def test_access_and_completion_are_audited_separately(admin, temp_vault):
    """A download used to be logged 'success' before its first byte.

    Two rows now: one for the grant, one for what the transfer did.
    """
    vid = temp_vault["id"]
    body = b"audit" * 1000
    file_id = _upload(admin, vid, unique("aud") + ".bin", body)

    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code == 200 and got.content == body

    def rows(action):
        # The action filter matches by prefix, so 'file_download' also returns the completed rows.
        # Both the action and the resource have to match exactly or this compares the wrong row --
        # which is how an earlier version of this test read the completion row's status and
        # reported the grant as unchanged.
        r = admin.get("/audit/log", params={"action": action, "limit": 50})
        assert r.status_code == 200, r.text
        return [row for row in r.json()
                if row.get("action") == action
                and (row.get("resource_id") or "") == str(file_id)]

    granted = rows("file_download")
    completed = rows("file_download_completed")

    assert granted, "the authorization row is missing"
    assert completed, (
        "no completion row: a transfer's outcome is still recorded before it has one")
    assert granted[0].get("status") == "authorized", (
        f"the grant is still logged as {granted[0].get('status')!r}, which is a claim about a "
        "transfer that had not happened yet")
    assert completed[0].get("status") == "success"
    detail = completed[0].get("details") or {}
    assert detail.get("outcome") == "completed"
    assert detail.get("bytes_sent") == len(body) == detail.get("total_bytes"), (
        "the completion row does not say how much was actually transferred")


def _blob_path(file_id):
    """Where the database says this file lives, relative to the storage root."""
    import os
    import subprocess
    db = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    out = subprocess.run(
        ["docker", "exec", db, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
         f"SELECT storage_path FROM files WHERE id = '{file_id}';"],
        capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, db)
    assert out.returncode == 0 and out.stdout.strip(), (
        "could not locate the stored blob, so the caller cannot corrupt it and would check "
        f"nothing: {out.stderr.strip()[:200]}")
    return out.stdout.strip()


def _break_checksum(file_id):
    import os
    import subprocess
    db = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    out = subprocess.run(
        ["docker", "exec", db, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
         f"UPDATE files SET checksum_sha256 = repeat('d', 64) WHERE id = '{file_id}';"],
        capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, db)
    assert out.returncode == 0 and "UPDATE 1" in out.stdout, (
        "did not rewrite the checksum of exactly one row, so the stored checksum still matches "
        f"the blob and the test proves nothing: rc={out.returncode} "
        f"out={out.stdout.strip()[:120]} err={out.stderr.strip()[:120]}")


def test_an_empty_file_with_a_wrong_checksum_is_not_served_as_a_success(admin, temp_vault):
    """The case the hold-back cannot cover, because there is nothing to withhold.

    A zero-length response has no length to fall short of, so a mismatch raised inside the body
    reaches the client as a complete, successful, empty transfer -- the server's own audit log
    saying the check failed while the HTTP transaction says it did not. It has to become an error
    status before the headers are sent.

    The empty file goes in through the direct multipart upload, which accepts one; the resumable
    path refuses a declared size of zero.
    """
    vid = temp_vault["id"]
    name = unique("empty") + ".bin"
    created = admin.post(f"/vaults/{vid}/files",
                         files=[("files", (name, b"", "application/octet-stream"))])
    assert created.status_code == 200, created.text
    file_id = created.json()["files"][0]["id"]

    assert admin.get(f"/vaults/{vid}/files/{file_id}/download").status_code == 200

    _break_checksum(file_id)
    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code >= 400, (
        f"an empty file whose checksum does not match was served as {got.status_code} with "
        f"{len(got.content)} bytes; the client cannot tell this from success")


def test_a_file_with_a_wrong_checksum_leaves_the_client_short(admin, temp_vault):
    """The ordinary case: the response stops before the promised length."""
    vid = temp_vault["id"]
    body = b"held-back" * 20000
    file_id = _upload(admin, vid, unique("cks") + ".bin", body, chunk_size=MB)
    _break_checksum(file_id)

    import requests
    session = admin.session
    url = f"{admin.base_url}/vaults/{vid}/files/{file_id}/download"
    try:
        response = session.get(url, timeout=30)
        served = len(response.content)
    except requests.exceptions.ChunkedEncodingError:
        served = -1          # the transport itself reported the truncation
    assert served != len(body), (
        "the whole file was served for a checksum that did not match")


def test_an_unreadable_blob_is_an_error_status_not_an_empty_success(admin, temp_vault):
    """A blob that no reader recognises must fail before the response body exists.

    Anything without the chunk-stream magic is routed to the legacy reader, which is a generator:
    nothing in it runs until the first piece is pulled, which under a streaming response is after
    the headers have gone out. Left lazy, an unreadable blob produced a 200 with a full
    Content-Length and an empty body, where it used to produce an error status.
    """
    import os
    import subprocess

    vid = temp_vault["id"]
    body = b"unreadable" * 3000
    file_id = _upload(admin, vid, unique("garbage") + ".bin", body, chunk_size=MB)
    rel = _blob_path(file_id)

    api = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    wrote = subprocess.run(
        ["docker", "exec", api, "sh", "-c",
         f"printf 'not any known format at all' > '/app/storage/{rel}'"],
        capture_output=True, text=True, timeout=60)
    skip_if_container_absent(wrote, api)
    assert wrote.returncode == 0, (
        "could not replace the stored blob, so the file is still readable and the assertion "
        f"below would pass for the wrong reason: {wrote.stderr.strip()[:200]}")

    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code >= 400, (
        f"an unreadable blob was answered {got.status_code} with {len(got.content)} bytes and "
        f"Content-Length {got.headers.get('Content-Length')}")


def test_a_client_that_disconnects_is_not_recorded_as_having_received_the_file(admin, temp_vault):
    """`served` counts bytes handed to the server, not bytes that reached anyone.

    Writes after a disconnect are discarded silently, so a generator that only counts what it
    yielded runs to the end and records a client that left as having received everything --
    including the exact byte count it did not receive.

    Note what this test cannot do. Whether the old code got this wrong depended on the file size
    against the socket buffer: a body small enough to be written in one go is gone before the
    client's departure can be observed, and no check placed in the loop can change that. At this
    size the pre-fix build already reported the failure on this host, so this test guards the
    property rather than proving the fix -- and a body that fits in one write will still be
    recorded as delivered, by any implementation.
    """
    vid = temp_vault["id"]
    body = b"D" * (12 * MB)
    file_id = _upload(admin, vid, unique("drop") + ".bin", body, chunk_size=MB)

    url = f"{admin.base_url}/vaults/{vid}/files/{file_id}/download"
    response = admin.session.get(url, stream=True, timeout=30)
    assert response.status_code == 200
    next(response.iter_content(65536))          # take a little, then leave
    response.close()

    import time
    deadline = time.time() + 60
    row = None
    while time.time() < deadline:
        rows = [r for r in admin.get("/audit/log",
                                     params={"action": "file_download_completed",
                                             "limit": 50}).json()
                if r.get("action") == "file_download_completed"
                and (r.get("resource_id") or "") == str(file_id)]
        if rows:
            row = rows[0]
            break
        time.sleep(2)

    assert row is not None, "no completion row was written for the abandoned transfer"
    assert row.get("status") != "success", (
        f"an abandoned transfer was recorded as {row.get('status')!r}")
    detail = row.get("details") or {}
    assert detail.get("bytes_sent", 0) < len(body), (
        f"the audit claims {detail.get('bytes_sent')} of {len(body)} bytes reached a client that "
        "had already gone")
