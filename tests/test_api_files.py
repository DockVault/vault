"""Files & folders: upload, list, download, rename, delete, folders.

Upload contract: multipart form-data, field name ``files`` (repeatable),
optional ``folder_id`` query param, optional ``X-Vault-Password`` header.
"""
import os
from datetime import datetime

from conftest import unique


def _upload(client, vault_id, name, content, folder_id=None, password=None):
    files = [("files", (name, content, "text/plain"))]
    params = {"folder_id": folder_id} if folder_id else None
    headers = {"X-Vault-Password": password} if password else None
    return client.post(f"/vaults/{vault_id}/files", files=files, params=params, headers=headers)


def test_upload_list_download_roundtrip(admin, temp_vault):
    vid = temp_vault["id"]
    content = b"hello dockvault\n" * 50
    name = unique("file") + ".txt"

    r = _upload(admin, vid, name, content)
    assert r.status_code == 200, r.text
    file_id = r.json()["files"][0]["id"]

    # list
    r = admin.get(f"/vaults/{vid}/files")
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(it["id"] == file_id for it in items)

    # download — content must match exactly
    r = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert r.status_code == 200
    assert r.content == content


def test_rename_file(admin, temp_vault):
    vid = temp_vault["id"]
    r = _upload(admin, vid, unique("f") + ".txt", b"data")
    file_id = r.json()["files"][0]["id"]
    new_name = unique("renamed") + ".txt"
    r = admin.put(f"/vaults/{vid}/files/{file_id}/rename", json={"new_name": new_name})
    assert r.status_code == 200
    assert r.json()["new_name"] == new_name


def test_delete_file(admin, temp_vault):
    vid = temp_vault["id"]
    r = _upload(admin, vid, unique("f") + ".txt", b"to be deleted")
    file_id = r.json()["files"][0]["id"]
    r = admin.post(f"/vaults/{vid}/files/{file_id}/delete")
    assert r.status_code == 200
    # download now 404
    r = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert r.status_code == 404


def test_create_folder_and_upload_into_it(admin, temp_vault):
    vid = temp_vault["id"]
    folder_name = unique("folder")
    r = admin.post(f"/vaults/{vid}/folders", json={"name": folder_name})
    assert r.status_code == 200, r.text
    folder_id = r.json()["folder"]["id"]

    # folder shows up in listing
    r = admin.get(f"/vaults/{vid}/files")
    items = r.json()["items"]
    assert any(it["id"] == folder_id and it["type"] == "folder" for it in items)

    # upload a file inside the folder
    r = _upload(admin, vid, unique("nested") + ".txt", b"nested", folder_id=folder_id)
    assert r.status_code == 200
    # listing the folder shows the nested file
    r = admin.get(f"/vaults/{vid}/files", params={"folder_id": folder_id})
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1


def test_rename_folder(admin, temp_vault):
    vid = temp_vault["id"]
    r = admin.post(f"/vaults/{vid}/folders", json={"name": unique("dir")})
    folder_id = r.json()["folder"]["id"]
    new_name = unique("renamed-dir")
    r = admin.put(f"/vaults/{vid}/files/{folder_id}/rename", json={"new_name": new_name})
    assert r.status_code == 200, r.text
    assert r.json()["new_name"] == new_name and r.json()["file_type"] == "folder"


def test_delete_folder_recursive(admin, temp_vault):
    vid = temp_vault["id"]
    r = admin.post(f"/vaults/{vid}/folders", json={"name": unique("dir")})
    folder_id = r.json()["folder"]["id"]
    # a file inside it
    r = _upload(admin, vid, unique("inside") + ".txt", b"bye", folder_id=folder_id)
    file_id = r.json()["files"][0]["id"]
    # delete the folder
    r = admin.post(f"/vaults/{vid}/folders/{folder_id}/delete")
    assert r.status_code == 200, r.text
    # the folder is gone from the root listing and the nested file is unreachable
    items = admin.get(f"/vaults/{vid}/files").json()["items"]
    assert not any(it["id"] == folder_id for it in items)
    assert admin.get(f"/vaults/{vid}/files/{file_id}/download").status_code == 404


# ---- resumable chunked uploads -------------------------------------------
_OCTET = {"Content-Type": "application/octet-stream"}


def _chunks(data, chunk_size):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def test_chunked_upload_resume_roundtrip(admin, temp_vault):
    """init → one chunk → resume same session → reject incomplete → complete →
    download is byte-identical (proves the full encrypt/decrypt round-trip)."""
    import hashlib
    vid = temp_vault["id"]
    chunk_size = 5 * 1024 * 1024
    data = bytes((i * 7 + 3) % 256 for i in range(7 * 1024 * 1024))  # ~7 MB → 2 chunks
    parts = _chunks(data, chunk_size)
    name = unique("big") + ".bin"

    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": name, "total_size": len(data),
        "total_chunks": len(parts), "chunk_size": chunk_size,
        "mime_type": "application/octet-stream",
    })
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]
    assert r.json()["received_chunks"] == []

    # upload only the first chunk, then "pause"
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=parts[0], headers=_OCTET).status_code == 200

    # resume: re-init the same file returns the SAME session and what it has
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": name, "total_size": len(data),
        "total_chunks": len(parts), "chunk_size": chunk_size,
    })
    assert r.json()["session_id"] == sid
    assert r.json()["received_chunks"] == [0]

    # completing while incomplete reports the missing index
    r = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert r.status_code == 409
    assert 1 in r.json()["detail"]["missing_chunks"]

    # finish the remaining chunks
    for i in range(1, len(parts)):
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/{i}", data=parts[i], headers=_OCTET).status_code == 200

    r = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert r.status_code == 200, r.text
    file_id = r.json()["id"]

    # session no longer listed as resumable
    assert all(s["session_id"] != sid for s in admin.get(f"/vaults/{vid}/uploads").json())

    # integrity
    r = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert r.status_code == 200
    assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(data).hexdigest()


def test_chunked_upload_cancel(admin, temp_vault):
    vid = temp_vault["id"]
    data = b"x" * 4096
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("c") + ".bin", "total_size": len(data),
        "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
    })
    sid = r.json()["session_id"]
    admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=data, headers=_OCTET)

    assert admin.delete(f"/vaults/{vid}/uploads/{sid}").status_code == 200
    assert all(s["session_id"] != sid for s in admin.get(f"/vaults/{vid}/uploads").json())
    # a cancelled session can't be completed
    assert admin.post(f"/vaults/{vid}/uploads/{sid}/complete").status_code == 409


def test_chunked_upload_into_folder(admin, temp_vault):
    vid = temp_vault["id"]
    folder_id = admin.post(f"/vaults/{vid}/folders", json={"name": unique("up")}).json()["folder"]["id"]
    data = b"folder-bound-chunk" * 100
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("f") + ".bin", "total_size": len(data),
        "total_chunks": 1, "chunk_size": 5 * 1024 * 1024, "folder_id": folder_id,
    })
    sid = r.json()["session_id"]
    admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=data, headers=_OCTET)
    file_id = admin.post(f"/vaults/{vid}/uploads/{sid}/complete").json()["id"]
    # the finished file lives inside the target folder
    items = admin.get(f"/vaults/{vid}/files", params={"folder_id": folder_id}).json()["items"]
    assert any(it["id"] == file_id for it in items)


def test_chunked_upload_rejects_oversized_chunk(admin, temp_vault):
    """Transient-disk-pressure guard: a chunk that would push the buffered bytes past
    the size declared (and quota-checked) at init is rejected (413), so a client can't
    balloon the _uploads/ buffer past what the limits already approved."""
    vid = temp_vault["id"]
    name = unique("dp") + ".bin"
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": name, "total_size": 100,
        "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
    })
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]
    # A single chunk bigger than the declared total is refused before it lands on disk.
    over = admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"x" * 200, headers=_OCTET)
    assert over.status_code == 413, over.text
    # The exact declared size still succeeds.
    ok = admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"x" * 100, headers=_OCTET)
    assert ok.status_code == 200, ok.text


def test_chunked_upload_rejects_cumulative_overflow(admin, temp_vault):
    """Even chunks that are individually small can't sum past the declared total: the
    bound is on the running buffered total, not just one chunk."""
    vid = temp_vault["id"]
    name = unique("dp2") + ".bin"
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": name, "total_size": 10,
        "total_chunks": 2, "chunk_size": 8,
    })
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"abcdef", headers=_OCTET).status_code == 200
    # 6 + 6 = 12 > 10 declared -> rejected
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=b"ghijkl", headers=_OCTET).status_code == 413
    # within budget (6 + 4 = 10) -> accepted
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=b"ghij", headers=_OCTET).status_code == 200


def test_chunked_upload_overwrite_corrects_byte_total(admin, temp_vault):
    """Re-sending a chunk at a different (in-budget) size must CORRECT the running byte
    total, not double-count it — otherwise the cumulative bound would be poisoned and a
    legitimate retried chunk would be falsely 413'd. Also proves the overwrite wins on disk."""
    vid = temp_vault["id"]
    name = unique("ow") + ".bin"
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": name, "total_size": 10, "total_chunks": 2, "chunk_size": 6,
    })
    sid = r.json()["session_id"]
    # chunk 0 = 6 bytes, then re-sent (overwritten) as 5 bytes.
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"aaaaaa", headers=_OCTET).status_code == 200
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"bbbbb", headers=_OCTET).status_code == 200
    # If the overwrite double-counted (6+5=11) the budget would be poisoned and this 5-byte
    # chunk 1 (5 used + 5 = 10) would be wrongly 413'd. It must be accepted.
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=b"ccccc", headers=_OCTET).status_code == 200
    out = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert out.status_code == 200, out.text
    fid = out.json()["id"]
    # The overwritten bytes (not the original) are what gets stored + reassembled.
    assert admin.get(f"/vaults/{vid}/files/{fid}/download").content == b"bbbbb" + b"ccccc"


# ---- chunk-session TTL is configurable ------------------------------------

def test_chunk_session_ttl_is_configurable(admin, temp_vault):
    """The session TTL now flows from settings (CHUNK_SESSION_TTL_HOURS, default 24h) instead
    of a hardcoded constant. We cross-check two independent surfaces: the server-computed
    ttl_hours from the maintenance inspect endpoint (clock-independent), and the init-returned
    expires_at (a wall-clock sanity check). If a deployment overrides the TTL, run the suite
    with the same CHUNK_SESSION_TTL_HOURS so this matches.

    NOTE: with the default stack all three sources are 24, so this can't by itself distinguish
    the settings path from the old literal — to fully prove configurability, run against a
    deployment with a non-default CHUNK_SESSION_TTL_HOURS and this asserts the override tracks."""
    vid = temp_vault["id"]
    ttl_hours = int(os.environ.get("CHUNK_SESSION_TTL_HOURS", "24"))

    # Surface 1: the server's own computed TTL (no host-clock dependence).
    info = admin.get("/api/maintenance/upload-sessions")
    assert info.status_code == 200, info.text
    assert info.json()["ttl_hours"] == ttl_hours, (
        f"inspect ttl_hours {info.json()['ttl_hours']} != configured {ttl_hours}"
    )

    # Surface 2: the expiry stamped on a new session (wall-clock cross-check).
    t0 = datetime.utcnow()
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("ttl") + ".bin", "total_size": 10,
        "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
    })
    assert r.status_code == 200, r.text
    expires_raw = r.json()["expires_at"]
    assert expires_raw, "init did not return an expires_at"
    # expires_at is naive UTC (server datetime.utcnow()); compare to a host naive-UTC stamp.
    expires_at = datetime.fromisoformat(expires_raw.replace("Z", ""))
    delta_hours = (expires_at - t0).total_seconds() / 3600.0
    # init happens within ~1s of t0; allow a wider tolerance to absorb host/container clock
    # skew (Docker Desktop clocks can drift after sleep/resume) — the precise value is pinned
    # by the clock-independent inspect check above.
    assert abs(delta_hours - ttl_hours) < 0.25, (
        f"expires_at is {delta_hours:.3f}h from now, expected ~{ttl_hours}h "
        f"(if far off, suspect host/container clock skew)"
    )


# ---- concurrent multi-session disk pressure -------------------------------

def test_chunked_upload_concurrent_sessions_independent_bounds(admin, temp_vault):
    """Several resumable sessions open at once must each enforce their OWN per-session
    transient-disk bound — one session's buffered bytes can neither poison nor relax
    another's budget. Interleave chunk writes across 3 concurrent sessions and assert each
    independently 413s its own overflow while still accepting its own in-budget bytes, then
    completes to the exact reassembled content."""
    vid = temp_vault["id"]
    # Each session: total_size=10, two 6-byte-capable chunks. 6+6=12 overflows; 6+4=10 fits.
    sids = []
    for _ in range(3):
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "file_name": unique("ms") + ".bin", "total_size": 10,
            "total_chunks": 2, "chunk_size": 6,
        })
        assert r.status_code == 200, r.text
        sids.append(r.json()["session_id"])

    # Round 1 (interleaved): every session takes a 6-byte chunk 0 — all accepted.
    for sid in sids:
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"AAAAAA", headers=_OCTET).status_code == 200

    # Round 2 (interleaved): a 6-byte chunk 1 would make 12 > 10 for EACH session
    # independently — every one must 413 (no cross-session budget sharing).
    for sid in sids:
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=b"BBBBBB", headers=_OCTET).status_code == 413

    # Round 3 (interleaved): the in-budget 4-byte chunk 1 (6+4=10) is accepted for each.
    for sid in sids:
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/1", data=b"CCCC", headers=_OCTET).status_code == 200

    # Each session finalises independently to its own exact bytes.
    for sid in sids:
        out = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
        assert out.status_code == 200, out.text
        fid = out.json()["id"]
        assert admin.get(f"/vaults/{vid}/files/{fid}/download").content == b"AAAAAA" + b"CCCC"


# ---- operator maintenance: orphaned chunk-session cleanup -----------------

def test_upload_session_maintenance_requires_admin(temp_user_client):
    """The maintenance inspect + cleanup endpoints are operator-only (admin) — including the
    most destructive invocation (deployment-wide hard purge), proven explicitly rather than
    inferred from the param-less call."""
    assert temp_user_client.get("/api/maintenance/upload-sessions").status_code == 403
    assert temp_user_client.post("/api/maintenance/upload-sessions/cleanup").status_code == 403
    # The deployment-wide hard purge (idle_minutes=0, no vault scope) is also refused.
    assert temp_user_client.post("/api/maintenance/upload-sessions/cleanup",
                                 params={"idle_minutes": 0}).status_code == 403


def test_upload_session_inspect_reports_disk(admin, temp_vault):
    """GET inspect returns a well-formed operator view including the configured TTL and the
    buffered-chunk disk footprint, which must reflect a freshly buffered chunk."""
    vid = temp_vault["id"]
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("insp") + ".bin", "total_size": 8,
        "total_chunks": 1, "chunk_size": 8,
    })
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"12345678", headers=_OCTET).status_code == 200

    info = admin.get("/api/maintenance/upload-sessions")
    assert info.status_code == 200, info.text
    body = info.json()
    for key in ("ttl_hours", "active_sessions", "terminal_or_expired_rows",
                "chunk_dirs", "orphan_dirs", "bytes_on_disk"):
        assert key in body, f"missing {key} in {body}"
    assert body["ttl_hours"] >= 1
    assert body["active_sessions"] >= 1       # our just-created session
    assert body["chunk_dirs"] >= 1            # its buffered chunk dir
    assert body["bytes_on_disk"] >= 8         # at least the 8 bytes we wrote
    # Our session is active, so its dir must NOT be counted as an orphan: there is at least
    # one non-orphan (active) chunk dir — proving orphan_dirs excludes live sessions.
    assert body["chunk_dirs"] - body["orphan_dirs"] >= 1, body
    # Tidy up so we don't leave a session lingering for the suite.
    admin.delete(f"/vaults/{vid}/uploads/{sid}")


def test_upload_session_cleanup_deployment_wide_keeps_active(admin, temp_vault):
    """The UNSCOPED sweep (no vault_id) is the path the periodic cleaner runs every few
    minutes in production — and it is the destructive 'remove every dir not actively kept'
    branch. It must still preserve an active, freshly-chunked session: assert on THIS
    session's survival (not global counts, which other suites perturb) by completing it."""
    vid = temp_vault["id"]
    data = b"survive-the-deployment-wide-sweep"
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("dw") + ".bin", "total_size": len(data),
        "total_chunks": 1, "chunk_size": len(data),
    })
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=data, headers=_OCTET).status_code == 200

    # Deployment-wide, default (no idle): keeps active+unexpired sessions across all vaults.
    res = admin.post("/api/maintenance/upload-sessions/cleanup")
    assert res.status_code == 200, res.text
    assert res.json()["scope"] == "deployment"
    assert res.json()["active_sessions_kept"] >= 1

    # Proof our specific in-flight session + its chunks survived the unscoped sweep.
    out = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert out.status_code == 200, out.text
    fid = out.json()["id"]
    assert admin.get(f"/vaults/{vid}/files/{fid}/download").content == data


def test_upload_session_cleanup_preserves_active(admin, temp_vault):
    """The DEFAULT cleanup (no idle threshold) is SAFE: it never destroys an active,
    unexpired upload — the buffered chunks survive and the upload still completes."""
    vid = temp_vault["id"]
    data = b"keep-me-alive-during-cleanup"
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("safe") + ".bin", "total_size": len(data),
        "total_chunks": 1, "chunk_size": len(data),
    })
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=data, headers=_OCTET).status_code == 200

    # A default, vault-scoped cleanup must keep the active session.
    res = admin.post("/api/maintenance/upload-sessions/cleanup", params={"vault_id": vid})
    assert res.status_code == 200, res.text
    assert res.json()["active_sessions_kept"] >= 1

    # Proof the live session + its chunks survived: it still completes.
    out = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert out.status_code == 200, out.text
    fid = out.json()["id"]
    assert admin.get(f"/vaults/{vid}/files/{fid}/download").content == data


def test_upload_session_cleanup_respects_idle_threshold(admin, temp_vault):
    """An idle threshold only reclaims sessions whose last chunk is OLDER than it. A just-
    written session (idle ~0) is left intact by a 60-minute threshold."""
    vid = temp_vault["id"]
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("idle") + ".bin", "total_size": 6,
        "total_chunks": 2, "chunk_size": 6,  # leave it incomplete (a stalled upload)
    })
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"ABCDEF", headers=_OCTET).status_code == 200

    res = admin.post("/api/maintenance/upload-sessions/cleanup",
                     params={"vault_id": vid, "idle_minutes": 60})
    assert res.status_code == 200, res.text
    assert res.json()["rows_pruned"] == 0, "recent session was wrongly reclaimed"
    # Still present and resumable.
    assert admin.get(f"/vaults/{vid}/uploads/{sid}").status_code == 200
    admin.delete(f"/vaults/{vid}/uploads/{sid}")


def test_upload_session_cleanup_force_reclaims_idle(admin, temp_vault):
    """idle_minutes=0 hard-purges active sessions: a stalled upload's row AND its buffered
    chunks are reclaimed on demand, instead of lingering under _uploads/<sid>/ until the TTL.
    Scoped to the vault so it can't disturb any other deployment session."""
    vid = temp_vault["id"]
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("stall") + ".bin", "total_size": 12,
        "total_chunks": 2, "chunk_size": 6,  # only chunk 0 sent -> stalled, never completes
    })
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"STALL0", headers=_OCTET).status_code == 200

    res = admin.post("/api/maintenance/upload-sessions/cleanup",
                     params={"vault_id": vid, "idle_minutes": 0})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["rows_pruned"] >= 1, body
    assert body["dirs_removed"] >= 1, body
    assert body["bytes_reclaimed"] >= 6, body

    # The session row + its chunks are gone: it can no longer be inspected or completed.
    assert admin.get(f"/vaults/{vid}/uploads/{sid}").status_code == 404
    assert admin.post(f"/vaults/{vid}/uploads/{sid}/complete").status_code == 404


def test_upload_session_cleanup_reclaims_concurrent_buffered_chunks(admin, temp_vault):
    """Many concurrent stalled sessions each buffer chunks on disk (the documented aggregate
    transient-disk exposure). The operator force-cleanup reclaims all of THIS vault's buffered
    sessions in one call — the mitigation for the multi-session disk-pressure limitation."""
    vid = temp_vault["id"]
    n = 4
    sids = []
    for _ in range(n):
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "file_name": unique("cc") + ".bin", "total_size": 20,
            "total_chunks": 2, "chunk_size": 10,  # one 10-byte chunk each, left incomplete
        })
        sid = r.json()["session_id"]
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=b"0123456789", headers=_OCTET).status_code == 200
        sids.append(sid)

    res = admin.post("/api/maintenance/upload-sessions/cleanup",
                     params={"vault_id": vid, "idle_minutes": 0})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["rows_pruned"] >= n, body
    assert body["dirs_removed"] >= n, body
    assert body["bytes_reclaimed"] >= n * 10, body
    # Every buffered session is gone.
    for sid in sids:
        assert admin.get(f"/vaults/{vid}/uploads/{sid}").status_code == 404


def test_upload_to_password_vault(admin, temp_vault_pw):
    vid = temp_vault_pw["id"]
    pw = temp_vault_pw["_password"]
    # without password -> rejected
    r = _upload(admin, vid, unique("f") + ".txt", b"secret")
    assert r.status_code in (401, 403)
    # with password -> ok and downloadable
    r = _upload(admin, vid, unique("f") + ".txt", b"secret", password=pw)
    assert r.status_code == 200
    file_id = r.json()["files"][0]["id"]
    r = admin.get(f"/vaults/{vid}/files/{file_id}/download",
                  headers={"X-Vault-Password": pw})
    assert r.status_code == 200
    assert r.content == b"secret"
