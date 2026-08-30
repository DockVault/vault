"""Live API: the anonymous upload FINALIZE path of receivers (slice 3b) — open → chunk → complete.

The file must land in the receiver's OWN vault (derived from the session binding, never a client id —
GATE 3), the reserve-at-open allocation must be reconciled once the bytes are stored, and a session
bound to one receiver must never be drivable through another. The finalize is admitted on a separate
anon-inbound budget (GATE 1) so anonymous uploads can't starve authenticated transfers.
"""
import os
import subprocess

import pytest

from conftest import unique

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_KB = 1024
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


def _mk_tag(admin, **over):
    payload = {"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
               "min_pin_len": 4, "password_min_len": 8, "auto_enroll_new_users": True,
               "kind_floor": "standard", "max_total_bytes_cap": 50 * _MB,
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


def _open(anon, token, filename, size, chunks=1, secret=None):
    body = {"filename": filename, "total_size": size, "total_chunks": chunks}
    if secret is not None:
        body["secret"] = secret
    return anon.post(f"/receivers/{token}/upload-session", json=body)


def _put_chunk(anon, token, sid, index, data):
    return anon.put(f"/receivers/{token}/upload-session/{sid}/chunks/{index}",
                    data=data, headers={"Content-Type": "application/octet-stream"})


def _complete(anon, token, sid):
    return anon.post(f"/receivers/{token}/upload-session/{sid}/complete", json={})


def _upload(anon, token, filename, content, secret=None):
    """Full open→chunk→complete of a single-chunk file. Returns the complete() response."""
    o = _open(anon, token, filename, len(content), 1, secret=secret)
    assert o.status_code == 200, o.text
    sid = o.json()["session_id"]
    c = _put_chunk(anon, token, sid, 0, content)
    assert c.status_code == 200, c.text
    return _complete(anon, token, sid)


# --- happy path -------------------------------------------------------------------------------------
def test_open_chunk_finalize_lands_in_receiver_vault(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    content = b"anonymous drop payload " * 40   # ~920 bytes
    r = _upload(anon, rec["token"], "drop.txt", content)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["name"] == "drop.txt" and out["size"] == len(content)

    # The owner sees the file in the receiver's vault.
    items = admin.get(f"/vaults/{rec['vault_id']}/files").json()["items"]
    row = next((it for it in items if it.get("name") == "drop.txt" and it.get("type") == "file"), None)
    assert row is not None and row["size"] == len(content)

    # The reserve-at-open allocation was reconciled (bytes are now stored on the vault, not reserved).
    rb = _psql(f"SELECT reserved_bytes FROM receivers WHERE id='{rec['id']}';")
    assert rb.stdout.strip() == "0", rb.stdout
    # upload_count advanced.
    uc = _psql(f"SELECT upload_count FROM receivers WHERE id='{rec['id']}';")
    assert uc.stdout.strip() == "1", uc.stdout


def test_multi_chunk_upload(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    # 3 chunks of a tiny CHUNK is impractical (server chunk cap is 64 MiB); declare 2 chunks over a
    # small payload split by the client at an arbitrary boundary.
    content = b"A" * (5000)
    o = _open(anon, rec["token"], "big.txt", len(content), 2)
    assert o.status_code == 200, o.text
    sid = o.json()["session_id"]
    half = len(content) // 2
    assert _put_chunk(anon, rec["token"], sid, 0, content[:half]).status_code == 200
    assert _put_chunk(anon, rec["token"], sid, 1, content[half:]).status_code == 200
    r = _complete(anon, rec["token"], sid)
    assert r.status_code == 200 and r.json()["size"] == len(content)


# --- GATE 3: a session is bound to its receiver ----------------------------------------------------
def test_session_bound_cannot_be_driven_via_another_receiver(admin, receivers_enabled):
    a = _mk_receiver(admin)
    b = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    o = _open(anon, a["token"], "x.txt", 1000, 1)
    assert o.status_code == 200
    sid = o.json()["session_id"]
    # Receiver B's token must not accept receiver A's session (binding mismatch -> uniform 404).
    assert _put_chunk(anon, b["token"], sid, 0, b"x" * 1000).status_code == 404
    assert _complete(anon, b["token"], sid).status_code == 404
    # The legitimate owner-A path still works.
    assert _put_chunk(anon, a["token"], sid, 0, b"x" * 1000).status_code == 200
    assert _complete(anon, a["token"], sid).status_code == 200


def test_unknown_session_or_token_404(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    import uuid as _uuid
    fake = str(_uuid.uuid4())
    assert _put_chunk(anon, rec["token"], fake, 0, b"x").status_code == 404
    assert _complete(anon, rec["token"], fake).status_code == 404
    o = _open(anon, rec["token"], "x.txt", 1000, 1)
    sid = o.json()["session_id"]
    assert _complete(anon, "doesnotexist123", sid).status_code == 404


# --- duplicate name ---------------------------------------------------------------------------------
def test_duplicate_name_is_409(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    assert _upload(anon, rec["token"], "same.txt", b"first").status_code == 200
    # a second file with the same name is refused (an anon drop never overwrites)
    assert _upload(anon, rec["token"], "same.txt", b"second one").status_code == 409


# --- revoke mid-upload ------------------------------------------------------------------------------
def test_revoke_between_open_and_finalize(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    o = _open(anon, rec["token"], "y.txt", 1000, 1)
    sid = o.json()["session_id"]
    assert _put_chunk(anon, rec["token"], sid, 0, b"y" * 1000).status_code == 200
    # revoke the receiver -> the finalize is refused (uniform 404)
    admin.post(f"/receivers/{rec['id']}/revoke")
    assert _complete(anon, rec["token"], sid).status_code == 404


def test_kill_switch_between_open_and_finalize(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    o = _open(anon, rec["token"], "z.txt", 1000, 1)
    sid = o.json()["session_id"]
    admin.put("/settings", json={"public_receivers_enabled": False})
    try:
        assert _complete(anon, rec["token"], sid).status_code == 404
    finally:
        admin.put("/settings", json={"public_receivers_enabled": True})
