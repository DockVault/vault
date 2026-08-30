"""Live API: the anonymous UPLOAD path of receivers — session OPEN (slice 3a).

Opening an anonymous upload session is the security-critical entry: it is rate-limited, secret-gated
with a per-link lockout, kill-switched, and — crucially — it ATOMICALLY RESERVES the declared size
against the receiver's total cap BEFORE any bytes move (reserve-at-open), and BINDS the minted
chunked-upload session to the receiver so it can only ever be finalized into that vault. The chunk PUT
and finalize are a later slice, so these cover OPEN only.
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


def _open(anon, token, **over):
    body = {"filename": "hello.txt", "total_size": 1000, "total_chunks": 1}
    body.update(over)
    return anon.post(f"/receivers/{token}/upload-session", json=body)


# --- happy path + reservation + binding -------------------------------------------------------------
def test_open_reserves_and_binds(admin, receivers_enabled):
    rec = _mk_receiver(admin, max_total_bytes=1 * _MB)
    token = rec["token"]
    anon = admin.clone_anonymous()
    r = _open(anon, token, filename="report.txt", total_size=4000, total_chunks=1)
    assert r.status_code == 200, r.text
    body = r.json()
    sid = body["session_id"]
    assert body["total_chunks"] == 1 and body["received_chunks"] == []

    # The declared size was reserved on the receiver (reserve-at-open).
    out = _psql(f"SELECT reserved_bytes FROM receivers WHERE id='{rec['id']}';")
    assert out.returncode == 0 and out.stdout.strip() == "4000", out.stderr or out.stdout
    # The session is bound to this receiver (so it can never finalize into another vault).
    b = _psql(f"SELECT receiver_id FROM receiver_upload_sessions WHERE session_id='{sid}';")
    assert b.stdout.strip() == rec["id"], b.stdout
    # The session belongs to the receiver's vault, owned by the receiver owner.
    s = _psql(f"SELECT vault_id FROM chunked_upload_sessions WHERE id='{sid}';")
    assert s.stdout.strip() == rec["vault_id"], s.stdout


# --- reserve-at-open enforces the total cap (GATE 2, sequential proof) ------------------------------
def test_reservation_blocks_over_capacity(admin, receivers_enabled):
    # A 20 KB receiver: two 15 KB opens can't both be reserved even though NOTHING has been finalized
    # (a count-at-finalize scheme would wrongly let both through).
    rec = _mk_receiver(admin, max_total_bytes=20 * _KB)
    token = rec["token"]
    anon = admin.clone_anonymous()
    first = _open(anon, token, total_size=15 * _KB, total_chunks=1)
    assert first.status_code == 200, first.text
    second = _open(anon, token, total_size=15 * _KB, total_chunks=1)
    assert second.status_code == 413, second.text
    # A small one that still fits alongside the first reservation succeeds.
    third = _open(anon, token, total_size=3 * _KB, total_chunks=1)
    assert third.status_code == 200, third.text


# --- per-file cap -----------------------------------------------------------------------------------
def test_per_file_cap(admin, receivers_enabled):
    tag = _mk_tag(admin, max_file_bytes_cap=2 * _MB)
    rec = _mk_receiver(admin, tag=tag, max_total_bytes=50 * _MB, max_file_bytes=1 * _MB)
    anon = admin.clone_anonymous()
    over = _open(anon, rec["token"], total_size=2 * _MB, total_chunks=1)
    assert over.status_code == 413, over.text
    ok = _open(anon, rec["token"], total_size=500 * _KB, total_chunks=1)
    assert ok.status_code == 200, ok.text


# --- file-type allowlist ----------------------------------------------------------------------------
def test_file_type_allowlist(admin, receivers_enabled):
    before = admin.get("/settings").json().get("allowed_file_types")
    admin.put("/settings", json={"allowed_file_types": ["txt", "pdf"]})
    try:
        rec = _mk_receiver(admin)
        anon = admin.clone_anonymous()
        bad = _open(anon, rec["token"], filename="malware.exe", total_size=1000, total_chunks=1)
        assert bad.status_code == 400, bad.text
        good = _open(anon, rec["token"], filename="doc.txt", total_size=1000, total_chunks=1)
        assert good.status_code == 200, good.text
    finally:
        admin.put("/settings", json={"allowed_file_types": before if before is not None else []})


# --- secret gate + lockout --------------------------------------------------------------------------
def test_secret_gate_and_lockout(admin, receivers_enabled):
    tag = _mk_tag(admin, require_secret="pin", min_pin_len=4)
    rec = _mk_receiver(admin, tag=tag, pin="4321")
    token = rec["token"]
    anon = admin.clone_anonymous()
    # no secret -> 401 secret_required
    r0 = _open(anon, token)
    assert r0.status_code == 401 and r0.json()["detail"]["error"] == "secret_required"
    # 5 wrong -> the 5th trips the lockout
    codes = [_open(anon, token, secret="0000").status_code for _ in range(5)]
    assert codes[:4] == [401, 401, 401, 401], codes
    assert codes[4] == 429, codes
    # even the correct pin is refused during lockout
    assert _open(anon, token, secret="4321").status_code == 429


def test_correct_secret_opens(admin, receivers_enabled):
    tag = _mk_tag(admin, require_secret="password", password_min_len=8)
    rec = _mk_receiver(admin, tag=tag, password="hunter2x")
    anon = admin.clone_anonymous()
    assert _open(anon, rec["token"], secret="nope1234").status_code == 401
    assert _open(anon, rec["token"], secret="hunter2x").status_code == 200


# --- kill switch / lifecycle / unknown --------------------------------------------------------------
def test_kill_switch_and_lifecycle_states(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    token = rec["token"]
    anon = admin.clone_anonymous()
    assert _open(anon, token).status_code == 200
    # paused -> 404
    admin.post(f"/receivers/{rec['id']}/pause", json={"paused": True})
    assert _open(anon, token).status_code == 404
    admin.post(f"/receivers/{rec['id']}/pause", json={"paused": False})
    assert _open(anon, token).status_code == 200
    # revoked -> 404
    admin.post(f"/receivers/{rec['id']}/revoke")
    assert _open(anon, token).status_code == 404


def test_master_switch_off_blocks_open(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    admin.put("/settings", json={"public_receivers_enabled": False})
    try:
        assert _open(admin.clone_anonymous(), rec["token"]).status_code == 404
    finally:
        admin.put("/settings", json={"public_receivers_enabled": True})


def test_unknown_token_is_404(admin, receivers_enabled):
    assert _open(admin.clone_anonymous(), "doesnotexist123").status_code == 404


def test_bad_upload_shape_rejected(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    anon = admin.clone_anonymous()
    assert _open(anon, rec["token"], total_size=0, total_chunks=1).status_code == 400
    assert _open(anon, rec["token"], total_size=1000, total_chunks=0).status_code == 400
    assert _open(anon, rec["token"], filename="", total_size=1000, total_chunks=1).status_code == 400
