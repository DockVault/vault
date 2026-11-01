"""While a large upload completes, the server goes on answering everyone else, on a running stack.

The web server answers every request from one event loop. Completing an upload reads its staged chunks,
encrypts them into the stored file and forces the file to the disk: seconds per GiB. That work ran on the
loop, so for its whole length the server answered nobody else, not even its health check. It now runs off
the loop (app/core/off_loop.py), each step to its end.

Here another client asks the health check and a vault listing over and over while uploads complete:
- one resumable upload: none of those requests waits as long as a third of the completion, nor a second;
- two at once: both are stored whole and read back the same, and the others are answered meanwhile;
- a client that goes away the moment it asked for the completion: the upload is stored whole, listed once,
  and no file is left on the disk that no row lists;
- a zero-knowledge upload refused at completion because the vault's key changed meanwhile: the refusal takes
  the vault's row lock, and the assembled file is then removed, which takes seconds. Every request that opens
  the vault (a listing records when it was opened) still answers at once, not after waiting for that lock.

The sizes are a few hundred MiB, so that a completion takes long enough to show a pause.
"""
import base64
import hashlib
import os
import subprocess
import threading
import time
import uuid

import pytest
import requests

from conftest import (
    ApiClient, create_zk_vault, ensure_ecc_keypair, post_zk, require_zk_first_chunk, zk_encrypt_name,
    zk_name_blind_index,
)

pytestmark = pytest.mark.integration

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")
CHUNK = 5 * 1024 * 1024


def _container():
    return os.environ.get("VAULT_API_CONTAINER", "vault-api")


class _Asker:
    """Another client: asks the health check and a listing, one after the other, and records when each
    request was sent and how long its answer took."""

    def __init__(self, admin, vault_id):
        self.session = requests.Session()
        self.session.headers.update(admin.session.headers)
        self.urls = [f"{BASE}/health", f"{BASE}/vaults/{vault_id}/files"]
        self.asked = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        i = 0
        while not self._stop.is_set():
            url = self.urls[i % len(self.urls)]
            i += 1
            sent = time.monotonic()
            try:
                status = self.session.get(url, timeout=60).status_code
            except requests.RequestException as exc:
                status = type(exc).__name__
            self.asked.append((sent, time.monotonic() - sent, url, status))
            time.sleep(0.05)

    def __enter__(self):
        self._thread.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(70)

    def during(self, start, end):
        return [a for a in self.asked if start <= a[0] <= end]


def _payload(seed: bytes, size: int):
    """`size` bytes, the same on every call for one seed, and their SHA-256."""
    block = hashlib.sha256(seed).digest() * (CHUNK // 32)
    digest = hashlib.sha256()
    pieces = []
    left = size
    while left:
        piece = block[:min(CHUNK, left)]
        pieces.append(piece)
        digest.update(piece)
        left -= len(piece)
    return pieces, digest.hexdigest()


def _staged(admin, vault_id, name, pieces, size):
    r = admin.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": size, "total_chunks": len(pieces), "chunk_size": CHUNK})
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    for i, piece in enumerate(pieces):
        r = admin.session.put(f"{BASE}/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=piece, timeout=120)
        assert r.status_code == 200, r.text
    return sid


def _listed(admin, vault_id, name):
    items = admin.get(f"/vaults/{vault_id}/files").json()["items"]
    return [it for it in items if it.get("type") == "file" and it.get("name") == name]


def _read_back(admin, vault_id, file_id):
    digest = hashlib.sha256()
    with admin.session.get(f"{BASE}/vaults/{vault_id}/files/{file_id}/download", stream=True, timeout=600) as r:
        assert r.status_code == 200, r.text
        for piece in r.iter_content(1024 * 1024):
            digest.update(piece)
    return digest.hexdigest()


def _blobs_on_disk(vault_id):
    out = subprocess.run(["docker", "exec", _container(), "sh", "-c",
                          f"find /app/storage/{vault_id} -type f | wc -l"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return int(out.stdout.strip())


@pytest.fixture
def vault(admin):
    v = admin.create_vault(name="completion-" + uuid.uuid4().hex[:8])
    try:
        yield v
    finally:
        admin.delete_vault(v["id"])


def _check_answered_during(asker, start, end):
    took = end - start
    during = asker.during(start, end)
    assert len(during) >= 3, f"too few requests were sent during a {took:.2f} s completion: {during}"
    assert all(status == 200 for *_, status in during), during
    worst = max(t for _, t, _, _ in during)
    assert worst < min(1.0, took / 3), (
        f"a request sent while the upload completed waited {worst:.2f} s, in a completion of {took:.2f} s")


def test_others_are_answered_while_a_large_upload_completes(admin, vault):
    size = 192 * 1024 * 1024
    pieces, sha = _payload(b"one", size)
    sid = _staged(admin, vault["id"], "large.bin", pieces, size)
    with _Asker(admin, vault["id"]) as asker:
        start = time.monotonic()
        r = admin.session.post(f"{BASE}/vaults/{vault['id']}/uploads/{sid}/complete", timeout=600)
        end = time.monotonic()
        time.sleep(0.3)
    assert r.status_code == 200, r.text
    _check_answered_during(asker, start, end)
    (item,) = _listed(admin, vault["id"], "large.bin")
    assert _read_back(admin, vault["id"], item["id"]) == sha


def test_two_uploads_completing_at_once_are_both_stored_whole(admin, vault):
    size = 128 * 1024 * 1024
    files = {name: _payload(name.encode(), size) for name in ("first.bin", "second.bin")}
    sids = {name: _staged(admin, vault["id"], name, pieces, size) for name, (pieces, _sha) in files.items()}
    answers = {}

    def complete(name):
        client = requests.Session()
        client.headers.update(admin.session.headers)
        answers[name] = client.post(f"{BASE}/vaults/{vault['id']}/uploads/{sids[name]}/complete", timeout=600)

    with _Asker(admin, vault["id"]) as asker:
        start = time.monotonic()
        threads = [threading.Thread(target=complete, args=(name,)) for name in files]
        for t in threads:
            t.start()
        for t in threads:
            t.join(620)
        end = time.monotonic()
        time.sleep(0.3)
    assert {name: a.status_code for name, a in answers.items()} == {"first.bin": 200, "second.bin": 200}, \
        {name: a.text for name, a in answers.items()}
    _check_answered_during(asker, start, end)
    for name, (_pieces, sha) in files.items():
        (item,) = _listed(admin, vault["id"], name)
        assert _read_back(admin, vault["id"], item["id"]) == sha, name
    assert _blobs_on_disk(vault["id"]) == 2


def test_a_client_that_leaves_as_it_asks_for_the_completion_still_gets_its_file_stored_whole(admin, vault):
    size = 128 * 1024 * 1024
    pieces, sha = _payload(b"left", size)
    sid = _staged(admin, vault["id"], "left.bin", pieces, size)
    client = requests.Session()
    client.headers.update(admin.session.headers)
    with pytest.raises(requests.exceptions.ReadTimeout):
        # Sent, then given up on before any answer: the connection closes while the server completes it.
        client.post(f"{BASE}/vaults/{vault['id']}/uploads/{sid}/complete", timeout=(10, 0.2))
    client.close()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and not _listed(admin, vault["id"], "left.bin"):
        time.sleep(0.5)
    (item,) = _listed(admin, vault["id"], "left.bin")
    assert item["size"] == size, item
    assert _read_back(admin, vault["id"], item["id"]) == sha
    # The session is gone once its file is stored, and the vault's only file on the disk is that one.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and any(
            s["session_id"] == sid for s in admin.get(f"/vaults/{vault['id']}/uploads").json()):
        time.sleep(0.5)
    assert all(s["session_id"] != sid for s in admin.get(f"/vaults/{vault['id']}/uploads").json())
    assert _blobs_on_disk(vault["id"]) == 1


@pytest.fixture
def zk_vault(admin):
    """A zero-knowledge vault, with the deployment's zero-knowledge setting put back as it was."""
    ensure_ecc_keypair(admin)
    before = admin.get("/settings").json().get("zero_knowledge_enabled") is True
    r = admin.put("/settings", json={"zero_knowledge_enabled": True})
    assert r.status_code == 200, r.text
    try:
        v = create_zk_vault(admin)
        try:
            yield v
        finally:
            admin.delete_vault(v["id"])
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": before})


def test_a_zero_knowledge_upload_refused_at_completion_keeps_the_vault_answering(admin, zk_vault):
    vid = zk_vault["id"]
    size = 52 * CHUNK                       # every chunk sent below is CHUNK bytes
    dek = os.urandom(32)
    name = "refused-%s.bin" % uuid.uuid4().hex[:8]
    object_id = str(uuid.uuid4())
    sealed = os.urandom(CHUNK)              # the browser's ciphertext: the server reads none of it
    require_zk_first_chunk(sealed)          # the session declares an attempt token
    r = admin.post(f"/vaults/{vid}/uploads", json={
        "total_size": size, "total_chunks": size // CHUNK, "chunk_size": CHUNK,
        "enc_name": zk_encrypt_name(name, dek, vid, "name", 1, obj_id=object_id),
        "name_bi": zk_name_blind_index(name, dek, vid, 1),
        "file_id": object_id, "blob_id": uuid.uuid4().hex, "zk_key_version": 1})
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]
    try:
        for i in range(size // CHUNK):
            r = admin.session.put(f"{BASE}/vaults/{vid}/uploads/{sid}/chunks/{i}", data=sealed, timeout=120,
                                  headers={"Content-Type": "application/octet-stream"})
            assert r.status_code == 200, r.text
        # The vault's key changes while the upload waits to be completed: it was encrypted under the old one.
        post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]),
                             "wrapped_dek": base64.b64encode(os.urandom(48)).decode(),
                             "ephemeral_public_key": base64.b64encode(os.urandom(48)).decode()}],
        }).raise_for_status()

        with _Asker(admin, vid) as asker:
            start = time.monotonic()
            r = admin.session.post(f"{BASE}/vaults/{vid}/uploads/{sid}/complete", json={"file_id": object_id},
                                   timeout=600)
            end = time.monotonic()
            time.sleep(0.3)
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["code"] == "stale_zk_epoch", r.text
        _check_answered_during(asker, start, end)
        # Nothing was stored: the assembled file is gone from the disk.
        assert not [it for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it.get("type") == "file"]
        assert _blobs_on_disk(vid) == 0
    finally:
        admin.delete(f"/vaults/{vid}/uploads/{sid}")
