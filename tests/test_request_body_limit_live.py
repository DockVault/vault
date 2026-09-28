"""Request bodies against the running deployment: an oversized body is refused at once and costs the
server nothing, and every legitimate body -- a sign-in, a multipart upload, a streamed chunk, a device
sync -- still goes through.

Before the limit counted streamed bytes, a chunked body to /auth/login had no bound at all, the JSON
parse ran on the event loop, and the 422 repeated the whole body back: 10 MB of small objects froze
the web app for about nine seconds, and a few 20 MB ones in parallel killed it. tests/test_body_limit.py
drives the middleware offline; this confirms the deployed stack behaves the same way.
"""
import http.client
import json
import os
import subprocess
import threading
import time
from urllib.parse import urlsplit

import pytest

from conftest import ApiClient, BASE_URL, _random_ip, unique
from _device_boundary_helpers import grant, mint_sync_cred, register_device

MiB = 1024 * 1024
_OCTET = {"Content-Type": "application/octet-stream"}


def _conn():
    parts = urlsplit(BASE_URL)
    cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    return cls(parts.hostname, parts.port, timeout=60)


def _objects(total):
    """`total` bytes of a JSON array of empty objects, in 1 MiB pieces: the costliest shape to parse."""
    piece = b"{}," * (MiB // 3)
    sent = 1
    yield b"["
    while sent + len(piece) < total - 3:
        yield piece
        sent += len(piece)
    yield b"{}]"


def _post(path, body, *, chunked=False, headers=None):
    """POST `body` (bytes, or an iterator of bytes when chunked); return (status, text, seconds)."""
    conn = _conn()
    head = {"Content-Type": "application/json", "X-Forwarded-For": _random_ip(), **(headers or {})}
    try:
        conn.connect()   # timed from here: resolving "localhost" can cost seconds on some hosts
        started = time.monotonic()
        conn.request("POST", path, body=body, headers=head, encode_chunked=chunked)
        response = conn.getresponse()
        text = response.read(4096).decode("utf-8", "replace")
        return response.status, text, time.monotonic() - started
    finally:
        conn.close()


class _Memory:
    """Allocated memory of the API container (page cache excluded), sampled ten times a second."""

    SCRIPT = ("while :; do cur=$(cat /sys/fs/cgroup/memory.current); "
              "fil=$(awk '/^inactive_file /{a=$2} /^active_file /{b=$2} END{print a+b}' "
              "/sys/fs/cgroup/memory.stat); echo $((cur - ${fil:-0})); sleep 0.1; done")

    def __init__(self):
        container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
        try:
            self.proc = subprocess.Popen(["docker", "exec", container, "sh", "-c", self.SCRIPT],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError as exc:
            pytest.skip(f"cannot reach the API container to read its memory: {exc}")
        self.samples = []
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while len(self.samples) < 5 and time.monotonic() < deadline:
            time.sleep(0.1)
        if len(self.samples) < 5:
            self.stop()
            pytest.skip("cannot read the API container's cgroup memory")
        self.baseline = max(self.samples)

    def _read(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line.isdigit():
                self.samples.append(int(line))

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def rise(self):
        time.sleep(0.5)
        self.stop()
        return max(self.samples) - self.baseline


class _Health:
    """How long /health takes to answer while something else runs: a frozen event loop shows here."""

    def __init__(self):
        self.worst, self.stopping = 0.0, False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stopping:
            conn = _conn()
            started = time.monotonic()
            try:
                conn.request("GET", "/health")
                conn.getresponse().read()
                self.worst = max(self.worst, time.monotonic() - started)
            except OSError:
                self.worst = max(self.worst, 60.0)
            finally:
                conn.close()
            time.sleep(0.2)

    def stop(self):
        self.stopping = True
        self.thread.join(70)
        return self.worst


# ------------------------------------------------------------------------------ refused, cheaply

def test_a_one_megabyte_sign_in_body_is_refused_at_once():
    body = json.dumps({"username": "u", "password": "p", "pad": "x" * MiB}).encode()
    status, text, seconds = _post("/auth/login", body)
    assert status == 413, text
    assert "64 KiB" in json.loads(text)["detail"]
    assert seconds < 5, f"a refused 1 MB body took {seconds:.1f} s"


def test_a_chunked_twenty_megabyte_sign_in_body_is_refused_quickly_and_costs_no_memory():
    memory, health = _Memory(), _Health()
    try:
        status, text, seconds = _post("/auth/login", _objects(20 * MiB), chunked=True)
    finally:
        worst = health.stop()
        rise = memory.rise()
    assert status == 413, text
    assert seconds < 15, f"a refused chunked body took {seconds:.1f} s"
    # Before the fix this body cost about 850 MiB and held the event loop for tens of seconds.
    assert rise < 32 * MiB, f"the API's memory rose {rise / MiB:.1f} MiB for a refused body"
    assert worst < 3, f"/health took {worst:.1f} s to answer while the body was refused"


def test_parallel_chunked_bodies_to_sign_in_leave_the_api_up():
    memory = _Memory()
    results = [None] * 4

    def one(i):
        results[i] = _post("/auth/login", _objects(20 * MiB), chunked=True)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(4)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
    finally:
        rise = memory.rise()
    assert [r[0] for r in results] == [413] * 4, results
    assert rise < 64 * MiB, f"the API's memory rose {rise / MiB:.1f} MiB for four refused bodies"
    conn = _conn()
    try:
        conn.request("GET", "/health")
        assert conn.getresponse().status == 200
    finally:
        conn.close()


def test_a_large_body_to_a_route_that_needs_a_session_is_refused_without_one(admin):
    """A note may be large, but only for a signed-in caller: anyone else meets the JSON limit before
    the body is parsed. With a session the same body reaches the handler, which answers itself."""
    body = json.dumps({"title": "t", "body": "x" * (2 * MiB)}).encode()
    status, text, _ = _post("/notes", body)
    assert status == 413, text
    status, text, _ = _post("/notes", body, headers={"Authorization": f"Bearer {admin.token}"})
    assert status == 400 and "too long" in json.loads(text)["detail"], (status, text)


def test_a_note_of_the_largest_size_an_admin_can_allow_still_saves(admin):
    """The largest note setting is 1,000,000 characters. Sent the way a client that escapes every
    non-ASCII character sends it (six bytes each), that is 6 MB of JSON: under the note route's limit."""
    before = admin.get("/settings").json().get("note_max_chars")
    note_id = None
    try:
        assert admin.put("/settings", json={"note_max_chars": 1_000_000}).status_code == 200
        r = admin.post("/notes", json={"title": unique("big"), "body": chr(0xE9) * 1_000_000})
        assert r.status_code == 200, r.text[:300]
        note_id = r.json()["id"]
    finally:
        if note_id:
            admin.delete(f"/notes/{note_id}")
        admin.put("/settings", json={"note_max_chars": before if before else 100000})


def test_a_rejected_sign_in_does_not_repeat_what_was_typed():
    marker = "Typed-Into-The-Wrong-Field-" + unique("pw")
    status, text, _ = _post("/auth/login", json.dumps(
        {"username": marker + "x" * 300, "password": "p"}).encode())
    assert status == 422, text
    assert marker not in text, "the 422 repeated the username field back"
    detail = json.loads(text)["detail"]
    assert detail[0]["loc"] == ["body", "username"] and detail[0]["msg"]
    assert all(set(e) == {"type", "loc", "msg"} for e in detail)


# ------------------------------------------------------------------------------ still accepted

def test_a_normal_sign_in_still_works(admin_creds):
    client = ApiClient()
    data = client.login(admin_creds["username"], admin_creds["password"])
    assert data["access_token"]
    assert client.get("/users/me").status_code == 200


def test_a_multipart_upload_above_the_json_limit_still_works(admin, temp_vault):
    vid = temp_vault["id"]
    content = os.urandom(3 * MiB)
    name = unique("f") + ".bin"
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "application/octet-stream"))])
    assert r.status_code == 200, r.text
    items = admin.get(f"/vaults/{vid}/files").json()["items"]
    file_id = next(it["id"] for it in items if it["type"] == "file" and it["name"] == name)
    assert admin.get(f"/vaults/{vid}/files/{file_id}/download").content == content
    anon = admin.clone_anonymous()
    r = anon.post(f"/vaults/{vid}/files",
                  files=[("files", (unique("f") + ".bin", content, "application/octet-stream"))])
    assert r.status_code == 413, "an anonymous multipart body was read past the JSON limit"


def test_a_chunked_resumable_upload_still_works(admin, temp_vault):
    vid = temp_vault["id"]
    size = 3 * MiB
    content = os.urandom(size)
    init = admin.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("chunked") + ".bin", "total_size": size,
        "total_chunks": 1, "chunk_size": size,
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]

    def pieces():   # no Content-Length: sent with chunked transfer-encoding
        for i in range(0, size, 256 * 1024):
            yield content[i:i + 256 * 1024]

    put = admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0", data=pieces(), headers=_OCTET)
    assert put.status_code == 200, put.text
    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    assert admin.get(f"/vaults/{vid}/files/{done.json()['id']}/download").content == content


def test_a_device_sync_still_works(admin, temp_vault):
    device = register_device(admin)
    try:
        grant(admin, device["device_id"], temp_vault["id"])
        minted = mint_sync_cred(device["secret"], temp_vault["id"])
        assert minted.status_code == 200, minted.text
        assert minted.json().get("host_public_key")
        anon = ApiClient()
        refreshed = anon.session.post(f"{BASE_URL}/device/refresh",
                                      headers={"Authorization": f"Bearer {device['secret']}"}, timeout=60)
        assert refreshed.status_code == 200, refreshed.text
    finally:
        admin.post(f"/devices/{device['device_id']}/revoke")
