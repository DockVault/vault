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
import uuid
from urllib.parse import urlsplit

import pytest

from conftest import ApiClient, BASE_URL, _random_ip, unique
from _device_boundary_helpers import grant, mint_sync_cred, register_device
from test_api_receiver_upload_finalize import _mk_receiver, _upload, receivers_enabled  # noqa: F401

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
    """Allocated memory of the API container (page cache excluded), sampled ten times a second.

    Ending the `docker exec` client does not end the loop it started inside the container, so the loop
    reports its own pid, stop() kills it there, and it ends by itself after ten minutes regardless."""

    SCRIPT = ("echo pid:$$; end=$(( $(date +%s) + 600 )); "
              "while [ $(date +%s) -lt $end ]; do cur=$(cat /sys/fs/cgroup/memory.current); "
              "fil=$(awk '/^inactive_file /{a=$2} /^active_file /{b=$2} END{print a+b}' "
              "/sys/fs/cgroup/memory.stat); echo $((cur - ${fil:-0})); sleep 0.1; done")

    def __init__(self):
        self.container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
        self.pid = None
        try:
            self.proc = subprocess.Popen(["docker", "exec", self.container, "sh", "-c", self.SCRIPT],
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
            if line.startswith("pid:") and line[4:].isdigit():
                self.pid = int(line[4:])
            elif line.isdigit():
                self.samples.append(int(line))

    def stop(self):
        if self.pid is not None:
            subprocess.run(["docker", "exec", self.container, "kill", str(self.pid)],
                           capture_output=True, timeout=30)
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
    """A note may be large, but only for a signed-in caller: anyone else meets the anonymous limit
    before the body is parsed. With a session the same body reaches the handler, which answers itself."""
    body = json.dumps({"title": "t", "body": "x" * (2 * MiB)}).encode()
    status, text, _ = _post("/notes", body)
    assert status == 413 and "64 KiB" in json.loads(text)["detail"], text
    status, text, _ = _post("/notes", body, headers={"Authorization": f"Bearer {admin.token}"})
    assert status == 400 and "too long" in json.loads(text)["detail"], (status, text)


def test_a_caller_with_no_session_meets_64_kib_on_every_route(admin):
    """Before, a caller with no session had up to 1 MiB of JSON parsed on any route that is not
    public, and only then was told 401. Now 64 KiB is the most anyone who is not signed in can send."""
    body = ("[" + ",".join(["{}"] * (MiB // 3 - 1)) + "]").encode()   # 1 MiB of objects: the costliest
    for path in ("/groups", "/vaults"):
        status, text, seconds = _post(path, body)
        print(f"POST {path} with no session: {status} in {seconds:.2f} s")
        assert status == 413 and "64 KiB" in json.loads(text)["detail"], (path, status, text)
    status, text, _ = _post("/vaults", body, headers={"Authorization": f"Bearer {admin.token}"})
    assert status == 422, (status, text[:200])   # signed in, the same body reaches the route


# ------------------------------------------------------------------------------ only a live session

# A validly signed token for a real administrator whose session was never created: what a token for a
# deleted session, or one forged with a leaked signing key, looks like to the server.
_MINT_ORPHAN = r'''
import secrets
from app.core.database import SessionLocal
from app.core.models import RoleEnum, User
from app.core.security import create_access_token
db = SessionLocal()
try:
    user = db.query(User).filter(User.role == RoleEnum.ADMIN).first()
    print("TOKEN:" + create_access_token(data={"sub": str(user.id), "username": user.username,
                                               "session_token": secrets.token_hex(32), "is_temporary": False}))
finally:
    db.close()
'''


def _orphan_token():
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    proc = subprocess.run(["docker", "exec", "-i", container, "python", "-"], input=_MINT_ORPHAN,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    if proc.returncode != 0 and "No such container" in (proc.stderr or ""):
        pytest.skip(f"no {container} container to mint the token in")
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("TOKEN:")), None)
    assert line, f"no token minted:\n{proc.stdout}\n{proc.stderr}"
    return line[len("TOKEN:"):].strip()


def _ended_token(admin, how):
    """A token whose session has ended in the way named."""
    if how == "never existed":
        return _orphan_token()
    if how == "temporary credential switched off":
        tc = admin.post("/auth/temp-credentials", json={"note": unique("bl-tc")}).json()
        client = ApiClient()
        client.login(tc["temp_username"], tc["credential"])
        assert client.get("/users/me").status_code == 200
        assert admin.post(f"/temp-creds/{tc['temp_username']}/deactivate").status_code == 200
        return client.token
    user = admin.create_user(role="user")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    assert client.get("/users/me").status_code == 200
    if how == "signed out":
        assert client.post("/api/logout").status_code == 200
    elif how == "account deactivated":
        assert admin.patch(f"/users/{user['id']}", json={"is_active": False}).status_code == 200
    elif how == "account locked by an administrator":
        assert admin.patch(f"/users/{user['id']}", json={"is_locked": True}).status_code == 200
    return client.token


def _declare_only(path, size, token, content_type="multipart/form-data; boundary=b"):
    """Send the headers of a `size`-byte body and none of it, and read the answer: a body refused on
    its declaration is answered before a byte of it is sent. Returns (status, text, headers, seconds)."""
    conn = _conn()
    try:
        conn.connect()
        started = time.monotonic()
        conn.putrequest("POST", path)
        for name, value in (("Content-Type", content_type), ("Content-Length", str(size)),
                            ("Authorization", f"Bearer {token}"), ("X-Forwarded-For", _random_ip())):
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        text = response.read(4096).decode("utf-8", "replace")
        return response.status, text, {k.lower(): v for k, v in response.getheaders()}, time.monotonic() - started
    finally:
        conn.close()


def _multipart(total):
    """A multipart upload of one `total`-byte file, in 1 MiB pieces."""
    yield b'--b\r\nContent-Disposition: form-data; name="files"; filename="a.bin"\r\n' \
          b"Content-Type: application/octet-stream\r\n\r\n"
    piece = b"A" * MiB
    for _ in range(total // MiB):
        yield piece
    yield b"\r\n--b--\r\n"


@pytest.mark.parametrize("how", ["signed out", "account deactivated", "account locked by an administrator",
                                 "temporary credential switched off", "never existed"])
def test_a_session_that_has_ended_cannot_send_a_large_body(admin, how):
    """Before, a token's signature and expiry were enough for the larger limits, so every one of these
    could have 48 MiB of multipart spooled to /tmp (memory, in the shipped compose files) or 8 MiB of
    JSON parsed before the route refused it. Now each is answered 401 before any of it is read."""
    token = _ended_token(admin, how)
    status, text, headers, seconds = _declare_only(f"/vaults/{uuid.uuid4()}/files", 48 * MiB, token)
    assert status == 401, (status, text)
    assert "sign in" in json.loads(text)["detail"] and headers.get("www-authenticate") == "Bearer"
    assert seconds < 5, f"refusing it took {seconds:.1f} s"
    status, text, _ = _post("/notes", json.dumps({"title": "t", "body": "x" * (2 * MiB)}).encode(),
                            headers={"Authorization": f"Bearer {token}"})
    assert status == 401, (status, text)


def test_a_chunked_upload_from_a_session_that_never_existed_is_refused_and_costs_no_memory():
    """The measured case: 48 MiB of chunked multipart with a signed token for no session was read
    whole, spooled to /tmp, before the route answered 401."""
    token = _orphan_token()
    memory = _Memory()
    try:
        status, text, seconds = _post(f"/vaults/{uuid.uuid4()}/files", _multipart(48 * MiB), chunked=True,
                                      headers={"Authorization": f"Bearer {token}",
                                               "Content-Type": "multipart/form-data; boundary=b"})
    finally:
        rise = memory.rise()
    print(f"{status} after {seconds:.2f} s; memory +{rise / MiB:.1f} MiB")
    assert status == 401, text
    assert rise < 8 * MiB, f"the API's memory rose {rise / MiB:.1f} MiB for a refused upload"
    assert seconds < 30, f"refusing it took {seconds:.1f} s"


@pytest.fixture
def largest_file_2_mb(admin):
    """The administrators' maximum file size set to 2 MB for the test, and put back afterwards. The
    body limit of a signed-in multipart upload is then 2 MiB plus 1 MiB for the form."""
    before = admin.get("/settings").json().get("max_file_size") or 0
    r = admin.put("/settings", json={"max_file_size": 2})
    assert r.status_code == 200, r.text
    try:
        yield 3 * MiB
    finally:
        admin.put("/settings", json={"max_file_size": before})


def test_a_signed_in_multipart_upload_is_held_to_the_largest_file(admin, temp_user_client, temp_vault,
                                                                  largest_file_2_mb):
    """Any signed-in session could send a multipart upload of any size: the whole form is spooled to /tmp
    (memory, in the shipped compose files) before the route checks the caller may upload to that vault.
    Now it is held to the largest file the deployment accepts plus 1 MiB, declared or chunked, whoever
    sends it."""
    limit, vid = largest_file_2_mb, temp_vault["id"]
    for who, token in (("administrator", admin.token), ("user", temp_user_client.token)):
        status, text, _headers, seconds = _declare_only(f"/vaults/{vid}/files", limit + 1, token)
        assert status == 413, (who, status, text)
        detail = json.loads(text)["detail"]
        assert "The limit for this request is 3 MiB" in detail and "resumable uploader" in detail, detail
        assert seconds < 5, f"refusing it took {seconds:.1f} s"

    memory = _Memory()
    try:
        status, text, seconds = _post(f"/vaults/{vid}/files", _multipart(32 * MiB), chunked=True,
                                      headers={"Authorization": f"Bearer {temp_user_client.token}",
                                               "Content-Type": "multipart/form-data; boundary=b"})
    finally:
        rise = memory.rise()
    print(f"{status} after {seconds:.2f} s; memory +{rise / MiB:.1f} MiB")
    assert status == 413, text
    assert "The limit for this request is 3 MiB" in json.loads(text)["detail"], text
    assert rise < 16 * MiB, f"the API's memory rose {rise / MiB:.1f} MiB for a refused upload"

    # A file the deployment accepts still uploads, at once: saving the setting took effect immediately.
    content = os.urandom(MiB + MiB // 2)
    name = unique("f") + ".bin"
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "application/octet-stream"))])
    assert r.status_code == 200, r.text


def test_a_large_email_template_still_saves(admin):
    body_html = "<p>" + "Welcome to the vault. " * 12_000 + "</p>"      # about 260 KB
    r = admin.post("/email/templates", json={"name": unique("big"), "subject": "Hello",
                                             "body_html": body_html})
    assert r.status_code == 201, r.text[:300]
    try:
        assert len(r.json()["body_html"]) > 200_000
    finally:
        admin.delete(f"/email/templates/{r.json()['id']}")


def test_a_logo_above_the_anonymous_limit_still_uploads(admin):
    padded = b"\x89PNG\r\n\x1a\n" + b"\0" * (300 * 1024)   # the type is read from the signature alone
    r = admin.post("/settings/brand/asset/logo", files={"file": ("logo.png", padded, "image/png")})
    try:
        assert r.status_code == 200, r.text[:300]
    finally:
        admin.delete("/settings/brand/asset/logo")


def test_an_upload_link_upload_above_the_anonymous_limit_still_works(admin, receivers_enabled):
    """An upload link is used by someone with no account; its chunk route checks the link before it
    reads the body, so the chunk limit is theirs too."""
    receiver = _mk_receiver(admin)
    content = os.urandom(3 * MiB)
    r = _upload(admin.clone_anonymous(), receiver["token"], unique("drop") + ".bin", content)
    assert r.status_code == 200, r.text
    assert r.json()["size"] == len(content)


def test_a_temporary_credential_still_uploads_above_the_anonymous_limit(admin, temp_vault):
    tc = admin.post("/auth/temp-credentials", json={"note": unique("bl-up")}).json()
    client = ApiClient()
    client.login(tc["temp_username"], tc["credential"])
    try:
        name = unique("tc") + ".bin"
        r = client.post(f"/vaults/{temp_vault['id']}/files",
                        files=[("files", (name, os.urandom(MiB), "application/octet-stream"))])
        assert r.status_code == 200, r.text[:300]
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/deactivate")


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
