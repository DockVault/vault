"""Requests waiting for a transfer slot hold no database connection, and everyone else is answered meanwhile, on a
running stack.

Every slot is held by a download whose client reads nothing, and as many downloads, rendered previews and public
link downloads as the queue takes are sent: they wait for a slot. They waited holding their read transaction, so
a connection each, and 16 downloads streaming with 32 waiting held the whole pool (38 connections at the default
ceiling): every request after them waited for a connection on the event loop, and the server stopped answering
anyone, for minutes. They now end their read transaction before they wait. So while they wait the database shows
none of them holding a connection in a transaction, and another account is answered within a second throughout:
a path the server answers on the event loop alone, a listing of its own vault (a query) and the health check.
Once the downloads let go, each waiting request is answered with what it asked for.

tests/test_transfers_asked_again_after_the_wait.py checks the same offline, with what is asked again after the
wait; tests/test_copies_on_the_transfer_ceiling_live.py the copies, moves and uploads that wait the same way.
"""
import hashlib
import os
import socket
import subprocess
import threading
import time
import uuid

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection

from conftest import skip_if_container_absent, unique

pytestmark = pytest.mark.integration

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")
API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
REDIS = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
MB = 1024 * 1024
CHUNK = 4 * MB
# Larger than everything between the server and a client that does not read can take in: the client's small
# window, the server's send buffer and those of the port's proxy, which can grow to 32 MiB.
HELD_SIZE = 64 * MB
ANSWERED_WITHIN = 1.0       # seconds: another account's every request while the transfers wait
_OCTET = {"Content-Type": "application/octet-stream"}
IN_TRANSACTION = ("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                  "AND state LIKE 'idle in transaction%' AND now() - state_change > interval '1 second'")


def _setting(name, default):
    """What the running deployment was configured with."""
    out = subprocess.run(["docker", "exec", API, "sh", "-c", f"echo ${{{name}:-{default}}}"],
                         capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, API)
    assert out.returncode == 0 and out.stdout.strip().isdigit(), (out.stdout, out.stderr)
    return int(out.stdout.strip())


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-v", "ON_ERROR_STOP=1",
                          "-Atc", sql], capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, DB)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


def _clear_open_throttle():
    """The opens of one link from one address are limited to ten a minute."""
    keys = subprocess.run(["docker", "exec", REDIS, "redis-cli", "--scan", "--pattern", "publiclink_redeem*"],
                          capture_output=True, text=True, timeout=30)
    skip_if_container_absent(keys, REDIS)
    assert keys.returncode == 0, keys.stderr
    for key in [k for k in keys.stdout.split("\n") if k]:
        subprocess.run(["docker", "exec", REDIS, "redis-cli", "DEL", key], capture_output=True, text=True,
                       timeout=30, check=True)


def _session(client):
    s = requests.Session()
    s.headers.update(client.session.headers)
    return s


def _upload(client, vault_id, name, content):
    """Through the resumable path, in 4 MiB chunks."""
    pieces = [content[i:i + CHUNK] for i in range(0, len(content), CHUNK)] or [b""]
    r = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content), "total_chunks": len(pieces), "chunk_size": CHUNK})
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    s = _session(client)
    for i, piece in enumerate(pieces):
        r = s.put(f"{BASE}/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=piece, timeout=300, headers=_OCTET)
        assert r.status_code == 200, r.text
    r = s.post(f"{BASE}/vaults/{vault_id}/uploads/{sid}/complete", timeout=600)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _metrics(admin):
    r = admin.get("/api/monitoring/metrics")
    assert r.status_code == 200, r.text
    m = r.json()
    return m["transfersInFlight"], m["transfersWaiting"]


def _until(admin, wanted, what, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        seen = _metrics(admin)
        if wanted(*seen):
            return seen
        assert time.monotonic() < deadline, f"never {what}: (in flight, waiting) = {seen}"
        time.sleep(0.2)


class _SmallWindow(HTTPAdapter):
    """A client whose socket takes in little at a time: a download it stops reading stays in flight, holding
    its slot, rather than landing whole in the socket buffers."""

    def init_poolmanager(self, *args, **kwargs):
        kwargs["socket_options"] = HTTPConnection.default_socket_options + [
            (socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)]
        return super().init_poolmanager(*args, **kwargs)


class _EverySlotHeld:
    """Every transfer slot held by a download whose client reads one piece and then nothing, until the block
    ends; then each reads to the end, so the slots come back at once."""

    def __init__(self, admin, vault_id, file_id, limit):
        self.admin, self.limit = admin, limit
        self.url = f"{BASE}/vaults/{vault_id}/files/{file_id}/download"
        self.release = threading.Event()
        self.statuses = []
        self.threads = [threading.Thread(target=self._hold, daemon=True) for _ in range(limit)]

    def _hold(self):
        s = _session(self.admin)
        s.mount("http://", _SmallWindow())
        s.mount("https://", _SmallWindow())
        with s.get(self.url, stream=True, timeout=600) as r:
            self.statuses.append(r.status_code)
            pieces = r.iter_content(MB)
            next(pieces)
            self.release.wait(180)
            for _ in pieces:
                pass

    def __enter__(self):
        _until(self.admin, lambda flying, waiting: flying == 0 and waiting == 0, "idle", 120)
        for t in self.threads:
            t.start()
        _until(self.admin, lambda flying, waiting: flying == self.limit, "every slot held")
        time.sleep(2)           # a download holds its connection while it streams: counted before
        return self

    def __exit__(self, *exc):
        self.release.set()
        for t in self.threads:
            t.join(120)
        assert self.statuses == [200] * self.limit, self.statuses


class _Asker:
    """Another account: asks a path the server does not have (answered on the event loop alone), a listing of its
    own vault and the health check, one after the other, recording when each was sent, how long its answer took
    and what it was."""

    def __init__(self, client, vault_id):
        self.session = _session(client)
        self.unknown = f"{BASE}/no-such-path-{uuid.uuid4().hex}"
        self.urls = {"unknown path": self.unknown, "listing": f"{BASE}/vaults/{vault_id}/files",
                     "health": f"{BASE}/health"}
        self.asked = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        kinds = list(self.urls)
        i = 0
        while not self._stop.is_set():
            kind = kinds[i % len(kinds)]
            i += 1
            sent = time.monotonic()
            try:
                status = self.session.get(self.urls[kind], timeout=60).status_code
            except requests.RequestException as exc:
                status = type(exc).__name__
            self.asked.append((sent, time.monotonic() - sent, kind, status))
            time.sleep(0.05)

    def __enter__(self):
        self._thread.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(70)

    def check_answered_during(self, start, end):
        """Every request sent between start and end answered, as expected, within ANSWERED_WITHIN."""
        during = [a for a in self.asked if start <= a[0] <= end]
        took = end - start
        assert len(during) >= 3 * took, f"{len(during)} answers in {took:.1f} s: {during}"
        expected = {"unknown path": 404, "listing": 200, "health": 200}
        assert all(status == expected[kind] for _, _, kind, status in during), during
        waits = {kind: max(t for _, t, k, _ in during if k == kind) for kind in self.urls}
        assert max(waits.values()) < ANSWERED_WITHIN, (
            f"another account waited too long while the transfers waited (the longest wait of each: {waits}; "
            f"{len(during)} asked in {took:.1f} s)")
        return waits


@pytest.fixture
def other(admin, temp_user_client):
    """Another account, with a vault of its own."""
    v = temp_user_client.create_vault(name=unique("asker"))
    try:
        yield temp_user_client, v["id"]
    finally:
        temp_user_client.delete_vault(v["id"])


@pytest.fixture
def vault(admin):
    v = admin.create_vault(name=unique("waits"))
    try:
        yield v["id"]
    finally:
        admin.delete_vault(v["id"])


@pytest.fixture
def file_links(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    r = admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    try:
        yield
    finally:
        admin.put("/settings", json=snap)


def _file_link(admin, vault_id, file_id, uses):
    tag = admin.post("/note-link-tags", json={
        "name": unique("waits"), "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "max_uses_cap": uses, "require_secret": "none"})
    assert tag.status_code in (200, 201), tag.text
    r = admin.post("/public-links", json={"vault_id": vault_id, "tag_id": tag.json()["id"], "ttl_hours": 1,
                                          "max_uses": uses, "target_type": "file", "target_file_id": file_id})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _grants(token, count):
    grants = []
    for i in range(count):
        if i % 9 == 0:
            _clear_open_throttle()
        r = requests.post(f"{BASE}/public-links/{token}/redeem", json={}, timeout=30)
        assert r.status_code == 200, r.text
        grants.append(r.json()["grant"])
    return grants


def test_downloads_previews_and_link_downloads_wait_holding_no_connection_and_everyone_else_is_answered(
        admin, other, vault, file_links):
    limit = _setting("MAX_CONCURRENT_TRANSFERS", 16)
    queue = _setting("MAX_QUEUED_TRANSFERS", 32)
    if limit > 64 or queue < 8:
        pytest.skip(f"needs a ceiling of at most 64 and room for 8 to wait (ceiling {limit}, queue {queue})")
    asker_client, asker_vault = other
    held = _upload(admin, vault, "held.bin", os.urandom(HELD_SIZE))
    small_content = os.urandom(1024)
    small = _upload(admin, vault, "small.bin", small_content)
    text = _upload(admin, vault, "notes.md", b"# Notes\n\nwritten while every slot was held\n")
    links, previews = queue // 4, queue // 4
    downloads = queue - links - previews
    token = _file_link(admin, vault, small, links)
    grants = _grants(token, links)

    answers = {}
    sent = []

    def send(name, url, headers=None, session=None):
        s = session or requests.Session()
        try:
            answers[name] = s.get(url, headers=headers or {}, timeout=180)
        except requests.RequestException as exc:
            answers[name] = exc

    with _EverySlotHeld(admin, vault, held, limit), _Asker(asker_client, asker_vault) as asker:
        before = int(_psql(IN_TRANSACTION))
        start = time.monotonic()
        for i in range(downloads):
            sent.append(threading.Thread(target=send, args=(
                f"download {i}", f"{BASE}/vaults/{vault}/files/{small}/download", None, _session(admin))))
        for i in range(previews):
            sent.append(threading.Thread(target=send, args=(
                f"preview {i}", f"{BASE}/vaults/{vault}/files/{text}/preview-render", None, _session(admin))))
        for i, grant in enumerate(grants):
            sent.append(threading.Thread(target=send, args=(
                f"link download {i}", f"{BASE}/public-links/{token}/download/{small}",
                {"X-Download-Grant": grant})))
        for t in sent:
            t.daemon = True
            t.start()
        _until(admin, lambda flying, waiting: waiting == queue, f"all {queue} requests waiting", 15)
        time.sleep(4)
        during = int(_psql(IN_TRANSACTION))
        flying, waiting = _metrics(admin)
        end = time.monotonic()
        assert (flying, waiting) == (limit, queue), "a request stopped waiting, or a download let go"
        assert during <= before, (
            f"{during - before} more connections held in a transaction while {queue} requests waited for a slot")
    for t in sent:
        t.join(200)
    waits = asker.check_answered_during(start, end)
    print(f"the longest wait of each of another account's requests while {queue} waited: {waits}")
    failed = {k: (v if isinstance(v, Exception) else (v.status_code, v.text[:200])) for k, v in answers.items()
              if isinstance(v, Exception) or v.status_code != 200}
    assert not failed and len(answers) == queue, failed
    for name, r in answers.items():
        if name.startswith("preview"):
            assert "written while every slot was held" in r.json()["html"], name
        else:
            assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(small_content).hexdigest(), name
    _until(admin, lambda flying, waiting: flying == 0 and waiting == 0, "idle again", 120)
