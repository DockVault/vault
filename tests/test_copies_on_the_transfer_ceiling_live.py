"""Copies, moves and folder copies are admitted on the transfer ceiling, and everyone else is still answered, on a
running stack.

A copy, a move to another vault and a folder copy each read, decrypt, encrypt and sync whole files in a thread of
their own (app/core/off_loop.py), on their request's database connection. They were not admitted on the transfer
ceiling, so a burst of them held every connection of the pool: the next request's first query waited for one on
the event loop, which answers every request, and nobody was answered until a copy ended, or until the pool's
30 s timeout. They are now admitted as an upload's completion is, a request waiting for its slot holds no
connection, and the pool is sized beyond what the ceilings admit (app/core/database.py). Each one's audit row is
written in its thread too: committed on the event loop, it waited for the disk the burst keeps busy, and the loop
with it.

- A burst of each, more requests than the pool has connections, sent at once while another account asks, one
  after the other, the health check, a listing of its own vault and a path the server does not have. It is
  answered throughout: at least three answers a second, every request within three seconds, and 95 in 100 of
  those to the path the server answers on the event loop alone within a second. Not every one of those: on a
  machine busy with other work one took 1.25 to 2.0 s in each burst, while 99 in 100 took under 0.75 s; the loop
  also reads the database for a listing and writes a file on the storage disk for the health check, both of
  which the burst keeps busy. Before, the event loop waited for a connection for most of the burst: five
  answers in eleven seconds, up to five seconds each, so each of the three bounds catches that. Every request
  of the burst is answered 200, or, past the ceiling's queue, 503 with Retry-After, or, past the account's own
  share of the slots and its room to wait for one, 429 with Retry-After; what each stored reads back whole.
- With every slot held by a download whose client does not read, copies, moves, folder copies and direct uploads
  sent meanwhile wait for a slot, and the database shows none of them holding a connection in a transaction.

A full deployment's answer (503 with Retry-After) to a copy, a move and a folder copy is checked in
tests/test_transfer_admission_live.py, on a deployment configured with a ceiling of one.
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

from conftest import skip_if_container_absent

pytestmark = pytest.mark.integration

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")
API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
MB = 1024 * 1024
CHUNK = 4 * MB
SIZE = 32 * MB          # each copy reads, decrypts, encrypts and syncs this much
BURST = 40              # more requests than the pool had connections (30)
LOOP_ALONE_WITHIN = 1.0     # seconds: 95 in 100 of the requests to a path the server answers on the event loop alone
ANSWERED_WITHIN = 3.0       # seconds: every request
ANSWERS_A_SECOND = 3
HELD_SIZE = 64 * MB


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


def _session(client):
    s = requests.Session()
    s.headers.update(client.session.headers)
    return s


def _payload(seed, size=SIZE):
    block = hashlib.sha256(seed).digest() * (CHUNK // 32)
    return [block] * (size // CHUNK), hashlib.sha256(block * (size // CHUNK)).hexdigest()


def _upload(client, vault_id, name, pieces, folder_id=None):
    size = sum(len(p) for p in pieces)
    r = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": size, "total_chunks": len(pieces), "chunk_size": CHUNK,
        **({"folder_id": folder_id} if folder_id else {})})
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    s = _session(client)
    for i, piece in enumerate(pieces):
        r = s.put(f"{BASE}/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=piece, timeout=300,
                  headers={"Content-Type": "application/octet-stream"})
        assert r.status_code == 200, r.text
    r = s.post(f"{BASE}/vaults/{vault_id}/uploads/{sid}/complete", timeout=600)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _folder(client, vault_id, name, parent=None):
    r = client.post(f"/vaults/{vault_id}/folders",
                    json={"name": name, **({"parent_folder_id": parent} if parent else {})})
    assert r.status_code in (200, 201), r.text
    return r.json()["folder"]["id"]


def _read_back(session, vault_id, file_id):
    digest = hashlib.sha256()
    with session.get(f"{BASE}/vaults/{vault_id}/files/{file_id}/download", stream=True, timeout=600) as r:
        assert r.status_code == 200, r.text
        for piece in r.iter_content(MB):
            digest.update(piece)
    return digest.hexdigest()


def _files_in(client, vault_id, folder_id=None):
    r = client.get(f"/vaults/{vault_id}/files", params={"folder_id": folder_id} if folder_id else None)
    assert r.status_code == 200, r.text
    return [it for it in r.json()["items"] if it.get("type") == "file"]


class _SmallWindow(HTTPAdapter):
    """A client whose socket takes in little at a time: a download it stops reading stays in flight, holding
    its slot, rather than landing whole in the socket buffers."""

    def init_poolmanager(self, *args, **kwargs):
        kwargs["socket_options"] = HTTPConnection.default_socket_options + [
            (socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)]
        return super().init_poolmanager(*args, **kwargs)


class _Asker:
    """Another account: asks the health check, a listing of its own vault and an unknown path, one after the
    other, recording when each was sent, how long its answer took and what it was."""

    def __init__(self, client, vault_id):
        self.session = _session(client)
        self.unknown = f"{BASE}/no-such-path-{uuid.uuid4().hex}"
        self.urls = [f"{BASE}/health", f"{BASE}/vaults/{vault_id}/files", self.unknown]
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

    def check_answered_during(self, start, end):
        during = [a for a in self.asked if start <= a[0] <= end]
        took = end - start
        assert len(during) >= max(6, ANSWERS_A_SECOND * took), (
            f"{len(during)} answers in the {took:.1f} s of the burst: {during}")
        expected = {url: (404 if url == self.unknown else 200) for url in self.urls}
        assert all(status == expected[url] for _, _, url, status in during), during
        waits = {name: max(t for _, t, u, _ in during if u == url)
                 for name, url in zip(("health", "listing", "unknown path"), self.urls)}
        alone = sorted(t for _, t, u, _ in during if u == self.unknown)
        most = alone[int(0.95 * (len(alone) - 1))]
        assert max(waits.values()) < ANSWERED_WITHIN and most < LOOP_ALONE_WITHIN, (
            f"another account waited too long during the {took:.1f} s of the burst (the longest wait of each: "
            f"{waits}; 95 in 100 of the path answered on the loop alone within {most:.2f} s; {len(during)} asked)")
        return waits


@pytest.fixture
def other(admin, temp_user_client):
    """Another account, with a vault of its own."""
    v = temp_user_client.create_vault(name="asker-" + uuid.uuid4().hex[:8])
    try:
        yield temp_user_client, v["id"]
    finally:
        temp_user_client.delete_vault(v["id"])


@pytest.fixture
def vaults(admin):
    made = []

    def make(prefix):
        v = admin.create_vault(name=f"{prefix}-{uuid.uuid4().hex[:8]}")
        made.append(v["id"])
        return v["id"]

    try:
        yield make
    finally:
        for vid in made:
            admin.delete_vault(vid)


def _burst(admin, requests_):
    """Send every (path, body) at once, each from its own client; return [(status, headers, json or text)]."""
    answers = [None] * len(requests_)
    go = threading.Event()

    def send(i, path, body):
        s = _session(admin)
        go.wait()
        r = s.post(f"{BASE}{path}", json=body, timeout=600)
        try:
            payload = r.json()
        except ValueError:
            payload = r.text
        answers[i] = (r.status_code, r.headers, payload)

    threads = [threading.Thread(target=send, args=(i, p, b)) for i, (p, b) in enumerate(requests_)]
    for t in threads:
        t.start()
    go.set()
    for t in threads:
        t.join(620)
    assert all(a is not None for a in answers), "a request of the burst never returned"
    return answers


def _check_burst_answers(answers):
    """Every answer 200, or with Retry-After: 503 past the ceiling's queue, or 429 past the account's own share of the
    slots and the room it has to wait for one (the burst is one account's); at least a ceiling's worth stored."""
    codes = [a[0] for a in answers]
    assert set(codes) <= {200, 429, 503}, [(a[0], a[2]) for a in answers if a[0] not in (200, 429, 503)]
    for status, headers, payload in answers:
        if status == 503:
            assert int(headers.get("Retry-After", "0")) >= 1 and "transfers" in str(payload), payload
        if status == 429:
            assert int(headers.get("Retry-After", "0")) >= 1 and "copies or moves" in str(payload), payload
    assert codes.count(200) >= min(len(answers), _setting("MAX_CONCURRENT_TRANSFERS", 16)), codes
    return [i for i, code in enumerate(codes) if code == 200]


def _sources(admin, make, prefix, count):
    """A vault holding the same SIZE-byte file in `count` folders, each made by a copy one after the other."""
    pieces, sha = _payload(prefix.encode())
    vid = make(prefix)
    first = _upload(admin, vid, "source.bin", pieces)
    folders = [_folder(admin, vid, f"f{i:02d}") for i in range(count)]
    files = []
    for fid in folders:
        r = admin.post(f"/vaults/{vid}/files/{first}/copy", json={"dest_vault_id": vid, "dest_folder_id": fid})
        assert r.status_code == 200, r.text
        files.append(r.json()["id"])
    return vid, folders, files, sha


def test_a_burst_of_copies_leaves_everyone_else_answered(admin, other, vaults):
    asker_client, asker_vault = other
    pieces, sha = _payload(b"copies")
    source_vault = vaults("copy-from")
    source = _upload(admin, source_vault, "copied.bin", pieces)
    dest = vaults("copy-to")
    folders = [_folder(admin, dest, f"f{i:02d}") for i in range(BURST)]
    with _Asker(asker_client, asker_vault) as asker:
        start = time.monotonic()
        answers = _burst(admin, [(f"/vaults/{source_vault}/files/{source}/copy",
                                  {"dest_vault_id": dest, "dest_folder_id": fid}) for fid in folders])
        end = time.monotonic()
        time.sleep(0.3)
    stored = _check_burst_answers(answers)
    asker.check_answered_during(start, end)
    reader = _session(admin)
    for i in stored:
        (item,) = _files_in(admin, dest, folders[i])
        assert item["id"] == answers[i][2]["id"]
        assert _read_back(reader, dest, item["id"]) == sha
    for i in set(range(BURST)) - set(stored):
        assert _files_in(admin, dest, folders[i]) == [], "a refused copy stored something"


def test_a_burst_of_moves_to_another_vault_leaves_everyone_else_answered(admin, other, vaults):
    asker_client, asker_vault = other
    source_vault, _folders, files, sha = _sources(admin, vaults, "move-from", BURST)
    dest = vaults("move-to")
    targets = [_folder(admin, dest, f"g{i:02d}") for i in range(BURST)]
    with _Asker(asker_client, asker_vault) as asker:
        start = time.monotonic()
        answers = _burst(admin, [(f"/vaults/{source_vault}/files/{fid}/move",
                                  {"dest_vault_id": dest, "dest_folder_id": target})
                                 for fid, target in zip(files, targets)])
        end = time.monotonic()
        time.sleep(0.3)
    moved = _check_burst_answers(answers)
    asker.check_answered_during(start, end)
    reader = _session(admin)
    for i in moved:
        (item,) = _files_in(admin, dest, targets[i])
        assert _read_back(reader, dest, item["id"]) == sha
        assert _files_in(admin, source_vault, _folders[i]) == [], "a moved file is still where it was"
    for i in set(range(BURST)) - set(moved):
        assert _files_in(admin, dest, targets[i]) == [] and len(_files_in(admin, source_vault, _folders[i])) == 1


def test_a_burst_of_folder_copies_leaves_everyone_else_answered(admin, other, vaults):
    asker_client, asker_vault = other
    vid, folders, _files, sha = _sources(admin, vaults, "folder-copy", BURST)
    into = _folder(admin, vid, "into")
    with _Asker(asker_client, asker_vault) as asker:
        start = time.monotonic()
        answers = _burst(admin, [(f"/vaults/{vid}/folders/{fid}/copy",
                                  {"dest_vault_id": vid, "dest_parent_folder_id": into}) for fid in folders])
        end = time.monotonic()
        time.sleep(0.3)
    copied = _check_burst_answers(answers)
    asker.check_answered_during(start, end)
    reader = _session(admin)
    for i in copied:
        (item,) = _files_in(admin, vid, answers[i][2]["id"])
        assert _read_back(reader, vid, item["id"]) == sha


def test_requests_waiting_for_a_slot_hold_no_database_connection(admin, vaults):
    """Every slot is held by a download whose client does not read. Copies, moves, folder copies and direct
    uploads sent meanwhile wait for a slot; the database shows none of them holding a connection in a
    transaction while they wait. Once the downloads let go, each is stored."""
    limit = _setting("MAX_CONCURRENT_TRANSFERS", 16)
    queue = _setting("MAX_QUEUED_TRANSFERS", 32)
    waiting = 8
    if limit > 32 or queue < waiting:
        pytest.skip(f"needs a ceiling of at most 32 and room for {waiting} to wait (ceiling {limit}, queue {queue})")
    vid = vaults("waiting")
    # Larger than everything between the server and a client that does not read can take in: the client's
    # small window, the server's send buffer and those of the port's proxy, which can grow to 32 MiB.
    held_pieces, _ = _payload(b"held", HELD_SIZE)
    held = _upload(admin, vid, "held.bin", held_pieces)
    small = _upload(admin, vid, "small.bin", [b"s" * 1024])
    other_vault = vaults("waiting-to")
    targets = [_folder(admin, other_vault, f"t{i}") for i in range(4)]
    copies_of_small = []
    for i in range(2):
        r = admin.post(f"/vaults/{vid}/files/{small}/copy",
                       json={"dest_vault_id": vid, "dest_folder_id": _folder(admin, vid, f"moving{i}")})
        assert r.status_code == 200, r.text
        copies_of_small.append(r.json()["id"])
    tree = [_folder(admin, vid, f"tree{i}") for i in range(2)]
    into = [_folder(admin, vid, f"into{i}") for i in range(2)]

    release = threading.Event()
    holders = []

    def hold():
        s = _session(admin)
        s.mount("http://", _SmallWindow())
        s.mount("https://", _SmallWindow())
        r = s.get(f"{BASE}/vaults/{vid}/files/{held}/download", stream=True, timeout=600)
        holders.append(r.status_code)
        pieces = r.iter_content(MB)
        next(pieces)
        release.wait(120)
        for _ in pieces:            # read to the end, so the slot comes back at once
            pass
        r.close()

    def metrics():
        return admin.get("/api/monitoring/metrics").json()

    held_threads = [threading.Thread(target=hold, daemon=True) for _ in range(limit)]
    for t in held_threads:
        t.start()
    answers = {}
    sent = []
    try:
        deadline = time.monotonic() + 60
        while metrics()["transfersInFlight"] < limit and time.monotonic() < deadline:
            time.sleep(0.2)
        assert metrics()["transfersInFlight"] == limit, "the downloads did not take every slot"
        time.sleep(2)                   # a download holds its connection while it streams: counted before
        in_transaction = ("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                          "AND state LIKE 'idle in transaction%' AND now() - state_change > interval '1 second'")
        before = int(_psql(in_transaction))

        def send(name, method, path, **kw):
            s = _session(admin)
            answers[name] = s.request(method, f"{BASE}{path}", timeout=120, **kw)

        for name, method, path, kw in [
            ("copy 1", "POST", f"/vaults/{vid}/files/{small}/copy",
             {"json": {"dest_vault_id": other_vault, "dest_folder_id": targets[0]}}),
            ("copy 2", "POST", f"/vaults/{vid}/files/{small}/copy",
             {"json": {"dest_vault_id": other_vault, "dest_folder_id": targets[1]}}),
            ("move 1", "POST", f"/vaults/{vid}/files/{copies_of_small[0]}/move",
             {"json": {"dest_vault_id": other_vault, "dest_folder_id": targets[2]}}),
            ("move 2", "POST", f"/vaults/{vid}/files/{copies_of_small[1]}/move",
             {"json": {"dest_vault_id": other_vault, "dest_folder_id": targets[3]}}),
            ("folder copy 1", "POST", f"/vaults/{vid}/folders/{tree[0]}/copy",
             {"json": {"dest_vault_id": vid, "dest_parent_folder_id": into[0]}}),
            ("folder copy 2", "POST", f"/vaults/{vid}/folders/{tree[1]}/copy",
             {"json": {"dest_vault_id": vid, "dest_parent_folder_id": into[1]}}),
            ("upload 1", "POST", f"/vaults/{vid}/files",
             {"files": [("files", ("direct-1.bin", b"d" * 2048, "application/octet-stream"))]}),
            ("upload 2", "POST", f"/vaults/{vid}/files",
             {"files": [("files", ("direct-2.bin", b"e" * 2048, "application/octet-stream"))]}),
        ]:
            t = threading.Thread(target=send, args=(name, method, path), kwargs=kw, daemon=True)
            t.start()
            sent.append(t)
        deadline = time.monotonic() + 15
        while metrics()["transfersWaiting"] < waiting and time.monotonic() < deadline:
            time.sleep(0.2)
        assert metrics()["transfersInFlight"] == limit, "a download let go of its slot: the instrument failed"
        assert metrics()["transfersWaiting"] == waiting, (
            f"{metrics()['transfersWaiting']} of the {waiting} requests sent wait for a slot "
            f"(answered already: { {k: v.status_code for k, v in answers.items()} })")
        time.sleep(2)
        during = int(_psql(in_transaction))
        assert metrics()["transfersInFlight"] == limit, "a download let go of its slot: the instrument failed"
        assert during <= before, (
            f"{during - before} more connections held in a transaction while {waiting} requests waited for a slot")
    finally:
        release.set()
        for t in held_threads:
            t.join(60)
        for t in sent:
            t.join(130)
    assert holders == [200] * limit
    assert {k: v.status_code for k, v in answers.items()} == {k: 200 for k in answers}, \
        {k: v.text[:200] for k, v in answers.items() if v.status_code != 200}
    assert len(answers) == waiting
    assert metrics()["transfersInFlight"] == 0 and metrics()["transfersWaiting"] == 0
