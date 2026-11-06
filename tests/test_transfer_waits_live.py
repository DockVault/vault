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


def _delete_keys(pattern):
    keys = subprocess.run(["docker", "exec", REDIS, "redis-cli", "--scan", "--pattern", pattern],
                          capture_output=True, text=True, timeout=30)
    skip_if_container_absent(keys, REDIS)
    assert keys.returncode == 0, keys.stderr
    for key in [k for k in keys.stdout.split("\n") if k]:
        subprocess.run(["docker", "exec", REDIS, "redis-cli", "DEL", key], capture_output=True, text=True,
                       timeout=30, check=True)


def _clear_open_throttle():
    """The opens of one link from one address are limited to ten a minute."""
    _delete_keys("publiclink_redeem*")


def _clear_poll_budget():
    """The monitor's metrics are read in the polled-reads class, 600 a minute per account by default: a test that
    watches them for long starts with that minute's budget unspent, not spent by the tests before it."""
    _delete_keys("rate_limit:api:poll*")


def _session(client):
    s = requests.Session()
    s.headers.update(client.session.headers)
    return s


def _upload(client, vault_id, name, content, folder_id=None):
    """Through the resumable path, in 4 MiB chunks."""
    pieces = [content[i:i + CHUNK] for i in range(0, len(content), CHUNK)] or [b""]
    r = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content), "total_chunks": len(pieces), "chunk_size": CHUNK,
        **({"folder_id": folder_id} if folder_id else {})})
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    s = _session(client)
    for i, piece in enumerate(pieces):
        r = s.put(f"{BASE}/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=piece, timeout=300, headers=_OCTET)
        assert r.status_code == 200, r.text
    r = s.post(f"{BASE}/vaults/{vault_id}/uploads/{sid}/complete", timeout=600)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _folder(client, vault_id, name, parent=None):
    r = client.post(f"/vaults/{vault_id}/folders",
                    json={"name": name, **({"parent_folder_id": parent} if parent else {})})
    assert r.status_code in (200, 201), r.text
    return r.json()["folder"]["id"]


def _files_in(client, vault_id, folder_id=None):
    r = client.get(f"/vaults/{vault_id}/files", params={"folder_id": folder_id} if folder_id else None)
    assert r.status_code == 200, r.text
    return {it["id"] for it in r.json()["items"]}


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


def test_a_move_within_one_vault_is_answered_while_every_slot_is_held(admin, vault):
    """A move within one vault is a reparent (one row, no bytes copied): like a folder move it takes no transfer
    slot, so it is answered while every slot is held, where it waited for one, and was refused once the wait ran
    out. A move to another vault copies the file, and waits for a slot."""
    limit = _setting("MAX_CONCURRENT_TRANSFERS", 16)
    queue = _setting("MAX_QUEUED_TRANSFERS", 32)
    if limit > 64 or queue < 1:
        pytest.skip(f"needs a ceiling of at most 64 and room for one to wait (ceiling {limit}, queue {queue})")
    held = _upload(admin, vault, "held.bin", os.urandom(HELD_SIZE))
    within, across = (_upload(admin, vault, f"{n}.bin", os.urandom(1024)) for n in ("within", "across"))
    into = _folder(admin, vault, "into")
    moved_folder = _folder(admin, vault, "moved")
    elsewhere = admin.create_vault(name=unique("waits-to"))["id"]
    answers = {}
    try:
        with _EverySlotHeld(admin, vault, held, limit):
            s = _session(admin)
            sent = time.monotonic()
            r = s.post(f"{BASE}/vaults/{vault}/files/{within}/move",
                       json={"dest_vault_id": vault, "dest_folder_id": into}, timeout=60)
            took = time.monotonic() - sent
            assert r.status_code == 200 and took < 5, (r.status_code, r.text[:200], f"{took:.1f} s")
            r = s.post(f"{BASE}/vaults/{vault}/folders/{moved_folder}/move",
                       json={"dest_vault_id": vault, "dest_parent_folder_id": into}, timeout=60)
            assert r.status_code == 200, r.text
            assert _metrics(admin) == (limit, 0)

            def send():
                answers["across"] = _session(admin).post(
                    f"{BASE}/vaults/{vault}/files/{across}/move", json={"dest_vault_id": elsewhere}, timeout=120)
            t = threading.Thread(target=send, daemon=True)
            t.start()
            _until(admin, lambda flying, waiting: waiting == 1, "the move to another vault waiting", 15)
        t.join(130)
        assert answers["across"].status_code == 200, answers["across"].text
        assert {within, moved_folder} <= _files_in(admin, vault, into)
        assert _files_in(admin, elsewhere) == {answers["across"].json()["id"]}
    finally:
        admin.delete_vault(elsewhere)


def test_a_transfer_waiting_for_its_slot_is_refused_when_what_let_it_in_changes(admin, vault):
    """Every slot held. Sent meanwhile, each waiting for a slot: a download and a copy from two sessions of one
    account, which are then signed out; a move to another vault by an account an administrator then locks; a
    download by a temporary credential that is then switched off; a download from a vault whose password then
    changes; and a copy nothing changed for. Once the slots come back, the five are refused (401: the lock ends
    the account's sessions, and the password's asks for it again) and did nothing; the last is copied. Before, a
    waiting copy or move ran after its session was signed out."""
    limit = _setting("MAX_CONCURRENT_TRANSFERS", 16)
    queue = _setting("MAX_QUEUED_TRANSFERS", 32)
    if limit > 64 or queue < 6:
        pytest.skip(f"needs a ceiling of at most 64 and room for 6 to wait (ceiling {limit}, queue {queue})")
    from conftest import ApiClient
    held = _upload(admin, vault, "held.bin", os.urandom(HELD_SIZE))
    users, vaults, lock, minted = [], [], {"on": False}, []
    try:
        signed_out = admin.create_user(role="user")
        locked = admin.create_user(role="user")
        users += [signed_out, locked]
        first, second, mover = ApiClient(), ApiClient(), ApiClient()
        first.login(signed_out["_username"], signed_out["_password"])
        second.login(signed_out["_username"], signed_out["_password"])
        mover.login(locked["_username"], locked["_password"])
        theirs = first.create_vault(name=unique("waits-out"))["id"]
        moving_from = mover.create_vault(name=unique("waits-from"))["id"]
        moving_to = mover.create_vault(name=unique("waits-to"))["id"]
        protected = admin.create_vault(name=unique("waits-pw"))["id"]
        vaults += [(signed_out, theirs, None), (locked, moving_from, None), (locked, moving_to, None),
                   (None, protected, "After-Change-2")]
        their_file = _upload(first, theirs, "theirs.bin", os.urandom(1024))
        copied_into = _folder(first, theirs, "copied")
        moved_file = _upload(mover, moving_from, "moved.bin", os.urandom(1024))
        protected_file = _upload(admin, protected, "protected.bin", os.urandom(1024))
        r = admin.put(f"/vaults/{protected}/password", json={"new_password": "Before-Change-1"})
        assert r.status_code == 200, r.text
        control_file = _upload(admin, vault, "control.bin", os.urandom(1024))
        control_into = _folder(admin, vault, "control")
        temp_file = _upload(admin, vault, "temporary.bin", os.urandom(1024))
        caps = ["vault.see_info", "vault.see_files", "file.download"]
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vault, "caps": caps}],
            "scope": {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
                      "temp": {"view": False, "create": False, "invalidate": False, "clear": False,
                               "delegate": False}}})
        assert r.status_code == 200, r.text
        minted.append(r.json()["temp_username"])
        temporary = ApiClient()
        temporary.login(r.json()["temp_username"], r.json()["credential"])

        sends = {
            "signed-out download": (_session(first), "GET", f"/vaults/{theirs}/files/{their_file}/download", {}),
            "signed-out copy": (_session(second), "POST", f"/vaults/{theirs}/files/{their_file}/copy",
                                {"json": {"dest_vault_id": theirs, "dest_folder_id": copied_into}}),
            "locked move": (_session(mover), "POST", f"/vaults/{moving_from}/files/{moved_file}/move",
                            {"json": {"dest_vault_id": moving_to}}),
            "switched-off credential download": (_session(temporary), "GET",
                                                 f"/vaults/{vault}/files/{temp_file}/download", {}),
            "changed password download": (_session(admin), "GET",
                                          f"/vaults/{protected}/files/{protected_file}/download",
                                          {"headers": {"X-Vault-Password": "Before-Change-1"}}),
            "control copy": (_session(admin), "POST", f"/vaults/{vault}/files/{control_file}/copy",
                             {"json": {"dest_vault_id": vault, "dest_folder_id": control_into}}),
        }
        answers = {}

        def send(name, session, method, path, kw):
            answers[name] = session.request(method, f"{BASE}{path}", timeout=120, **kw)

        threads = [threading.Thread(target=send, args=(name, *how), daemon=True) for name, how in sends.items()]
        with _EverySlotHeld(admin, vault, held, limit):
            for t in threads:
                t.start()
            _until(admin, lambda flying, waiting: waiting == len(sends), f"all {len(sends)} waiting", 15)
            for client in (first, second):
                r = client.post("/auth/sign-out")
                assert r.status_code == 200 and r.json()["session_ended"] is True, r.text
            r = admin.post(f"/api/user-management/users/{locked['id']}/toggle-locked")
            assert r.status_code == 200, r.text
            lock["on"] = True
            r = admin.post(f"/temp-creds/{minted[0]}/deactivate")
            assert r.status_code == 200, r.text
            r = admin.put(f"/vaults/{protected}/password",
                          json={"current_password": "Before-Change-1", "new_password": "After-Change-2"})
            assert r.status_code == 200, r.text
            assert _metrics(admin) == (limit, len(sends)), "a request stopped waiting before the slots came back"
        for t in threads:
            t.join(130)
        got = {name: (r.status_code, r.text[:200]) for name, r in answers.items()}
        assert got["signed-out download"][0] == 401, got
        assert got["signed-out copy"][0] == 401, got
        assert got["locked move"][0] == 401, got
        assert got["switched-off credential download"][0] == 401, got
        assert got["changed password download"][0] == 401 and "password" in got["changed password download"][1], got
        assert got["control copy"][0] == 200, got
        # What the refused ones would have done, not done (seen by each owner, signed in again).
        unlocked = admin.post(f"/api/user-management/users/{locked['id']}/toggle-locked")
        assert unlocked.status_code == 200, unlocked.text
        lock["on"] = False
        first, mover = ApiClient(), ApiClient()
        first.login(signed_out["_username"], signed_out["_password"])
        mover.login(locked["_username"], locked["_password"])
        assert _files_in(first, theirs, copied_into) == set(), "a copy ran after its session was signed out"
        assert moved_file in _files_in(mover, moving_from) and _files_in(mover, moving_to) == set(), (
            "a move ran after its account was locked")
        assert _files_in(admin, vault, control_into) == {answers["control copy"].json()["id"]}
    finally:
        for name in minted:
            admin.post(f"/temp-creds/{name}/delete")
        if lock["on"]:
            admin.post(f"/api/user-management/users/{locked['id']}/toggle-locked")
        for owner, vid, password in vaults:
            client = admin
            if owner is not None:
                client = ApiClient()
                client.login(owner["_username"], owner["_password"])
            client.delete_vault(vid, vault_password=password)
        for user in users:
            admin.delete_user(user["id"])


def test_one_account_holds_at_most_a_quarter_of_the_slots_with_copies(admin, other, vault):
    """One account sends twice its share of folder copies of a large tree at once. At most its share (a quarter of
    the ceiling) run at a time, the others wait their turn and are all done, and another account's download meanwhile
    is admitted at once. Before, one account's long folder copies held every slot while everyone else waited."""
    limit = _setting("MAX_CONCURRENT_TRANSFERS", 16)
    queue = _setting("MAX_QUEUED_TRANSFERS", 32)
    share = max(1, limit // 4)
    if limit > 64 or limit < 4 or queue < share:
        pytest.skip(f"needs a ceiling of 4 to 64 and room for {share} to wait (ceiling {limit}, queue {queue})")
    asker_client, asker_vault = other
    theirs = _upload(asker_client, asker_vault, "theirs.bin", os.urandom(1024))
    tree = _folder(admin, vault, "tree")
    for i in range(3):
        _upload(admin, vault, f"part{i}.bin", os.urandom(32 * MB), folder_id=tree)
    into = [_folder(admin, vault, f"into{i}") for i in range(2 * share)]
    seen, stop, answers, unwatched = [], threading.Event(), {}, []

    def watch():
        # Five reads a second: a copy of the tree lasts many times longer, and with the reads of the waits below
        # they stay well inside the account's budget for polled reads (600 a minute by default), however long the
        # copies take.
        while not stop.is_set():
            try:
                seen.append((time.monotonic(), *_metrics(admin)))
            except AssertionError as exc:
                unwatched.append(str(exc)[:300])
                return
            time.sleep(0.2)

    def copy(i):
        answers[i] = _session(admin).post(f"{BASE}/vaults/{vault}/folders/{tree}/copy",
                                          json={"dest_vault_id": vault, "dest_parent_folder_id": into[i]},
                                          timeout=120)

    _clear_poll_budget()
    _until(admin, lambda flying, waiting: flying == 0 and waiting == 0, "idle", 120)
    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    threads = [threading.Thread(target=copy, args=(i,), daemon=True) for i in range(2 * share)]
    try:
        for t in threads:
            t.start()
        _until(admin, lambda flying, waiting: waiting > 0, "a copy waiting for its turn", 30)
        sent = time.monotonic()
        r = _session(asker_client).get(f"{BASE}/vaults/{asker_vault}/files/{theirs}/download", timeout=60)
        took = time.monotonic() - sent
        assert r.status_code == 200 and took < 3, (r.status_code, f"{took:.1f} s")
        for t in threads:
            t.join(130)
    finally:
        stop.set()
        watcher.join(10)
    assert not unwatched, f"the metrics stopped being read while the copies ran: {unwatched}"
    assert {i: a.status_code for i, a in answers.items()} == {i: 200 for i in range(2 * share)}, (
        {i: a.text[:200] for i, a in answers.items() if a.status_code != 200})
    # Not counting the other account's download, which held a slot of its own for as long as it took.
    copies_only = [(flying, waiting) for at, flying, waiting in seen if not sent - 0.2 <= at <= sent + took + 0.2]
    most = max(flying for flying, _waiting in copies_only)
    assert most <= share, f"one account's copies held {most} slots at once, past its share of {share}"
    assert max(waiting for _flying, waiting in copies_only) > 0, "no copy waited: the instrument saw nothing"
