"""The room for a file is decided as its row is written, in turns, offline.

A vault's size limit and the deployment's storage limit are each a total read, a decision, and a commit
some time later. While every upload finished on the event loop nothing ran between the read and the commit;
uploads, copies and moves now finish in threads of their own (app/core/off_loop.py), so two of them could
both read the same total, both decide there was room, and both commit. finalize_streaming_upload, which
every one of them reaches, now reads both totals under locks held until its commit: the deployment's turn
(a transaction-level advisory lock, when the deployment has a storage limit), then the vault's row. A file
it finds no room for is refused there, rolled back and removed.

These run the real finalize against an in-memory session that applies the queries' filters
(tests/_memory_db.py) and records each lock, statement and lock_timeout change in order, and the removal of a
refused file.
tests/test_vault_size_accounting.py finishes uploads, copies and moves at the same moment on a running stack.
"""
import ast
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB
from app.core.models import File, Vault

set_bare_api_env()          # one test imports app.api.api_server, which needs it when this module runs alone

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"
SFTP = ROOT / "app" / "sftp" / "sftp_server.py"
MB = 1024 * 1024
LONGER = "30000ms"          # STORAGE_TURN_WAIT_SECONDS, as the statement sets it
CONNECTION = "5s"           # the connection's own lock_timeout


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class _DB(MemoryDB):
    """MemoryDB as PostgreSQL: it answers the statements the turn and the longer wait send. A setting made
    with set_config(..., true) lasts until the transaction ends, as PostgreSQL keeps it; one made for the session
    (false) stays on the connection after the commit or the rollback."""

    def __init__(self, tables, dialect="postgresql"):
        super().__init__(tables)
        self.dialect = dialect
        self.lock_timeout = CONNECTION
        self.session_lock_timeout = CONNECTION

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name=self.dialect))

    def execute(self, statement, params=None):
        self.usable()
        sql, params = str(statement), dict(params or {})
        if "current_setting('lock_timeout')" in sql:
            return _Result(self.lock_timeout)
        if "set_config('lock_timeout'" in sql:
            self.lock_timeout = params["wait"]
            if not re.search(r",\s*true\s*\)\s*$", sql.strip(), re.IGNORECASE):
                self.session_lock_timeout = params["wait"]
            self.log.append(("lock_timeout", params["wait"]))
            return _Result(params["wait"])
        self.log.append(("execute", sql, params))
        return _Result(None)

    def commit(self):
        super().commit()
        self.lock_timeout = self.session_lock_timeout

    def rollback(self):
        super().rollback()
        self.lock_timeout = self.session_lock_timeout


def _vault(stored, limit):
    return SimpleNamespace(id=uuid.uuid4(), type="standard", total_size_bytes=stored, size_limit=limit,
                           file_count=0, expire_files_after_days=None, expire_files_unit="days")


def _service(db, removed):
    import app.services.vault_service as vs
    svc = vs.VaultService.__new__(vs.VaultService)
    svc.db = db
    svc.storage_path = None

    def remove(paths):
        # In the session's log too, so a test sees whether the file went before or after the rollback. (A finish
        # that stores its file asks for the removal of the files it replaced, none here.)
        if paths:
            db.log.append(("removed",))
        removed.extend(paths)
    svc._remove_blobs = remove

    def staged(*a, **k):
        db.log.append(("replace staged",))
        return []
    svc._stage_same_name_replacement = staged
    return svc


@pytest.fixture
def limits(monkeypatch):
    """Set the deployment's storage limit (None: none) and what it holds, as finalize reads them."""
    import app.services.vault_service as vs
    state = {"cap": None, "used": 0, "db": None}
    monkeypatch.setattr(vs, "deployment_storage_limit_bytes", lambda _db: state["cap"])

    def stored(_db):
        _db.log.append(("deployment total",))
        return state["used"]
    monkeypatch.setattr(vs, "deployment_storage_used", stored)
    return state


@pytest.fixture
def finish(monkeypatch, limits):
    """finalize_streaming_upload on a service over `db`, with the sealing stubbed. Returns (call, removed),
    where `removed` lists the files the service removed."""
    import app.core.security as security
    import app.services.vault_service as vs
    monkeypatch.setattr(vs, "_seal_named_object", lambda *a, **k: None)
    monkeypatch.setattr(vs, "_seal_file_checksum", lambda *a, **k: None)
    monkeypatch.setattr(security, "content_mac", lambda *a, **k: "mac")
    removed = []

    def call(db, vault, size, *, request_vault=None, replace=False, cap=None, used=0, svc=None):
        limits["cap"], limits["used"] = cap, used
        svc = svc or _service(db, removed)
        info = {"id": uuid.uuid4(), "name": "a.bin", "original_name": "a.bin", "vault_id": vault.id,
                "folder_id": None, "mime_type": "application/octet-stream",
                "storage_path": f"{vault.id}/files/new-{uuid.uuid4().hex}", "is_encrypted": True,
                "password_hash": None, "expires_at": None, "uploaded_by": uuid.uuid4(),
                "vault": request_vault or vault}
        return svc.finalize_streaming_upload(info, size, "0" * 64, replace_same_name=replace)

    return call, removed


def _kinds(db):
    out = []
    for entry in db.log:
        if entry[0] == "lock":
            out.append(("lock", entry[1].__name__, entry[2]))
        elif entry[0] == "add":
            out.append(("add", type(entry[1]).__name__))
        elif entry[0] == "update":
            out.append(("update", entry[1].__name__))
        elif entry[0] == "execute":
            out.append(("turn",) if "pg_advisory_xact_lock(" in entry[1] else ("execute", entry[1]))
        elif entry[0] == "lock_timeout":
            out.append(entry)
        else:
            out.append(entry[:1])
    return out


VAULT_ROW = [("lock_timeout", LONGER), ("lock", "Vault", {"key_share": True}), ("lock_timeout", CONNECTION)]
TURN = [("lock_timeout", LONGER), ("turn",), ("lock_timeout", CONNECTION)]


def test_a_file_with_room_is_checked_under_the_vaults_row_lock_before_its_row_is_written(finish):
    call, removed = finish
    vault = _vault(10 * MB, 64 * MB)
    db = _DB({Vault: [vault]})
    added = call(db, vault, 54 * MB, replace=True)
    assert isinstance(added, File) and removed == []
    kinds = _kinds(db)
    # No deployment limit, so no turn: the vault's row first, FOR NO KEY UPDATE as every writer of it takes
    # it, waited for longer than the connection's own lock_timeout, which is then put back.
    assert kinds[:3] == VAULT_ROW, kinds
    rest = [k[0] for k in kinds[3:]]
    # Then the replace, the row, the counters and the commit, in the transaction that holds the lock.
    assert rest == ["replace staged", "add", "update", "commit"], rest


def test_the_vaults_total_is_the_one_read_under_the_lock(finish):
    """Another file finished into the vault while this one waited for the lock: the total read under it counts
    that file. The vault the request loaded (and the caller's own check read) did not."""
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault(0, 64 * MB)
    db = _DB({Vault: [vault]})
    loaded_by_the_request = _vault(0, 64 * MB)
    loaded_by_the_request.id = vault.id

    def the_other_finish_commits():
        vault.total_size_bytes = 48 * MB
    db.on_lock.append(the_other_finish_commits)

    with pytest.raises(vs.StorageLimitExceeded) as refused:
        call(db, vault, 24 * MB, request_vault=loaded_by_the_request)
    assert (refused.value.kind, refused.value.used, refused.value.cap) == ("vault", 48 * MB, 64 * MB)


def test_a_file_the_vault_has_no_room_for_is_refused_rolled_back_and_removed(finish):
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault(48 * MB, 64 * MB)
    db = _DB({Vault: [vault]})
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        call(db, vault, 24 * MB, replace=True)
    assert refused.value.kind == "vault"
    assert isinstance(refused.value, vs.FileTooLargeError), "the routes answer it as a 413"
    # Refused before anything was staged or written, then rolled back: the lock is let go, and a file it
    # was to replace is untouched. The new file is removed only after that: its removal overwrites the whole
    # file, and every request that opens the vault would wait for the row lock meanwhile.
    assert _kinds(db) == VAULT_ROW + [("rollback",), ("removed",)], _kinds(db)
    assert len(removed) == 1 and removed[0].startswith(f"{vault.id}/files/new-"), removed
    assert vault.total_size_bytes == 48 * MB


def test_a_file_that_fills_the_vault_exactly_is_stored(finish):
    call, removed = finish
    vault = _vault(40 * MB, 64 * MB)
    db = _DB({Vault: [vault]})
    assert isinstance(call(db, vault, 24 * MB), File) and removed == []


@pytest.mark.parametrize("limit", [None, 0])
def test_a_vault_with_no_size_limit_takes_any_file(finish, limit):
    call, removed = finish
    vault = _vault(10 ** 12, limit)
    db = _DB({Vault: [vault]})
    assert isinstance(call(db, vault, 24 * MB), File) and removed == []


def test_the_deployments_turn_comes_before_the_vaults_row(finish):
    """So a finish waiting its turn holds no row lock: a request that opens its vault meanwhile does not
    wait behind the deployment's queue. The deployment's total is read in the turn."""
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault(0, None)
    db = _DB({Vault: [vault]})
    assert isinstance(call(db, vault, 16 * MB, cap=100 * MB, used=60 * MB), File) and removed == []
    kinds = _kinds(db)
    assert kinds[:6] == TURN + VAULT_ROW, kinds
    assert [k[0] for k in kinds[6:]] == ["deployment total", "add", "update", "commit"], kinds
    # A TRANSACTION-level lock, on the turn's own class: let go at the commit (or the rollback).
    (turn,) = [e for e in db.log if e[0] == "execute"]
    assert "pg_advisory_xact_lock(:c, :k)" in turn[1], turn
    assert turn[2] == {"c": vs.STORAGE_TURN[0], "k": vs.STORAGE_TURN[1]}


def test_a_file_the_deployment_has_no_room_for_is_refused_rolled_back_and_removed(finish):
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault(0, None)
    db = _DB({Vault: [vault]})
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        call(db, vault, 16 * MB, cap=100 * MB, used=90 * MB)
    assert (refused.value.kind, refused.value.used, refused.value.cap) == ("deployment", 90 * MB, 100 * MB)
    # The turn and the row let go before the new file is removed, as for the vault's limit: no finish anywhere
    # in the deployment waits for its turn while this one overwrites a file nobody will keep.
    assert _kinds(db) == TURN + VAULT_ROW + [("deployment total",), ("rollback",), ("removed",)], _kinds(db)
    assert len(removed) == 1


def test_the_turn_and_the_longer_wait_are_only_postgres(finish):
    """Elsewhere there is no advisory lock to take, nor a lock_timeout to set (and no concurrent server);
    the checks still run."""
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault(0, None)
    db = _DB({Vault: [vault]}, dialect="sqlite")
    with pytest.raises(vs.StorageLimitExceeded):
        call(db, vault, 16 * MB, cap=10 * MB, used=0)
    assert _kinds(db) == [("lock", "Vault", {"key_share": True}), ("deployment total",), ("rollback",),
                          ("removed",)]


def test_the_longer_wait_ends_with_its_transaction_when_a_wait_runs_out(finish):
    """A wait that runs out raises before the longer wait is put back. It is set for the transaction only
    (set_config's third argument), so the rollback that follows puts the connection's own lock_timeout back. Set
    for the session, the 30 s would stay on the pooled connection for every request that uses it next."""
    from sqlalchemy.exc import OperationalError
    call, removed = finish
    vault = _vault(0, 64 * MB)
    db = _DB({Vault: [vault]})
    db.held.add(vault.id)           # another transaction holds the vault's row past the wait
    with pytest.raises(OperationalError):
        call(db, vault, 16 * MB)
    assert db.lock_timeout == LONGER, "the wait raised, so nothing put the setting back yet"
    db.rollback()                   # what the request's session does with the error
    assert db.lock_timeout == CONNECTION


def test_the_turn_is_decided_once_a_transaction(limits):
    """A caller that locks the vault's row itself takes the turn first; finalize, later in the same
    transaction, takes no second turn and no second decision. A new transaction decides again."""
    import app.services.vault_service as vs
    limits["cap"] = 100 * MB
    db = _DB({Vault: []})
    svc = _service(db, [])
    assert svc.take_storage_turn() == 100 * MB
    assert svc.take_storage_turn() == 100 * MB
    assert [k for k in _kinds(db) if k == ("turn",)] == [("turn",)]
    db.commit()
    assert svc.take_storage_turn() == 100 * MB
    assert [k for k in _kinds(db) if k == ("turn",)] == [("turn",), ("turn",)]
    assert vs.STORAGE_TURN_WAIT_SECONDS * 1000 == int(LONGER[:-2])


def test_a_limit_set_after_the_caller_decided_does_not_put_the_turn_after_the_row(finish, limits):
    """The caller found no limit and took no turn, then locked the vault's row; a limit set meanwhile does not
    make finalize take the turn now, which would be after the row, the other order."""
    call, removed = finish
    vault = _vault(0, None)
    db = _DB({Vault: [vault]})
    svc = _service(db, removed)
    limits["cap"] = None
    assert svc.take_storage_turn() is None
    db.query(Vault.id).filter(Vault.id == vault.id).with_for_update(key_share=True).first()
    assert isinstance(call(db, vault, 16 * MB, cap=1, used=10 ** 9, svc=svc), File)
    assert ("turn",) not in _kinds(db) and ("deployment total",) not in _kinds(db)


def test_the_advisory_lock_class_is_its_own():
    """No other advisory lock in the app uses this class, so the turn is the storage check's alone."""
    import app.services.vault_service as vs
    hits = []
    for path in (ROOT / "app").rglob("*.py"):
        if hex(vs.STORAGE_TURN[0]) in path.read_text(encoding="utf-8").lower():
            hits.append(path.relative_to(ROOT).as_posix())
    assert hits == ["app/services/vault_service.py"], hits


# ---- the callers that lock the vault's row themselves -----------------------------------------------


def _function(tree, name, kind):
    found = [n for n in ast.walk(tree) if isinstance(n, kind) and n.name == name]
    assert len(found) == 1, f"{name} found {len(found)} times"
    return found[0]


def _first_line(node, text):
    lines = [n.lineno for n in ast.walk(node) if hasattr(n, "lineno") and text in ast.unparse(n)
             and isinstance(n, ast.Call)]
    assert lines, f"no call with {text!r}"
    return min(lines)


def test_a_zero_knowledge_completion_takes_the_turn_before_it_locks_the_vaults_row():
    node = _function(ast.parse(API.read_text(encoding="utf-8")), "_complete_chunked_upload", ast.AsyncFunctionDef)
    record = _function(node, "_record", ast.FunctionDef)
    turn = _first_line(record, "vault_service.take_storage_turn()")
    row = _first_line(record, ".with_for_update()")
    assert turn < row, (turn, row)


def test_an_sftp_write_takes_the_turn_before_it_locks_the_vaults_row_when_it_persists():
    tree = ast.parse(SFTP.read_text(encoding="utf-8"))
    authorize = _function(tree, "_authorize_upload_persist", ast.FunctionDef)
    (guarded,) = [n for n in ast.walk(authorize) if isinstance(n, ast.If) and ast.unparse(n.test) == "persisting"]
    assert [ast.unparse(n) for n in guarded.body] == ["vault_service.take_storage_turn()"], ast.unparse(guarded)
    assert guarded.lineno < _first_line(authorize, ".with_for_update(key_share=True)")
    # The two calls that go on to write the row say so; the one before the file is encrypted does not.
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "_authorize_upload_persist"]
    persisting = sorted(any(k.arg == "persisting" and ast.unparse(k.value) == "True" for k in c.keywords)
                        for c in calls)
    assert persisting == [False, True, True], persisting


# ---- a copy, a move to another vault and a folder copy ----------------------------------------------


def _copy_service(monkeypatch, refusal_kind):
    import app.services.vault_service as vs
    monkeypatch.setattr(vs, "would_exceed_deployment_storage", lambda db, n: (False, 0, 0))
    dest = _vault(0, 64 * MB)
    svc = vs.VaultService.__new__(vs.VaultService)
    svc.db = _DB({Vault: [dest]})
    svc.open_download_stream = lambda *a, **k: SimpleNamespace(chunks=lambda: iter([b"x" * 10]),
                                                               close=lambda: None)

    class _Ctx:
        total_bytes = 10

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def write_chunk(self, chunk):
            pass

    svc.upload_file_streaming = lambda *a, **k: ({"storage_path": "p"}, _Ctx())

    def refuse(*a, **k):
        raise vs.StorageLimitExceeded("found under the lock", kind=refusal_kind, used=1, cap=2)
    svc.finalize_streaming_upload = refuse
    source = SimpleNamespace(id=uuid.uuid4(), size_bytes=10, original_name="a.txt", name="a.txt",
                             mime_type="text/plain", password_hash=None)
    return svc, source, dest


@pytest.mark.parametrize("kind", ["vault", "deployment"])
def test_a_copy_refused_as_its_row_is_written_answers_as_the_check_before_it_does(monkeypatch, kind):
    import app.services.vault_service as vs
    svc, source, dest = _copy_service(monkeypatch, kind)
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        svc._stream_copy_file_record(source, SimpleNamespace(id="u"), dest.id, None)
    assert str(refused.value) == vs._COPY_REFUSALS[kind]
    assert refused.value.kind == kind


# ---- what each upload route answers ---------------------------------------------------------------


def test_the_routes_answer_a_refusal_as_a_413_in_their_own_words():
    from fastapi import HTTPException

    from app.api.api_server import _no_room
    from app.services.vault_service import StorageLimitExceeded
    vault = _no_room(StorageLimitExceeded("x", kind="vault", used=5, cap=6), "No room in this vault.")
    assert isinstance(vault, HTTPException) and (vault.status_code, vault.detail) == (413, "No room in this vault.")
    deployment = _no_room(StorageLimitExceeded("x", kind="deployment", used=3 * MB, cap=4 * MB), "unused")
    assert deployment.status_code == 413
    assert "storage limit would be exceeded" in deployment.detail and "already stored" in deployment.detail


# (the route, where finalize is called in it, the words its vault refusal is answered with)
ROUTES = [
    ("receiver_complete_upload", "_record", "This upload would exceed the link's space."),
    ("_complete_chunked_upload", "_record", "File would exceed the vault size limit"),
    ("upload_file", None, "Upload rejected: Vault size limit would be exceeded"),
]


@pytest.mark.parametrize("route, inner, words", ROUTES)
def test_each_upload_route_answers_finalizes_refusal(route, inner, words):
    """The call that writes the row is inside a try that answers StorageLimitExceeded with _no_room in that
    route's words, before any broader handler: otherwise the refusal would reach the route's catch-all and
    answer 500."""
    node = _function(ast.parse(API.read_text(encoding="utf-8")), route, ast.AsyncFunctionDef)
    if inner is not None:
        node = _function(node, inner, ast.FunctionDef)
    tries = [t for t in ast.walk(node) if isinstance(t, ast.Try)
             and "finalize_streaming_upload" in "".join(ast.unparse(s) for s in t.body)]
    # The innermost: the first handlers the refusal meets.
    innermost = [t for t in tries if not any(o is not t and o in list(ast.walk(t)) for o in tries)]
    assert len(innermost) == 1, f"{route}: {len(innermost)} innermost tries around the finalize call"
    (handled,) = innermost
    names = [ast.unparse(h.type) if h.type is not None else "" for h in handled.handlers]
    assert "StorageLimitExceeded" in names, names
    position = names.index("StorageLimitExceeded")
    assert not [n for n in names[:position] if n in ("Exception", "BaseException", "FileTooLargeError", "")], names
    body = ast.unparse(handled.handlers[position])
    assert f"_no_room(refused, {words!r})" in body, body
