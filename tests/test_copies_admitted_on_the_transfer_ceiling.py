"""Copies, moves and folder copies are admitted on the transfer ceiling, and wait for a slot holding no database
connection; the database pool is sized beyond what the ceilings admit, offline.

A copy, a move and a folder copy run to their end in a thread (app/core/off_loop.py), each on its request's
database connection. They were not admitted on the transfer ceiling: a burst of them held every connection of
the pool (30, where the thread pool has 32 threads), and the next request's first query waited for one on the
event loop. Now each takes a slot of the same ceiling as an upload's completion, after the checks that cost
nothing to answer, and ends its read transaction first, so a request waiting for a slot holds no connection;
a full ceiling answers as it answers an upload (503 with Retry-After). The pool's capacity is one connection for
each transfer the two ceilings admit and each sign-in handed to a thread, and ten more.

These drive the three endpoints themselves with a stand-in session that counts the connections its
transactions hold, and the real admission gate. tests/test_copies_on_the_transfer_ceiling_live.py sends bursts of
each on a running stack, and tests/test_transfer_admission_live.py checks the refusal on a ceiling of one.
"""
import asyncio
import threading
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import database  # noqa: E402
from app.core.transfer_admission import TransferAdmission, admitted_at_most, ceiling, link_ceiling  # noqa: E402
from _async_run import run_coroutine  # noqa: E402

pytestmark = pytest.mark.unit


class _Session:
    """What the request's session does with its connection: the first query of a transaction checks one out,
    commit and rollback give it back."""

    def __init__(self):
        self.held = 0
        self.log = []

    def _query_ran(self):
        if not self.held:
            self.held = 1
            self.log.append("checked out")

    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        self._query_ran()
        return SimpleNamespace(id=uuid.uuid4())

    def commit(self):
        self.held = 0
        self.log.append("commit")

    def rollback(self):
        self.held = 0
        self.log.append("rollback")


class _World:
    def __init__(self, monkeypatch, gate, *, fail_with=None, refuse_access=False):
        self.db = _Session()
        self.gate = gate
        self.ran = []
        self.audited = []
        world = self

        class _VaultService:
            def __init__(self, db, ps):
                pass

            def get_vault(self, *a, **k):
                if refuse_access:
                    raise S.PermissionDeniedError("no access")
                world.db._query_ran()
                world.db.commit()                       # as the real get_vault does

            def _work(self, name):
                # Runs in a thread of the off-loop pool, holding the request's slot and its connection.
                world.db._query_ran()
                world.ran.append((name, dict(world.gate.stats()), world.db.held))
                if fail_with is not None:
                    raise fail_with
                return SimpleNamespace(id=uuid.uuid4())

            def copy_file(self, *a, **k):
                return self._work("copy")

            def move_file(self, *a, **k):
                return self._work("move")

            def copy_folder(self, *a, **k):
                return self._work("folder copy")

        monkeypatch.setattr(S, "transfer_admission", gate)
        monkeypatch.setattr(S, "PermissionService", lambda db: object())
        monkeypatch.setattr(S, "VaultService", _VaultService)
        monkeypatch.setattr(S, "AuditLogger", lambda db: SimpleNamespace(
            log_action=lambda **k: world.audited.append((k["action"], threading.current_thread().name))))
        monkeypatch.setattr(S, "require_item_scope", lambda *a, **k: None)
        monkeypatch.setattr(S, "require_folder_scope", lambda *a, **k: world.db._query_ran())
        monkeypatch.setattr(S, "_principal_can_replace_file", lambda *a, **k: False)
        monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.1")
        import app.core.temp_scope as temp_scope
        monkeypatch.setattr(temp_scope, "require_cap", lambda *a, **k: None)


def _raw(endpoint):
    while hasattr(endpoint, "__wrapped__"):
        endpoint = endpoint.__wrapped__
    return endpoint


def _call(kind, world):
    """The endpoint's coroutine for `kind`, as FastAPI would call it."""
    user = SimpleNamespace(id=uuid.uuid4())
    vid, item = uuid.uuid4(), uuid.uuid4()
    if kind == "copy":
        return _raw(S.copy_file_endpoint)(vid, item, S.ItemMoveCopy(dest_vault_id=uuid.uuid4()), None,
                                          current_user=user, db=world.db, x_vault_password=None,
                                          x_dest_vault_password=None, x_file_password=None)
    if kind == "move":
        return _raw(S.move_file_endpoint)(vid, item, S.ItemMoveCopy(dest_vault_id=uuid.uuid4()), None,
                                          current_user=user, db=world.db, x_vault_password=None,
                                          x_dest_vault_password=None, x_file_password=None)
    return _raw(S.copy_folder_endpoint)(vid, item, S.FolderMoveCopy(dest_vault_id=vid), None,
                                        current_user=user, db=world.db, x_vault_password=None)


KINDS = ["copy", "move", "folder copy"]


@pytest.mark.parametrize("kind", KINDS)
def test_it_waits_for_a_slot_holding_no_connection_then_runs_holding_the_slot(monkeypatch, kind):
    async def scenario():
        gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=30)
        world = _World(monkeypatch, gate)
        other = await gate.acquire()                    # another transfer holds the only slot
        task = asyncio.ensure_future(_call(kind, world))
        for _ in range(200):
            if gate.stats()["waiting"]:
                break
            await asyncio.sleep(0.01)
        waiting = (gate.stats()["waiting"], world.db.held, list(world.ran))
        gate.release(other)
        answer = await task
        return world, waiting, answer, gate.stats()

    world, waiting, answer, after = run_coroutine(scenario())
    assert waiting == (1, 0, []), f"(waiting, connections held, work done) while it waited: {waiting}"
    assert world.db.log.index("rollback") < world.db.log.index("checked out", world.db.log.index("rollback")), \
        world.db.log
    ((name, stats, held),) = world.ran
    assert name == kind and stats["in_flight"] == 1 and held == 1, world.ran
    assert answer["id"]
    # Its audit row is written off the loop too, in the same thread as the work: a commit on the loop waits for a
    # disk the copies keep busy, and nobody else is answered meanwhile.
    ((action, thread),) = world.audited
    assert action == {"copy": "file_copy", "move": "file_move", "folder copy": "folder_copy"}[kind]
    assert thread.startswith("stored-bytes"), thread
    assert after["in_flight"] == 0 and after["admitted"] == 2, "its slot was not given back"


@pytest.mark.parametrize("kind", KINDS)
def test_a_full_ceiling_refuses_it_as_it_refuses_an_upload(monkeypatch, kind):
    async def scenario():
        gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=20)
        world = _World(monkeypatch, gate)
        other = await gate.acquire()
        try:
            await _call(kind, world)
        except HTTPException as exc:
            refused = exc
        else:
            refused = None
        stats = gate.stats()
        gate.release(other)
        return world, refused, stats

    world, refused, stats = run_coroutine(scenario())
    assert refused is not None and refused.status_code == 503, refused
    assert refused.headers["Retry-After"] == "20" and "transfers" in refused.detail
    expected = S._busy_response(S.TransferBusy(retry_after=20, waiting=0, limit=1))
    assert (refused.detail, refused.headers) == (expected.detail, expected.headers)
    assert world.ran == [], "the work ran without a slot"
    assert stats["refused"] == 1 and stats["in_flight"] == 1 and world.db.held == 0


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("failure", [S.DuplicateNameError("taken"), RuntimeError("the disk is gone")])
def test_it_gives_its_slot_back_when_its_work_fails(monkeypatch, kind, failure):
    async def scenario():
        gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=1)
        world = _World(monkeypatch, gate, fail_with=failure)
        try:
            await _call(kind, world)
        except (HTTPException, RuntimeError) as exc:
            raised = exc
        return world, raised, gate.stats()

    world, raised, stats = run_coroutine(scenario())
    assert len(world.ran) == 1 and world.audited == []
    if isinstance(failure, S.DuplicateNameError):
        assert isinstance(raised, HTTPException) and raised.status_code == 409
    else:
        assert raised is failure
    assert stats["in_flight"] == 0 and stats["admitted"] == 1, stats


@pytest.mark.parametrize("kind", KINDS)
def test_a_request_its_checks_refuse_takes_no_slot(monkeypatch, kind):
    async def scenario():
        gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=1)
        world = _World(monkeypatch, gate, refuse_access=True)
        with pytest.raises(S.PermissionDeniedError):
            await _call(kind, world)
        return world, gate.stats()

    world, stats = run_coroutine(scenario())
    assert world.ran == [] and stats["admitted"] == 0 and stats["refused"] == 0


def test_a_move_within_one_vault_takes_no_slot_and_a_full_ceiling_never_refuses_it(monkeypatch):
    """A move within one vault is a reparent: one row changes, no bytes are copied. Like a folder move it takes no
    transfer slot, so it is answered while the ceiling and its queue are full, and it runs on the event loop as a
    folder move and a rename do. A move to another vault is refused then (the test above)."""
    async def scenario():
        gate = TransferAdmission(limit=1, max_waiting=0, wait_seconds=20)
        world = _World(monkeypatch, gate)
        other = await gate.acquire()
        vid = uuid.uuid4()
        answer = await _raw(S.move_file_endpoint)(vid, uuid.uuid4(), S.ItemMoveCopy(dest_vault_id=vid), None,
                                                  current_user=SimpleNamespace(id=uuid.uuid4()), db=world.db,
                                                  x_vault_password=None, x_dest_vault_password=None,
                                                  x_file_password=None)
        stats = gate.stats()
        gate.release(other)
        return world, answer, stats

    world, answer, stats = run_coroutine(scenario())
    assert answer["message"] == "File moved" and answer["id"]
    ((name, seen, _held),) = world.ran
    assert name == "move" and seen["in_flight"] == 1, "it took a slot"
    assert stats["admitted"] == 1 and stats["refused"] == 0 and stats["waiting"] == 0, stats
    ((action, thread),) = world.audited
    assert action == "file_move" and not thread.startswith("stored-bytes"), thread


# ---- the pool ----------------------------------------------------------------------------------------------------

def test_the_pool_keeps_ten_connections_beyond_every_transfer_and_sign_in_handed_to_a_thread():
    from app.core.auth_offload import AUTH_OFFLOAD_LIMIT
    for limit in list(range(-1, 130)) + [256, 1000]:
        capacity = database.pool_capacity(limit)
        assert capacity >= database.MIN_CAPACITY == 30
        assert capacity - admitted_at_most(limit) - AUTH_OFFLOAD_LIMIT >= database.LOOP_RESERVE == 10, limit
    # At the default ceiling: 16 transfers, 4 upload links' completions, 8 sign-ins, and 10 more.
    assert database.pool_capacity(16) == 38
    assert admitted_at_most(16) == ceiling(16) + link_ceiling(16) == 20


def test_the_two_ceilings_are_the_ones_the_pool_counts():
    assert S.transfer_admission.limit == ceiling(S.settings.max_concurrent_transfers)
    assert S.receiver_transfer_admission.limit == link_ceiling(S.settings.max_concurrent_transfers)


@pytest.mark.parametrize("limit", [1, 16, 40])
def test_the_engine_is_made_with_that_capacity(monkeypatch, limit):
    seen = {}

    def fake_create_engine(url, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr(database, "create_engine", fake_create_engine)
    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database.settings, "database_url", "postgresql://u:p@db:5432/x")
    monkeypatch.setattr(database.settings, "max_concurrent_transfers", limit)
    monkeypatch.setattr(database, "runtime_is_initialized", lambda: True)
    with pytest.raises(Exception):
        database.initialize_consumers()
    assert seen["pool_size"] == database.POOL_SIZE == 10
    assert seen["pool_size"] + seen["max_overflow"] == database.pool_capacity(limit)
