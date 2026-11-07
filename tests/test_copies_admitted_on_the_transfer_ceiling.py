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
    def __init__(self, monkeypatch, gate, *, fail_with=None, refuse_access=False, hold=None):
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
                if hold is not None:
                    assert hold.wait(10)
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
        # What is asked again once it has its slot (tests/test_transfers_asked_again_after_the_wait.py).
        monkeypatch.setattr(S, "_user_for_token", lambda token, db: SimpleNamespace(id=uuid.uuid4()))
        monkeypatch.setattr(S, "_vault_credential_fingerprint", lambda db, vault_id: None)
        import app.core.endpoint_permissions as endpoint_permissions
        import app.core.temp_scope as temp_scope
        monkeypatch.setattr(temp_scope, "require_cap", lambda *a, **k: None)
        monkeypatch.setattr(endpoint_permissions, "check_endpoint_permission", lambda *a, **k: None)


def _raw(endpoint):
    while hasattr(endpoint, "__wrapped__"):
        endpoint = endpoint.__wrapped__
    return endpoint


REQUEST = SimpleNamespace(headers={"authorization": "Bearer t"})


def _call(kind, world, user=None):
    """The endpoint's coroutine for `kind`, as FastAPI would call it."""
    user = user or SimpleNamespace(id=uuid.uuid4())
    vid, item = uuid.uuid4(), uuid.uuid4()
    if kind == "copy":
        return _raw(S.copy_file_endpoint)(vid, item, S.ItemMoveCopy(dest_vault_id=uuid.uuid4()), REQUEST,
                                          current_user=user, db=world.db, x_vault_password=None,
                                          x_dest_vault_password=None, x_file_password=None)
    if kind == "move":
        return _raw(S.move_file_endpoint)(vid, item, S.ItemMoveCopy(dest_vault_id=uuid.uuid4()), REQUEST,
                                          current_user=user, db=world.db, x_vault_password=None,
                                          x_dest_vault_password=None, x_file_password=None)
    return _raw(S.copy_folder_endpoint)(vid, item, S.FolderMoveCopy(dest_vault_id=vid), REQUEST,
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
        answer = await _raw(S.move_file_endpoint)(vid, uuid.uuid4(), S.ItemMoveCopy(dest_vault_id=vid), REQUEST,
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


@pytest.mark.parametrize("kind", KINDS)
def test_one_account_holds_at_most_its_share_of_the_slots_with_copies(monkeypatch, kind):
    """A quarter of the ceiling, at least one: at a ceiling of 4, one account's second copy waits for its first to
    end, while another account's copy is admitted at once. Without it one account's long folder copies held every
    slot."""
    async def scenario():
        gate = TransferAdmission(limit=4, max_waiting=8, wait_seconds=30)
        hold = threading.Event()
        world = _World(monkeypatch, gate, hold=hold)
        one, another = SimpleNamespace(id=uuid.uuid4()), SimpleNamespace(id=uuid.uuid4())

        async def until(done):
            for _ in range(500):
                if done():
                    return True
                await asyncio.sleep(0.01)
            return False

        try:
            first = asyncio.ensure_future(_call(kind, world, user=one))
            assert await until(lambda: len(world.ran) == 1)
            second = asyncio.ensure_future(_call(kind, world, user=one))
            third = asyncio.ensure_future(_call(kind, world, user=another))
            await until(lambda: len(world.ran) == 2 and gate.stats()["waiting_for_share"] == 1)
            seen = (gate.stats()["in_flight"], gate.stats()["waiting_for_share"], gate.stats()["waiting"],
                    len(world.ran))
            # What the Activity page's "Now" panel shows: a copy waiting for its share is waiting too.
            shown = S._activity_transfers()
        finally:
            hold.set()
        answers = await asyncio.gather(first, second, third)
        return seen, shown, answers, gate.stats()

    seen, shown, answers, after = run_coroutine(scenario())
    assert seen == (2, 1, 0, 2), f"(in flight, waiting for its share, waiting, run) while the first copy ran: {seen}"
    assert (shown["in_flight"], shown["waiting"], shown["limit"]) == (2, 1, 4), shown
    assert all(a["id"] for a in answers)
    assert (after["in_flight"], after["waiting"], after["admitted"]) == (0, 0, 3), after


@pytest.mark.parametrize("kind", KINDS)
def test_an_account_past_its_share_is_told_its_share_is_in_use_not_that_the_server_is_full(monkeypatch, kind):
    """One account's copy past its share, with no room to wait for it: 429 saying the account's copies are what it
    waits for, with Retry-After, and not counted as load the deployment shed. The deployment has slots free."""
    async def scenario():
        gate = TransferAdmission(limit=4, max_waiting=0, wait_seconds=20)
        hold = threading.Event()
        world = _World(monkeypatch, gate, hold=hold)
        one = SimpleNamespace(id=uuid.uuid4())
        try:
            first = asyncio.ensure_future(_call(kind, world, user=one))
            for _ in range(500):
                if world.ran:
                    break
                await asyncio.sleep(0.01)
            try:
                await _call(kind, world, user=one)
            except HTTPException as exc:
                refused = exc
            else:
                refused = None
            stats = gate.stats()
        finally:
            hold.set()
        await first
        return refused, stats, world

    refused, stats, world = run_coroutine(scenario())
    assert refused is not None and refused.status_code == 429, refused
    assert refused.headers["Retry-After"] == "20"
    assert refused.detail.startswith("This account already has 1 copy or move running at once"), refused.detail
    assert "already handling" not in refused.detail
    assert (stats["refused"], stats["refused_over_share"], stats["in_flight"]) == (0, 1, 1), stats
    assert len(world.ran) == 1, "the refused copy ran"


def test_a_full_deployment_and_a_full_share_are_told_apart():
    """A full share names the account's others that wait only when some do: with none (a queue of 0, or the last of
    them gave up) it said "and others waiting" all the same."""
    full = S._busy_response(S.TransferBusy(retry_after=20, waiting=32, limit=16))
    share = S._busy_response(S.ShareBusy(retry_after=20, share=4, waiting=3))
    alone = S._busy_response(S.ShareBusy(retry_after=20, share=4))
    assert (full.status_code, share.status_code, alone.status_code) == (503, 429, 429)
    assert full.detail == "The server is already handling 16 transfers. Try again in a few seconds."
    assert share.detail == ("This account already has 4 copies or moves running at once, the most one account may "
                            "run, and 3 more waiting for one of them to finish. Try again when one has finished.")
    assert alone.detail == ("This account already has 4 copies or moves running at once, the most one account may "
                            "run. Try again when one has finished.")
    assert full.headers == share.headers == alone.headers == {"Retry-After": "20"}


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


@pytest.mark.parametrize("carries_transfers", [True, False])
@pytest.mark.parametrize("limit", [1, 16, 40])
def test_the_engine_is_made_with_that_capacity(monkeypatch, limit, carries_transfers):
    """The web server's pool from the ceiling; any other process's (the SFTP server's, a command's) 30, whatever the
    ceiling: SFTP transfers are not on it, and the two pools sized from it together passed PostgreSQL's 100
    connections from a ceiling of about 25."""
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
        database.initialize_consumers(carries_transfers=carries_transfers)
    assert seen["pool_size"] == database.POOL_SIZE == 10
    expected = database.pool_capacity(limit) if carries_transfers else database.MIN_CAPACITY
    assert seen["pool_size"] + seen["max_overflow"] == expected


@pytest.mark.parametrize("component, carries", [("API", True), ("SFTP", False)])
def test_only_the_web_server_sizes_its_pool_from_the_ceiling(monkeypatch, component, carries):
    from app.core import config
    asked = []
    monkeypatch.setattr(config, "initialize_runtime",
                        lambda **k: SimpleNamespace(plan_log_pull=False, log_token_pepper=""))
    monkeypatch.setattr(database, "initialize_consumers", lambda **k: asked.append(k))
    config.bootstrap_entrypoint(component)
    assert asked == [{"carries_transfers": carries}]


def test_the_two_pools_fit_in_what_postgresql_accepts_up_to_a_ceiling_of_40():
    """PostgreSQL accepts 100 connections unless it is told otherwise: the web server's pool and the SFTP server's
    hold 68 of them at the default ceiling, 96 at 39 and 98 at 40, as the documentation says."""
    both = {limit: database.pool_capacity(limit) + database.MIN_CAPACITY for limit in (16, 39, 40, 41, 42, 43)}
    assert both == {16: 68, 39: 96, 40: 98, 41: 99, 42: 100, 43: 101}
    assert all(database.pool_capacity(limit) + database.MIN_CAPACITY <= 100 for limit in range(-1, 43))


# max_connections, superuser_reserved_connections, a superuser, the role's own limit (-1: none)
SHIPPED, OWN_ROLE = (100, 3, True, -1), (100, 3, False, -1)


@pytest.mark.parametrize("row, ceiling_, sftp, needed, usable, highest", [
    (SHIPPED, 16, True, 68, 100, 42),
    (SHIPPED, 43, True, 101, 100, 42),
    (OWN_ROLE, 39, True, 96, 97, 39),
    (OWN_ROLE, 40, True, 98, 97, 39),         # the 98 of a ceiling of 40 is past what a role that is not one opens
    (OWN_ROLE, 40, False, 68, 97, 63),        # no SFTP server beside it
    ((100, 3, False, 50), 16, True, 68, 50, 0),
    ((200, 5, False, -1), 64, True, 128, 195, 118),
])
def test_what_the_pools_may_open_is_set_against_what_the_role_may(row, ceiling_, sftp, needed, usable, highest):
    room = database.connection_room(row, ceiling_, sftp)
    assert (room["needed"], room["usable"], room["highest_ceiling"]) == (needed, usable, highest)
    if highest:
        assert database.pool_capacity(highest) + (database.MIN_CAPACITY if sftp else 0) <= usable
    assert database.pool_capacity(highest + 1) + (database.MIN_CAPACITY if sftp else 0) > usable


class _RoomEngine:
    """An engine on PostgreSQL whose server answers ``row`` to the question of connection_room."""

    def __init__(self, row):
        self.row = row
        self.dialect = SimpleNamespace(name="postgresql")

    def connect(self):
        engine = self

        class _Connection:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, statement):
                assert "superuser_reserved_connections" in str(statement)
                return SimpleNamespace(first=lambda: engine.row)
        return _Connection()


@pytest.mark.parametrize("row, ceiling_, said", [
    (OWN_ROLE, 40, "Set MAX_CONCURRENT_TRANSFERS to 39 or less"),
    (SHIPPED, 43, "Set MAX_CONCURRENT_TRANSFERS to 42 or less"),
    (OWN_ROLE, 16, None),
    (SHIPPED, 42, None),
])
def test_the_start_says_when_the_pools_may_open_more_than_the_role_may(monkeypatch, capsys, row, ceiling_, said):
    from app.core import sftp_versions
    monkeypatch.setattr(database, "_require_engine", lambda: _RoomEngine(row))
    monkeypatch.setattr(database.settings, "max_concurrent_transfers", ceiling_)
    monkeypatch.delenv(sftp_versions.COMBINED_SFTP_ENV, raising=False)
    capsys.readouterr()
    database.report_connection_room()
    out = capsys.readouterr().out
    if said is None:
        assert out == ""
    else:
        assert out.startswith(f"Warning: at MAX_CONCURRENT_TRANSFERS={ceiling_} the database pools") and said in out
        assert ("3 of them kept for superusers" in out) == (row is OWN_ROLE)


def test_a_database_that_cannot_be_asked_is_said_and_the_start_goes_on(monkeypatch, capsys):
    def unreachable():
        raise ConnectionError("db:5432 refused")
    monkeypatch.setattr(database, "_require_engine", unreachable)
    database.report_connection_room()
    out = capsys.readouterr().out
    assert out == "Warning: the database's connection limit was not checked (ConnectionError)\n"


def test_the_web_server_asks_at_its_start_whether_the_pools_fit(monkeypatch):
    """The check above is the web server's start's: its lifespan asks it once the database is set up, before the
    schema's statements run, so a ceiling the database cannot serve is said in the log of every start."""
    import app.core.data_requirements as data_requirements
    calls = []

    class Asked(Exception):
        pass

    def room():
        calls.append("pools")
        raise Asked()

    def went_on():
        raise AssertionError("the start went on without asking whether the pools fit")

    monkeypatch.setattr(S, "initialize_runtime", lambda *a, **k: calls.append("runtime"))
    monkeypatch.setattr(data_requirements, "check_at_startup", lambda who: calls.append(("newer data", who)))
    monkeypatch.setattr(S, "init_db", lambda: calls.append("tables"))
    monkeypatch.setattr(database, "report_connection_room", room)
    monkeypatch.setattr(S, "_run_lightweight_migrations", went_on)
    with pytest.raises(Asked):
        run_coroutine(S.lifespan(S.app).__aenter__())
    assert calls == ["runtime", ("newer data", "web"), "tables", "pools"]
