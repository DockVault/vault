"""When a vault was last opened is written at most once a minute per vault, by a thread of its own, offline.

Every request that works in a vault opens it through VaultService.get_vault, which wrote the vault's
last_accessed and committed each time: on the event loop for the web server, a wait for the disk of 0.6 to 1.6 s
when it is busy, and a wait for the vault's row lock. It now hands the time to app/core/vault_access.py, whose
writer writes it when the stored time is more than a minute away from it.

These open vaults of a real SQLite database through the real get_vault and the real writer,
and record every statement with the thread that sent it. tests/test_vault_last_access_live.py checks the same on a
running stack: a listing does not wait for a lock on the vault's row, and the readers report the latest opening.
"""
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import models as m  # noqa: E402
from app.core import vault_access  # noqa: E402

pytestmark = pytest.mark.unit

MINUTE = timedelta(seconds=vault_access.EVERY_SECONDS)


class _Statements:
    """Every statement the engine sends, with the thread that sent it."""

    def __init__(self, engine):
        self.seen = []
        sa.event.listen(engine, "before_cursor_execute", self._record)

    def _record(self, conn, cursor, statement, parameters, context, executemany):
        self.seen.append((threading.get_ident(), " ".join(statement.split())))

    def updates_of_vaults(self, thread=None):
        return [s for t, s in self.seen
                if s.upper().startswith("UPDATE VAULTS") and (thread is None or t == thread)]


@pytest.fixture
def world():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'vaults.db'}")
        m.Vault.__table__.create(engine)
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        statements = _Statements(engine)
        session = make()
        owner = uuid.uuid4()
        vault = m.Vault(id=uuid.uuid4(), owner_id=owner, type="standard")
        session.add(vault)
        session.commit()
        try:
            yield SimpleNamespace(make=make, engine=engine, statements=statements, vault_id=vault.id, owner=owner)
        finally:
            assert vault_access.flush(30), "the writer did not finish"
            session.close()
            engine.dispose()


def _stored(world):
    with world.make() as s:
        return s.get(m.Vault, world.vault_id).last_accessed


def _open(world, when):
    """vault_access.opened with the vault as a request's session reads it."""
    with world.make() as s:
        vault_access.opened(s, s.get(m.Vault, world.vault_id), when=when)
    assert vault_access.flush(30)


def _past(minutes):
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) - timedelta(minutes=minutes)


def test_get_vault_writes_nothing_itself_and_the_writer_records_the_opening(world):
    from app.services.vault_service import VaultService
    svc = VaultService.__new__(VaultService)
    svc.db = world.make()
    svc.permission_service = SimpleNamespace(require_vault_permission=lambda *a, **k: None)
    user = SimpleNamespace(id=world.owner, role=None)
    before = datetime.now(timezone.utc).replace(tzinfo=None)
    vault = svc.get_vault(world.vault_id, user)
    # Nothing was written on the thread that opened the vault, and its transaction is over as it always was.
    assert world.statements.updates_of_vaults(threading.get_ident()) == []
    assert not svc.db.in_transaction(), "get_vault no longer ends its transaction"
    assert vault.id == world.vault_id
    assert vault_access.flush(30)
    written = world.statements.updates_of_vaults()
    assert len(written) == 1, world.statements.seen
    stored = _stored(world)
    assert stored is not None and before <= stored <= datetime.now(timezone.utc).replace(tzinfo=None)
    svc.db.close()


def test_a_vault_opened_again_within_a_minute_is_not_written_again(world):
    first = _past(10)
    _open(world, first)
    assert _stored(world) == first
    for seconds in (1, 20, 45, 59, 60):
        _open(world, first + timedelta(seconds=seconds))
    assert len(world.statements.updates_of_vaults()) == 1, "written again within the minute"
    assert _stored(world) == first
    later = first + MINUTE + timedelta(seconds=1)
    _open(world, later)
    assert _stored(world) == later
    assert len(world.statements.updates_of_vaults()) == 2


def test_the_stored_time_is_never_more_than_a_minute_behind_and_written_at_most_once_a_minute(world):
    start = _past(30)
    latest = None
    for step in range(0, 20 * 60, 7):         # opened every 7 s for 20 minutes
        latest = start + timedelta(seconds=step)
        _open(world, latest)
        stored = _stored(world)
        assert latest - MINUTE <= stored <= latest, (latest, stored)
    writes = len(world.statements.updates_of_vaults())
    assert writes <= (latest - start) / MINUTE + 1, writes
    assert writes >= (latest - start) / (MINUTE + timedelta(seconds=7)), writes


def test_a_late_write_never_puts_back_a_later_time(world):
    """A request read the vault before another process wrote a later time: its own, earlier, time is not
    written over it."""
    later = _past(1)
    with world.make() as s:
        stale = s.get(m.Vault, world.vault_id)
        _ = stale.last_accessed                 # read as None, before the other process writes
        with world.make() as other:
            other.execute(sa.update(m.Vault).where(m.Vault.id == world.vault_id).values(last_accessed=later))
            other.commit()
        vault_access.opened(s, stale, when=later - timedelta(seconds=90))
    assert vault_access.flush(30)
    assert _stored(world) == later


def test_a_time_more_than_a_minute_ahead_of_the_clock_is_put_right(world):
    with world.make() as s:
        s.execute(sa.update(m.Vault).where(m.Vault.id == world.vault_id)
                  .values(last_accessed=datetime(2099, 1, 1)))
        s.commit()
    now = _past(0)
    _open(world, now)
    assert _stored(world) == now


def test_a_write_that_fails_is_tried_again(world, monkeypatch):
    monkeypatch.setattr(vault_access, "RETRY_SECONDS", 0.05)
    failed = []

    def refuse_once(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE VAULTS") and not failed:
            failed.append(threading.get_ident())
            raise sa.exc.OperationalError(statement, parameters, Exception("the row is locked"))
    sa.event.listen(world.engine, "before_cursor_execute", refuse_once)
    when = _past(2)
    _open(world, when)
    assert failed, "the first write was not refused"
    assert _stored(world) == when


def _refuse_writes(world, times, also=None):
    """Make the database refuse the next `times` updates of a vault's last access (running `also`, in the writer's
    thread, before each refusal); returns the list each refusal is recorded in."""
    refused = []

    def refuse(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE VAULTS") and len(refused) < times:
            refused.append(threading.get_ident())
            if also is not None:
                also(len(refused))
            raise sa.exc.OperationalError(statement, parameters, Exception("the row is locked"))
    sa.event.listen(world.engine, "before_cursor_execute", refuse)
    return refused


def test_a_write_the_database_refuses_is_tried_until_it_is_written(world, monkeypatch):
    """It was given up after four attempts (about 35 s against a held row), and the opening was lost."""
    monkeypatch.setattr(vault_access, "RETRY_SECONDS", 0.01)
    monkeypatch.setattr(vault_access, "MAX_RETRY_SECONDS", 0.04)
    refused = _refuse_writes(world, times=9)
    when = _past(5)
    _open(world, when)
    assert len(refused) == 9, "the writes were not refused"
    assert _stored(world) == when
    assert vault_access.flush(5) and not vault_access._waiting


def _attempt_times(world, times, error):
    """Make the database refuse the next `times` updates of a vault's last access with `error`; returns the list of
    when each was refused (time.monotonic)."""
    import time
    at = []

    def refuse(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE VAULTS") and len(at) < times:
            at.append(time.monotonic())
            raise error(statement, parameters, Exception("refused"))
    sa.event.listen(world.engine, "before_cursor_execute", refuse)
    return at


def test_the_wait_between_attempts_doubles_up_to_its_longest(world, monkeypatch, caplog):
    """A write that keeps failing (the database away, the row held) was tried every 5 s for as long as the process
    ran. The wait now doubles after each failure, up to MAX_RETRY_SECONDS, and each failure is a warning."""
    import logging
    monkeypatch.setattr(vault_access, "RETRY_SECONDS", 0.05)
    monkeypatch.setattr(vault_access, "MAX_RETRY_SECONDS", 0.4)
    caplog.set_level(logging.WARNING, logger=vault_access.__name__)
    at = _attempt_times(world, 6, sa.exc.OperationalError)
    when = _past(3)
    _open(world, when)
    assert len(at) == 6 and _stored(world) == when
    gaps = [b - a for a, b in zip(at, at[1:])]
    for gap, least in zip(gaps, [0.05, 0.1, 0.2, 0.4, 0.4]):
        assert least * 0.9 <= gap < least + 0.35, (gaps, least)
    assert {r.levelno for r in caplog.records if r.name == vault_access.__name__} == {logging.WARNING}


@pytest.mark.parametrize("error", [sa.exc.ProgrammingError, sa.exc.DataError, sa.exc.IntegrityError])
def test_a_write_the_database_refuses_as_it_is_is_an_error_and_waits_the_longest(world, monkeypatch, caplog, error):
    """Trying again soon cannot cure a statement the database refuses itself (a column it does not have, after a
    rollback of the schema, say): said as an error, and tried again only at the longest wait."""
    import logging
    monkeypatch.setattr(vault_access, "RETRY_SECONDS", 0.01)
    monkeypatch.setattr(vault_access, "MAX_RETRY_SECONDS", 0.3)
    caplog.set_level(logging.WARNING, logger=vault_access.__name__)
    at = _attempt_times(world, 2, error)
    when = _past(3)
    _open(world, when)
    assert len(at) == 2 and _stored(world) == when
    assert at[1] - at[0] >= 0.27, "tried again before the longest wait"
    said = [r for r in caplog.records if r.name == vault_access.__name__]
    assert said and all(r.levelno == logging.ERROR for r in said)
    assert said[0].getMessage().startswith(f"A vault's last access cannot be recorded: the database refuses the "
                                           f"write itself ({error.__name__}, attempt 1)")


def test_a_time_within_a_minute_of_the_stored_one_is_not_written(world):
    """The write itself moves the stored time only when it is more than a minute behind: another process (the SFTP
    server's writer beside the web server's) stored a time, and a request that read the vault before that hands
    its own opening, 30 s later, to this writer. Written, the two servers would each write once a minute, and so
    more often than that between them."""
    stored = _past(10)
    with world.make() as s:
        stale = s.get(m.Vault, world.vault_id)
        _ = stale.last_accessed                 # read as None, before the other process writes
        with world.make() as other:
            other.execute(sa.update(m.Vault).where(m.Vault.id == world.vault_id).values(last_accessed=stored))
            other.commit()
        vault_access.opened(s, stale, when=stored + timedelta(seconds=30))
    assert vault_access.flush(30)
    assert _stored(world) == stored, "written again within the minute"
    # More than a minute after it, it is written.
    later = stored + MINUTE + timedelta(seconds=1)
    _open(world, later)
    assert _stored(world) == later


def test_an_opening_that_comes_while_a_write_fails_is_the_one_written_next(world, monkeypatch):
    """The write in progress is out of the queue; an opening meanwhile queues a write of its own, and the failed
    write, tried again, takes it in rather than putting its own, earlier, time back over it."""
    monkeypatch.setattr(vault_access, "RETRY_SECONDS", 0.05)
    first, meanwhile = _past(9), _past(7)

    def open_again(_n):
        with world.make() as s:
            vault_access.opened(s, SimpleNamespace(id=world.vault_id, last_accessed=None), when=meanwhile)
    _refuse_writes(world, times=1, also=open_again)
    _open(world, first)
    assert _stored(world) == meanwhile


def test_a_later_opening_moves_a_write_that_is_still_waiting(world):
    """While the writer is busy, two openings of one vault queue one write, which takes the later time."""
    busy, go = threading.Event(), threading.Event()

    def hold(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE VAULTS") and not busy.is_set():
            busy.set()
            assert go.wait(30)
    sa.event.listen(world.engine, "before_cursor_execute", hold)
    first, second, third = _past(10), _past(8), _past(6)
    with world.make() as s:
        vault_access.opened(s, SimpleNamespace(id=world.vault_id, last_accessed=None), when=first)
    assert busy.wait(30), "the writer did not start"
    with world.make() as s:
        for when in (second, third):
            vault_access.opened(s, SimpleNamespace(id=world.vault_id, last_accessed=None), when=when)
    assert len(vault_access._waiting) == 1 and vault_access._waiting[world.vault_id].when == third
    go.set()
    assert vault_access.flush(30)
    assert _stored(world) == third


def test_the_readers_forget_the_oldest_openings_first(monkeypatch):
    """Past KEEP vaults the readers forget half of what they remember: the oldest openings, which the stored times
    have caught up with, never the newest."""
    monkeypatch.setattr(vault_access, "KEEP", 4)
    monkeypatch.setattr(vault_access, "_seen", {})
    stand_in = SimpleNamespace(get_bind=lambda: None)       # bound to no engine: nothing is written
    vaults = [uuid.uuid4() for _ in range(5)]
    times = [_past(50 - i) for i in range(5)]
    for vault_id, when in zip(vaults, times):
        vault_access.opened(stand_in, SimpleNamespace(id=vault_id, last_accessed=None), when=when)
    assert [vault_access.last_access(v, None) for v in vaults] == [None, None] + times[2:]


# Run in a process of its own, against a database file the test reads afterwards: what the writer does when the
# process stops, and when its thread is gone.
_CHILD = """
import sys, threading, time, uuid
from datetime import datetime, timedelta, timezone
sys.path.insert(0, sys.argv[2])
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from app.core import models as m
from app.core import vault_access

engine = sa.create_engine("sqlite:///" + sys.argv[1])
m.Vault.__table__.create(engine)
make = sessionmaker(bind=engine)
vault_id = uuid.uuid4()
with make() as s:
    s.add(m.Vault(id=vault_id, owner_id=uuid.uuid4(), type="standard"))
    s.commit()
when = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) - timedelta(minutes=5)
print(vault_id.hex, when.isoformat(), flush=True)
case = sys.argv[3]
if case == "stopped while waiting":
    vault_access.RETRY_SECONDS = 1.0
    refused = []

    def refuse(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE VAULTS") and not refused:
            refused.append(1)
            raise sa.exc.OperationalError(statement, parameters, Exception("the row is locked"))
    sa.event.listen(engine, "before_cursor_execute", refuse)
    with make() as s:
        vault_access.opened(s, s.get(m.Vault, vault_id), when=when)
    while not refused:
        time.sleep(0.01)
    # The write waits for its retry, a second from now: the process stops.
elif case == "writer gone":
    gone = threading.Thread(target=lambda: None)
    gone.start()
    gone.join()
    vault_access._thread = gone                 # a writer that stopped (one a fork left behind, say)
    with make() as s:
        vault_access.opened(s, s.get(m.Vault, vault_id), when=when)
    print("flushed" if vault_access.flush(10) else "not-flushed", flush=True)
"""


def _in_a_process_of_its_own(case):
    import subprocess
    import sys
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        path = Path(tmp) / "vaults.db"
        out = subprocess.run([sys.executable, "-c", _CHILD, str(path), str(root), case], capture_output=True,
                             text=True, timeout=60, cwd=str(root))
        assert out.returncode == 0, out.stderr[-2000:]
        words = out.stdout.split()
        vault_id, when = uuid.UUID(words[0]), datetime.fromisoformat(words[1])
        engine = sa.create_engine(f"sqlite:///{path}")
        try:
            with engine.connect() as c:
                stored = c.execute(sa.select(m.Vault.last_accessed).where(m.Vault.id == vault_id)).scalar()
        finally:
            engine.dispose()
    return when, stored, words[2:]


def test_a_write_still_waiting_when_the_process_stops_is_written_then():
    when, stored, _ = _in_a_process_of_its_own("stopped while waiting")
    assert stored == when, "the opening was lost at the stop"


def test_a_writer_that_stopped_is_started_again():
    when, stored, said = _in_a_process_of_its_own("writer gone")
    assert said == ["flushed"] and stored == when


def test_the_readers_report_the_latest_opening_this_process_saw(world):
    first = _past(10)
    _open(world, first)
    again = first + timedelta(seconds=30)
    _open(world, again)
    stored = _stored(world)
    assert stored == first, "written again within the minute"
    assert vault_access.last_access(world.vault_id, stored) == again
    # A later time stored by another process is reported as stored; a vault this process never opened, as stored.
    assert vault_access.last_access(world.vault_id, again + timedelta(seconds=5)) == again + timedelta(seconds=5)
    assert vault_access.last_access(uuid.uuid4(), first) == first
    assert vault_access.last_access(uuid.uuid4(), None) is None


def test_a_session_not_bound_to_an_engine_has_nothing_written():
    vault = SimpleNamespace(id=uuid.uuid4(), last_accessed=None)
    stand_in = SimpleNamespace(get_bind=lambda: SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))
    when = _past(0)
    vault_access.opened(stand_in, vault, when=when)
    assert vault_access.flush(5)
    assert vault_access.last_access(vault.id, None) == when
