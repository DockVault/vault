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


def test_a_write_given_up_on_does_not_stop_the_next(world, monkeypatch):
    monkeypatch.setattr(vault_access, "RETRY_SECONDS", 0.01)

    def refuse(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("UPDATE VAULTS"):
            raise sa.exc.OperationalError(statement, parameters, Exception("the database is away"))
    sa.event.listen(world.engine, "before_cursor_execute", refuse)
    _open(world, _past(5))
    assert _stored(world) is None
    sa.event.remove(world.engine, "before_cursor_execute", refuse)
    when = _past(4)
    _open(world, when)
    assert _stored(world) == when


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
