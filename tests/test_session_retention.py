"""Finished session and pending sign-in rows are deleted after 30 days.

Each row in active_sessions and pending_logins holds the address a sign-in came from. Sessions were
only ever marked inactive and pending sign-ins only marked consumed, so every address stayed in the
database for as long as the deployment ran. The periodic cleanup now deletes the finished ones once
they are older than SESSION_DATA_RETENTION_DAYS (app/core/session_retention.py).

The real conditions run here against the real active_sessions table and a stand-in for
pending_logins (whose creation default is Postgres-only SQL), in a throwaway SQLite database.
"""
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import session_retention as R  # noqa: E402
from app.core.models import ActiveSession  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 9, 1, 12, 0, 0)
OLD = NOW - timedelta(days=R.SESSION_DATA_RETENTION_DAYS, minutes=1)
RECENT = NOW - timedelta(days=R.SESSION_DATA_RETENTION_DAYS - 1)

_Probe = declarative_base()


class Pending(_Probe):
    """The columns of pending_logins the purge reads."""
    __tablename__ = "pending_probe"
    id = sa.Column(sa.Integer, primary_key=True)
    client_ip = sa.Column(sa.String)
    expires_at = sa.Column(sa.DateTime)
    consumed_at = sa.Column(sa.DateTime)
    created_at = sa.Column(sa.DateTime)


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'retention.db'}")
        ActiveSession.__table__.create(engine)
        _Probe.metadata.create_all(engine)
        s = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield s
        s.close()
        engine.dispose()


def _session(db, *, active, last, revoked=False, expires=None, started=None):
    row = ActiveSession(session_token=uuid.uuid4().hex, user_id=uuid.uuid4(), ip_address="198.51.100.4",
                        is_active=active, revoked=revoked, expires_at=expires,
                        started_at=started or last, last_activity=last)
    db.add(row)
    db.commit()
    return row.id


def _pending(db, *, created, consumed=None, expires=None):
    row = Pending(client_ip="198.51.100.4", created_at=created, consumed_at=consumed, expires_at=expires)
    db.add(row)
    db.commit()
    return row.id


def _purge(db, token_minutes=30):
    out = R.purge_old_session_data(db, now=NOW, token_lifetime_minutes=token_minutes,
                                   pending_model=Pending)
    db.commit()
    return out


def _left(db, model):
    return {r.id for r in db.query(model).all()}


def test_finished_sessions_older_than_the_retention_are_deleted(db):
    gone = {
        _session(db, active=False, last=OLD),                                  # ended
        _session(db, active=False, revoked=True, last=OLD),                    # revoked
        _session(db, active=True, last=OLD, expires=NOW - timedelta(days=1)),  # past its expiry
    }
    kept = {
        _session(db, active=False, last=RECENT),                               # ended, but recently
        _session(db, active=True, last=OLD),                                   # still open
        _session(db, active=True, last=OLD, expires=NOW + timedelta(days=1)),  # not yet expired
        _session(db, active=False, last=RECENT, started=OLD),                  # used recently
    }
    assert _purge(db) == (len(gone), 0)
    assert _left(db, ActiveSession) == kept


def test_finished_pending_sign_ins_older_than_the_retention_are_deleted(db):
    gone = {
        _pending(db, created=OLD, consumed=OLD),
        _pending(db, created=OLD, expires=OLD + timedelta(minutes=5)),
    }
    kept = {
        _pending(db, created=RECENT, consumed=RECENT),
        _pending(db, created=RECENT, expires=RECENT + timedelta(minutes=5)),
        _pending(db, created=OLD, expires=NOW + timedelta(minutes=5)),   # not finished
    }
    assert _purge(db) == (0, len(gone))
    assert _left(db, Pending) == kept


def test_a_row_is_kept_as_long_as_a_token_it_backs_can_live(db):
    """A deployment that lets tokens live longer than the retention keeps session rows that long:
    deleting a row a live token names would end that session early."""
    row = _session(db, active=False, last=OLD)
    assert _purge(db, token_minutes=60 * 24 * 45) == (0, 0)
    assert _left(db, ActiveSession) == {row}
    assert R.session_window(60 * 24 * 45) == timedelta(days=45)
    assert R.session_window(30) == timedelta(days=R.SESSION_DATA_RETENTION_DAYS)


def test_the_retention_is_thirty_days():
    assert R.SESSION_DATA_RETENTION_DAYS == 30


def test_the_periodic_cleanup_runs_the_purge_and_commits_it():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    reaper = src[src.index("async def cleanup_expired_sessions"):]
    reaper = reaper[:reaper.index("\ndef ")]
    call = reaper.index("purge_old_session_data(db)")
    assert reaper.index("db.commit()", call) < reaper.index("db.rollback()", call)
