"""Revoking an account's sessions also revokes the web sessions that have gone idle.

The periodic cleanup marks a session inactive once it has been idle for its grace window (about an
hour), and a web request never updates that idle time. A regular token is refused only when its row
is missing or revoked, so an inactive row still admits its token until the token expires. Revoking
selected only active rows, so terminating a user's sessions, a password change or reset, and the
"sign out other sessions" step after enrolling a second factor all left every web session older than
about an hour working.

A durable revocation now also revokes the regular rows that are inactive but not yet revoked, in one
statement, and counts them. It sends them no force-close signal: nothing live can still act on such a
row (see _revoke_sessions). A non-durable revocation, which only ends live SFTP transports, is
unchanged.

These tests run the real _revoke_sessions against the real active_sessions table in a throwaway SQLite
database. test_revoke_idle_sessions_live.py drives the routes.
"""
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core.models import ActiveSession, ChunkedUploadSession  # noqa: E402
from app.core.session_hash_utils import hash_session_token  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    """A throwaway database with the real active_sessions table, and the upload sessions a
    credential's revocation cancels. autoflush is off, as in the app."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'sessions.db'}")
        ActiveSession.__table__.create(engine)
        ChunkedUploadSession.__table__.create(engine)
        s = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield s
        s.close()
        engine.dispose()


@pytest.fixture
def published(monkeypatch):
    """The session tokens a force-close signal was sent for."""
    sent = []

    def publish(channel, message):
        assert channel == "session_terminations"
        sent.append(S.json.loads(message)["session_token"])
        return True

    monkeypatch.setattr(S, "_guarded_publish_force", publish)
    return sent


def _row(db, user_id, *, active, revoked=False, temp_credential_id=None, token=None):
    row = ActiveSession(session_token=hash_session_token(token or uuid.uuid4().hex), user_id=user_id,
                        temp_credential_id=temp_credential_id, ip_address="198.51.100.7",
                        is_active=active, revoked=revoked)
    db.add(row)
    db.commit()
    return row.id


def _state(db, row_id):
    db.expire_all()
    row = db.query(ActiveSession).filter(ActiveSession.id == row_id).one()
    return row.is_active, row.revoked


def _token(db, row_id):
    return db.query(ActiveSession.session_token).filter(ActiveSession.id == row_id).scalar()


def _revoke(db, **kw):
    count = S._revoke_sessions(db, actor_username="tester", **kw)
    db.commit()
    return count


def test_a_durable_revocation_also_revokes_the_idle_web_sessions(db, published):
    user, other = uuid.uuid4(), uuid.uuid4()
    live = _row(db, user, active=True)
    idle = _row(db, user, active=False)                      # reaped by the cleanup, token still valid
    logged_out = _row(db, user, active=False, revoked=True)
    temp_idle = _row(db, user, active=False, temp_credential_id=uuid.uuid4())
    someone_else = _row(db, other, active=False)

    assert _revoke(db, user_id=user) == 2, "the live session and the idle one"

    assert _state(db, live) == (False, True)
    assert _state(db, idle) == (False, True), "an idle web session kept a working token"
    assert _state(db, logged_out) == (False, True)
    # A temporary credential's token is refused once its row is inactive: nothing to add.
    assert _state(db, temp_idle) == (False, False)
    assert _state(db, someone_else) == (False, False), "another account's session was touched"
    # Only the live session gets a force-close signal.
    assert published == [_token(db, live)]


def test_a_session_the_cleanup_ends_meanwhile_is_revoked_and_counted_once(db, monkeypatch):
    """The cleanup can mark a live session inactive between the moment this loads it as live and
    the statement that revokes the idle ones. It must still end up revoked, and be counted once."""
    user = uuid.uuid4()
    live = _row(db, user, active=True)

    def cleanup_runs_meanwhile(channel, message):
        other = sessionmaker(bind=db.get_bind())()
        other.query(ActiveSession).filter(ActiveSession.id == live).update({"is_active": False})
        other.commit()
        other.close()
        return True

    monkeypatch.setattr(S, "_guarded_publish_force", cleanup_runs_meanwhile)
    assert _revoke(db, user_id=user) == 1
    assert _state(db, live) == (False, True)


def test_the_revoked_rows_are_left_out_of_the_count(db, published):
    user = uuid.uuid4()
    for _ in range(3):
        _row(db, user, active=False, revoked=True)
    idle = _row(db, user, active=False)
    assert _revoke(db, user_id=user) == 1
    assert _state(db, idle) == (False, True)
    assert published == []


@pytest.mark.parametrize("own_active", [True, False], ids=["own-active", "own-idle"])
def test_the_callers_own_session_is_kept_whether_active_or_idle(db, published, own_active):
    user = uuid.uuid4()
    own = _row(db, user, active=own_active, token="the-callers-own-token")
    live = _row(db, user, active=True)
    idle = _row(db, user, active=False)

    assert _revoke(db, user_id=user, except_session_token="the-callers-own-token") == 2

    assert _state(db, own) == (own_active, False), "the caller's own session was revoked"
    assert _state(db, live) == (False, True)
    assert _state(db, idle) == (False, True)
    assert published == [_token(db, live)]


def test_a_non_durable_revocation_ends_only_the_live_sessions(db, published):
    """Turning SFTP off ends live transports and must leave the web sessions working."""
    user = uuid.uuid4()
    live = _row(db, user, active=True)
    idle = _row(db, user, active=False)

    assert _revoke(db, user_id=user, durable=False) == 1

    assert _state(db, live) == (False, False)
    assert _state(db, idle) == (False, False)
    assert published == [_token(db, live)]


def test_a_temporary_credential_revocation_counts_only_its_live_sessions(db, published):
    user, cred = uuid.uuid4(), uuid.uuid4()
    live = _row(db, user, active=True, temp_credential_id=cred)
    ended = _row(db, user, active=False, temp_credential_id=cred)
    parent_idle = _row(db, user, active=False)

    assert _revoke(db, temp_credential_id=cred) == 1

    assert _state(db, live) == (False, True)
    assert _state(db, ended) == (False, False)
    assert _state(db, parent_idle) == (False, False), "the credential's owner's own sessions are not its to end"
    assert published == [_token(db, live)]
