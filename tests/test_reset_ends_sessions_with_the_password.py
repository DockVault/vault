"""A password reset ends the account's sessions in the transaction that writes the password, offline
(app/api/api_server.py, do_reset).

Both commit, or neither does: a stolen session must not outlive the reset, so a reset whose sessions could not be
ended changes nothing (the password stays, the link is not used) and says so, and the operator's log has the error's
id, class and place, never its message. test_password_reset.py checks on a running stack that the sessions end.
"""
# ruff: noqa: F811 -- the fixtures of test_password_origin are imported by name and used as parameters
import re

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from test_password_origin import OLD, _link, _use, _user, db, world  # noqa: F401 -- the fixtures are used by name
from app.api import api_server as api
from app.core.models import PasswordResetToken, User
from app.core.security import verify_password

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def judged(monkeypatch):
    """The link is judged elsewhere (test_reset_link_maker_authority.py): here it always stands."""
    monkeypatch.setattr(api, "_reset_link_refusal", lambda *a, **k: None)


def _password_elsewhere(db, user) -> str:
    """The account's password hash as another connection reads it: what has been committed."""
    with Session(bind=db.get_bind()) as other:
        return other.get(User, user.id).password_hash


def test_the_sessions_end_in_the_transaction_that_writes_the_password(db, world, monkeypatch):
    bob = _user(db, "bob")
    token = _link(db, bob, created_by=None, made_by_other=False)
    seen = []

    def revoke(db_, **kw):
        seen.append((kw["user_id"], verify_password(OLD, _password_elsewhere(db_, bob))))
        return 1
    monkeypatch.setattr(api, "_revoke_sessions", revoke)
    assert _use(db, token) == {"ok": True}
    assert seen == [(bob.id, True)], "the new password was not committed before the sessions were ended"
    assert not verify_password(OLD, _password_elsewhere(db, bob))


def test_a_reset_whose_sessions_cannot_be_ended_changes_nothing_and_says_so(db, world, monkeypatch, capsys):
    bob = _user(db, "bob")
    token = _link(db, bob, created_by=None, made_by_other=False)

    def broken(db_, **kw):
        raise RuntimeError("text of the failure that stays out of the log")
    monkeypatch.setattr(api, "_revoke_sessions", broken)
    capsys.readouterr()
    with pytest.raises(HTTPException) as refused:
        _use(db, token)
    assert refused.value.status_code == 503
    assert refused.value.detail.startswith("The password was not changed: try the link again")
    db.expire_all()
    assert verify_password(OLD, db.get(User, bob.id).password_hash)
    assert db.query(PasswordResetToken).one().consumed_at is None, "the link was not used"
    out = capsys.readouterr().out
    line = [ln for ln in out.splitlines() if "password reset not completed" in ln]
    assert len(line) == 1 and line[0].endswith(": RuntimeError"), out
    error_id = re.search(r"\(ID: ([0-9a-f-]{36})\)", line[0]).group(1)
    assert error_id in refused.value.detail
    assert "text of the failure" not in out
    # The link works once the sessions can be ended.
    monkeypatch.setattr(api, "_revoke_sessions", lambda db_, **kw: 0)
    assert _use(db, token) == {"ok": True}
    assert not verify_password(OLD, _password_elsewhere(db, bob))


# The real revocation, kept before the fixtures stand one in.
REVOKE = api._revoke_sessions


def _live_session(db, user):
    import uuid
    from app.core.models import ActiveSession
    ActiveSession.__table__.create(db.get_bind(), checkfirst=True)
    row = ActiveSession(session_token="h" * 64, user_id=user.id, ip_address="198.51.100.7", is_active=True,
                        revoked=False)
    db.add(row)
    db.commit()
    return row.id


def _signals(db, user, monkeypatch):
    """What the SFTP server is told, each with whether the new password was committed by then."""
    seen = []
    monkeypatch.setattr(api, "_revoke_sessions", REVOKE)
    monkeypatch.setattr(api, "_guarded_publish_force", lambda channel, message: seen.append(
        (channel, not verify_password(OLD, _password_elsewhere(db, user)))) or True)
    return seen


def test_the_sftp_servers_signal_goes_once_the_reset_has_committed(db, world, monkeypatch):
    bob = _user(db, "bob")
    _live_session(db, bob)
    token = _link(db, bob, created_by=None, made_by_other=False)
    seen = _signals(db, bob, monkeypatch)
    assert _use(db, token) == {"ok": True}
    assert seen == [("session_terminations", True)], "the live transports were cut before the reset committed"


def test_a_reset_that_does_not_commit_cuts_no_live_transport(db, world, monkeypatch):
    """The reset answers "the password was not changed": the person's live SFTP transfers go on."""
    bob = _user(db, "bob")
    _live_session(db, bob)
    token = _link(db, bob, created_by=None, made_by_other=False)
    seen = _signals(db, bob, monkeypatch)
    real_commit = db.commit
    calls = []

    def commit():
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("the database went away")
        return real_commit()
    monkeypatch.setattr(db, "commit", commit)
    with pytest.raises(HTTPException) as refused:
        _use(db, token)
    assert refused.value.status_code == 503 and calls
    assert seen == [], "a reset that changed nothing cut the live transports"
    assert verify_password(OLD, _password_elsewhere(db, bob))
