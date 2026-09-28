"""Deactivating a user revokes their sessions, on every route that deactivates.

While an account is deactivated each request is refused by the per-request active check. A regular
session token is refused for good only when its row is revoked, so a deactivation that revoked
nothing left every token the user held working again the moment the account was reactivated.
PATCH /users/{id}, which the web app's Users page uses, revoked; the API routes
POST /api/user-management/users/{id}/toggle-active and PUT /api/user-management/users/{id} did not.

The three routes that deactivate a user now revoke durably: the live sessions and the idle ones the
periodic cleanup has marked inactive. Reactivating leaves them revoked.

These drive the two user-management handlers (without their permission and step-up decorators,
which the live tests cover) and the real _revoke_sessions against the real tables in a throwaway
SQLite database. test_deactivation_revokes_sessions_live.py drives the routes and checks that the
old token answers 401 after reactivation.
"""
import inspect
import tempfile
import types
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine  # the one loop helper; see tests/_async_run.py
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
import app.api.user_management_api as UM  # noqa: E402
from app.core.models import (  # noqa: E402
    ActiveSession, CredentialChange, RoleEnum, User, Vault, VaultMemberKey,
)
from app.core.session_hash_utils import hash_session_token  # noqa: E402

pytestmark = pytest.mark.unit

TOGGLE = inspect.unwrap(UM.toggle_user_active)
PUT = inspect.unwrap(UM.update_user)


@pytest.fixture
def db(monkeypatch):
    """A throwaway database with the tables deactivation touches, and the audit log, the user cap
    and the force-close signal stubbed out."""
    sent = []
    monkeypatch.setattr(S, "_guarded_publish_force",
                        lambda channel, message: sent.append(S.json.loads(message)) or True)
    monkeypatch.setattr(S, "_enforce_user_cap", lambda db: None)
    monkeypatch.setattr(UM, "AuditLogger", lambda db: types.SimpleNamespace(
        log_custom_action=lambda **kw: None))

    async def user_detail(**kw):
        return None
    monkeypatch.setattr(UM, "get_user_detail", user_detail)

    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'users.db'}")
        # credential_changes: deactivating an account withdraws the requests it has open.
        for table in (User.__table__, Vault.__table__, VaultMemberKey.__table__,
                      ActiveSession.__table__, CredentialChange.__table__):
            table.create(engine)
        s = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        s.sent = sent
        yield s
        s.close()
        engine.dispose()


def _account(db, role=RoleEnum.USER):
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=role,
             is_active=True)
    db.add(u)
    db.commit()
    return u


def _session(db, user, *, active):
    row = ActiveSession(session_token=hash_session_token(uuid.uuid4().hex), user_id=user.id,
                        ip_address="198.51.100.7", is_active=active, revoked=False)
    db.add(row)
    db.commit()
    return row.id


def _revoked(db, row_id):
    db.expire_all()
    return db.query(ActiveSession.revoked).filter(ActiveSession.id == row_id).scalar()


def _toggle(db, target, admin):
    return run_coroutine(TOGGLE(user_id=target.id, current_user=admin, db=db, request=None))


def _put(db, target, admin, **fields):
    return run_coroutine(PUT(user_id=target.id, update_data=UM.UserUpdateRequest(**fields),
                             request=None, current_user=admin, db=db))


def test_toggle_active_revokes_the_live_and_the_idle_sessions_and_reactivation_keeps_them_revoked(db):
    admin, target, bystander = _account(db, RoleEnum.ADMIN), _account(db), _account(db)
    live = _session(db, target, active=True)
    idle = _session(db, target, active=False)       # marked inactive by the cleanup, token still valid
    other = _session(db, bystander, active=True)

    assert _toggle(db, target, admin)["is_active"] is False
    assert _revoked(db, live) and _revoked(db, idle), "a deactivated user's session was not revoked"
    assert [m["session_id"] for m in db.sent] == [str(live)], "only the live session is force-closed"
    assert _revoked(db, other) is False, "another account's session was touched"

    assert _toggle(db, target, admin)["is_active"] is True
    assert _revoked(db, live) and _revoked(db, idle), "reactivation brought a session back"


def test_reactivating_revokes_nothing(db):
    """The revocation belongs to the deactivation: turning an account back on ends no session."""
    admin, target = _account(db, RoleEnum.ADMIN), _account(db)
    target.is_active = False
    db.commit()
    kept = _session(db, target, active=True)

    assert _toggle(db, target, admin)["is_active"] is True
    assert _revoked(db, kept) is False
    assert db.sent == []


def test_put_deactivation_revokes_the_sessions(db):
    admin, target = _account(db, RoleEnum.ADMIN), _account(db)
    live = _session(db, target, active=True)
    idle = _session(db, target, active=False)

    _put(db, target, admin, is_active=False)
    db.expire_all()
    assert db.query(User.is_active).filter(User.id == target.id).scalar() is False
    assert _revoked(db, live) and _revoked(db, idle)


def test_a_put_that_leaves_the_account_active_revokes_nothing(db):
    admin, target = _account(db, RoleEnum.ADMIN), _account(db)
    live = _session(db, target, active=True)

    _put(db, target, admin, is_active=True)
    _put(db, target, admin, role=RoleEnum.USER)
    assert _revoked(db, live) is False
    assert db.sent == []
