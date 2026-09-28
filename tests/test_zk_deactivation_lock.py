"""Deactivating a user locks each of their zero-knowledge vaults before switching off their keys.

Deactivating a user switches off every zero-knowledge key they hold (except in vaults they own), and
the vaults then report that a rotation is owed. It did so without the vault row lock that a rotation
holds from its key-holder check to its commit, and that removing a member takes. So a rotation in
flight could commit an active key for the user at the new epoch just after their old keys were
switched off; the deactivated user then held a current key, and since no key at the current epoch
was switched off, nothing reported the rotation that vault owed.

Now each affected vault is locked, in ascending id order, before its keys are read, and the keys are
read again once the locks are held. The three routes that deactivate a user take those locks before
the last-administrator check locks the administrator rows: a path that holds a vault row may go on
to wait for a user row (writing a key row checks the users it names), so vault rows come first
everywhere, and no two paths can wait on each other in a cycle.

SQLite has no row locks, so these tests read the statements the code sends, rendered as Postgres
would receive them, and stand in for the concurrent rotation with a second session that commits at
the moment the lock is requested. test_zk_rekey_key_holder_live.py holds the lock on a running
deployment and watches a deactivation wait for it.
"""
import inspect
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine  # the one loop helper; see tests/_async_run.py
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
import app.api.user_management_api as UM  # noqa: E402
from app.api.ecc_router import _rekey_owed  # noqa: E402
from app.core.key_wrap_algorithms import DIRECT_DEK_ALGO  # noqa: E402
from app.core.models import (  # noqa: E402
    AccountInvitation, CredentialChange, RoleEnum, User, Vault, VaultMemberKey, vault_members,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    """(sessionmaker, locks): a file-backed SQLite database with the tables deactivation touches,
    and the list of row locks the code asks for, in order, as ("vaults" | "users" |
    "account_invitations", sql, params)."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'offboard.db'}",
                                  connect_args={"check_same_thread": False})
        # credential_changes: deactivating an administrator withdraws the requests they have open.
        # account_invitations: and revokes the invitations they made to be an administrator.
        for table in (User.__table__, Vault.__table__, vault_members, VaultMemberKey.__table__,
                      CredentialChange.__table__, AccountInvitation.__table__):
            table.create(engine)
        # The application's own session flags (app/core/database.py).
        Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        locks = []

        @sa.event.listens_for(Session, "do_orm_execute")
        def record(state):
            if not state.is_select:
                return
            compiled = state.statement.compile(dialect=postgresql.dialect())
            sql = str(compiled)
            if "FOR UPDATE" in sql:
                table = next((t for t in ("vaults", "users", "account_invitations")
                              if f"FROM {t}" in sql), sql)
                locks.append((table, sql, compiled.params))

        yield Session, locks
        engine.dispose()


def _person(s, role=RoleEnum.USER):
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=role,
             is_active=True, is_locked=False)
    s.add(u)
    s.flush()
    return u.id


def _key(s, vault_id, user_id, epoch):
    s.add(VaultMemberKey(vault_id=vault_id, user_id=user_id, wrapped_dek="w", ephemeral_public_key="e",
                         wrapping_algorithm=DIRECT_DEK_ALGO, key_version=epoch, is_active=True))


def _world(Session, leaver_role=RoleEnum.USER):
    """Someone about to be deactivated, holding a key in three vaults owned by others and in one
    they own, plus an administrator who does the deactivating (so the leaver, when an
    administrator too, is never the last one)."""
    s = Session()
    leaver, owner, actor = _person(s, leaver_role), _person(s), _person(s, RoleEnum.ADMIN)
    shared = [uuid.uuid4() for _ in range(3)]
    own = uuid.uuid4()
    for vid in shared:
        s.add(Vault(id=vid, owner_id=owner, type="zero_knowledge", key_wrapping_mode="direct",
                    dek_version=1))
    s.add(Vault(id=own, owner_id=leaver, type="zero_knowledge", key_wrapping_mode="direct",
                dek_version=1))
    s.flush()
    for vid in shared:
        _key(s, vid, owner, 1)
        _key(s, vid, leaver, 1)
    _key(s, own, leaver, 1)
    s.commit()
    s.close()
    return {"leaver": leaver, "owner": owner, "actor": actor, "shared": shared, "own": own}


def _active(Session, user_id, vault_id=None):
    s = Session()
    try:
        q = s.query(VaultMemberKey.vault_id, VaultMemberKey.key_version).filter(
            VaultMemberKey.user_id == user_id, VaultMemberKey.is_active == True)  # noqa: E712
        if vault_id is not None:
            q = q.filter(VaultMemberKey.vault_id == vault_id)
        return sorted(q.all())
    finally:
        s.close()


def _locked_ids(lock):
    _, sql, params = lock
    assert "ORDER BY vaults.id" in sql and "ORDER BY vaults.id DESC" not in sql, (
        f"the vaults are not locked in ascending id order: {sql}")
    (ids,) = [v for v in params.values() if isinstance(v, (list, tuple))]
    return set(ids)


def _blacklist(Session, w):
    s = Session()
    try:
        n = UM._blacklist_user_vault_keys(s, w["leaver"], w["actor"])
        s.commit()
        return n
    finally:
        s.close()


def test_every_vault_is_locked_in_id_order_and_only_the_owners_is_left_alone(db):
    Session, locks = db
    w = _world(Session)

    assert _blacklist(Session, w) == 3
    assert [t for t, _, _ in locks] == ["vaults"], locks
    assert _locked_ids(locks[0]) == set(w["shared"]), "not every vault holding a key was locked"
    assert _active(Session, w["leaver"]) == [(w["own"], 1)], "the owner carve-out is gone"


def test_a_key_a_rotation_commits_while_the_lock_is_awaited_is_switched_off_too(db):
    """The race the lock closes. A rotation of one vault holds its row lock and commits a key for
    the leaver at epoch 2 while the deactivation waits for that lock. Here the rotation's commit
    happens at the moment the lock is requested. Keys read before the lock miss it; keys read under
    it do not."""
    Session, _ = db
    w = _world(Session)
    rotated = w["shared"][1]
    committed = []

    @sa.event.listens_for(Session, "do_orm_execute")
    def rotate_while_waiting(state):
        sql = str(state.statement.compile(dialect=postgresql.dialect())) if state.is_select else ""
        if "FOR UPDATE" in sql and "FROM vaults" in sql and not committed:
            other = Session()
            other.query(Vault).filter(Vault.id == rotated).update({"dek_version": 2})
            _key(other, rotated, w["owner"], 2)
            _key(other, rotated, w["leaver"], 2)
            other.commit()
            other.close()
            committed.append(True)

    _blacklist(Session, w)

    assert committed, "the stand-in rotation never ran"
    assert _active(Session, w["leaver"], rotated) == [], "the key the rotation wrote was left active"
    s = Session()
    try:
        assert _rekey_owed(s, s.query(Vault).filter(Vault.id == rotated).one()) is True, (
            "the vault does not report the rotation it owes")
    finally:
        s.close()


def test_a_vault_shared_with_the_user_while_the_lock_is_awaited_is_locked_too(db):
    """Sharing a vault takes that vault's row lock, so a vault shared with the leaver while the
    deactivation waits was not among the vaults it locked. It is found when the keys are read again
    under the locks, locked in turn, and its key switched off."""
    Session, locks = db
    w = _world(Session)
    late = uuid.uuid4()

    @sa.event.listens_for(Session, "do_orm_execute")
    def share_while_waiting(state):
        sql = str(state.statement.compile(dialect=postgresql.dialect())) if state.is_select else ""
        if "FOR UPDATE" in sql and "FROM vaults" in sql and len(locks) == 1:
            other = Session()
            other.add(Vault(id=late, owner_id=w["owner"], type="zero_knowledge",
                            key_wrapping_mode="direct", dek_version=1))
            other.flush()
            _key(other, late, w["owner"], 1)
            _key(other, late, w["leaver"], 1)
            other.commit()
            other.close()

    assert _blacklist(Session, w) == 4
    assert [t for t, _, _ in locks] == ["vaults", "vaults"], locks
    assert _locked_ids(locks[1]) == {late}
    assert _active(Session, w["leaver"], late) == []


# --------------------------------------------------------------------------- the three routes

_ROUTES = {
    "toggle-active": lambda w, s, actor: inspect.unwrap(UM.toggle_user_active)(
        user_id=w["leaver"], current_user=actor, db=s, request=None),
    "PUT /api/user-management/users/{id}": lambda w, s, actor: inspect.unwrap(UM.update_user)(
        user_id=w["leaver"], update_data=UM.UserUpdateRequest(is_active=False), request=None,
        current_user=actor, db=s),
    "PATCH /users/{id}": lambda w, s, actor: inspect.unwrap(S.update_user)(
        user_id=w["leaver"], user_update=S.UserUpdate(is_active=False), current_user=actor, db=s,
        request=None),
}


class _NoAudit:
    def __init__(self, db):
        pass

    def __getattr__(self, name):
        return lambda *a, **k: None


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_each_route_locks_the_vaults_before_the_administrator_rows(db, monkeypatch, route):
    """The leaver is an administrator, so each route also runs the last-administrator check, which
    locks every administrator row. The vault rows must be locked first."""
    Session, locks = db
    monkeypatch.setattr(UM, "AuditLogger", _NoAudit)
    monkeypatch.setattr(S, "AuditLogger", _NoAudit)
    monkeypatch.setattr(S, "_revoke_sessions", lambda *a, **k: 0)
    w = _world(Session, leaver_role=RoleEnum.ADMIN)

    s = Session()
    try:
        actor = s.query(User).filter(User.id == w["actor"]).one()
        try:
            run_coroutine(_ROUTES[route](w, s, actor))
        except Exception:  # noqa: BLE001 -- what a route does after its commit is not under test
            pass
    finally:
        s.close()

    tables = [t for t, _, _ in locks]
    assert "users" in tables, f"{route} did not run the last-administrator check: {tables}"
    assert tables.index("vaults") < tables.index("users"), (
        f"{route} locked the administrator rows before the vaults: {tables}")
    assert _locked_ids(locks[tables.index("vaults")]) == set(w["shared"])
    # The leaver's invitations to be an administrator are locked after the administrator rows:
    # accepting one reads its maker's row under a share lock and then claims the invitation, so the
    # other order could deadlock with an acceptance.
    assert "account_invitations" in tables, f"{route} did not revoke the leaver's invitations: {tables}"
    assert tables.index("users") < tables.index("account_invitations"), (
        f"{route} locked the invitations before the administrator rows: {tables}")
    # And the deactivation itself went through.
    s = Session()
    try:
        assert s.query(User.is_active).filter(User.id == w["leaver"]).scalar() is False
    finally:
        s.close()
    assert _active(Session, w["leaver"]) == [(w["own"], 1)]
