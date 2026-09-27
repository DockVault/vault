"""DELETE /vaults/{id}/permissions/{user}: the owner cannot be removed, and a request that removes
nobody changes nothing.

The owner's access comes from owning the vault, not from a member row, so this route has nothing of
theirs to remove. It used to answer 404 for the owner -- but only after it had switched off, and
committed, every zero-knowledge key the owner held, at every epoch. Nobody else may give the owner a
new key, so a Manager or an administrator could lock an owner out of their own zero-knowledge vault
for good: no reading, no sharing, no rotating. The same happened to anyone who held a key without
being a member.

Now the owner is refused with 400 before anything is written, on every vault type, and the member
row is removed first: when there was none to remove, the request is rolled back and answered 404
with the user's keys untouched.

This file drives the real handler (below its permission decorators, which the live test covers)
against the real tables in a throwaway SQLite database, and records every statement that writes.
test_vault_owner_not_revocable_live.py drives the route on a running deployment.
"""
import inspect
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine  # the one loop helper; see tests/_async_run.py
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core.key_wrap_algorithms import DIRECT_DEK_ALGO  # noqa: E402
from app.core.models import RoleEnum, User, Vault, VaultMemberKey, vault_members  # noqa: E402

pytestmark = pytest.mark.unit

REVOKE = inspect.unwrap(S.revoke_vault_permission)
OWNER_REFUSED = "The vault owner's access cannot be revoked"
NOT_A_MEMBER = "User does not have access to this vault"


@pytest.fixture
def db(monkeypatch):
    """(sessionmaker, writes, audited): a file-backed SQLite database with the tables the route
    touches, the SQL of every INSERT, UPDATE and DELETE sent to it, and every audit row the route
    asked for."""
    audited = []
    monkeypatch.setattr(S, "_audit_access_change",
                        lambda db, actor, action, *a, **k: audited.append(action))
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'revoke.db'}",
                                  connect_args={"check_same_thread": False})
        for table in (User.__table__, Vault.__table__, vault_members, VaultMemberKey.__table__):
            table.create(engine)
        writes = []

        @sa.event.listens_for(engine, "before_cursor_execute")
        def record(conn, cursor, statement, params, context, executemany):
            if statement.lstrip().split(None, 1)[0].upper() in ("INSERT", "UPDATE", "DELETE"):
                writes.append(statement)

        # The application's own session flags (app/core/database.py).
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False), writes, audited
        engine.dispose()


def _person(s, role=RoleEnum.USER):
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=role)
    s.add(u)
    s.flush()
    return u.id


def _key(s, vault_id, user_id, epoch):
    s.add(VaultMemberKey(vault_id=vault_id, user_id=user_id, wrapped_dek="w", ephemeral_public_key="e",
                         wrapping_algorithm=DIRECT_DEK_ALGO, key_version=epoch, is_active=True))


def _vault(Session, kind="zero_knowledge"):
    """A vault at epoch 2 whose owner holds a key at both epochs, a Manager who holds no key, a
    member who holds both, a global admin who is neither, and someone who holds a key at both
    epochs without being a member (a share whose access grant never landed)."""
    s = Session()
    owner, manager, member, admin, keyed = (_person(s), _person(s), _person(s),
                                            _person(s, RoleEnum.ADMIN), _person(s))
    vid = uuid.uuid4()
    s.add(Vault(id=vid, owner_id=owner, type=kind, key_wrapping_mode="direct", dek_version=2))
    s.flush()
    s.execute(vault_members.insert().values(vault_id=vid, user_id=manager, read_permission=True,
                                            manage_permission=True))
    s.execute(vault_members.insert().values(vault_id=vid, user_id=member, read_permission=True))
    if kind == "zero_knowledge":
        for person in (owner, member, keyed):
            _key(s, vid, person, 1)
            _key(s, vid, person, 2)
    s.commit()
    s.close()
    return {"vault": vid, "owner": owner, "manager": manager, "member": member, "admin": admin,
            "keyed": keyed}


def _revoke(Session, vault_id, caller, target):
    s = Session()
    try:
        user = s.query(User).filter(User.id == caller).first()
        return run_coroutine(REVOKE(vault_id=vault_id, user_id=target, current_user=user, db=s))
    finally:
        s.close()


def _refused(Session, vault_id, caller, target):
    with pytest.raises(HTTPException) as exc:
        _revoke(Session, vault_id, caller, target)
    return exc.value


def _active_keys(Session, vault_id, user_id):
    s = Session()
    try:
        return sorted(k for (k,) in s.query(VaultMemberKey.key_version).filter(
            VaultMemberKey.vault_id == vault_id, VaultMemberKey.user_id == user_id,
            VaultMemberKey.is_active == True))  # noqa: E712
    finally:
        s.close()


def _members(Session, vault_id):
    s = Session()
    try:
        return {r.user_id for r in s.execute(
            vault_members.select().where(vault_members.c.vault_id == vault_id))}
    finally:
        s.close()


@pytest.mark.parametrize("kind", ["zero_knowledge", "standard"])
@pytest.mark.parametrize("caller", ["manager", "admin", "owner"])
def test_the_owner_is_refused_before_anything_is_written(db, kind, caller):
    """A Manager who holds no key and an administrator who holds none are the two who could lock an
    owner out; the owner removing themselves is refused the same way."""
    Session, writes, audited = db
    v = _vault(Session, kind)
    members_before = _members(Session, v["vault"])
    writes.clear()

    err = _refused(Session, v["vault"], v[caller], v["owner"])

    assert err.status_code == 400 and err.detail == OWNER_REFUSED
    assert writes == [], f"a refused request wrote: {writes}"
    assert audited == []
    assert _members(Session, v["vault"]) == members_before
    if kind == "zero_knowledge":
        assert _active_keys(Session, v["vault"], v["owner"]) == [1, 2], "the owner lost a key"


def test_removing_someone_who_is_not_a_member_changes_nothing(db):
    """They hold keys at two epochs but have no member row. The route removes the member row first;
    finding none, it rolls back and answers 404 before their keys are touched."""
    Session, writes, audited = db
    v = _vault(Session)
    writes.clear()

    err = _refused(Session, v["vault"], v["admin"], v["keyed"])

    assert err.status_code == 404 and err.detail == NOT_A_MEMBER
    assert _active_keys(Session, v["vault"], v["keyed"]) == [1, 2], "a 404 switched off keys"
    assert not any("vault_member_keys" in w for w in writes), writes
    assert audited == []


def test_removing_a_member_removes_the_row_and_switches_off_their_keys(db):
    """The control for the two tests above: the same route, on someone who is a member, removes
    them, switches off every key they hold and records it -- so the refusals above are the guards'
    doing, not the stand-in database's."""
    Session, _, audited = db
    v = _vault(Session)

    out = _revoke(Session, v["vault"], v["manager"], v["member"])

    assert out == {"message": "Permission revoked successfully"}
    assert v["member"] not in _members(Session, v["vault"])
    assert _active_keys(Session, v["vault"], v["member"]) == []
    assert _active_keys(Session, v["vault"], v["owner"]) == [1, 2]
    assert audited == ["vault_permission_revoked"]
