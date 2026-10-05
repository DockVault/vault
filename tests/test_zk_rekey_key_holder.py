"""Only someone who holds a zero-knowledge vault's key may rotate it.

A rotation runs in the caller's browser: it mints the new key and wraps it for every remaining
member, and the server stores the wraps. So whoever runs a rotation learns the key that protects
every file uploaded after it. POST /ecc/vaults/{id}/rekey used to accept the owner, any global admin
or any Manager, whether or not they held the key, and did not even need to remove anyone. An
administrator who was never given the key could rotate it, learn the new one, and read everything
uploaded afterwards (given the stored ciphertext), while the members kept working and noticed
nothing.

Now the caller must hold an active key at the vault's CURRENT epoch -- a wrapped DEK at dek_version
in a direct vault, a team private key at team_key_version in a hierarchical one -- checked under the
vault row lock the rotation already takes. And because the caller learns the new key, they must be
one of the members it is wrapped for: nobody rotates themselves out.

The same holds for handing out key material that members will then use: sharing the vault key with
a new member (POST /ecc/vaults/{id}/members), which already required *a* key and now requires the
current one, and minting or extending the name-index key (PUT /ecc/vaults/{id}/index-key), which
required only management rights.

This file drives the real handlers (without their permission decorators, which the live tests cover)
against the real tables in a throwaway SQLite database. test_zk_rekey_key_holder_live.py drives the
route on a running deployment, including the lock under a real concurrent removal.

The requests here carry no key proof, so they run with enforcement off, where a request without one is
handled as it was before proofs existed: the rule under test is the key-holder check, which a proof
adds to rather than replaces (test_zk_key_proof_handler.py covers the proofs).
"""
import inspect
import json
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import sqltypes

from _async_run import run_coroutine  # the one loop helper; see tests/_async_run.py
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import ecc_router as E  # noqa: E402
from app.core.key_wrap_algorithms import DIRECT_DEK_ALGO, TEAMPRIV_ALGO  # noqa: E402
from app.core.models import (  # noqa: E402
    RoleEnum, User, UserKeyPair, Vault, VaultMemberIndexKey, VaultMemberKey, vault_members,
)

pytestmark = pytest.mark.unit

# The route's own function, below its two permission decorators (endpoint group + temp-credential
# scope). Those are exercised by the live tests; what is under test here is the handler's decision.
REKEY = inspect.unwrap(E.rekey_vault)
GRANT = inspect.unwrap(E.grant_member_key)
PUT_INDEX_KEY = inspect.unwrap(E.put_vault_index_key)

NOT_A_HOLDER = E._NOT_A_KEY_HOLDER
MUST_REMAIN = "must remain a member"


# --------------------------------------------------------------------------- the database

@pytest.fixture
def Session(monkeypatch):
    """A file-backed SQLite database with the tables a rotation touches.

    Postgres accepts a UUID's text form wherever a UUID goes, and the handler relies on that (the
    vault id arrives as a path string, member ids as JSON strings). SQLite's UUID binding does not,
    so it is taught to here; nothing else about the binding changes."""
    original = sqltypes.Uuid.bind_processor

    def bind_processor(self, dialect):
        inner = original(self, dialect)
        if inner is None:
            return None

        def process(value):
            return inner(uuid.UUID(value) if isinstance(value, str) else value)
        return process

    monkeypatch.setattr(sqltypes.Uuid, "bind_processor", bind_processor)
    monkeypatch.setattr(E, "_ecc_rate_limit", lambda *a, **k: None)
    monkeypatch.setattr(E, "_audit_zk", lambda *a, **k: None)
    monkeypatch.setattr(E.zk_key_proof, "enforcement_enabled", lambda: False)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'zk.db'}",
                                  connect_args={"check_same_thread": False})
        for table in (User.__table__, Vault.__table__, vault_members,
                      VaultMemberKey.__table__, UserKeyPair.__table__,
                      VaultMemberIndexKey.__table__):
            table.create(engine)
        # The application's own session flags (app/core/database.py).
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _person(s, role=RoleEnum.USER):
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=role)
    s.add(u)
    s.flush()
    s.add(UserKeyPair(user_id=u.id, public_key="pub", fingerprint=uuid.uuid4().hex))
    return u.id


def _member(s, vault_id, user_id, manage=False):
    s.execute(vault_members.insert().values(
        vault_id=vault_id, user_id=user_id, read_permission=True, manage_permission=manage))


def _key(s, vault_id, user_id, epoch, algo=DIRECT_DEK_ALGO, active=True):
    s.add(VaultMemberKey(vault_id=vault_id, user_id=user_id, wrapped_dek="w", ephemeral_public_key="e",
                         wrapping_algorithm=algo, key_version=epoch, is_active=active))


def _direct_vault(Session, *, epoch=1):
    """A direct vault at `epoch`: its owner holds the key, a Manager holds the key, and a global
    admin who is neither a member nor a key holder."""
    s = Session()
    owner, manager, admin = _person(s), _person(s), _person(s, RoleEnum.ADMIN)
    vid = uuid.uuid4()
    s.add(Vault(id=vid, owner_id=owner, type="zero_knowledge", key_wrapping_mode="direct",
                dek_version=epoch))
    s.flush()
    _member(s, vid, manager, manage=True)
    for e in range(1, epoch + 1):
        _key(s, vid, owner, e)
        _key(s, vid, manager, e)
    s.commit()
    s.close()
    return vid, owner, manager, admin


def _hier_vault(Session, *, team_epoch=1):
    """A hierarchical vault whose owner and Manager hold the team private key at `team_epoch`."""
    s = Session()
    owner, manager, admin = _person(s), _person(s), _person(s, RoleEnum.ADMIN)
    vid = uuid.uuid4()
    team_key = {"1": {"wrapped_dek": "d", "ephemeral_public_key": "e", "team_key_version": team_epoch}}
    s.add(Vault(id=vid, owner_id=owner, type="zero_knowledge", key_wrapping_mode="hierarchical",
                dek_version=1, team_key_version=team_epoch, team_public_key="TEAMPUB",
                team_key=json.dumps(team_key)))
    s.flush()
    _member(s, vid, manager, manage=True)
    for e in range(1, team_epoch + 1):
        _key(s, vid, owner, e, TEAMPRIV_ALGO)
        _key(s, vid, manager, e, TEAMPRIV_ALGO)
    s.commit()
    s.close()
    return vid, owner, manager, admin


def _wraps(*user_ids):
    return [E.MemberKeyWrap(user_id=str(u), wrapped_dek="new", ephemeral_public_key="eph")
            for u in user_ids]


def _direct_body(frm, *remaining, revoke=None):
    return E.RekeyRequest(from_version=frm, to_version=frm + 1, revoke_user_id=revoke,
                          member_keys=_wraps(*remaining))


def _routine_hier_body(frm=1):
    """A routine hierarchical rotation: a new DEK wrapped to the UNCHANGED team public key. It
    needs no private key at all -- the team public key is public -- which is why this path needs
    the rule as much as the others."""
    return E.RekeyRequest(from_version=frm, to_version=frm + 1, member_keys=[],
                          team_dek_wrapped="dek-to-team", team_dek_ephemeral_public_key="eph")


def _new_team_public_key():
    """A fresh P-384 public key: a team rotation must install one."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _team_rotation_body(*remaining, revoke=None, frm=1):
    return E.RekeyRequest(from_version=frm, to_version=frm + 1, revoke_user_id=revoke,
                          member_keys=_wraps(*remaining), team_public_key=_new_team_public_key(),
                          team_dek_wrapped="dek-to-team", team_dek_ephemeral_public_key="eph")


def _rotate(Session, vid, caller, body):
    s = Session()
    try:
        user = s.query(User).filter(User.id == caller).first()
        return run_coroutine(REKEY(vault_id=str(vid), request=body, current_user=user, db=s))
    finally:
        s.close()


def _refused(Session, vid, caller, body):
    with pytest.raises(HTTPException) as exc:
        _rotate(Session, vid, caller, body)
    return exc.value


def _state(Session, vid):
    """(dek_version, team_key_version, team_public_key, number of key rows) -- what a refused
    rotation must leave exactly as it was."""
    s = Session()
    try:
        v = s.query(Vault).filter(Vault.id == vid).first()
        rows = s.query(VaultMemberKey).filter(VaultMemberKey.vault_id == vid).count()
        return v.dek_version, v.team_key_version, v.team_public_key, rows
    finally:
        s.close()


# --------------------------------------------------------------------------- direct vaults

def test_direct_a_holder_rotates(Session):
    vid, owner, manager, _ = _direct_vault(Session)
    out = _rotate(Session, vid, owner, _direct_body(1, owner, manager))
    assert out["status"] == "ok" and out["dek_version"] == 2
    assert _state(Session, vid)[0] == 2

    # A Manager who holds the key rotates too: holding it, not owning the vault, is the rule.
    out = _rotate(Session, vid, manager, _direct_body(2, owner, manager))
    assert out["dek_version"] == 3


def test_direct_an_admin_who_holds_no_key_is_refused_and_nothing_changes(Session):
    """The case the rule exists for: a global admin may manage the vault but was never given its
    key. A rotation that removes nobody would still hand them the new key."""
    vid, owner, manager, admin = _direct_vault(Session)
    before = _state(Session, vid)
    err = _refused(Session, vid, admin, _direct_body(1, owner, manager))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER
    assert _state(Session, vid) == before, "a refused rotation changed the vault or its keys"


def test_direct_a_manager_whose_key_was_removed_is_refused(Session):
    """Still a Manager (management rights intact), but their key at the current epoch is gone."""
    vid, owner, manager, _ = _direct_vault(Session)
    s = Session()
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == manager).update({"is_active": False})
    s.commit()
    s.close()
    err = _refused(Session, vid, manager, _direct_body(1, owner))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER


def test_direct_a_key_from_an_older_epoch_only_is_not_the_key(Session):
    """A row at an older epoch opens old files; it is not the key in use now."""
    vid, owner, manager, _ = _direct_vault(Session, epoch=2)
    s = Session()
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == manager,
                                   VaultMemberKey.key_version == 2).delete()
    s.commit()
    s.close()
    before = _state(Session, vid)
    err = _refused(Session, vid, manager, _direct_body(2, owner))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER
    assert _state(Session, vid) == before


def test_direct_a_holder_cannot_rotate_themselves_out(Session):
    """Whoever rotates learns the new key, so removing yourself in your own rotation would leave
    you holding the key to files written after you left. (A Manager is already stopped by the
    peer-Manager rule and the owner cannot be removed; a global admin who is a member and holds the
    key is the one this reaches.)"""
    vid, owner, manager, admin = _direct_vault(Session)
    s = Session()
    _member(s, vid, admin, manage=True)
    _key(s, vid, admin, 1)
    s.commit()
    s.close()
    before = _state(Session, vid)
    err = _refused(Session, vid, admin, _direct_body(1, owner, manager, revoke=admin))
    assert err.status_code == 403 and MUST_REMAIN in err.detail
    assert _state(Session, vid) == before


def test_direct_a_holder_who_is_no_longer_a_member_is_refused(Session):
    """A global admin can hold a key without a membership row (a share whose access grant has not
    landed). They hold the key, but the rotation would not wrap the new one for them -- and they
    would learn it anyway."""
    vid, owner, manager, admin = _direct_vault(Session)
    s = Session()
    _key(s, vid, admin, 1)
    s.commit()
    s.close()
    err = _refused(Session, vid, admin, _direct_body(1, owner, manager))
    assert err.status_code == 403 and MUST_REMAIN in err.detail


# --------------------------------------------------------------------------- hierarchical vaults

def test_hierarchical_a_holder_rotates_routinely_and_with_a_new_team_key(Session):
    vid, owner, manager, _ = _hier_vault(Session)
    assert _rotate(Session, vid, manager, _routine_hier_body(1))["dek_version"] == 2
    out = _rotate(Session, vid, owner, _team_rotation_body(owner, manager, frm=2))
    assert out["dek_version"] == 3 and out["team_key_version"] == 2


def test_hierarchical_an_admin_who_holds_no_team_key_is_refused(Session):
    vid, owner, manager, admin = _hier_vault(Session)
    before = _state(Session, vid)
    for body in (_routine_hier_body(1), _team_rotation_body(owner, manager)):
        err = _refused(Session, vid, admin, body)
        assert err.status_code == 403 and err.detail == NOT_A_HOLDER
    assert _state(Session, vid) == before


def test_hierarchical_a_team_key_from_an_older_team_epoch_only_is_refused(Session):
    vid, owner, manager, _ = _hier_vault(Session, team_epoch=2)
    s = Session()
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == manager,
                                   VaultMemberKey.key_version == 2).delete()
    s.commit()
    s.close()
    err = _refused(Session, vid, manager, _routine_hier_body(1))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER


def test_hierarchical_only_a_team_private_key_counts(Session):
    """Both kinds of row share one table, told apart by label. A direct-DEK row at the number of
    the current team epoch is not the team private key and must not pass for it."""
    vid, _, _, admin = _hier_vault(Session)
    s = Session()
    _member(s, vid, admin, manage=True)
    _key(s, vid, admin, 1, DIRECT_DEK_ALGO)
    s.commit()
    s.close()
    err = _refused(Session, vid, admin, _routine_hier_body(1))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER


def test_hierarchical_a_holder_cannot_rotate_themselves_out(Session):
    vid, owner, manager, admin = _hier_vault(Session)
    s = Session()
    _member(s, vid, admin, manage=True)
    _key(s, vid, admin, 1, TEAMPRIV_ALGO)
    s.commit()
    s.close()
    err = _refused(Session, vid, admin, _team_rotation_body(owner, manager, revoke=admin))
    assert err.status_code == 403 and MUST_REMAIN in err.detail


# --------------------------------------------------------------------------- the lock

def _remove_caller_while_waiting_for_the_lock(monkeypatch, Session, vid, caller):
    """Deactivate the caller's keys, from another session, at the last moment before the handler
    takes the vault row lock -- where a removal of the caller that held the lock first would land.

    The orphan sweep is the handler's last step before the lock, so it is the hook: the real sweep
    runs, then the removal commits."""
    real_sweep = E._reconcile_orphan_member_keys

    def sweep_then_remove(db, vault):
        changed = real_sweep(db, vault)
        other = Session()
        other.query(VaultMemberKey).filter(VaultMemberKey.vault_id == vid,
                                           VaultMemberKey.user_id == caller).update({"is_active": False})
        other.commit()
        other.close()
        return changed

    monkeypatch.setattr(E, "_reconcile_orphan_member_keys", sweep_then_remove)


def test_direct_the_check_reads_the_key_after_the_lock(monkeypatch, Session):
    """Checked on entry, the caller would pass on a key that was removed before the rotation got
    the lock. Checked under the lock, the removal is visible and the rotation is refused."""
    vid, owner, manager, _ = _direct_vault(Session)
    _remove_caller_while_waiting_for_the_lock(monkeypatch, Session, vid, manager)
    err = _refused(Session, vid, manager, _direct_body(1, owner, manager))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER
    assert _state(Session, vid)[0] == 1


def test_hierarchical_the_check_reads_the_key_after_the_lock(monkeypatch, Session):
    vid, _, manager, _ = _hier_vault(Session)
    _remove_caller_while_waiting_for_the_lock(monkeypatch, Session, vid, manager)
    err = _refused(Session, vid, manager, _routine_hier_body(1))
    assert err.status_code == 403 and err.detail == NOT_A_HOLDER
    assert _state(Session, vid)[0] == 1


def test_a_non_holder_is_refused_before_the_body_is_used(Session):
    """The check comes before anything in the request is looked at, so a caller who does not hold
    the key learns nothing from the answer -- not even the live epoch that a stale from_version is
    told about -- and a body that would otherwise be rejected for its shape is refused as theirs."""
    vid, owner, manager, admin = _direct_vault(Session, epoch=2)
    stale = _refused(Session, vid, admin, _direct_body(1, owner, manager))
    assert stale.status_code == 403 and stale.detail == NOT_A_HOLDER
    assert "epoch" not in stale.detail
    bad_shape = _refused(Session, vid, admin, E.RekeyRequest(from_version=2, to_version=9, member_keys=[]))
    assert bad_shape.status_code == 403 and bad_shape.detail == NOT_A_HOLDER


# --------------------------------------------------------------------------- handing out key material

def _call(Session, handler, caller, **kwargs):
    s = Session()
    try:
        user = s.query(User).filter(User.id == caller).first()
        return run_coroutine(handler(current_user=user, db=s, **kwargs))
    finally:
        s.close()


def _new_person(Session):
    s = Session()
    uid = _person(s)
    s.commit()
    s.close()
    return uid


def _rows_for(Session, vid, user_id):
    s = Session()
    try:
        return s.query(VaultMemberKey).filter(VaultMemberKey.vault_id == vid,
                                              VaultMemberKey.user_id == user_id).count()
    finally:
        s.close()


def _direct_share(target):
    return E.GrantMemberKeyRequest(user_id=str(target), wrapped_dek="w", ephemeral_public_key="e")


def _team_share(target):
    return E.GrantMemberKeyRequest(user_id=str(target), wrapped_team_privkey="w",
                                   team_ephemeral_public_key="e")


def test_sharing_needs_the_current_key_not_just_a_key(Session):
    """A Manager whose only active row is from an older epoch does not hold the key in use now, so
    whatever they wrap for a new member is not it -- and members use what they are given."""
    vid, _, manager, _ = _direct_vault(Session, epoch=2)
    s = Session()
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == manager,
                                   VaultMemberKey.key_version == 2).delete()
    s.commit()
    s.close()
    target = _new_person(Session)
    with pytest.raises(HTTPException) as exc:
        _call(Session, GRANT, manager, vault_id=str(vid), request=_direct_share(target))
    assert exc.value.status_code == 403 and "current key" in exc.value.detail
    assert _rows_for(Session, vid, target) == 0, "a refused share still stored a key"


def test_sharing_by_a_holder_of_the_current_key_works(Session):
    vid, _, manager, _ = _direct_vault(Session, epoch=2)
    target = _new_person(Session)
    out = _call(Session, GRANT, manager, vault_id=str(vid), request=_direct_share(target))
    assert out["status"] == "ok" and out["key_version"] == 2


def test_sharing_a_hierarchical_vault_needs_the_current_team_key(Session):
    vid, _, manager, _ = _hier_vault(Session, team_epoch=2)
    target = _new_person(Session)
    assert _call(Session, GRANT, manager, vault_id=str(vid),
                 request=_team_share(target))["key_version"] == 2
    s = Session()
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == manager,
                                   VaultMemberKey.key_version == 2).delete()
    s.commit()
    s.close()
    other = _new_person(Session)
    with pytest.raises(HTTPException) as exc:
        _call(Session, GRANT, manager, vault_id=str(vid), request=_team_share(other))
    assert exc.value.status_code == 403
    assert _rows_for(Session, vid, other) == 0


def _index_wraps(*user_ids):
    return E.IndexKeyPut(wraps=[E.IndexKeyWrap(user_id=str(u), encrypted_index_key="k",
                                               ephemeral_public_key="e") for u in user_ids])


def _index_rows(Session, vid):
    s = Session()
    try:
        return s.query(VaultMemberIndexKey).filter(VaultMemberIndexKey.vault_id == vid).count()
    finally:
        s.close()


def test_an_admin_without_the_key_cannot_mint_the_name_index_key(Session):
    """The name-index key is one every member then uses for the names they write. Whoever mints it
    knows it, and with the stored indices can confirm a guessed file name."""
    vid, owner, manager, admin = _direct_vault(Session)
    with pytest.raises(HTTPException) as exc:
        _call(Session, PUT_INDEX_KEY, admin, vault_id=str(vid), body=_index_wraps(owner, manager))
    assert exc.value.status_code == 403 and "holds this vault's key" in exc.value.detail
    assert _index_rows(Session, vid) == 0

    out = _call(Session, PUT_INDEX_KEY, owner, vault_id=str(vid), body=_index_wraps(owner, manager))
    assert out["status"] == "ok" and _index_rows(Session, vid) == 2


def test_a_key_from_an_older_epoch_only_cannot_mint_the_name_index_key(Session):
    vid, _, manager, _ = _hier_vault(Session, team_epoch=2)
    s = Session()
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == manager,
                                   VaultMemberKey.key_version == 2).delete()
    s.commit()
    s.close()
    with pytest.raises(HTTPException) as exc:
        _call(Session, PUT_INDEX_KEY, manager, vault_id=str(vid), body=_index_wraps(manager))
    assert exc.value.status_code == 403
    assert _index_rows(Session, vid) == 0
