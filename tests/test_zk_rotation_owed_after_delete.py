"""A deleted account still leaves its zero-knowledge vaults owing a rotation.

Deleting an account takes its key rows with it (they cascade), so the removal of someone who held a
vault's current key used to leave no trace for the "rotation owed" check, which looks for a deactivated
row at the current epoch: the vault's key holders were not told to rotate, and a hierarchical vault
accepted a rotation of its DEK alone -- wrapped to the team key the deleted person still has. The delete
now records the epoch on the vault first (``record_rotations_owed_by``), and both checks read it until a
rotation moves the epoch past it. This file drives the recorder and the checks against the real tables in a
throwaway SQLite database; test_zk_rotation_owed_after_delete_live.py deletes real accounts on a running
deployment.
"""
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import sqltypes

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import ecc_router as E  # noqa: E402
from app.core.key_wrap_algorithms import DIRECT_DEK_ALGO, TEAMPRIV_ALGO  # noqa: E402
from app.core.models import User, Vault, VaultMemberKey, vault_members  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def Session(monkeypatch):
    original = sqltypes.Uuid.bind_processor

    def bind_processor(self, dialect):
        inner = original(self, dialect)
        if inner is None:
            return None

        def process(value):
            return inner(uuid.UUID(value) if isinstance(value, str) else value)
        return process

    monkeypatch.setattr(sqltypes.Uuid, "bind_processor", bind_processor)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'owed.db'}", connect_args={"check_same_thread": False})
        for table in (User.__table__, Vault.__table__, vault_members, VaultMemberKey.__table__):
            table.create(engine)
        maker = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        opened = []

        def session():
            opened.append(maker())
            return opened[-1]
        yield session
        for s in opened:
            s.close()
        engine.dispose()


def _person(s):
    u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x")
    s.add(u)
    s.flush()
    return u.id


def _vault(s, mode, *, dek=1, team=1):
    owner = _person(s)
    vid = uuid.uuid4()
    s.add(Vault(id=vid, owner_id=owner, type="zero_knowledge", key_wrapping_mode=mode, dek_version=dek,
                team_key_version=team))
    s.flush()
    return vid, owner


def _key(s, vid, uid, epoch, *, algo, active=True):
    s.add(VaultMemberKey(vault_id=vid, user_id=uid, wrapped_dek="w", ephemeral_public_key="e",
                         wrapping_algorithm=algo, key_version=epoch, is_active=active))
    s.flush()


def _delete_rows_of(s, uid):
    """What the database's cascade does when the account row goes."""
    s.query(VaultMemberKey).filter(VaultMemberKey.user_id == uid).delete(synchronize_session=False)
    s.flush()


def test_a_deleted_holder_of_a_direct_vaults_key_leaves_it_owing_a_rotation(Session):
    s = Session()
    vid, owner = _vault(s, "direct")
    member = _person(s)
    for uid in (owner, member):
        _key(s, vid, uid, 1, algo=DIRECT_DEK_ALGO)
    assert E.record_rotations_owed_by(s, member) == [str(vid)]
    _delete_rows_of(s, member)
    vault = s.get(Vault, vid)
    assert vault.rotation_owed_epoch == 1
    assert E._rekey_owed(s, vault) is True
    # A rotation moves the epoch past it, which ends it.
    vault.dek_version = 2
    assert E._rekey_owed(s, vault) is False


def test_a_deleted_team_member_forces_a_team_rotation_and_a_dek_rotation_does_not_end_it(Session):
    s = Session()
    vid, owner = _vault(s, "hierarchical")
    member = _person(s)
    for uid in (owner, member):
        _key(s, vid, uid, 1, algo=TEAMPRIV_ALGO)
    assert E.record_rotations_owed_by(s, member) == [str(vid)]
    _delete_rows_of(s, member)
    vault = s.get(Vault, vid)
    assert vault.rotation_owed_epoch == 1          # the team epoch, not the DEK epoch
    assert E._team_rotation_owed(s, vault) is True and E._rekey_owed(s, vault) is True
    # A rotation of the DEK alone keeps the team key the deleted person has: still owed.
    vault.dek_version = 2
    assert E._team_rotation_owed(s, vault) is True
    # A new team key ends it.
    vault.team_key_version = 2
    assert E._team_rotation_owed(s, vault) is False and E._rekey_owed(s, vault) is False


def test_the_epoch_recorded_is_the_vaults_own_current_one(Session):
    s = Session()
    direct, d_owner = _vault(s, "direct", dek=3)
    team, t_owner = _vault(s, "hierarchical", dek=5, team=2)
    member = _person(s)
    _key(s, direct, member, 3, algo=DIRECT_DEK_ALGO)
    _key(s, team, member, 2, algo=TEAMPRIV_ALGO)
    assert sorted(E.record_rotations_owed_by(s, member)) == sorted([str(direct), str(team)])
    assert s.get(Vault, direct).rotation_owed_epoch == 3
    assert s.get(Vault, team).rotation_owed_epoch == 2


@pytest.mark.parametrize("case", ["an older epoch only", "a key of another kind", "no key"])
def test_an_account_that_was_never_given_the_current_key_marks_nothing(Session, case):
    s = Session()
    vid, owner = _vault(s, "direct", dek=2)
    member = _person(s)
    _key(s, vid, owner, 2, algo=DIRECT_DEK_ALGO)
    if case == "an older epoch only":
        _key(s, vid, member, 1, algo=DIRECT_DEK_ALGO, active=False)
    elif case == "a key of another kind":
        # A team key row on a direct vault is not the vault's key.
        _key(s, vid, member, 2, algo=TEAMPRIV_ALGO, active=False)
    assert E.record_rotations_owed_by(s, member) == []
    assert s.get(Vault, vid).rotation_owed_epoch is None


@pytest.mark.parametrize("mode", ["direct", "hierarchical"])
def test_a_switched_off_key_at_the_current_epoch_is_still_owed_after_the_delete(Session, mode):
    """Deactivating an account, or removing a member without a rotation, switches the key rows off and
    leaves them at the current epoch: that row is what makes the vault owe a rotation. Deleting the account
    later erases it, so the delete records it as it would an active one."""
    s = Session()
    vid, owner = _vault(s, mode, dek=3, team=2)
    member = _person(s)
    algo, epoch = (DIRECT_DEK_ALGO, 3) if mode == "direct" else (TEAMPRIV_ALGO, 2)
    _key(s, vid, owner, epoch, algo=algo)
    _key(s, vid, member, epoch, algo=algo, active=False)
    vault = s.get(Vault, vid)
    assert E._rekey_owed(s, vault) is True          # owed while the switched-off row is there
    assert E.record_rotations_owed_by(s, member) == [str(vid)]
    _delete_rows_of(s, member)
    vault = s.get(Vault, vid)
    assert vault.rotation_owed_epoch == epoch
    assert E._rekey_owed(s, vault) is True          # and still owed once the delete took the row
    if mode == "hierarchical":
        vault.dek_version = 4                       # a rotation of the DEK alone does not end it
        assert E._team_rotation_owed(s, vault) is True
        vault.team_key_version = 3
    else:
        vault.dek_version = 4
    assert E._rekey_owed(s, vault) is False


def test_each_vault_is_locked_and_read_again_before_the_account_is_judged():
    """A rotation in flight holds the vault row; the recorder takes the same lock and reads the row again under
    it, so it judges the account against the epoch the rotation left, never a stale one."""
    import inspect
    src = inspect.getsource(E.record_rotations_owed_by)
    lock = src.index("with_for_update()")
    assert src.count("with_for_update()") == 1
    assert src.index("populate_existing()") < lock < src.index("_had_current_key(db, locked, user_id)")
    assert src.index("vault_ids = sorted(") < lock           # every vault, in a fixed order


def test_nothing_owed_reads_as_before(Session):
    """A vault with no recorded epoch answers from its rows alone, as it did before the column."""
    s = Session()
    vid, owner = _vault(s, "direct")
    _key(s, vid, owner, 1, algo=DIRECT_DEK_ALGO)
    vault = s.get(Vault, vid)
    assert vault.rotation_owed_epoch is None and E._rekey_owed(s, vault) is False


def test_the_user_delete_records_what_is_owed_before_the_account_goes():
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = server.index("async def delete_user(")
    body = server[start:server.index("\n@app.", start)]
    assert body.count("record_rotations_owed_by(db, user.id)") == 1
    assert body.count("db.delete(user)") == 1
    assert body.index("record_rotations_owed_by(db, user.id)") < body.index("db.delete(user)")
    # The record and the delete commit together: no commit between them.
    between = body[body.index("record_rotations_owed_by(db, user.id)"):body.index("db.delete(user)")]
    assert "commit" not in between
    # The record locks vault rows; the last-administrator check locks every administrator's row. Vault rows
    # are locked first everywhere (a rotation holding one writes key rows, which lock the users they name),
    # so the record comes before the check, or a rotation for an administrator could deadlock with the delete.
    assert body.count("removes_last_admin(db, user)") == 1
    assert body.index("record_rotations_owed_by(db, user.id)") < body.index("removes_last_admin(db, user)")
    # Every hard delete of an account goes through that route.
    app_py = [p for p in (ROOT / "app").rglob("*.py")]
    deletes = [p for p in app_py if "db.delete(user)" in p.read_text(encoding="utf-8")]
    assert deletes == [ROOT / "app" / "api" / "api_server.py"]


def test_the_column_reaches_an_existing_deployment():
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert "\"ALTER TABLE vaults ADD COLUMN IF NOT EXISTS rotation_owed_epoch INTEGER\"," in server
    column = Vault.__table__.c.rotation_owed_epoch
    assert column.nullable and column.default is None and column.server_default is None
