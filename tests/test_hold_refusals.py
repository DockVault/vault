"""What a legal hold refuses, offline on a real (SQLite) database (app/core/hold_refusals.py and the routes that
ask it).

A vault a hold keeps anything of (a hold stands on it, or files, folders or old names a released hold kept wait for
their purge) cannot be deleted: the route answers 409 with a sentence naming the case, records
``hold_blocked_delete`` under it, and leaves the vault as it was; a refusal by the database itself (a hold placed after the route asked) gets the same
answer.

SQLite has no triggers: a test writes the hold and kept rows the database and the hold routes would write.
test_hold_refusals_live.py drives the same refusals on a running stack.
"""
import inspect
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as S  # noqa: E402
from app.core import hold_refusals as hr  # noqa: E402
from app.core import kept_tables  # noqa: E402
from app.core import models as m  # noqa: E402
from _async_run import run_coroutine  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 2, 10, 0)


@pytest.fixture(autouse=True)
def text_ids(monkeypatch):
    """The retire route takes a vault's id as text, which Postgres reads as an id; SQLite's id type is taught the
    same, before the database is made (its bind processors are kept per database)."""
    from sqlalchemy.sql import sqltypes
    original = sqltypes.Uuid.bind_processor

    def bind_processor(self, dialect):
        inner = original(self, dialect)
        if inner is None:
            return None
        return lambda value: inner(uuid.UUID(value) if isinstance(value, str) else value)
    monkeypatch.setattr(sqltypes.Uuid, "bind_processor", bind_processor)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """The refusals read the time to tell a release that still waits from one whose purge time has come: here it
    is NOW, whatever the day the tests run."""
    monkeypatch.setattr(hr, "_now", lambda: NOW)


@pytest.fixture
def db(text_ids):
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def _user(db, name, role=m.RoleEnum.USER):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False)
    db.add(u)
    db.commit()
    return u


def _vault(db, owner):
    v = m.Vault(id=uuid.uuid4(), name="Quarterly accounts", owner_id=owner.id)
    db.add(v)
    db.commit()
    return v


def _case(db, auditor, number):
    case = m.ComplianceCase(id=uuid.uuid4(), number=number, status="hold_only", purpose="litigation_hold",
                            legal_basis="legal_obligation", justification_enc="sealed", owner_note_enc="sealed",
                            auditor_id=auditor.id, auditor_username=auditor.username, requested_at=NOW,
                            created_at=NOW, updated_at=NOW)
    db.add(case)
    db.commit()
    return case


def _hold(db, case, vault, *, released=None, purge_after=None):
    db.add(m.LegalHoldVault(case_id=case.id, vault_id=vault.id, placed_by_username="ada", placed_at=NOW,
                            released_at=released, purge_after=purge_after))
    db.commit()


def _kept_file(db, vault, epoch=None):
    db.add(m.HeldFile(id=uuid.uuid4(), vault_id=vault.id, storage_path=f"{vault.id}/{uuid.uuid4()}", size_bytes=1,
                      encryption_metadata={"key_version": epoch} if epoch is not None else None,
                      kept_reason="deleted", kept_at=NOW))
    db.commit()


def _kept_folder(db, vault, epoch=None):
    db.add(m.HeldFolder(id=uuid.uuid4(), vault_id=vault.id, name_key_version=epoch, kept_reason="deleted",
                        kept_at=NOW))
    db.commit()


def _kept_name(db, vault, *, kind="folder", epoch=None):
    """The old sealed name of an object renamed while a hold stood, as the rename triggers keep it."""
    db.add(m.HeldNameHistory(id=uuid.uuid4(), object_id=uuid.uuid4(), vault_id=vault.id, kind=kind,
                             enc_name="zk2:old-sealed-name", name_key_version=epoch, renamed_at=NOW))
    db.commit()


# What a released hold can leave waiting for its purge: a file or folder deleted from the vault, or only the old
# name of something renamed in it.
KEPT = {"a file": _kept_file, "a folder": _kept_folder, "an old name": _kept_name}


@pytest.fixture
def world(db):
    ada = _user(db, "ada", m.RoleEnum.ADMIN)
    olga = _user(db, "olga")
    return SimpleNamespace(db=db, ada=ada, olga=olga, vault=_vault(db, olga), other=_vault(db, olga))


def _blocked(db):
    return db.query(m.AuditLog).filter(m.AuditLog.action == hr.ACTION).order_by(m.AuditLog.timestamp).all()


# --------------------------------------------------------------------------- what keeps a vault

def test_nothing_keeps_a_vault_without_a_hold_or_kept_rows(world):
    assert hr.vault_keeping(world.db, world.vault.id) is None
    # A hold on another vault, and a released hold whose kept rows were purged, keep nothing of this one.
    case = _case(world.db, world.ada, "C-2026-0001")
    _hold(world.db, case, world.other)
    old = _case(world.db, world.ada, "C-2026-0002")
    _hold(world.db, old, world.vault, released=NOW - timedelta(days=9), purge_after=NOW - timedelta(days=2))
    assert hr.vault_keeping(world.db, world.vault.id) is None


def test_a_standing_hold_keeps_the_vault_under_its_case(world):
    case = _case(world.db, world.ada, "C-2026-0003")
    _hold(world.db, case, world.vault)
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert keeping.standing == [(case.id, "C-2026-0003")] and keeping.waiting == []
    text = hr.vault_text(keeping)
    assert "under a legal hold until case C-2026-0003 ends" in text and "cannot be deleted" in text


@pytest.mark.parametrize("kept", sorted(KEPT))
def test_kept_rows_of_a_released_hold_keep_the_vault_until_their_purge(world, kept):
    """Whatever the hold kept waits for its purge, an old name alone included: until then the release can be
    undone, and what was kept must still open."""
    case = _case(world.db, world.ada, "C-2026-0004")
    purge = NOW + timedelta(days=5)
    _hold(world.db, case, world.vault, released=NOW - timedelta(days=2), purge_after=purge)
    assert hr.vault_keeping(world.db, world.vault.id) is None
    assert not kept_tables.has_kept_rows(world.db, world.vault.id)
    KEPT[kept](world.db, world.vault)
    assert kept_tables.has_kept_rows(world.db, world.vault.id) and kept_tables.vault_keeps(world.db, world.vault.id)
    assert not kept_tables.has_kept_rows(world.db, world.other.id), "only that vault's"
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert keeping.standing == [] and keeping.waiting == [(case.id, "C-2026-0004")] and keeping.purge_after == purge
    text = hr.vault_text(keeping)
    assert "case C-2026-0004" in text and f"until they are purged after {purge:%Y-%m-%d}" in text
    assert "can be deleted then" in text


def test_two_standing_holds_are_both_named(world):
    first, second = _case(world.db, world.ada, "C-2026-0005"), _case(world.db, world.ada, "C-2026-0006")
    _hold(world.db, second, world.vault)
    _hold(world.db, first, world.vault)
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert [n for _c, n in keeping.standing] == ["C-2026-0005", "C-2026-0006"]
    assert "cases C-2026-0005 and C-2026-0006" in hr.vault_text(keeping)


def test_two_releases_that_both_wait_are_both_named_with_the_latest_purge_time(world):
    """What a vault kept waits until no release of it waits (the purge's own rule). A case's purge delay is the
    stricter of its value at approval and now, so a release made earlier can wait longer than a later one: both
    can still be undone, both are named, and the vault can be deleted after the later of their two purge times."""
    earlier, later = _case(world.db, world.ada, "C-2026-0022"), _case(world.db, world.ada, "C-2026-0023")
    long_wait, short_wait = NOW + timedelta(days=27), NOW + timedelta(days=6)
    _hold(world.db, earlier, world.vault, released=NOW - timedelta(days=3), purge_after=long_wait)
    _hold(world.db, later, world.vault, released=NOW - timedelta(days=1), purge_after=short_wait)
    _kept_file(world.db, world.vault)
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert keeping.standing == []
    assert keeping.waiting == [(earlier.id, "C-2026-0022"), (later.id, "C-2026-0023")]
    assert keeping.purge_after == long_wait
    text = hr.vault_text(keeping)
    assert "cases C-2026-0022 and C-2026-0023" in text and f"purged after {long_wait:%Y-%m-%d}" in text
    assert f"{short_wait:%Y-%m-%d}" not in text


def test_a_release_whose_purge_time_has_come_is_not_named_while_another_waits(world):
    """The first release's purge time has come (it can no longer be undone); a later one still waits: the vault is
    kept for that one, and its date is the one given."""
    done, waits = _case(world.db, world.ada, "C-2026-0024"), _case(world.db, world.ada, "C-2026-0025")
    _hold(world.db, done, world.vault, released=NOW - timedelta(days=10), purge_after=NOW - timedelta(days=3))
    _hold(world.db, waits, world.vault, released=NOW - timedelta(days=1), purge_after=NOW + timedelta(days=6))
    _kept_name(world.db, world.vault)
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert keeping.waiting == [(waits.id, "C-2026-0025")] and keeping.purge_after == NOW + timedelta(days=6)
    assert "C-2026-0024" not in hr.vault_text(keeping) and "C-2026-0024" not in hr.key_versions_text(keeping)


def test_when_every_purge_time_has_come_the_latest_is_named_until_the_purge_runs(world):
    """Kept rows the purge has not taken yet, though every release's time has come (its next pass takes them):
    the vault still waits, for the release of the latest purge time."""
    first, last = _case(world.db, world.ada, "C-2026-0026"), _case(world.db, world.ada, "C-2026-0027")
    _hold(world.db, first, world.vault, released=NOW - timedelta(days=12), purge_after=NOW - timedelta(days=5))
    _hold(world.db, last, world.vault, released=NOW - timedelta(days=8), purge_after=NOW - timedelta(hours=1))
    _kept_folder(world.db, world.vault)
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert keeping.waiting == [(last.id, "C-2026-0027")] and keeping.purge_after == NOW - timedelta(hours=1)


def test_a_release_with_no_purge_time_keeps_its_date_untold(world):
    """A released hold with no purge time (which no path writes) still waits, and no date is given rather than
    another release's earlier one."""
    told, untold = _case(world.db, world.ada, "C-2026-0028"), _case(world.db, world.ada, "C-2026-0029")
    _hold(world.db, told, world.vault, released=NOW - timedelta(days=1), purge_after=NOW + timedelta(days=6))
    _hold(world.db, untold, world.vault, released=NOW - timedelta(days=1), purge_after=None)
    _kept_file(world.db, world.vault)
    keeping = hr.vault_keeping(world.db, world.vault.id)
    assert [n for _c, n in keeping.waiting] == ["C-2026-0028", "C-2026-0029"] and keeping.purge_after is None
    assert "until they are purged:" in hr.vault_text(keeping)


# --------------------------------------------------------------------------- the record

def test_the_refusal_is_recorded_under_each_case_with_no_name(world):
    first, second = _case(world.db, world.ada, "C-2026-0007"), _case(world.db, world.ada, "C-2026-0008")
    _hold(world.db, first, world.vault)
    _hold(world.db, second, world.vault)
    hr.record(world.db, world.olga, hr.VAULT, hr.vault_keeping(world.db, world.vault.id), vault_id=world.vault.id)
    rows = _blocked(world.db)
    assert sorted((r.case_id, r.details["case_number"]) for r in rows) == sorted(
        [(first.id, "C-2026-0007"), (second.id, "C-2026-0008")])
    for r in rows:
        assert r.status == "failure" and r.user_id == world.olga.id
        assert (r.resource_type, r.resource_id) == ("vault", str(world.vault.id))
        assert r.details["kind"] == "vault" and r.details["vault_id"] == str(world.vault.id)
        assert "Quarterly accounts" not in str(r.details), "no vault name"


def test_a_record_that_cannot_be_written_never_raises(world, monkeypatch):
    def broken(*_a, **_k):
        raise RuntimeError("no database")
    monkeypatch.setattr(world.db, "commit", broken)
    hr.record(world.db, world.olga, hr.VAULT, hr.Keeping(), vault_id=world.vault.id)


def test_only_the_vaults_triggers_refusal_is_taken_for_a_hold():
    def raised(hint):
        orig = Exception("refused")
        orig.diag = SimpleNamespace(message_hint=hint)
        return sa.exc.InternalError("DELETE FROM vaults", {}, orig)
    assert hr.is_trigger_refusal(raised(kept_tables.HOLD_HINT)) is True
    assert hr.is_trigger_refusal(raised("something else")) is False
    assert hr.is_trigger_refusal(raised(None)) is False
    assert hr.is_trigger_refusal(RuntimeError("no orig")) is False


# --------------------------------------------------------------------------- the vault delete route

DELETE_VAULT = inspect.unwrap(S.delete_vault)


@pytest.fixture
def route(world, monkeypatch):
    """The vault delete route with the vault service standing in: get_vault returns the vault, and delete_vault
    records the call (and does what ``then`` says)."""
    state = SimpleNamespace(deleted=[], then=None)

    class _Service:
        def __init__(self, db, _perms):
            self.db = db

        def get_vault(self, vault_id, user, password, require_password=False):
            return world.db.get(m.Vault, vault_id)

        def delete_vault(self, vault_id, user):
            if state.then is not None:
                state.then()
            state.deleted.append(vault_id)

    monkeypatch.setattr(S, "VaultService", _Service)
    monkeypatch.setattr(S, "get_client_ip", lambda request: "10.0.0.9")

    def call(user):
        return run_coroutine(DELETE_VAULT(vault_id=world.vault.id, request=None, vault_password=None,
                                          x_vault_password=None, current_user=user, db=world.db))
    state.call = call
    return state


@pytest.mark.parametrize("held", ["standing"] + sorted(KEPT))
def test_the_route_refuses_a_held_vaults_delete_with_409_and_records_it(world, route, held):
    """Under the hold, or in the release's window while what it kept waits: a vault whose hold kept only the old
    name of something renamed in it too, since the undo of the release would then find no vault."""
    case = _case(world.db, world.ada, "C-2026-0009")
    if held == "standing":
        _hold(world.db, case, world.vault)
    else:
        _hold(world.db, case, world.vault, released=NOW, purge_after=NOW + timedelta(days=7))
        KEPT[held](world.db, world.vault)
    with pytest.raises(HTTPException) as refused:
        route.call(world.olga)
    assert refused.value.status_code == 409 and "C-2026-0009" in refused.value.detail
    assert route.deleted == [], "the vault service was never asked to delete"
    assert world.db.get(m.Vault, world.vault.id) is not None
    (row,) = _blocked(world.db)
    assert row.case_id == case.id and row.details["kind"] == "vault" and row.user_id == world.olga.id
    assert not world.db.query(m.AuditLog).filter(m.AuditLog.action == "vault_deleted").count()


def test_the_route_takes_the_databases_refusal_for_the_same_answer(world, route):
    """A hold placed after the route asked: the vaults trigger refuses the delete, and the route answers 409 under
    the hold's case rather than 500."""
    case = _case(world.db, world.ada, "C-2026-0010")

    def placed_meanwhile():
        _hold(world.db, case, world.vault)
        orig = Exception(f"vault {world.vault.id} is under a legal hold")
        orig.diag = SimpleNamespace(message_hint=kept_tables.HOLD_HINT)
        raise sa.exc.InternalError("DELETE FROM vaults", {}, orig)
    route.then = placed_meanwhile
    with pytest.raises(HTTPException) as refused:
        route.call(world.olga)
    assert refused.value.status_code == 409 and "C-2026-0010" in refused.value.detail
    (row,) = _blocked(world.db)
    assert row.case_id == case.id


def test_another_failure_of_the_delete_is_still_a_500(world, route):
    def fails():
        raise RuntimeError("disk")
    route.then = fails
    with pytest.raises(HTTPException) as failed:
        route.call(world.olga)
    assert failed.value.status_code == 500 and _blocked(world.db) == []


def test_a_vault_nothing_keeps_is_deleted_as_before(world, route):
    """The control: the same call with no hold reaches the vault service, and nothing is refused."""
    out = route.call(world.olga)
    assert route.deleted == [world.vault.id] and "deleted" in out["message"] and _blocked(world.db) == []


def test_the_route_asks_after_the_owner_check_and_before_the_service_deletes():
    source = inspect.getsource(S.delete_vault)
    asked = source.index("hold_refusals.vault_keeping(db, vault_id)")
    assert source.index("Only the vault owner or an admin can delete this vault") < asked
    assert asked < source.index("vault_service.delete_vault(vault_id, current_user)")
    assert source.count("hold_refusals.is_trigger_refusal(e)") == 1


# --------------------------------------------------------------------------- retiring older key versions

from app.api import ecc_router as E  # noqa: E402

RETIRE = inspect.unwrap(E.retire_dek_versions)


@pytest.fixture
def zk(world, monkeypatch):
    """A zero-knowledge vault of olga's at epoch 2 with nothing sealed under epoch 1: a retire deletes her epoch-1
    key row."""
    monkeypatch.setattr(E, "_ecc_rate_limit", lambda user, bucket: None)
    v = m.Vault(id=uuid.uuid4(), owner_id=world.olga.id, type="zero_knowledge", key_wrapping_mode="direct",
                dek_version=2)
    world.db.add(v)
    for epoch in (1, 2):
        world.db.add(m.VaultMemberKey(vault_id=v.id, user_id=world.olga.id, encrypted_dek=f"w{epoch}",
                                      ephemeral_public_key="e", key_version=epoch))
    world.db.commit()
    return v


def _key_epochs(db, vault):
    return sorted(k.key_version for k in db.query(m.VaultMemberKey).filter(m.VaultMemberKey.vault_id == vault.id))


def _retire(world, vault):
    return run_coroutine(RETIRE(vault_id=str(vault.id), current_user=world.olga, db=world.db))


@pytest.mark.parametrize("held", ["standing"] + sorted(KEPT))
def test_retiring_older_key_versions_is_refused_while_a_hold_keeps_the_vault(world, zk, held):
    """A kept old name was sealed under its epoch's key like a kept file: retired in the release's window, the
    name could never be opened again, even once the release is undone."""
    case = _case(world.db, world.ada, "C-2026-0011")
    if held == "standing":
        _hold(world.db, case, zk)
    else:
        _hold(world.db, case, zk, released=NOW, purge_after=NOW + timedelta(days=7))
        KEPT[held](world.db, zk)
    with pytest.raises(HTTPException) as refused:
        _retire(world, zk)
    assert refused.value.status_code == 409 and "C-2026-0011" in refused.value.detail
    assert "older key versions are kept" in refused.value.detail
    assert _key_epochs(world.db, zk) == [1, 2], "no key row was deleted"
    (row,) = _blocked(world.db)
    assert row.case_id == case.id and row.details["kind"] == "key_versions"
    assert row.details["vault_id"] == str(zk.id) and row.user_id == world.olga.id
    assert not world.db.query(m.AuditLog).filter(m.AuditLog.action == "zk_versions_retired").count()


def test_a_retire_with_nothing_keeping_the_vault_still_deletes_the_unused_versions(world, zk):
    """The control: the same call with no hold deletes the epoch-1 row, so a refusal above is the hold's doing."""
    out = _retire(world, zk)
    assert out["rows_deleted"] == 1 and _key_epochs(world.db, zk) == [2] and _blocked(world.db) == []


def test_a_hold_on_another_vault_does_not_stop_this_ones_retire(world, zk):
    _hold(world.db, _case(world.db, world.ada, "C-2026-0012"), world.vault)
    assert _retire(world, zk)["rows_deleted"] == 1


def test_a_manager_who_is_not_the_owner_is_told_of_the_hold_and_not_of_its_case(world, zk, monkeypatch):
    """A vault's members learn that it is held, never by which case: the owner was told of the case, and an
    administrator sees it, but another manager's refusal names none."""
    mia = _user(world.db, "mia")
    monkeypatch.setattr(E, "_can_manage_vault", lambda db, vault, user: True)
    case = _case(world.db, world.ada, "C-2026-0021")
    _hold(world.db, case, zk)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(RETIRE(vault_id=str(zk.id), current_user=mia, db=world.db))
    assert refused.value.status_code == 409 and "under a legal hold:" in refused.value.detail
    assert "C-2026" not in refused.value.detail and "case" not in refused.value.detail
    assert _key_epochs(world.db, zk) == [1, 2]
    (row,) = _blocked(world.db)
    assert row.case_id == case.id and row.user_id == mia.id
    # Released with kept rows: the same, without the case.
    world.db.query(m.LegalHoldVault).update({"released_at": NOW, "purge_after": NOW + timedelta(days=7)})
    world.db.commit()
    _kept_file(world.db, zk)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(RETIRE(vault_id=str(zk.id), current_user=mia, db=world.db))
    assert "a legal hold kept" in refused.value.detail and "C-2026" not in refused.value.detail
    # An administrator is told the case.
    with pytest.raises(HTTPException) as refused:
        run_coroutine(RETIRE(vault_id=str(zk.id), current_user=world.ada, db=world.db))
    assert "C-2026-0021" in refused.value.detail


def test_the_retire_asks_under_the_vaults_row_lock_before_it_reads_the_floor():
    source = inspect.getsource(E.retire_dek_versions)
    asked = source.index("hold_refusals.vault_keeping(db, locked.id)")
    assert source.index(".with_for_update().first())") < asked < source.index("_lowest_epoch_in_use(db, vault_id, locked)")
    assert asked < source.index("VaultKeyProof.dek_epoch < proof_floor")


# --------------------------------------------------------------------------- the lowest epoch in use

def test_the_lowest_epoch_in_use_counts_what_a_hold_kept(world):
    """A retire keeps every key version at or above the lowest epoch in use. What a hold kept of the vault was
    sealed under its epochs: the floor counts the kept files' content epochs and the kept folders' name epochs, so
    no retire drops a key they need."""
    v = m.Vault(id=uuid.uuid4(), owner_id=world.olga.id, type="zero_knowledge", key_wrapping_mode="direct",
                dek_version=4)
    world.db.add(v)
    world.db.add(m.File(id=uuid.uuid4(), vault_id=v.id, name=None, storage_path=f"{v.id}/live", size_bytes=1,
                        encryption_metadata={"key_version": 4}))
    world.db.commit()
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 4
    world.db.add(m.HeldFolder(id=uuid.uuid4(), vault_id=v.id, name_key_version=3, kept_reason="deleted",
                              kept_at=NOW))
    world.db.commit()
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 3
    world.db.add(m.HeldFile(id=uuid.uuid4(), vault_id=v.id, storage_path=f"{v.id}/kept", size_bytes=1,
                            encryption_metadata={"key_version": 2}, kept_reason="replaced", kept_at=NOW))
    world.db.commit()
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 2
    # A kept file with no recorded epoch was sealed before epochs were recorded: epoch 1, as for a live file.
    world.db.add(m.HeldFile(id=uuid.uuid4(), vault_id=v.id, storage_path=f"{v.id}/old", size_bytes=1,
                            encryption_metadata=None, kept_reason="deleted", kept_at=NOW))
    world.db.commit()
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 1


@pytest.mark.parametrize("kind", ["folder", "file"])
def test_the_lowest_epoch_in_use_counts_an_old_name_a_hold_kept(world, kind):
    """A folder sealed at epoch 1, then renamed at epoch 2 while a hold stood: its live name is at 2, and the
    name the hold kept is at 1. After the release, while the release can still be undone, the floor stays at 1,
    so a retire keeps the epoch-1 key the kept name opens with. A file's old name is at its content epoch then;
    an old name with no recorded epoch is at 1, as everything is."""
    v = m.Vault(id=uuid.uuid4(), owner_id=world.olga.id, type="zero_knowledge", key_wrapping_mode="direct",
                dek_version=3)
    world.db.add(v)
    world.db.add(m.Folder(id=uuid.uuid4(), vault_id=v.id, name=None, enc_name="zk2:renamed", name_key_version=3))
    world.db.commit()
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 3
    _kept_name(world.db, v, kind=kind, epoch=2)
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 2
    assert kept_tables.kept_epochs(world.db, v.id) == ([], [], [2])
    _kept_name(world.db, v, kind=kind, epoch=None)
    assert E._lowest_epoch_in_use(world.db, v.id, v) == 1


def test_only_this_vaults_kept_rows_count(world):
    """Kept files, folders and old names of another vault count for nothing here, each table's on its own."""
    v = m.Vault(id=uuid.uuid4(), owner_id=world.olga.id, type="zero_knowledge", dek_version=5)
    world.db.add(v)
    world.db.commit()
    for kept in (_kept_file, _kept_folder, _kept_name):
        kept(world.db, world.vault, epoch=1)
        assert E._lowest_epoch_in_use(world.db, v.id, v) is None
        assert kept_tables.kept_epochs(world.db, v.id) == ([], [], [])
        assert not kept_tables.has_kept_rows(world.db, v.id) and not kept_tables.vault_keeps(world.db, v.id)
    files, folders, names = kept_tables.kept_epochs(world.db, world.vault.id)
    assert (len(files), folders, names) == (1, [1], [1])


def test_a_database_without_the_kept_tables_counts_none(monkeypatch):
    """A stand-in session (no database behind it) reads no kept rows rather than failing."""
    assert kept_tables.kept_epochs(SimpleNamespace(), uuid.uuid4()) == ([], [], [])
    assert kept_tables.has_kept_rows(SimpleNamespace(), uuid.uuid4()) is False


# --------------------------------------------------------------------------- a custodian's account

def _custodian_case(db, auditor, number, person, *, how="person"):
    """A case about ``person``: among the people it concerns as its custodian, or in its scope as one."""
    case = _case(db, auditor, number)
    if how == "person":
        db.add(m.ComplianceCasePerson(case_id=case.id, user_id=person.id, why="custodian"))
    else:
        db.add(m.ComplianceCaseScope(case_id=case.id, kind="custodian", target_id=person.id))
    db.commit()
    return case


@pytest.mark.parametrize("how", ["person", "scope"])
def test_the_custodian_of_a_case_whose_hold_stands_is_kept(world, how):
    otto = _user(world.db, "otto")
    case = _custodian_case(world.db, world.ada, "C-2026-0013", otto, how=how)
    assert hr.custodian_keeping(world.db, otto.id) is None, "no hold yet"
    _hold(world.db, case, world.vault)
    keeping = hr.custodian_keeping(world.db, otto.id)
    assert keeping.standing == [(case.id, "C-2026-0013")] and keeping.waiting == []
    text = hr.account_text(keeping)
    assert "custodian of case C-2026-0013" in text and "cannot be deleted until the hold ends" in text


@pytest.mark.parametrize("kept", sorted(KEPT))
def test_a_released_hold_keeps_its_custodian_while_what_it_kept_waits_for_its_purge(world, kept):
    otto = _user(world.db, "otto")
    case = _custodian_case(world.db, world.ada, "C-2026-0014", otto)
    purge = NOW + timedelta(days=6)
    _hold(world.db, case, world.vault, released=NOW, purge_after=purge)
    assert hr.custodian_keeping(world.db, otto.id) is None, "it kept nothing"
    KEPT[kept](world.db, world.vault)
    keeping = hr.custodian_keeping(world.db, otto.id)
    assert keeping.standing == [] and keeping.waiting == [(case.id, "C-2026-0014")] and keeping.purge_after == purge
    assert f"cannot be deleted until they are purged after {purge:%Y-%m-%d}" in hr.account_text(keeping)


def test_an_owner_or_someone_named_is_not_kept_as_a_custodian_is(world):
    otto = _user(world.db, "otto")
    case = _case(world.db, world.ada, "C-2026-0015")
    world.db.add(m.ComplianceCasePerson(case_id=case.id, user_id=world.olga.id, why="owner"))
    world.db.add(m.ComplianceCasePerson(case_id=case.id, user_id=otto.id, why="named"))
    world.db.add(m.ComplianceCaseScope(case_id=case.id, kind="vault", target_id=world.vault.id))
    world.db.commit()
    _hold(world.db, case, world.vault)
    assert hr.custodian_keeping(world.db, world.olga.id) is None
    assert hr.custodian_keeping(world.db, otto.id) is None


def test_another_cases_hold_on_the_vault_does_not_keep_a_custodian_whose_own_hold_ended(world):
    otto = _user(world.db, "otto")
    own = _custodian_case(world.db, world.ada, "C-2026-0016", otto)
    _hold(world.db, own, world.vault, released=NOW, purge_after=NOW - timedelta(days=1))
    _hold(world.db, _case(world.db, world.ada, "C-2026-0017"), world.vault)
    assert hr.custodian_keeping(world.db, otto.id) is None
    # Not even while the other case's hold keeps rows of the vault: the custodian's own release can no longer be
    # undone, so what the vault keeps now is kept for the other case.
    _kept_file(world.db, world.vault)
    assert hr.custodian_keeping(world.db, otto.id) is None


def test_a_custodian_whose_case_held_two_vaults_waits_for_the_later_purge(world):
    """The case held two vaults, both released and both keeping rows, with different purge times (a vault can wait
    for another case's longer delay too, which is that case's): the account can be deleted after the later."""
    otto = _user(world.db, "otto")
    case = _custodian_case(world.db, world.ada, "C-2026-0030", otto)
    sooner, later = NOW + timedelta(days=2), NOW + timedelta(days=9)
    _hold(world.db, case, world.other, released=NOW - timedelta(days=5), purge_after=later)
    _hold(world.db, case, world.vault, released=NOW - timedelta(days=1), purge_after=sooner)
    _kept_file(world.db, world.vault)
    _kept_name(world.db, world.other)
    keeping = hr.custodian_keeping(world.db, otto.id)
    assert keeping.waiting == [(case.id, "C-2026-0030")] and keeping.purge_after == later
    assert f"until they are purged after {later:%Y-%m-%d}" in hr.account_text(keeping)
    # Only a vault that keeps rows counts: with the later one's rows purged, the sooner date is the one.
    world.db.query(m.HeldNameHistory).delete()
    world.db.commit()
    assert hr.custodian_keeping(world.db, otto.id).purge_after == sooner
    # And with both of its purge times come, the account is kept no more.
    assert hr.custodian_keeping(world.db, otto.id, now=later + timedelta(minutes=1)) is None


def test_on_postgres_the_check_takes_the_turn_of_holds_and_deletions_shared_first(world, monkeypatch):
    """A hold an approval commits before the check is seen, and one placed meanwhile waits for the deleting
    transaction: the check takes the turn before it reads anything."""
    from app.core import legal_holds
    otto = _user(world.db, "otto")
    case = _custodian_case(world.db, world.ada, "C-2026-0020", otto)
    _hold(world.db, case, world.vault)
    seen = []
    real_query = world.db.query

    def query(*a, **k):
        seen.append("read")
        return real_query(*a, **k)
    monkeypatch.setattr(world.db, "query", query)
    monkeypatch.setattr(hr, "_dialect", lambda db: "postgresql")
    monkeypatch.setattr(legal_holds, "take_turn", lambda db, *, shared: seen.append(("turn", shared)))
    assert hr.custodian_keeping(world.db, otto.id) is not None
    assert seen[0] == ("turn", True) and seen.count(("turn", True)) == 1


DELETE_USER = inspect.unwrap(S.delete_user)


def _delete_user(world, target):
    return run_coroutine(DELETE_USER(user_id=target.id, current_user=world.ada, db=world.db, request=None))


def test_deleting_a_custodians_account_is_refused_with_409_and_recorded(world):
    otto = _user(world.db, "otto")
    case = _custodian_case(world.db, world.ada, "C-2026-0018", otto)
    _hold(world.db, case, world.vault)
    with pytest.raises(HTTPException) as refused:
        _delete_user(world, otto)
    assert refused.value.status_code == 409 and "custodian of case C-2026-0018" in refused.value.detail
    assert world.db.get(m.User, otto.id) is not None
    (row,) = _blocked(world.db)
    assert row.case_id == case.id and row.user_id == world.ada.id and row.status == "failure"
    assert (row.resource_type, row.resource_id) == ("user", str(otto.id))
    assert row.details["kind"] == "account" and row.details["target_user_id"] == str(otto.id)
    assert row.details["target_username"] == "otto" and row.details["case_number"] == "C-2026-0018"


def test_a_custodians_account_is_deleted_once_nothing_of_the_case_is_kept(world, monkeypatch):
    """The control: the same call once the hold ended and kept nothing reaches the delete."""
    monkeypatch.setattr(S, "get_client_ip", lambda request: "10.0.0.9")
    otto = _user(world.db, "otto")
    oid = otto.id
    case = _custodian_case(world.db, world.ada, "C-2026-0019", otto)
    _hold(world.db, case, world.vault, released=NOW, purge_after=NOW - timedelta(days=1))
    out = _delete_user(world, otto)
    assert "deleted" in out["message"] and world.db.get(m.User, oid) is None and _blocked(world.db) == []


def test_the_delete_asks_before_it_locks_any_vault_row():
    source = inspect.getsource(S.delete_user)
    asked = source.index("hold_refusals.custodian_keeping(db, user.id)")
    assert source.index("Cannot delete your own account") < asked
    assert asked < source.index("record_rotations_owed_by(db, user.id)") < source.index("db.delete(user)")
