"""The administrators' "force zero-knowledge" setting, offline, against the deployment's plan.

The setting holds only where the plan lets zero-knowledge vaults be made at all. Saved while the plan
included zero-knowledge and kept after the plan dropped it, it used to refuse a standard vault (zero-knowledge
is required) while a zero-knowledge vault was refused as not enabled, so nobody outside an exempted department
could make any vault. Each test asks the server's own create check (_resolve_vault_type_for_create) and rule
(_user_must_use_zk) against a throwaway database. test_host_operator_zk_status_live.py asks them inside a
running stack.
"""
import itertools
import types
import uuid

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as api  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import Group, RoleEnum, SystemSetting, User, Vault, user_groups  # noqa: E402

pytestmark = pytest.mark.unit

TABLES = (User.__table__, Group.__table__, user_groups, Vault.__table__, SystemSetting.__table__)
REQUIRED = "This organization requires zero-knowledge vaults. Choose the Zero-knowledge type."
NOT_ENABLED = "Zero-knowledge vaults are not enabled on this deployment."
KINDS = ("standard", "zero_knowledge")


@pytest.fixture
def db(tmp_path, monkeypatch):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'zk-force.db'}")
    # The tables as they are, less the indexes over an expression only Postgres can build.
    metadata = sa.MetaData()
    for table in TABLES:
        copy = table.to_metadata(metadata)
        for index in [i for i in copy.indexes if not all(isinstance(e, sa.Column) for e in i.expressions)]:
            copy.indexes.discard(index)
    metadata.create_all(engine)
    for name, value in (("plan_zero_knowledge", True), ("plan_force_zero_knowledge", False),
                        ("plan_max_zk_vaults", -1), ("plan_allowed_vault_types", "")):
        monkeypatch.setattr(settings, name, value)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _person(db, department=None):
    """An account, in the department given or in none. The checks read only its id."""
    person = uuid.uuid4()
    db.execute(sa.insert(User.__table__).values(id=person, username=f"person-{person.hex[:8]}",
                                                password_hash="x", role=RoleEnum.USER, is_active=True,
                                                is_locked=False))
    if department:
        db.execute(sa.insert(user_groups).values(user_id=person, group_id=department, group_role="member"))
    db.commit()
    return types.SimpleNamespace(id=person)


def _department(db):
    department = uuid.uuid4()
    db.execute(sa.insert(Group.__table__).values(id=department, name=f"department-{department.hex[:8]}"))
    db.commit()
    return department


def _stored(db, **values):
    db.execute(sa.delete(SystemSetting.__table__))
    db.execute(sa.insert(SystemSetting.__table__).values(key="global", value=values))
    db.commit()


def _create(db, person, kind):
    """What the server answers a request to make a vault of this kind: the kind, or why it refuses."""
    try:
        return api._resolve_vault_type_for_create(person, kind, db)
    except HTTPException as exc:
        assert exc.status_code == 400, exc
        return exc.detail


def test_a_force_kept_after_the_plan_dropped_zero_knowledge_refuses_no_standard_vault(db, monkeypatch):
    _stored(db, zero_knowledge_enabled=True, force_zero_knowledge=True)
    person = _person(db)
    # While the plan includes zero-knowledge, the administrators' force holds.
    assert api._user_must_use_zk(db, person) is True
    assert [_create(db, person, kind) for kind in KINDS] == [REQUIRED, "zero_knowledge"]
    # The plan loses zero-knowledge, the setting stays saved: standard vaults can be made again.
    monkeypatch.setattr(settings, "plan_zero_knowledge", False)
    assert api._user_must_use_zk(db, person) is False
    assert [_create(db, person, kind) for kind in KINDS] == ["standard", NOT_ENABLED]
    # The plan gets it back: the saved setting holds again, with nothing saved anew.
    monkeypatch.setattr(settings, "plan_zero_knowledge", True)
    assert [_create(db, person, kind) for kind in KINDS] == [REQUIRED, "zero_knowledge"]


def test_a_department_exempted_from_the_force_still_makes_standard_vaults(db):
    exempt = _department(db)
    _stored(db, zero_knowledge_enabled=True, force_zero_knowledge=True,
            standard_vault_allowed_groups=[str(exempt)])
    inside, outside = _person(db, exempt), _person(db)
    assert [_create(db, inside, "standard"), _create(db, outside, "standard")] == ["standard", REQUIRED]


def test_a_plan_that_forces_zero_knowledge_still_forces_it(db, monkeypatch):
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", True)
    _stored(db, zero_knowledge_enabled=False)
    person = _person(db)
    assert [_create(db, person, kind) for kind in KINDS] == [REQUIRED, "zero_knowledge"]


# A saved switch: absent (never saved), saved on, saved off.
SAVED = (None, True, False)


@pytest.mark.parametrize("plan_zk, plan_force, force, enabled",
                         list(itertools.product((True, False), (True, False), SAVED, SAVED)))
def test_no_mix_of_plan_and_saved_settings_leaves_no_vault_to_make(db, monkeypatch, plan_zk, plan_force,
                                                                   force, enabled):
    """Whatever the plan and the saved switches say, someone in no department can make a vault of some kind,
    and someone told to use zero-knowledge can make a zero-knowledge vault."""
    monkeypatch.setattr(settings, "plan_zero_knowledge", plan_zk)
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", plan_force)
    saved = {"force_zero_knowledge": force, "zero_knowledge_enabled": enabled}
    _stored(db, **{key: value for key, value in saved.items() if value is not None})
    person = _person(db)
    made = {kind: _create(db, person, kind) for kind in KINDS}
    assert any(made[kind] == kind for kind in KINDS), made
    if api._user_must_use_zk(db, person):
        assert made["zero_knowledge"] == "zero_knowledge", made
