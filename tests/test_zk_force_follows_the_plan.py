"""The administrators' "force zero-knowledge" setting, offline, against the deployment's plan.

The setting holds only where the plan lets zero-knowledge vaults be made at all. Saved while the plan
included zero-knowledge and kept after the plan dropped it, it used to refuse a standard vault (zero-knowledge
is required) while a zero-knowledge vault was refused as not enabled, so nobody outside an exempted department
could make any vault. The same holds for the plan's other settings (its cap on zero-knowledge vaults and the
allowed vault types) mixed with the two saved switches: no mix leaves nobody a vault to make
(app/core/zero_knowledge_rules.py has the rules). Each test asks the server's own create check
(_resolve_vault_type_for_create) and rules (_user_must_use_zk, _zk_enabled) against a throwaway database.
test_host_operator_zk_status_live.py asks them inside a running stack; test_zero_knowledge_settings_save.py
covers what a settings save may change.
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


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    engine = sa.create_engine(f"sqlite:///{tmp_path_factory.mktemp('zk-force') / 'zk-force.db'}")
    # The tables as they are, less the indexes over an expression only Postgres can build.
    metadata = sa.MetaData()
    for table in TABLES:
        copy = table.to_metadata(metadata)
        for index in [i for i in copy.indexes if not all(isinstance(e, sa.Column) for e in i.expressions)]:
            copy.indexes.discard(index)
    metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine, monkeypatch):
    for name, value in (("plan_zero_knowledge", True), ("plan_force_zero_knowledge", False),
                        ("plan_max_zk_vaults", -1), ("plan_allowed_vault_types", "")):
        monkeypatch.setattr(settings, name, value)
    session = sessionmaker(bind=engine)()
    for table in reversed(TABLES):        # each test starts from empty tables
        session.execute(sa.delete(table))
    session.commit()
    yield session
    session.close()


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
# The plan's cap on zero-knowledge vaults: none, 0 (the plan has none), and one with room.
CAPS = (-1, 0, 2)
# The operator's allowed types: every type (empty), each one alone, and both named.
ALLOWED = ("", "standard", "zero_knowledge", "standard,zero_knowledge")


@pytest.mark.parametrize("plan_zk, plan_force, cap, allowed, force, enabled",
                         list(itertools.product((True, False), (True, False), CAPS, ALLOWED, SAVED, SAVED)))
def test_no_mix_of_zero_knowledge_settings_leaves_no_vault_to_make(db, monkeypatch, plan_zk, plan_force, cap,
                                                                    allowed, force, enabled):
    """No mix of the plan's zero-knowledge settings (whether it has zero-knowledge, forces it, its cap on
    zero-knowledge vaults, the allowed vault types) and the two saved switches leaves someone in no department
    without a vault to make; someone told to use zero-knowledge can make a zero-knowledge vault; and what the
    vault form is told (/zk-enabled's zero_knowledge_enabled) is whether one can be made. A cap with room is
    used here: a cap that is reached is a quota, refused with its own message."""
    for name, value in (("plan_zero_knowledge", plan_zk), ("plan_force_zero_knowledge", plan_force),
                        ("plan_max_zk_vaults", cap), ("plan_allowed_vault_types", allowed)):
        monkeypatch.setattr(settings, name, value)
    saved = {"force_zero_knowledge": force, "zero_knowledge_enabled": enabled}
    _stored(db, **{key: value for key, value in saved.items() if value is not None})
    person = _person(db)
    made = {kind: _create(db, person, kind) for kind in KINDS}
    assert any(made[kind] == kind for kind in KINDS), made
    zk_allowed = "zero_knowledge" in api._allowed_vault_types()
    if zk_allowed and api._user_must_use_zk(db, person):
        assert made["zero_knowledge"] == "zero_knowledge", made
    assert (api._zk_enabled(db) and zk_allowed) == (made["zero_knowledge"] == "zero_knowledge"), made


def test_a_cap_of_none_is_a_plan_without_zero_knowledge(db, monkeypatch):
    """PLAN_MAX_ZK_VAULTS=0 with the administrators' force saved: zero-knowledge used to read as enabled while
    none could be made, and standard vaults were refused. A cap of 0 now counts as no zero-knowledge, for the
    force (the plan's and the administrators') and for what the vault form is told."""
    monkeypatch.setattr(settings, "plan_max_zk_vaults", 0)
    _stored(db, zero_knowledge_enabled=True, force_zero_knowledge=True)
    person = _person(db)
    assert api._zk_enabled(db) is False and api._user_must_use_zk(db, person) is False
    assert [_create(db, person, kind) for kind in KINDS] == ["standard", NOT_ENABLED]
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", True)
    assert api._user_must_use_zk(db, person) is False
    assert _create(db, person, "standard") == "standard"


def test_an_administrators_off_switch_does_not_apply_where_only_zero_knowledge_is_allowed(db, monkeypatch):
    """PLAN_ALLOWED_VAULT_TYPES=zero_knowledge on a plan with zero-knowledge, and zero-knowledge saved off (saved
    before the operator changed the allowed types): standard vaults are not permitted, so the off switch
    would leave nothing to make. It does not apply; zero-knowledge vaults can be made."""
    monkeypatch.setattr(settings, "plan_allowed_vault_types", "zero_knowledge")
    _stored(db, zero_knowledge_enabled=False)
    person = _person(db)
    assert [_create(db, person, kind) for kind in KINDS] == [
        "Vault type 'standard' is not permitted on this deployment.", "zero_knowledge"]


def test_only_zero_knowledge_allowed_on_a_plan_without_it_allows_every_type(db, monkeypatch):
    """The operator's list keeps its promise: naming only a type the plan does not offer stops nothing."""
    monkeypatch.setattr(settings, "plan_allowed_vault_types", "zero_knowledge")
    person = _person(db)
    for name, value in (("plan_zero_knowledge", False), ("plan_max_zk_vaults", 0)):
        monkeypatch.setattr(settings, "plan_zero_knowledge", True)
        monkeypatch.setattr(settings, "plan_max_zk_vaults", -1)
        monkeypatch.setattr(settings, name, value)
        assert api._allowed_vault_types() == {"standard", "zero_knowledge"}
        assert [_create(db, person, kind) for kind in KINDS] == ["standard", NOT_ENABLED]


def test_a_force_saved_with_the_switch_never_saved_holds(db):
    """Never saved, the zero-knowledge switch counts as on (the plan's zero-knowledge is on by itself), so a
    force saved alone holds as it would with the switch saved on."""
    _stored(db, force_zero_knowledge=True)
    person = _person(db)
    assert api._zk_enabled(db) is True and api._user_must_use_zk(db, person) is True
    assert [_create(db, person, kind) for kind in KINDS] == [REQUIRED, "zero_knowledge"]
