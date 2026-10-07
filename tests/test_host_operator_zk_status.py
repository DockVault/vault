"""The host command's zk-status action, offline: a deployment's zero-knowledge state in counts and switches,
read without an account or a password and without changing anything.

A managing operator's tooling used to read these facts by signing in as the first administrator and asking
GET /zk-enabled and GET /zk/unsealed. Here they come from the host command run in the container, so no
password is kept for it. Each test runs the whole command (python -m app.core.host_operator zk-status) against
a throwaway database, and reads its answer from standard output as the tooling does.
test_host_operator_zk_status_live.py runs it inside a running stack.
"""
import contextlib
import json
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_privacy  # noqa: E402
from app.core import database  # noqa: E402
from app.core import host_operator  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import (AuditLog, File, Folder, Group, RoleEnum, SystemSetting, User,  # noqa: E402
                             Vault, user_groups)

pytestmark = pytest.mark.unit

KEYS = {"zero_knowledge_enabled", "must_use_zk", "plan_zero_knowledge", "max_zk_vaults", "zk_vault_count",
        "zk_vaults", "files_unsealed", "folders_unsealed", "vaults_affected"}
SWITCHES = {"zero_knowledge_enabled", "must_use_zk", "plan_zero_knowledge"}
TABLES = (User.__table__, Group.__table__, user_groups, Vault.__table__, Folder.__table__, File.__table__,
          SystemSetting.__table__, AuditLog.__table__)

# Names a zero-knowledge vault could leak through a careless summary: none may reach the answer.
NAMES = ("Quarterly-Plan-Owner-Copy.pdf", "Board Minutes 2026", "Payroll Vault Seven", "Legal Hold Archive",
         "owner-one-of-the-vaults", "someone@example.com", "Research Department Nine")


@pytest.fixture
def db(tmp_path, monkeypatch):
    # The route's own run happens on the test helper's thread, so a connection may cross threads.
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'zk-status.db'}", connect_args={"check_same_thread": False})
    # The tables as they are, less the indexes over an expression only Postgres can build.
    metadata = sa.MetaData()
    for table in TABLES:
        copy = table.to_metadata(metadata)
        for index in [i for i in copy.indexes if not all(isinstance(e, sa.Column) for e in i.expressions)]:
            copy.indexes.discard(index)
    metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    @contextlib.contextmanager
    def context():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr(database, "get_db_context", context)
    # The command says it writes a deployment's audit rows; this process is not one, so that is put back.
    monkeypatch.setattr(audit_privacy, "_required", audit_privacy._required)
    for name, value in (("plan_zero_knowledge", True), ("plan_force_zero_knowledge", False),
                        ("plan_max_zk_vaults", -1), ("plan_allowed_vault_types", "")):
        monkeypatch.setattr(settings, name, value)
    session = factory()
    yield session
    session.close()
    engine.dispose()


def _add(db, table, **values):
    """A row written as the table stores it, past the models' own events (a name is stored as given)."""
    if "id" in table.c:
        values.setdefault("id", uuid.uuid4())
    db.execute(sa.insert(table).values(**values))
    db.commit()
    return values.get("id")


def _vault(db, owner, kind, name, active=True):
    return _add(db, Vault.__table__, owner_id=owner, type=kind, name=name, is_active=active)


def _file(db, vault, name, enc_name):
    return _add(db, File.__table__, vault_id=vault, name=name, original_name=name, enc_name=enc_name,
                size_bytes=1, storage_path=f"/storage/{uuid.uuid4()}")


def _folder(db, vault, name, enc_name):
    return _add(db, Folder.__table__, vault_id=vault, name=name, enc_name=enc_name)


def _settings(db, **stored):
    db.execute(sa.delete(SystemSetting.__table__))
    db.execute(sa.insert(SystemSetting.__table__).values(key="global", value=stored))
    db.commit()


def _seed(db):
    """Three zero-knowledge vaults (one of them made inactive) and a standard one. Unsealed in the first
    zero-knowledge vault: one file with no sealed name and one folder with a name that is not a sealed blob.
    In the inactive one: one file with no sealed name. In the third: only a folder with no sealed name.
    Sealed names (v1 and v2) are not counted, nor is a standard vault's name. No account is an
    administrator; the owner is a plain user."""
    owner = _add(db, User.__table__, username=NAMES[4], email=NAMES[5], password_hash="x", role=RoleEnum.USER,
                 is_active=True, is_locked=False)
    zk = _vault(db, owner, "zero_knowledge", NAMES[2])
    gone = _vault(db, owner, "zero_knowledge", NAMES[3], active=False)
    std = _vault(db, owner, "standard", "Standard Vault Name")
    _file(db, zk, NAMES[0], None)
    _file(db, zk, "sealed-v1", "zk1:c2VhbGVk")
    _file(db, zk, "sealed-v2", "zk2:c2VhbGVk")
    _folder(db, zk, NAMES[1], NAMES[1])
    _folder(db, zk, "sealed-folder", "zk2:Zm9sZGVy")
    _file(db, gone, "old-file-name.txt", None)
    folders_only = _vault(db, owner, "zero_knowledge", "Folders Only Vault")
    _folder(db, folders_only, "an unsealed folder name", None)
    _file(db, folders_only, "sealed-file", "zk2:ZmlsZQ==")
    _file(db, std, "standard-file.txt", None)
    _folder(db, std, "standard-folder", None)
    _add(db, Group.__table__, name=NAMES[6])
    return owner


def _zk_status(capsys):
    code = host_operator.run(["zk-status"])
    out, err = capsys.readouterr()
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 1, out              # standard output carries the answer alone
    answer = json.loads(lines[0])
    assert code == 0 and answer["ok"] is True, answer
    return answer, out + err


def _rows(db):
    return {t.name: sorted(map(repr, db.execute(sa.select(t)).all())) for t in TABLES}


def test_it_answers_the_facts_the_tooling_read_as_an_administrator(db, capsys):
    _seed(db)
    answer, _ = _zk_status(capsys)
    assert set(answer) == {"ok", "zero_knowledge"}
    assert answer["zero_knowledge"] == {
        "zero_knowledge_enabled": True, "must_use_zk": False, "plan_zero_knowledge": True, "max_zk_vaults": -1,
        "zk_vault_count": 2,                  # active zero-knowledge vaults: the plan's limit counts these
        "zk_vaults": 3, "files_unsealed": 2, "folders_unsealed": 2, "vaults_affected": 3}


def test_nothing_name_like_or_secret_is_in_the_answer(db, capsys, monkeypatch):
    monkeypatch.setattr(settings, "admin_username", "first-admin-name")
    monkeypatch.setattr(settings, "admin_password", "First-Admin-Pass-Never-Shown-1")
    _seed(db)
    answer, printed = _zk_status(capsys)
    state = answer["zero_knowledge"]
    assert set(state) == KEYS
    # Switches and counts, nothing else: no text at all, so no name can be in it.
    assert all(type(state[k]) is bool for k in SWITCHES)
    assert all(type(state[k]) is int for k in KEYS - SWITCHES)
    for secret in NAMES + ("first-admin-name", "First-Admin-Pass-Never-Shown-1", "zk1:", "zk2:"):
        assert secret not in printed, secret


def test_it_needs_no_account_and_changes_nothing(db, capsys):
    # No user at all, and no administrator: the command reads the database directly.
    assert db.execute(sa.select(sa.func.count()).select_from(User.__table__)).scalar() == 0
    answer, _ = _zk_status(capsys)
    assert answer["zero_knowledge"]["zk_vaults"] == 0 and answer["zero_knowledge"]["files_unsealed"] == 0
    _seed(db)
    before = _rows(db)
    _zk_status(capsys)
    _zk_status(capsys)
    assert _rows(db) == before, "a read changed the database"
    assert before["audit_logs"] == [], "a read wrote an audit row"


def test_the_counts_are_the_administrators_route_counts(db, capsys):
    _seed(db)
    import app.api.api_server as api
    answer, _ = _zk_status(capsys)
    session = sessionmaker(bind=db.get_bind())()
    try:
        route = run_coroutine(api.zk_unsealed_count(current_user=None, db=session))
    finally:
        session.close()
    assert route == {k: answer["zero_knowledge"][k]
                     for k in ("zk_vaults", "files_unsealed", "folders_unsealed", "vaults_affected")}


@pytest.mark.parametrize("plan_zk, plan_force, allowed, stored, enabled, must", [
    (True, False, "", {}, True, False),                                               # the plan's default
    (True, False, "", {"zero_knowledge_enabled": False}, False, False),                # turned off here
    (False, False, "", {"zero_knowledge_enabled": True}, False, False),                # not in the plan
    (True, True, "", {"zero_knowledge_enabled": False}, True, True),                   # the plan forces it
    (True, False, "", {"zero_knowledge_enabled": True, "force_zero_knowledge": True}, True, True),
    (True, False, "", {"zero_knowledge_enabled": False, "force_zero_knowledge": True}, False, False),
    (True, True, "standard", {}, False, False),                                        # not an allowed type
    (True, False, "zero_knowledge", {}, True, False),
])
def test_the_switches_follow_the_plan_the_setting_and_the_allowed_types(
        db, capsys, monkeypatch, plan_zk, plan_force, allowed, stored, enabled, must):
    monkeypatch.setattr(settings, "plan_zero_knowledge", plan_zk)
    monkeypatch.setattr(settings, "plan_force_zero_knowledge", plan_force)
    monkeypatch.setattr(settings, "plan_allowed_vault_types", allowed)
    monkeypatch.setattr(settings, "plan_max_zk_vaults", 3)
    _settings(db, **stored)
    state = _zk_status(capsys)[0]["zero_knowledge"]
    assert (state["zero_knowledge_enabled"], state["must_use_zk"]) == (enabled, must)
    assert (state["plan_zero_knowledge"], state["max_zk_vaults"]) == (plan_zk, 3)


def test_must_use_zk_is_the_rule_for_a_person_in_no_department(db, capsys):
    # Forced, with a department exempted: a person outside it must use zero-knowledge, so the deployment
    # answers True, whoever is in the exempted department (here the only account is).
    owner = _seed(db)
    exempt = db.execute(sa.select(Group.__table__.c.id)).scalar()
    _add(db, user_groups, user_id=owner, group_id=exempt, group_role="member")
    _settings(db, zero_knowledge_enabled=True, force_zero_knowledge=True,
              standard_vault_allowed_groups=[str(exempt)])
    assert _zk_status(capsys)[0]["zero_knowledge"]["must_use_zk"] is True


def test_it_needs_nothing_named_on_the_command_line(db, capsys):
    assert "zk-status" in host_operator.ACTIONS
    args = host_operator.build_parser().parse_args(["zk-status"])
    assert (args.username, args.confirm_username, args.request_id) == (None, None, None)
    # Named anyway, an account changes nothing about the answer.
    _seed(db)
    plain = _zk_status(capsys)[0]
    code = host_operator.run(["zk-status", "--username", "nobody-at-all"])
    assert code == 0 and json.loads(capsys.readouterr().out.strip().splitlines()[-1]) == plain


def test_the_readme_and_the_inventory_say_how_to_run_it_and_what_it_prints():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    inventory = (root / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    assert readme.count("docker exec vault python -m app.core.host_operator zk-status   # vault-api in the split") == 1
    # The section as one line, so a sentence is found wherever the file wraps it.
    flat = " ".join(readme.split())
    said = flat[flat.index("The tool that `dockvault.py accounts` runs in the web container also reads the "
                           "deployment's zero-knowledge state"):]
    said = said[:said.index(" ### ")]
    for claim in ("no account and no password", "for someone in no department", "(`-1` for none)",
                  "never a name, a key or content", "It is not audited"):
        assert claim in said, claim
    assert inventory.count("`python -m app.core.host_operator zk-status`") == 1
