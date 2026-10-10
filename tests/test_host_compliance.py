"""Compliance access from the host, offline on a real database (app/core/host_compliance.py, run inside the web
container by `dockvault.py cases`; app/core/case_eligibility.py).

The server's operator approves an auditor right or a case only while no independent administrator with an
authenticator exists: the host operator has no account the exclusions of the independence rule could apply to,
so an administrator they do apply to decides instead. Each approval is recorded as operator@host, a refusal too.
An auditor right is approved by typing the account's username again, a case by typing its reference again (a
case has no number until it is approved). Revoking is always allowed. downgrade-blockers lists the records of
data an older version cannot read; the host operator answers it too, as `dockvault.py update` asks it.
test_host_compliance_live.py runs the tool on a running stack.
"""
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import admin_grants  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import case_eligibility as ce  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import host_compliance as hc  # noqa: E402
from app.core import host_operator  # noqa: E402
from app.core import independence as ind  # noqa: E402
from app.core.models import (AdminGrant, AuditLog, AuditorGrant, ComplianceCase, ComplianceCasePerson,  # noqa: E402
                             ComplianceCaseVault, CredentialChange, DataRequirement, LegalHoldVault, RoleEnum,
                             SecondFactorEnrollment, User, Vault)
from app.core.security import seal_case_field  # noqa: E402

pytestmark = pytest.mark.unit

OLD = timedelta(days=400)


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'host.db'}")
        copies = sa.MetaData()
        for model in (User, AdminGrant, CredentialChange, AuditLog, AuditorGrant, SecondFactorEnrollment,
                      ComplianceCase, ComplianceCasePerson, ComplianceCaseVault, DataRequirement, LegalHoldVault,
                      Vault):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    told = []
    monkeypatch.setattr(rights, "deliver", lambda notices: told.extend(notices))
    values = {key: cs.current(key) for key in cs.KEYS}
    monkeypatch.setattr(cs, "current", lambda key: values[key])
    monkeypatch.setattr(hc, "CASE_STEPS", {})
    return SimpleNamespace(told=told, settings=values)


def _user(db, name, role=RoleEnum.USER, *, totp=True, created_by=None):
    u = User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
             is_locked=False, created_by=created_by)
    db.add(u)
    db.commit()
    if role == RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=rights.utcnow() - OLD)
    if totp:
        db.add(SecondFactorEnrollment(user_id=u.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()
    return u


def _act(db, *argv):
    """The tool's answer to ``argv``: (answer, exit status)."""
    try:
        hc._act(db, hc.build_parser().parse_args(list(argv)))
    except host_operator._Answer as done:
        return done.obj, done.code
    raise AssertionError("no answer")


def _rows(db, action):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == action).all()


@pytest.fixture
def proposal(db):
    """ada (an administrator with an authenticator) proposed the right for uma."""
    ada, uma = _user(db, "ada", RoleEnum.ADMIN), _user(db, "uma")
    grant = rights.propose(db, uma, proposer=ada)
    db.commit()
    return SimpleNamespace(ada=ada, uma=uma, grant=grant)


# --------------------------------------------------------------------------- the parser

def test_the_tool_offers_every_host_action():
    assert set(hc.ACTIONS) == {"list", "show", "approve", "reject", "confirm-hold", "grant-approve",
                               "revoke-auditor", "downgrade-blockers"}
    args = hc.build_parser().parse_args(["grant-approve", "--grant", "g", "--confirm-username", "uma"])
    assert (args.action, args.grant, args.confirm_username) == ("grant-approve", "g", "uma")
    args = hc.build_parser().parse_args(["reject", "--case", "c", "--confirm-case", "abcd1234", "--reason", "r"])
    assert (args.case, args.confirm_case, args.reason) == ("c", "abcd1234", "r")
    with pytest.raises(SystemExit):
        hc.build_parser().parse_args(["promote"])
    assert "downgrade-blockers" in host_operator.ACTIONS
    assert host_operator.build_parser().parse_args(["downgrade-blockers", "--target", "0.33.2"]).target == "0.33.2"


def test_a_case_is_named_by_its_reference_typed_again():
    case_id = uuid.UUID("3f2a9c1b-0000-4000-8000-000000000001")
    assert hc.reference(case_id) == "3f2a9c1b"
    assert hc.case_confirmation_problem(case_id, "3f2a9c1b") is None
    assert hc.case_confirmation_problem(case_id, " 3F2A9C1B ") is None
    assert "does not match" in hc.case_confirmation_problem(case_id, "3f2a9c1c")
    assert "again" in hc.case_confirmation_problem(case_id, "")
    assert "again" in hc.case_confirmation_problem(case_id, None)


# The case steps the host takes are run by the modules that own them, which register here. Those not written
# yet are listed; writing one fails this test until it leaves the list, which is empty when compliance access
# is complete.
STEPS_TO_COME = set()


def test_each_case_step_is_registered_by_its_module_or_still_to_come(monkeypatch):
    import importlib
    import sys
    monkeypatch.undo()           # the real registry, filled as the app's modules are imported
    importlib.import_module("app.api.api_server")
    registered = set(sys.modules["app.core.host_compliance"].CASE_STEPS)
    assert STEPS_TO_COME <= set(hc.STEP_ACTIONS)
    for action in hc.STEP_ACTIONS:
        if action in STEPS_TO_COME:
            assert action not in registered, f"{action} is registered: take it off STEPS_TO_COME"
        else:
            assert action in registered, f"no module registers the host's {action}"
    with pytest.raises(LookupError):
        hc.register_case_step("promote", lambda *a, **k: None)


# --------------------------------------------------------------------------- an auditor right

def test_the_host_approves_a_right_only_when_no_independent_administrator_exists(db, proposal, quiet):
    bob = _user(db, "bob", RoleEnum.ADMIN)
    answer, code = _act(db, "grant-approve", "--grant", str(proposal.grant.id), "--confirm-username", "uma")
    assert code == 2 and "bob" in answer["error"] and "may not" in answer["error"]
    assert db.get(AuditorGrant, proposal.grant.id).status == "proposed"
    refused = _rows(db, "auditor_grant_refused")[0]
    assert refused.username == cc.HOST_OPERATOR and refused.user_id is None
    assert refused.details["action"] == "grant-approve" and refused.details["reason"] == "independent_admin"
    # bob without an authenticator cannot approve (the approval asks for its code): the host may.
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == bob.id).delete()
    db.commit()
    answer, code = _act(db, "grant-approve", "--grant", str(proposal.grant.id), "--confirm-username", "uma")
    assert code == 0 and answer["granted"]["status"] == "active", answer
    grant = db.get(AuditorGrant, proposal.grant.id)
    assert grant.approved_by is None and grant.approved_by_operator and grant.approved_by_username == cc.HOST_OPERATOR
    assert grant.second_factor_enrollment_id == rights.active_totp(db, proposal.uma.id).id
    row = _rows(db, "auditor_granted")[0]
    assert row.username == cc.HOST_OPERATOR and row.user_id is None
    assert [n["event"] for n in quiet.told][-1] == "granted"


def test_an_administrator_who_is_not_independent_does_not_stop_the_host(db, proposal):
    # The proposer, and an administrator who created the account, may not approve: the host may.
    maker = _user(db, "max", RoleEnum.ADMIN)
    proposal.uma.created_by = maker.id
    db.commit()
    answer, code = _act(db, "grant-approve", "--grant", str(proposal.grant.id), "--confirm-username", "uma")
    assert code == 0, answer


@pytest.mark.parametrize("case", ["username typed wrong", "no username", "lapsed", "access off", "not proposed",
                                  "account unfit", "unknown grant", "not an id"])
def test_what_the_host_refuses_to_approve(db, proposal, quiet, case):
    grant_id, typed = str(proposal.grant.id), "uma"
    if case == "username typed wrong":
        typed = "umaa"
    elif case == "no username":
        typed = None
    elif case == "lapsed":
        proposal.grant.proposed_at = rights.utcnow() - timedelta(days=7, seconds=1)
    elif case == "access off":
        quiet.settings[cs.ACCESS] = cs.DISABLED
    elif case == "not proposed":
        rights.revoke(db, proposal.grant, actor=None)
    elif case == "account unfit":
        proposal.uma.password_set_by_other_at = rights.utcnow()
    elif case == "unknown grant":
        grant_id = str(uuid.uuid4())
    elif case == "not an id":
        grant_id = "not-an-id"
    db.commit()
    argv = ["grant-approve", "--grant", grant_id] + (["--confirm-username", typed] if typed is not None else [])
    answer, code = _act(db, *argv)
    assert code == 2 and answer["ok"] is False, answer
    if case not in ("unknown grant", "not an id"):
        assert db.get(AuditorGrant, proposal.grant.id).status == ("revoked" if case == "not proposed" else "proposed")
    assert not _rows(db, "auditor_granted")


def test_the_host_revokes_a_right(db, proposal, quiet):
    rights.approve(db, proposal.grant, approver=None)
    db.commit()
    answer, code = _act(db, "revoke-auditor", "--username", "uma", "--confirm-username", "um")
    assert code == 2 and db.get(AuditorGrant, proposal.grant.id).status == "active"
    answer, code = _act(db, "revoke-auditor", "--username", "uma", "--confirm-username", "uma", "--reason", "done")
    assert code == 0 and answer["revoked"]["status"] == "revoked"
    grant = db.get(AuditorGrant, proposal.grant.id)
    assert grant.revoked_by is None and grant.revoked_by_username == cc.HOST_OPERATOR
    row = _rows(db, "auditor_revoked")[0]
    assert row.username == cc.HOST_OPERATOR and row.details["by"] == "host operator"
    assert _act(db, "revoke-auditor", "--username", "uma", "--confirm-username", "uma")[1] == 2


def test_the_list_and_show_say_what_the_host_may_approve(db, proposal):
    answer, code = _act(db, "list")
    assert code == 0 and [g["username"] for g in answer["grants"]] == ["uma"]
    assert answer["grants"][0]["host_may_approve"] is True and answer["grants"][0]["independent_approvers"] == []
    bob = _user(db, "bob", RoleEnum.ADMIN)
    answer, _ = _act(db, "show", "--grant", str(proposal.grant.id))
    assert answer["grant"]["host_may_approve"] is False and answer["grant"]["independent_approvers"] == ["bob"]
    assert answer["grant"]["provenance"]["username"] == "uma"
    assert _act(db, "show")[1] == 2
    assert bob


# --------------------------------------------------------------------------- a case

def _case(db, auditor, grant, *, people=()):
    case = ComplianceCase(id=uuid.uuid4(), status="pending", purpose="investigation", legal_basis="legitimate",
                          auditor_id=auditor.id, auditor_username=auditor.username, grant_id=grant.id,
                          justification_enc="", owner_note_enc="")
    case.justification_enc = seal_case_field(case.id, "Suspected leak of the price list", "justification")
    case.owner_note_enc = seal_case_field(case.id, "note", "owner_note")
    db.add(case)
    for person, why in people:
        db.add(ComplianceCasePerson(case_id=case.id, user_id=person.id, why=why))
    db.commit()
    return case


@pytest.fixture
def case_world(db, proposal):
    """uma holds the right (proposed by ada, approved on the host) and asked for a case about owen's vault."""
    rights.approve(db, proposal.grant, approver=None)
    owen = _user(db, "owen")
    db.commit()
    case = _case(db, proposal.uma, proposal.grant, people=[(owen, "owner")])
    return SimpleNamespace(case=case, ada=proposal.ada, uma=proposal.uma, owen=owen, grant=proposal.grant)


@pytest.mark.parametrize("who,expected", [
    ("the auditor", ind.ASKED), ("the grant's proposer", ind.PROPOSED), ("a person concerned", ind.CONCERNED),
    ("the auditor's creator", ind.CREATED_SUBJECT), ("a changer while the grant stood", ind.CHANGED_SUBJECT),
    ("an independent administrator", None)])
def test_who_may_approve_a_case(db, case_world, who, expected):
    w = case_world
    approver = {"the auditor": w.uma, "the grant's proposer": w.ada}.get(who)
    if approver is None:
        approver = _user(db, "zed", RoleEnum.ADMIN)
    if who == "a person concerned":
        db.add(ComplianceCasePerson(case_id=w.case.id, user_id=approver.id, why="named"))
    elif who == "the auditor's creator":
        w.uma.created_by = approver.id
    elif who == "a changer while the grant stood":
        w.grant.credential_changers = [{"id": str(approver.id), "name": "zed", "kind": "email", "at": "x"}]
    if who == "the auditor":
        w.uma.role = RoleEnum.ADMIN
        admin_grants.record(db, w.uma.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                            now=rights.utcnow() - OLD)
    db.commit()
    assert ce.approver_refusal(db, w.case, approver) == expected


def test_a_case_whose_grant_is_gone_has_no_approver(db, case_world):
    zed = _user(db, "zed", RoleEnum.ADMIN)
    case_world.case.grant_id = None
    db.commit()
    assert ce.approver_refusal(db, case_world.case, zed) == ce.NO_GRANT
    assert ce.independent_approvers(db, case_world.case) == []
    assert ce.approver_refusal(db, case_world.case, case_world.owen) == ce.NOT_ABLE


def test_the_host_approves_a_case_only_when_no_independent_administrator_exists(db, case_world, monkeypatch):
    ref = hc.reference(case_world.case.id)
    zed = _user(db, "zed", RoleEnum.ADMIN)
    ran = []
    monkeypatch.setitem(hc.CASE_STEPS, "approve",
                        lambda db_, case, reason=None: ran.append(case.id) or {"id": str(case.id), "status": "active"})
    answer, code = _act(db, "approve", "--case", str(case_world.case.id), "--confirm-case", ref)
    assert code == 2 and "zed" in answer["error"] and ran == []
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == zed.id).delete()
    db.commit()
    assert _act(db, "approve", "--case", str(case_world.case.id), "--confirm-case", "00000000")[1] == 2
    assert ran == []
    answer, code = _act(db, "approve", "--case", str(case_world.case.id), "--confirm-case", ref)
    assert code == 0 and ran == [case_world.case.id] and answer["case"]["status"] == "active"


def test_a_case_step_no_module_registered_is_refused(db, case_world):
    ref = hc.reference(case_world.case.id)
    for action in ("approve", "confirm-hold"):
        answer, code = _act(db, action, "--case", str(case_world.case.id), "--confirm-case", ref)
        assert code == 2 and "not available" in answer["error"]
    answer, code = _act(db, "reject", "--case", str(case_world.case.id), "--confirm-case", ref)
    assert code == 2 and "--reason" in answer["error"]


def test_the_host_sees_the_justification_only_when_it_may_approve(db, case_world):
    answer, code = _act(db, "show", "--case", str(case_world.case.id))
    assert code == 0 and answer["case"]["justification"] == "Suspected leak of the price list"
    assert answer["case"]["reference"] == hc.reference(case_world.case.id)
    _user(db, "zed", RoleEnum.ADMIN)
    answer, _ = _act(db, "show", "--case", str(case_world.case.id))
    assert "justification" not in answer["case"] and answer["case"]["independent_approvers"] == ["zed"]


def test_approving_a_case_is_refused_while_compliance_access_is_off(db, case_world, quiet, monkeypatch):
    monkeypatch.setitem(hc.CASE_STEPS, "approve", lambda *a, **k: {"status": "active"})
    quiet.settings[cs.ACCESS] = cs.DISABLED
    answer, code = _act(db, "approve", "--case", str(case_world.case.id), "--confirm-case",
                        hc.reference(case_world.case.id))
    assert code == 2 and "COMPLIANCE_ACCESS" in answer["error"]


# --------------------------------------------------------------------------- downgrade blockers

def test_downgrade_blockers_lists_the_records_an_older_version_cannot_read(db):
    db.add(DataRequirement(key="holds", requires_at_least="0.34.0", reason="Legal holds keep files",
                           undo="Release the holds"))
    db.commit()
    answer, code = _act(db, "downgrade-blockers", "--target", "v0.33.2")
    assert code == 0 and answer["target"] == "0.33.2"
    assert answer["blockers"] == [{"key": "holds", "requires_at_least": "0.34.0", "reason": "Legal holds keep files",
                                   "undo": "Release the holds"}]
    assert _act(db, "downgrade-blockers", "--target", "0.34.0")[0]["blockers"] == []
    assert _act(db, "downgrade-blockers", "--target", "latest")[1] == 2
    assert _act(db, "downgrade-blockers")[1] == 2


def test_the_host_operator_answers_downgrade_blockers_as_dockvault_update_reads_it(db, monkeypatch):
    import importlib.util
    from contextlib import contextmanager
    from app.core import audit_privacy, database
    db.add(DataRequirement(key="levels", requires_at_least="0.34.0", reason="Recording levels", undo=None))
    db.commit()

    @contextmanager
    def same_db():
        yield db

    monkeypatch.setattr(database, "get_db_context", same_db)
    monkeypatch.setattr(audit_privacy, "require", lambda: None)
    with pytest.raises(host_operator._Answer) as done:
        host_operator._run(host_operator.build_parser().parse_args(["downgrade-blockers", "--target", "0.33.2"]), None)
    spec = importlib.util.spec_from_file_location("dockvault_cases_reader", Path(__file__).resolve().parent.parent
                                                  / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    assert dv.parse_downgrade_blockers(done.value.obj) == [
        {"key": "levels", "requires_at_least": "0.34.0", "reason": "Recording levels", "undo": None}]


def test_the_account_tool_run_as_a_program_refuses_a_bad_version_with_its_own_answer(db, monkeypatch):
    """Run as a program, the account tool is __main__: a refusal raised by another module's copy of it would not
    be the answer its run() catches, and the process would die with a traceback instead of answering."""
    import importlib.util
    from contextlib import contextmanager
    from app.core import audit_privacy, database
    spec = importlib.util.spec_from_file_location("host_operator_as_a_program",
                                                  Path(__file__).resolve().parent.parent / "app" / "core" /
                                                  "host_operator.py")
    program = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(program)

    @contextmanager
    def same_db():
        yield db

    monkeypatch.setattr(database, "get_db_context", same_db)
    monkeypatch.setattr(audit_privacy, "require", lambda: None)
    for target in ("next", None):
        argv = ["downgrade-blockers"] + (["--target", target] if target else [])
        with pytest.raises(program._Answer) as done:
            program._run(program.build_parser().parse_args(argv), None)
        assert done.value.code == 2 and "--target" in done.value.obj["error"]


STOPPED = {"ok": False, "error": "The compliance tool stopped before it could answer."}


class _StartUpExits:
    """An import finder that answers for the web app the way its start-up does when it refuses this
    container's configuration: a message on standard error, then SystemExit(1)."""

    def find_spec(self, name, path=None, target=None):
        if name == "app.api.api_server":
            import sys
            print("DockVault API startup failed [made-up]: refused at db.example.internal", file=sys.stderr)
            raise SystemExit(1)
        return None


WHAT_STOPPED = {"while it imports": "ModuleNotFoundError", "when its start-up exits": "SystemExit",
                "while it works": "RuntimeError"}


@pytest.mark.parametrize("where", list(WHAT_STOPPED))
def test_the_compliance_tool_answers_once_when_something_unexpected_stops_it(monkeypatch, capsys, where):
    # dockvault.py cases reads one JSON object on standard output, as it does from the account tool. Something
    # nothing expected (the database out of reach, say) must not leave it with nothing to read: the answer kept
    # for that case is printed, with exit status 1, and what happened is on standard error, never in the answer.
    import json
    import sys
    if where == "while it imports":
        # Importing the web app is the first thing it does; a module set to None cannot be imported.
        monkeypatch.setitem(sys.modules, "app.api.api_server", None)
    elif where == "when its start-up exits":
        monkeypatch.delitem(sys.modules, "app.api.api_server", raising=False)
        monkeypatch.setattr(sys, "meta_path", [_StartUpExits(), *sys.meta_path])
    else:
        def stops(args):
            raise RuntimeError("the database at db.example.internal is out of reach")
        monkeypatch.setattr(hc, "_run", stops)
    code = hc.run(["list"])
    out, err = capsys.readouterr()
    assert code == 1
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [STOPPED]
    assert "Traceback" in err and WHAT_STOPPED[where] in err
    assert "db.example.internal" not in out
