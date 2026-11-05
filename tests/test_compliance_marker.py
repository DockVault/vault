"""The rollback marker of the records of compliance access, offline (app/core/compliance_marker.py).

A release before 0.34.0 knows no cases and deletes every audit row older than a positive AUDIT_LOG_RETENTION_DAYS. So
while a case is open, a case's records must stay, or the record of a step of compliance access taken is younger
than COMPLIANCE_RECORD_MIN_DAYS, a row in data_requirements stops such a release from starting (0.33.1 and later),
and dockvault.py update refuses to go back unless forced. Every audit row of such a step writes the marker in its own
transaction; a refusal, which any account can cause, and a vault owner's own steps on Access to my vaults do not.
sync() removes it once nothing needs it, at the start and at each pass of the pruner's compliance_cases job.
test_compliance_marker_live.py checks on Postgres that sync() never removes it while a transaction that wrote such a
row is still open.
"""
import importlib.util
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import _release_conditions as rc  # noqa: E402
from app.core import compliance_marker as marker  # noqa: E402
from app.core import recording_marker  # noqa: E402
from app.core import retention  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import AuditLog, ComplianceCase  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 5, 12, 0, 0)
FLOOR = 400


@pytest.fixture
def db(monkeypatch):
    from _kept_db import kept_database
    settings = SimpleNamespace(settings_locked_keys="", compliance_record_min_days=FLOOR)
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    monkeypatch.setattr(recording_marker, "running_version", lambda: "0.34.0")
    with kept_database() as (make, _engine):
        made = []

        def session():
            made.append(make())
            return made[-1]

        monkeypatch.setattr(reg, "_default_session_factory", session)
        s = session()
        s.factory = session
        yield s
        for one in made:
            one.close()


def _rows(db):
    return db.execute(text("SELECT key, requires_at_least, reason, undo FROM data_requirements")).fetchall()


def _case(db, *, closed_days=None, kept_until_days=None, counts_kept=True):
    closed = None if closed_days is None else NOW - timedelta(days=closed_days)
    db.add(ComplianceCase(id=uuid.uuid4(), status="closed" if closed is not None else "active",
                          purpose="internal_investigation", legal_basis="f", justification_enc="x",
                          owner_note_enc="x", auditor_id=uuid.uuid4(), auditor_username="aud", closed_at=closed,
                          records_kept_until=None if kept_until_days is None else NOW + timedelta(days=kept_until_days),
                          counts_kept_at=closed if counts_kept else None))
    db.commit()


def _row(db, days, action="auditor_granted", status="success"):
    db.add(AuditLog(id=uuid.uuid4(), action=action, status=status, timestamp=NOW - timedelta(days=days)))
    db.commit()


def _matrix_module():
    spec = importlib.util.spec_from_file_location("upgrade_matrix_for_compliance",
                                                  ROOT / ".github" / "scripts" / "upgrade_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("released", [False, True], ids=["now", "at-the-release"])
def test_the_condition_is_the_one_kept_for_the_release_and_one_the_matrix_takes(released):
    """Added to the newest edge below 0.34.0, which carries none of 0.34.0's conditions, whether or not the matrix
    declares 0.34.0 already (it does from the release commit on)."""
    um = _matrix_module()
    data = json.loads((ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8"))
    data = rc.before_the_release(rc.with_the_release(data) if released else data)
    edge = data["edges"][-1]
    assert marker.CONDITION["id"] not in {c["id"] for c in edge.get("conditions", [])}
    edge.setdefault("conditions", []).append(dict(marker.CONDITION))
    um.validate_matrix(data, released_ceiling=None)
    cid = marker.CONDITION["id"]
    assert marker.CONDITION["blocks_rollback"] is True and cid in rc.BLOCKS_ROLLBACK and cid in rc.ON_UPGRADED
    assert rc.DETECT[cid] == marker.CONDITION["detect"] and rc.SUMMARY[cid] == marker.CONDITION["summary"]
    assert f"FROM data_requirements WHERE key = '{marker.KEY}'" in marker.CONDITION["detect"]


@pytest.mark.parametrize("state", [
    dict(case=dict()),                                                  # open
    dict(case=dict(closed_days=10)),                                    # closed, within the floor
    dict(case=dict(closed_days=FLOOR + 5, counts_kept=False)),          # its counts not yet kept on it
    dict(case=dict(closed_days=FLOOR + 5, kept_until_days=30)),         # its own floor, set at approval, ahead
    dict(row=1),                                                        # a compliance row of yesterday
    dict(row=FLOOR - 1),                                                # one a day inside the floor
])
def test_the_marker_is_there_while_a_case_is_open_or_its_records_or_a_compliance_row_must_be_kept(db, state):
    if "case" in state:
        _case(db, **state["case"])
    if "row" in state:
        _row(db, state["row"])
    assert marker.sync(db, now=NOW) is True
    ((key, needs, reason, undo),) = _rows(db)
    assert (key, needs) == ("compliance-records", "0.34.0")
    assert "while AUDIT_LOG_RETENTION_DAYS is positive it deletes every audit row older than that" in reason
    assert undo.startswith("Wait until no compliance case is open") and undo.endswith(
        "Then start DockVault 0.34.0 or later once so it removes this marker.")
    db.commit()
    assert marker.sync(db, now=NOW) is True and len(_rows(db)) == 1, "written once, then kept"


@pytest.mark.parametrize("state", [
    dict(),
    dict(case=dict(closed_days=FLOOR + 5, kept_until_days=-1)),         # closed and released
    dict(row=FLOOR + 1),                                                # a compliance row past the floor
    dict(row=1, action="file_uploaded"),                                # a young row of another category
])
def test_no_marker_when_nothing_must_be_kept(db, state):
    if "case" in state:
        _case(db, **state["case"])
    if "row" in state:
        _row(db, state["row"], action=state.get("action", "auditor_granted"))
    assert marker.sync(db, now=NOW) is False and _rows(db) == []


# A refused step, which any signed-in account can cause, and a vault owner's own steps on Access to my vaults.
NOT_COUNTED = [
    ("case_access_refused", "failure"),     # a read of a case that does not exist
    ("hold_placed", "failure"),             # a hold its account may not place
    ("auditor_grant_refused", "failure"),
    ("audit_name_revealed", "failure"),
    ("case_requested", "error"),
    ("owner_access_unlocked", "success"),   # an owner shows their own vault's names on their page
    ("owner_access_unlocked", "failure"),   # with a wrong vault password
    ("owner_notice_seen", "success"),       # an owner reads their notices
]


@pytest.mark.parametrize("action, status", NOT_COUNTED)
def test_a_refused_step_or_a_vault_owners_own_writes_and_keeps_no_marker(db, action, status):
    """Neither may stop every rollback for COMPLIANCE_RECORD_MIN_DAYS on a deployment that never used compliance
    access. The row is written all the same, and the pruner keeps it as long as any row of the category."""
    from app.core import compliance_retention as cr
    row = AuditLogger(db).build_row(action=action, status=status, username="someone")
    db.add(row)
    db.commit()
    assert db.get(AuditLog, row.id) is not None and _rows(db) == [], "its transaction wrote no marker"
    _row(db, 1, action=action, status=status)
    assert db.query(AuditLog).filter(cr.compliance_rows_kept(AuditLog, NOW)).count() == 2, "kept all the same"
    assert marker.kept_now(db, NOW) is False and marker.sync(db, now=NOW) is False and _rows(db) == []


def test_an_ordinary_accounts_refused_case_read_and_hold_record_their_refusals_and_no_marker(db):
    """Through the code that records them: a signed-in account with no right asks for a case that does not exist and
    tries to place a legal hold."""
    from app.core import case_access, legal_holds
    from app.core.models import RoleEnum, User
    user = User(id=uuid.uuid4(), username="plain", email="plain@example.com", password_hash="x", role=RoleEnum.USER,
                is_active=True)
    db.add(user)
    db.commit()
    case_access.record_refused(db, uuid.uuid4(), user, case_access.Refused(case_access.NO_CASE))
    legal_holds.record_refusal(db, "hold_placed", None, actor=user, reason=legal_holds.NOT_ALLOWED)
    rows = db.query(AuditLog.action, AuditLog.status).filter(AuditLog.user_id == user.id).all()
    assert sorted(rows) == [("case_access_refused", "failure"), ("hold_placed", "failure")]
    assert _rows(db) == [] and marker.sync(db, now=NOW) is False


def test_every_step_of_the_category_taken_counts_but_a_vault_owners_own(db):
    """counts() (the row's own transaction) and counted_rows() (sync) take the same rows: every action of the
    compliance category taken (status success) but OWN_STEPS; no refusal, no row of another category."""
    from app.core import audit_catalog
    actions = list(audit_catalog.stored_names(["compliance"]))
    assert marker.OWN_STEPS == {"owner_access_unlocked", "owner_notice_seen"} and marker.OWN_STEPS < set(actions)
    statuses = ("success", "failure", "error")
    for action in actions:
        assert marker.counts(action, "success") is (action not in marker.OWN_STEPS), action
        assert not marker.counts(action, "failure") and not marker.counts(action, "error"), action
    assert not marker.counts("file_uploaded", "success") and not marker.counts(None, "success")
    for action in actions + ["file_uploaded"]:
        for status in statuses:
            db.add(AuditLog(id=uuid.uuid4(), action=action, status=status, timestamp=NOW - timedelta(days=1)))
    db.add(AuditLog(id=uuid.uuid4(), action="auditor_granted", status="success",
                    timestamp=NOW - timedelta(days=FLOOR + 1)))
    db.commit()
    found = set(db.query(AuditLog.action, AuditLog.status).filter(marker.counted_rows(AuditLog, NOW)).all())
    assert found == {(a, st) for a in actions + ["file_uploaded"] for st in statuses if marker.counts(a, st)}
    assert len(found) == len(actions) - len(marker.OWN_STEPS)


def test_the_undo_holds_with_no_case_and_names_only_what_the_host_tool_can_do():
    """The marker stands without any case (an auditor right's steps, a name revealed): the undo asks to wait, and
    closes a case only where one is open. From the host a case can only be turned down while it waits for approval:
    dockvault.py cases neither closes one nor releases a hold."""
    from app.core import case_rules, host_compliance
    undo = marker.UNDO.format(version="0.34.0")
    assert undo.startswith("Wait until no compliance case is open and the records of compliance access are older "
                           "than COMPLIANCE_RECORD_MIN_DAYS")
    assert "dockvault.py cases can only turn down one not yet approved" in undo
    assert not any(a.startswith(("close", "release")) for a in host_compliance.ACTIONS)
    assert "reject" in host_compliance.STEP_ACTIONS
    assert [old for (old, step) in case_rules.TRANSITIONS if step == case_rules.REJECT] == [case_rules.PENDING]
    tool = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    actions = tool.split("\nCASE_ACTIONS = (", 1)[1].split("\n)\n", 1)[0]
    assert '("reject", "Turn a case down")' in actions
    assert '("close' not in actions and '("release' not in actions


def test_the_marker_goes_once_its_records_may_go(db):
    _row(db, FLOOR - 1)
    assert marker.sync(db, now=NOW) is True
    db.commit()
    assert marker.sync(db, now=NOW + timedelta(days=2)) is False and _rows(db) == []


def test_a_compliance_row_writes_the_marker_in_the_transaction_that_writes_the_row(db):
    db.add(AuditLogger(db).build_row(action="case_requested", status="success", username="aud"))
    assert [r[0] for r in _rows(db)] == ["compliance-records"]
    db.rollback()
    assert _rows(db) == [], "rolled back with the row"
    db.add(AuditLogger(db).build_row(action="file_uploaded", status="success", username="aud"))
    assert _rows(db) == [], "a row of another category writes nothing"
    db.rollback()
    AuditLogger(db).log_action(action="auditor_granted", status="success", username="admin")
    other = db.factory()
    assert [r[0] for r in _rows(other)] == ["compliance-records"]


def test_a_failure_to_write_the_marker_never_fails_the_change(db, monkeypatch, capsys):
    def broken(_when):
        raise RuntimeError("no version")
    monkeypatch.setattr(marker, "_params", broken)
    row = AuditLogger(db).build_row(action="case_requested", status="success", username="aud")
    db.add(row)
    db.commit()
    assert db.get(AuditLog, row.id) is not None
    assert "the compliance records' rollback marker was not written (RuntimeError)" in capsys.readouterr().out


def test_the_pruners_compliance_cases_job_brings_the_marker_in_line(db):
    _row(db, FLOOR - 1)
    retention.run_compliance_cases(retention.Pass(db.factory, now=NOW))
    assert [r[0] for r in _rows(db.factory())] == ["compliance-records"]
    retention.run_compliance_cases(retention.Pass(db.factory, now=NOW + timedelta(days=2)))
    assert _rows(db.factory()) == []


def test_the_start_checks_the_marker():
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = source.split("\ndef _run_lightweight_migrations(", 1)[1].split("\ndef ", 1)[0]
    lines = [ln.strip() for ln in body.splitlines()]
    assert lines.count("compliance_marker.check_at_start()") == 1


def test_the_host_action_names_the_records_to_an_older_target_only(db):
    from app.core import host_compliance
    _case(db)
    marker.sync(db, now=NOW)
    db.commit()
    (blocker,) = host_compliance.downgrade_blockers(db, "0.33.6")
    assert blocker["key"] == "compliance-records" and blocker["requires_at_least"] == "0.34.0"
    assert host_compliance.downgrade_blockers(db, "0.34.0") == []


def test_dockvault_refuses_to_go_back_over_the_records_unless_forced(db, monkeypatch, tmp_path, capsys):
    from app.core import host_compliance
    from test_data_requirements import _Deployment, _answers
    _case(db)
    marker.sync(db, now=NOW)
    db.commit()
    blockers = host_compliance.downgrade_blockers(db, "0.33.6")
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers(blockers))
    with pytest.raises(SystemExit):
        deployment.update("v0.33.6")
    out = capsys.readouterr().out
    assert "Compliance cases are open" in out and "Wait until no compliance case is open" in out
    assert deployment.image() == deployment.dv.LOCAL_IMAGE, "it did not go back"
    deployment.update("v0.33.6", force_downgrade=True)
    assert deployment.image().endswith(":v0.33.6")
