"""What the pruner keeps for compliance access, offline (app/core/compliance_retention.py).

A positive audit retention deletes no row written under a case while the case is open or one of its holds
stands, nor before COMPLIANCE_RECORD_MIN_DAYS (and the case's own floor) after it closed; rows of the
compliance category are kept that long after they were written. The size cap never deletes them either.
After the floor they follow the audit log's retention like any other row. The rules are registered with
the pruner when it is imported, so every pass reads them. The audit job deletes only rows of sealed hours,
through the audit log's integrity chain, which runs on each test's database.
"""
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_catalog  # noqa: E402
from app.core import audit_retention as ar  # noqa: E402
from app.core import compliance_retention as cr  # noqa: E402
from app.core import retention  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import (AuditArchiveBlock, AuditLog, AuditSeal, ComplianceCase,  # noqa: E402
                             LegalHoldVault, ManagedSetting, ManagedSettingChange, SystemSetting, User)
from _audit_chain_env import Chain  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 20, 12, 0, 0)
PLAIN = "file_upload"


@pytest.fixture
def env(monkeypatch):
    settings = SimpleNamespace(settings_locked_keys="", retention_hold=False, log_prune_interval_minutes=15,
                               log_prune_batch_rows=5000, retention_reduction_delay_days=7,
                               audit_log_retention_days=0, audit_min_retention_days=0, audit_protected_min_days=0,
                               audit_log_max_mb=0, plan_log_max_days=-1, plan_log_max_mb=-1,
                               compliance_record_min_days=2190)
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    monkeypatch.setattr(retention, "_settings", lambda: settings)
    monkeypatch.setattr(retention, "KEEP_RULES", {"audit_logs": [cr.case_rows_kept, cr.compliance_rows_kept]})
    monkeypatch.setattr(retention, "AS_IS_RULES", {"audit_logs": [cr.case_rows_kept]})
    return settings


def _copy(model, metadata):
    columns = []
    for column in model.__table__.columns:
        default = column.server_default
        if default is not None and "now()" in str(getattr(default, "arg", "")):
            default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        elif default is not None:
            default = sa.schema.DefaultClause(default.arg)
        columns.append(sa.Column(column.name, column.type, primary_key=column.primary_key, nullable=column.nullable,
                                 server_default=default))
    sa.Table(model.__tablename__, metadata, *columns)


@pytest.fixture
def factory(monkeypatch):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'audit.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, AuditSeal, AuditArchiveBlock, ManagedSetting, ManagedSettingChange,
                      SystemSetting, ComplianceCase, LegalHoldVault):
            _copy(model, copies)
        copies.create_all(engine)
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        made = []

        def session():
            made.append(make())
            return made[-1]

        monkeypatch.setattr(reg, "_default_session_factory", session)
        yield session
        for s in made:
            s.close()
        engine.dispose()


def _case(db, *, closed_days=None, kept_until_days=None, counts_kept=True):
    """A case, open or closed ``closed_days`` ago; a closed one has its counts kept on it (cases.keep_counts, which
    the compliance cases' job does 30 days after the close) unless ``counts_kept`` is false."""
    closed = None if closed_days is None else NOW - timedelta(days=closed_days)
    case = ComplianceCase(id=uuid.uuid4(), status="closed" if closed_days is not None else "active",
                          purpose="internal_investigation", legal_basis="f", justification_enc="x",
                          owner_note_enc="x", auditor_id=uuid.uuid4(), auditor_username="aud",
                          closed_at=closed,
                          records_kept_until=None if kept_until_days is None else NOW + timedelta(days=kept_until_days),
                          counts_kept_at=closed if counts_kept else None)
    db.add(case)
    db.commit()
    return case.id


def _hold(db, case_id, *, released=False, lapsed=False):
    db.add(LegalHoldVault(case_id=case_id, vault_id=uuid.uuid4(), placed_by_username="aud",
                          placed_at=NOW - timedelta(days=4000),
                          released_at=NOW - timedelta(days=1) if released else None,
                          lapsed_at=NOW - timedelta(days=1) if lapsed else None))
    db.commit()


def _row(db, days, action=PLAIN, case_id=None, size=0):
    row = AuditLog(id=uuid.uuid4(), action=action, status="success", case_id=case_id,
                   timestamp=NOW - timedelta(days=days), details={"pad": "x" * size} if size else None)
    db.add(row)
    db.commit()
    return row.id


def _left(factory, ids):
    return {r.id for r in factory().query(AuditLog.id).filter(AuditLog.id.in_(list(ids))).all()}


_CHAIN = []


@pytest.fixture(autouse=True)
def chain(request, monkeypatch, tmp_path):
    """The audit chain on the test's database, when the test has one."""
    if "factory" not in request.fixturenames:
        yield None
        return
    c = Chain(monkeypatch, tmp_path, request.getfixturevalue("env"), request.getfixturevalue("factory"), NOW)
    _CHAIN.append(c)
    yield c
    _CHAIN.clear()


def _prune(factory, numbers, now=NOW):
    """The audit job with these numbers, once every hour that may be sealed at ``now`` is sealed."""
    _CHAIN[-1].seal_all(now)
    return ar.prune(retention.Pass(factory, now=now), numbers)


def _prune_sized(factory, numbers):
    """The audit job with these numbers once a delay of sealing has run since the rows were sealed: the size cap
    counts an hour's bytes only from then."""
    c = _CHAIN[-1]
    until = NOW + timedelta(days=7, hours=2)
    c.seal_all(NOW)
    while c.clock() + timedelta(hours=6) <= until:
        c.seal_all(c.clock() + timedelta(hours=6))
    c.seal_all(until)
    return ar.prune(retention.Pass(factory, now=until), numbers)


def test_the_rules_are_registered_with_the_pruner_when_it_is_imported():
    """In a process of its own, importing the pruner alone registers both rules."""
    import subprocess
    import sys
    root = Path(__file__).resolve().parent.parent
    script = ("import sys; sys.path.insert(0, 'tests'); from _bare_api_env import set_bare_api_env; "
              "set_bare_api_env(); from app.core import retention; "
              "print(sorted(r.__module__ + '.' + r.__name__ for r in retention.KEEP_RULES['audit_logs']))")
    out = subprocess.run([sys.executable, "-c", script], cwd=root, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-600:]
    assert out.stdout.strip() == ("['app.core.compliance_retention.case_rows_kept', "
                                  "'app.core.compliance_retention.compliance_rows_kept']")
    assert retention.KEEP_MODULES == ("app.core.compliance_retention",)


def test_a_positive_retention_deletes_no_case_row_while_it_must_stay(env, factory):
    db = factory()
    open_case = _case(db)
    closed_recently = _case(db, closed_days=100)
    closed_long_ago = _case(db, closed_days=3000)
    held = _case(db, closed_days=3000)
    _hold(db, held)
    released = _case(db, closed_days=3000)
    _hold(db, released, released=True)
    lapsed = _case(db, closed_days=3000)
    _hold(db, lapsed, lapsed=True)
    own_floor = _case(db, closed_days=3000, kept_until_days=30)
    own_floor_passed = _case(db, closed_days=3000, kept_until_days=-1)
    kept = {
        "plain young": _row(db, 10),
        "open case": _row(db, 4000, case_id=open_case),
        "closed recently": _row(db, 4000, case_id=closed_recently),
        "hold standing": _row(db, 4000, case_id=held),
        "its own floor": _row(db, 4000, case_id=own_floor),
        "unknown case": _row(db, 4000, case_id=uuid.uuid4()),
        "compliance row": _row(db, 400, action="auditor_granted"),
    }
    gone = {
        "plain old": _row(db, 400),
        "closed long ago": _row(db, 4000, case_id=closed_long_ago),
        "hold released": _row(db, 4000, case_id=released),
        "hold lapsed": _row(db, 4000, case_id=lapsed),
        "its own floor passed": _row(db, 4000, case_id=own_floor_passed),
        "compliance row past the floor": _row(db, 2200, action="case_file_viewed"),
    }
    done = _prune(factory, ar.Numbers(30, 0, 0, 0))
    assert done.deleted == len(gone)
    left = _left(factory, list(kept.values()) + list(gone.values()))
    assert {k for k, v in kept.items() if v not in left} == set()
    assert {k for k, v in gone.items() if v in left} == set()


def test_a_closed_cases_rows_stay_past_its_floor_until_its_counts_are_kept_on_it(env, factory):
    """The Compliance page reads a case's counts from its rows until they are kept on the case (cases.keep_counts):
    its rows must not go before."""
    from app.core.models import ComplianceCase
    db = factory()
    not_counted = _case(db, closed_days=3000, counts_kept=False)
    row = _row(db, 4000, case_id=not_counted)
    _prune(factory, ar.Numbers(30, 0, 0, 0))
    assert _left(factory, [row]) == {row}
    db = factory()
    db.query(ComplianceCase).filter(ComplianceCase.id == not_counted).update(
        {ComplianceCase.counts_kept_at: NOW - timedelta(days=2970)}, synchronize_session=False)
    db.commit()
    _prune(factory, ar.Numbers(30, 0, 0, 0))
    assert _left(factory, [row]) == set()


@pytest.mark.parametrize("state", [
    {}, {"closed_days": 100}, {"closed_days": 2190}, {"closed_days": 2191}, {"closed_days": 2191, "counts_kept": False},
    {"closed_days": 2191, "kept_until_days": 5}, {"closed_days": 2191, "kept_until_days": -5},
    {"closed_days": 3000, "kept_until_days": -100}, {"closed_days": 2191, "hold": "standing"},
    {"closed_days": 2191, "hold": "released"}, {"closed_days": 2191, "hold": "lapsed"}])
def test_when_a_cases_rows_stopped_being_kept_is_read_as_the_rule_keeps_them(env, factory, state):
    """The owner's page says when a case's record of the files opened stopped being kept
    (case_rows_released_since): exactly when the rule the pruner and the archive read lets its rows go."""
    state = dict(state)
    hold = state.pop("hold", None)
    db = factory()
    case_id = _case(db, **state)
    if hold:
        _hold(db, case_id, released=hold == "released", lapsed=hold == "lapsed")
    row = _row(db, 3500, case_id=case_id)
    kept = db.query(AuditLog.id).filter(AuditLog.id == row, cr.case_rows_kept(AuditLog, NOW)).first() is not None
    case = db.get(ComplianceCase, case_id)
    since = cr.case_rows_released_since(db, case, NOW)
    assert (since is None) == kept, (state, hold, since)
    if since is not None:
        floor = case.closed_at + timedelta(days=2190)
        assert since == max(floor, case.records_kept_until or floor) < NOW


def test_the_floor_is_read_from_the_settings(env, factory):
    db = factory()
    case = _case(db, closed_days=500)
    row = _row(db, 4000, case_id=case)
    compliance = _row(db, 500, action="hold_placed")
    _prune(factory, ar.Numbers(30, 0, 0, 0))
    assert _left(factory, [row, compliance]) == {row, compliance}
    env.compliance_record_min_days = 400
    _prune(factory, ar.Numbers(30, 0, 0, 0))
    assert _left(factory, [row, compliance]) == set()


def test_the_size_cap_never_deletes_a_row_a_case_keeps(env, factory):
    db = factory()
    case = _case(db)
    quarter = ar.MB // 4 - 200                          # four rows fit in a megabyte
    # The cap keeps the newest rows that fit and cuts what is older. The kept rows lie in what it cuts, among rows
    # that may go: without the rules it would delete them with those.
    newest = [_row(db, d, size=quarter) for d in (30, 31, 32, 33)]
    keep = [_row(db, d, case_id=case, size=quarter) for d in (50, 51, 52)]
    keep.append(_row(db, 53, action="case_approved", size=quarter))
    older = [_row(db, d, size=quarter) for d in (54, 55, 56, 57)]
    _prune_sized(factory, ar.Numbers(0, 0, 0, 1))
    left = _left(factory, newest + keep + older)
    assert set(keep) <= left and set(newest) <= left
    assert not set(older) & left


def test_without_a_maximum_nothing_is_deleted_and_after_the_floor_case_rows_go_like_the_rest(env, factory):
    db = factory()
    case = _case(db, closed_days=3000)
    rows = [_row(db, 4000, case_id=case), _row(db, 4000)]
    _prune(factory, ar.Numbers(0, 0, 0, 0))
    assert _left(factory, rows) == set(rows)
    _prune(factory, ar.Numbers(5000, 0, 0, 0))
    assert _left(factory, rows) == set(rows)
    _prune(factory, ar.Numbers(3999, 0, 0, 0))
    assert _left(factory, rows) == set()


def test_every_compliance_action_is_in_its_own_category():
    names = set(audit_catalog.stored_names(["compliance"]))
    assert ("compliance", "Compliance access") in audit_catalog.CATEGORIES
    for name in ("auditor_grant_proposed", "auditor_granted", "auditor_grant_refused", "auditor_suspended",
                 "case_requested", "case_approved", "case_file_viewed", "case_access_refused", "hold_placed",
                 "held_file_purged", "hold_blocked_delete", "audit_name_revealed", "owner_notice_written",
                 "owner_notice_email_failed", "case_names_viewed", "auditor_events_viewed", "case_access_ended",
                 "owner_notice_seen", "owner_access_unlocked"):
        assert name in names, name
    assert len(names) == 47
