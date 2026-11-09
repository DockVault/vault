"""How long audit rows are kept: the three numbers (app/core/audit_retention.py), offline.

The maximum deletes rows older than it; the protected minimum keeps every row younger than it; the
administration and security rows are kept at least AUDIT_PROTECTED_MIN_DAYS (365 by default), lowerable
only in .env; the size cap deletes the oldest rows that do not fit, never an administration or security row,
nor one younger than the reduction delay, and tells the administrators once a day when the protected rows
alone do not fit. .env ceilings forbid "for ever" and "off"; the startup contract refuses numbers that
contradict each other. The preview says what the job deletes, by the same conditions. After an upgrade, a
positive AUDIT_LOG_RETENTION_DAYS waits like any change that deletes sooner. These run on a throwaway SQLite
database, with the audit log's integrity chain running on it: the audit job deletes only rows of sealed
hours, through the chain, and acts on the chain's state.
"""
import inspect
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

from app.api import managed_settings_router as routes  # noqa: E402
from app.core import audit_retention as ar  # noqa: E402
from app.core import retention  # noqa: E402
from app.core import setting_changes as sc  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import (AuditArchiveBlock, AuditLog, AuditSeal, ManagedSetting,  # noqa: E402
                             ManagedSettingChange, RoleEnum, SystemSetting, User)
from _audit_chain_env import Chain  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 20, 12, 0, 0)
ADMIN_ACTION = "settings_updated"        # an administration row
SECURITY_ACTION = "access_denied"        # a security row
PLAIN = "file_upload"


def _settings(**kw):
    base = dict(settings_locked_keys="", retention_hold=False, log_prune_interval_minutes=15,
                log_prune_batch_rows=5000, retention_reduction_delay_days=7, audit_log_retention_days=0,
                audit_min_retention_days=0, audit_protected_min_days=365, audit_log_max_mb=0,
                plan_log_max_days=-1, plan_log_max_mb=-1, security_alert_retention_days=90,
                jwt_access_token_expire_minutes=60)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    settings = _settings()
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    monkeypatch.setattr(retention, "_settings", lambda: settings)
    monkeypatch.setattr(retention, "KEEP_RULES", {})
    monkeypatch.setattr(sc, "announce", lambda *a, **k: None)
    return settings


@pytest.fixture
def factory(monkeypatch):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'audit.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, AuditSeal, AuditArchiveBlock, ManagedSetting, ManagedSettingChange,
                      SystemSetting):
            columns = []
            for column in model.__table__.columns:
                default = column.server_default
                if default is not None and "now()" in str(getattr(default, "arg", "")):
                    default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
                elif default is not None:
                    default = sa.schema.DefaultClause(default.arg)
                columns.append(sa.Column(column.name, column.type, primary_key=column.primary_key,
                                         nullable=column.nullable, server_default=default))
            sa.Table(model.__tablename__, copies, *columns)
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


def _row(db, days, action=PLAIN, size=0, hours=0):
    row = AuditLog(id=uuid.uuid4(), action=action, status="success",
                   timestamp=NOW - timedelta(days=days, hours=hours), details={"pad": "x" * size} if size else None)
    db.add(row)
    db.commit()
    return row.id


def _left(factory):
    """The seeded rows still there (not the rows the pruner and the settings changes write themselves)."""
    return {r.id for r in factory().query(AuditLog.id).filter(
        AuditLog.action.in_((PLAIN, ADMIN_ACTION, SECURITY_ACTION))).all()}


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


def _run(factory, now=NOW):
    """A pass of the pruner at ``now`` (the chain's clock too)."""
    _CHAIN[-1].at(now)
    return retention.run_pass(factory, now=now)


def _prune(factory, numbers, now=NOW):
    """The audit job with these numbers, once every hour that may be sealed at ``now`` is sealed."""
    _CHAIN[-1].seal_all(now)
    return ar.prune(retention.Pass(factory, now=now), numbers)


# The size cap counts an hour's bytes only once a delay of sealing has passed since its seal: the rows seeded
# at NOW are sealed then, and count from a week on.
AFTER_DELAY = NOW + timedelta(days=7, hours=2)


def _age_chain(until):
    """Sealing runs every six hours (no gap) until ``until``."""
    c = _CHAIN[-1]
    c.seal_all(c.clock())
    for _ in range(3):                       # hourly at first: the newest hours are sealed as they close
        if c.clock() + timedelta(hours=1) <= until:
            c.seal_all(c.clock() + timedelta(hours=1))
    while c.clock() + timedelta(hours=6) <= until:
        c.seal_all(c.clock() + timedelta(hours=6))
    c.seal_all(until)


def _prune_sized(factory, numbers, now=AFTER_DELAY):
    """The audit job with these numbers once a delay of sealing has run since the seeded rows were sealed."""
    _age_chain(now)
    return ar.prune(retention.Pass(factory, now=now), numbers)


def _numbers(max_days=0, min_days=0, admin_min_days=365, max_mb=0):
    return ar.Numbers(max_days, min_days, admin_min_days, max_mb)


# --------------------------------------------------------------------------- the settings

def test_the_three_numbers_are_managed_settings_whose_lowering_waits(env):
    expected = {
        ar.MAX_DAYS: (0, "audit_log_retention_days", None, "plan_log_max_days", 0, "days"),
        ar.MIN_DAYS: (0, "audit_min_retention_days", "audit_min_retention_days", None, None, "days"),
        ar.ADMIN_MIN_DAYS: (365, "audit_protected_min_days", "audit_protected_min_days", None, None, "days"),
        ar.MAX_MB: (0, "audit_log_max_mb", None, "plan_log_max_mb", 0, "MB"),
    }
    for key, (default, env_name, floor, ceiling, unlimited, unit) in expected.items():
        spec = reg.spec_for(key)
        assert (spec.default, spec.env, spec.floor, spec.ceiling, spec.unlimited, spec.unit) == (
            default, env_name, floor, ceiling, unlimited, unit), key
        assert (spec.editable, spec.reduction, spec.group) == (reg.ADMIN, reg.LOWER, ar.GROUP), key
    assert ar.current() == _numbers()


def test_the_protected_minimum_for_administration_rows_is_lowered_only_in_env(env):
    spec = reg.spec_for(ar.ADMIN_MIN_DAYS)
    assert reg.check_bounds(spec, 364) == ("audit_admin_min_days cannot be 364 days: the deployment keeps it at "
                                          "least 365 days (AUDIT_PROTECTED_MIN_DAYS in .env)")
    assert reg.check_bounds(spec, 400) is None
    env.audit_protected_min_days = 30
    assert reg.resolve(ar.ADMIN_MIN_DAYS) == 30 and reg.check_bounds(spec, 30) is None


def test_a_ceiling_forbids_for_ever_and_off(env):
    env.plan_log_max_days, env.plan_log_max_mb = 180, 500
    assert reg.resolve(ar.MAX_DAYS) == 180 and reg.resolve(ar.MAX_MB) == 500     # the deployment's 0, clamped
    max_days, max_mb = reg.spec_for(ar.MAX_DAYS), reg.spec_for(ar.MAX_MB)
    assert "cannot be no limit" in reg.check_bounds(max_days, 0)
    assert "cannot be 200 days" in reg.check_bounds(max_days, 200)
    assert reg.check_bounds(max_days, 90) is None
    assert "cannot be no limit" in reg.check_bounds(max_mb, 0)
    env.plan_log_max_days = env.plan_log_max_mb = -1                  # -1: no ceiling
    assert reg.check_bounds(max_days, 0) is None and reg.resolve(ar.MAX_DAYS) == 0
    assert reg.check_contract() == []


@pytest.mark.parametrize("given,why", [
    (dict(plan_log_max_days=180), "AUDIT_PROTECTED_MIN_DAYS (365) is longer than PLAN_LOG_MAX_DAYS (180)"),
    (dict(plan_log_max_days=180, audit_protected_min_days=90, audit_min_retention_days=200),
     "AUDIT_MIN_RETENTION_DAYS (200) is longer than PLAN_LOG_MAX_DAYS (180)"),
    (dict(audit_log_retention_days=30, audit_min_retention_days=60),
     "AUDIT_LOG_RETENTION_DAYS (30) is shorter than AUDIT_MIN_RETENTION_DAYS (60)"),
])
def test_the_start_is_refused_when_the_numbers_contradict_each_other(env, factory, monkeypatch, given, why):
    for name, value in given.items():
        setattr(env, name, value)
    problems = reg.check_contract()
    assert any(p.startswith(why) for p in problems), problems
    monkeypatch.setattr(reg, "_refresher", None)
    with pytest.raises(reg.SettingsContractError, match=why.replace("(", r"\(").replace(")", r"\)")):
        reg.start(session_factory=factory, interval=10)


@pytest.mark.parametrize("given", [
    dict(), dict(plan_log_max_days=400), dict(plan_log_max_days=180, audit_protected_min_days=180),
    dict(audit_log_retention_days=90, audit_min_retention_days=90), dict(audit_log_retention_days=0,
                                                                         audit_min_retention_days=60),
])
def test_numbers_that_agree_start(env, given):
    for name, value in given.items():
        setattr(env, name, value)
    assert reg.check_contract() == []


@pytest.mark.parametrize("key,value,stored,why", [
    (ar.MAX_DAYS, 30, {ar.MIN_DAYS: 60}, "cannot be kept at most 30 days while every row is kept at least 60 days"),
    (ar.MIN_DAYS, 60, {ar.MAX_DAYS: 30}, "cannot be kept at most 30 days while every row is kept at least 60 days"),
    (ar.MAX_DAYS, 60, {ar.MIN_DAYS: 60}, None),
    (ar.MIN_DAYS, 400, {ar.MAX_DAYS: 0}, None),
    (ar.MAX_DAYS, None, {ar.MIN_DAYS: 60}, None),       # back to the deployment's for ever
    (ar.ADMIN_MIN_DAYS, 800, {ar.MAX_DAYS: 30}, None),  # the category minimum outlasts the maximum by design
])
def test_the_panel_refuses_a_maximum_shorter_than_the_minimum_for_every_row(env, key, value, stored, why):
    reg._cache.rows = {k: (v, n) for n, (k, v) in enumerate(stored.items(), 1)}
    assert ar.cross_check in sc.CROSS_CHECKS
    found = routes.refusal(reg.spec_for(key), value)
    assert (found is None) if why is None else (why in found), found


# --------------------------------------------------------------------------- by age

def _seed_ages(factory):
    db = factory()
    return {
        "plain_10": _row(db, 10), "plain_100": _row(db, 100), "plain_400": _row(db, 400),
        "admin_100": _row(db, 100, ADMIN_ACTION), "admin_400": _row(db, 400, ADMIN_ACTION),
        "security_300": _row(db, 300, SECURITY_ACTION), "security_800": _row(db, 800, SECURITY_ACTION),
    }


@pytest.mark.parametrize("numbers,kept", [
    (_numbers(), {"plain_10", "plain_100", "plain_400", "admin_100", "admin_400", "security_300", "security_800"}),
    (_numbers(max_days=30), {"plain_10", "admin_100", "security_300"}),
    (_numbers(max_days=7), {"admin_100", "security_300"}),
    (_numbers(max_days=30, min_days=200), {"plain_10", "plain_100", "admin_100", "security_300"}),
    (_numbers(max_days=30, admin_min_days=0), {"plain_10"}),
    (_numbers(max_days=30, admin_min_days=900), {"plain_10", "admin_100", "admin_400", "security_300", "security_800"}),
    (_numbers(max_days=500, admin_min_days=0), {"plain_10", "plain_100", "plain_400", "admin_100", "admin_400",
                                                 "security_300"}),
])
def test_how_the_maximum_and_the_minimums_work_together(env, factory, numbers, kept):
    ids = _seed_ages(factory)
    _prune(factory, numbers)
    assert {name for name, i in ids.items() if i in _left(factory)} == kept


def test_a_keep_rule_of_another_module_keeps_rows_the_maximum_would_delete(env, factory):
    ids = _seed_ages(factory)
    retention.register_keep("audit_logs", lambda model, now: model.id == ids["plain_400"])
    _prune(factory, _numbers(max_days=30))
    assert ids["plain_400"] in _left(factory) and ids["plain_100"] not in _left(factory)


# --------------------------------------------------------------------------- by size

MB = ar.MB


def _big(db, days, action=PLAIN, hours=0):
    """A row of a little under a quarter of a megabyte: four fit in one."""
    return _row(db, days, action, size=MB // 4 - 200, hours=hours)


def test_the_size_cap_deletes_the_oldest_rows_that_do_not_fit(env, factory):
    db = factory()
    rows = [_big(db, 30 + n) for n in range(8)]            # 2 MB, newest first
    _prune(factory, _numbers(max_mb=1))
    assert set(rows) <= _left(factory)                       # sealed now: they count from a week on
    _prune_sized(factory, _numbers(max_mb=1))
    left = _left(factory)
    assert [r in left for r in rows] == [True, True, True, True, False, False, False, False]


def test_the_size_cap_never_deletes_administration_or_security_rows(env, factory):
    db = factory()
    admin = [_big(db, 30 + n, ADMIN_ACTION) for n in range(3)]
    security = [_big(db, 40 + n, SECURITY_ACTION) for n in range(2)]
    plain = [_big(db, 50 + n) for n in range(3)]
    _prune_sized(factory, _numbers(max_mb=1, admin_min_days=0))
    left = _left(factory)
    assert set(admin + security) <= left
    assert not set(plain) & left


def test_rows_sealed_less_than_a_delay_ago_neither_count_nor_go(env, factory):
    db = factory()
    old = [_big(db, 20 + n) for n in range(3)]
    _prune_sized(factory, _numbers(max_mb=1))
    assert set(old) <= _left(factory)                       # the 0.75 MB counted fits
    # 2 MB written in the two hours after AFTER_DELAY: sealed then, so they count nothing yet.
    fresh = [_row(db, 0, size=MB // 4 - 200, hours=-(7 * 24 + 2 + n / 4)) for n in range(8)]
    _prune_sized(factory, _numbers(max_mb=1), now=AFTER_DELAY + timedelta(hours=4))
    assert set(fresh + old) <= _left(factory)
    env.retention_reduction_delay_days = 1
    _CHAIN[-1].setenv("RETENTION_REDUCTION_DELAY_DAYS", 1)   # .env's delay, which the chain seals first
    later = AFTER_DELAY + timedelta(days=2)
    _prune_sized(factory, _numbers(max_mb=1), now=later)
    assert len(set(fresh + old) & _left(factory)) == 4       # newest 1 MB of the counted rows


def test_an_hour_sealed_inside_the_window_counts_nothing_and_its_rows_stay(env, factory):
    # Five rows of a quarter of a megabyte in the hour before NOW, sealed after it closes: at a week and
    # fourteen minutes on, the window starts before that seal, so the hour counts nothing and nothing goes.
    db = factory()
    counted = [_big(db, 0, hours=(4 + n) / 60) for n in range(5)]
    first = NOW + timedelta(days=7, minutes=14)
    _age_chain(first)
    shown = ar.preview(factory(), first, _numbers(max_mb=1))
    assert shown["by_size"]["rows"] == 0
    ar.prune(retention.Pass(factory, now=first), _numbers(max_mb=1))
    assert set(counted) <= _left(factory)
    # Two hours on, the seal lies before the window: the hour counts, and its rows go; a row younger than
    # the window's start stays, whatever the cap.
    later = first + timedelta(hours=2)
    young = _row(db, 0, hours=-(7 * 24 + 1.5), size=MB // 4 - 200)
    _age_chain(later)
    shown = ar.preview(factory(), later, _numbers(max_mb=1))
    assert shown["by_size"]["rows"] == 5
    ar.prune(retention.Pass(factory, now=later), _numbers(max_mb=1))
    left = _left(factory)
    assert young in left and not set(counted) & left


def test_rows_younger_than_the_minimum_are_never_deleted_by_size(env, factory):
    db = factory()
    rows = [_big(db, 30 + n) for n in range(8)]
    _prune_sized(factory, _numbers(max_mb=1, min_days=60))
    assert set(rows) <= _left(factory)


def test_when_the_protected_rows_alone_do_not_fit_they_stay_and_the_administrators_are_told_once_a_day(
        env, factory, monkeypatch):
    told = []
    monkeypatch.setattr(ar, "warn_cap_unmet", lambda numbers, plan, now: told.append((plan.protected_bytes, now)))
    db = factory()
    admin = [_big(db, 30 + n, ADMIN_ACTION) for n in range(6)]
    plain = [_big(db, 40 + n) for n in range(2)]
    _prune_sized(factory, _numbers(max_mb=1, admin_min_days=0))
    assert set(admin) <= _left(factory) and not set(plain) & _left(factory)
    assert len(told) == 1 and told[0][0] > MB
    _prune_sized(factory, _numbers(max_mb=2, admin_min_days=0))
    assert len(told) == 1


def test_the_warning_is_one_notice_a_day_to_every_active_administrator(env, factory, monkeypatch):
    from contextlib import contextmanager

    from app.api import api_server as api
    sent = []

    @contextmanager
    def ctx():
        s = factory()
        yield s

    import app.core.database as database
    monkeypatch.setattr(database, "get_db_context", ctx)
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, **kw: sent.append((sorted(ids), ntype, kw)))
    db = factory()
    admins = [User(id=uuid.uuid4(), username=n, email=f"{n}@x.org", password_hash="x", role=role, is_active=active)
              for n, role, active in (("a", RoleEnum.ADMIN, True), ("b", RoleEnum.ADMIN, False),
                                      ("c", RoleEnum.USER, True))]
    db.add_all(admins)
    db.commit()
    ar.warn_cap_unmet(_numbers(max_mb=1), ar.SizePlan(protected_bytes=3 * MB, met=False), NOW)
    ((ids, ntype, kw),) = sent
    assert ids == [str(admins[0].id)] and ntype == "retention_warning"
    assert kw["dedup_prefix"] == "audit-size-cap:2026-10-20" and "3 MB" in kw["body"] and "1 MB" in kw["body"]


# --------------------------------------------------------------------------- the preview

@pytest.mark.parametrize("numbers", [
    _numbers(max_days=30), _numbers(max_days=30, min_days=200), _numbers(max_mb=1), _numbers(max_days=45, max_mb=1),
    _numbers(max_days=7, admin_min_days=0, max_mb=1), _numbers(),
])
def test_the_preview_is_what_the_job_deletes(env, factory, numbers):
    db = factory()
    _seed_ages(factory)
    for n in range(6):
        _big(db, 20 + 7 * n)
        _big(db, 21 + 7 * n, ADMIN_ACTION)
    before = _left(factory)
    _age_chain(AFTER_DELAY)
    shown = ar.preview(factory(), AFTER_DELAY, numbers)
    result = ar.prune(retention.Pass(factory, now=AFTER_DELAY), numbers)
    gone = before - _left(factory)
    assert shown["by_age"]["rows"] + shown["by_size"]["rows"] == len(gone) == result.deleted


def test_the_preview_route_is_a_bounded_plain_function_for_administrators(env, factory, monkeypatch):
    route = routes.preview_audit_retention
    # The rows' ages count from NOW and the route reads the clock itself: read from the wall clock, the youngest
    # row passed the 30-day maximum 30 days after it was seeded, whatever day the suite runs.
    monkeypatch.setattr(sc, "utcnow", lambda: NOW)
    assert not inspect.iscoroutinefunction(route)
    body = inspect.getsource(route).split('"""', 2)[2]
    assert body.lstrip().startswith("limit_statements(db, PREVIEW_STATEMENT_TIMEOUT_MS)")
    user = SimpleNamespace(id=None, username="alice")
    _seed_ages(factory)
    out = route(max_days=30, current_user=user, db=factory())
    assert out["numbers"] == {ar.MAX_DAYS: 30, ar.MIN_DAYS: 0, ar.ADMIN_MIN_DAYS: 365, ar.MAX_MB: 0}
    assert out["by_age"]["rows"] == 4
    from fastapi import HTTPException
    for bad in (dict(max_days=-3), dict(admin_min_days=10), dict(max_days="x")):
        with pytest.raises(HTTPException) as caught:
            route(current_user=user, db=factory(), **bad)
        assert caught.value.status_code == 400


# --------------------------------------------------------------------------- the first pass after an upgrade

def test_a_retention_set_in_env_before_the_upgrade_waits_with_notice(env, factory, monkeypatch):
    told = []
    monkeypatch.setattr(sc, "announce", lambda event, details, by=None: told.append((event, details)))
    env.audit_log_retention_days = 90
    _CHAIN[-1].setenv("AUDIT_LOG_RETENTION_DAYS", 90)
    ids = _seed_ages(factory)
    done = dict(_run(factory, now=NOW))
    assert done["audit_logs"].deleted == 0 and _left(factory) == set(ids.values())
    stored = factory().get(ManagedSetting, ar.MAX_DAYS)
    assert (stored.value, stored.updated_by_name) == (0, ar.SERVER)
    change = factory().query(ManagedSettingChange).one()
    # The server's request, sealed in the audit chain: once it applies, 90 is the panel's value, which a later
    # change of AUDIT_LOG_RETENTION_DAYS no longer moves.
    assert (change.status, change.setting, change.old_value, change.new_value, change.requested_by_name) == (
        sc.PENDING, 90, 0, 90, ar.SERVER)
    assert change.effective_at == NOW + timedelta(days=7)
    ((event, details),) = told
    assert event == sc.SCHEDULED and details["new"] == 90
    rows = [r.details for r in factory().query(AuditLog).filter(AuditLog.action == sc.SCHEDULED_ACTION)]
    assert rows and rows[0]["requested_by"] == ar.SERVER
    # Nothing is deleted until the wait is over, and nothing is scheduled twice. The pruner runs every few
    # hours meanwhile: the wait counts only time while sealing ran.
    at = NOW
    while at < NOW + timedelta(days=6, hours=18):
        at += timedelta(hours=6)
        _run(factory, now=at)
    assert _left(factory) == set(ids.values()) and factory().query(ManagedSettingChange).count() == 1
    _run(factory, now=NOW + timedelta(days=7))
    assert factory().query(ManagedSettingChange).one().status == sc.APPLIED
    assert ids["plain_400"] not in _left(factory) and ids["plain_10"] in _left(factory)


def test_the_audit_job_deletes_nothing_until_the_first_pass_has_decided(env, factory, monkeypatch, capsys):
    env.audit_log_retention_days = 90
    ids = _seed_ages(factory)

    def broken(p):
        raise RuntimeError("no")

    real = ar.schedule_env_retention_once
    monkeypatch.setattr(ar, "schedule_env_retention_once", broken)
    done = dict(_run(factory, now=NOW))
    assert done["audit_env_retention"] is None and done["audit_logs"].deleted == 0
    assert _left(factory) == set(ids.values())
    assert factory().get(SystemSetting, ar.MARKER) is None
    assert "the audit_env_retention job has not run yet" in capsys.readouterr().out
    monkeypatch.setattr(ar, "schedule_env_retention_once", real)
    done = dict(_run(factory, now=NOW))
    assert done["audit_logs"].deleted == 0 and _left(factory) == set(ids.values())
    assert factory().query(ManagedSettingChange).one().new_value == 90


@pytest.mark.parametrize("case", ["no_older_rows", "admin_value_stored", "locked", "keep_for_ever"])
def test_nothing_waits_when_nothing_would_be_deleted_or_the_choice_is_already_made(env, factory, case):
    env.audit_log_retention_days = 0 if case == "keep_for_ever" else 90
    db = factory()
    _row(db, 10 if case == "no_older_rows" else 400)
    if case == "admin_value_stored":
        reg.store(db, ar.MAX_DAYS, 365)
        db.commit()
    if case == "locked":
        env.settings_locked_keys = ar.GROUP
    _run(factory, now=NOW)
    assert factory().query(ManagedSettingChange).count() == 0
    assert factory().get(SystemSetting, ar.MARKER) is not None
    stored = factory().get(ManagedSetting, ar.MAX_DAYS)
    assert (stored.value if stored else None) == (365 if case == "admin_value_stored" else None)


def test_the_audit_job_is_the_three_numbers_and_the_hold_stops_it(env):
    jobs = {j.name: j for j in retention.JOBS}
    names = [j.name for j in retention.JOBS]
    assert names.index("audit_env_retention") < names.index("audit_logs")
    assert jobs["audit_logs"].held is True and jobs["audit_env_retention"].held is False
    assert "audit_retention.prune(p)" in inspect.getsource(retention.prune_audit_logs)


def test_the_settings_are_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    from app.core.config import Settings
    given = {"AUDIT_MIN_RETENTION_DAYS": "30", "AUDIT_PROTECTED_MIN_DAYS": "400", "AUDIT_LOG_MAX_MB": "2048",
             "PLAN_LOG_MAX_DAYS": "730", "PLAN_LOG_MAX_MB": "4096"}
    defaults = {"AUDIT_MIN_RETENTION_DAYS": "0", "AUDIT_PROTECTED_MIN_DAYS": "365", "AUDIT_LOG_MAX_MB": "0",
                "PLAN_LOG_MAX_DAYS": "-1", "PLAN_LOG_MAX_MB": "-1"}
    for name, value in defaults.items():
        assert Settings.model_fields[name.lower()].default == int(value)
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for name, value in defaults.items():
        assert example.count(f"\n# {name}={value}\n") == 1, name
    spec = importlib.util.spec_from_file_location("dockvault_audit", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    lines = dv.build_env_lines({**dv.new_set_config(given, "prefix-1", "dep-1"), "server_name": "localhost"})
    written = dv.parse_env("\n".join(lines))
    assert {k: written.get(k) for k in given} == given
    parsed = Settings(**{k.lower(): v for k, v in written.items() if k in given})
    assert [getattr(parsed, k.lower()) for k in given] == [int(v) for v in given.values()]
    for kept in ({}, defaults):
        plain = dv.build_env_lines({**dv.new_set_config(kept, "prefix-1", "dep-1"), "server_name": "localhost"})
        assert not [line for line in plain if line.split("=")[0] in given]


def test_the_maximum_deletes_from_its_exact_day_on(env, factory):
    db = factory()
    inside = _row(db, 30, hours=-1)          # 29 days 23 hours old
    outside = _row(db, 30, hours=1)          # 30 days 1 hour old
    _prune(factory, _numbers(max_days=30))
    assert inside in _left(factory) and outside not in _left(factory)


def test_the_preview_counts_an_hour_the_maximum_cuts_through_as_the_job_does(env, factory):
    """The maximum's cutoff can fall inside an hour: the size cap must not count that hour's rows the
    maximum deletes, or the preview would promise more than the job deletes."""
    now = NOW + timedelta(minutes=30)                 # the 45-day cutoff falls at 12:30 of its day
    db = factory()
    base = NOW - timedelta(days=45)
    for minutes in (-10, 10):                          # 12:20 (past the maximum) and 12:40 (within it)
        db.add(AuditLog(id=uuid.uuid4(), action=PLAIN, status="success",
                        timestamp=base + timedelta(minutes=30 + minutes), details={"pad": "x" * (MB // 4 - 200)}))
    for hours in (3, 4, 5):                            # three more within it, later that day
        db.add(AuditLog(id=uuid.uuid4(), action=PLAIN, status="success", timestamp=base + timedelta(hours=hours),
                        details={"pad": "x" * (MB // 4 - 200)}))
    db.commit()
    numbers = _numbers(max_days=45, max_mb=1)
    shown = ar.preview(factory(), now, numbers)
    result = _prune(factory, numbers, now=now)
    assert (shown["by_age"]["rows"], shown["by_size"]["rows"]) == (1, 0)
    assert result.deleted == 1
