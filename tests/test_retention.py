"""The pruner (app/core/retention.py), offline.

Every timed deletion of records is a job of the pruner: finished sessions and pending sign-ins, the records
of credential changes, the sign-in throttle's fallback rows, resolved security alerts, and audit rows, plus
the settings changes that wait. A pass runs each job once, in batches (one transaction each), within a time
budget; one runner works at a time; a job that deleted something writes one retention_pruned row; row-keep
rules keep what other modules protect; and the hold switch stops the jobs over logs and security records
while the working-record jobs go on. The pruner runs on a thread of its own, started by the web process
only; no request handler prunes, and the periodic loop on the event loop does none of the pruner's work.
These run on a throwaway SQLite database.
"""
import ast
import inspect
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import retention  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import (ActiveSession, AuditLog, CredentialChange, ManagedSetting,  # noqa: E402
                             ManagedSettingChange, PendingLogin, RateLimitRecord, RoleEnum, SecurityAlert,
                             SystemSetting, User)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 20, 12, 0, 0)
OLD = NOW - timedelta(days=400)


@pytest.fixture
def env(monkeypatch):
    """Deployment settings the test controls and no stored values."""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    settings = SimpleNamespace(settings_locked_keys="", retention_hold=False, log_prune_interval_minutes=15,
                               log_prune_batch_rows=5000, retention_reduction_delay_days=7,
                               audit_log_retention_days=0, security_alert_retention_days=90,
                               jwt_access_token_expire_minutes=60)
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    monkeypatch.setattr(retention, "_settings", lambda: settings)
    monkeypatch.setattr(retention, "KEEP_RULES", {})
    return settings


@pytest.fixture
def factory(monkeypatch):
    """Sessions on a throwaway database (a copy of each table with SQLite's "now"); every session made is
    closed at the end."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'retention.db'}")
        copies = sa.MetaData()
        for model in (User, ActiveSession, PendingLogin, CredentialChange, RateLimitRecord, SecurityAlert,
                      AuditLog, ManagedSetting, ManagedSettingChange, SystemSetting):
            # Each column as it is, without the foreign keys (the tables they name are not copied), and with
            # SQLite's spelling of "now" where Postgres's is the default.
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

        session.made = made
        monkeypatch.setattr(reg, "_default_session_factory", session)
        # An install past its first pass after the upgrade (test_audit_retention.py covers that pass).
        first = session()
        first.add(SystemSetting(key="audit_env_retention_scheduled", value={}))
        first.commit()
        yield session
        for s in made:
            s.close()
        engine.dispose()


def _user(db, name="alice"):
    user = User(id=uuid.uuid4(), username=name, email=f"{name}@example.com", password_hash="x",
                role=RoleEnum.ADMIN, is_active=True)
    db.add(user)
    db.commit()
    return user


def _audit(db, when, action="file_upload", n=1):
    for _ in range(n):
        db.add(AuditLog(id=uuid.uuid4(), action=action, status="success", timestamp=when))
    db.commit()


def _alert(db, when, resolved):
    alert = SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning", message="m",
                          timestamp=when, resolved=resolved, details={})
    db.add(alert)
    db.commit()
    return alert.id


def _count(factory, model, *conditions):
    return factory().query(model).filter(*conditions).count()


def _pass(factory, **kw):
    kw.setdefault("now", NOW)
    return dict(retention.run_pass(factory, **kw))


def _pruned(factory, job):
    return [r.details for r in factory().query(AuditLog).filter(AuditLog.action == "retention_pruned",
                                                                AuditLog.resource_id == job).all()]


# --------------------------------------------------------------------------- the settings

def test_the_hold_switch_is_a_setting_whose_turning_off_waits(env):
    spec = reg.spec_for(retention.HOLD_KEY)
    assert (spec.kind, spec.default, spec.env, spec.editable, spec.reduction) == (
        "bool", False, "retention_hold", reg.ADMIN, reg.LOWER)
    assert reg.is_reduction(spec, True, False) and not reg.is_reduction(spec, False, True)
    assert reg.bounds(spec) == (False, None)            # a floor of off holds nothing
    assert reg.check_bounds(spec, False) is None
    env.retention_hold = True
    assert reg.resolve(retention.HOLD_KEY) is True and reg.bounds(spec) == (True, None)
    reg._cache.rows = {retention.HOLD_KEY: (False, 1)}
    assert retention.hold_in_force() is True            # RETENTION_HOLD=true: the panel cannot turn it off
    assert reg.check_bounds(spec, False) == ("logs_hold cannot be off: the deployment keeps it on "
                                             "(RETENTION_HOLD in .env)")
    assert reg.check_bounds(spec, True) is None
    env.retention_hold = False
    assert retention.hold_in_force() is False


def test_the_pass_interval_and_batch_are_set_only_in_env_within_bounds(env):
    for key, default, low, high in ((retention.INTERVAL_KEY, 15, 1, 1440), (retention.BATCH_KEY, 5000, 100, 100000)):
        spec = reg.spec_for(key)
        assert (spec.default, spec.minimum, spec.maximum, spec.editable) == (default, low, high, reg.ENV_ONLY)
    env.log_prune_interval_minutes = 2
    assert retention.interval_seconds() == 120.0
    env.log_prune_batch_rows = 50
    assert any("LOG_PRUNE_BATCH_ROWS is not valid" in p for p in reg.check_contract())


def test_the_fixed_windows_are_listed_and_fixed(env):
    for key, value in (("session_records_days", 30), ("credential_change_records_days", 14),
                       ("rate_limit_records_hours", 1)):
        spec = reg.spec_for(key)
        assert (spec.editable, spec.default, reg.resolve(key)) == (reg.FIXED, value, value)


def test_the_retention_settings_are_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    from app.core.config import Settings
    fields = Settings.model_fields
    assert (fields["retention_hold"].default, fields["log_prune_interval_minutes"].default,
            fields["log_prune_batch_rows"].default) == (False, 15, 5000)
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for line in ("# RETENTION_HOLD=false", "# LOG_PRUNE_INTERVAL_MINUTES=15", "# LOG_PRUNE_BATCH_ROWS=5000"):
        assert example.count(f"\n{line}\n") == 1, line
    spec = importlib.util.spec_from_file_location("dockvault_pruner", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    given = {"RETENTION_HOLD": "true", "LOG_PRUNE_INTERVAL_MINUTES": "5", "LOG_PRUNE_BATCH_ROWS": "1000"}
    lines = dv.build_env_lines({**dv.new_set_config(given, "prefix-1", "dep-1"), "server_name": "localhost"})
    written = dv.parse_env("\n".join(lines))
    assert {k: written.get(k) for k in given} == given
    parsed = Settings(retention_hold=written["RETENTION_HOLD"],
                      log_prune_interval_minutes=written["LOG_PRUNE_INTERVAL_MINUTES"],
                      log_prune_batch_rows=written["LOG_PRUNE_BATCH_ROWS"])
    assert (parsed.retention_hold, parsed.log_prune_interval_minutes, parsed.log_prune_batch_rows) == (True, 5, 1000)
    defaults = {"RETENTION_HOLD": "false", "LOG_PRUNE_INTERVAL_MINUTES": "15", "LOG_PRUNE_BATCH_ROWS": "5000"}
    for kept in ({}, defaults):
        plain = dv.build_env_lines({**dv.new_set_config(kept, "prefix-1", "dep-1"), "server_name": "localhost"})
        assert not [line for line in plain if line.split("=")[0] in given]


# --------------------------------------------------------------------------- the jobs

def test_the_jobs_and_which_the_hold_switch_stops():
    assert [(j.name, j.held) for j in retention.JOBS] == [
        ("setting_changes", False), ("sessions", False), ("credential_changes", False),
        ("rate_limit_records", False), ("security_alerts", True), ("security_records", True),
        ("security_alert_values", True), ("audit_env_retention", False), ("audit_logs", True)]


def test_finished_sessions_and_sign_ins_go_after_their_window(env, factory):
    db = factory()
    user = _user(db)
    for n, (active, last) in enumerate(((False, OLD), (True, OLD), (False, NOW - timedelta(days=5)))):
        db.add(ActiveSession(id=uuid.uuid4(), user_id=user.id, session_token=f"t{n}", ip_address="10.0.0.1",
                             is_active=active, revoked=False, started_at=last, last_activity=last))
    db.add(PendingLogin(id=uuid.uuid4(), user_id=user.id, created_at=OLD, consumed_at=OLD,
                        expires_at=OLD))
    db.add(PendingLogin(id=uuid.uuid4(), user_id=user.id, created_at=NOW, expires_at=NOW + timedelta(minutes=5)))
    db.commit()
    result = _pass(factory)["sessions"]
    assert result.deleted == 2
    assert _count(factory, ActiveSession) == 2 and _count(factory, PendingLogin) == 1
    # One record for each transaction that deleted: here one batch from each table.
    rows = sorted(_pruned(factory, "sessions"), key=lambda r: r["table"])
    assert [(r["job"], r["table"], r["deleted"], r["oldest"], r["newest"]) for r in rows] == [
        ("sessions", table, 1, OLD.isoformat() + "Z", OLD.isoformat() + "Z")
        for table in sorted((ActiveSession.__tablename__, PendingLogin.__tablename__))]


def test_credential_change_records_go_fourteen_days_after_they_end(env, factory):
    from app.core import credential_changes as cc
    db = factory()
    user = _user(db)
    for status, when in ((cc.APPLIED[0], OLD), (cc.DENIED, OLD), (cc.HELD, OLD), (cc.APPLIED[0], NOW)):
        db.add(CredentialChange(id=uuid.uuid4(), target_user_id=user.id, kind="password", status=status,
                                requested_by_name="alice", requested_at=when, expires_at=when + timedelta(days=7),
                                applied_at=when if status in cc.APPLIED else None,
                                decided_at=when if status == cc.DENIED else None, summary="s"))
    db.commit()
    assert _pass(factory)["credential_changes"].deleted == 2
    assert sorted(c.status for c in factory().query(CredentialChange).all()) == sorted([cc.HELD, cc.APPLIED[0]])
    (row,) = _pruned(factory, "credential_changes")
    assert (row["table"], row["deleted"]) == (CredentialChange.__tablename__, 2)


def test_throttle_records_go_an_hour_after_their_window(env, factory):
    db = factory()
    for n, when in enumerate((NOW - timedelta(hours=2), NOW - timedelta(minutes=10))):
        db.add(RateLimitRecord(id=uuid.uuid4(), identifier=f"x{n}", action="login", window_start=when,
                               attempt_count=1))
    db.commit()
    assert _pass(factory)["rate_limit_records"].deleted == 1
    assert _count(factory, RateLimitRecord) == 1


def test_resolved_alerts_go_after_their_window_and_unresolved_ones_stay(env, factory):
    db = factory()
    old_resolved = _alert(db, OLD, True)
    old_open = _alert(db, OLD, False)
    recent_resolved = _alert(db, NOW - timedelta(days=10), True)
    assert _pass(factory)["security_alerts"].deleted == 1
    left = {a.id for a in factory().query(SecurityAlert).all()}
    assert left == {old_open, recent_resolved} and old_resolved not in left
    env.security_alert_retention_days = 5
    assert _pass(factory)["security_alerts"].deleted == 1


def test_audit_rows_go_only_after_a_positive_retention(env, factory):
    db = factory()
    _audit(db, OLD, n=3)
    _audit(db, NOW - timedelta(days=1))
    assert _pass(factory)["audit_logs"].deleted == 0 and _count(factory, AuditLog) == 4
    env.audit_log_retention_days = 30
    assert _pass(factory)["audit_logs"].deleted == 3
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 1
    (row,) = _pruned(factory, "audit_logs")
    assert row["deleted"] == 3


@pytest.mark.parametrize("rows,transactions", [(5, 3), (4, 3), (1, 1), (0, 1)])
def test_a_job_deletes_in_batches_one_transaction_each(env, factory, monkeypatch, rows, transactions):
    env.audit_log_retention_days = 30
    monkeypatch.setattr(retention, "JOBS", [j for j in retention.JOBS if j.name == "audit_logs"])
    db = factory()
    _audit(db, OLD, n=rows)
    before = len(factory.made)
    assert _pass(factory, batch_rows=2)["audit_logs"].deleted == rows
    # One session to read the settings, one to see the first pass after an upgrade is done, and one per
    # batch (5 rows in twos: 2, 2, 1; 4 rows: 2, 2, then an empty one), each batch writing its own record.
    assert len(factory.made) - before == 2 + transactions
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 0
    assert [r["deleted"] for r in _pruned(factory, "audit_logs")] == [2] * (rows // 2) + [1] * (rows % 2)


def test_every_batch_statement_is_bounded(env, factory, monkeypatch):
    seen = []
    monkeypatch.setattr(retention, "limit_statements", lambda db: seen.append(db))
    env.audit_log_retention_days = 30
    db = factory()
    _audit(db, OLD, n=5)
    _pass(factory, batch_rows=2)
    assert len(seen) >= 3


def test_the_statement_bound_is_set_on_postgres(monkeypatch):
    executed = []

    class Bind:
        dialect = SimpleNamespace(name="postgresql")

    session = SimpleNamespace(get_bind=lambda: Bind(), execute=lambda statement: executed.append(str(statement)))
    retention.limit_statements(session)
    assert executed == [f"SET LOCAL statement_timeout = {retention.STATEMENT_TIMEOUT_MS}"]


def test_a_pass_stops_when_its_time_runs_out(env, factory):
    env.audit_log_retention_days = 30
    db = factory()
    _audit(db, OLD, n=5)
    assert _pass(factory, budget_seconds=0) == {}
    assert _count(factory, AuditLog) == 5


def test_a_job_that_fails_never_stops_the_others(env, factory, monkeypatch, capsys):
    env.audit_log_retention_days = 30
    db = factory()
    _audit(db, OLD, n=2)

    def broken(p):
        raise RuntimeError("no")

    monkeypatch.setattr(retention, "JOBS", [retention.Job("broken", "Broken", broken)] + retention.JOBS)
    done = _pass(factory)
    assert done["broken"] is None and done["audit_logs"].deleted == 2
    assert "the pruner's broken job failed (RuntimeError)" in capsys.readouterr().out


def test_every_batch_commits_with_its_record_or_not_at_all(env, factory, monkeypatch, capsys):
    """A pass stopped part way leaves a record of each batch it committed, and a batch whose record cannot
    be written deletes nothing."""
    env.audit_log_retention_days = 30
    monkeypatch.setattr(retention, "JOBS", [j for j in retention.JOBS if j.name == "audit_logs"])
    _audit(factory(), OLD, n=5)
    real, calls = retention.Pass.record, []

    def second_fails(self, db, done, table=None):
        calls.append(done.deleted)
        if len(calls) == 2:
            raise RuntimeError("no")
        return real(self, db, done, table)

    monkeypatch.setattr(retention.Pass, "record", second_fails)
    assert _pass(factory, batch_rows=2)["audit_logs"] is None
    assert "the pruner's audit_logs job failed (RuntimeError)" in capsys.readouterr().out
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 3
    (row,) = _pruned(factory, "audit_logs")
    assert (row["job"], row["table"], row["deleted"]) == ("audit_logs", AuditLog.__tablename__, 2)
    monkeypatch.setattr(retention.Pass, "record", real)
    assert _pass(factory, batch_rows=2)["audit_logs"].deleted == 3
    assert sorted(r["deleted"] for r in _pruned(factory, "audit_logs")) == [1, 2, 2]


def test_a_job_that_deleted_nothing_writes_no_row(env, factory):
    _pass(factory)
    assert _count(factory, AuditLog, AuditLog.action == "retention_pruned") == 0


def test_the_record_is_catalogued_as_the_servers_own():
    from app.core import audit_catalog
    entry = audit_catalog.lookup("retention_pruned")
    assert entry is not None and entry.automatic is True and entry.category == "administration"


# --------------------------------------------------------------------------- the hold switch and what is kept

def test_the_hold_switch_stops_the_log_jobs_and_not_the_working_records(env, factory):
    env.audit_log_retention_days = 30
    db = factory()
    _audit(db, OLD, n=2)
    _alert(db, OLD, True)
    db.add(RateLimitRecord(id=uuid.uuid4(), identifier="x", action="login", window_start=OLD, attempt_count=1))
    db.commit()
    reg.store(db, retention.HOLD_KEY, True)             # stored by another process: the pass reads it itself
    db.commit()
    done = _pass(factory)
    assert done["audit_logs"] is None and done["security_alerts"] is None
    assert done["rate_limit_records"].deleted == 1
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 2
    assert _count(factory, SecurityAlert) == 1
    reg.store(db, retention.HOLD_KEY, None)
    db.commit()
    done = _pass(factory)
    assert done["audit_logs"].deleted == 2 and done["security_alerts"].deleted == 1


def test_rows_a_keep_rule_keeps_are_never_deleted(env, factory):
    env.audit_log_retention_days = 30
    db = factory()
    _audit(db, OLD, action="settings_updated", n=2)
    _audit(db, OLD, action="file_upload", n=3)
    retention.register_keep("audit_logs", lambda model, now: model.action == "settings_updated")
    retention.register_keep("audit_logs", lambda model, now: None)      # keeps nothing just now
    assert _pass(factory)["audit_logs"].deleted == 3
    assert _count(factory, AuditLog, AuditLog.action == "settings_updated") == 2


def test_a_keep_rule_is_added_once(env):
    rule = lambda model, now: None  # noqa: E731
    retention.register_keep("audit_logs", rule)
    retention.register_keep("audit_logs", rule)
    assert retention.KEEP_RULES == {"audit_logs": [rule]}


# --------------------------------------------------------------------------- the waiting settings changes

def test_a_pass_applies_the_settings_changes_that_are_due(env, factory, monkeypatch):
    from app.core import setting_changes as sc
    monkeypatch.setattr(sc, "announce", lambda *a, **k: None)
    db = factory()
    alice = _user(db)
    sc.request(db, retention.HOLD_KEY, True, actor=alice, now=NOW - timedelta(days=30))
    db.commit()
    reg.refresh(factory)
    sc.request(db, retention.HOLD_KEY, False, actor=alice, now=NOW - timedelta(days=8))
    db.commit()
    assert reg.resolve(retention.HOLD_KEY) is True
    _pass(factory)
    reg.refresh(factory)
    assert reg.resolve(retention.HOLD_KEY) is False


# --------------------------------------------------------------------------- one runner, off the event loop

def test_two_runners_at_once_means_one_works(env, factory, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def slow(p):
        entered.set()
        release.wait(10)
        return retention.JobResult()

    monkeypatch.setattr(retention, "JOBS", [retention.Job("slow", "Slow", slow)])
    first = []
    t = threading.Thread(target=lambda: first.append(retention.run_pass(factory, now=NOW)))
    t.start()
    assert entered.wait(10)
    assert retention.run_pass(factory, now=NOW) is None
    release.set()
    t.join(10)
    assert first and first[0] == [("slow", first[0][0][1])]
    assert retention.run_pass(factory, now=NOW) is not None


def test_on_postgres_the_runner_holds_an_advisory_lock_on_its_own_connection(monkeypatch):
    statements = []

    class Conn:
        invalidated = closed = False

        def execution_options(self, **kw):
            statements.append(("options", kw))
            return self

        def execute(self, statement, params=None):
            statements.append((str(statement), params))
            return SimpleNamespace(scalar=lambda: owner)

        def invalidate(self):
            Conn.invalidated = True

        def close(self):
            Conn.closed = True

    engine = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"), connect=lambda: Conn())
    for owner in (True, False):
        statements.clear()
        with retention._runner_turn(engine) as mine:
            assert mine is owner
        lock = {"c": retention.RUNNER_LOCK[0], "k": retention.RUNNER_LOCK[1]}
        expected = [("options", {"isolation_level": "AUTOCOMMIT"}), ("SELECT pg_try_advisory_lock(:c, :k)", lock)]
        if owner:
            expected.append(("SELECT pg_advisory_unlock(:c, :k)", lock))
        assert statements == expected
        assert Conn.invalidated and Conn.closed


def test_the_pruner_runs_off_the_event_loop_on_its_own_thread():
    from _async_run import run_coroutine
    seen = []
    loop_thread = []

    def fake_pass():
        seen.append(threading.current_thread().name)

    async def main():
        import asyncio
        loop_thread.append(threading.current_thread().name)
        task = asyncio.ensure_future(retention.run_forever(first_delay=0.01, interval=lambda: 0.01, pass_fn=fake_pass))
        deadline = time.monotonic() + 10
        while len(seen) < 3 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    run_coroutine(main())
    assert len(seen) >= 3
    assert all(name.startswith("retention") for name in seen) and loop_thread[0] not in seen


def test_a_failed_pass_never_ends_the_pruner(capsys):
    from _async_run import run_coroutine
    calls = []

    def broken():
        calls.append(1)
        raise RuntimeError("no")

    async def main():
        import asyncio
        task = asyncio.ensure_future(retention.run_forever(first_delay=0, interval=lambda: 0.01, pass_fn=broken))
        deadline = time.monotonic() + 10
        while len(calls) < 2 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        task.cancel()

    run_coroutine(main())
    assert len(calls) >= 2


def test_only_the_web_process_starts_the_pruner():
    from app.sftp import sftp_server
    lifespan = inspect.getsource(api.lifespan)
    before, after = lifespan.split("\n    yield\n")
    assert before.count("retention.run_forever(") == 1
    assert after.count("retention_task.cancel()") == 1
    assert "retention" not in inspect.getsource(sftp_server)


# --------------------------------------------------------------------------- nothing else prunes

def _handed_the_pass(fn) -> set:
    """The functions ``fn`` hands its pass, or a part of it, to: calls with ``p`` or ``p.<x>`` among their
    arguments."""
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        args = list(node.args) + [k.value for k in node.keywords]
        if any(isinstance(a, ast.Name) and a.id == "p"
               or isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name) and a.value.id == "p"
               for a in args):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if name:
                names.add(name)
    return names


def _job_functions() -> set:
    """Every job's function, and every function a job hands its pass to, followed into other modules."""
    import importlib
    found, todo = set(), [job.run for job in retention.JOBS]
    while todo:
        fn = todo.pop()
        if fn.__name__ in found:
            continue
        found.add(fn.__name__)
        for name in _handed_the_pass(ast.parse(inspect.getsource(fn).lstrip())):
            for module in ("app.core.retention", "app.core.audit_retention", "app.core.security_records",
                           "app.core.setting_changes", "app.core.credential_changes",
                           "app.core.session_retention"):
                target = getattr(importlib.import_module(module), name, None)
                if inspect.isfunction(target):
                    todo.append(target)
    return found


# What the pruner owns: the functions its jobs run (followed into the modules they hand their pass to), the
# pass itself, the functions it replaced, and the models its jobs delete from.
OWNED_FUNCTIONS = _job_functions() | {"Pass", "delete_in_batches", "run_pass", "prune_done", "apply_due",
                                      "purge_old_session_data", "cleanup_old_audit_logs", "cleanup_old_alerts"}
OWNED_MODELS = {"AuditLog", "SecurityAlert", "SecurityRecord", "RateLimitRecord", "CredentialChange",
                "ActiveSession", "PendingLogin", "ManagedSettingChange"}
# Timed deletions the periodic loop keeps, each for a reason. Any other call there whose name starts with
# prune or purge is a deletion that belongs in a job.
LOOP_DELETIONS = {
    # The sign-in lockout's working counts that hold no lock: a few rows, deleted by an indexed statement.
    "prune_stale",
}


def _owned_tables() -> set:
    from app.core import models
    return {getattr(models, name).__tablename__ for name in OWNED_MODELS}


def _aliases(tree) -> dict:
    """Names imported under another name anywhere in ``tree`` (``from x import Model as M``): M -> Model."""
    return {a.asname: a.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
            for a in node.names if a.asname}


def _problems(fn, aliases=None):
    """Calls in ``fn`` of a function the pruner owns, and deletes from a model or table it owns: an ORM
    query's delete, a Core delete(Model), or a DELETE in SQL text. Names imported under another name, in
    ``fn`` or in ``aliases`` (the module's), are read as the names they stand for."""
    aliases = {**(aliases or {}), **_aliases(fn)}
    tables = _owned_tables()
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for table in re.findall(r"delete\s+from\s+\"?(\w+)", node.value, re.IGNORECASE):
                if table in tables:
                    found.append(f"deletes from {table}")
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else None)
        name = aliases.get(name, name)
        if name in OWNED_FUNCTIONS:
            found.append(f"calls {name}")
        if name == "delete":
            parts = ([node.func.value] if isinstance(node.func, ast.Attribute) else []) + list(node.args)
            named = set()
            for part in parts:
                for n in ast.walk(part):
                    if isinstance(n, ast.Name):
                        named.add(aliases.get(n.id, n.id))
                    elif isinstance(n, ast.Attribute):
                        named.add(n.attr)
            if named & OWNED_MODELS:
                found.append(f"deletes {sorted(named & OWNED_MODELS)}")
    return found


def _route_handlers():
    for path in sorted((ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = _aliases(tree)
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                    and d.func.attr in {"get", "post", "put", "patch", "delete", "websocket"}
                    for d in fn.decorator_list):
                yield path.relative_to(ROOT).as_posix(), fn, aliases


def test_no_request_handler_prunes():
    handlers = list(_route_handlers())
    assert len(handlers) > 200
    found = [(path, fn.name, p) for path, fn, aliases in handlers for p in _problems(fn, aliases)]
    assert not found, found


def _loop_deletions(tree):
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name.startswith(("prune", "purge")) and name not in LOOP_DELETIONS:
                found.append(f"calls {name}")
    return found


def test_the_periodic_loop_does_none_of_the_pruners_work():
    tree = ast.parse(inspect.getsource(api.cleanup_expired_sessions))
    assert _problems(tree, _aliases(ast.parse(inspect.getsource(api)))) == []
    assert _loop_deletions(tree) == []
    # The kept deletions are still there: a name that went away leaves the list.
    names = {getattr(n.func, "attr", getattr(n.func, "id", None)) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert LOOP_DELETIONS <= names


def test_the_owned_functions_follow_the_jobs():
    for job in retention.JOBS:
        assert job.run.__name__ in OWNED_FUNCTIONS
    for name in ("prune_records", "clear_alert_values", "schedule_env_retention_once", "env_retention_decided",
                 "prune", "apply_due", "prune_done", "delete_in_batches"):
        assert name in OWNED_FUNCTIONS, name


def test_the_scan_finds_what_it_looks_for():
    source = "def f(db):\n    db.query(AuditLog).filter(x).delete()\n    prune_done(db)\n    run_pass()\n"
    assert _problems(ast.parse(source)) == ["deletes ['AuditLog']", "calls prune_done", "calls run_pass"]
    source = ("def f(db):\n    db.query(SecurityRecord).delete()\n    db.query(ActiveSession).filter(x).delete()\n"
              "    prune_security_records(p)\n    Pass(factory)\n")
    assert _problems(ast.parse(source)) == ["deletes ['SecurityRecord']", "deletes ['ActiveSession']",
                                            "calls prune_security_records", "calls Pass"]
    source = ("def f(db):\n    from app.core.models import SecurityRecord as R\n    db.query(R).filter(R.at < 1).delete()\n"
              "    db.execute(sa.delete(models.AuditLog))\n    db.execute(delete(PendingLogin))\n"
              "    db.execute(text('DELETE FROM security_alerts WHERE 1 = 1'))\n    db.delete(row)\n")
    assert _problems(ast.parse(source)) == ["deletes ['SecurityRecord']", "deletes ['AuditLog']",
                                            "deletes ['PendingLogin']", "deletes from security_alerts"]
    source = "from app.core.retention import run_pass as go\ndef f():\n    go()\n"
    assert _problems(ast.parse(source).body[1], _aliases(ast.parse(source))) == ["calls run_pass"]
    source = "async def f():\n    prune_stale(db)\n    purge_expired_things(db)\n    prune_x(db)\n"
    assert _loop_deletions(ast.parse(source)) == ["calls purge_expired_things", "calls prune_x"]


def test_the_prunes_made_on_read_are_gone():
    from app.services import audit_logger, security_monitor
    assert not hasattr(audit_logger.AuditLogger, "cleanup_old_audit_logs")
    assert not hasattr(security_monitor.SecurityMonitor, "cleanup_old_alerts")


def test_the_first_pass_waits_so_it_never_delays_the_start():
    from _async_run import run_coroutine
    calls = []

    async def main():
        import asyncio
        task = asyncio.ensure_future(retention.run_forever(first_delay=30, interval=lambda: 0.01,
                                                           pass_fn=lambda: calls.append(1)))
        await asyncio.sleep(0.3)
        task.cancel()

    run_coroutine(main())
    assert calls == []
    assert retention.FIRST_PASS_SECONDS >= 30
    assert "retention.run_forever()" in inspect.getsource(api.lifespan)
