"""The security record (app/core/security_records.py), offline.

Every failed sign-in the app audits (a web password, a second-factor code, an SFTP password) writes a
security record in the same commit as its audit row, with the name as typed and the address in full whatever
the audit row keeps; a record that cannot be written never costs the audit row (an alert says so instead).
The pruner deletes records past the window (security_record_days, bounded by .env) and
clears the names and addresses of older security alerts, resolved or not; alert messages hold placeholders
instead of names and addresses, completed when shown. The security monitor's statistics read the records.
These run on a throwaway SQLite database.
"""
import contextlib
import inspect
import logging
import sys
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

from app.core import retention  # noqa: E402
from app.core import security_records as srec  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import (AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange, RoleEnum,  # noqa: E402
                             SecurityAlert, SecurityRecord, SystemSetting, User)
from app.services import audit_logger, audit_row_hooks  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 20, 12, 0, 0)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    settings = SimpleNamespace(settings_locked_keys="", retention_hold=False, log_prune_interval_minutes=15,
                               log_prune_batch_rows=5000, retention_reduction_delay_days=7,
                               audit_log_retention_days=0, security_alert_retention_days=90,
                               security_record_days=30, security_record_min_days=7, security_record_max_days=365,
                               jwt_access_token_expire_minutes=60)
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    monkeypatch.setattr(retention, "_settings", lambda: settings)
    return settings


@pytest.fixture
def factory(monkeypatch):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'records.db'}")
        copies = sa.MetaData()
        # The audit chain's table too, empty: the pruner holds the jobs over logs when it cannot tell whether a
        # chain it has not read holds them.
        for model in (User, AuditLog, AuditSeal, SecurityRecord, SecurityAlert, ManagedSetting, ManagedSettingChange,
                      SystemSetting):
            columns = [sa.Column(c.name, c.type, primary_key=c.primary_key, nullable=c.nullable)
                       for c in model.__table__.columns]
            sa.Table(model.__tablename__, copies, *columns)
        copies.create_all(engine)
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        made = []

        def session():
            made.append(make())
            return made[-1]

        monkeypatch.setattr(reg, "_default_session_factory", session)
        first = session()
        first.add(SystemSetting(key="audit_env_retention_scheduled", value={}))
        first.commit()
        yield session
        for s in made:
            s.close()
        engine.dispose()


def _user(db, name="alice"):
    user = User(id=uuid.uuid4(), username=name, email=f"{name}@x.org", password_hash="x", role=RoleEnum.USER,
                is_active=True)
    db.add(user)
    db.commit()
    return user


def _records(factory):
    return factory().query(SecurityRecord).order_by(SecurityRecord.at).all()


# --------------------------------------------------------------------------- the settings

def test_the_window_is_a_managed_setting_bounded_by_env(env):
    spec = reg.spec_for(srec.WINDOW_KEY)
    assert (spec.default, spec.env, spec.floor, spec.ceiling, spec.reduction, spec.editable) == (
        30, "security_record_days", "security_record_min_days", "security_record_max_days", reg.LOWER, reg.ADMIN)
    assert reg.check_bounds(spec, 6) == ("security_record_days cannot be 6 days: the deployment keeps it at least "
                                        "7 days (SECURITY_RECORD_MIN_DAYS in .env)")
    assert "at most 365 days (SECURITY_RECORD_MAX_DAYS in .env)" in reg.check_bounds(spec, 400)
    env.security_record_min_days, env.security_record_max_days = 60, 30
    assert any("floor (60) is above the ceiling (30)" in p for p in reg.check_contract())


def test_the_resolved_alert_retention_is_listed_and_set_only_in_env(env):
    spec = reg.spec_for(srec.ALERT_RETENTION_KEY)
    assert (spec.default, spec.env, spec.editable) == (90, "security_alert_retention_days", reg.ENV_ONLY)
    assert "prune_resolved_alerts" in [j.run.__name__ for j in retention.JOBS]
    assert "registry.resolve(security_records.ALERT_RETENTION_KEY)" in inspect.getsource(retention.prune_resolved_alerts)


def test_the_settings_are_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    from app.core.config import Settings
    defaults = {"SECURITY_RECORD_DAYS": "30", "SECURITY_RECORD_MIN_DAYS": "7", "SECURITY_RECORD_MAX_DAYS": "365"}
    given = {"SECURITY_RECORD_DAYS": "60", "SECURITY_RECORD_MIN_DAYS": "14", "SECURITY_RECORD_MAX_DAYS": "180"}
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for name, value in defaults.items():
        assert Settings.model_fields[name.lower()].default == int(value)
        assert example.count(f"\n# {name}={value}\n") == 1, name
    spec = importlib.util.spec_from_file_location("dockvault_records", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    lines = dv.build_env_lines({**dv.new_set_config(given, "prefix-1", "dep-1"), "server_name": "localhost"})
    written = dv.parse_env("\n".join(lines))
    assert {k: written.get(k) for k in given} == given
    for kept in ({}, defaults):
        plain = dv.build_env_lines({**dv.new_set_config(kept, "prefix-1", "dep-1"), "server_name": "localhost"})
        assert not [line for line in plain if line.split("=")[0] in given]


# --------------------------------------------------------------------------- writing it

def test_a_failed_sign_in_writes_its_record_in_the_commit_of_its_audit_row(env, factory):
    from app.core import request_context
    db = factory()
    alice = _user(db)
    request_context.set_process_default_channel("sftp")
    try:
        for name in ("alice", "no-such-name", "Alice@X.org", "nobody@x.org"):
            record_id = audit_logger.AuditLogger(db).log_login_failure(name, "203.0.113.7", "Invalid credentials")
            assert record_id is not None
    finally:
        request_context.set_process_default_channel(None)
    got = {r.name: r for r in _records(factory)}
    first = got["alice"]
    assert (first.kind, first.name, first.address, first.account_id, first.reason) == (
        srec.LOGIN, "alice", "203.0.113.7", alice.id, "Invalid credentials")
    assert got["no-such-name"].account_id is None
    assert got["Alice@X.org"].account_id == alice.id        # a sign-in by email address names its account
    assert got["nobody@x.org"].account_id is None
    assert first.channel == factory().query(AuditLog).first().channel == "sftp"
    rows = factory().query(AuditLog).filter(AuditLog.action == "login_failure").count()
    assert rows == 4


def _degraded_alerts():
    from app.core import audit_privacy as ap
    return [a for a in ap.pending_alerts() if a["reason"] == ap.RECORD_NOT_WRITTEN]


def test_a_record_that_cannot_be_written_never_costs_the_audit_row(env, factory, caplog):
    """A fault in the security_records table alone (here it is gone, so its insert fails) loses the records,
    never the audit rows written with them or the caller's answer: the methods return, the rows commit, and
    an alert without any value of the failures tells the administrators."""
    from app.core import audit_privacy as ap
    db = factory()
    alice = _user(db)
    SecurityRecord.__table__.drop(db.get_bind())
    caplog.set_level(logging.WARNING, logger=audit_logger.logger.name)
    for name in ("alice", "no-such-name"):
        assert audit_logger.AuditLogger(db).log_login_failure(name, "203.0.113.7", "Invalid credentials") is None
    audit_logger.AuditLogger(db).log_second_factor_failure(alice, ip_address="192.0.2.5", details={"method": "totp"})
    # The operational log names the error by its type alone: its text carries the statement and its values
    # (on PostgreSQL a constraint's message carries the whole failing row, the name as typed with it).
    warned = [r for r in caplog.records if r.name == audit_logger.logger.name]
    assert [r.getMessage() for r in warned] == [
        f"A {action} security record could not be written (OperationalError); its audit row was kept"
        for action in ("login_failure", "login_failure", "second_factor_failed")]
    assert [(r.exc_info, r.stack_info) for r in warned] == [(None, None)] * 3     # nor its traceback
    check = factory()
    assert check.query(AuditLog).filter(AuditLog.action == "login_failure").count() == 2
    assert check.query(AuditLog).filter(AuditLog.action == "second_factor_failed").count() == 1
    # The session that wrote them goes on as usual.
    assert db.query(User).filter(User.username == "alice").one().id == alice.id
    # One alert for the process (the cooldown folds the repeats), with the error's type and the row's action.
    assert _degraded_alerts() == [{"reason": ap.RECORD_NOT_WRITTEN, "subject": "OperationalError",
                                   "action": "login_failure"}]
    assert ap.flush_alerts(factory) == 1
    (alert,) = check.query(SecurityAlert).all()
    assert alert.event_type == ap.ALERT_EVENT and alert.details["reason"] == ap.RECORD_NOT_WRITTEN
    assert "could not be written" in alert.message and "OperationalError" in alert.message
    for value in ("alice", "no-such-name", "203.0.113.7", "192.0.2.5"):
        assert value not in repr((alert.message, alert.details, alert.username, alert.ip_address))


def test_an_audit_row_that_cannot_be_written_writes_no_record(env, factory):
    """The other way round, the failure still raises as before, and its record is not written either."""
    db = factory()
    AuditLog.__table__.drop(db.get_bind())
    with pytest.raises(sa.exc.OperationalError):
        audit_logger.AuditLogger(db).log_login_failure("alice", "203.0.113.7", "x")
    db.rollback()
    assert _records(factory) == []
    assert _degraded_alerts() == []


def test_a_failed_account_lookup_runs_under_a_savepoint_of_its_own_and_keeps_the_record(env, factory):
    """The record is written under the savepoint the failure's audit row opens for it (_add_security_record), so
    its own lookup of the account the typed name names runs under a savepoint of its own: on PostgreSQL a
    statement that fails aborts the transaction it runs in, and the record would be lost with it
    (tests/test_security_records_live.py has that on PostgreSQL). Here the record's lookup fails and notes how
    many savepoints it ran under; the record and its audit row are written all the same, without the account."""
    db = factory()
    _user(db)
    depth, queried = [0], []
    real_nested, real_query = db.begin_nested, db.query

    @contextlib.contextmanager
    def nested():
        depth[0] += 1
        try:
            with real_nested():
                yield
        finally:
            depth[0] -= 1

    def query(*entities, **kwargs):
        if sys._getframe(1).f_code.co_filename.endswith("security_records.py"):
            queried.append(depth[0])
            raise RuntimeError("the users table cannot be read")
        return real_query(*entities, **kwargs)

    db.begin_nested, db.query = nested, query
    record_id = audit_logger.AuditLogger(db).log_login_failure("alice", "203.0.113.7", "Invalid credentials")
    assert record_id is not None
    # One lookup (the name has no "@"), under _add_security_record's savepoint and one of its own.
    assert queried == [2]
    (rec,) = _records(factory)
    assert (rec.name, rec.account_id, rec.address) == ("alice", None, "203.0.113.7")
    assert factory().query(AuditLog).filter(AuditLog.action == "login_failure").count() == 1
    assert _degraded_alerts() == []


def test_the_record_keeps_full_values_whatever_the_audit_row_keeps(env, factory, monkeypatch):
    def forget(row, raw_details):
        row.username, row.ip_address = None, None

    monkeypatch.setattr(audit_row_hooks, "privacy", forget)
    db = factory()
    audit_logger.AuditLogger(db).log_login_failure("carol", "198.51.100.4", "x")
    row = factory().query(AuditLog).one()
    assert (row.username, row.ip_address) == (None, None)
    (rec,) = _records(factory)
    assert (rec.name, rec.address) == ("carol", "198.51.100.4")


def test_a_rejected_second_factor_writes_its_record_too(env, factory):
    db = factory()
    bob = _user(db, "bob")
    audit_logger.AuditLogger(db).log_second_factor_failure(bob, ip_address="192.0.2.5",
                                                          details={"method": "totp"})
    (rec,) = _records(factory)
    assert (rec.kind, rec.name, rec.account_id, rec.address, rec.reason) == (
        srec.SECOND_FACTOR, "bob", bob.id, "192.0.2.5", "second factor (totp)")
    assert factory().query(AuditLog).filter(AuditLog.action == "second_factor_failed").count() == 1


def test_the_record_indexes_the_columns_deletes_and_lookups_go_by():
    columns = SecurityRecord.__table__.c
    # The pruner deletes by time; blocks and statistics look up by address and account; deleting an alert
    # sets alert_id to NULL on its records, a scan of the table per alert without the index.
    assert [name for name in ("at", "account_id", "address", "alert_id") if not columns[name].index] == []


def test_every_place_that_audits_a_failed_sign_in_writes_the_record():
    import ast
    from app.api import api_server as api
    from app.sftp import sftp_server
    src = inspect.getsource(api)
    assert src.count("log_second_factor_failure(") == 2
    assert '"second_factor_failed"' not in src and "action=\"second_factor_failed\"" not in src
    assert inspect.getsource(sftp_server).count("audit_logger.log_login_failure(") == 2
    # Nothing else writes those rows except through the two methods that write the record with them.
    tree = ast.parse((ROOT / "app" / "services" / "audit_logger.py").read_text(encoding="utf-8"))
    writers = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
               and any(isinstance(c, ast.Constant) and c.value in ("login_failure", "second_factor_failed")
                       for c in ast.walk(n))]
    assert sorted(writers) == ["log_login_failure", "log_second_factor_failure"]


# --------------------------------------------------------------------------- the window

def _old_record(db, days, name="x"):
    db.add(SecurityRecord(id=uuid.uuid4(), at=NOW - timedelta(days=days), kind=srec.LOGIN, name=name,
                          address="203.0.113.9"))
    db.commit()


def test_records_go_after_the_window(env, factory):
    db = factory()
    for days, name in ((31, "old"), (29, "recent")):
        _old_record(db, days, name)
    done = dict(retention.run_pass(factory, now=NOW))
    assert done["security_records"].deleted == 1
    assert [r.name for r in _records(factory)] == ["recent"]
    s = factory()
    reg.store(s, srec.WINDOW_KEY, 10)                   # the pass reads the stored window itself
    s.commit()
    retention.run_pass(factory, now=NOW)
    assert _records(factory) == []


def test_the_hold_switch_stops_the_record_jobs(env, factory):
    db = factory()
    _old_record(db, 31)
    reg.store(db, retention.HOLD_KEY, True)
    db.commit()
    done = dict(retention.run_pass(factory, now=NOW))
    assert done["security_records"] is None and done["security_alert_values"] is None
    assert len(_records(factory)) == 1


# --------------------------------------------------------------------------- alerts

def _alert(db, days, *, resolved=False, username="mallory", ip="203.0.113.66",
           message=f"WARNING: 7 failures for {srec.NAME_TOKEN} from {srec.ADDRESS_TOKEN}"):
    alert = SecurityAlert(id=uuid.uuid4(), event_type="multiple_failed_logins", severity="warning",
                          message=message, username=username, ip_address=ip,
                          timestamp=NOW - timedelta(days=days), resolved=resolved, details={})
    db.add(alert)
    db.commit()
    return alert.id


def test_old_alerts_lose_their_names_and_addresses_resolved_or_not(env, factory):
    db = factory()
    open_old = _alert(db, 40)
    resolved_old = _alert(db, 40, resolved=True)
    legacy = _alert(db, 40, message="WARNING: Multiple failed login attempts - 7 failures for mallory from "
                                   "203.0.113.66")
    recent = _alert(db, 5)
    done = dict(retention.run_pass(factory, now=NOW))
    assert done["security_alert_values"].cleared == 3
    got = {a.id: a for a in factory().query(SecurityAlert).all()}
    for alert_id in (open_old, resolved_old, legacy):
        assert (got[alert_id].username, got[alert_id].ip_address) == (None, None)
        assert "mallory" not in got[alert_id].message and "203.0.113.66" not in got[alert_id].message
        assert srec.render_message(got[alert_id]) == (
            "WARNING: " + ("Multiple failed login attempts - " if alert_id == legacy else "")
            + "7 failures for (name removed) from (address removed)")
    assert (got[recent].username, got[recent].ip_address) == ("mallory", "203.0.113.66")
    (row,) = [r.details for r in factory().query(AuditLog).filter(AuditLog.action == "retention_pruned")
              if r.details["job"] == "security_alert_values"]
    assert row["cleared"] == 3


def test_a_message_is_completed_when_it_is_shown():
    alert = SimpleNamespace(message=f"for {srec.NAME_TOKEN} from {srec.ADDRESS_TOKEN}", username="eve",
                            ip_address="192.0.2.1")
    assert srec.render_message(alert) == "for eve from 192.0.2.1"
    assert srec.render_message(SimpleNamespace(message="plain", username=None, ip_address=None)) == "plain"


def test_an_alert_never_writes_the_name_or_the_address_into_its_message(env, monkeypatch):
    from app.services import security_monitor as sm
    raised = []

    class Db:
        def query(self, *_a):
            return SimpleNamespace(filter=lambda *a: SimpleNamespace(update=lambda *a, **k: raised.append("link")))

        def commit(self):
            pass

        def rollback(self):
            pass

    monitor = sm.SecurityMonitor(Db())
    monkeypatch.setattr(monitor, "_windowed_count", lambda *a, **k: 50)
    monkeypatch.setattr(monitor, "_raise_alert", lambda **kw: raised.append(kw) or SimpleNamespace(id=uuid.uuid4()))
    monitor.record_failed_login("mallory", "203.0.113.66", "bad password", record_id=uuid.uuid4())
    alert = raised[0]
    assert "mallory" not in alert["message"] and "203.0.113.66" not in alert["message"]
    assert srec.NAME_TOKEN in alert["message"] and srec.ADDRESS_TOKEN in alert["message"]
    assert (alert["username"], alert["ip_address"]) == ("mallory", "203.0.113.66")
    assert raised[1] == "link"                       # the record is linked to the alert it raised
    source = inspect.getsource(sm.SecurityMonitor)
    assert "f\"{username" not in source and "{ip_address} in {" not in source


def test_the_failed_sign_in_statistics_read_the_records(env, factory):
    from app.services import security_monitor as sm
    db = factory()
    for address in ("203.0.113.1", "203.0.113.1", "203.0.113.2"):
        db.add(SecurityRecord(id=uuid.uuid4(), at=datetime.utcnow(), kind=srec.LOGIN, name="x", address=address))
    db.add(SecurityRecord(id=uuid.uuid4(), at=datetime.utcnow(), kind=srec.SECOND_FACTOR, name="x",
                          address="203.0.113.3"))
    db.commit()
    metrics = sm.SecurityMonitor(factory()).get_security_metrics(hours=24)
    assert metrics["failed_logins"] == 3
    assert metrics["top_failed_ips"] == [{"ip": "203.0.113.1", "count": 2}, {"ip": "203.0.113.2", "count": 1}]


def test_the_alerts_list_shows_messages_completed_from_the_alerts_fields():
    from app.api import api_server as api
    source = inspect.getsource(api.get_security_alerts)
    assert '"message": render_alert_message(alert),' in source
    from app.services import security_monitor as sm
    assert "'message': render_message(alert)," in inspect.getsource(sm.SecurityMonitor._broadcast_alert)


def test_the_record_jobs_are_held_by_the_hold_switch():
    jobs = {j.name: j for j in retention.JOBS}
    assert jobs["security_records"].held and jobs["security_alert_values"].held
