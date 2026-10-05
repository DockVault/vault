"""The marker that keeps an earlier release from starting while the levels record less (app/core/recording_marker.py).

While the newest version of the recording levels records less of any kind than earlier releases did, a row in
data_requirements names the release that introduced the levels, why, and how to undo it; it goes when the levels
are set back. It is kept in the transaction that writes each version, at each start and once a day. The upgrade
condition's detect query says the same. Rows an earlier release wrote after the levels began are flagged.
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

from app.core import audit_privacy as ap  # noqa: E402
from app.core import recording_marker as rm  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, AuditPrivacyPolicy, Notification, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    rm._reset_for_tests()
    yield
    rm._reset_for_tests()


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'marker.db'}")
        for model in (User, AuditLog, AuditPrivacyPolicy, Notification):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _marker(factory):
    db = factory()
    try:
        if not sa.inspect(db.bind).has_table("data_requirements"):
            return None
        row = db.execute(sa.text("SELECT key, requires_at_least, reason, undo, since FROM data_requirements")).all()
        return row[0] if row else None
    finally:
        db.close()


@pytest.mark.parametrize("change,less", [
    ({}, False), ({"names": "fingerprint"}, False), ({"names": "full"}, False), ({"ip": "shortened"}, True),
    ({"emails": "none"}, True), ({"signin_names": "fingerprint"}, True), ({"user_agent": "none"}, True)])
def test_what_records_less_than_earlier_releases(change, less):
    assert rm.records_less({**ap.POLICY_ONE, **change}) is less


def test_the_marker_comes_and_goes_with_the_versions(factory, monkeypatch):
    monkeypatch.setattr(rm, "running_version", lambda: "0.34.0")
    ap.prepare(factory)
    assert _marker(factory) is None
    db = factory()
    ap.lock_policies(db)
    ap.write_version(db, {**ap.POLICY_ONE, "ip": "shortened"}, previous=ap.read_latest(db), reason="admin")
    db.commit()
    key, version, reason, undo, since = _marker(factory)
    assert (key, version) == ("recording-levels", "0.34.0")
    assert "record less" in reason and "Settings, Activity and records" in undo and "AUDIT_MAX_" in undo
    assert since is not None
    # A second version that records less keeps the one marker.
    db = factory()
    ap.write_version(db, {**ap.POLICY_ONE, "ip": "none"}, previous=ap.read_latest(db), reason="admin")
    db.commit()
    assert _marker(factory)[:2] == ("recording-levels", "0.34.0")
    db = factory()
    assert db.execute(sa.text("SELECT count(*) FROM data_requirements")).scalar() == 1
    ap.write_version(db, {**ap.POLICY_ONE, "names": "full"}, previous=ap.read_latest(db), reason="admin")
    db.commit()
    assert _marker(factory) is None


def test_a_version_rolled_back_leaves_no_marker(factory):
    ap.prepare(factory)
    db = factory()
    ap.write_version(db, {**ap.POLICY_ONE, "emails": "none"}, previous=ap.read_latest(db), reason="admin")
    db.rollback()
    db.close()
    assert _marker(factory) is None


def test_a_lowered_limit_at_the_start_writes_the_marker(factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_user_agent", "none")
    ap.prepare(factory)
    assert _marker(factory)[0] == "recording-levels"


def test_each_start_puts_back_a_marker_that_went_missing(factory):
    ap.prepare(factory)
    db = factory()
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **{**ap.POLICY_ONE, "ip": "none"}))
    db.commit()
    db.close()
    assert _marker(factory) is None
    ap.prepare(factory)
    assert _marker(factory)[0] == "recording-levels"


def test_the_detect_query_reads_the_newest_version(factory):
    ap.prepare(factory)
    db = factory()
    assert rm.stricter_now(db) is False
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **{**ap.POLICY_ONE, "signin_names": "fingerprint"}))
    db.commit()
    assert rm.stricter_now(db) is True
    db.add(AuditPrivacyPolicy(version=3, reason="admin", **ap.POLICY_ONE))
    db.commit()
    assert rm.stricter_now(db) is False
    assert "max(version)" in rm.STRICTER_SQL
    db.close()


@pytest.mark.parametrize("running,required", [("0.34.0", "0.34.0"), ("0.35.2", "0.34.0"), ("0.33.0", "0.33.0"),
                                              ("", "0.34.0"), ("next", "0.34.0"), ("1.0.0", "0.34.0")])
def test_the_version_the_marker_asks_for(running, required):
    assert rm.required_version(running) == required


def test_the_daily_check_runs_once_a_day_and_never_raises(factory):
    ap.prepare(factory)
    db = factory()
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **{**ap.POLICY_ONE, "ip": "none"}))
    db.commit()
    db.close()
    assert rm.check_daily(factory, now=1000.0) is True
    db = factory()
    db.add(AuditPrivacyPolicy(version=3, reason="admin", **ap.POLICY_ONE))
    db.commit()
    db.close()
    assert rm.check_daily(factory, now=1000.0 + rm.CHECK_SECONDS - 1) is None
    assert _marker(factory) is not None
    assert rm.check_daily(factory, now=1000.0 + rm.CHECK_SECONDS) is False
    assert _marker(factory) is None

    def down():
        raise RuntimeError("no database")

    rm._reset_for_tests()
    assert rm.check_daily(down, now=5.0) is None


def test_the_table_has_the_columns_the_reader_reads():
    for ddl in (rm._DDL_POSTGRES, rm._DDL_OTHER):
        for column in ("key VARCHAR(64) PRIMARY KEY", "requires_at_least VARCHAR(32) NOT NULL", "reason TEXT NOT NULL",
                       "undo TEXT", "since TIMESTAMP NOT NULL"):
            assert column in ddl
    assert "DEFAULT (now() AT TIME ZONE 'utc')" in rm._DDL_POSTGRES


def test_a_row_an_earlier_release_wrote_after_the_levels_began_is_flagged(monkeypatch):
    from app.services.activity_events import recorded_by_earlier_release
    began = datetime(2026, 10, 1, 12, 0, 0)
    monkeypatch.setattr(ap._cache, "began", began)
    row = lambda ts, v=None: SimpleNamespace(timestamp=ts, privacy_version=v)  # noqa: E731
    assert recorded_by_earlier_release(row(began + timedelta(seconds=1))) is True
    assert recorded_by_earlier_release(row(began - timedelta(seconds=1))) is False
    assert recorded_by_earlier_release(row(began + timedelta(days=1), 2)) is False
    monkeypatch.setattr(ap._cache, "began", None)
    assert recorded_by_earlier_release(row(began + timedelta(days=1))) is False


def test_the_start_reads_when_the_levels_began(factory):
    ap.prepare(factory)
    db = factory()
    first = db.query(AuditPrivacyPolicy.created_at).filter(AuditPrivacyPolicy.version == 1).scalar()
    db.close()
    assert ap.levels_began() == first is not None
