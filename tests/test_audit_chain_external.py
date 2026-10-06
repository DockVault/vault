"""Sealing over rows a release without the chain removed (app/core/audit_chain_external.py), offline: a rollback
to a release that prunes by time, then back; the acknowledgment accepts exactly a time cutoff as old as the
stated retention, and refuses a targeted deletion, a later row missing, a cutoff too recent, and rows that
change between its two phases.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_external as external
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_integrity as ai
from app.core.models import AuditLog
from test_audit_chain_trust import _run_to

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _host(env):
    st = ai.ChainState(settings=env.settings, clock=env.clock)
    st.role = "host"
    return st


def _rolled_back(env, keep_days=34):
    """Rows over four days, sealed; then 0.33.x runs for two days with AUDIT_LOG_RETENTION_DAYS=keep_days and
    prunes by time; then 0.34.x again. Returns (ids, cutoff time the old release used)."""
    ids = []
    for d in range(4):
        for h in (3, 9, 15):
            ids.append(env.row(T0 - timedelta(days=33 - d, hours=h)))
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=1))
    env.clock.advance(days=2)                            # the older release ran
    cutoff = env.clock() - timedelta(days=keep_days)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.timestamp < cutoff, AuditLog.action == "file_uploaded").delete()
        db.commit()
    env.seal()
    assert "rows-missing" in failures(env.verify())
    return ids, cutoff


def _removal(env, before, days, **kw):
    seen = external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=days, read=True)
    return seen, external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=days,
                                                     expect=seen["state"], **kw)


def _first_kept_time(env, cutoff):
    with env.session() as db:
        return db.query(AuditLog.timestamp).filter(AuditLog.timestamp >= cutoff,
                                                   AuditLog.action == "file_uploaded").order_by(
            AuditLog.timestamp).first()[0]


def test_a_rollback_prune_is_sealed_over_once_its_shape_and_age_check_out(env):
    _ids, cutoff = _rolled_back(env)
    before = _first_kept_time(env, cutoff)
    seen, done = _removal(env, before, 34)
    assert done["sealed"] and any("sealed count, count now" in ln for ln in seen["lines"])
    prunes = [s for s in env.seals() if s.kind == "prune"]
    assert prunes and all(p.detail["reason"] == "external" and p.detail["by"] == "host" for p in prunes)
    assert prunes[-1].detail["cutoff"]["retention_days"] == 34
    report = env.verify()
    assert failures(report) == []
    env.clock.advance(hours=1)
    assert env.seal().stopped is None


def test_a_cutoff_more_recent_than_the_stated_retention_allows_is_refused(env):
    _ids, cutoff = _rolled_back(env)
    before = _first_kept_time(env, cutoff)
    with pytest.raises(host.Refused, match="too recent"):
        external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=40, read=True)


def test_a_targeted_deletion_is_refused(env):
    ids = []
    for h in (3, 9, 15):
        ids.append(env.row(T0 - timedelta(days=33, hours=h)))
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=1))
    env.clock.advance(days=2)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[1]).delete()      # the middle one only
        db.commit()
    env.seal()
    with pytest.raises(host.Refused, match="not a time cutoff"):
        external.acknowledge_removed_before(env.engine, _host(env), T0 - timedelta(days=33, hours=9),
                                            retention_days=30, read=True)


def test_a_later_row_missing_is_refused(env):
    ids, cutoff = _rolled_back(env)
    with env.session() as db:
        kept = db.query(AuditLog.id, AuditLog.timestamp).filter(AuditLog.timestamp >= cutoff,
                                                                AuditLog.action == "file_uploaded").order_by(
            AuditLog.timestamp).all()
        db.query(AuditLog).filter(AuditLog.id == kept[-1][0]).delete()
        db.commit()
    with pytest.raises(host.Refused, match="lost rows"):
        external.acknowledge_removed_before(env.engine, _host(env), _first_kept_time(env, cutoff),
                                            retention_days=34, read=True)


def test_a_row_deleted_between_the_phases_makes_the_write_refuse(env):
    _ids, cutoff = _rolled_back(env)
    before = _first_kept_time(env, cutoff)
    seen = external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=34, read=True)
    with env.session() as db:
        first = db.query(AuditLog).filter(AuditLog.timestamp == before).first()
        db.delete(first)
        db.commit()
    with pytest.raises(host.Refused):
        external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=34, expect=seen["state"])
    assert not [s for s in env.seals() if s.kind == "prune"]


def test_with_no_stop_in_the_chain_nothing_is_acknowledged(env):
    ids = [env.row(T0 - timedelta(days=5, hours=h)) for h in (3, 9)]
    env.run_until_sealed()
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[1]).delete()
        db.commit()
    with pytest.raises(host.Refused, match="no period in which no seal was written"):
        external.acknowledge_removed_before(env.engine, _host(env), T0 - timedelta(days=5, hours=3),
                                            retention_days=1, read=True)
