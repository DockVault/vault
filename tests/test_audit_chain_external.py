"""Sealing over rows a release without the chain removed (app/core/audit_chain_external.py), offline: a rollback
to a release that prunes by time, then back; the acknowledgment accepts exactly a time cutoff as old as the
stated retention, and refuses a targeted deletion, a later row missing, a cutoff too recent, and rows that
change between its two phases.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures, host_rows
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
    st.process_kind = "host"
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
    # One audit row a day, each saying what its prune seal sealed over.
    assert sorted(host_rows(env, external.ACTION), key=lambda r: r["day"]) == [
        {"day": p.detail["hours"][0][0][:10], "hours": len(p.detail["hours"]), "cutoff": p.detail["cutoff"]["hour"],
         "retention_days": 34} for p in prunes]
    report = env.verify()
    assert failures(report) == []
    # Reported for good, each prune with its reason and what it removed.
    pruned = [f for f in report.findings if f.kind == "pruned"]
    assert [f.seq for f in pruned] == [p.seq for p in prunes]
    assert all(f.severity == "information" and "external prune of" in f.message for f in pruned)
    with env.session() as db:
        gone = len(_ids) - db.query(AuditLog).filter(AuditLog.id.in_(_ids)).count()
    assert gone and sum(int(f.message.split(" rows removed")[0].split(", ")[-1]) for f in pruned) == gone
    env.clock.advance(hours=1)
    assert env.seal().stopped is None


def test_the_hours_a_removal_re_roots_keep_their_nonces_and_lose_their_salt(env):
    """Rows written without a nonce (before the upgrade) in the hours an older release cut by time: the prune
    seal that seals over the removal writes each kept row's derived nonce into the row and deletes the hour's
    salt in the same transaction, as every change to such an hour does; an hour it does not change keeps its
    salt, and every row still verifies."""
    hour = ai.hour_floor(T0 - timedelta(days=33, hours=3))
    earlier = hour - timedelta(hours=6)
    for m in (5, 35):
        env.row(earlier + timedelta(minutes=m), nonce=False)
    env.row(hour + timedelta(minutes=10), nonce=False)
    kept = env.row(hour + timedelta(minutes=50), nonce=False)
    later = ai.hour_floor(T0 - timedelta(days=30))
    env.row(later + timedelta(minutes=20), nonce=False)
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=1))
    env.clock.advance(days=2)                            # the older release ran
    with env.session() as db:
        salts = {h: bytes(ai.working_row(db, h).legacy_salt) for h in (earlier, hour, later)}
        db.query(AuditLog).filter(AuditLog.timestamp < hour + timedelta(minutes=30)).delete()
        db.commit()
    env.seal()
    _seen, done = _removal(env, hour + timedelta(minutes=50), 34)
    assert done["sealed"] and done["hours"] == 2
    with env.session() as db:
        assert ai.working_row(db, earlier).legacy_salt is None and ai.working_row(db, hour).legacy_salt is None
        assert bytes(ai.working_row(db, later).legacy_salt) == salts[later]
        assert bytes(db.get(AuditLog, kept).seal_nonce) == fmt.legacy_nonce(salts[hour], kept)
    assert failures(env.verify()) == []


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


def test_a_row_added_to_a_sealed_hour_is_no_removal(env):
    _ids, cutoff = _rolled_back(env)
    env.row(T0 - timedelta(days=30, hours=3, minutes=-20))
    with pytest.raises(host.Refused, match="holds rows its seal does not"):
        external.acknowledge_removed_before(env.engine, _host(env), _first_kept_time(env, cutoff),
                                            retention_days=34, read=True)


def test_a_row_changed_in_an_hour_after_the_cutoff_is_no_removal(env):
    _ids, cutoff = _rolled_back(env)
    with env.session() as db:
        newest = db.query(AuditLog).filter(AuditLog.action == "file_uploaded").order_by(
            AuditLog.timestamp.desc()).first()
        newest.ip_address = "198.51.100.1"
        db.commit()
    with pytest.raises(host.Refused, match="does not check out against its seal"):
        external.acknowledge_removed_before(env.engine, _host(env), _first_kept_time(env, cutoff),
                                            retention_days=34, read=True)


def test_rows_missing_from_the_middle_of_the_cutoff_hour_are_no_time_cutoff(env):
    first = env.row(T0 - timedelta(days=33, hours=3))
    middle = env.row(T0 - timedelta(days=33, hours=3, minutes=-10))
    env.row(T0 - timedelta(days=33, hours=3, minutes=-20))
    env.row(T0 - timedelta(days=32, hours=3))
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=1))
    env.clock.advance(days=2)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == middle).delete()
        db.commit()
    env.seal()
    with pytest.raises(host.Refused, match="not its first ones"):
        external.acknowledge_removed_before(env.engine, _host(env), T0 - timedelta(days=33, hours=3),
                                            retention_days=30, read=True)
    assert first is not None


def test_rows_changed_between_the_days_of_the_write_stop_it(env, monkeypatch):
    """The write seals one day per transaction, each reading its hours again: a row put into an hour of the last
    day after the first day's seal makes that day refuse, naming the seals written so far."""
    _ids, cutoff = _rolled_back(env)
    before = _first_kept_time(env, cutoff)
    seen = external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=34, read=True)
    real = external.host_audit_row
    calls = []

    def after_the_first_day(db, action, details, status="success"):
        calls.append(details["day"])
        if len(calls) == 1:
            env.row(T0 - timedelta(days=31, hours=3, minutes=-5))      # an hour of the last day
        return real(db, action, details, status)
    monkeypatch.setattr(external, "host_audit_row", after_the_first_day)
    with pytest.raises(host.Refused, match="changed while its removal was being sealed"):
        external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=34,
                                            expect=seen["state"])
    prunes = [s for s in env.seals() if s.kind == "prune"]
    assert len(calls) >= 1 and len(prunes) == len(calls)
    last_hour = fmt.hour_text(ai.hour_floor(T0 - timedelta(days=31, hours=3)))
    assert not any(h[0] == last_hour for p in prunes for h in p.detail["hours"])
