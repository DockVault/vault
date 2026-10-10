"""The audit log's integrity chain (app/core/audit_integrity.py), offline, on a throwaway SQLite database:
genesis and the hour seals, runs of empty hours, late rows, rows without a nonce, the head record, the keys,
tampering of every class, and the chain events (a prune, an erase) that keep it valid."""
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_integrity as ai
from app.core.models import AuditLog, AuditSeal

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def test_an_empty_log_gets_genesis_and_its_policy_seal_then_empty_hours(env):
    r = env.seal()
    assert r.stopped is None
    seals = env.seals()
    assert [s.kind for s in seals[:2]] == ["genesis", "policy"]
    assert seals[0].detail["first_row_hour"] is None
    # On an empty log the chain's first hour is the one after the backlog: nothing to seal yet.
    env.clock.advance(hours=3)
    env.seal()
    kinds = [s.kind for s in env.seals()]
    assert kinds[2:] and set(kinds[2:]) == {"hour"}
    report = env.verify()
    assert failures(report) == [], report.findings
    assert report.head.startswith("dvchain1:")
    assert ai.status(env.st)["head"] == report.head


def test_rows_are_sealed_by_hour_after_the_lag_and_verify_clean(env):
    for h in range(5):
        env.row(T0 - timedelta(hours=10 - h, minutes=5))
        env.row(T0 - timedelta(hours=10 - h, minutes=35))
    env.row(T0 - timedelta(minutes=10))           # the current hour: not sealed yet
    env.run_until_sealed()
    seals = env.seals()
    hours = [s for s in seals if s.kind == "hour"]
    assert hours[0].period_start == ai.hour_floor(T0 - timedelta(hours=10, minutes=5))
    assert hours[-1].period_end <= ai.hour_floor(T0 - timedelta(minutes=60))
    assert sum(s.row_count for s in hours) == 10
    report = env.verify()
    assert failures(report) == [], report.findings
    assert report.rows_checked >= 10


def test_a_run_of_empty_hours_shares_one_seal(env):
    env.row(T0 - timedelta(days=40))
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    runs = [s for s in env.seals() if s.kind == "hour" and s.period_end - s.period_start > timedelta(hours=1)]
    assert runs and runs[0].row_count == 0
    assert len([s for s in env.seals() if s.kind == "hour"]) <= 4
    assert failures(env.verify()) == []


def test_the_hour_waits_for_the_lag(env):
    env.row(T0 - timedelta(minutes=30))
    env.seal()
    env.clock.at = T0 + timedelta(minutes=59)
    env.seal()
    sealed = [s for s in env.seals() if s.kind == "hour"]
    assert not any(s.period_start == ai.hour_floor(T0 - timedelta(minutes=30)) for s in sealed)
    env.clock.at = T0 + timedelta(minutes=61)
    env.seal()
    assert any(s.period_start == ai.hour_floor(T0 - timedelta(minutes=30)) and s.row_count == 1
               for s in env.seals() if s.kind == "hour")


# --------------------------------------------------------------------------- tampering

def _sealed_env(env, n=6):
    ids = [env.row(T0 - timedelta(hours=8, minutes=m)) for m in range(0, 60, 60 // n)]
    env.run_until_sealed()
    assert failures(env.verify()) == []
    return ids


def _update(env, row_id, **values):
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == row_id).update(values, synchronize_session=False)
        db.commit()


@pytest.mark.parametrize("column,value,which", [
    ("action", "logout", "stable fields"),
    ("status", "failure", "stable fields"),
    ("resource_id", "x", "stable fields"),
    ("username", "mallory", "personal values"),
    ("ip_address", "198.51.100.1", "personal values"),
    ("endpoint", "/other", "personal values"),
    ("error_message", "nothing", "personal values"),
])
def test_a_changed_field_of_each_class_is_found(env, column, value, which):
    ids = _sealed_env(env)
    _update(env, ids[2], **{column: value})
    report = env.verify()
    found = [f for f in report.findings if f.kind == "rows-altered"]
    assert found and which in found[0].message


def test_a_changed_detail_is_found_and_a_respelling_is_not(env):
    ids = _sealed_env(env)
    with env.engine.begin() as conn:
        conn.exec_driver_sql("UPDATE audit_logs SET details = ? WHERE id = ?", ('{ "n" : 1 }', ids[1].hex))
    assert failures(env.verify()) == []
    with env.engine.begin() as conn:
        conn.exec_driver_sql("UPDATE audit_logs SET details = ? WHERE id = ?", ('{"n": 2}', ids[1].hex))
    assert "rows-altered" in failures(env.verify())


def test_a_deleted_row_and_an_inserted_row_are_named(env):
    ids = _sealed_env(env)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[0]).delete()
        db.commit()
    report = env.verify()
    missing = [f for f in report.findings if f.kind == "rows-missing"]
    assert missing and str(ids[0]) in missing[0].message
    env.row(T0 - timedelta(hours=8, minutes=1))
    report = env.verify()
    assert "rows-added" in failures(report)


def test_two_rows_swapping_values_are_found(env):
    ids = _sealed_env(env)
    _update(env, ids[0], username="bob")
    _update(env, ids[1], username="alice")
    with env.session() as db:
        names = dict(db.query(AuditLog.id, AuditLog.username).filter(AuditLog.id.in_(ids[:2])).all())
    _update(env, ids[1], username="bob")
    assert "rows-altered" in failures(env.verify())


def test_an_edited_seal_body_breaks_its_link_and_stops_sealing(env):
    _sealed_env(env)
    hour = [s for s in env.seals() if s.kind == "hour" and s.row_count][0]
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == hour.seq).update({AuditSeal.row_bytes: 2 ** 60})
        db.commit()
    report = env.verify()
    assert "link-broken" in failures(report) and "head-record-mismatch" in failures(report)
    env.fresh_process()
    env.clock.advance(hours=2)
    r = env.seal()
    assert r.stopped == "head-record-mismatch"


def test_seals_cut_from_the_tail_stop_sealing_and_nothing_is_resealed(env):
    _sealed_env(env)
    newest = env.seals()[-1].seq
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq >= newest - 1).delete()
        db.commit()
    env.clock.advance(hours=2)
    r = env.seal()
    assert r.stopped == "head-record-mismatch"
    assert env.seals()[-1].seq == newest - 2
    assert "head-record-mismatch" in failures(env.verify())


def test_every_seal_deleted_never_runs_genesis_again(env):
    _sealed_env(env)
    with env.session() as db:
        db.query(AuditSeal).delete()
        db.commit()
    env.fresh_process()
    r = env.seal()
    assert r.stopped == "head-record-mismatch"
    assert env.seals() == []


def test_a_seal_forged_without_the_key_is_refused(env):
    _sealed_env(env)
    last = env.seals()[-1]
    view = env.st.view
    body = ai.Seal(last.seq + 1, "ack", None, None, fmt.FORMAT, 0, 0, None, None, None,
                   {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin", "user_id": None,
                    "request": None}, last.key_id, env.clock())
    link = fmt.link(view.link_at(last.seq), body.body())
    with env.session() as db:
        db.add(AuditSeal(seq=body.seq, kind="ack", format=1, row_count=0, row_bytes=0, detail=body.detail,
                         key_id=last.key_id, sealed_at=body.sealed_at, mac=b"\x00" * 32, link=link))
        db.commit()
    env.clock.advance(hours=2)
    assert env.seal().stopped == "mac-invalid"
    assert "mac-invalid" in failures(env.verify())


def test_a_stored_link_edited_alone_is_link_broken_and_nothing_else(env):
    _sealed_env(env)
    seal = env.seals()[3]
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == seal.seq).update({AuditSeal.link: b"\x01" * 32})
        db.commit()
    assert failures(env.verify()) == ["link-broken"]


def test_a_chain_rewritten_under_a_made_up_key_stops_the_sealer(env):
    _sealed_env(env)
    import hashlib
    fake = fmt.chain_key("z" * 64)
    fake_id = fmt.key_id(fake)
    prev = fmt.LINK_0
    with env.session() as db:
        for s in db.query(AuditSeal).order_by(AuditSeal.seq).all():
            s.key_id = fake_id
            seal = ai.Seal(s.seq, s.kind, s.period_start, s.period_end, s.format, s.row_count, s.row_bytes,
                           s.root_s, s.root_c, s.ids_digest, s.detail, fake_id, s.sealed_at)
            link = fmt.link(prev, seal.body())
            s.link, s.mac = link, fmt.mac(fake, link)
            prev = link
        db.commit()
    env.fresh_process()
    env.clock.advance(hours=2)
    assert env.seal().stopped == "head-record-mismatch"
    assert "head-record-mismatch" in failures(env.verify())
    assert hashlib


def test_rows_dated_before_genesis_or_ahead_are_found(env):
    _sealed_env(env)
    env.row(T0 - timedelta(days=400))
    env.row(T0 + timedelta(days=30))
    kinds = failures(env.verify())
    assert "row-before-genesis" in kinds and "future-dated" in kinds
    env.clock.advance(hours=2)
    env.seal()
    rec = env.st.head_store().load()
    assert {"row-before-genesis", "future-dated"} <= set(rec["failures"])


# --------------------------------------------------------------------------- late rows

def test_a_row_arriving_within_six_hours_is_sealed_late_and_stays_a_warning(env):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    late_id = env.row(hour + timedelta(minutes=20))
    env.clock.advance(hours=1)
    r = env.seal()
    assert r.late == 1
    late = [s for s in env.seals() if s.kind == "late"]
    assert late and late[0].detail["added"] == [str(late_id)]
    report = env.verify()
    assert failures(report) == []
    assert "late" in report.kinds("warning")
    assert "late" in ai.status(env.st)["warnings"]
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.action == ai.LATE_ACTION).count() == 1


def test_a_row_arriving_after_six_hours_is_a_failure(env):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    env.clock.advance(hours=7)
    env.seal()
    env.row(ai.hour_floor(T0 - timedelta(hours=3)) + timedelta(minutes=20))
    env.clock.advance(minutes=30)
    r = env.seal()
    assert r.late == 0
    assert "rows-added" in failures(env.verify())


def test_a_late_row_in_an_hour_inside_a_run_reroots_that_hour_alone(env):
    env.row(T0 - timedelta(hours=9, minutes=10))
    env.run_until_sealed()
    runs = [s for s in env.seals() if s.kind == "hour" and s.period_end - s.period_start > timedelta(hours=1)]
    assert runs
    inside = runs[-1].period_start + timedelta(hours=1)
    env.clock.advance(minutes=20)
    env.row(inside + timedelta(minutes=5))
    r = env.seal()
    assert r.late == 1
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- rows without a nonce

def test_rows_without_a_nonce_get_their_hours_salt(env):
    for m in (5, 25, 45):
        env.row(T0 - timedelta(hours=6, minutes=m), nonce=False)
    env.run_until_sealed()
    hour = [s for s in env.seals() if s.kind == "hour" and s.row_count][0]
    assert hour.legacy_salt is not None and len(hour.legacy_salt) == 32
    assert failures(env.verify()) == []
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == hour.seq).update({AuditSeal.legacy_salt: None})
        db.commit()
    assert "nonce-missing" in failures(env.verify())


# --------------------------------------------------------------------------- the nonce

def test_build_row_gives_every_row_a_random_nonce():
    from app.services.audit_logger import AuditLogger

    class _Db:
        def query(self, *a, **k):
            raise AssertionError("not needed")

    a = AuditLogger(_Db()).build_row(action="logout", status="success", username="x")
    b = AuditLogger(_Db()).build_row(action="logout", status="success", username="x")
    assert isinstance(a.seal_nonce, bytes) and len(a.seal_nonce) == 16 and a.seal_nonce != b.seal_nonce


def test_rows_changed_with_a_late_row_are_never_sealed_over(env):
    first = env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    env.row(ai.hour_floor(T0 - timedelta(hours=3, minutes=10)) + timedelta(minutes=20))   # the same hour
    _update(env, first, username="mallory")
    env.clock.advance(hours=1)
    assert env.seal().late == 0
    assert {"rows-added", "rows-altered"} <= set(failures(env.verify()))


def test_a_row_added_to_the_backlog_before_its_hour_is_sealed_is_found(env):
    for h in (30, 20, 10):
        env.row(T0 - timedelta(hours=h))
    r = ai.seal_pass(env.session, engine=env.engine, st=env.st, now=env.clock(), time_left=lambda: False)
    assert r.stopped is None and [s.kind for s in env.seals()] == ["genesis", "policy"]
    assert env.seals()[0].detail["backlog_rows"] == 3
    env.row(T0 - timedelta(hours=25))           # inserted into the backlog before its hour is sealed
    env.run_until_sealed()
    assert "backlog-count" in failures(env.verify())


def test_a_fresh_install_has_no_backlog(env):
    env.seal()
    assert env.st.backlog is False                 # nothing before the first row's hour: normal passes


def test_an_old_log_is_sealed_with_passes_close_together(monkeypatch, tmp_path):
    from _audit_chain_env import Env
    from app.core import retention
    e = Env(monkeypatch, tmp_path)
    try:
        for h in range(3):
            e.row(T0 - timedelta(days=3, hours=h))
        ai.seal_pass(e.session, engine=e.engine, st=e.st, now=e.clock(), time_left=lambda: False)
        assert e.st.backlog is True
        assert retention.interval_seconds() == retention.BACKLOG_PAUSE_SECONDS
        e.run_until_sealed()
        assert e.st.backlog is False
    finally:
        e.close()


def test_the_host_command_runs_the_module_without_registering_its_settings_twice(monkeypatch):
    import runpy
    from app.core import audit_chain_verify
    monkeypatch.setattr(audit_chain_verify, "main", lambda argv=None: 0)
    with pytest.raises(SystemExit) as done:
        runpy.run_module("app.core.audit_integrity", run_name="__main__")
    assert done.value.code == 0


def test_a_chain_started_after_its_first_rows_reports_no_backlog(env):
    env.row(T0 - timedelta(minutes=10))
    env.seal()
    info = env.verify().kinds("information")
    assert "backlog-in-progress" not in info and "sealing-behind" in info


def test_a_reader_under_the_chain_lock_waits_for_a_writer_of_its_own_process(env):
    """A reader's chain lock takes the process's own writers' mutex as well as the advisory lock: without a database
    lock (the offline database) the mutex is all that keeps a writer of the same process from committing between the
    reader's snapshot and its read of the head record. While a writer holds it, the reader waits, then is told to
    retry; once it is free, the reader takes it."""
    env.seal()
    assert env.st.mutex.acquire(timeout=1)
    try:
        with pytest.raises(ai.ChainBusy):
            with ai.chain_lock(env.engine, env.st, wait=0.2):
                pytest.fail("the reader took the lock a writer holds")
    finally:
        env.st.mutex.release()
    with ai.chain_lock(env.engine, env.st, wait=1):
        assert not env.st.mutex.acquire(blocking=False)       # the reader holds it now
    assert env.st.mutex.acquire(blocking=False)
    env.st.mutex.release()
