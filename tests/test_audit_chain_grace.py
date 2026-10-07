"""After a restore, and while one is not finished, nothing is deleted; the chain's hold stops every job over
logs (app/core/audit_integrity.py ChainState.holds_deletion, app/core/retention.py chain_holds), offline:

- while a restore mark lies beside the head record (dockvault.py restore wrote it, accept-restore removes it),
  the pruner deletes nothing, the waiting changes do not apply, and the status says restore-pending;
- a restore seal's grace: nothing is deleted before its grace_until plus the gaps after it, and verify rejects
  an applies or a prune sealed inside it;
- the hold switch in the chain holds the security jobs too, whatever the database says.

Runs on a throwaway SQLite database (the fixtures of tests/test_retention.py)."""
import os
import uuid
from datetime import timedelta

import pytest

from app.core import audit_chain_format as fmt
from app.core import audit_chain_verify as v
from app.core import audit_head_record as hr
from app.core import audit_integrity as ai
from app.core import retention
from app.core import settings_registry as reg
from app.core.models import AuditLog, AuditSeal, SecurityAlert
from test_retention import (NOW, OLD, _CHAIN, _alert, _audit, _count, _pass, _retention_days, chain, env,  # noqa: F401
                            factory)

pytestmark = pytest.mark.unit


def _mark(at=NOW):
    st = _CHAIN[-1].st
    hr.write_mark(st.head_store().path, {"at": fmt.time_text(at), "bundle": "dockvault-x-20261020", "record": None})


def _unmark():
    hr.remove_mark(_CHAIN[-1].st.head_store().path)


def test_a_restore_mark_holds_every_deletion_and_shows_restore_pending(env, factory):
    db = factory()
    _audit(db, OLD, n=2)
    _alert(db, OLD, True)
    _retention_days(env, 30)
    _mark()
    done = _pass(factory)
    assert done["audit_logs"] is None and done["security_alerts"] is None
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 2
    assert _count(factory, SecurityAlert) == 1
    status = ai.status(_CHAIN[-1].st)
    assert "restore-pending" in status["warnings"]
    assert _CHAIN[-1].st.holds_deletion().startswith("a restore is not finished")
    _unmark()
    done = _pass(factory, now=NOW + timedelta(minutes=30))
    assert done["security_alerts"].deleted == 1
    assert "restore-pending" not in ai.status(_CHAIN[-1].st)["warnings"]


def test_an_unreadable_mark_still_holds(env, factory):
    st = _CHAIN[-1].st
    _CHAIN[-1].seal_all(NOW)
    path = hr.mark_path(st.head_store().path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    assert st.restore_mark() == {"unreadable": "JSONDecodeError"}
    assert st.holds_deletion()


def _restore_seal(grace_days=7, at=None):
    """A restore seal the server's own writer appends (as accept-database-head writes one)."""
    c = _CHAIN[-1]
    if at is not None:
        c.at(at)
    grace = c.clock() + timedelta(days=grace_days)
    with ai.ChainWriter(ai._engine_of(c.factory), c.st) as w:
        detail = {"cause": "database", "lost_from_seq": None, "lost_through_seq": None, "lost_head": None,
                  "record_missing": False, "under_left_key": None, "grace_until": fmt.time_text(grace),
                  "acknowledges": [], "hours": {"lost": None, "compared_from": None, "changed": [],
                                                "days_changed": [], "deleted_through_seq": None},
                  "lost": {"policy": None, "cancels": [], "erases": []}, "by": "host"}
        return w.append("restore", detail=detail).seq, grace


def test_nothing_is_deleted_before_the_grace_ends_plus_the_gaps_after_it(env, factory):
    db = factory()
    _audit(db, OLD, n=2)
    _retention_days(env, 30)
    _CHAIN[-1].seal_all(NOW)
    _seq, grace = _restore_seal()
    _pass(factory, now=NOW + timedelta(minutes=30))
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 2
    # Passes every six hours up to a day before the grace's end, then a stop of two days: the grace ends that
    # much later than it says.
    t = NOW + timedelta(hours=6)
    last = t
    while t < grace - timedelta(days=1):
        _pass(factory, now=t)
        last = t
        t += timedelta(hours=6)
    t = last + timedelta(days=2)
    _pass(factory, now=t)
    end = grace + (t - last)
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 2
    while t + timedelta(hours=6) < end - timedelta(hours=2):
        t += timedelta(hours=6)
        _pass(factory, now=t)
    _pass(factory, now=end - timedelta(hours=2))
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 2
    _pass(factory, now=end + timedelta(hours=2))
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 0


def _verify_off(factory):
    db = factory()
    return v.verify(db, record=None, held={}, check_rows=False)


def test_verify_rejects_a_prune_sealed_inside_a_grace(env, factory):
    db = factory()
    _audit(db, OLD, n=2)
    _retention_days(env, 30)
    _CHAIN[-1].seal_all(NOW)
    _restore_seal()
    c = _CHAIN[-1]
    c.at(NOW + timedelta(hours=1))
    newest = c.st.view.newest_policy()
    hour = next(iter(c.st.view.single_hours()))
    root = ai.hour_root(db, c.st.view, hour)
    with ai.ChainWriter(ai._engine_of(c.factory), c.st) as w:
        w.append("prune", detail={"reason": "retention", "policy_seq": newest[0], "request_seq": None,
                                  "hours": [[fmt.hour_text(hour), root.seq, root.count, root.bytes, root.root_s.hex(),
                                             root.root_c.hex(), root.ids_digest.hex()]]})
    found = [f.message for f in _verify_off(factory).findings if f.kind == "unjustified"]
    assert any("inside the grace" in m for m in found), found


def test_the_chains_hold_holds_the_security_jobs_whatever_the_database_says(env, factory):
    db = factory()
    _alert(db, OLD, True)
    _CHAIN[-1].seal_all(NOW)
    from app.core import audit_chain_policy_seals as ps
    from app.core.models import RoleEnum, User
    admin = User(id=uuid.uuid4(), username="ada", email="ada@x.org", password_hash="x", role=RoleEnum.ADMIN,
                 is_active=True)
    db.add(admin)
    db.commit()
    with ps.change_transaction(ai._engine_of(factory)) as w:
        assert ps.change(w, retention.HOLD_KEY, True, admin, now=NOW).status == "applied"
    reg.store(db, retention.HOLD_KEY, False)     # the database says off, without a seal
    db.commit()
    done = _pass(factory, now=NOW + timedelta(minutes=30))
    assert done["security_alerts"] is None
    assert _count(factory, SecurityAlert) == 1


# --------------------------------------------------------------------------- a process that has just started

def _fresh_process():
    """The same database and head record, read by a process that has just started: its view is empty until a
    pass reads the chain."""
    c = _CHAIN[-1]
    c.st = ai.ChainState(settings=c.st.settings, clock=c.clock)
    ai.set_state(c.st)
    return c.st


def test_a_process_that_has_just_started_holds_the_log_jobs_during_a_grace(env, factory):
    db = factory()
    _alert(db, OLD, True)
    _CHAIN[-1].seal_all(NOW)
    _restore_seal()
    assert _fresh_process().view.position == 0
    done = _pass(factory, now=NOW + timedelta(minutes=30))
    assert done["security_alerts"] is None and done["audit_logs"] is None, done
    assert _count(factory, SecurityAlert) == 1


def test_a_process_that_has_just_started_holds_the_log_jobs_by_the_chains_hold(env, factory):
    db = factory()
    _alert(db, OLD, True)
    _CHAIN[-1].seal_all(NOW)
    from app.core import audit_chain_policy_seals as ps
    from app.core.models import RoleEnum, User
    admin = User(id=uuid.uuid4(), username="ada", email="ada@x.org", password_hash="x", role=RoleEnum.ADMIN,
                 is_active=True)
    db.add(admin)
    db.commit()
    with ps.change_transaction(ai._engine_of(factory)) as w:
        assert ps.change(w, retention.HOLD_KEY, True, admin, now=NOW).status == "applied"
    reg.store(db, retention.HOLD_KEY, False)     # the database says off, without a seal
    db.commit()
    _fresh_process()
    done = _pass(factory, now=NOW + timedelta(minutes=30))
    assert done["security_alerts"] is None, done
    assert _count(factory, SecurityAlert) == 1


def test_a_chain_this_process_cannot_read_holds_the_log_jobs_and_one_not_started_holds_nothing(env, factory):
    db = factory()
    _alert(db, OLD, True)
    _CHAIN[-1].seal_all(NOW)
    os.remove(_CHAIN[-1].st.head_store().path)       # the head record lost: sealing stops before reading
    st = _fresh_process()
    done = _pass(factory, now=NOW + timedelta(minutes=30))
    assert st.stopped is not None and st.view.position == 0
    assert done["security_alerts"] is None, done
    assert _count(factory, SecurityAlert) == 1
    assert retention._chain_in_database(factory) is True
    db.query(AuditSeal).delete()
    db.commit()
    assert retention._chain_in_database(factory) is False


# --------------------------------------------------------------------------- each guard on its own

def _reduction(factory, days=30, at=NOW):
    """An administrator's reduction of the audit maximum: a request that waits the delay."""
    from app.core import audit_chain_policy_seals as ps
    from app.core.models import RoleEnum, User
    db = factory()
    admin = User(id=uuid.uuid4(), username="ada" + uuid.uuid4().hex[:4], email=uuid.uuid4().hex[:6] + "@x.org",
                 password_hash="x", role=RoleEnum.ADMIN, is_active=True)
    db.add(admin)
    db.commit()
    with ps.change_transaction(ai._engine_of(factory)) as w:
        outcome = ps.change(w, "audit_max_days", days, admin, now=at)
    assert outcome.status == "pending"
    return [s for s in factory().query(AuditSeal).filter(AuditSeal.kind == "request")][-1].seq


def _passes(factory, start, end, step=timedelta(hours=6)):
    t = start
    while t <= end:
        _pass(factory, now=t)
        t += step


def test_a_request_that_comes_due_while_a_restore_is_unfinished_waits_for_its_acceptance(env, factory):
    _CHAIN[-1].seal_all(NOW)
    req = _reduction(factory)
    _passes(factory, NOW + timedelta(hours=6), NOW + timedelta(days=7) - timedelta(hours=1))
    assert req in _CHAIN[-1].st.view.pending_requests()
    _mark(NOW + timedelta(days=7))
    _pass(factory, now=NOW + timedelta(days=7, hours=2))
    assert req in _CHAIN[-1].st.view.pending_requests()
    _unmark()
    _pass(factory, now=NOW + timedelta(days=7, hours=3))
    assert req not in _CHAIN[-1].st.view.pending_requests()


def test_a_request_waits_for_the_end_of_the_grace_after_a_restore(env, factory):
    _CHAIN[-1].seal_all(NOW)
    req = _reduction(factory)
    _passes(factory, NOW + timedelta(hours=6), NOW + timedelta(days=1))
    _seq, grace = _restore_seal(at=NOW + timedelta(days=1, hours=1))
    _passes(factory, NOW + timedelta(days=1, hours=6), NOW + timedelta(days=7, hours=6))
    assert req in _CHAIN[-1].st.view.pending_requests()        # its own delay has run; the grace has not
    _passes(factory, NOW + timedelta(days=7, hours=12), grace + timedelta(hours=6))
    assert req not in _CHAIN[-1].st.view.pending_requests()


def test_the_prune_and_the_audit_job_each_delete_nothing_while_a_restore_is_unfinished(env, factory):
    """Whoever calls them: the audit job and the chain's prune check the restore mark themselves, not only the
    pass that runs them."""
    from app.core import audit_chain_prune
    from app.core import audit_retention as ar
    db = factory()
    _audit(db, OLD, n=2)
    _retention_days(env, 30)
    _CHAIN[-1].seal_all(NOW)
    _mark()
    p = retention.Pass(factory, now=NOW + timedelta(minutes=30))
    numbers = ar.chain_numbers()[0]
    assert ar.prune(p, numbers).deleted == 0
    aged = ar.by_age(AuditLog, p.now, numbers)
    assert aged
    assert audit_chain_prune.prune(p, retention.deletable(AuditLog, p.now, *aged), reason="retention").deleted == 0
    assert _count(factory, AuditLog, AuditLog.action == "file_upload") == 2


def test_a_chain_whose_hold_cannot_be_read_holds_the_log_jobs(env, factory, monkeypatch):
    from app.core import audit_chain_honour as honour
    _CHAIN[-1].seal_all(NOW)
    assert retention.chain_holds(factory) is False

    def broken(*args, **kw):
        raise RuntimeError("unreadable")
    monkeypatch.setattr(honour, "honoured_state", broken)
    assert retention.chain_holds(factory) is True


def test_a_pass_decides_the_hold_after_reading_what_another_process_sealed(env, factory):
    """The server's process has read the chain; the host's command then writes a restore seal in a process of
    its own. The server's next pass reads it before deciding, and holds the log jobs for the grace."""
    db = factory()
    _alert(db, OLD, True)
    c = _CHAIN[-1]
    c.seal_all(NOW)
    host_st = ai.ChainState(settings=c.st.settings, clock=c.clock)
    c.at(NOW + timedelta(minutes=10))
    with ai.ChainWriter(ai._engine_of(factory), host_st) as w:
        w.append("restore", detail={
            "cause": "database", "lost_from_seq": None, "lost_through_seq": None, "lost_head": None,
            "record_missing": False, "under_left_key": None,
            "grace_until": fmt.time_text(NOW + timedelta(days=7)), "acknowledges": [],
            "hours": {"lost": None, "compared_from": None, "changed": [], "days_changed": [],
                      "deleted_through_seq": None},
            "lost": {"policy": None, "cancels": [], "erases": []}, "by": "host"})
    assert c.st.view.position < host_st.view.position
    done = _pass(factory, now=NOW + timedelta(minutes=30))
    assert done["security_alerts"] is None, done
    assert _count(factory, SecurityAlert) == 1
