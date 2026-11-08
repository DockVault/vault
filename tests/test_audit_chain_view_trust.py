"""Trusting the chain's view only while it is read through (app/core/audit_integrity.py ChainState.view_read, view_mark,
still_read and trusted), offline, on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py):

- a check clears the flag before it accepts any seal below the head record's, which the record's link has not verified
  yet, and sets it again only once it has read the chain through: held between accepting such a seal and the next
  step, no reader answers from the view;
- a reader that began before a check cleared the flag, and finishes after the check set it again, does not answer
  from what it read either (the flag's mark moved);
- a check that ends before the record's link has verified the seals it accepted (a database error while the seals
  are read, a record that does not match, later put right) starts the view again, so the next check reads them from
  the first seal and meets a break of the key sequence among them itself: the pass reports it;
- while the view is not read through, nothing that comes from it is shown or acted on: the settings page's values,
  its list of waiting changes and what it says of the chain, the lists' delay, whether the install ran before, the
  chain's hold and numbers, the warnings an administrator acknowledges, the changes and cancels saved while sealing
  is stopped, the checks against the genesis seal, and the pruner's jobs that read the view outside the chain lock.

test_activity_archive_unread.py covers the readers of the archived days; test_activity_archive_unread_live.py the same
through a web process on Postgres.
"""
import threading
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest

from _audit_chain_env import Env, T0
from app.core import audit_archive as arc
from app.core import audit_integrity as ai
from app.core import retention
from app.services import activity_archive as archive
from test_activity_archive_unread import (ARCHIVED, _archived, _break_key_sequence, _reported, _sealed_elsewhere,
                                          _tamper_one_seal, at)

pytestmark = pytest.mark.unit

ADMIN = SimpleNamespace(id=uuid.uuid4(), username="alice", role="admin")


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _readers(env, st):
    """What each reader of the view outside the chain lock answers from ``st`` now."""
    from app.api import managed_settings_router as routes
    from app.core import audit_chain_pending as pending
    from app.core import audit_chain_policy_seals as ps
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    from app.core import retention_storage as rs
    try:
        days = sorted(archive.archives(st))
    except archive.Unread:
        days = "unread"
    with env.session() as db:
        listed = pending.listed(db, st)
    return {"days": days, "chain_read": routes.chain_read(st), "summary": arc.summary(st)["read"],
            "pending": (len(listed[0]), listed[1]["read"]), "existing_install": rs.existing_install(None, st),
            "erase_delay": pe.listed_delay_days(st), "removal_delay": removal.listed_delay_days(st),
            "numbers": ps.numbers(st) is not None}


# --------------------------------------------------------------------------- a check that accepts seals below the record

def test_no_reader_answers_from_the_view_while_a_check_accepts_seals_the_record_has_not_verified(env):
    """A process that has read the chain through; another seals more and moves the head record on. The next check
    accepts the seals up to the record's one by one, verified only once it reaches the record's link: held right after
    it accepted the first of them, every reader refuses or says not known yet; once it has read through, they answer."""
    _archived(env)
    st = env.st
    read = _readers(env, st)
    assert read["days"] == [ARCHIVED] and read["chain_read"] is True and read["summary"] is True
    assert read["pending"][1] is True and read["existing_install"] in (True, False) and read["erase_delay"] is not None
    before, after = _sealed_elsewhere(env)
    reached, go, failed = threading.Event(), threading.Event(), []
    real = st.view.accept

    def accept(seal, link):
        real(seal, link)
        if seal.seq == before + 1:
            reached.set()
            assert go.wait(30)

    def check():
        try:
            with ai.ChainWriter(env.engine, st, check_key=False, writer="reader"):
                pass
        except Exception as exc:  # noqa: BLE001
            failed.append(exc)
    st.view.accept = accept
    t = threading.Thread(target=check)
    t.start()
    try:
        assert reached.wait(30)
        assert st.view.position == before + 1 and st.view_read is False
        held = _readers(env, st)
        assert held == {"days": "unread", "chain_read": False, "summary": False, "pending": (0, False),
                        "existing_install": None, "erase_delay": None, "removal_delay": None, "numbers": False}
        assert retention.chain_holds(env.session) is True
        assert ai.read_view(env.engine, st, wait=0.05) is False        # it waits for the check, which holds the lock
    finally:
        go.set()
        t.join(30)
        del st.view.accept
    assert failed == [] and st.view_read is True and st.view.position == after
    assert _readers(env, st)["days"] == [ARCHIVED] and retention.chain_holds(env.session) is False


def test_a_reader_that_began_before_a_check_cleared_the_view_does_not_answer_from_it(env):
    """A reader outside the chain lock takes the flag's mark before it reads and compares it after: a check that
    cleared the flag meanwhile (it began to accept a seal below the record) and set it again leaves the mark behind,
    and the reader refuses what it read."""
    _archived(env)
    st = env.st
    real = st.view

    class _Midway:
        """The view as a reader reads it while a check clears the flag and sets it again."""

        def __getattr__(self, name):
            st.view_read = False
            st.view_read = True
            return getattr(real, name)
    st.view = _Midway()
    try:
        assert _readers(env, st) == {"days": "unread", "chain_read": False, "summary": False, "pending": (0, False),
                                     "existing_install": None, "erase_delay": None, "removal_delay": None,
                                     "numbers": False}
        assert retention.chain_holds(env.session) is True
        with pytest.raises(ai.ViewUnread):
            st.trusted(lambda view: view.position)
    finally:
        st.view = real
    assert st.view_read is True and _readers(env, st)["days"] == [ARCHIVED]
    # What a reader raises from a view that stayed read through is its own.
    with pytest.raises(KeyError):
        st.trusted(lambda view: {}["missing"])


def test_a_reader_that_fails_on_a_view_a_check_is_changing_is_told_the_view_is_not_read(env):
    """A check that starts the view again replaces its arrays while a reader may be reading them: what the reader
    then meets (an index past the end) is not its own failure, but a view not read through."""
    _archived(env)
    st = env.st
    real = st.view

    class _Changing:
        def __getattr__(self, name):
            st.view_read = False
            st.view_read = True
            raise IndexError("the view's arrays changed under the reader")
    st.view = _Changing()
    try:
        with pytest.raises(ai.ViewUnread):
            st.trusted(lambda view: view.position)
        with pytest.raises(archive.Unread):
            archive.archives(st)
    finally:
        st.view = real


# --------------------------------------------------------------------------- a check that ends before the record's link

def _seals_that_fail_once(monkeypatch, after):
    """read_seals as the database gives it, but the first stream fails right after it has handed over seal
    ``after`` (a database error while the seals are read); every later one reads them all."""
    real = ai.read_seals
    failed = []

    def read_seals(db, after_seq=0, upto=None):
        for seal in real(db, after_seq, upto):
            yield seal
            if seal.seq == after and not failed:
                failed.append(seal.seq)
                raise RuntimeError("the connection to the database was lost")
    monkeypatch.setattr(ai, "read_seals", read_seals)
    return failed


def test_a_break_of_the_key_sequence_is_met_by_the_pass_when_the_start_s_read_failed_right_after_it(env, monkeypatch):
    """The start's read accepts the seal that breaks the key sequence, and the database fails right after it, before
    the record's link: the view starts again, so the pass reads from the first seal, meets the break, stops and
    reports it, as when the start's read had read on to the record."""
    _archived(env)
    k, rec_seq = _break_key_sequence(env)
    st = env.fresh_process()
    failed = _seals_that_fail_once(monkeypatch, k)
    assert ai.read_at_start(env.engine, st, timeout=10) is False
    assert failed == [k]
    assert (st.view_read, st.view.position, st.view_stop, st.read_stopped) == (False, 0, None, None)
    env.clock.advance(minutes=30)
    r = env.seal()
    assert r.stopped == "key-sequence" and st.stopped.kind == "key-sequence" and st.stopped.seq == k
    assert _reported(env, st, "key-sequence")
    assert st.view_read is False and st.view.position == rec_seq - 1
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-sequence"


def test_a_break_of_the_key_sequence_is_met_once_a_record_that_did_not_match_is_put_right(env):
    """The start's read meets a record whose link does not match at the record's seal, after it accepted the seal that
    breaks the key sequence: the view starts again. The record put right, the pass reads from the first seal and stops
    on the break, and reports it."""
    import json
    _archived(env)
    k, rec_seq = _break_key_sequence(env)
    path = env.st.head_store().path
    with open(path, encoding="utf-8") as fh:
        record = json.load(fh)
    right = record["link"]
    record["link"] = "00" * 32
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    st = env.fresh_process()
    assert ai.read_at_start(env.engine, st, timeout=10) is False
    assert (st.read_stopped, st.view_read, st.view.position, st.view_stop) == ("head-record-mismatch", False, 0, None)
    record["link"] = right
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    st.store = None
    env.clock.advance(minutes=30)
    r = env.seal()
    assert r.stopped == "key-sequence" and st.stopped.seq == k and _reported(env, st, "key-sequence")


def test_a_check_that_ends_before_the_record_s_link_keeps_none_of_the_seals_it_accepted(env, monkeypatch):
    """A process that had read the chain through: the seals another writer sealed up to the record are accepted, and
    the database fails before the record's: none of them stays, nor the view before them, until a check reads the
    chain through again from the first seal."""
    _archived(env)
    st = env.st
    before, after = _sealed_elsewhere(env)
    _seals_that_fail_once(monkeypatch, before + 1)
    with pytest.raises(RuntimeError):
        with ai.ChainWriter(env.engine, st, check_key=False):
            pass
    assert st.view_read is False and st.view.position == 0
    assert ai.read_view(env.engine, st) is True and st.view.position == after


# --------------------------------------------------------------------------- while the view is not read through

def _waiting_change(env):
    """A reduction of the audit log's maximum, sealed as a request that waits. Returns its change id."""
    from app.core import audit_chain_policy_seals as ps
    with ps.change_transaction(env.engine) as w:
        ps.change(w, "audit_max_days", 400, ADMIN)
    with env.session() as db:
        from app.core.models import ManagedSettingChange
        (row,) = db.query(ManagedSettingChange).filter(ManagedSettingChange.status == "pending").all()
        return row.id


def _not_read_through(env):
    """A process that has just started on a chain whose key sequence breaks under the head record: its view holds the
    seals before the record's (their link checked out), and is not read through; sealing is not stopped (only a
    read met the stop)."""
    k, rec_seq = _break_key_sequence(env)
    st = env.fresh_process()
    assert ai.read_at_start(env.engine, st, timeout=10) is False
    assert st.view.position == rec_seq - 1 and st.view.newest_policy() is not None
    assert (st.view_read, st.stopped, st.read_stopped) == (False, None, "key-sequence")
    return st


def test_the_settings_page_shows_nothing_of_a_view_not_read_through_and_says_why(env):
    from app.api import managed_settings_router as routes
    from app.core import audit_chain_pending as pending
    from app.core import settings_registry as registry
    _archived(env)
    change = _waiting_change(env)
    with env.session() as db:
        assert [e["id"] for e in pending.entries(db, env.st)] == [str(change)]
    st = _not_read_through(env)
    assert routes.chain_read(st) is False
    rows = {r["key"]: r for r in routes.with_chain(registry.describe())}
    assert rows["audit_max_days"]["chain_read"] is False and rows["audit_max_days"]["value"] is None
    assert rows["audit_max_days"]["source"] == routes.SOURCE_UNREAD
    with env.session() as db:
        assert pending.entries(db, st) == []
        assert pending.listed(db, st) == ([], {"read": False, "stopped": "key-sequence"})
    assert pending.chain_state(st) == {"read": False, "stopped": "key-sequence"}
    st.stopped = ai.ChainStopped("head-record-mismatch", "a stop the pass met")
    assert pending.chain_state(st) == {"read": False, "stopped": "head-record-mismatch"}


def test_the_lists_delay_and_whether_the_install_ran_before_are_not_known_from_a_view_not_read_through(env):
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    from app.core import retention_storage as rs
    _archived(env)
    assert pe.listed_delay_days(env.st) == pe.delay_days(env.st.view, env.st)
    assert rs.existing_install(None, env.st) in (True, False)
    st = _not_read_through(env)
    assert pe.listed_delay_days(st) is None and removal.listed_delay_days(st) is None
    assert rs.existing_install(None, st) is None


def test_the_lists_routes_give_the_delay_as_the_lists_know_it():
    import inspect
    from app.api import person_erase_router as erase_routes
    from app.api import value_removal_router as removal_routes
    assert '"delay_days": pe.listed_delay_days(st)' in inspect.getsource(erase_routes.list_erase_requests)
    assert '"delay_days": removal.listed_delay_days(st)' in inspect.getsource(removal_routes.list_removals)
    for fn in (erase_routes.list_erase_requests, removal_routes.list_removals):
        assert "delay_days(st.view" not in inspect.getsource(fn)


def test_the_chain_s_hold_and_numbers_are_not_read_from_a_view_not_read_through(env):
    """The chain's honoured hold is off and its numbers known while the view is read through; while it is not, the
    chain in the database holds every job over logs, and the audit job has no numbers to act on."""
    from app.core import audit_chain_policy_seals as ps
    _archived(env)
    assert retention.chain_holds(env.session) is False and ps.numbers(env.st) is not None
    st = _not_read_through(env)
    assert retention.chain_holds(env.session) is True
    assert ps.numbers(st) is None


def test_the_warnings_an_administrator_acknowledges_are_not_listed_from_a_view_not_read_through(env):
    from app.api import audit_integrity_router as r
    _archived(env)
    with env.session() as db:
        out = r.get_warnings(current_user=ADMIN, db=db)
    assert out["read"] is True and out["warnings"] == []
    _not_read_through(env)
    with env.session() as db:
        out = r.get_warnings(current_user=ADMIN, db=db)
    assert out["read"] is False and out["warnings"] == []


def test_the_warnings_are_not_listed_when_the_view_was_cleared_while_they_were_read(env, monkeypatch):
    from app.api import audit_integrity_router as r
    _archived(env)
    st = env.st
    real = r.admin_warnings

    def admin_warnings(view, record):
        st.view_read = False
        st.view_read = True
        return real(view, record)
    monkeypatch.setattr(r, "admin_warnings", admin_warnings)
    with env.session() as db:
        out = r.get_warnings(current_user=ADMIN, db=db)
    assert out["read"] is False and out["warnings"] == []


def test_a_preview_answers_only_from_a_view_that_stayed_read_through(env):
    from fastapi import HTTPException
    from app.api import audit_integrity_router as r
    _archived(env)
    st = env.st
    with env.session() as db:
        assert r.answer_from_view(db, "What it would change", lambda: {"rows": 3}) == {"rows": 3}

        def counted():
            st.view_read = False            # a check began to accept a seal below the record while it counted
            st.view_read = True
            return {"rows": 3}
        with pytest.raises(HTTPException) as refused:
            r.answer_from_view(db, "What it would change", counted)
    assert refused.value.status_code == 503 and refused.value.headers == {"Retry-After": "60"}
    assert refused.value.detail.startswith("What it would change cannot be told yet")


def test_a_change_or_a_cancel_while_sealing_is_stopped_is_not_judged_from_a_view_not_read_through(env):
    from app.core import audit_chain_policy_seals as ps
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    from app.core import settings_registry as registry
    _archived(env)
    change = _waiting_change(env)
    with env.session() as db:
        # A change that keeps more is saved while sealing is stopped, judged from a view read through.
        assert ps.refuses_while_stopped(db, "logs_hold", True, st=env.st) is False
    st = _not_read_through(env)
    with env.session() as db:
        assert ps.refuses_while_stopped(db, "logs_hold", True, st=st) is True
        assert ps.refuses_while_stopped(db, "greeting_days", 5, st=st) is False      # a setting the chain does not hold
        with pytest.raises(registry.SettingRefused, match="cannot be told just now"):
            ps.cancel_while_stopped(db, change, ADMIN, st)
        db.rollback()

    class _NoRows:
        def get(self, *_a):
            raise AssertionError("nothing is read before the view is")
    with pytest.raises(pe.Refused, match="Whether this erase is still waiting cannot be told just now"):
        pe.cancel_while_stopped(_NoRows(), uuid.uuid4(), ADMIN, st)
    with pytest.raises(removal.Refused, match="Whether this removal is still waiting cannot be told just now"):
        removal.cancel_while_stopped(_NoRows(), uuid.uuid4(), ADMIN, st)


def test_a_cancel_while_sealing_is_stopped_is_refused_when_the_view_was_cleared_while_it_was_judged(env):
    """The settings' cancel judges from the view, then ends the change's row: when a check cleared the view meanwhile,
    it is refused (its row is rolled back by the route), never saved from what it read."""
    from app.core import audit_chain_policy_seals as ps
    from app.core import settings_registry as registry
    from app.core import setting_changes
    _archived(env)
    change = _waiting_change(env)
    st = env.st
    real = setting_changes.cancel

    def cancel(*a, **kw):
        st.view_read = False
        st.view_read = True
        return real(*a, **kw)
    env.monkeypatch.setattr(setting_changes, "cancel", cancel)
    with env.session() as db:
        with pytest.raises(registry.SettingRefused, match="cannot be told just now"):
            ps.cancel_while_stopped(db, change, ADMIN, st)


def test_an_erase_or_a_removal_cancelled_while_sealing_is_stopped_is_refused_when_the_view_was_cleared(
        env, monkeypatch):
    """Each cancel judges from the view, then ends the request's row: when a check cleared the view meanwhile, it is
    refused (the route rolls the row back), never saved from what it read."""
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    _archived(env)
    st = env.st

    def end_row(*a, **kw):
        st.view_read = False
        st.view_read = True

    class _NoRows:
        def get(self, *_a):
            return None
    monkeypatch.setattr(pe, "held_request", lambda view, request_id: 7)
    monkeypatch.setattr(st.view, "pending_requests", lambda: {7: {"what": "erase"}})
    monkeypatch.setattr(st.view, "requests", {7: {"what": "erase", "placeholder": "erased-0000abcd"}})
    monkeypatch.setattr(pe, "_end_row", end_row)
    with pytest.raises(pe.Refused, match="Whether this erase is still waiting cannot be told just now"):
        pe.cancel_while_stopped(_NoRows(), uuid.uuid4(), ADMIN, st)
    monkeypatch.setattr(removal, "_cancellable", lambda view, request_id: None)
    monkeypatch.setattr(removal, "_end_row", end_row)
    with pytest.raises(removal.Refused, match="Whether this removal is still waiting cannot be told just now"):
        removal.cancel_while_stopped(_NoRows(), uuid.uuid4(), ADMIN, st)
    # Read through all along, each is saved.
    monkeypatch.setattr(pe, "_end_row", lambda *a, **kw: None)
    monkeypatch.setattr(removal, "_end_row", lambda *a, **kw: None)
    assert pe.cancel_while_stopped(_NoRows(), uuid.uuid4(), ADMIN, st)["status"] == pe.CANCELLED
    assert removal.cancel_while_stopped(_NoRows(), uuid.uuid4(), ADMIN, st)["status"] == removal.CANCELLED


def test_the_checks_against_the_genesis_seal_wait_for_a_view_read_through(env):
    _archived(env)
    first = env.st.view.first_hour()
    env.row(first - timedelta(hours=2))
    assert "row-before-genesis" in ai.every_pass_checks(env.session, env.st, env.clock())
    st = _not_read_through(env)
    assert "row-before-genesis" not in ai.every_pass_checks(env.session, st, env.clock())


def test_the_key_a_restore_waits_for_is_read_from_the_record_while_the_view_is_not_read_through(env):
    _archived(env)
    st = _not_read_through(env)
    seen = []
    st.keys_held = lambda: {}
    real = st.view.key_in_force
    st.view.key_in_force = lambda: seen.append(1) or real()
    assert st.unheld_key_in_force() == env.st.head_store().load()["key_id"]
    assert seen == []


# --------------------------------------------------------------------------- the pruner's jobs that read the view

def _recorded(env, module, *names, result=None, calls=None):
    calls = [] if calls is None else calls
    for name in names:
        env.monkeypatch.setattr(module, name, lambda *a, _n=name, **k: calls.append(_n) or result)
    return calls


def _jobs(env):
    """Each job that reads the view outside the chain lock, with what it calls once it has passed its gate."""
    from app.core import audit_chain_erase as erase
    from app.core import audit_chain_policy_seals as ps
    from app.core import audit_rewrite as rewrite
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    erased = _recorded(env, erase, "due", "vetoed", result=[])
    _recorded(env, pe, "sweep_names", result=0, calls=erased)
    return [
        (retention.apply_waiting_changes, _recorded(env, ps, "apply_due", "backstop", result={})),
        (arc.archive_job, _recorded(env, arc, "starts_at", result=None)),
        (erase.run_job, erased),
        (rewrite.shorten_job, _recorded(env, rewrite, "full_days", result=None)),
        (removal.run_job, _recorded(env, removal, "due", "vetoed", result=[])),
    ]


def test_the_pruner_s_jobs_that_read_the_view_wait_for_one_read_through(env):
    _archived(env)
    jobs = _jobs(env)
    for job, calls in jobs:
        job(retention.Pass(env.session, now=env.clock()))
        assert calls, job.__name__
        calls.clear()
    st = _not_read_through(env)
    assert st.stopped is None
    for job, calls in jobs:
        job(retention.Pass(env.session, now=env.clock()))
        assert calls == [], job.__name__


def test_the_erase_job_keeps_the_sealed_names_when_the_view_was_cleared_during_its_run(env):
    from app.core import audit_chain_erase as erase
    from app.core import person_erase as pe
    _archived(env)
    st = env.st
    swept = _recorded(env, pe, "sweep_names", result=0)
    env.monkeypatch.setattr(erase, "vetoed", lambda *a, **k: [])
    env.monkeypatch.setattr(erase, "due", lambda *a, **k: [])
    erase.run_job(retention.Pass(env.session, now=env.clock()))
    assert swept == ["sweep_names"]
    swept.clear()

    def due(*a, **k):
        st.view_read = False                 # a check during the run, which accepted a seal below the record
        return []
    env.monkeypatch.setattr(erase, "due", due)
    erase.run_job(retention.Pass(env.session, now=env.clock()))
    assert swept == []
