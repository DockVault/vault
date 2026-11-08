"""Trusting the chain's view only while it is read through (app/core/audit_integrity.py ChainState.view_read, view_mark,
still_read and trusted), offline, on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py):

- a check clears the flag before it accepts any seal below the head record's, which the record's link has not verified
  yet, and sets it again only once it has read the chain through: held between accepting such a seal and the next
  step, no reader answers from the view;
- a reader that began before a check cleared the flag, and finishes after the check set it again, does not answer
  from what it read either (the flag's mark moved), nor does one whose mark was taken during the clear;
- a check that ends before the record's link has verified the seals it accepted (a database error while the seals
  are read, a record that does not match, later put right) starts the view again, so the next check reads them from
  the first seal and meets a break of the key sequence among them itself: the pass reports it;
- while the view is not read through, nothing that comes from it is shown or acted on: the settings page's values,
  its list of waiting changes and what it says of the chain, the lists' delay, whether the install ran before, the
  chain's hold and numbers, the warnings an administrator acknowledges, the changes and cancels saved while sealing
  is stopped, the checks against the genesis seal, the erase and removal lists' entries, and the pruner's jobs that
  read the view outside the chain lock;
- while sealing is stopped and the view is not read through, a change of a setting the chain records is refused
  saying so (never that it deletes records sooner), except turning the hold on, told by its spec: it is saved from
  the database's value and sealed from the database once a check reads the chain through; with sealing running, a
  change is judged by the chain writer's own read of the chain.

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


def test_a_mark_taken_while_a_check_clears_the_flag_never_trusts_what_was_read_during_the_check(env):
    """A reader outside the chain lock may take its mark (the epoch, then the flag) at any instant, the instants
    inside a check's clear of the flag among them, and then read the view while the check holds seals below the head
    record's that the record's link has not verified yet (a part of the chain only). Whatever the instant, the mark
    never lets it trust what it read: not while the check holds such a seal, and not once the check has read the
    chain through either (a clear writes the flag before it moves the epoch, so a mark taken during it is none)."""
    _archived(env)
    st = env.st
    before, after = _sealed_elsewhere(env)
    marks, held = [], []

    class Hooked(type(st)):
        @property
        def _view_read(self):
            return self.__dict__["_vr"]

        @_view_read.setter
        def _view_read(self, value):
            self.__dict__["_vr"] = value
            if self.__dict__.get("_armed") and not value:
                marks.append(self.view_mark())       # a reader switched in right after the flag was written

        @property
        def view_epoch(self):
            return self.__dict__["_ve"]

        @view_epoch.setter
        def view_epoch(self, value):
            self.__dict__["_ve"] = value
            if self.__dict__.get("_armed"):
                marks.append(self.view_mark())       # ... or right after the epoch moved

    st.__dict__["_vr"] = st.__dict__.pop("_view_read")
    st.__dict__["_ve"] = st.__dict__.pop("view_epoch")
    st.__class__ = Hooked
    st.__dict__["_armed"] = True
    real = st.view.accept

    def accept(seal, link):
        real(seal, link)
        if seal.seq < after:
            # Below the record's seal: the view holds a seal the record's link has not verified, and a reader reads.
            held.append([st.still_read(m) for m in marks])
    st.view.accept = accept
    try:
        with ai.ChainWriter(env.engine, st, check_key=False, writer="reader"):
            pass
    finally:
        del st.view.accept
        st.__dict__["_armed"] = False
    assert st.view_read is True and st.view.position == after
    assert marks and len(held) == after - before - 1
    assert not any(any(trusted) for trusted in held)
    assert [m for m in marks if st.still_read(m)] == []


def test_a_mark_whose_two_reads_a_clear_runs_between_never_trusts_the_view_once_the_flag_is_set_again():
    """view_mark() reads two things, the epoch and the flag, and a check's clear can run between those two reads from
    another thread. Whichever the mark reads first, a mark taken across a clear never matches once the check sets the
    flag again: the reader read the view during the check."""
    st = ai.ChainState()
    st.view_read = True                       # read through once (a set does not move the epoch)
    reads = []

    class Hooked(type(st)):
        def _clear_if_second(self, name):
            if self.__dict__.get("_armed") and reads and reads[-1] != name:
                # A check clears the flag right here, between the mark's two reads, as the setter does it.
                self.__dict__["_armed"] = False
                type(st).view_read.fset(self, False)
            reads.append(name)

        @property
        def _view_read(self):
            self._clear_if_second("flag")
            return self.__dict__["_vr"]

        @_view_read.setter
        def _view_read(self, value):
            self.__dict__["_vr"] = value

        @property
        def view_epoch(self):
            self._clear_if_second("epoch")
            return self.__dict__["_ve"]

        @view_epoch.setter
        def view_epoch(self, value):
            self.__dict__["_ve"] = value

    st.__dict__["_vr"] = st.__dict__.pop("_view_read")
    st.__dict__["_ve"] = st.__dict__.pop("view_epoch")
    st.__class__ = Hooked
    st.__dict__["_armed"] = True
    mark = st.view_mark()
    assert st.__dict__["_armed"] is False, reads           # the clear ran inside view_mark
    # The reader reads the view while the check accepts seals the record's link has not verified; then the check reads
    # the chain through and sets the flag again.
    st.view_read = True
    assert not st.still_read(mark), (mark, reads, st.view_epoch)


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
        assert ps.refuses_while_stopped(db, "audit_max_days", 0, st=env.st) is False      # for ever keeps more
        assert ps.while_stopped(db, "audit_max_days", 0, st=env.st)[1] is not None        # judged by the chain
    st = _not_read_through(env)
    with env.session() as db:
        # What the chain last gave is not known: only turning the hold on, the strongest value whatever is in force,
        # is taken, judged from the database's value and never from the view; every other change of a setting the
        # chain records is refused, saying the chain is not read through.
        assert ps.refuses_while_stopped(db, "logs_hold", True, st=st) is False
        assert ps.while_stopped(db, "logs_hold", True, st=st) == (None, None)
        assert ps.judge_now("logs_hold", st) is None and ps.judge_now("audit_max_days", st) is None
        for key, value in (("logs_hold", False), ("logs_hold", None), ("audit_max_days", 400),
                           ("audit_max_days", 0)):
            assert ps.while_stopped(db, key, value, st=st) == (ps.UNREAD, None), (key, value)
            assert ps.refuses_while_stopped(db, key, value, st=st) is True, (key, value)
        assert ps.while_stopped(db, "log_prune_interval_minutes", 30, st=st) == (None, None)  # not the chain's
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


def test_the_hold_taken_while_the_view_is_not_read_through_is_told_by_its_spec_never_by_its_key(env, monkeypatch):
    """Only a switch whose turning off deletes sooner (kind bool, reduction lower), turned on, is taken while the view
    is not read through: the hold's own key with another reduction is refused, another key with the hold's spec is
    taken, and no other value of either is."""
    import dataclasses
    from app.core import audit_chain_policy as pol
    from app.core import audit_chain_policy_seals as ps
    from app.core import settings_registry as registry
    hold = registry.spec_for("logs_hold")
    assert ps.only_adds_a_hold(hold, True) is True
    for value in (False, None, 1, "true"):
        assert ps.only_adds_a_hold(hold, value) is False, value
    assert ps.only_adds_a_hold(dataclasses.replace(hold, reduction=registry.HIGHER), True) is False
    assert ps.only_adds_a_hold(dataclasses.replace(hold, reduction=None), True) is False
    assert ps.only_adds_a_hold(dataclasses.replace(hold, kind="int"), True) is False
    assert ps.only_adds_a_hold(None, True) is False
    _archived(env)
    st = _not_read_through(env)
    specs = {"logs_hold": dataclasses.replace(hold, reduction=registry.HIGHER),
             "keep_everything": dataclasses.replace(hold, key="keep_everything")}
    real_spec, real_keys = registry.spec_for, pol.chain_setting_keys
    monkeypatch.setattr(registry, "spec_for", lambda key: specs.get(key) or real_spec(key))
    monkeypatch.setattr(pol, "chain_setting_keys", lambda: real_keys() + ("keep_everything",))
    with env.session() as db:
        assert ps.while_stopped(db, "logs_hold", True, st=st) == (ps.UNREAD, None)
        assert ps.while_stopped(db, "keep_everything", True, st=st) == (None, None)
        for value in (False, None):
            assert ps.while_stopped(db, "keep_everything", value, st=st) == (ps.UNREAD, None)


def test_a_change_judged_while_a_check_clears_the_view_is_refused_as_not_known(env, monkeypatch):
    """A change made while sealing is stopped is judged from the view in one trusted read. When a check clears the view
    while that judge is made (one that began to accept seals the head record's link has not verified), the judge is
    not used: the change is refused as one whose value in force is not known, and judge_now gives none."""
    from app.core import audit_chain_policy_seals as ps
    _archived(env)
    st = env.st
    assert st.view_read is True
    real = ps.judge
    calls = []

    def judge(view, record, key, now=None):
        calls.append(key)
        st.view_read = False          # a check clears the view while the judge reads it
        return real(view, record, key, now)
    monkeypatch.setattr(ps, "judge", judge)
    with env.session() as db:
        assert ps.while_stopped(db, "audit_max_days", 500, st=st) == (ps.UNREAD, None)
    st.view_read = True
    assert ps.judge_now("audit_max_days", st) is None
    assert calls == ["audit_max_days", "audit_max_days"]


def _route(env):
    """The managed-settings routes, the step-up passed."""
    from app.api import managed_settings_router as routes
    env.monkeypatch.setattr(routes, "_step_up", lambda db, user, request: None)
    return routes


def _put(routes, env, key, value):
    with env.session() as db:
        return routes.put_managed_setting(key, routes.ManagedValue(value=value), request=None, current_user=ADMIN,
                                          db=db)


UNREAD_TEXT = ("The value in force is not known yet, so this change cannot be made: the audit log's integrity chain "
               "does not check out (head-record-mismatch), so this server has not read it through; the integrity "
               "status on the Activity page says what to do. Nothing was changed; try again later.")


def test_while_sealing_is_stopped_and_the_view_is_not_read_through_only_turning_the_hold_on_is_saved(env):
    """A process started while the chain does not check out (a seal before the head record's changed): no seal can be
    written, and this process has not read the chain through. Turning the hold on is saved at once (it keeps more
    whatever the chain holds), judged from the database's value, and sealed from the database once a check reads the
    chain through; turning it off, or setting a number the chain holds, longer or shorter, is refused (409) saying the
    chain is not read through and why, never that the change deletes records sooner; so is a cancel."""
    from fastapi import HTTPException
    from app.core import setting_changes as sc
    from app.core.models import AuditLog, ManagedSetting, ManagedSettingChange
    routes = _route(env)
    _archived(env)
    change = _waiting_change(env)
    _tamper_one_seal(env)
    seals = len(env.seals())
    # A process whose own start read has not run: the stop its change's check just met is named all the same.
    bare = env.fresh_process()
    with pytest.raises(HTTPException) as refused:
        _put(routes, env, "audit_max_days", 400)
    assert (refused.value.status_code, refused.value.detail) == (409, UNREAD_TEXT)
    assert (bare.view_read, bare.read_stopped, bare.stopped) == (False, None, None)
    assert ai.unread_reason(bare) == ("this server has not finished reading the audit log's integrity chain since "
                                      "it started")
    st = env.fresh_process()
    assert ai.read_at_start(env.engine, st, timeout=10) is False
    assert (st.view_read, st.read_stopped, st.stopped, st.view.position) == (False, "head-record-mismatch", None, 0)
    for key, value in (("audit_max_days", 400), ("audit_max_days", 0), ("audit_max_days", 30), ("logs_hold", False)):
        with pytest.raises(HTTPException) as refused:
            _put(routes, env, key, value)
        assert (refused.value.status_code, refused.value.detail) == (409, UNREAD_TEXT), (key, value)
        assert "sooner" not in refused.value.detail
    with env.session() as db:
        with pytest.raises(HTTPException) as refused:
            routes.cancel_managed_setting_change(change, current_user=ADMIN, db=db)
    assert refused.value.status_code == 409 and "sooner" not in refused.value.detail
    assert refused.value.detail == ("Whether this change is still waiting cannot be told just now: the audit log's "
                                    "integrity chain does not check out (head-record-mismatch), so this server has "
                                    "not read it through; the integrity status on the Activity page says what to do. "
                                    "Nothing was cancelled; try again later.")
    with env.session() as db:
        assert db.query(ManagedSetting).count() == 0
        assert db.query(AuditLog).filter(AuditLog.action.in_((sc.CHANGED, sc.CANCELLED_ACTION))).count() == 0
    out = _put(routes, env, "logs_hold", True)
    assert (out["status"], out["change"]) == ("applied", None)
    # The answer shows nothing of the view either: the value in force is still the chain's, not known yet.
    assert (out["setting"]["chain_read"], out["setting"]["value"]) == (False, None)
    with env.session() as db:
        assert db.get(ManagedSetting, "logs_hold").value is True
        (row,) = db.query(AuditLog).filter(AuditLog.action == sc.CHANGED).all()
        assert (row.details["key"], row.details["old"], row.details["new"]) == ("logs_hold", False, True)
        assert db.get(ManagedSettingChange, change).status == sc.PENDING       # the waiting change is untouched
    assert retention.hold_in_force() is True and len(env.seals()) == seals
    # The seal put right: a check reads the chain through, and the pass seals the hold from the database.
    with env.engine.begin() as c:
        c.exec_driver_sql("UPDATE audit_seals SET row_bytes = row_bytes - 1 WHERE seq = 2")
    assert ai.read_view(env.engine, st) is True
    retention.apply_waiting_changes(retention.Pass(env.session, now=env.clock()))
    added = env.seals()[seals:]
    assert [(s.kind, s.detail["cause"]) for s in added] == [("policy", "database")]
    assert added[0].detail["state"]["logs_hold"]["value"] is True


def test_with_the_view_not_read_through_and_sealing_running_a_change_is_judged_by_the_writer_s_own_read(env,
                                                                                                         monkeypatch):
    """A process that has just started, the chain checking out: a change goes through the chain writer, whose check
    reads the chain through before the change is judged, so nothing is judged from the view as it was. Turning the
    hold on is saved and sealed at once; a number the chain holds is judged by the chain (a reduction waits)."""
    from app.core import audit_chain_policy_seals as ps
    routes = _route(env)
    _archived(env)
    st = env.fresh_process()
    assert (st.view_read, st.view.position, st.stopped) == (False, 0, None)
    seen = []
    real = ps.judge

    def judge(view, record, key, now=None):
        seen.append((key, st.view_read, view.position))
        return real(view, record, key, now)
    monkeypatch.setattr(ps, "judge", judge)
    seals = len(env.seals())
    out = _put(routes, env, "logs_hold", True)
    assert out["status"] == "applied" and "chain_read" not in out["setting"] and out["setting"]["value"] is True
    added = env.seals()[seals:]
    assert [(s.kind, s.detail["cause"]) for s in added] == [("policy", "request")]
    assert added[0].detail["state"]["logs_hold"]["value"] is True
    out = _put(routes, env, "audit_max_days", 400)
    assert out["status"] == "pending" and out["change"]["setting"] == 400
    assert [s.kind for s in env.seals()[seals + 1:]] == ["request"]
    assert seen == [("logs_hold", True, seals), ("audit_max_days", True, seals + 1)]


def test_the_hold_turned_on_while_the_view_is_not_read_through_is_judged_from_the_database_not_from_the_view(env):
    """A process whose view holds seals but is not read through (a break of the key sequence under the head record):
    the chain holds the hold on, the database, edited, holds it off. Turning the hold on through the route is judged
    from the database's value: its audit row says the hold was off, and nothing of the unread view reaches it."""
    from app.core import setting_changes as sc
    from app.core.models import AuditLog, ManagedSetting
    from test_activity_archive_unread import HOT
    routes = _route(env)
    _archived(env)
    out = _put(routes, env, "logs_hold", True)                 # sealing runs: sealed at once, the chain holds it on
    assert out["status"] == "applied"
    for h in (1, 2, 3):
        env.row(at(HOT, 20, h) + timedelta(hours=h))
    env.run_until_sealed()                                     # the head record moves past the hold's seal
    with env.session() as db:
        db.get(ManagedSetting, "logs_hold").value = False      # the database edited: the hold off
        db.commit()
    st = _not_read_through(env)
    assert st.view.newest_policy()[1]["state"]["logs_hold"]["value"] is True
    with env.session() as db:
        before = db.query(AuditLog).filter(AuditLog.action == sc.CHANGED).count()
    out = _put(routes, env, "logs_hold", True)
    assert out["status"] == "applied" and out["setting"]["chain_read"] is False
    with env.session() as db:
        rows = db.query(AuditLog).filter(AuditLog.action == sc.CHANGED).all()
        assert len(rows) == before + 1 == 2
        # The first from no stored value (the default, off), the second from the database's edited value (off); a
        # row saying the hold was on would come from the unread view.
        assert sorted((r.details["old"], r.details["new"]) for r in rows) == [(False, True), (False, True)]
        assert db.get(ManagedSetting, "logs_hold").value is True


def test_while_the_view_is_not_read_through_a_listed_erase_or_removal_holds_nothing_from_it(env, monkeypatch):
    """The erase and removal lists build their entries from no view while it is not read through: a request the unread
    view holds waiting (its seals not verified) gives no seq, no run date from its seal and no cancel, only the row's
    copies and the status unread. Read through, the same request in the view gives them."""
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    _archived(env)
    rid = uuid.uuid4()
    when = T0 + timedelta(days=7)
    row = SimpleNamespace(id=rid, status="pending", placeholder="erased-0000abcd", requested_by_name="alice",
                          requested_at=T0, effective_at=when, started_at=None, completed_at=None, decided_by_name=None,
                          decided_at=None, waiting=None, counts=None, levels=["full"], before=T0)
    sealed = {"request": str(rid), "not_before": "2027-01-01T00:00:00Z", "placeholder": "erased-1111abcd",
              "new": {"levels": ["minimal"], "before": "2026-01-01T00:00:00Z"}}
    first = env.st
    unread = _not_read_through(env)
    for module, what in ((pe, "erase"), (removal, "removal")):
        for st in (first, unread):
            monkeypatch.setitem(st.view.requests, 9999, dict(sealed, what=what))
        (read,) = pe._listed([row], first, module.entry_of)
        assert (read["status"], read["request_seq"], read["effective_at"], read["cancellable"]) == (
            module.PENDING, 9999, "2027-01-01T00:00:00Z", True), what
        (e,) = pe._listed([row], unread, module.entry_of)
        assert (e["status"], e["request_seq"], e["effective_at"], e["cancellable"]) == (
            pe.UNREAD, None, module._iso(when), False), what
        assert e.get("through") is None and e.get("placeholder", row.placeholder) == row.placeholder
        assert e.get("levels", row.levels) == row.levels


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
