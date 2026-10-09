"""Accepting a restored audit chain on the host (app/core/audit_chain_restore.py), offline:

- accept-database-head: a cut tail, the cut hours' rows edited, seals deleted with their rows left alone, a cut
  reaching back more than 30 days, a chain rewritten from some seal, a chain whose newest MAC does not verify,
  a lost cancel and a lost hold sealed again, a lost head record, a database that lost every seal, a chain
  ending under a key the recorded one had left; the server's process takes the new generation with no restart;
- accept-restore: a whole backup restored (the database and the head record of a week ago): the restore mark
  holds every deletion, the seals of the backup's window are acknowledged, a seal the running server accepted
  after the restart is not, what the restore undid is named and sealed again.

Each host command runs in a process of its own; the server's process takes the head record at its next check.
Runs on a throwaway SQLite database (tests/_audit_chain_env.py)."""
import json
import os
import shutil
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, KEY_TEXT, T0, failures, host_rows
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_policy_seals as ps
from app.core import audit_chain_restore as restore
from app.core import audit_head_record as hr
from app.core import audit_integrity as ai
from app.core.models import AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange
from test_audit_chain_trust import _admin, _change, _run_to

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


def _accept(env, confirm=None, **kw):
    seen = restore.accept_database_head(env.engine, _host(env), read=True, **kw)
    done = restore.accept_database_head(env.engine, _host(env), expect=seen["state"],
                                        confirm=confirm if confirm is not None else seen["confirm"], **kw)
    return seen, done


def _cut_from(env, seq):
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq >= seq).delete()
        db.commit()


def _sealed_day(env, hours=6):
    ids = [env.row(T0 - timedelta(hours=10, minutes=-m * 10)) for m in range(hours)]
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(hours=12))
    return ids


def test_a_cut_tail_is_accepted_and_the_server_takes_the_new_generation(env):
    _sealed_day(env)
    newest = env.seals()[-1].seq
    _cut_from(env, newest - 3)
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen, done = _accept(env)
    text = "\n".join(seen["lines"])
    assert "a prefix of the recorded one" in text and seen["confirm"] == []
    seal = env.seals()[-1]
    assert seal.kind == "restore" and seal.detail["cause"] == "database"
    assert seal.detail["lost_through_seq"] == newest and seal.detail["grace_until"]
    assert fmt.parse_time_text(seal.detail["grace_until"]) - seal.sealed_at == timedelta(days=done["grace_days"])
    assert done["generation"] == 2
    assert host_rows(env, restore.RESTORED_ACTION) == [{"cause": "database", "lost_through_seq": newest,
                                                        "deleted_through_seq": None}]
    env.clock.advance(hours=1)
    assert env.seal().stopped is None                    # the same process, no restart
    assert env.st.view.generation == 2
    report = env.verify()
    assert failures(report) == []


def test_the_cut_hours_rows_edited_are_named_and_recorded(env):
    ids = _sealed_day(env)
    # Cut the tail back to before the hour of the newest rows, then edit a row of that hour.
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    root = env.st.view.entry_for(hour).root
    _cut_from(env, root.seq)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[0]).update({AuditLog.username: "mallory"})
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen, _done = _accept(env)
    assert any(fmt.hour_text(hour) in ln and "a change made while its seal was missing" in ln
               for ln in seen["lines"])
    seal = [s for s in env.seals() if s.kind == "restore"][0]
    assert [c[0] for c in seal.detail["hours"]["changed"]] == [fmt.hour_text(hour)]


def test_deleted_seals_with_their_rows_left_alone_are_named_and_confirmed_by_name(env):
    _sealed_day(env)
    newest = env.seals()[-1]
    _cut_from(env, newest.seq - 2)
    env.row(env.clock() - timedelta(minutes=5))          # a row the copy holds, written after the lost seals
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert seen["confirm"] and seen["confirm"][0].startswith("deleted-through-")
    assert any("SEALS WERE DELETED" in ln for ln in seen["lines"])
    with pytest.raises(host.Refused, match="confirm by name"):
        restore.accept_database_head(env.engine, _host(env), expect=seen["state"], confirm=[])
    restore.accept_database_head(env.engine, _host(env), expect=seen["state"], confirm=seen["confirm"])
    seal = [s for s in env.seals() if s.kind == "restore"][0]
    assert seal.detail["hours"]["deleted_through_seq"] == int(seen["confirm"][0].split("-")[-1])
    told = [f for f in env.verify().findings if f.kind == "resealed-after-restore"]
    assert told and f"seals through {seal.detail['hours']['deleted_through_seq']} were deleted" in told[0].message


def test_a_cut_reaching_back_more_than_30_days_names_the_changed_day(env):
    old = env.row(T0 - timedelta(days=40, hours=5))
    env.row(T0 - timedelta(days=39, hours=5))
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=2))
    day = (T0 - timedelta(days=40, hours=5)).date()
    assert day.isoformat() in env.st.head_store().load()["days"]
    hour = ai.hour_floor(T0 - timedelta(days=40, hours=5))
    _cut_from(env, env.st.view.entry_for(hour).root.seq)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == old).update({AuditLog.action: "logout"})
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen, _done = _accept(env)
    seal = [s for s in env.seals() if s.kind == "restore"][0]
    assert seal.detail["hours"]["days_changed"] == [day.isoformat()]
    assert (day + timedelta(days=1)).isoformat() not in seal.detail["hours"]["days_changed"]


def test_a_chain_rewritten_from_some_seal_is_named_first(env):
    _sealed_day(env)
    hour_seal = [s for s in env.seals() if s.kind == "hour" and s.row_count][-1].seq
    _cut_from(env, hour_seal)
    from test_audit_chain_guards import _forge
    _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                        "user_id": None, "request": None})     # another seal in its place, under the key in force
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert f"rewritten-from-{hour_seal}" in seen["confirm"]
    assert any("THE CHAINS PART" in ln for ln in seen["lines"])
    with pytest.raises(host.Refused, match="confirm by name"):
        restore.accept_database_head(env.engine, _host(env), expect=seen["state"], confirm=[])


def test_a_chain_whose_newest_mac_does_not_verify_is_refused(env):
    _sealed_day(env)
    newest = env.seals()[-1].seq
    _cut_from(env, newest - 2)
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == newest - 3).update({AuditSeal.mac: b"\x00" * 32})
        db.commit()
    with pytest.raises(host.Refused, match="cannot be accepted"):
        restore.accept_database_head(env.engine, _host(env), read=True)


def test_a_lost_cancel_and_a_lost_hold_are_sealed_again(env):
    old = env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    admin = _admin(env)
    outcome = _change(env, admin, "audit_max_days", 30)
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    before_cut = env.seals()[-1].seq
    with ps.change_transaction(env.engine) as w:
        ps.cancel(w, outcome.change.id, admin)
    assert _change(env, admin, "logs_hold", True).status == "applied"
    _cut_from(env, before_cut + 1)
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen, done = _accept(env)
    assert done["cancels"] == [req] and done["resealed"] == ["logs_hold"]
    assert any("Lost: the cancel" in ln for ln in seen["lines"])
    kinds = [s.kind for s in env.seals()[-3:]]
    assert kinds == ["restore", "policy", "cancel"]
    assert env.seals()[-2].detail["cause"] == "restore"
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert req not in env.st.view.pending_requests()
    assert ps.numbers(env.st)["logs_hold"] is True
    assert failures(env.verify()) == []
    with env.session() as db:
        assert db.get(AuditLog, old) is not None


def test_a_lost_cancel_of_a_request_the_resealed_raise_supersedes_is_not_sealed_again(env):
    """A reduction asked for and cancelled, then a raise of the same setting, both cut from the tail: the restore
    seals the raise again, and that supersedes the request, so no cancel of it is written (a cancel of a request
    that is not pending would fail verification for good). The request's change row, which the restored database
    shows waiting, ends as superseded, as a newer change of the setting ends it on the panel."""
    from app.core import setting_changes as sc
    env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    admin = _admin(env)
    assert _change(env, admin, "audit_min_days", 30).status == "applied"
    outcome = _change(env, admin, "audit_min_days", 10)
    assert outcome.status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    before_cut = env.seals()[-1].seq
    with ps.change_transaction(env.engine) as w:
        ps.cancel(w, outcome.change.id, admin)
    assert _change(env, admin, "audit_min_days", 60).status == "applied"
    _cut_from(env, before_cut + 1)
    with env.session() as db:              # the database as it stood before the cancel and the raise
        change = db.get(ManagedSettingChange, outcome.change.id)
        change.status, change.decided_by, change.decided_by_name = sc.PENDING, None, None
        change.decided_at, change.reason = None, None
        db.get(ManagedSetting, "audit_min_days").value = 30
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen, done = _accept(env)
    assert any("Lost: the cancel" in ln for ln in seen["lines"])
    assert not any("Cancels sealed again" in ln for ln in seen["lines"])
    assert any(f"supersede (their rows end as superseded): request {req} (audit_min_days)" in ln
               for ln in seen["lines"]), seen["lines"]
    assert done["resealed"] == ["audit_min_days"] and done["cancels"] == []
    assert done["superseded"] == [str(outcome.change.id)]
    assert [s.kind for s in env.seals()[-2:]] == ["restore", "policy"]
    assert req not in env.st.view.pending_requests()
    with env.session() as db:
        change = db.get(ManagedSettingChange, outcome.change.id)
        assert (change.status, change.reason) == (sc.SUPERSEDED, "a value sealed again after a restore")
        assert sc.pending_for(db, "audit_min_days") == []
    # Asked again for a request no longer pending (as after a change between the restore and its cancels), the
    # cancels' own step writes nothing.
    before = len(env.seals())
    restore._reseal_cancels(env.engine, _host(env), [req])
    assert len(env.seals()) == before
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert ps.numbers(env.st)["audit_min_days"] == 60
    assert failures(env.verify()) == []


def test_a_lost_head_record_is_accepted_after_the_key_history_is_confirmed(env):
    _sealed_day(env)
    os.unlink(env.st.head_store().path)
    env.fresh_process()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-missing"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert any(c.startswith("key-history-") for c in seen["confirm"])
    restore.accept_database_head(env.engine, _host(env), expect=seen["state"], confirm=seen["confirm"])
    seal = [s for s in env.seals() if s.kind == "restore"][0]
    assert seal.detail["record_missing"] is True
    env.fresh_process()
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_a_database_that_lost_every_seal_gets_a_genesis_naming_the_lost_head(env):
    _sealed_day(env)
    head = env.verify().head
    _cut_from(env, 1)
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    _seen, done = _accept(env)
    genesis = env.seals()[0]
    assert genesis.kind == "genesis" and genesis.detail["replaces"] == head and genesis.detail["grace_until"]
    assert env.seals()[1].kind == "policy" and env.seals()[1].detail["cause"] == "genesis"
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_a_chain_ending_under_a_key_the_recorded_one_left_needs_rekey(env):
    env.settings.audit_chain_key = ""
    env.row(T0 - timedelta(hours=8))
    env.run_until_sealed()
    env.settings.audit_chain_key = KEY_TEXT
    env.clock.advance(hours=1)
    env.seal()
    key_seal = [s for s in env.seals() if s.kind == "key"][0].seq
    env.clock.advance(hours=2)
    env.seal()
    _cut_from(env, key_seal)                             # back to before the move: the chain ends under the left key
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert any(c.startswith("left-key-") for c in seen["confirm"])
    restore.accept_database_head(env.engine, _host(env), expect=seen["state"], confirm=seen["confirm"])
    assert [s for s in env.seals() if s.kind == "restore"][0].detail["under_left_key"]
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-not-current"
    # Reported for good, whatever the host does next.
    told = [f for f in env.verify().findings if f.kind == "restored-under-left-key"]
    assert told and told[0].severity == "information" and "anyone holding it could have written it" in told[0].message


# --------------------------------------------------------------------------- accept-restore

def _snapshot(env):
    env.engine.dispose()
    db_path = env.engine.url.database
    copy_db = db_path + ".bundle"
    shutil.copyfile(db_path, copy_db)
    record = env.st.head_store().load()
    return copy_db, record


def _restore_bundle(env, snap):
    """dockvault.py restore: the head record of the volume replaced is copied into the mark, the keys volume (the
    bundle's record) and the database are put back."""
    copy_db, bundle_record = snap
    path = env.st.head_store().path
    replaced = hr.read_file(path)
    env.engine.dispose()
    shutil.copyfile(copy_db, env.engine.url.database)
    hr._write_file(path, bundle_record)
    hr.write_mark(path, {"at": fmt.time_text(env.clock()), "bundle": "dockvault-test-1", "record": replaced,
                         "restored_record": bundle_record})
    env.fresh_process()


def test_a_whole_backup_restored_holds_deletion_until_accepted_and_names_what_it_undid(env):
    old = env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    admin = _admin(env)
    outcome = _change(env, admin, "audit_max_days", 30)
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    snap = _snapshot(env)
    with ps.change_transaction(env.engine) as w:
        ps.cancel(w, outcome.change.id, admin)
    _run_to(env, env.clock() + timedelta(days=8))
    _restore_bundle(env, snap)
    from app.core import retention
    retention.run_pass(env.session, now=env.clock())
    assert "restore-pending" in ai.status(env.st)["warnings"]
    with env.session() as db:
        assert db.get(AuditLog, old) is not None             # the request's delay ran out, nothing applies
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    assert any("Undone by the restore: the cancel" in ln for ln in seen["lines"])
    done = restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert done["cancels"] == [req]
    assert host_rows(env, restore.RESTORED_ACTION) == [{"cause": "backup", "bundle": "dockvault-test-1",
                                                        "acknowledges": done["acknowledged"]}]
    assert hr.read_mark(env.st.head_store().path) is None
    seal = [s for s in env.seals() if s.kind == "restore"][0]
    assert seal.detail["cause"] == "backup" and seal.detail["grace_until"]
    retention.run_pass(env.session, now=env.clock() + timedelta(minutes=30))
    assert req not in env.st.view.pending_requests()
    assert failures(env.verify()) == []
    # The change row the restored database showed waiting again is ended with its cancel.
    with env.session() as db:
        change = db.get(ManagedSettingChange, outcome.change.id)
        assert (change.status, change.decided_by_name) == ("cancelled", "operator@host")


def test_a_raise_a_whole_backup_restore_undid_is_sealed_again_and_stored(env):
    env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    admin = _admin(env)
    snap = _snapshot(env)
    assert _change(env, admin, "audit_admin_min_days", 400).status == "applied"
    env.clock.advance(hours=1)
    env.seal()
    _restore_bundle(env, snap)
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    done = restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert done["resealed"] == ["audit_admin_min_days"]
    with env.session() as db:
        assert db.get(ManagedSetting, "audit_admin_min_days").value == 400
    from app.core import retention
    retention.run_pass(env.session, now=env.clock() + timedelta(minutes=30))
    assert env.st.view.newest_state()["audit_admin_min_days"]["value"] == 400
    assert "unjustified-input" not in ai.status(env.st)["failures"]
    assert failures(env.verify()) == []


def test_a_waiting_change_the_raise_a_whole_backup_restore_undid_superseded_ends_with_it(env):
    """A reduction waiting when the backup was taken, then a raise of the same setting (which ended it): the
    restored database shows it waiting again. accept-restore seals the raise again, which supersedes it, and its
    change row ends as superseded in the same transaction instead of being shown as due for good."""
    from app.core import setting_changes as sc
    env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    admin = _admin(env)
    assert _change(env, admin, "audit_min_days", 30).status == "applied"
    waiting = _change(env, admin, "audit_min_days", 10)
    assert waiting.status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    snap = _snapshot(env)
    assert _change(env, admin, "audit_min_days", 60).status == "applied"
    env.clock.advance(hours=1)
    env.seal()
    _restore_bundle(env, snap)
    with env.session() as db:
        assert db.get(ManagedSettingChange, waiting.change.id).status == sc.PENDING
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    assert any(f"request {req} (audit_min_days)" in ln for ln in seen["lines"]), seen["lines"]
    done = restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert done["resealed"] == ["audit_min_days"] and done["superseded"] == [str(waiting.change.id)]
    with env.session() as db:
        assert db.get(ManagedSettingChange, waiting.change.id).status == sc.SUPERSEDED
        assert db.get(ManagedSetting, "audit_min_days").value == 60
    assert req not in env.st.view.pending_requests()
    env.clock.advance(hours=1)
    env.seal()
    assert failures(env.verify()) == []


def test_the_backup_windows_seals_are_acknowledged_and_a_later_one_is_not(env):
    env.row(T0 - timedelta(hours=8))
    env.run_until_sealed()
    copy_db, _rec = _snapshot(env)
    record_at_keys = env.st.head_store().load()           # the keys volume archived first ...
    env.clock.advance(hours=2)
    env.seal()                                            # ... a seal written meanwhile ...
    env.engine.dispose()
    shutil.copyfile(env.engine.url.database, copy_db)     # ... then the database part
    window = env.seals()[-1].seq
    env.clock.advance(hours=3)
    env.seal()
    _restore_bundle(env, (copy_db, record_at_keys))
    from app.core import retention
    retention.run_pass(env.session, now=env.clock())      # the first start: it accepts the window's seal
    from test_audit_chain_guards import _forge
    later = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                                "user_id": None, "request": None})
    env.clock.advance(minutes=10)
    retention.run_pass(env.session, now=env.clock())      # a running process accepts a later one
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    done = restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert window in done["acknowledged"] and later not in done["acknowledged"]
    env.clock.advance(minutes=30)
    env.seal()
    assert later in ai.unacknowledged_foreign(env.st.view, env.st.head_store().load())


# --------------------------------------------------------------------------- what a restore compares

def test_a_row_added_to_a_cut_hour_is_named_as_a_change_made_while_its_seal_was_missing(env):
    """The hour of the database's newest row may hold fewer rows than its lost seal summarised (an older copy);
    more is a change."""
    _sealed_day(env)
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    _cut_from(env, env.st.view.entry_for(hour).root.seq)
    env.row(hour + timedelta(minutes=59))
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert any(fmt.hour_text(hour) in ln and "a change made while its seal was missing" in ln
               for ln in seen["lines"]), seen["lines"]


def test_a_stable_value_edited_in_a_cut_hour_is_named(env):
    ids = _sealed_day(env)
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    _cut_from(env, env.st.view.entry_for(hour).root.seq)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[0]).update({AuditLog.action: "logout"})
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert any(fmt.hour_text(hour) in ln for ln in seen["lines"]), seen["lines"]


def test_a_cut_day_of_rows_without_a_nonce_is_compared_by_its_stable_digest(env):
    """A day older than the hour summaries whose rows have no nonce: its personal values cannot be compared
    once its salt is gone with the cut, so the day is compared by its stable digest, and an untouched day is no
    change."""
    env.row(T0 - timedelta(days=40, hours=5), nonce=False)
    env.row(T0 - timedelta(days=39, hours=5))
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=2))
    day = (T0 - timedelta(days=40, hours=5)).date()
    assert env.st.head_store().load()["days"][day.isoformat()]["salted"] is True
    hour = ai.hour_floor(T0 - timedelta(days=40, hours=5))
    _cut_from(env, env.st.view.entry_for(hour).root.seq)
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert not any(day.isoformat() in ln and "no longer give the digest" in ln for ln in seen["lines"]), \
        seen["lines"]


def test_the_grace_takes_the_longest_delay_the_chain_and_the_head_records_give(env):
    """The checkpoint a record kept: the chain's state with a one-day delay (another writer's, set aside) and
    its honoured form with nine days. The grace is the honoured nine, longer than the accepted chain's seven
    and the state's one."""
    env.run_until_sealed()
    assert restore.grace_days(env.st.view) == 7
    record = {"checkpoints": {"policy": {"state": {"reduction_delay_days": {"value": 1}},
                                         "honoured": {"reduction_delay_days": {"value": 9}}}}}
    assert restore.grace_days(env.st.view, record) == 9
    assert restore.grace_days(env.st.view, None, record) == 9


def test_the_grace_takes_envs_delay_when_it_is_longer_than_the_chains_and_the_head_records(env, monkeypatch):
    """RETENTION_REDUCTION_DELAY_DAYS raised to 12 in .env while sealing was stopped, longer than the accepted
    chain's 7 and the head record's 7 (and the 9 a record's honoured state gives): the grace is .env's 12, for
    accept-database-head's restore seal and for accept-restore's two records alike."""
    _sealed_day(env)
    newest = env.seals()[-1].seq
    _cut_from(env, newest - 2)
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    record = env.st.head_store().load()
    assert restore.grace_days(env.st.view, record) == 7
    monkeypatch.setenv("RETENTION_REDUCTION_DELAY_DAYS", "12")
    env.settings.retention_reduction_delay_days = 12
    honoured = {"checkpoints": {"policy": {"state": {"reduction_delay_days": {"value": 1}},
                                           "honoured": {"reduction_delay_days": {"value": 9}}}}}
    assert restore.grace_days(env.st.view, record, honoured) == 12
    seen, done = _accept(env)
    assert done["grace_days"] == 12 and any("Nothing is deleted for 12 days" in ln for ln in seen["lines"])
    seal = [s for s in env.seals() if s.kind == "restore"][-1]
    assert fmt.parse_time_text(seal.detail["grace_until"]) - seal.sealed_at == timedelta(days=12)
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_a_lost_cancel_is_not_offered_for_another_request_at_its_seq(env):
    """The database's seal at the cancelled request's seq is another request (its link is not the one the record
    kept): the cancel is not offered for it."""
    from test_audit_chain_guards import _forge
    env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    admin = _admin(env)
    outcome = _change(env, admin, "audit_max_days", 30)
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    with ps.change_transaction(env.engine) as w:
        ps.cancel(w, outcome.change.id, admin)
    env.clock.advance(hours=1)
    env.seal()
    _cut_from(env, req)
    other = _forge(env, "request", lambda seq, at: {
        "what": "setting", "request": str(uuid.uuid4()), "setting": "audit_max_days", "old": 0, "new": 60,
        "subject": None, "placeholder": None, "not_before": fmt.time_text(at + timedelta(days=7)),
        "audit_row": None, "by": "admin", "user_id": None})
    assert other == req
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    assert not any("Lost: the cancel" in ln for ln in seen["lines"]), seen["lines"]


# --------------------------------------------------------------------------- accept-restore

def test_accept_restore_raises_the_generation(env):
    env.row(T0 - timedelta(hours=8))
    env.run_until_sealed()
    snap = _snapshot(env)
    env.clock.advance(hours=2)
    env.seal()
    _restore_bundle(env, snap)
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert env.st.head_store().load()["generation"] == 2


def test_a_key_history_only_the_replaced_record_held_is_kept_and_the_left_key_named(env):
    """The chain moved to AUDIT_CHAIN_KEY after the backup: the restored chain is under the key it left. The
    restore says so, and the replaced record's key history stays in the record."""
    env.settings.audit_chain_key = ""
    env.row(T0 - timedelta(hours=8))
    env.run_until_sealed()
    snap = _snapshot(env)
    env.settings.audit_chain_key = KEY_TEXT
    env.clock.advance(hours=1)
    env.seal()
    moved_to = env.st.current_key().key_id
    assert any(e["key_id"] == moved_to for e in env.st.head_store().load()["keys"])
    _restore_bundle(env, snap)
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    assert any("WHICH THE REPLACED RECORD HAD LEFT" in ln for ln in seen["lines"]), seen["lines"]
    restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert any(e["key_id"] == moved_to for e in env.st.head_store().load()["keys"])


def test_a_seal_the_restored_record_listed_is_not_the_first_starts_whatever_the_marks_clock(env):
    """The host's clock behind the server's: the mark's time comes before the first start that accepted another
    writer's seal before the backup. That seal stays the restored record's (a warning), and the first start after
    the restore is the one whose seals the restore acknowledges."""
    from app.core import retention
    from test_audit_chain_guards import _forge
    env.row(T0 - timedelta(hours=8))
    env.run_until_sealed()
    mark_at = env.clock()
    listed = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                                 "user_id": None, "request": None})
    env.clock.advance(minutes=10)
    env.fresh_process()
    retention.run_pass(env.session, now=env.clock())          # a start accepts it: listed, not acknowledged
    copy_db, _rec = _snapshot(env)
    record_at_keys = env.st.head_store().load()
    env.clock.advance(hours=2)
    env.seal()                                                # a seal of the backup's window
    window = env.seals()[-1].seq
    env.engine.dispose()
    shutil.copyfile(env.engine.url.database, copy_db)
    path = env.st.head_store().path
    replaced = hr.read_file(path)
    shutil.copyfile(copy_db, env.engine.url.database)
    hr._write_file(path, record_at_keys)
    hr.write_mark(path, {"at": fmt.time_text(mark_at), "bundle": "dockvault-test-1", "record": replaced,
                         "restored_record": record_at_keys})
    env.fresh_process()
    env.clock.advance(minutes=10)
    retention.run_pass(env.session, now=env.clock())          # the first start after the restore
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    done = restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    assert window in done["acknowledged"] and listed not in done["acknowledged"], done


def test_a_cut_hour_whose_summary_holds_no_salt_is_compared_by_its_stable_root(env):
    """An hour whose summary holds no salt (as a prune's re-rooting leaves it) and whose rows have no nonce: its
    personal values cannot be compared, so an untouched hour is no change; a stable value edited is one."""
    ids = [env.row(T0 - timedelta(hours=10, minutes=-m * 10), nonce=False) for m in range(3)]
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(hours=12))
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    record = env.st.head_store().load()
    record["hours"][fmt.hour_text(hour)]["salt"] = None
    _cut_from(env, env.st.view.entry_for(hour).root.seq)
    held = _host(env).keys_held()

    def changed():
        with env.session() as db:
            view, problems = restore.database_chain(db, held, 2)
            assert problems == []
            return [c[0] for c in restore.lost_hours(db, view, record, env.clock())["changed"]]
    assert changed() == []
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[0]).update({AuditLog.action: "logout"})
        db.commit()
    assert changed() == [fmt.hour_text(hour)]
