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

from _audit_chain_env import Env, KEY_TEXT, T0, failures
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
    st.role = "host"
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
    assert done["generation"] == 2
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
