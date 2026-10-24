"""The host's commands that let sealing go on after it stopped (app/core/audit_chain_recovery.py), offline:

- rekey: a key changed without the old one waits until the host gives it (--old-key-file), and the key seal
  carries its proof; a lost key: --accept-unverified-history, listed in the head record, information for good;
  a return to a key the chain left needs a confirmation; dockvault.py's key change in one step;
- after-record: a host command that crashed before its record write is finished by accepting its seal; a seal
  refused on its face is discarded, its rows saved, the deletion and its ack seal in one transaction, and the
  server's view rebuilt from the higher discard count; a seal a writer accepted is never discarded.

Each host command runs in a process of its own (a chain state of its own); the server's process takes the
head record the host wrote at its next check. Runs on a throwaway SQLite database (tests/_audit_chain_env.py)."""
import json
import os
from datetime import timedelta

import pytest

from _audit_chain_env import Env, KEY_TEXT, T0, failures, host_rows
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_recovery as recovery
from app.core import audit_head_record as hr
from app.core import audit_integrity as ai
from app.core.models import AuditSeal
from test_audit_chain_guards import _forge

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _host(env):
    """The host tool's process: a chain state of its own, on the same database and head record."""
    st = ai.ChainState(settings=env.settings, clock=env.clock)
    st.process_kind = "host"
    return st


def _two(env, fn, **kw):
    seen = fn(env.engine, _host(env), read=True, **kw)
    return seen, fn(env.engine, _host(env), expect=seen["state"], **kw)


def _key_changed_without_the_old_one(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    env.settings.audit_chain_key = "e" * 64
    env.settings.encryption_key = "Z2hhbmdlbWVjaGFuZ2VtZWNoYW5nZW1lY2hhbmdlbWU="
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-change-waiting"


# --------------------------------------------------------------------------- rekey

def test_rekey_with_the_old_key_moves_the_chain_with_its_proof(env):
    _key_changed_without_the_old_one(env)
    with pytest.raises(host.Refused, match="not held"):
        recovery.rekey(env.engine, _host(env), read=True)
    old = fmt.chain_key(KEY_TEXT)
    seen, done = _two(env, recovery.rekey, old_key=old)
    key_seal = env.seals()[-1]
    assert key_seal.kind == "key" and key_seal.detail["old_key_proof"] and key_seal.detail["by"] == "host"
    assert done["to"] == env.st.current_key().key_id
    # Its audit row keeps what it did: the key ids it moved between (never read as an email address).
    assert host_rows(env, recovery.KEY_ACTION) == [{"from_key": key_seal.detail["old_key_id"], "to_key": done["to"],
                                                    "proof": True}]
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    report = env.verify()
    assert failures(report) == [] and "key-change-waiting" not in report.kinds("warning")


def test_rekey_says_of_the_key_given_whether_this_chain_was_ever_under_it(env):
    """dockvault.py's key change keeps the old key in a file until the chain has moved off it, and says to remove that
    file once rekey says its key is no longer needed. rekey says so only of a key this chain was under: of one it was
    never under (another volume set's chain key, say) it says it is not this chain's, before and after a move, and
    whether or not there is anything to do."""
    _key_changed_without_the_old_one(env)
    old = fmt.chain_key(KEY_TEXT)
    stranger = fmt.chain_key("f" * 64)
    with pytest.raises(host.Refused) as why:
        recovery.rekey(env.engine, _host(env), old_key=stranger, read=True)
    assert "is not held" in str(why.value)
    assert f"The key given ({fmt.key_id(stranger)}) was never in force on this chain" in str(why.value)
    seen = recovery.rekey(env.engine, _host(env), old_key=old, read=True)
    assert f"The key given ({fmt.key_id(old)}) is the one the chain is under: once the key seal is written, it is " \
           "no longer needed." in seen["lines"]
    recovery.rekey(env.engine, _host(env), old_key=old, expect=seen["state"])
    with pytest.raises(host.Refused) as why:
        recovery.rekey(env.engine, _host(env), old_key=old, read=True)
    told = str(why.value)
    assert "already under the current key" in told and "nothing to do" in told
    assert f"The key given ({fmt.key_id(old)}) is one this chain was under before it moved on: it is no longer " \
           "needed" in told
    with pytest.raises(host.Refused) as why:
        recovery.rekey(env.engine, _host(env), old_key=stranger, read=True)
    told = str(why.value)
    assert "nothing to do" in told and "was never in force on this chain: it is not this chain's old key" in told
    assert "no longer needed" not in told
    with pytest.raises(host.Refused, match=r"is the current key, not an old one"):
        recovery.rekey(env.engine, _host(env), old_key=fmt.chain_key(env.settings.audit_chain_key), read=True)
    with pytest.raises(host.Refused) as why:
        recovery.rekey(env.engine, _host(env), read=True)
    assert str(why.value).endswith("nothing to do")


def test_rekey_moving_with_a_key_the_server_holds_says_the_key_given_was_not_this_chains(env):
    """The chain is under the key derived from ENCRYPTION_KEY, which the server always holds: the move needs no key
    given, and a key given that the chain was never under is said not to be its."""
    env.settings.audit_chain_key = ""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    env.settings.audit_chain_key = "e" * 64
    stranger = fmt.chain_key("f" * 64)
    seen = recovery.rekey(env.engine, _host(env), old_key=stranger, read=True)
    assert any(f"The key given ({fmt.key_id(stranger)}) was never in force on this chain" in ln
               for ln in seen["lines"])
    assert not any("no longer needed" in ln for ln in seen["lines"])


def test_a_lost_old_key_is_accepted_without_its_proof_and_reported_for_good(env):
    _key_changed_without_the_old_one(env)
    seen = recovery.rekey(env.engine, _host(env), accept_unverified=True, read=True)
    text = "\n".join(seen["lines"])
    assert "WITHOUT the old key's proof" in text and "head record: seal" in text
    recovery.rekey(env.engine, _host(env), accept_unverified=True, expect=seen["state"])
    key_seal = env.seals()[-1]
    assert key_seal.detail["accepted_unverified"] is True and key_seal.detail["old_key_proof"] is None
    record = env.st.head_store().load()
    assert any(e["seq"] == key_seal.seq for e in record["unverified_keys"])
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    report = env.verify()
    assert failures(report) == [] and "key-accepted-unverified" in report.kinds("information")


def test_rekey_refuses_a_newest_seal_that_does_not_verify_under_the_old_key(env):
    _key_changed_without_the_old_one(env)
    newest = env.seals()[-1].seq
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == newest).update({AuditSeal.mac: b"\x00" * 32})
        db.commit()
    with pytest.raises(host.Refused, match="does not verify"):
        recovery.rekey(env.engine, _host(env), old_key=fmt.chain_key(KEY_TEXT), read=True)
    assert env.seals()[-1].kind != "key"


def test_a_lost_key_is_never_accepted_in_one_step(env):
    _key_changed_without_the_old_one(env)
    with pytest.raises(host.Refused, match="never written in one step"):
        recovery.rekey(env.engine, _host(env), accept_unverified=True, one_step=True)
    assert env.seals()[-1].kind != "key"


def _shared_then_own(env):
    env.settings.audit_chain_key = ""
    env.run_until_sealed()
    env.settings.audit_chain_key = KEY_TEXT
    env.clock.advance(hours=1)
    env.seal()
    assert [s for s in env.seals() if s.kind == "key"]


def test_a_return_to_a_key_the_chain_left_needs_a_confirmation(env):
    _shared_then_own(env)
    env.settings.audit_chain_key = ""
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-not-current"
    old = fmt.chain_key(KEY_TEXT)
    seen = recovery.rekey(env.engine, _host(env), old_key=old, read=True)
    assert seen["returning"] and "--confirm-return" in "\n".join(seen["lines"])
    with pytest.raises(host.Refused, match="--confirm-return"):
        recovery.rekey(env.engine, _host(env), old_key=old, expect=seen["state"])
    with pytest.raises(host.Refused, match="never written in one step"):
        recovery.rekey(env.engine, _host(env), old_key=old, one_step=True)
    recovery.rekey(env.engine, _host(env), old_key=old, expect=seen["state"], confirm_return=True)
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_the_key_change_of_dockvault_is_one_step_forward_with_its_proof(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    env.settings.audit_chain_key = "e" * 64
    done = recovery.rekey(env.engine, _host(env), old_key=fmt.chain_key(KEY_TEXT), one_step=True)
    assert done["to"] == env.st.current_key().key_id and env.seals()[-1].detail["old_key_proof"]
    env.clock.advance(hours=1)
    assert env.seal().stopped is None and failures(env.verify()) == []


# --------------------------------------------------------------------------- after-record

def test_a_host_seal_whose_record_write_was_lost_is_finished_by_after_record(env, monkeypatch):
    env.row(T0 - timedelta(hours=10))
    env.run_until_sealed()
    env.row(ai.hour_floor(T0 - timedelta(hours=10)) + timedelta(minutes=30))
    env.clock.advance(hours=8)
    env.seal()
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    seen = host.seal_late_rows(env.engine, _host(env), hour, read=True)
    # The host command crashes between its commit and its record write.
    with monkeypatch.context() as m:
        m.setattr(hr.HeadStore, "write", lambda self, change, now: (_ for _ in ()).throw(OSError("full")))
        with pytest.raises(Exception):
            host.seal_late_rows(env.engine, _host(env), hour, expect=seen["state"])
    assert env.seals()[-1].kind == "late"
    env.fresh_process()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "host-seal-unrecorded"
    seen, done = _two(env, recovery.after_record)
    assert env.seals()[-2].kind == "late" and env.seals()[-1].kind == "ack"
    assert "host-seal-unrecorded" in done["failures"]
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def _refused_on_its_face(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    seq = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                              "user_id": None, "request": None}, sealed_at=env.clock() - timedelta(hours=3))
    env.clock.advance(minutes=30)
    assert env.seal().stopped == "after-record-invalid"
    return seq


def test_a_seal_refused_on_its_face_is_discarded_with_its_rows_saved(env):
    seq = _refused_on_its_face(env)
    seen, done = _two(env, recovery.after_record, discard=True)
    assert done["discarded"] == [seq] and os.path.exists(done["saved"])
    with open(done["saved"], encoding="utf-8") as fh:
        assert json.load(fh)[0]["seq"] == seq
    ack = env.seals()[-1]
    assert ack.seq == seq and ack.kind == "ack" and ack.detail["discarded"][0][0] == seq
    assert host_rows(env, recovery.DISCARDED_ACTION) == [{"seals": [seq], "saved": done["saved"]}]
    record = env.st.head_store().load()
    assert record["discards"] == 1
    # The server's process, which read the chain before, rebuilds its view from the higher discard count.
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    report = env.verify()
    assert failures(report) == []
    told = [f for f in report.findings if f.kind == "acknowledged" and f.seq == ack.seq]
    assert told and "by host" in told[0].message and f"discarded seals {seq}" in told[0].message


def test_the_saved_seals_of_a_discard_are_handed_to_their_owner_before_they_are_synced(env, monkeypatch, tmp_path):
    """A discard run as root saves the seals in a file given the keys directory's owner before its sync, so the file
    synced is the final one, owner and all."""
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    events = []
    real_fsync = os.fsync
    monkeypatch.setattr(hr.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(hr.os, "chown", lambda path, uid, gid: events.append(("chown", path)), raising=False)
    monkeypatch.setattr(os, "fsync", lambda fd: (events.append(("fsync", fd)), real_fsync(fd))[1])
    with env.session() as db:
        target = recovery._save_discarded(str(tmp_path / "audit-chain-head.json"), db, 1, env.clock())
    with open(target, encoding="utf-8") as fh:
        assert json.load(fh)
    # Then its name, the directory, before the deletion of the seals commits (not on Windows).
    assert [e[0] for e in events] == ["chown", "fsync"] + (["fsync"] if os.name != "nt" else []), events
    assert events[0][1] == target


def test_a_discard_that_fails_leaves_the_seals_and_writes_no_ack(env, monkeypatch):
    seq = _refused_on_its_face(env)
    seen = recovery.after_record(env.engine, _host(env), discard=True, read=True)
    real = ai.ChainWriter.append

    def broken(self, kind, **kw):
        raise RuntimeError("crash")
    monkeypatch.setattr(ai.ChainWriter, "append", broken)
    with pytest.raises(RuntimeError):
        recovery.after_record(env.engine, _host(env), discard=True, expect=seen["state"])
    monkeypatch.setattr(ai.ChainWriter, "append", real)
    assert env.seals()[-1].seq == seq
    assert env.st.head_store().load()["discards"] == 0


def test_rekey_writes_only_the_state_its_read_printed(env):
    _key_changed_without_the_old_one(env)
    old = fmt.chain_key(KEY_TEXT)
    with pytest.raises(host.Refused, match="changed since you looked"):
        recovery.rekey(env.engine, _host(env), old_key=old, expect="dvstate1:" + "0" * 64)
    assert env.seals()[-1].kind != "key"


def test_a_seal_after_the_record_whose_mac_does_not_verify_is_never_accepted(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    seq = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                              "user_id": None, "request": None})
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == seq).update({AuditSeal.mac: b"\x00" * 32})
        db.commit()
    seen = recovery.after_record(env.engine, _host(env), read=True)
    assert any("REFUSED: its MAC does not verify" in ln for ln in seen["lines"]), seen["lines"]
    with pytest.raises(host.Refused, match="cannot be accepted"):
        recovery.after_record(env.engine, _host(env), expect=seen["state"])
    assert env.seals()[-1].seq == seq


def _unproven_key_seal(env):
    """A key seal another writer appended with no proof (accepted_unverified), under a new current key."""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    old_id = env.st.view.key_in_force()
    env.settings.audit_chain_key = "e" * 64
    new = env.st.current_key()
    return _forge(env, "key", {"old_key_id": old_id, "new_key_id": new.key_id, "old_key_proof": None,
                               "accepted_unverified": True, "by": "host"}, key=new)


def test_a_key_seal_with_no_proof_is_accepted_only_when_the_host_says_it_wrote_it(env):
    seq = _unproven_key_seal(env)
    seen = recovery.after_record(env.engine, _host(env), read=True)
    assert any("--confirm-unverified" in ln for ln in seen["lines"]), seen["lines"]
    with pytest.raises(host.Refused, match="cannot be accepted"):
        recovery.after_record(env.engine, _host(env), expect=seen["state"])
    seen = recovery.after_record(env.engine, _host(env), read=True, confirm_unverified=True)
    done = recovery.after_record(env.engine, _host(env), expect=seen["state"], confirm_unverified=True)
    assert seq in done["accepted"]


def test_a_seal_a_writer_accepted_is_never_discarded(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    accepted = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                                   "user_id": None, "request": None})
    env.clock.advance(minutes=30)
    assert env.seal().stopped is None
    with pytest.raises(host.Refused, match="accepted"):
        recovery.after_record(env.engine, _host(env), discard=True, discard_from=accepted, read=True)
    with pytest.raises(host.Refused):
        recovery.after_record(env.engine, _host(env), discard=True, read=True)


def test_after_record_accepts_another_writers_listed_seals_for_good(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    seq = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                              "user_id": None, "request": None})
    env.clock.advance(minutes=30)
    env.seal()
    assert seq in ai.unacknowledged_foreign(env.st.view, env.st.head_store().load())
    # Listed by the head record and not acknowledged: verify's own report warns of it, and exits 1.
    report = env.verify()
    assert [(f.severity, f.seq) for f in report.findings if f.kind == "after-record"] == [("warning", seq)]
    assert report.exit_code == 1
    _two(env, recovery.after_record)
    assert host_rows(env, recovery.ACCEPTED_ACTION) == [{"seals": [seq], "failures": []}]
    env.clock.advance(minutes=30)
    env.seal()
    assert seq not in ai.unacknowledged_foreign(env.st.view, env.st.head_store().load())
    report = env.verify()
    assert "after-record" not in report.kinds("warning")
    assert any(f.kind == "acknowledged" and f"by host: seals {seq}" in f.message for f in report.findings)


# --------------------------------------------------------------------------- seals while the chain is to move

def _waiting_to_move(env):
    """A chain under the key derived from ENCRYPTION_KEY, and AUDIT_CHAIN_KEY set since (by hand, or by
    audit change-key with no key before): the chain moves to it on its own at the sealer's next pass."""
    env.settings.audit_chain_key = ""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    derived = env.st.current_key().key_id
    env.settings.audit_chain_key = "f" * 64
    return derived


def test_a_change_made_before_the_chain_moves_to_a_new_key_goes_under_the_key_it_is_under(env):
    """An administrator's change in the minute between the restart under a new AUDIT_CHAIN_KEY and the sealer's
    move: its seal goes under the key the chain is still under, never under the new one (that would break the key
    sequence for good), and the move follows it."""
    from test_audit_chain_trust import _admin, _change
    derived = _waiting_to_move(env)
    admin = _admin(env)
    before = len(env.seals())
    assert _change(env, admin, "logs_hold", True).status == "applied"
    new = [(s.kind, s.key_id) for s in env.seals()[before:]]
    assert new == [("policy", derived)]
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    moved = [s for s in env.seals()[before:] if s.kind == "key"]
    assert moved and moved[0].detail["old_key_id"] == derived and moved[0].key_id == env.st.current_key().key_id
    assert failures(env.verify()) == []


def test_an_env_change_with_a_new_key_is_sealed_under_the_key_the_chain_is_under_and_the_chain_then_moves(
        env, monkeypatch):
    """The restart that brings a new AUDIT_CHAIN_KEY changes a retention line of .env too: the policy seal of the
    .env change, written before the sealer moves the chain, goes under the key the chain is still under."""
    derived = _waiting_to_move(env)
    monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "400")
    before = len(env.seals())
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    new = [(s.kind, s.key_id) for s in env.seals()[before:]]
    assert new[:2] == [("policy", derived), ("key", env.st.current_key().key_id)], new
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_a_seal_under_a_key_other_than_the_one_in_force_is_never_written(env):
    """A writer that asks for a seal under another key than the one in force at its position (but a key seal that
    moves on), or under the key in force when it does not hold it, is refused, and nothing is written."""
    from app.core import audit_chain_keys as keys
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    before = [(s.seq, s.key_id) for s in env.seals()]
    other_key = fmt.chain_key("9" * 64)
    other = keys.ChainKey(other_key, fmt.key_id(other_key), "given")
    ack = {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "host", "user_id": None,
           "request": None}
    with pytest.raises(ai.NotUnderKeyInForce, match="not the key in force"):
        with ai.ChainWriter(env.engine, _host(env), writer="host", check_key=False) as w:
            w.append("ack", detail=dict(ack), key=other)
    env.settings.audit_chain_key = "e" * 64
    env.settings.encryption_key = "Z2hhbmdlbWVjaGFuZ2VtZWNoYW5nZW1lY2hhbmdlbWU="
    with pytest.raises(ai.NotUnderKeyInForce, match="does not hold"):
        with ai.ChainWriter(env.engine, _host(env), writer="host", check_key=False) as w:
            w.append("ack", detail=dict(ack))
    assert [(s.seq, s.key_id) for s in env.seals()] == before


def test_after_record_writes_its_ack_under_the_key_in_force_given_with_old_key_file(env):
    """A seal after the head record to discard, while the chain is under a key this process no longer holds (a key
    change whose move waits): the ack goes under the key in force, so it needs that key; without it after-record says
    so and writes nothing, with it the ack is under it, and rekey then moves the chain."""
    seq = _refused_on_its_face(env)
    old_kid = env.st.current_key().key_id
    env.settings.audit_chain_key = "e" * 64
    env.settings.encryption_key = "Z2hhbmdlbWVjaGFuZ2VtZWNoYW5nZW1lY2hhbmdlbWU="
    seen = recovery.after_record(env.engine, _host(env), discard=True, read=True)
    assert any(f"The ack seal goes under {old_kid}" in ln for ln in seen["lines"]), seen["lines"]
    with pytest.raises(host.Refused, match="--old-key-file. Nothing was written"):
        recovery.after_record(env.engine, _host(env), discard=True, expect=seen["state"])
    assert env.seals()[-1].seq == seq
    old = fmt.chain_key(KEY_TEXT)
    seen = recovery.after_record(env.engine, _host(env), discard=True, read=True, old_key=old)
    recovery.after_record(env.engine, _host(env), discard=True, expect=seen["state"], old_key=old)
    ack = env.seals()[-1]
    assert (ack.seq, ack.kind, ack.key_id) == (seq, "ack", old_kid)
    seen = recovery.rekey(env.engine, _host(env), old_key=old, read=True)
    recovery.rekey(env.engine, _host(env), old_key=old, expect=seen["state"])
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_after_record_accepts_under_the_key_in_force_given_with_old_key_file(env, monkeypatch):
    """A host seal whose record write was lost, accepted while the chain is under a key this process no longer holds:
    the ack goes under that key, given with --old-key-file, and rekey then moves the chain."""
    env.row(T0 - timedelta(hours=10))
    env.run_until_sealed()
    env.row(ai.hour_floor(T0 - timedelta(hours=10)) + timedelta(minutes=30))
    env.clock.advance(hours=8)
    env.seal()
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    seen = host.seal_late_rows(env.engine, _host(env), hour, read=True)
    with monkeypatch.context() as m:
        m.setattr(hr.HeadStore, "write", lambda self, change, now: (_ for _ in ()).throw(OSError("full")))
        with pytest.raises(Exception):
            host.seal_late_rows(env.engine, _host(env), hour, expect=seen["state"])
    old_kid = env.st.current_key().key_id
    env.settings.audit_chain_key = "e" * 64
    env.settings.encryption_key = "Z2hhbmdlbWVjaGFuZ2VtZWNoYW5nZW1lY2hhbmdlbWU="
    env.fresh_process()
    old = fmt.chain_key(KEY_TEXT)
    seen = recovery.after_record(env.engine, _host(env), read=True, old_key=old)
    recovery.after_record(env.engine, _host(env), expect=seen["state"], old_key=old)
    ack = env.seals()[-1]
    assert (ack.kind, ack.key_id) == ("ack", old_kid)
    seen = recovery.rekey(env.engine, _host(env), old_key=old, read=True)
    recovery.rekey(env.engine, _host(env), old_key=old, expect=seen["state"])
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_a_seal_after_a_key_seal_in_the_same_transaction_goes_under_the_key_moved_to(env):
    """A writer that moves the chain and then writes another seal before it commits: that seal is under the key the
    key seal moved to, the key in force at its position."""
    _waiting_to_move(env)
    before = len(env.seals())
    with ai.ChainWriter(env.engine, env.st) as w:
        assert w.key_move is not None
        ai.write_key_move(w)
        w.append("ack", detail={"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                                "user_id": None, "request": None})
    new = [(s.kind, s.key_id) for s in env.seals()[before:]]
    current = env.st.current_key().key_id
    assert new == [("key", current), ("ack", current)]
    env.clock.advance(hours=1)
    assert env.seal().stopped is None
    assert "key-sequence" not in failures(env.verify())
