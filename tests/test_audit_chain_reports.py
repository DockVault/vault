"""What audit verify reports for good, as information (app/core/audit_chain_verify.py), offline:

- an erase seal, with its rows, hour and request;
- each gap of more than 12 hours in the seals' times, with the requests it pushed back (a request made before
  it and still pending), and none for a stop of 11 hours;
- a restore: the seals it lost and its grace, and the hours it sealed again with the ones it found changed.

The other kinds are pinned where their commands are tested: pruned (test_audit_chain_external), acknowledged
(test_audit_chain_recovery), restored-under-left-key and deleted seals (test_audit_chain_restore).
Runs on a throwaway SQLite database (tests/_audit_chain_env.py)."""
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_integrity as ai
from app.core.models import AuditLog
from test_audit_chain_guards import _append, _erase, _erase_request, _off, _request, _wait_days
from test_audit_chain_restore import _accept, _cut_from, _sealed_day

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _found(report, kind):
    return [f for f in report.findings if f.kind == kind]


def test_an_erase_is_reported_with_its_rows_hour_and_request(env):
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 8)
    seq = _erase(env, req, placeholder, hour, [[str(uuid.uuid4()), "00" * 32, "11" * 32]], final=True)
    found = _found(_off(env), "erased")
    assert [(f.severity, f.seq) for f in found] == [("information", seq)]
    assert f"1 rows of hour {fmt.hour_text(hour)} erased for request {req} (its last)" in found[0].message


def _cancel(env, req):
    return _append(env, "cancel", {"cancels": req, "request": None, "audit_row": None, "by": "admin",
                                   "user_id": None})


def test_a_stop_of_more_than_12_hours_is_a_gap_naming_the_requests_it_pushed_back(env):
    env.run_until_sealed()
    ended = _append(env, "request", _request("setting", setting="audit_max_days", old=None, new=95))
    _cancel(env, ended)                                  # ended before the gap: not pushed back
    across = _append(env, "request", _request("setting", setting="audit_max_days", old=None, new=92))
    req = _append(env, "request", _request("setting", setting="audit_max_days", old=None, new=90))
    env.clock.advance(hours=11)                          # a stop of 11 hours pushes nothing back
    env.seal()
    assert _found(_off(env), "gap") == []
    env.clock.advance(hours=13)
    env.seal()
    _cancel(env, across)                                 # pending across the gap, ended after it: pushed back
    gaps = _found(env.verify(), "gap")
    assert len(gaps) == 1 and gaps[0].severity == "information"
    assert "(13.0 hours)" in gaps[0].message
    assert gaps[0].message.endswith(f"requests pushed back by it: {across}, {req}")
    # A request made after the gap is not pushed back by it.
    later = _append(env, "request", _request("setting", setting="audit_max_days", old=None, new=80))
    assert str(later) not in _found(env.verify(), "gap")[0].message.split(": ")[-1].split(", ")


def test_a_restore_is_reported_for_good_with_the_hours_it_sealed_again(env):
    ids = _sealed_day(env)
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    root = env.st.view.entry_for(hour).root
    newest = env.seals()[-1].seq
    _cut_from(env, root.seq)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[0]).update({AuditLog.username: "mallory"})
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    _accept(env)
    rseq = [s for s in env.seals() if s.kind == "restore"][-1].seq
    for _ in range(3):
        env.clock.advance(hours=6)
        env.seal()
    report = env.verify()
    assert failures(report) == []
    restored = _found(report, "restored")
    assert [f.seq for f in restored] == [rseq]
    assert f"seals {root.seq}-{newest} lost" in restored[0].message and "nothing deleted until" in restored[0].message
    resealed = _found(report, "resealed-after-restore")
    assert [f.seq for f in resealed] == [rseq]
    assert "sealed again from their rows" in resealed[0].message
    assert f"changed: {fmt.hour_text(hour)}" in resealed[0].message


def test_the_daily_check_leaves_out_what_each_seal_did(env):
    """The server's daily check keeps only failures and warnings; audit verify reports the rest."""
    from app.core import audit_chain_verify as v
    env.run_until_sealed()
    env.clock.advance(hours=13)
    env.seal()
    report = v.daily_check(env.session, env.st, force=True)
    assert report is not None and "gap" not in report.kinds() and "gap" in env.verify().kinds()
