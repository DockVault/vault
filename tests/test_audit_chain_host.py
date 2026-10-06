"""The host's acknowledgments of the audit chain, in two phases (app/core/audit_chain_host.py), offline:

- every command reads first and prints the state it saw; the write refuses when the chain or the rows changed
  in between;
- acknowledging another writer's seal first says what it starts: an applies' due date, what the pruner then
  acts on;
- ``--rows``: a row holding a value no release writes is a failure until the host has looked at it, then
  information;
- ``--late-rows``: rows added to a sealed hour after the 6-hour window are sealed by a host late seal, which
  counts as acknowledged; a row added, or a sealed row changed, between the phases makes the write refuse.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_integrity as ai
from app.core.models import AuditLog
from test_audit_chain_dates import _admin_reduction_due, _applies_of

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _both(fn, *args, **kw):
    seen = fn(*args, read=True, **kw)
    return seen, fn(*args, expect=seen["state"], **kw)


def test_acknowledging_another_writers_applies_says_when_its_value_counts(env):
    env.run_until_sealed()
    req = _admin_reduction_due(env, 90)
    applies = _applies_of(env, req, 90)
    env.clock.advance(minutes=30)
    env.seal()
    seen = host.acknowledge(env.engine, env.st, seqs=[applies], failures=False, read=True)
    text = "\n".join(seen["lines"])
    assert f"applies request {req}" in text and "counts from the later" in text
    assert "audit_max_days: 0" in text and "-> 90" in text
    host.acknowledge(env.engine, env.st, seqs=[applies], failures=False, expect=seen["state"])
    assert env.st.view.newest_state()["audit_max_days"]["value"] == 90


def _unwritable_row(env, at):
    rid = env.row(at)
    with env.engine.begin() as conn:
        conn.exec_driver_sql("UPDATE audit_logs SET details = ? WHERE id = ?", ('{"n": 1e400}', rid.hex))
    return rid


def test_a_value_no_release_writes_is_a_failure_until_the_host_acknowledges_the_row(env):
    plain = env.row(T0 - timedelta(hours=6))
    odd = _unwritable_row(env, T0 - timedelta(hours=6, minutes=-5))
    env.run_until_sealed()
    report = env.verify()
    assert any("value-not-writable" in f.message and str(odd) in f.message for f in report.findings
               if f.kind == "rows-altered")
    with pytest.raises(host.Refused, match="not a row holding a value"):
        host.acknowledge(env.engine, env.st, seqs=[], failures=False, rows=[str(plain)], read=True)
    seen, done = _both(host.acknowledge, env.engine, env.st, seqs=[], failures=False, rows=[str(odd)])
    assert done["rows"] == [str(odd)] and any(str(odd) in ln for ln in seen["lines"])
    assert env.seals()[-1].detail["rows"] == [str(odd)]
    report = env.verify()
    assert failures(report) == [] and "value-not-writable" in report.kinds("information")


def _late_after_window(env):
    """A row added to an hour sealed more than 6 hours before: a failure, not a late seal."""
    env.row(T0 - timedelta(hours=10))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=10))
    env.clock.advance(hours=8)
    env.seal()
    added = env.row(hour + timedelta(minutes=40))
    env.clock.advance(hours=1)
    env.seal()
    assert not [s for s in env.seals() if s.kind == "late"]
    assert "rows-added" in failures(env.verify())
    return hour, added


def test_the_host_seals_rows_added_after_the_window_once_it_has_read_them(env):
    hour, added = _late_after_window(env)
    seen = host.seal_late_rows(env.engine, env.st, hour, read=True)
    assert str(added) in "\n".join(seen["lines"])
    done = host.seal_late_rows(env.engine, env.st, hour, expect=seen["state"])
    late = env.seals()[-1]
    assert late.kind == "late" and late.detail["by"] == "host" and late.detail["added"] == [str(added)]
    assert done["sealed"] == late.seq
    report = env.verify()
    assert failures(report) == [] and "late" not in report.kinds("warning")
    assert "late" not in ai.status(env.st)["warnings"]


def test_a_row_added_between_the_phases_makes_the_late_seal_refuse(env):
    hour, _added = _late_after_window(env)
    seen = host.seal_late_rows(env.engine, env.st, hour, read=True)
    env.row(hour + timedelta(minutes=50))
    with pytest.raises(host.Refused, match="changed since you looked"):
        host.seal_late_rows(env.engine, env.st, hour, expect=seen["state"])
    assert env.seals()[-1].kind != "late"


def test_rows_of_the_seal_changed_too_are_never_sealed_over(env):
    hour, _added = _late_after_window(env)
    with env.session() as db:
        first = db.query(AuditLog).filter(AuditLog.timestamp == T0 - timedelta(hours=10)).one()
        first.username = "mallory"
        db.commit()
    with pytest.raises(host.Refused, match="changed too"):
        host.seal_late_rows(env.engine, env.st, hour, read=True)


def test_a_late_row_in_an_hour_inside_a_run_is_sealed_by_the_host(env):
    env.row(T0 - timedelta(days=3))
    env.row(T0 - timedelta(hours=2))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(days=2))
    assert env.st.view.entry_for(hour).is_run
    env.clock.advance(hours=8)
    env.seal()
    added = env.row(hour + timedelta(minutes=5), nonce=False)
    _seen, done = _both(host.seal_late_rows, env.engine, env.st, hour)
    assert done["added"] == 1 and env.st.view.has_own(hour)
    assert failures(env.verify()) == []
    with env.session() as db:
        assert ai.working_row(db, hour).legacy_salt is not None
    assert added is not None
