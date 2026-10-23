"""The host's acknowledgments of the audit chain, in two phases (app/core/audit_chain_host.py), offline:

- every command reads first and prints the state it saw; the write refuses when the chain or the rows changed
  in between, and reads all it compares in one snapshot, taken before it reads anything;
- acknowledging another writer's seal first says what it starts: an applies' due date, what the pruner then
  acts on;
- ``--rows``: a row holding a value no release writes is a failure until the host has looked at it, then
  information;
- ``--late-rows``: rows added to a sealed hour after the 6-hour window are sealed by a host late seal, which
  counts as acknowledged; a row added, or a sealed row changed, between the phases makes the write refuse.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures, host_rows
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
    assert host_rows(env, host.ACKNOWLEDGED_ACTION) == [{"acknowledges": [], "failures": [], "rows": [str(odd)]}]
    report = env.verify()
    assert failures(report) == [] and "value-not-writable" in report.kinds("information")


def test_only_the_hosts_ack_acknowledges_a_row(env):
    """An ack seal naming a row acknowledges it only when the host wrote it: one by an administrator leaves the
    value no release writes a failure."""
    odd = _unwritable_row(env, T0 - timedelta(hours=6))
    env.run_until_sealed()
    with ai.ChainWriter(env.engine, env.st) as w:
        w.append("ack", detail={"acknowledges": [], "failures": [], "rows": [str(odd)], "discarded": [],
                                "by": "admin", "user_id": None, "request": None})
    assert str(odd) not in env.st.view.acked_rows
    assert any("value-not-writable" in f.message for f in env.verify().findings if f.kind == "rows-altered")


def test_a_row_changed_between_the_phases_makes_the_rows_acknowledgment_refuse(env):
    odd = _unwritable_row(env, T0 - timedelta(hours=6))
    env.run_until_sealed()
    seen = host.acknowledge(env.engine, env.st, seqs=[], failures=False, rows=[str(odd)], read=True)
    with env.engine.begin() as conn:
        conn.exec_driver_sql("UPDATE audit_logs SET username = ? WHERE id = ?", ("mallory", odd.hex))
    with pytest.raises(host.Refused, match="changed since you looked"):
        host.acknowledge(env.engine, env.st, seqs=[], failures=False, rows=[str(odd)], expect=seen["state"])
    assert env.seals()[-1].kind != "ack"


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
    assert host_rows(env, host.ACKNOWLEDGED_ACTION) == [{"late_rows": fmt.hour_text(hour), "added": 1}]
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


# --------------------------------------------------------------------------- one snapshot

class _Recorder:
    def __init__(self):
        self.executed = []

    def execute(self, statement, *args, **kw):
        self.executed.append(str(statement))


def test_a_host_writer_takes_its_snapshot_before_it_reads_anything(env, monkeypatch):
    """Postgres takes REPEATABLE READ only as a transaction's first statement: the host's writer sets it right
    after the statement timeout, before the head record check reads the chain; the server's writers do not."""
    with monkeypatch.context() as m:
        m.setattr(ai, "_is_pg", lambda bind: True)
        db = _Recorder()
        ai.ChainWriter(env.engine, env.st, snapshot=True)._begin(db)
        assert db.executed == [f"SET LOCAL statement_timeout = {ai.SEAL_STATEMENT_TIMEOUT_MS}",
                               "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"]
        db = _Recorder()
        ai.ChainWriter(env.engine, env.st)._begin(db)
        assert db.executed == [f"SET LOCAL statement_timeout = {ai.SEAL_STATEMENT_TIMEOUT_MS}"]
    order = []
    real_check = ai.ChainWriter.check
    with monkeypatch.context() as m:
        m.setattr(ai.ChainWriter, "_begin", lambda self, db: order.append("begin"))
        m.setattr(ai.ChainWriter, "check", lambda self: (order.append("check"), real_check(self))[1])
        with ai.ChainWriter(env.engine, env.st, snapshot=True):
            pass
    assert order == ["begin", "check"]


def test_every_host_command_reads_its_write_phase_in_one_snapshot(env, monkeypatch):
    from app.core import audit_chain_external as external
    from app.core import audit_chain_recovery as recovery
    from app.core import audit_chain_restore as restore
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    opened = []
    real = ai.ChainWriter.__init__

    def init(self, *args, **kw):
        opened.append(kw.get("snapshot", False))
        real(self, *args, **kw)
    monkeypatch.setattr(ai.ChainWriter, "__init__", init)
    commands = [
        lambda: host.acknowledge(env.engine, env.st, seqs=[], failures=False, read=True),
        lambda: host.seal_late_rows(env.engine, env.st, T0 + timedelta(days=1), read=True),
        lambda: external.acknowledge_removed_before(env.engine, env.st, T0, retention_days=7, read=True),
        lambda: recovery.rekey(env.engine, env.st, read=True),
        lambda: recovery.after_record(env.engine, env.st, read=True),
        lambda: restore.accept_database_head(env.engine, env.st, read=True),
        lambda: restore.accept_restore(env.engine, env.st, read=True),
    ]
    for command in commands:
        opened.clear()
        with pytest.raises(host.Refused):
            command()
        assert opened == [True], opened
    opened.clear()
    env.clock.advance(hours=1)
    env.seal()
    assert opened and not any(opened)
