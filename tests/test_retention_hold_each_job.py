"""The hold switch, decided again during a pass of the pruner (app/core/retention.py), offline: the stored settings
are read again before each job over logs and before each batch of one, so a hold turned on during a pass stops
what comes after it; the audit chain's honoured hold stops every job over logs in the pass.
"""
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import T0
from _erase_env import EraseEnv
from app.core import retention
from app.core.models import SecurityRecord

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = EraseEnv(monkeypatch, tmp_path)
    yield e
    e.close()


def test_a_hold_switched_on_during_a_pass_stops_the_jobs_over_logs_after_it(env, monkeypatch):
    held = {"on": False}
    ran = []
    monkeypatch.setattr(retention, "hold_in_force", lambda: held["on"])
    monkeypatch.setattr(retention, "chain_holds", lambda sf=None: False)

    def first(p):
        ran.append("first")
        held["on"] = True
        return retention.JobResult()

    def second(p):
        ran.append("second")
        return retention.JobResult()
    monkeypatch.setattr(retention, "JOBS", [retention.Job("first", "first", first, held=True),
                                            retention.Job("second", "second", second, held=True)])
    done = retention.run_pass(env.session, now=env.clock())
    assert ran == ["first"] and done[-1] == ("second", None)


def test_the_chains_hold_stops_every_job_over_logs_in_the_pass(env, monkeypatch):
    ran = []
    monkeypatch.setattr(retention, "hold_in_force", lambda: False)
    monkeypatch.setattr(retention, "chain_holds", lambda sf=None: True)
    monkeypatch.setattr(retention, "JOBS", [retention.Job("free", "free", lambda p: ran.append("free"), held=False),
                                            retention.Job("held", "held", lambda p: ran.append("held"), held=True)])
    done = retention.run_pass(env.session, now=env.clock())
    assert ran == ["free"] and done[-1] == ("held", None)


def test_a_hold_switched_on_between_two_batches_stops_the_next_batch(env, monkeypatch):
    with env.session() as db:
        for i in range(4):
            db.add(SecurityRecord(id=uuid.uuid4(), at=T0 - timedelta(days=100 + i), kind="login_failure",
                                  name="x", address="198.51.100.4"))
        db.commit()
    held = {"on": False}
    monkeypatch.setattr(retention, "hold_in_force", lambda: held["on"])
    monkeypatch.setattr(retention, "chain_holds", lambda sf=None: False)
    p = retention.Pass(env.session, now=env.clock(), batch_rows=2)
    p.job_name, p.job_held = "security_records", True
    real = p.record

    def record(db, batch, table):
        real(db, batch, table)
        held["on"] = True                                     # turned on once the first batch is in
    p.record = record
    p.delete_in_batches(SecurityRecord, [SecurityRecord.at < T0 - timedelta(days=50)], SecurityRecord.at)
    with env.session() as db:
        assert db.query(SecurityRecord).count() == 2
