"""The audit log's integrity chain, offline: what the server takes from where.

- an administrator's change is judged against the chain (the honoured entry and the chain's), never against
  the value the database stores, and the panel shows what the pruner acts on;
- seals another writer appends after the head record: a request waits for the host's acknowledgment and a
  delay from when the server first accepted it; an acknowledgment in that writer's own ``ack`` seal counts for
  nothing; a writer whose own work fails still lists the seals it accepted;
- a lost head record stays a lost head record, and the status shows its failures and that sealing stopped;
- warnings are acknowledged: the seals written from the database's values by seal, the rest by kind;
- the pruner's passes are never further apart than the chain's gap allows;
- the size cap counts no bytes the chain did not seal.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import os
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_policy as pol
from app.core import audit_chain_policy_seals as ps
from app.core import audit_integrity as ai
from app.core import audit_retention as ar
from app.core import retention
from app.core import setting_changes as sc
from app.core import settings_registry as reg
from app.core.models import AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange, RoleEnum, User

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _admin(env, name="ada"):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username=name, email=f"{name}@example.com", password_hash="x", role=RoleEnum.ADMIN,
                    is_active=True))
        db.commit()
    return env.session().get(User, uid)


def _change(env, actor, key, value):
    with ps.change_transaction(env.engine) as w:
        return ps.change(w, key, value, actor, now=env.clock())


def _forge(env, kind, detail):
    """A seal appended by someone who holds the key in force but not the host (no head record write)."""
    with env.session() as db:
        seals = list(ai.read_seals(db, 0))
    prev = fmt.LINK_0
    for s in seals:
        prev = fmt.link(prev, s.body())
    key = env.st.current_key()
    seq = seals[-1].seq + 1
    if callable(detail):
        detail = detail(seq, env.clock())
    seal = ai.Seal(seq, kind, None, None, fmt.FORMAT, 0, 0, None, None, None, detail, key.key_id, env.clock())
    link = fmt.link(prev, seal.body())
    with env.session() as db:
        db.add(AuditSeal(seq=seq, kind=kind, format=1, row_count=0, row_bytes=0, detail=detail, key_id=key.key_id,
                         sealed_at=seal.sealed_at, mac=fmt.mac(key.key, link), link=link))
        db.commit()
    return seq


def _passes(env, hours, step=6):
    end = env.clock() + timedelta(hours=hours)
    while env.clock() < end:
        env.clock.advance(hours=step)
        retention.run_pass(env.session, now=env.clock())


def _newest_policy(env):
    return env.st.view.newest_policy()


def _ack_by_host(env, seqs=(), failures_too=False):
    head = env.verify(check_rows=False).head
    return host.acknowledge(env.engine, env.st, seqs=list(seqs), failures=failures_too, expect=head)


def _lower_max_days_elsewhere(env, days=100):
    """Another writer's env seal that lowers the chain's maximum to ``days``: accepted as a warning and set
    aside, so the pruner still keeps the log for ever."""
    seq_prev, d = _newest_policy(env)
    inputs = dict(d["inputs"], AUDIT_LOG_RETENTION_DAYS=str(days))

    def make(seq, _at):
        return ps._policy_detail(pol.env_state(d["state"], inputs, seq), inputs, "env", by="server")
    return _forge(env, "policy", make)


def _foreign_applies(env, new=400):
    """An administrator's reduction of the maximum from "for ever" to ``new`` days, due, then applied by
    another writer's seal the host has not seen: the chain says ``new``, the pruner keeps the log for ever."""
    outcome = _change(env, _admin(env, "bea"), "audit_max_days", new)
    assert outcome.status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    for _ in range(32):
        env.clock.advance(hours=6)
        env.seal()
    seq_prev, d = _newest_policy(env)
    asked = env.st.view.requests[req]
    spec = {s.key: s for s in pol.chain_specs()}["audit_max_days"]
    ns = pol.settings_from_inputs(d["inputs"])

    def make(seq, _at):
        state = {k: dict(e) for k, e in d["state"].items()}
        state["audit_max_days"] = {**ps.setting_fields(spec, new, ns, d["inputs"], req), "set_by": seq}
        return ps._policy_detail(state, d["inputs"], "applies", request_seq=req, request=asked["request"],
                                 by="server")
    return _forge(env, "policy", make)


# --------------------------------------------------------------------------- the administrator's change

def test_a_value_written_into_the_database_never_turns_an_admins_raise_into_a_reduction(env):
    """From "for ever" in the chain, 400 days is a reduction that waits, whatever the database stores."""
    from app.api import managed_settings_router as routes
    old = env.row(T0 - timedelta(days=500))
    env.run_until_sealed()
    assert env.st.view.newest_state()["audit_max_days"]["value"] == 0
    with env.session() as db:
        db.add(ManagedSetting(key="audit_max_days", value=10, version=1))
        db.commit()
    reg.refresh(env.session)
    (row,) = routes.with_chain(reg.describe(["audit_max_days"]))
    assert (row["value"], row["chain"]["value"], row["stored"], row["database_stored"]) == (0, 0, None, 10)
    assert (row["source"], row["clamped"]) == (row["chain"]["source"], False)
    outcome = _change(env, _admin(env), "audit_max_days", 400)
    assert outcome.status == "pending" and outcome.old == 0
    assert env.seals()[-1].kind == "request"
    _passes(env, 6)
    with env.session() as db:
        assert db.get(AuditLog, old) is not None
    assert "unjustified" not in failures(env.verify())


def test_the_panel_row_shows_the_chains_source_and_setting_and_the_databases_value_apart(env, monkeypatch):
    """An administrator's 400 days, clamped to 365 by a ceiling .env sets later; then 300 written into the
    database without the key. The row shows the chain's: 365, set by an administrator as 400, clamped."""
    from app.api import managed_settings_router as routes
    env.run_until_sealed()
    assert _change(env, _admin(env), "audit_max_days", 400).status == "pending"
    _passes(env, 7 * 24 + 6)
    monkeypatch.setenv("PLAN_LOG_MAX_DAYS", "365")
    env.settings.plan_log_max_days = 365
    env.clock.advance(minutes=5)
    env.seal()
    entry = env.st.view.newest_state()["audit_max_days"]
    assert (entry["value"], entry["source"], entry["setting"]) == (365, "clamped", 400)
    with env.session() as db:
        reg.store(db, "audit_max_days", 300)
        db.commit()
    reg.refresh(env.session)
    (row,) = routes.with_chain(reg.describe(["audit_max_days"]))
    assert (row["value"], row["source"], row["stored"], row["clamped"]) == (365, "admin", 400, True)
    assert row["database_stored"] == 300


def test_a_change_between_the_honoured_and_the_chains_value_is_a_reduction(env):
    """The chain says 100 days (another writer's seal, set aside); the pruner keeps the log for ever. 200 keeps
    more than the chain's value and deletes sooner than the honoured one: it waits."""
    env.run_until_sealed()
    _lower_max_days_elsewhere(env)
    outcome = _change(env, _admin(env), "audit_max_days", 200)
    assert env.st.view.newest_state()["audit_max_days"]["value"] == 100
    assert ar.chain_numbers()[0].max_days == 0
    assert outcome.status == "pending" and env.seals()[-1].kind == "request"


def test_asking_for_the_value_another_writers_set_aside_seal_put_in_the_chain_is_a_request(env):
    """Another writer applied a reduction from "for ever" to 400 days, in the chain and in the database, and the
    host has not seen its seal: the pruner keeps the log for ever. 400 asked for again changes what is in force:
    a request from "for ever" that waits, not "unchanged"."""
    env.run_until_sealed()
    _foreign_applies(env, 400)
    with env.session() as db:
        reg.store(db, "audit_max_days", 400)
        db.query(ManagedSettingChange).filter(ManagedSettingChange.status == sc.PENDING).update(
            {ManagedSettingChange.status: sc.APPLIED})
        db.commit()
    reg.refresh(env.session)
    env.clock.advance(minutes=30)
    env.seal()
    assert env.st.view.newest_state()["audit_max_days"]["setting"] == 400
    assert ar.chain_numbers()[0].max_days == 0
    outcome = _change(env, _admin(env), "audit_max_days", 400)
    assert (outcome.status, outcome.old) == ("pending", 0)
    assert env.seals()[-1].kind == "request" and env.seals()[-1].detail["old"] == 0


def test_the_honoured_setting_given_again_after_another_writers_seal_is_sealed_at_once(env):
    """Another writer applied a due reduction (30 to 10 days) the host has not seen: the pruner keeps 30. The
    administrator's 30 given again deletes sooner than neither, and the server's seal puts it back."""
    env.run_until_sealed()
    ada = _admin(env)
    assert _change(env, ada, "security_record_days", 40).status == "applied"
    assert _change(env, ada, "security_record_days", 10).status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    for _ in range(32):
        env.clock.advance(hours=6)
        env.seal()
    seq_prev, d = _newest_policy(env)
    asked = env.st.view.requests[req]
    spec = {s.key: s for s in pol.chain_specs()}["security_record_days"]

    def make(seq, _at):
        state = {k: dict(e) for k, e in d["state"].items()}
        state["security_record_days"] = {**ps.setting_fields(spec, 10, pol.settings_from_inputs(d["inputs"]),
                                                              d["inputs"], req), "set_by": seq}
        return ps._policy_detail(state, d["inputs"], "applies", request_seq=req, request=asked["request"],
                                 by="server")
    _forge(env, "policy", make)
    outcome = _change(env, ada, "security_record_days", 40)
    assert outcome.status == "applied"
    seal = env.seals()[-1]
    assert seal.kind == "policy" and seal.detail["cause"] == "request"
    assert seal.detail["state"]["security_record_days"]["setting"] == 40
    assert ar.chain_numbers() is not None
    assert ps.numbers()["security_record_days"] == 40


def test_a_value_the_database_lost_is_put_right_by_asking_for_it_again(env):
    """The chain holds the hold switch on; the database's value was cleared without the key. Asking for it
    again stores it (other jobs read the database), and its policy seal supersedes the request waiting to turn
    it off."""
    env.run_until_sealed()
    ada = _admin(env)
    assert _change(env, ada, "logs_hold", True).status == "applied"
    waiting = _change(env, ada, "logs_hold", False)
    assert waiting.status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    with env.session() as db:
        db.query(ManagedSetting).filter(ManagedSetting.key == "logs_hold").update({ManagedSetting.value: None})
        db.commit()
    before = len(env.seals())
    again = _change(env, ada, "logs_hold", True)
    assert again.status == "applied"
    with env.session() as db:
        assert db.get(ManagedSetting, "logs_hold").value is True
        assert db.get(ManagedSettingChange, waiting.change.id).status == sc.SUPERSEDED
    added = env.seals()[before:]
    assert [s.kind for s in added] == ["policy"] and added[0].detail["cause"] == "request"
    assert added[0].detail["state"]["logs_hold"]["value"] is True
    assert req not in env.st.view.pending_requests()
    assert failures(env.verify()) == []


def test_a_setting_the_chain_does_not_record_writes_no_seal(env):
    env.run_until_sealed()
    before = len(env.seals())
    with ps.change_transaction(env.engine) as w:
        outcome = sc.Outcome("applied", key="greeting_days", setting=5)
        ps.seal_request_outcome(w, outcome, _admin(env))
    assert len(env.seals()) == before


def test_a_reduction_is_refused_while_sealing_is_stopped_judged_by_the_chain(env):
    """While sealing is stopped, the database's value does not decide either: a raise from a value written
    into it is still a reduction against what the chain gave, and is refused."""
    env.run_until_sealed()
    with env.session() as db:
        db.add(ManagedSetting(key="audit_max_days", value=10, version=1))
        db.commit()
    assert ps.refuses_while_stopped(env.session(), "audit_max_days", 400, st=env.st)
    assert not ps.refuses_while_stopped(env.session(), "logs_hold", True, st=env.st)


# --------------------------------------------------------------------------- another writer's seals

def _foreign_request(env, new=30, days=60):
    """A request appended by another writer with a change row written into the database."""
    change_id = uuid.uuid4()
    with env.session() as db:
        db.add(ManagedSettingChange(id=change_id, key="audit_max_days", setting=new, old_value=0, new_value=new,
                                    status=sc.PENDING, requested_by=None, requested_by_name="x",
                                    requested_at=env.clock(), effective_at=env.clock() + timedelta(days=7)))
        db.commit()
    return _forge(env, "request", lambda seq, at: {
        "what": "setting", "request": str(change_id), "setting": "audit_max_days", "old": 0, "new": new,
        "subject": None, "placeholder": None, "not_before": fmt.time_text(at + timedelta(days=7)),
        "audit_row": None, "by": "admin", "user_id": None})


def test_another_writers_request_waits_for_the_host(env):
    old = env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    req = _foreign_request(env)
    _passes(env, 9 * 24)
    with env.session() as db:
        assert db.get(AuditLog, old) is not None
    assert req not in env.st.view.applied
    assert req in host.warning_seqs(env.st.view, env.st.head_store().load())


def test_another_writers_request_counts_a_delay_from_the_servers_acceptance_once_acknowledged(env):
    """Appended an hour before the server first reads it: its own not_before comes an hour before a delay has
    run since the server accepted it, and only the later counts."""
    env.run_until_sealed()
    req = _foreign_request(env)
    _passes(env, 1, step=1)          # the server accepts it here
    _ack_by_host(env, [req])
    accepted = fmt.parse_time_text([e for e in env.st.head_store().load()["after_record"]
                                    if e["seq"] == req][0]["accepted_at"])
    _passes(env, 7 * 24 - 1, step=1)
    not_before = fmt.parse_time_text(env.st.view.requests[req]["not_before"])
    assert not_before <= env.clock() < accepted + timedelta(days=7)
    assert req not in env.st.view.applied
    _passes(env, 1, step=1)
    assert req in env.st.view.applied
    assert ar.chain_numbers()[0].max_days == 30


def _accepted_at(env, seq):
    return fmt.parse_time_text([e for e in env.st.head_store().load()["after_record"]
                                if e["seq"] == seq][0]["accepted_at"])


def _run_to(env, when):
    """The pruner every 6 hours, then every hour, until the clock reaches ``when``."""
    while env.clock() + timedelta(hours=6) <= when:
        env.clock.advance(hours=6)
        retention.run_pass(env.session, now=env.clock())
    while env.clock() < when:
        env.clock.advance(hours=1)
        retention.run_pass(env.session, now=env.clock())


def test_another_writers_request_adds_a_stop_after_the_servers_acceptance(env):
    """Appended 11 hours before the server first reads it (sealing ran: no gap), then a stop of two days: due
    once seven days of sealing have run since the acceptance, so at the acceptance + 9 days, not 11 hours sooner
    as it would be from its own sealed_at."""
    env.run_until_sealed()
    forged_at = env.clock()
    req = _foreign_request(env)
    env.clock.advance(hours=11)
    retention.run_pass(env.session, now=env.clock())      # the server accepts it here
    accepted = _accepted_at(env, req)
    assert accepted - forged_at == timedelta(hours=11)
    _ack_by_host(env, [req])
    _run_to(env, forged_at + timedelta(days=3))
    env.clock.advance(days=2)                               # the server was stopped
    retention.run_pass(env.session, now=env.clock())
    _run_to(env, accepted + timedelta(days=9, hours=-1))
    assert req in env.st.view.pending_requests() and req not in env.st.view.applied
    assert ar.chain_numbers()[0].max_days == 0
    _run_to(env, accepted + timedelta(days=9, hours=1))
    assert req in env.st.view.applied
    assert ar.chain_numbers()[0].max_days == 30


def test_another_writers_request_counts_no_stop_from_before_the_servers_acceptance(env):
    """A stop of two days long before another writer's request: due seven days after the server accepted the
    request; a stop that ended before the acceptance moves nothing."""
    env.run_until_sealed()
    env.clock.advance(days=2)                               # the server was stopped
    _run_to(env, env.clock() + timedelta(days=1))
    req = _foreign_request(env)
    _passes(env, 1, step=1)                                 # the server accepts it here
    accepted = _accepted_at(env, req)
    _ack_by_host(env, [req])
    _run_to(env, accepted + timedelta(days=7, hours=-1))
    assert req not in env.st.view.applied
    _run_to(env, accepted + timedelta(days=7, hours=1))
    assert req in env.st.view.applied
    assert ar.chain_numbers()[0].max_days == 30


def test_an_acknowledgment_in_another_writers_own_ack_seal_counts_for_nothing(env):
    old = env.row(T0 - timedelta(days=450))
    env.run_until_sealed()
    lowered = _foreign_applies(env)
    env.clock.advance(minutes=30)
    env.seal()
    _forge(env, "ack", {"acknowledges": [lowered], "failures": [], "rows": [], "discarded": [], "by": "admin",
                        "user_id": None, "request": None})
    _passes(env, 12)
    with env.session() as db:
        assert db.get(AuditLog, old) is not None
    assert ar.chain_numbers()[0].max_days == 0
    assert lowered in host.warning_seqs(env.st.view, env.st.head_store().load())


def test_the_hosts_acknowledgment_lets_another_writers_seal_count(env):
    env.run_until_sealed()
    lowered = _foreign_applies(env)
    env.clock.advance(minutes=30)
    env.seal()
    assert ar.chain_numbers()[0].max_days == 0
    _ack_by_host(env, [lowered])
    assert ar.chain_numbers()[0].max_days == 400


def _hold_on_elsewhere(env):
    seq_prev, d = _newest_policy(env)

    def make(seq, _at):
        state = {k: dict(e) for k, e in d["state"].items()}
        state["logs_hold"] = {**state["logs_hold"], "value": True, "source": "setting", "setting": True,
                              "request_seq": seq, "set_by": seq}
        return ps._policy_detail(state, d["inputs"], "request", by="admin")
    return _forge(env, "policy", make)


def _listed(env):
    return [e["seq"] for e in env.st.head_store().load().get("after_record") or []]


def test_a_writer_whose_own_work_fails_still_lists_the_seals_it_accepted(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    foreign = _hold_on_elsewhere(env)
    with pytest.raises(RuntimeError):
        with ai.ChainWriter(env.engine, env.st) as w:
            assert w.st.view.position == foreign
            raise RuntimeError("its own work failed")
    assert foreign in _listed(env)
    env.clock.advance(hours=1)
    env.seal()
    assert foreign in _listed(env)
    assert "after-record" in ai.status(env.st)["warnings"]


@pytest.mark.parametrize("fails", ["after its own seal", "at its commit"])
def test_a_writer_whose_own_seal_is_rolled_back_lists_the_seals_it_accepted_and_nothing_of_its_own(env, fails):
    """A writer reads another writer's seal, seals an hour of its own, then its work or its commit fails: on its
    way out the head record lists the accepted seal, and holds no summary or link of the seal rolled back."""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    foreign = _hold_on_elsewhere(env)
    env.clock.advance(hours=2)
    head = env.st.head_store().load()
    own = None
    with pytest.raises(RuntimeError):
        with ai.ChainWriter(env.engine, env.st) as w:
            assert w.st.view.position == foreign
            own = ai.seal_hour(w, w.st.view.newest_hour_end, env.clock(), None)
            if fails == "after its own seal":
                raise RuntimeError("its own work failed")

            def refuse():
                raise RuntimeError("the commit failed")
            w.db.commit = refuse
    assert own is not None and own.seq == foreign + 1
    with env.session() as db:
        assert db.query(AuditSeal).filter(AuditSeal.seq == own.seq).count() == 0
    record = env.st.head_store().load()
    assert foreign in _listed(env) and env.st.pending_after == []
    assert record.get("hours") == head.get("hours") and record.get("links") == head.get("links")
    assert record["seq"] == foreign
    env.clock.advance(minutes=5)
    assert env.seal().stopped is None
    assert failures(env.verify()) == []


def test_a_writer_whose_check_stops_after_accepting_a_seal_still_lists_it(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    foreign = _hold_on_elsewhere(env)
    _forge(env, "bogus", {})
    env.clock.advance(minutes=30)
    assert env.seal().stopped == "after-record-invalid"
    assert foreign in _listed(env)


def test_seals_accepted_while_the_record_could_not_be_written_stay_another_writers(env, monkeypatch):
    """A writer reads another writer's seal and cannot write the head record: the next writer, in this process,
    still sets the seal aside, and lists it."""
    env.run_until_sealed()
    lowered = _foreign_applies(env)

    def refuse(self):
        raise RuntimeError("the head record could not be written")
    with monkeypatch.context() as m:
        m.setattr(ai.ChainWriter, "_write_record", refuse)
        env.clock.advance(minutes=30)
        env.seal()
    assert [e["seq"] for e in env.st.pending_after] == [lowered]
    assert ar.chain_numbers()[0].max_days == 0
    assert lowered not in _listed(env)
    assert "after-record" in ai.status(env.st)["warnings"]      # from the seals the record does not list yet
    outcome = _change(env, _admin(env), "audit_max_days", 500)     # more than the chain's 400, less than for ever
    assert outcome.status == "pending"
    assert lowered in _listed(env) and env.st.pending_after == []


def test_a_late_seal_stays_a_warning_when_another_writer_acknowledges_it(env):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3, minutes=10))
    env.row(hour + timedelta(minutes=40))
    env.clock.advance(minutes=20)
    assert env.seal().late == 1
    late = env.st.view.late_seqs[-1]
    _forge(env, "ack", {"acknowledges": [late], "failures": [], "rows": [], "discarded": [], "by": "admin",
                        "user_id": None, "request": None})
    env.clock.advance(minutes=20)
    env.seal()
    assert ai.status(env.st)["warnings"]["late"]["seqs"] == [late]
    assert late in host.warning_seqs(env.st.view, env.st.head_store().load())
    _ack_by_host(env, [late])
    assert "late" not in ai.status(env.st)["warnings"]


# --------------------------------------------------------------------------- a lost head record

def test_a_lost_head_record_stays_lost_and_the_status_says_sealing_stopped(env):
    env.run_until_sealed()
    os.remove(env.settings.audit_chain_head_file)
    env.fresh_process()
    for _ in range(3):
        env.clock.advance(hours=1)
        assert env.seal().stopped == "head-record-missing"
    status = ai.status(env.st)
    assert status["stopped"]["kind"] == "head-record-missing"
    assert "head-record-missing" in status["failures"] and status["outcome"] == "failed"
    assert status["head"] is None


def test_a_record_with_findings_only_lets_genesis_run(env):
    ai.report_failures(env.st, None, {"db-hooks": "a trigger on audit_logs"})
    assert env.seal().stopped is None
    assert env.seals()[0].kind == "genesis"


def test_the_status_shows_sealing_stopped_with_no_failure_kept(env):
    env.run_until_sealed()
    env.st.stopped = ai.ChainStopped("busy-elsewhere", "another process holds the lock")
    status = ai.status(env.st)
    assert status["outcome"] == "stopped" and status["stopped"]["kind"] == "busy-elsewhere"


# --------------------------------------------------------------------------- warnings acknowledged

def test_a_cancel_the_database_made_is_a_warning_the_host_acknowledges_by_its_seal(env):
    env.run_until_sealed()
    outcome = _change(env, _admin(env), "audit_max_days", 400)
    with env.session() as db:
        db.query(ManagedSettingChange).filter(ManagedSettingChange.id == outcome.change.id).update(
            {ManagedSettingChange.status: sc.CANCELLED})
        db.commit()
    _passes(env, 6)
    cancel = env.seals()[-1]
    assert cancel.kind == "cancel" and cancel.detail["by"] == "database"
    status = ai.status(env.st)
    assert status["warnings"]["veto-from-database"]["seqs"] == [cancel.seq]
    assert "keeps more, or a waiting change it no longer shows" in status["warnings"]["veto-from-database"]["message"]
    assert "veto-from-database" not in (env.st.head_store().load().get("warnings") or {})
    assert "veto-from-database" in env.verify(check_rows=False).kinds("warning")
    _ack_by_host(env, [cancel.seq])
    assert "veto-from-database" not in ai.status(env.st)["warnings"]
    assert "veto-from-database" not in env.verify(check_rows=False).kinds("warning")


def test_warnings_kept_by_kind_are_acknowledged_with_the_failures(env):
    env.run_until_sealed()
    ai.report_failures(env.st, None, {}, {"sealed-at-backwards": "seal 9 steps back",
                                          "key-change-waiting": "a key waits"})
    with pytest.raises(host.Refused):
        _ack_by_host(env)
    done = _ack_by_host(env, failures_too=True)
    assert done["failures"] == ["sealed-at-backwards"]
    warnings = ai.status(env.st)["warnings"]
    assert "sealed-at-backwards" not in warnings and "key-change-waiting" in warnings


# --------------------------------------------------------------------------- the pruner's interval

def test_passes_are_never_further_apart_than_the_chains_gap_allows(env, monkeypatch):
    for minutes, seconds in ((15, 900), (360, 21600), (1440, 21600)):
        monkeypatch.setattr(reg, "resolve", lambda key, _m=minutes: _m)
        assert retention.interval_seconds() == seconds
    assert retention.MAX_INTERVAL_MINUTES * 60 < pol.GAP.total_seconds()


# --------------------------------------------------------------------------- the size cap

def test_a_bulky_row_written_into_a_sealed_hour_counts_nothing_toward_the_size_cap(env, monkeypatch):
    """Written straight into the table (no key) into an hour sealed long ago, past the 6 hours in which a row
    arriving there is sealed late: the hour counts what the chain sealed for it."""
    monkeypatch.setenv("AUDIT_LOG_MAX_MB", "1")
    env.settings.audit_log_max_mb = 1
    genuine = [env.row(T0 - timedelta(days=30, hours=h)) for h in range(5)]
    env.run_until_sealed()
    assert env.st.view.newest_state()["audit_max_mb"]["value"] == 1
    _passes(env, 8, step=1)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(genuine)).count() == 5
    env.row(T0 - timedelta(days=10), details={"blob": "x" * 2_000_000})
    _passes(env, 1, step=1)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(genuine)).count() == 5
    assert "rows-added" in failures(env.verify())


def test_the_size_cap_still_deletes_by_the_bytes_the_chain_sealed(env, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_MAX_MB", "1")
    env.settings.audit_log_max_mb = 1
    old = [env.row(T0 - timedelta(days=30, hours=h), details={"blob": "y" * 400_000}) for h in range(4)]
    env.run_until_sealed()
    env.clock.advance(minutes=30)
    retention.run_pass(env.session, now=env.clock())
    with env.session() as db:
        left = db.query(AuditLog).filter(AuditLog.id.in_(old)).count()
    assert 0 < left < 4
    assert failures(env.verify()) == []
