"""The retention state in the audit chain (app/core/audit_chain_policy_seals.py), offline: every input to the
audit pruner is a seal written when it is made, the pruner acts on the chain and never on the database's
values alone, the database can only hold a deletion back, and only .env sets the delay.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_policy as pol
from app.core import audit_chain_policy_seals as ps
from app.core import audit_chain_verify as verify_mod
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
    db = env.session()
    return db.get(User, uid)


def _change(env, actor, key, value):
    with ps.change_transaction(env.engine) as w:
        outcome = sc.request(w.db, key, value, actor=actor, now=env.clock())
        ps.seal_request_outcome(w, outcome, actor)
    return outcome


def _cancel(env, actor, change_id):
    with ps.change_transaction(env.engine) as w:
        change = sc.cancel(w.db, change_id, actor=actor, now=env.clock())
        ps.seal_cancel(w, change, actor)


def _passes(env, hours, step=6):
    """The pruner every ``step`` hours for ``hours`` hours: sealing, the due changes, the audit job."""
    end = env.clock() + timedelta(hours=hours)
    while env.clock() < end:
        env.clock.advance(hours=step)
        retention.run_pass(env.session, now=env.clock())


def _kinds(env):
    return [s.kind for s in env.seals()]


def _forge(env, kind, detail, **body):
    """A seal appended by someone who holds the key in force but not the host (no head record write)."""
    with env.session() as db:
        seals = list(ai.read_seals(db, 0))
    prev = fmt.LINK_0
    for s in seals:
        prev = fmt.link(prev, s.body())
    key = env.st.current_key()
    seal = ai.Seal(seals[-1].seq + 1, kind, body.get("period_start"), body.get("period_end"), fmt.FORMAT,
                   body.get("row_count", 0), body.get("row_bytes", 0), body.get("root_s"), body.get("root_c"),
                   body.get("ids_digest"), detail, key.key_id, body.get("sealed_at") or env.clock())
    link = fmt.link(prev, seal.body())
    with env.session() as db:
        db.add(AuditSeal(seq=seal.seq, kind=kind, period_start=seal.period_start, period_end=seal.period_end,
                         format=1, row_count=seal.row_count, row_bytes=seal.row_bytes, root_s=seal.root_s,
                         root_c=seal.root_c, ids_digest=seal.ids_digest, detail=detail, key_id=key.key_id,
                         sealed_at=seal.sealed_at, mac=fmt.mac(key.key, link), link=link))
        db.commit()
    return seal.seq


def _newest_policy(env):
    return [s for s in env.seals() if s.kind == "policy"][-1]


# --------------------------------------------------------------------------- genesis and .env

def test_the_first_policy_seal_holds_dotenv_and_the_defaults(env):
    env.seal()
    seal = env.seals()[1]
    assert seal.kind == "policy" and seal.detail["cause"] == "genesis"
    state = seal.detail["state"]
    assert set(state) == set(pol.chain_setting_keys()) | {pol.DELAY_ENTRY}
    assert state[pol.DELAY_ENTRY] == {"value": 7, "source": "default", "setting": None, "request_seq": None,
                                      "set_by": 2}
    assert state["audit_max_days"]["value"] == 0 and state["audit_admin_min_days"]["value"] == 365
    assert set(seal.detail["inputs"]) == set(pol.input_names()) and not any(seal.detail["inputs"].values())
    assert failures(env.verify()) == []


def test_an_env_change_is_sealed_before_anything_acts_on_it(env, monkeypatch):
    env.seal()
    monkeypatch.setenv("RETENTION_REDUCTION_DELAY_DAYS", "10")
    env.settings.retention_reduction_delay_days = 10
    env.clock.advance(minutes=10)
    env.seal()
    seal = _newest_policy(env)
    assert seal.detail["cause"] == "env" and seal.detail["inputs"]["RETENTION_REDUCTION_DELAY_DAYS"] == "10"
    assert seal.detail["state"][pol.DELAY_ENTRY] == {"value": 10, "source": "env", "setting": None,
                                                     "request_seq": None, "set_by": seal.seq}
    env.clock.advance(minutes=10)
    env.seal()
    assert _newest_policy(env).seq == seal.seq          # the same inputs again: no seal
    assert failures(env.verify()) == []


def test_a_first_start_with_a_positive_retention_waits_like_a_request(env, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "90")
    env.settings.audit_log_retention_days = 90
    old = [env.row(T0 - timedelta(days=200, hours=h)) for h in range(3)]
    env.run_until_sealed()
    seals = env.seals()
    assert [s.kind for s in seals[:3]] == ["genesis", "policy", "request"]
    assert seals[1].detail["state"]["audit_max_days"]["source"] == "held"
    request = seals[2].detail
    assert (request["by"], request["setting"], request["new"], request["old"]) == ("server", "audit_max_days", 90, 0)
    with env.session() as db:
        change = db.query(ManagedSettingChange).one()
        assert change.effective_at == fmt.parse_time_text(request["not_before"])
    _passes(env, 6 * 24 + 18)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(old)).count() == 3
    _passes(env, 12)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(old)).count() == 0
        assert db.query(ManagedSettingChange).one().status == sc.APPLIED
    applies = [s for s in env.seals() if s.kind == "policy" and s.detail["cause"] == "applies"]
    assert applies and applies[0].detail["request_seq"] == 3
    assert "prune" in _kinds(env)
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- an administrator's changes

def test_a_change_that_deletes_later_is_a_policy_seal_applied_at_once(env):
    env.seal()
    ada = _admin(env)
    outcome = _change(env, ada, "audit_max_days", 400)
    assert outcome.status == "pending"                 # 0 (for ever) to 400 deletes sooner
    env.clock.advance(minutes=5)
    outcome = _change(env, ada, "logs_hold", True)
    assert outcome.status == "applied"
    seal = _newest_policy(env)
    assert seal.detail["cause"] == "request" and seal.detail["by"] == "admin"
    entry = seal.detail["state"]["logs_hold"]
    assert (entry["value"], entry["source"], entry["setting"], entry["request_seq"]) == (True, "setting", True, seal.seq)
    assert ar.chain_numbers()[2] is True
    assert failures(env.verify()) == []


def test_a_reduction_waits_its_delay_and_a_cancel_by_another_admin_stops_it(env):
    env.seal()
    ada, bob = _admin(env), _admin(env, "bob")
    _change(env, ada, "logs_hold", True)
    env.clock.advance(minutes=5)
    outcome = _change(env, ada, "logs_hold", False)
    assert outcome.status == "pending"
    request = [s for s in env.seals() if s.kind == "request"][-1]
    assert request.detail["old"] is True and request.detail["new"] is False
    _passes(env, 24)
    _cancel(env, bob, outcome.change.id)
    cancel = env.seals()[-1]
    assert cancel.kind == "cancel" and cancel.detail["cancels"] == request.seq
    _passes(env, 7 * 24)
    assert ar.chain_numbers()[2] is True
    assert failures(env.verify()) == []


def test_a_newer_change_supersedes_and_the_old_request_never_applies(env):
    env.seal()
    ada = _admin(env)
    _change(env, ada, "audit_max_days", 400)
    env.clock.advance(minutes=1)
    _change(env, ada, "audit_max_days", 500)
    first, second = [s for s in env.seals() if s.kind == "request"]
    view = env.st.view
    assert first.seq not in view.pending_requests() and second.seq in view.pending_requests()
    _passes(env, 7 * 24 + 6)
    assert ar.chain_numbers()[0].max_days == 500
    applied = [s.detail["request_seq"] for s in env.seals() if s.kind == "policy" and s.detail["cause"] == "applies"]
    assert applied == [second.seq]
    assert failures(env.verify()) == []


def test_a_reduction_is_refused_while_sealing_is_stopped(env):
    env.seal()
    ada = _admin(env)
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == env.seals()[-1].seq).delete()
        db.commit()
    env.fresh_process()
    with pytest.raises(ai.ChainStopped):
        _change(env, ada, "audit_max_days", 400)


# --------------------------------------------------------------------------- the database can only hold back

def test_a_value_written_into_the_database_that_deletes_sooner_is_not_acted_on(env):
    old = env.row(T0 - timedelta(days=200))
    env.run_until_sealed()
    with env.session() as db:
        reg.store(db, "audit_max_days", 30)
        db.commit()
    reg.refresh(env.session)
    env.clock.advance(hours=3)
    retention.run_pass(env.session, now=env.clock())
    with env.session() as db:
        assert db.get(AuditLog, old) is not None
    record = env.st.head_store().load()
    assert "unjustified-input" in record["failures"]


def test_a_value_written_into_the_database_that_keeps_more_is_sealed_as_a_veto(env):
    env.seal()
    ada = _admin(env)
    _change(env, ada, "audit_max_days", 400)
    _passes(env, 7 * 24 + 6)
    assert ar.chain_numbers()[0].max_days == 400
    with env.session() as db:
        reg.store(db, "audit_max_days", 900)
        db.commit()
    _passes(env, 6)
    seal = _newest_policy(env)
    assert seal.detail["cause"] == "database" and seal.detail["state"]["audit_max_days"]["value"] == 900
    assert ar.chain_numbers()[0].max_days == 900
    _passes(env, 12)
    assert len([s for s in env.seals() if s.kind == "policy" and s.detail["cause"] == "database"]) == 1
    assert failures(env.verify()) == []


def test_a_request_row_written_into_the_database_is_ignored(env):
    env.seal()
    with env.session() as db:
        db.add(ManagedSettingChange(key="audit_max_days", setting=1, old_value=0, new_value=1, status=sc.PENDING,
                                    requested_by_name="x", requested_at=env.clock(),
                                    effective_at=env.clock() - timedelta(days=1)))
        db.commit()
    _passes(env, 12)
    assert ar.chain_numbers()[0].max_days == 0
    assert "unjustified-input" in env.st.head_store().load()["failures"]


# --------------------------------------------------------------------------- only .env sets the delay

def test_a_policy_seal_raising_the_delay_is_refused_on_its_face_and_unjustified_off_the_server(env):
    env.seal()
    newest = _newest_policy(env)
    state = {k: dict(v) for k, v in newest.detail["state"].items()}
    seq = env.seals()[-1].seq + 1
    state[pol.DELAY_ENTRY] = {"value": 36500, "source": "setting", "setting": 36500, "request_seq": seq,
                              "set_by": seq}
    _forge(env, "policy", {"state": state, "inputs": newest.detail["inputs"], "cause": "request",
                           "request_seq": None, "request": None, "audit_row": None, "by": "admin",
                           "user_id": None})
    env.clock.advance(hours=2)
    assert env.seal().stopped == "after-record-invalid"
    with env.session() as db:
        off = verify_mod.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    found = [f for f in off.findings if f.kind == "unjustified"]
    assert found and "reduction_delay_days" in found[0].message
    assert pol.delay_days(env.st.view.newest_state()) == 7


@pytest.mark.parametrize("cause", ["database", "request"])
def test_a_policy_seal_setting_a_name_the_registry_does_not_hold_is_unjustified(env, cause):
    env.seal()
    newest = _newest_policy(env)
    state = {k: dict(v) for k, v in newest.detail["state"].items()}
    seq = env.seals()[-1].seq + 1
    state["made_up_days"] = {"value": 1, "source": "setting", "setting": 1, "request_seq": seq, "set_by": seq}
    _forge(env, "policy", {"state": state, "inputs": newest.detail["inputs"], "cause": cause,
                           "request_seq": None, "request": None, "audit_row": None, "by": "admin",
                           "user_id": None})
    with env.session() as db:
        off = verify_mod.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    assert "unjustified" in off.kinds("failure")


def test_a_request_naming_the_delay_is_unjustified_and_never_applies(env):
    env.seal()
    _forge(env, "request", {"what": "setting", "request": str(uuid.uuid4()), "setting": pol.DELAY_ENTRY, "old": 7,
                            "new": 1, "subject": None, "placeholder": None,
                            "not_before": fmt.time_text(env.clock() + timedelta(days=7)), "audit_row": None,
                            "by": "admin", "user_id": None})
    with env.session() as db:
        off = verify_mod.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    found = [f for f in off.findings if f.kind == "unjustified"]
    assert found and "not a setting the panel manages" in found[0].message
    env.clock.advance(hours=2)
    assert env.seal().stopped == "after-record-invalid"


def test_a_genuine_env_change_of_the_delay_still_sets_it(env, monkeypatch):
    env.seal()
    monkeypatch.setenv("RETENTION_REDUCTION_DELAY_DAYS", "3")
    env.clock.advance(minutes=5)
    env.seal()
    assert pol.delay_days(env.st.view.newest_state()) == 3
    assert _newest_policy(env).detail["state"][pol.DELAY_ENTRY]["source"] == "env"
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- applies, from the chain alone

def test_verify_rejects_an_applies_seal_early_after_a_cancel_or_twice(env):
    env.seal()
    ada = _admin(env)
    outcome = _change(env, ada, "audit_max_days", 400)
    request = [s for s in env.seals() if s.kind == "request"][-1]
    newest = _newest_policy(env)

    def applies():
        state = {k: dict(v) for k, v in _newest_policy(env).detail["state"].items()}
        seq = env.seals()[-1].seq + 1
        state["audit_max_days"] = {"value": 400, "source": "setting", "setting": 400, "request_seq": request.seq,
                                   "set_by": seq}
        return _forge(env, "policy", {"state": state, "inputs": newest.detail["inputs"], "cause": "applies",
                                      "request_seq": request.seq, "request": str(outcome.change.id),
                                      "audit_row": None, "by": "server", "user_id": None})

    early = applies()
    with env.session() as db:
        report = verify_mod.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    assert any(f.kind == "unjustified" and f.seq == early and "delay" in f.message for f in report.findings)


def test_the_database_turning_the_hold_off_does_not_release_the_audit_rows(env, monkeypatch):
    old = env.row(T0 - timedelta(days=200))
    env.run_until_sealed()
    ada = _admin(env)
    _change(env, ada, "logs_hold", True)
    monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "30")
    env.settings.audit_log_retention_days = 30
    with env.session() as db:
        reg.store(db, "logs_hold", None)       # the hold "off" in the database only
        db.commit()
    reg.refresh(env.session)
    _passes(env, 12)
    with env.session() as db:
        assert db.get(AuditLog, old) is not None
    assert ar.chain_numbers()[2] is True


def test_a_stop_of_two_days_moves_a_due_change_on_by_its_length(env):
    env.seal()
    ada = _admin(env)
    _change(env, ada, "logs_hold", True)
    _change(env, ada, "logs_hold", False)
    _passes(env, 24)
    env.clock.advance(days=2)                   # the server was stopped: no pass, no seal
    _passes(env, 5 * 24 + 6)                    # seven days after the request, five of them sealing
    assert ar.chain_numbers()[2] is True
    _passes(env, 2 * 24 + 6)
    assert ar.chain_numbers()[2] is False
    assert failures(env.verify()) == []


def test_vetoes_from_the_database_are_sealed_at_most_once_a_day(env):
    env.seal()
    for value in (900, 1000):
        with env.session() as db:
            reg.store(db, "audit_admin_min_days", value)
            db.commit()
        _passes(env, 1, step=1)
    vetoes = [s for s in env.seals() if s.kind == "policy" and s.detail["cause"] == "database"]
    assert len(vetoes) == 1 and vetoes[0].detail["state"]["audit_admin_min_days"]["value"] == 900
    _passes(env, 24)
    vetoes = [s for s in env.seals() if s.kind == "policy" and s.detail["cause"] == "database"]
    assert len(vetoes) == 2 and vetoes[1].detail["state"]["audit_admin_min_days"]["value"] == 1000
    assert failures(env.verify()) == []


def test_a_request_short_of_the_delay_is_unjustified(env):
    env.seal()
    _forge(env, "request", {"what": "setting", "request": str(uuid.uuid4()), "setting": "audit_max_days", "old": 0,
                            "new": 30, "subject": None, "placeholder": None,
                            "not_before": fmt.time_text(env.clock() + timedelta(days=1)), "audit_row": None,
                            "by": "admin", "user_id": None})
    with env.session() as db:
        off = verify_mod.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    found = [f for f in off.findings if f.kind == "unjustified"]
    assert found and "short of the delay" in found[0].message


def test_a_policy_seal_that_does_not_copy_an_entry_it_does_not_set_is_unjustified(env):
    env.seal()
    newest = _newest_policy(env)
    state = {k: dict(v) for k, v in newest.detail["state"].items()}
    seq = env.seals()[-1].seq + 1
    state["logs_hold"] = {"value": True, "source": "setting", "setting": True, "request_seq": seq, "set_by": seq}
    state["audit_max_days"]["set_by"] = seq      # its fields unchanged: it names a seal that did not set it
    _forge(env, "policy", {"state": state, "inputs": newest.detail["inputs"], "cause": "request",
                           "request_seq": None, "request": None, "audit_row": None, "by": "admin", "user_id": None})
    with env.session() as db:
        off = verify_mod.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    found = [f for f in off.findings if f.kind == "unjustified"]
    assert found and "not copied" in found[0].message


def test_nothing_applies_while_a_gap_is_open(env):
    """A request whose delay ran while sealing ran, then a stop of 13 hours: on the return, before anything is
    sealed again, nothing is due (the pass seals first, which closes the gap and counts it)."""
    env.seal()
    ada = _admin(env)
    _change(env, ada, "logs_hold", True)
    _change(env, ada, "logs_hold", False)
    request = [s for s in env.seals() if s.kind == "request"][-1]
    for _ in range(30):                          # seven and a half days of sealing, nothing applied
        env.clock.advance(hours=6)
        env.seal()
    assert ps.due_requests(env.st.view, env.clock()) == [request.seq]
    env.clock.advance(hours=13)                  # stopped
    assert ps.due_requests(env.st.view, env.clock()) == []
