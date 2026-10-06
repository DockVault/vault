"""The audit chain's dates and the honoured state, offline (app/core/audit_chain_honour.py,
app/core/audit_chain_times.py):

- the honoured state is a replay of the policy seals that count, merged with the chain's: a value another
  writer set aside is not laundered through an .env clamp and release, and a bound another writer raised
  counts at once;
- another writer's applies counts from the later of the host's acknowledgment and its request's due date,
  and when the request is another writer's too, from a delay after the server first accepted it;
- another writer's seals sit, for the gaps, where the server first accepted them: seals appended across a
  stop do not hide it;
- an administrator cannot cancel a request another writer's applies already applied; changing it back works.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_honour as honour
from app.core import audit_chain_policy as pol
from app.core import audit_chain_policy_seals as ps
from app.core import audit_integrity as ai
from app.core import audit_retention as ar
from app.core import retention
from app.core import setting_changes as sc
from app.core import settings_registry as reg
from app.core.models import AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange
from test_audit_chain_guards import _forge
from test_audit_chain_trust import _ack_by_host, _admin, _change, _newest_policy, _run_to

pytestmark = pytest.mark.unit


def _env(monkeypatch, tmp_path, **inputs):
    """A chain whose .env sets ``inputs`` (by their upper-case names), as the settings and as the process
    environment the chain reads its inputs from."""
    kw = {name.lower(): value for name, value in inputs.items()}
    e = Env(monkeypatch, tmp_path, **kw)
    for name, value in inputs.items():
        monkeypatch.setenv(name, str(value))
    return e


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = _env(monkeypatch, tmp_path, AUDIT_PROTECTED_MIN_DAYS=30)
    yield e
    e.close()


def _set_input(env, name, value):
    env.monkeypatch.setenv(name, str(value))
    setattr(env.settings, name.lower(), value)


def _honoured_max_days(env):
    return honour.honoured_state(env.st.view, env.st.known_record(), env.clock())["audit_max_days"]["value"]


def _accept(env):
    """The server reads the chain (a writer's check), accepting what another writer appended, and writes
    nothing of its own."""
    with ai.ChainWriter(env.engine, env.st):
        pass


def _request_after(env, new, delay_days):
    """A request for the maximum appended by another writer, with its change row, waiting ``delay_days``."""
    change_id = uuid.uuid4()
    with env.session() as db:
        db.add(ManagedSettingChange(id=change_id, key="audit_max_days", setting=new, old_value=0, new_value=new,
                                    status=sc.PENDING, requested_by=None, requested_by_name="x",
                                    requested_at=env.clock(), effective_at=env.clock() + timedelta(days=7)))
        db.commit()
    return _forge(env, "request", lambda seq, at: {
        "what": "setting", "request": str(change_id), "setting": "audit_max_days", "old": 0, "new": new,
        "subject": None, "placeholder": None, "not_before": fmt.time_text(at + timedelta(days=delay_days)),
        "audit_row": None, "by": "admin", "user_id": None})


def _db_newest_policy(env):
    """The newest policy seal's detail as the database holds it (another writer reads it there)."""
    with env.session() as db:
        seal = db.query(AuditSeal).filter(AuditSeal.kind == "policy").order_by(AuditSeal.seq.desc()).first()
        return seal.detail


def _db_request(env, req):
    with env.session() as db:
        return db.get(AuditSeal, req).detail


def _applies_of(env, req, new):
    """Another writer's applies of request ``req``, setting the maximum to ``new``, with what the server's
    applies writes into the database: the stored value, and the change row marked applied."""
    d = _db_newest_policy(env)
    asked = _db_request(env, req)
    with env.session() as db:
        row = db.get(ManagedSetting, "audit_max_days")
        if row is None:
            db.add(ManagedSetting(key="audit_max_days", value=new, version=1))
        else:
            row.value = new
        change = db.get(ManagedSettingChange, uuid.UUID(asked["request"]))
        if change is not None:
            change.status = sc.APPLIED
        db.commit()
    spec = {s.key: s for s in pol.chain_specs()}["audit_max_days"]
    ns = pol.settings_from_inputs(d["inputs"])

    def make(seq, _at):
        state = {k: dict(e) for k, e in d["state"].items()}
        state["audit_max_days"] = {**ps.setting_fields(spec, new, ns, d["inputs"], req), "set_by": seq}
        return ps._policy_detail(state, d["inputs"], "applies", request_seq=req, request=asked["request"],
                                 by="server")
    return _forge(env, "policy", make)


def _env_seal_elsewhere(env, **changed):
    """Another writer's env seal with ``changed`` inputs."""
    d = _db_newest_policy(env)
    inputs = dict(d["inputs"], **{k: str(v) for k, v in changed.items()})

    def make(seq, _at):
        return ps._policy_detail(pol.env_state(d["state"], inputs, seq), inputs, "env", by="server")
    return _forge(env, "policy", make)


def _admin_reduction_due(env, new):
    """An administrator's reduction of the maximum to ``new``, sealed and left to come due (sealing runs,
    nothing applies it)."""
    outcome = _change(env, _admin(env, f"a{uuid.uuid4().hex[:6]}"), "audit_max_days", new)
    assert outcome.status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    for _ in range(32):
        env.clock.advance(hours=6)
        env.seal()
    return req


# --------------------------------------------------------------------------- the replay

def test_a_set_aside_value_is_not_laundered_through_an_env_clamp_and_release(env):
    env.run_until_sealed()
    req = _admin_reduction_due(env, 90)
    lowered = _applies_of(env, req, 90)
    env.clock.advance(minutes=30)
    env.seal()
    assert _honoured_max_days(env) == 0                  # set aside: the log is kept for ever
    _set_input(env, "PLAN_LOG_MAX_DAYS", 60)
    env.clock.advance(minutes=30)
    env.seal()                                           # the server's env seal clamps the chain's 90 to 60
    assert env.st.view.newest_state()["audit_max_days"]["value"] == 60
    assert _honoured_max_days(env) == 60
    _set_input(env, "PLAN_LOG_MAX_DAYS", 1000)
    env.clock.advance(minutes=30)
    env.seal()                                           # and releases it: the chain says 90 again
    assert env.st.view.newest_state()["audit_max_days"]["value"] == 90
    assert _honoured_max_days(env) == 1000               # the replay's "for ever" under the new ceiling
    _ack_by_host(env, [lowered])
    assert _honoured_max_days(env) == 90                 # counted once the host has seen it
    assert failures(env.verify()) == []


def test_a_bound_another_writer_raised_counts_at_once_and_its_lowering_does_not(monkeypatch, tmp_path):
    env = _env(monkeypatch, tmp_path, AUDIT_PROTECTED_MIN_DAYS=30, PLAN_LOG_MAX_DAYS=365)
    try:
        env.run_until_sealed()
        assert _change(env, _admin(env), "audit_max_days", 400).status == "applied"   # clamped to 365
        assert env.st.view.newest_state()["audit_max_days"]["value"] == 365
        req = _admin_reduction_due(env, 90)
        _env_seal_elsewhere(env, PLAN_LOG_MAX_DAYS=1000)
        _applies_of(env, req, 90)
        _accept(env)
        assert env.st.view.newest_state()["audit_max_days"]["value"] == 90
        # The raised bound through the chain's side, the administrator's 400 through the replay's.
        assert _honoured_max_days(env) == 400
    finally:
        env.close()


# --------------------------------------------------------------------------- another writer's applies

def test_another_writers_applies_of_its_own_request_counts_a_delay_after_the_servers_acceptance(env):
    """Another writer's env seal sets the delay to one day (set aside: seven stay honoured), its
    request waits one day by the chain, and its applies follows a day later. The value counts only once the
    host has acknowledged all three and seven days have run since the server accepted the request."""
    old = env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    _env_seal_elsewhere(env, RETENTION_REDUCTION_DELAY_DAYS=1)
    env_seal = [s for s in env.seals()][-1].seq
    req = _request_after(env, 30, 1)
    retention.run_pass(env.session, now=env.clock())     # the server accepts both here
    accepted = fmt.parse_time_text([e for e in env.st.head_store().load()["after_record"]
                                    if e["seq"] == req][0]["accepted_at"])
    _run_to(env, env.clock() + timedelta(days=1, hours=1))
    applies = _applies_of(env, req, 30)
    retention.run_pass(env.session, now=env.clock())
    assert _honoured_max_days(env) == 0
    # Acknowledged without the request: the value still waits for the request's acknowledgment.
    _ack_by_host(env, [env_seal, applies])
    _run_to(env, accepted + timedelta(days=7, hours=1))
    assert _honoured_max_days(env) == 0
    _ack_by_host(env, [req])
    assert _honoured_max_days(env) == 30
    retention.run_pass(env.session, now=env.clock())
    with env.session() as db:
        assert db.get(AuditLog, old) is None


def test_another_writers_applies_counts_no_earlier_than_its_requests_due_date(env):
    """The same, acknowledged the next day: the value waits until seven days after the server accepted the
    request, not the one day the request's own dates give."""
    env.run_until_sealed()
    env_seal = _env_seal_elsewhere(env, RETENTION_REDUCTION_DELAY_DAYS=1)
    req = _request_after(env, 30, 1)
    retention.run_pass(env.session, now=env.clock())
    accepted = fmt.parse_time_text([e for e in env.st.head_store().load()["after_record"]
                                    if e["seq"] == req][0]["accepted_at"])
    _run_to(env, env.clock() + timedelta(days=1, hours=1))
    applies = _applies_of(env, req, 30)
    retention.run_pass(env.session, now=env.clock())
    env.clock.advance(hours=12)
    retention.run_pass(env.session, now=env.clock())
    _ack_by_host(env, [env_seal, req, applies])
    assert _honoured_max_days(env) == 0
    due = honour.request_due(env.st.view, env.st.known_record(), req, env.clock())
    assert abs(due - (accepted + timedelta(days=7))) < timedelta(minutes=1)
    _run_to(env, accepted + timedelta(days=7, hours=-1))
    assert _honoured_max_days(env) == 0
    _run_to(env, accepted + timedelta(days=7, hours=1))
    assert _honoured_max_days(env) == 30


def _forge_hours_across(env, until, step=11):
    """Another writer's empty hour seals every ``step`` hours from where sealing stopped until ``until``, each
    dated at its own time (the server is stopped meanwhile)."""
    while env.clock() + timedelta(hours=step) <= until:
        env.clock.advance(hours=step)
        with env.session() as db:
            last = db.query(AuditSeal).filter(AuditSeal.kind == "hour").order_by(AuditSeal.seq.desc()).first()
            first = db.get(AuditSeal, 1).detail
        start = last.period_end if last is not None else fmt.parse_time_text(first["backlog_through"]) + ai.HOUR
        end = ai.hour_floor(env.clock()) - ai.HOUR
        if end <= start:
            continue
        _forge(env, "hour", {}, period_start=start, period_end=end, root_s=fmt.EMPTY_ROOT, root_c=fmt.EMPTY_ROOT,
               ids_digest=fmt.ids_digest([]))


def test_a_request_and_its_applies_appended_across_a_stop_count_from_the_restart(env):
    """During a stop of ten days another writer appends a request dated at the stop's start,
    hour seals every 11 hours, and the applies a week on. All are accepted at the restart; the value counts
    no earlier than seven days of sealing after the restart, and a stop of three days before then moves it on
    by three days."""
    env.run_until_sealed()
    req = _request_after(env, 30, 7)
    stop_end = env.clock() + timedelta(days=10)
    _forge_hours_across(env, env.clock() + timedelta(days=7, hours=12))
    applies = _applies_of(env, req, 30)
    _forge_hours_across(env, stop_end)
    env.clock.at = stop_end
    retention.run_pass(env.session, now=env.clock())     # the restart: every seal of the stop accepted here
    _ack_by_host(env, [req, applies])
    restart = stop_end
    _run_to(env, restart + timedelta(days=2))
    env.clock.advance(days=3)                            # stopped again for three days
    retention.run_pass(env.session, now=env.clock())
    _run_to(env, restart + timedelta(days=10, hours=-2))
    assert _honoured_max_days(env) == 0
    _run_to(env, restart + timedelta(days=10, hours=2))
    assert _honoured_max_days(env) == 30


def test_seals_appended_across_a_stop_do_not_hide_it_from_a_pending_request(env):
    """A five-day stop with another writer's hour seals dated every 11 hours: the server places them at the
    restart, so the stop is still a gap, and an administrator's pending reduction waits five days more."""
    old = env.row(T0 - timedelta(days=60))
    env.run_until_sealed()
    outcome = _change(env, _admin(env), "audit_max_days", 30)
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    made = env.clock()
    _run_to(env, made + timedelta(days=1))
    _forge_hours_across(env, env.clock() + timedelta(days=5))
    retention.run_pass(env.session, now=env.clock())     # the restart
    _run_to(env, made + timedelta(days=7, hours=2))
    assert req not in env.st.view.applied and outcome.status == "pending"
    with env.session() as db:
        assert db.get(AuditLog, old) is not None
    _run_to(env, made + timedelta(days=12, hours=2))
    assert req in env.st.view.applied


def test_a_cancel_of_a_request_another_writers_applies_applied_is_refused_and_the_change_back_works(env):
    env.run_until_sealed()
    admin = _admin(env)
    outcome = _change(env, admin, "audit_max_days", 90)
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    _run_to(env, env.clock() + timedelta(days=7, hours=-1))
    nb = fmt.parse_time_text(env.st.view.requests[req]["not_before"])
    env.clock.at = nb
    applies = _applies_of(env, req, 90)                  # dated at the request's not_before ...
    env.clock.at = nb - timedelta(minutes=4)
    _accept(env)                                         # ... four minutes before the server's clock gets there
    assert applies in ai.unacknowledged_foreign(env.st.view, env.st.known_record())
    with pytest.raises(reg.SettingRefused) as refused:
        with ps.change_transaction(env.engine) as w:
            ps.cancel(w, outcome.change.id, admin)
    assert "cannot be cancelled" in str(refused.value) and "back to no limit" in str(refused.value)
    back = _change(env, admin, "audit_max_days", None)
    assert back.status == "applied"
    _ack_by_host(env, [applies])
    _run_to(env, env.clock() + timedelta(days=8))
    assert _honoured_max_days(env) == 0
    assert failures(env.verify()) == []
