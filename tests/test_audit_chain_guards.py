"""The audit log's integrity chain, offline: each rule a seal must meet, one test per rule.

- seals another writer appends after the head record, with the key in force but not the host: the face check
  the server runs before it accepts one (the rules audit verify applies to its kind, and the writer's own);
- the process's own chain: the newest seal's MAC, and the seal at the view's position read again;
- audit verify off the server (no head record): every rule a seal of each kind must meet;
- the rows with no timestamp, which genesis seals.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import secrets
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_policy as pol
from app.core import audit_chain_policy_seals as ps
from app.core import audit_chain_verify as v
from app.core import audit_integrity as ai
from app.core.models import AuditLog, AuditSeal

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _forge(env, kind, detail, *, key=None, **body):
    """A seal appended by someone who holds a key but not the host: no head record write. ``detail`` may be a
    function of (seq, sealed_at)."""
    with env.session() as db:
        seals = list(ai.read_seals(db, 0))
    prev = fmt.LINK_0
    for s in seals:
        prev = fmt.link(prev, s.body())
    key = key or env.st.current_key()
    seq = seals[-1].seq + 1
    at = body.get("sealed_at") or env.clock()
    if callable(detail):
        detail = detail(seq, at)
    seal = ai.Seal(seq, kind, body.get("period_start"), body.get("period_end"), fmt.FORMAT, body.get("row_count", 0),
                   body.get("row_bytes", 0), body.get("root_s"), body.get("root_c"), body.get("ids_digest"), detail,
                   key.key_id, at)
    link = fmt.link(prev, seal.body())
    with env.session() as db:
        db.add(AuditSeal(seq=seq, kind=kind, period_start=seal.period_start, period_end=seal.period_end, format=1,
                         row_count=seal.row_count, row_bytes=seal.row_bytes, root_s=seal.root_s, root_c=seal.root_c,
                         ids_digest=seal.ids_digest, detail=detail, key_id=key.key_id, sealed_at=at,
                         mac=fmt.mac(key.key, link), link=link))
        db.commit()
    return seq


def _append(env, kind, detail, **body):
    """A seal the server's own writer appends, with no check of its fields (audit verify then judges it)."""
    with ai.ChainWriter(env.engine, env.st) as w:
        return w.append(kind, detail=detail, **body).seq


def _off(env, **kw):
    """audit verify off the server: no head record."""
    kw.setdefault("check_rows", False)
    with env.session() as db:
        return v.verify(db, record=None, held={}, now=env.clock(), **kw)


def _why(report, kind="unjustified"):
    return [f.message for f in report.findings if f.kind == kind]


def _stopped_by(env, kind):
    """The next pass stops with ``kind``; the reason it gives."""
    env.clock.advance(minutes=30)
    result = env.seal()
    assert result.stopped == kind, (result.stopped, env.st.stopped)
    return str(env.st.stopped)


def _ack(by="admin"):
    return {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": by, "user_id": None,
            "request": None}


def _newest_policy(env):
    return env.st.view.newest_policy()


def _policy(env, cause, change, *, by="admin"):
    """A policy seal's detail: the newest policy seal's state with ``change(state, seq)`` applied."""
    seq_prev, d = _newest_policy(env)

    def make(seq, _at):
        state = {k: dict(e) for k, e in d["state"].items()}
        change(state, seq)
        return ps._policy_detail(state, d["inputs"], cause, by=by)
    return make


def _set(name, **fields):
    def change(state, seq):
        state[name] = {**state[name], **fields, "set_by": seq}
    return change


def _request(what="setting", *, by="admin", delay=7, **fields):
    def make(seq, at):
        d = {"what": what, "request": str(uuid.uuid4()), "setting": None, "old": None, "new": None, "subject": None,
             "placeholder": None, "not_before": fmt.time_text(at + timedelta(days=delay)), "audit_row": None,
             "by": by, "user_id": None}
        d.update(fields)
        return d
    return make


def _wait_days(env, days):
    """Passes of the sealer every six hours for ``days`` days (no gap, so a delay runs)."""
    for _ in range(days * 4):
        env.clock.advance(hours=6)
        env.seal()


def _sealed_hours(env):
    """A chain with an hour of rows sealed, and the empty hours after it."""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    assert env.st.view.newest_hour_end is not None


def _root(env, hour):
    """The hour's newest root seal, with its roots read again through the view's links."""
    with env.session() as db:
        return ai.hour_root(db, env.st.view, hour)


def _hour_entry(env, hour):
    root = _root(env, hour)
    return [fmt.hour_text(hour), root.seq, root.count, root.bytes, root.root_s.hex(), root.root_c.hex(),
            root.ids_digest.hex(), 0]


# --------------------------------------------------------------------------- another writer's seals: the face check

def test_a_seal_dated_ahead_of_the_servers_clock_is_refused(env):
    env.run_until_sealed()
    _forge(env, "ack", _ack(), sealed_at=env.clock() + timedelta(hours=3))
    assert "ahead of the server's clock" in _stopped_by(env, "after-record-invalid")


def test_a_seal_of_an_unknown_kind_is_refused(env):
    env.run_until_sealed()
    _forge(env, "bogus", {})
    assert "unknown kind" in _stopped_by(env, "after-record-invalid")


def test_an_archive_seal_appended_after_the_record_meets_step_four(env):
    """Its fields are checked as audit verify checks them (tests/test_audit_archive.py has each rule)."""
    env.run_until_sealed()
    _forge(env, "archive", {"day": "2026-10-19", "cause": "archive", "after_seq": None, "parts": [],
                            "complete": True})
    assert "an archive seal whose period is not its day" in _stopped_by(env, "after-record-invalid")


def test_an_hour_seal_that_does_not_start_where_the_last_ended_is_refused(env):
    _sealed_hours(env)
    start = env.st.view.newest_hour_end + ai.HOUR
    _forge(env, "hour", {"protected_bytes": 0}, period_start=start, period_end=start + ai.HOUR, root_s=fmt.EMPTY_ROOT,
           root_c=fmt.EMPTY_ROOT, ids_digest=fmt.ids_digest([]))
    assert "an hour seal starting at" in _stopped_by(env, "after-record-invalid")


def test_a_late_seal_that_does_not_follow_its_hours_root_is_refused_and_unjustified(env):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3, minutes=10))
    root = _root(env, hour)
    _forge(env, "late", {"hour": fmt.hour_text(hour), "prev_seq": root.seq - 1, "added": [], "by": "sealer",
                         "protected_bytes": 0},
           period_start=hour, period_end=hour + ai.HOUR, root_s=root.root_s, root_c=root.root_c,
           ids_digest=root.ids_digest, row_count=root.count)
    assert "does not follow its hour's root seal" in _stopped_by(env, "after-record-invalid")
    assert any("does not follow its hour's root seal" in m for m in _why(_off(env)))


def test_a_prune_seal_appended_after_the_record_meets_step_four(env):
    """A prune seal that names no policy seal: refused on its face, as audit verify calls it unjustified."""
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    _forge(env, "prune", {"reason": "retention", "policy_seq": 1, "request_seq": None,
                          "hours": [_hour_entry(env, hour)]})
    assert "does not name the policy seal in force" in _stopped_by(env, "after-record-invalid")


def test_a_cancel_of_a_request_that_is_not_pending_is_refused_and_unjustified(env):
    env.run_until_sealed()
    _forge(env, "cancel", {"cancels": 999, "request": None, "audit_row": None, "by": "admin", "user_id": None})
    assert "not pending" in _stopped_by(env, "after-record-invalid")
    assert any("not pending" in m for m in _why(_off(env)))


def test_a_seal_only_the_host_writes_that_the_record_does_not_list_stops_sealing(env):
    env.run_until_sealed()
    _forge(env, "ack", _ack(by="host"))
    _stopped_by(env, "host-seal-unrecorded")
    report = env.verify()
    assert "host-seal-unrecorded" in failures(report)


def test_a_key_seal_after_the_record_needs_its_proof(env):
    env.settings.audit_chain_key = ""
    env.run_until_sealed()
    old = env.st.current_key()
    env.settings.audit_chain_key = "d" * 64
    new = env.st.current_key()
    _forge(env, "key", {"old_key_id": old.key_id, "new_key_id": new.key_id, "old_key_proof": "00" * 32,
                        "accepted_unverified": False, "by": "sealer"}, key=new)
    assert "no proof" in _stopped_by(env, "key-unverified")


def test_a_key_seal_that_does_not_move_on_from_the_key_in_force_breaks_the_sequence(env):
    env.settings.audit_chain_key = ""
    env.run_until_sealed()
    old = env.st.current_key()
    env.settings.audit_chain_key = "d" * 64
    new = env.st.current_key()

    proof = fmt.old_key_proof(old.key, env.st.view.link_at(env.st.view.position), new.key_id).hex()
    _forge(env, "key", {"old_key_id": "kc1:" + "0" * 16, "new_key_id": new.key_id, "old_key_proof": proof,
                        "accepted_unverified": False, "by": "sealer"}, key=new)
    assert "does not move on" in _stopped_by(env, "key-sequence")


def test_a_seal_number_skipped_after_the_view_stops_sealing(env):
    env.run_until_sealed()
    seq = _forge(env, "ack", _ack())
    with env.session() as db:            # the seal after the view's position is renumbered: a gap
        db.query(AuditSeal).filter(AuditSeal.seq == seq).update({AuditSeal.seq: seq + 1})
        db.commit()
    _stopped_by(env, "seq-gap")


# --------------------------------------------------------------------------- the process's own chain

def test_the_newest_seals_mac_is_checked_under_the_key_in_force(env):
    env.run_until_sealed()
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == env.st.view.position).update({AuditSeal.mac: b"\0" * 32})
        db.commit()
    assert "does not verify under the key in force" in _stopped_by(env, "key-unverified")


def test_the_seal_at_the_views_position_is_read_again_by_a_running_process(env):
    env.run_until_sealed()
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == env.st.view.position).update({AuditSeal.row_bytes: 999})
        db.commit()
    assert "changed or went after this process accepted it" in _stopped_by(env, "head-record-mismatch")


# --------------------------------------------------------------------------- step 4, off the server

def test_an_anchor_that_names_another_link_is_a_mismatch(env):
    env.run_until_sealed()
    good = env.verify().head
    seq, _link = fmt.parse_head(good)
    assert "anchor-mismatch" not in failures(_off(env, anchor=good))
    assert "anchor-mismatch" in failures(_off(env, anchor=fmt.head(seq, b"\1" * 32)))


def test_hour_seals_must_tile_time(env):
    _sealed_hours(env)
    start = env.st.view.newest_hour_end + 2 * ai.HOUR
    _append(env, "hour", {"protected_bytes": 0}, period_start=start, period_end=start + ai.HOUR, root_s=fmt.EMPTY_ROOT,
            root_c=fmt.EMPTY_ROOT, ids_dig=fmt.ids_digest([]))
    assert "hour-missing" in failures(_off(env))


def test_a_run_of_hours_holding_rows_is_unjustified(env):
    _sealed_hours(env)
    start = env.st.view.newest_hour_end
    _append(env, "hour", {"protected_bytes": 0}, period_start=start, period_end=start + 2 * ai.HOUR, row_count=3,
            root_s=fmt.EMPTY_ROOT, root_c=fmt.EMPTY_ROOT, ids_dig=fmt.ids_digest([]))
    assert any("holds rows" in m for m in _why(_off(env)))


def test_a_seal_stepping_back_in_time_is_a_warning(env):
    env.run_until_sealed()
    env.clock.advance(hours=-1)
    _append(env, "ack", _ack())
    assert "sealed-at-backwards" in _off(env).kinds("warning")


def test_a_genesis_that_is_not_seal_one_is_unjustified(env):
    env.run_until_sealed()
    _append(env, "genesis", {"format": 1, "release": "x", "first_row_hour": None,
                             "backlog_through": fmt.hour_text(T0), "backlog_rows": 0, "undated_rows": 0,
                             "replaces": None, "grace_until": None},
            root_s=fmt.EMPTY_ROOT, root_c=fmt.EMPTY_ROOT, ids_dig=fmt.ids_digest([]))
    assert any("only seal 1 is genesis" in m for m in _why(_off(env)))


def test_a_host_seal_after_the_record_is_reported_by_audit_verify(env):
    env.run_until_sealed()
    _forge(env, "ack", _ack(by="host"))
    assert "host-seal-unrecorded" in failures(env.verify(check_rows=False))
    assert "host-seal-unrecorded" not in failures(_off(env))


def test_a_policy_seal_that_drops_an_entry_is_unjustified(env):
    env.run_until_sealed()

    def drop(state, seq):
        state.pop("logs_hold")
        state["security_record_days"] = {**state["security_record_days"], "value": 60, "source": "setting",
                                         "setting": 60, "request_seq": seq, "set_by": seq}
    _append(env, "policy", _policy(env, "request", drop))
    assert any("entries are not the previous seal's" in m for m in _why(_off(env)))


def test_an_entry_of_source_default_must_hold_the_default(env):
    env.run_until_sealed()
    _append(env, "policy", _policy(env, "request", lambda state, seq: _set(
        "security_record_days", value=60, request_seq=seq)(state, seq)))
    assert any("does not hold its .env input" in m for m in _why(_off(env)))


def test_two_database_seals_in_one_day_are_unjustified(env):
    env.run_until_sealed()
    for value in (60, 90):
        _append(env, "policy", _policy(env, "database", lambda state, seq, value=value: _set(
            "security_record_days", value=value, source="setting", setting=value, request_seq=seq)(state, seq),
            by="database"))
    assert _why(_off(env)) == [m for m in _why(_off(env)) if "second database seal in one day" in m] != []


def test_a_request_by_the_server_other_than_the_first_starts_is_unjustified(env):
    env.run_until_sealed()
    _append(env, "request", _request(by="server", setting="audit_max_days", old=0, new=400))
    assert any("by the server other than the first start's" in m for m in _why(_off(env)))


def _admin(env, name="ada"):
    from app.core.models import RoleEnum, User
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username=name, email=f"{name}@example.com", password_hash="x", role=RoleEnum.ADMIN,
                    is_active=True))
        db.commit()
    return env.session().get(User, uid)


def _change(env, actor, key, value):
    with ps.change_transaction(env.engine) as w:
        return ps.change(w, key, value, actor, now=env.clock())


def _due_request(env, name="security_record_days", new=10):
    """An administrator's reduction whose delay has run."""
    outcome = _change(env, _admin(env), name, new)
    assert outcome.status == "pending"
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    _wait_days(env, 8)
    return req


def _applies(env, req, change):
    seq_prev, d = _newest_policy(env)
    asked = env.st.view.requests[req]

    def make(seq, _at):
        state = {k: dict(e) for k, e in d["state"].items()}
        spec = {s.key: s for s in pol.chain_specs()}[asked["setting"]]
        ns = pol.settings_from_inputs(d["inputs"])
        state[asked["setting"]] = {**ps.setting_fields(spec, asked["new"], ns, d["inputs"], req), "set_by": seq}
        change(state, seq)
        return ps._policy_detail(state, d["inputs"], "applies", request_seq=req, request=asked["request"],
                                 by="server")
    return make


def test_an_applies_seal_that_sets_more_than_its_requests_setting_is_unjustified(env):
    env.run_until_sealed()
    req = _due_request(env)
    _append(env, "policy", _applies(env, req, _set("logs_hold", value=True, source="setting", setting=True,
                                                   request_seq=req)))
    assert any("sets more than its request's setting" in m for m in _why(_off(env)))


def test_an_applies_seal_must_set_its_requests_value(env):
    env.run_until_sealed()
    req = _due_request(env)
    _append(env, "policy", _applies(env, req, _set("security_record_days", value=12, source="setting", setting=12,
                                                   request_seq=req)))
    assert any("does not set its request's value" in m for m in _why(_off(env)))


def test_an_applies_seal_as_its_request_says_is_justified(env):
    env.run_until_sealed()
    req = _due_request(env)
    _append(env, "policy", _applies(env, req, lambda state, seq: None))
    assert _why(_off(env)) == []


def _erase_request(env, placeholder=None, subject="ab" * 32):
    placeholder = placeholder or "erased-" + secrets.token_hex(4)
    return _append(env, "request", _request("erase", subject=subject, placeholder=placeholder)), placeholder


def test_an_erase_request_needs_its_subject_and_placeholder(env):
    env.run_until_sealed()
    _erase_request(env, subject=None)
    assert any("without its subject and placeholder" in m for m in _why(_off(env)))


def test_two_erase_requests_may_not_share_a_placeholder(env):
    env.run_until_sealed()
    _req, placeholder = _erase_request(env)
    _erase_request(env, placeholder=placeholder)
    assert any("sharing another's placeholder" in m for m in _why(_off(env)))


def _erase(env, req, placeholder, hour, rows, *, final=False, policy_seq=None):
    return _append(env, "erase", {"hour": fmt.hour_text(hour), "request_seq": req, "request_id": None,
                                  "placeholder": placeholder, "policy_seq": policy_seq or _newest_policy(env)[0],
                                  "bytes_now": 0, "through": fmt.hour_text(hour), "final": final, "rows": rows})


def test_a_row_erased_twice_is_unjustified(env):
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 8)
    row = [str(uuid.uuid4()), "00" * 32, "11" * 32]
    _erase(env, req, placeholder, hour, [row])
    assert _why(_off(env)) == []
    _erase(env, req, placeholder, hour, [row])
    assert any("a row erased twice" in m for m in _why(_off(env)))


@pytest.mark.parametrize("how", ["cancelled", "completed"])
def test_an_erase_seal_for_a_request_that_is_not_pending_is_unjustified(env, how):
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 8)
    if how == "cancelled":
        _append(env, "cancel", {"cancels": req, "request": None, "audit_row": None, "by": "admin", "user_id": None})
    else:
        _erase(env, req, placeholder, hour, [], final=True)
    _erase(env, req, placeholder, hour, [])
    assert any("not pending" in m for m in _why(_off(env)))


def test_an_erase_seal_naming_another_policy_seal_than_the_one_in_force_is_unjustified(env):
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 8)
    _erase(env, req, placeholder, hour, [], final=True, policy_seq=_newest_policy(env)[0] - 1)
    assert any("does not name the policy seal in force" in m for m in _why(_off(env)))


def test_an_erase_request_naming_a_setting_or_a_value_is_unjustified(env):
    env.run_until_sealed()
    _append(env, "request", _request("erase", subject="ab" * 32, placeholder="erased-" + secrets.token_hex(4),
                                     setting="audit_max_days"))
    assert any("naming a setting or a value" in m for m in _why(_off(env)))


def test_an_erase_sealed_after_not_before_but_inside_a_stops_extension_is_unjustified(env):
    """A stop in sealing moves an erase on by its length, on verify's side too."""
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 2)
    env.clock.advance(hours=48)                          # a two-day stop
    for _ in range(4 * 4 + 2):                           # past not_before, inside the stop's length after it
        env.clock.advance(hours=6)
        env.seal()
    not_before = fmt.parse_time_text(env.st.view.requests[req]["not_before"])
    assert not_before + timedelta(hours=6) < env.clock() < not_before + timedelta(hours=48)
    _erase(env, req, placeholder, hour, [], final=True)
    assert any("before its request's delay has run" in m for m in _why(_off(env)))


def _erase_seal(env, req, placeholder, hour, through, *, final=False):
    return _append(env, "erase", {"hour": fmt.hour_text(hour), "request_seq": req, "request_id": None,
                                  "placeholder": placeholder, "policy_seq": _newest_policy(env)[0], "bytes_now": 0,
                                  "through": fmt.hour_text(through), "final": final, "rows": []})


def test_an_erase_seal_whose_scope_is_not_its_runs_is_unjustified(env):
    for h in (5, 3):
        env.row(T0 - timedelta(hours=h))
    env.run_until_sealed()
    first, second = ai.hour_floor(T0 - timedelta(hours=5)), ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 8)
    _erase_seal(env, req, placeholder, first, second)
    assert _why(_off(env)) == []
    _erase_seal(env, req, placeholder, first, first, final=True)        # an hour inside either scope
    assert any("whose scope is not its run's" in m for m in _why(_off(env)))


def test_an_erase_seal_for_an_hour_after_its_runs_scope_is_unjustified(env):
    for h in (5, 3):
        env.row(T0 - timedelta(hours=h))
    env.run_until_sealed()
    first, second = ai.hour_floor(T0 - timedelta(hours=5)), ai.hour_floor(T0 - timedelta(hours=3))
    req, placeholder = _erase_request(env)
    _wait_days(env, 8)
    _erase_seal(env, req, placeholder, second, first, final=True)
    assert any("for an hour after its run's scope" in m for m in _why(_off(env)))


def test_a_cancel_of_a_pending_request_is_justified(env):
    env.run_until_sealed()
    req, _placeholder = _erase_request(env)
    _append(env, "cancel", {"cancels": req, "request": None, "audit_row": None, "by": "admin", "user_id": None})
    assert _why(_off(env)) == []


def _prune(env, hours, policy_seq=None):
    return _append(env, "prune", {"reason": "retention", "policy_seq": policy_seq or _newest_policy(env)[0],
                                  "request_seq": None, "hours": hours})


def test_a_prune_seal_must_follow_each_hours_root_seal(env):
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    entry = _hour_entry(env, ai.hour_floor(T0 - timedelta(hours=3)))
    _prune(env, [entry])
    assert _why(_off(env)) == []
    entry[1] = entry[1] - 1
    _prune(env, [entry])
    assert any("does not follow its root seal" in m for m in _why(_off(env)))


def test_a_prune_seal_must_name_the_policy_seal_in_force(env):
    env.row(T0 - timedelta(hours=3))
    env.run_until_sealed()
    _prune(env, [_hour_entry(env, ai.hour_floor(T0 - timedelta(hours=3)))], policy_seq=1)
    assert any("does not name the policy seal in force" in m for m in _why(_off(env)))


def test_a_prune_seal_covers_one_day(env):
    first, second = T0 - timedelta(days=2, hours=1), T0 - timedelta(days=1, hours=1)
    env.row(first)
    env.row(second)
    env.run_until_sealed()
    _prune(env, [_hour_entry(env, ai.hour_floor(first)), _hour_entry(env, ai.hour_floor(second))])
    assert any("more than one day" in m for m in _why(_off(env)))


# --------------------------------------------------------------------------- the rows with no timestamp

def _undated(env, **kw):
    row = env.row(T0 - timedelta(hours=5), **kw)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == row).update({AuditLog.timestamp: None})
        db.commit()
    return row


def test_an_undated_row_edited_after_genesis_is_found(env):
    row = _undated(env, username="ghost")
    _undated(env, nonce=False)
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    assert failures(env.verify()) == []
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == row).update({AuditLog.username: "mallory"})
        db.commit()
    report = env.verify()
    assert "rows-altered" in failures(report)
    assert [f.hour for f in report.findings if f.kind == "rows-altered"] == ["undated"]


def test_an_undated_row_added_after_genesis_is_counted_by_every_pass_and_by_audit_verify(env):
    env.run_until_sealed()
    _undated(env)
    env.clock.advance(hours=1)
    env.seal()
    assert "undated-row" in env.st.head_store().load()["failures"]
    assert "undated-row" in failures(env.verify(check_rows=False))
    assert "rows-added" in failures(env.verify())
