"""Removing the values recorded under earlier recording levels (app/core/audit_value_removal.py), offline, on a
throwaway SQLite database with a chain of its own (tests/_removal_env.py):

- asking writes the row, the request seal (its levels and the end of the hour it is asked in) and the audit row;
  every administrator is told; nothing is removed before the delay; one removal at a time; nothing to remove at full;
- once due, the rows written before it, as rows and in archived days, keep only what the levels record: each changed
  row gets a fresh nonce, one rewrite seal per day of hours (and per archived day, with the archive seal of cause
  rewrite after it) names the request and its scope, the last seal is final with no hour, the stable roots and ids
  stay, and verify is clean; a row written after it is untouched; an erased row is passed over; the preview counted
  what it changed, and one past its time says what it had counted;
- a cancel stops it before it begins, never after; the database removing its row, or marking it no longer waiting,
  vetoes it; a row whose copies differ from its seal is not acted on; it waits for a registered rule (legal holds,
  open cases), the hold switch, a restore's grace, and the hours it covers to be sealed; an hour that waits after
  one rewritten the same day leaves that one rewritten;
- verify refuses a rewrite seal for levels that names no removal, comes before its delay, after it is complete, over
  another scope, over hours after it, and a final seal with hours; and a removal request that is not well formed.
"""
import json
import uuid
from datetime import datetime, time, timedelta

import pytest

from _audit_chain_env import T0, failures
from _removal_env import RemovalEnv, until
from app.core import audit_archive as arc
from app.core import audit_chain_format as fmt
from app.core import audit_chain_verify as v
from app.core import audit_integrity as ai
from app.core import audit_privacy as ap
from app.core import audit_rewrite as rw
from app.core import audit_value_removal as vr
from app.core import person_erase as pe
from app.core import retention
from app.core.models import AuditArchiveBlock, AuditLog, AuditValueRemoval

pytestmark = pytest.mark.unit

LOWER = {ap.NAMES: ap.FULL, ap.SIGNIN_NAMES: ap.FULL, ap.EMAILS: ap.NONE, ap.IP: ap.SHORTENED,
         ap.USER_AGENT: ap.NONE}


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = RemovalEnv(monkeypatch, tmp_path, levels=LOWER, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _audit(env, action):
    with env.session() as db:
        return db.query(AuditLog).filter(AuditLog.action == action).all()


def _hot(env):
    h1 = T0 - timedelta(hours=30)
    ids = [env.put(h1 + timedelta(minutes=5), details={"email": "a@example.com", "n": 1}),
           env.put(h1 + timedelta(minutes=15)),
           env.put(T0 - timedelta(hours=20), details={"changes": {"email": "b@example.com", "role": "user"}}),
           env.put(T0 - timedelta(hours=19), ip_address=None, user_agent=None)]   # nothing above the levels
    env.run_until_sealed()
    return ids


def _stable(env):
    """{hour: (root_s, ids digest)} of every hour seal."""
    return {s.period_start: (bytes(s.root_s), bytes(s.ids_digest)) for s in env.seals()
            if s.kind == "hour" and s.period_end - s.period_start == timedelta(hours=1)}


def test_a_removal_brings_earlier_rows_down_to_the_levels_and_the_chain_still_verifies(env):
    ids = _hot(env)
    nonces = {i: bytes(env.get(i).seal_nonce) for i in ids}
    stable = _stable(env)
    with env.session() as db:
        preview = vr.preview(db, env.st, env.clock())
    assert preview["rows"] == 3 and preview["counted"] is True
    assert {k["key"]: k["rows"] for k in preview["kinds"]} == {ap.EMAILS: 2, ap.IP: 3, ap.USER_AGENT: 3}
    asked = env.ask_removal()
    assert asked["status"] == vr.PENDING and asked["levels"] == LOWER
    seal = [s for s in env.seals() if s.kind == "request"][-1]
    assert seal.detail["what"] == "removal" and seal.detail["new"] == {
        "levels": LOWER, "before": fmt.hour_text(ai.hour_floor(seal.sealed_at) + timedelta(hours=1))}
    assert fmt.parse_time_text(seal.detail["not_before"]) == seal.sealed_at + timedelta(days=7)
    assert len(_audit(env, vr.REQUESTED_ACTION)) == 1
    env.passes(6)
    later = env.put(ai.hour_floor(env.clock()) + timedelta(minutes=10))   # after the scope ends
    env.passes(24 * 6)
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    for i in ids[:3]:
        row = env.get(i)
        assert row.ip_address is None and row.recorded == {"ip": "203.0.113.0/24"} and row.user_agent is None
        assert "email" not in json.dumps(row.details)
        assert bytes(row.seal_nonce) not in (nonces[i], fmt.ZERO_NONCE)
    assert env.get(ids[0]).details == {"n": 1} and env.get(ids[2]).details == {"changes": {"role": "user"}}
    assert bytes(env.get(ids[3]).seal_nonce) == nonces[ids[3]]
    assert env.get(later).ip_address == "203.0.113.9" and env.get(later).user_agent == "Mozilla/5.0 test"
    rewrites = env.rewrite_seals()
    assert [len(s.detail["hours"]) for s in rewrites] == [2, 0]
    assert [s.detail["final"] for s in rewrites] == [False, True]
    assert {s.detail["reason"] for s in rewrites} == {"levels"} and {s.detail["request_seq"] for s in rewrites} == {seal.seq}
    assert {s.detail["through"] for s in rewrites} == {fmt.hour_text(fmt.parse_time_text(seal.detail["new"]["before"])
                                                                     - timedelta(hours=1))}
    for h in rewrites[0].detail["hours"]:
        assert (bytes.fromhex(h[4]), bytes.fromhex(h[6])) == stable[fmt.parse_time_text(h[0])]
    row = env.removal_row(asked["id"])
    assert row.counts == {"rows": 3, "archived_rows": 0} == {"rows": preview["rows"], "archived_rows": 0}
    done = _audit(env, vr.REMOVED_ACTION)
    assert len(done) == 1 and done[0].details["rows"] == 3
    assert [e for e, f in env.removal_told] == ["completed"] and env.removal_told[0][1]["rows"] == 3
    report = env.verify()
    assert failures(report) == [], report.findings


def test_a_preview_that_runs_out_of_time_says_what_it_had_counted(env, monkeypatch):
    """Past its time a preview gives what it had counted, marked not counted; one that cannot count gives no
    number."""
    _hot(env)
    with env.session() as db:
        ctx, before = rw.Context.load(db), vr.scope_end(env.clock())
        assert vr.count_changes(db, env.st.view, LOWER, before, ctx)["counted"] is True
        assert vr.count_changes(db, env.st.view, LOWER, before, ctx, budget=-1) == {
            "rows": 0, "kinds": {ap.EMAILS: 0, ap.IP: 0, ap.USER_AGENT: 0}, "counted": False}
    monkeypatch.setattr(vr, "PREVIEW_SECONDS", -1)
    with env.session() as db:
        p = vr.preview(db, env.st, env.clock())
    assert p["counted"] is False and p["rows"] == 0

    def cannot(*args, **kwargs):
        raise RuntimeError("canceling statement due to statement timeout")
    monkeypatch.setattr(vr, "count_changes", cannot)
    with env.session() as db:
        p = vr.preview(db, env.st, env.clock())
    assert p["rows"] is None and p["counted"] is False and [k["rows"] for k in p["kinds"]] == [None] * 3


def test_nothing_is_asked_for_at_full_and_one_removal_waits_at_a_time(env):
    _hot(env)
    env.levels = {k: ap.FULL for k in ap.POLICY_KEYS}
    with pytest.raises(vr.Refused, match="nothing to remove"):
        env.ask_removal()
    env.levels = dict(LOWER)
    env.ask_removal()
    with pytest.raises(vr.Refused, match="already waiting"):
        env.ask_removal()


def test_a_cancelled_removal_never_runs(env):
    ids = _hot(env)
    asked = env.ask_removal()
    admin = env.admin("bea")
    out = env.cancel_removal(asked["id"], admin)
    assert out["status"] == vr.CANCELLED and env.removal_row(asked["id"]).decided_by_name == "bea"
    cancel = [s for s in env.seals() if s.kind == "cancel"][-1]
    assert cancel.detail["by"] == "admin" and cancel.detail["request"] == asked["id"]
    with pytest.raises(vr.Refused, match="no longer waiting"):
        env.cancel_removal(asked["id"], admin)
    env.week()
    env.passes(24)
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    assert len(_audit(env, vr.CANCELLED_ACTION)) == 1
    assert failures(env.verify()) == []


def test_a_removal_that_has_begun_completes_and_cannot_be_cancelled(env):
    env.put(T0 - timedelta(days=3), details={"email": "c@example.com"})      # another day: the first unit
    ids = _hot(env)
    asked = env.ask_removal()
    # The delay runs while a rule holds it back, so the run can then be started one unit at a time.
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    pe.WAIT_RULES.clear()
    seq = env.removal_row(asked["id"]).request_seq
    p = retention.Pass(env.session, now=env.clock())
    with ai.ChainWriter(env.engine, env.st) as w:
        outcome, changed, _cursor, done, _why = vr.step(p, w, seq, {})
    assert outcome == vr.REWRITTEN and changed == 1 and done is None
    with pytest.raises(vr.Refused, match="has begun"):
        env.cancel_removal(asked["id"], env.admin("cy"))
    assert vr.entry_of(env.removal_row(asked["id"]), env.st.view)["status"] == vr.RUNNING
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert all(env.get(i).ip_address is None for i in ids[:3])
    assert failures(env.verify()) == []


def test_the_database_removing_its_row_vetoes_it_and_a_changed_copy_is_not_acted_on(env):
    ids = _hot(env)
    asked = env.ask_removal()
    with env.session() as db:
        db.query(AuditValueRemoval).filter(AuditValueRemoval.id == uuid.UUID(asked["id"])).delete()
        db.commit()
    env.removal_job()
    cancel = [s for s in env.seals() if s.kind == "cancel"][-1]
    assert cancel.detail["by"] == "database" and cancel.detail["request"] == asked["id"]
    second = env.ask_removal()
    with env.session() as db:
        row = db.get(AuditValueRemoval, uuid.UUID(second["id"]))
        row.levels = dict(LOWER, ip=ap.NONE)
        db.commit()
    with env.session() as db:
        assert any("other levels" in m for m in vr.pending_input_problems(db, env.st.view))
    env.week()
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"


@pytest.mark.parametrize("status", [vr.CANCELLED, vr.COMPLETED])
def test_the_database_marking_its_row_no_longer_waiting_vetoes_it(env, status):
    """A row the database no longer shows waiting vetoes the removal as a removed row does, before its delay: it is
    ended by a cancel seal from the database, and nothing is rewritten, then or later."""
    ids = _hot(env)
    asked = env.ask_removal()
    with env.session() as db:
        db.get(AuditValueRemoval, uuid.UUID(asked["id"])).status = status
        db.commit()
    env.removal_job()
    cancel = [s for s in env.seals() if s.kind == "cancel"][-1]
    assert cancel.detail["by"] == "database" and cancel.detail["request"] == asked["id"]
    env.week()
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    assert failures(env.verify()) == []


def test_it_waits_for_a_registered_rule_and_the_hold_switch(env, monkeypatch):
    ids = _hot(env)
    asked = env.ask_removal()
    monkeypatch.setattr(pe, "WAIT_RULES", [lambda db, now: "a legal hold is in force"])
    env.week()
    assert env.rewrite_seals() == [] and env.removal_row(asked["id"]).waiting == "It waits: a legal hold is in force."
    monkeypatch.setattr(pe, "WAIT_RULES", [])
    env.settings.retention_hold = True
    env.passes(24)
    assert env.rewrite_seals() == []
    env.settings.retention_hold = False
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(ids[0]).ip_address is None


def test_the_job_itself_rewrites_nothing_during_the_grace_after_a_restore(env, monkeypatch):
    """A pass skips the job while a restore's grace runs; the job run on its own, its delay run, rewrites nothing
    either, and the removal goes on once the grace is over."""
    ids = _hot(env)
    asked = env.ask_removal()
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    pe.WAIT_RULES.clear()
    real = type(env.st).holds_deletion
    monkeypatch.setattr(type(env.st), "holds_deletion", lambda self: "the grace after a restore runs until later")
    env.removal_job()                 # run directly: a pass skips a held job before it starts
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    assert env.removal_row(asked["id"]).status == vr.PENDING
    monkeypatch.setattr(type(env.st), "holds_deletion", real)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(ids[0]).ip_address is None


def test_it_does_not_begin_while_the_hours_it_covers_are_not_all_sealed(env, monkeypatch):
    """Its delay run, a removal does not begin, rewriting nothing and still cancellable, while sealing has stopped
    (a gap is open, so it is not due), nor, a step of it taken on its own, while the hour it was asked in is not
    sealed; once sealing goes on it begins and completes."""
    ids = _hot(env)
    asked = env.ask_removal()
    real = ai.seal_pass
    monkeypatch.setattr(ai, "seal_pass", lambda *a, **k: None)
    env.week()
    assert env.removal_row(asked["id"]).status == vr.PENDING
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    seq = env.removal_row(asked["id"]).request_seq
    p = retention.Pass(env.session, now=env.clock())
    with ai.ChainWriter(ai._engine_of(env.session), env.st) as w:
        outcome, changed, _cursor, done, why = vr.step(p, w, seq, {})
        assert w.written == []
    assert (outcome, changed, done, why) == (vr.WAIT, 0, None, "It waits until every hour it covers is sealed.")
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    monkeypatch.setattr(ai, "seal_pass", real)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(ids[0]).ip_address is None and failures(env.verify()) == []


DAY = (T0 - timedelta(days=100)).date()


def _at(hour, minute=0):
    return datetime.combine(DAY, time(hour, minute))


def test_archived_days_are_rewritten_in_their_blocks(env):
    ids = [env.put(_at(3, 5), details={"email": "a@example.com"}), env.put(_at(3, 15), seal_nonce=None),
           env.put(_at(5, 5), ip_address=None, user_agent=None)]
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditArchiveBlock).count() == 1
        assert db.query(AuditLog).filter(AuditLog.id.in_(ids)).count() == 0
    with env.session() as db:
        preview = vr.preview(db, env.st, env.clock())
    assert preview["archived_days"] == 1
    asked = env.ask_removal()
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        part = env.st.view.archives[block.day].parts[0]
        rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day, part).rows()}
        assert _at(3) not in arc.open_part(db, block.day, part).salts
    for i in ids[:2]:
        assert rows[i]["ip_address"] is None and rows[i]["user_agent"] is None
        assert json.loads(rows[i]["recorded"]) == {"ip": "203.0.113.0/24"}
    assert "email" not in (rows[ids[0]]["details"] or "")
    assert rows[ids[2]]["recorded"] is None
    kinds = [s.kind for s in env.seals()]
    first = env.rewrite_seals()[0]
    assert kinds[kinds.index("rewrite") + 1] == "archive"
    archive = next(s for s in env.seals() if s.kind == "archive" and s.seq == first.seq + 1)
    assert archive.detail["cause"] == "rewrite" and archive.detail["after_seq"] == first.seq
    assert env.removal_row(asked["id"]).counts == {"rows": 0, "archived_rows": 2}
    report = env.verify()
    assert failures(report) == [], report.findings


@pytest.mark.parametrize("archived", [False, True])
def test_a_removal_passes_over_an_erased_row_even_when_its_change_would_take_it(env, monkeypatch, archived):
    """An erased row stays as its erase seal says: a removal passes over it, as a row and in an archived day, even
    when the change it runs would take it (here every row also gives up its browser description)."""
    when = _at(3, 5) if archived else T0 - timedelta(hours=30)
    erased = env.put(when, username="eve")
    kept = env.put(when + timedelta(minutes=10))
    env.run_until_sealed()
    if archived:
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
    erase = env.ask("eve")
    assert until(env, lambda: env.request_row(erase["id"]).status == pe.COMPLETED)
    real = rw.reduced
    monkeypatch.setattr(rw, "reduced", lambda row, levels, ctx: dict(real(row, levels, ctx) or {}, user_agent=None))
    asked = env.ask_removal()
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    if archived:
        with env.session() as db:
            block = db.query(AuditArchiveBlock).one()
            part = env.st.view.archives[block.day].parts[0]
            rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day, part).rows()}
    else:
        rows = {i: {c: getattr(env.get(i), c) for c in ("username", "seal_nonce", "ip_address", "recorded")}
                for i in (erased, kept)}
    assert rows[erased]["username"] == erase["placeholder"] and bytes(rows[erased]["seal_nonce"]) == fmt.ZERO_NONCE
    assert rows[kept]["ip_address"] is None and rows[kept]["recorded"] is not None
    report = env.verify()
    assert failures(report) == [], report.findings


# --------------------------------------------------------------------------- what verify refuses

class _Seal:
    def __init__(self, seq, kind, detail, sealed_at):
        self.seq, self.kind, self.detail, self.sealed_at = seq, kind, detail, sealed_at


def _due_removal(env):
    """A removal whose delay has run, held back by a rule meanwhile so that it has not begun."""
    _hot(env)
    asked = env.ask_removal()
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    pe.WAIT_RULES.clear()
    seq = env.removal_row(asked["id"]).request_seq
    req = env.st.view.requests[seq]
    before = fmt.parse_time_text(req["new"]["before"])
    assert env.rewrite_seals() == [] and env.clock() > fmt.parse_time_text(req["not_before"])
    return seq, req, before


def test_verify_refuses_a_rewrite_for_levels_out_of_its_removal(env):
    seq, req, before = _due_removal(env)
    view = env.st.view
    after = env.clock()
    hour = fmt.hour_text(T0 - timedelta(hours=30))
    good = {"reason": "levels", "policy_seq": view.newest_policy()[0], "request_seq": seq, "hours": [[hour]],
            "through": fmt.hour_text(before - timedelta(hours=1)), "final": False}
    assert rw.rewrite_problem(view, _Seal(view.position + 1, "rewrite", good, after)) is None
    cases = [
        (dict(good, request_seq=seq - 1), after, "names no removal"),
        (dict(good, request_seq=None), after, "names no removal"),
        (good, after - timedelta(days=2), "before its request's delay"),
        (dict(good, through=hour), after, "scope is not its removal's"),
        (dict(good, final=None), after, "scope is not its removal's"),
        (dict(good, hours=[[fmt.hour_text(before)]]), after, "after its removal's scope"),
        (dict(good, final=True), after, "last seal that rewrites hours"),
        (dict(good, hours=[]), after, "no hours"),
        (dict(good, reason="tidy"), after, "no reason a rewrite has"),
    ]
    for detail, at, why in cases:
        assert why in (rw.rewrite_problem(view, _Seal(view.position + 1, "rewrite", detail, at)) or ""), (detail, why)
    # A pending request of another kind is not a removal.
    from app.core import audit_chain_policy_seals as ps
    with ps.change_transaction(env.engine) as w:
        ps.change(w, rw.FULL_DAYS_KEY, 30, env.admin("setter"), now=env.clock())
    view = env.st.view
    other = max(s for s, d in view.pending_requests().items() if d.get("what") == "setting")
    assert "names no removal" in (rw.rewrite_problem(view, _Seal(view.position + 1, "rewrite",
                                                                 dict(good, request_seq=other), after)) or "")
    # Once final, nothing more of it.
    assert until(env, lambda: seq in env.st.view.finals)
    assert "not pending" in rw.rewrite_problem(env.st.view, _Seal(env.st.view.position + 1, "rewrite", good,
                                                                    env.clock()))


def test_verify_refuses_a_removal_request_that_is_not_well_formed(env):
    _hot(env)
    at = env.clock()
    before = fmt.hour_text(ai.hour_floor(at) + timedelta(hours=1))
    good = {"what": "removal", "setting": None, "old": None, "subject": None, "placeholder": None,
            "new": {"levels": dict(LOWER), "before": before}}
    assert rw.removal_request_problem(good, at) is None
    bad = [
        (dict(good, setting="audit_max_days"), "naming a setting"),
        (dict(good, placeholder="erased-0a1b2c3d"), "naming a setting"),
        (dict(good, new={"levels": dict(LOWER)}), "its levels and the time"),
        (dict(good, new={"levels": {k: ap.FULL for k in ap.POLICY_KEYS}, "before": before}), "removes nothing"),
        (dict(good, new={"levels": dict(LOWER, ip="fingerprint"), "before": before}), "is not a level of ip"),
        (dict(good, new={"levels": {ap.IP: ap.NONE}, "before": before}), "a level for each kind"),
        (dict(good, new={"levels": dict(LOWER), "before": fmt.time_text(ai.hour_floor(at) + timedelta(minutes=30))}),
         "before an hour boundary"),
        (dict(good, new={"levels": dict(LOWER), "before": fmt.hour_text(ai.hour_floor(at))}),
         "do not end with the hour"),
        (dict(good, new={"levels": dict(LOWER), "before": fmt.hour_text(ai.hour_floor(at) + timedelta(hours=2))}),
         "do not end with the hour"),
    ]
    for detail, why in bad:
        assert why in (rw.removal_request_problem(detail, at) or ""), (detail, why)


def test_a_forged_removal_rewrite_is_found_by_verify(env):
    seq, req, before = _due_removal(env)
    assert until(env, lambda: seq in env.st.view.finals)
    assert failures(env.verify()) == []
    # Another writer with the key appends a rewrite for the completed removal: verify refuses it.
    with ai.ChainWriter(env.engine, env.st) as w:
        w.append("rewrite", detail={"reason": "levels", "policy_seq": w.st.view.newest_policy()[0],
                                    "request_seq": seq, "hours": [], "through": fmt.hour_text(before - timedelta(hours=1)),
                                    "final": True})
    assert failures(env.verify()) != []


def test_a_removal_over_archived_days_and_rows_reaches_both(env):
    archived = env.put(_at(3, 5))
    hot = env.put(T0 - timedelta(hours=30))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    asked = env.ask_removal()
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(hot).ip_address is None
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        part = env.st.view.archives[block.day].parts[0]
        rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day, part).rows()}
    assert rows[archived]["ip_address"] is None
    assert env.removal_row(asked["id"]).counts == {"rows": 1, "archived_rows": 1}
    assert failures(env.verify()) == []


def test_an_archived_day_with_nothing_to_remove_is_passed_over_and_the_rows_after_it_are_reached(env):
    env.put(_at(3, 5), ip_address=None, user_agent=None)
    hot = env.put(T0 - timedelta(hours=30))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        payload = db.query(AuditArchiveBlock).one().payload
    asked = env.ask_removal()
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(hot).ip_address is None and env.get(hot).user_agent is None
    with env.session() as db:
        assert db.query(AuditArchiveBlock).one().payload == payload
    assert env.removal_row(asked["id"]).counts == {"rows": 1, "archived_rows": 0}
    assert failures(env.verify()) == []


def test_the_job_itself_rewrites_nothing_while_the_chain_holds(env, monkeypatch):
    from app.core import audit_chain_policy_seals as ps
    ids = _hot(env)
    asked = env.ask_removal()
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    pe.WAIT_RULES.clear()
    numbers = ps.numbers
    monkeypatch.setattr(ps, "numbers", lambda st=None: dict(numbers(st), logs_hold=True))
    env.removal_job()                 # run directly: a pass skips a held job before it starts
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    assert env.removal_row(asked["id"]).waiting == "It waits while the hold switch is on."


def test_a_removal_request_not_well_formed_is_found_by_verify(env):
    _hot(env)
    with ai.ChainWriter(env.engine, env.st) as w:
        w.append("request", detail=lambda seq, sealed_at: {
            "what": "removal", "request": str(uuid.uuid4()), "setting": None, "old": None,
            "new": {"levels": {k: ap.FULL for k in ap.POLICY_KEYS}, "before": fmt.hour_text(ai.hour_floor(sealed_at))},
            "subject": None, "placeholder": None, "not_before": fmt.time_text(sealed_at + timedelta(days=7)),
            "audit_row": None, "by": "admin", "user_id": None})
    assert failures(env.verify()) != []


def test_a_removal_waits_at_an_hour_another_writer_sealed(env, monkeypatch):
    ids = _hot(env)
    asked = env.ask_removal()
    hour = ai.hour_floor(T0 - timedelta(hours=30))
    real = ai.hour_held
    monkeypatch.setattr(ai, "hour_held", lambda view, record, h: 77 if h == hour else real(view, record, h))
    env.week()
    assert env.rewrite_seals() == [] and env.get(ids[0]).ip_address == "203.0.113.9"
    assert "waits for the host operator" in (env.removal_row(asked["id"]).waiting or "")
    monkeypatch.setattr(ai, "hour_held", real)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)


def test_an_hour_that_waits_after_one_rewritten_the_same_day_leaves_that_one_sealed(env, monkeypatch):
    """The hours of one day go in one transaction: an hour that waits after one already rewritten in it leaves that
    one rewritten under its rewrite seal; the removal waits at the other, and goes on once it no longer waits."""
    ids = _hot(env)
    asked = env.ask_removal()
    first, held = ai.hour_floor(T0 - timedelta(hours=30)), ai.hour_floor(T0 - timedelta(hours=20))
    real = ai.hour_held
    monkeypatch.setattr(ai, "hour_held", lambda view, record, h: 77 if h == held else real(view, record, h))
    env.week()
    assert env.get(ids[0]).ip_address is None and env.get(ids[1]).ip_address is None
    assert env.get(ids[2]).ip_address == "203.0.113.9"
    assert [[e[0] for e in s.detail["hours"]] for s in env.rewrite_seals()] == [[fmt.hour_text(first)]]
    assert "waits for the host operator" in (env.removal_row(asked["id"]).waiting or "")
    monkeypatch.setattr(ai, "hour_held", real)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(ids[2]).ip_address is None
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- a day archived over several passes

class _Steps(retention.Pass):
    """A pass with time for ``n`` transactions of a job, so that a run can be taken a unit at a time."""

    def __init__(self, env, n=1):
        super().__init__(env.session, now=env.clock())
        self.left = n

    def time_left(self):
        self.left -= 1
        return self.left >= 0


def _half_archived(env, monkeypatch):
    """A day archived over two passes, as a large day is: its 02:00 rows in a block, its 09:00 rows still rows."""
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    early = [env.put(_at(2, m)) for m in (5, 15, 25)]
    late = [env.put(_at(9, m)) for m in (5, 15, 25)]
    env.run_until_sealed()
    monkeypatch.setattr(ai, "ROW_BUDGET", 3)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    monkeypatch.setattr(ai, "ROW_BUDGET", 50000)
    with env.session() as db:
        assert db.query(AuditArchiveBlock).count() == 1
        assert db.query(AuditLog).filter(AuditLog.id.in_(early)).count() == 0
        assert db.query(AuditLog).filter(AuditLog.id.in_(late)).count() == 3
    return early, late


def _values(env):
    """{id: (ip_address, user_agent)} of every row, as rows and in the archived days' blocks."""
    out = {}
    with env.session() as db:
        for r in db.query(AuditLog).all():
            out[r.id] = (r.ip_address, r.user_agent)
        for day, entry in env.st.view.archives.items():
            for part in entry.parts:
                for r in arc.PartReader(db, env.st.view, day, part).rows():
                    out[r["id"]] = (r["ip_address"], r["user_agent"])
    return out


def _idle_archive(monkeypatch):
    """The archive job idle (a day this large takes several of its passes); returns the real one."""
    real = arc.archive_job
    monkeypatch.setattr(arc, "archive_job", lambda p: retention.JobResult())
    return real


def test_a_removal_over_a_day_archived_in_part_reaches_the_hours_still_held_as_rows(env, monkeypatch):
    """A day whose first hours are in a block and whose later hours are still rows (between two archive passes): the
    removal brings both down, its counts are the preview's rows and the block's, and verify is clean."""
    early, late = _half_archived(env, monkeypatch)
    with env.session() as db:
        preview = vr.preview(db, env.st, env.clock())
    assert preview["rows"] == 3 and preview["archived_days"] == 1
    asked = env.ask_removal()
    real = _idle_archive(monkeypatch)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    values = _values(env)
    assert [i for i in early + late if values[i] != (None, None)] == []
    assert env.removal_row(asked["id"]).counts == {"rows": preview["rows"], "archived_rows": 3}
    assert failures(env.verify()) == []
    # Archived afterwards, the later hours stay as the removal left them.
    monkeypatch.setattr(arc, "archive_job", real)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(late)).count() == 0
    values = _values(env)
    assert [i for i in late if values[i] != (None, None)] == []
    assert failures(env.verify()) == []


def test_a_removal_takes_the_day_again_when_the_archive_finishes_it_between_two_of_its_steps(env, monkeypatch):
    """The archive job archives the day's later hours after the removal rewrote its first block: the day is taken
    again for them (its first block then holds nothing to change), and every row of it is brought down."""
    early, late = _half_archived(env, monkeypatch)
    asked = env.ask_removal()
    real = _idle_archive(monkeypatch)
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    pe.WAIT_RULES.clear()
    vr.run_job(_Steps(env, 1))
    values = _values(env)
    assert [values[i] for i in early] == [(None, None)] * 3
    assert [values[i] for i in late] == [("203.0.113.9", "Mozilla/5.0 test")] * 3
    assert env.removal_row(asked["id"]).status == vr.RUNNING
    monkeypatch.setattr(arc, "archive_job", real)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(late)).count() == 0
    monkeypatch.setattr(arc, "archive_job", lambda p: retention.JobResult())
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    values = _values(env)
    assert [i for i in early + late if values[i] != (None, None)] == []
    assert env.removal_row(asked["id"]).counts == {"rows": 0, "archived_rows": 6}
    hours = [[e[0] for e in s.detail["hours"]] for s in env.rewrite_seals()]
    assert hours == [[fmt.hour_text(_at(2))], [fmt.hour_text(_at(9))], []]
    assert failures(env.verify()) == []


def test_a_removal_whose_own_day_is_archived_before_it_runs_completes(env, monkeypatch):
    """Held back for days, a removal meets the day it was asked in archived: the rows of that day written before its
    scope's end are brought down, the later ones are not, and it completes."""
    monkeypatch.setattr(arc, "hot_days", lambda: 0)
    real = _idle_archive(monkeypatch)
    inside = env.put(env.clock() - timedelta(minutes=20))
    env.run_until_sealed()
    asked = env.ask_removal()
    before = env.removal_row(asked["id"]).before
    after = env.put(before + timedelta(minutes=5))
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    monkeypatch.setattr(arc, "archive_job", real)
    for _ in range(4):
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert before.date() in env.st.view.archives
    pe.WAIT_RULES.clear()
    monkeypatch.setattr(arc, "archive_job", lambda p: retention.JobResult())
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED, hours=24 * 3)
    values = _values(env)
    assert values[inside] == (None, None) and values[after] == ("203.0.113.9", "Mozilla/5.0 test")
    assert failures(env.verify()) == []


def test_rows_left_in_an_archived_hour_are_reported_and_nothing_of_the_day_is_rewritten(env, monkeypatch):
    """A row of audit_logs in an hour a block holds (no path of the app writes one there): the removal reports
    row-in-archived-day for that day, rewrites nothing in it, and does not complete."""
    kept = env.put(_at(3, 5))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    asked = env.ask_removal()
    pe.WAIT_RULES.append(lambda db, now: "held for the test")
    env.week()
    pe.WAIT_RULES.clear()
    stray = env.put(_at(3, 30))
    with env.session() as db:
        payload = db.query(AuditArchiveBlock).one().payload
    seen = {}
    monkeypatch.setattr(ai, "report_failures", lambda st, f, found, *a, **k: seen.update(found))
    env.removal_job()
    assert "row-in-archived-day" in seen
    assert f"nothing in {DAY.isoformat()} was rewritten" in seen["row-in-archived-day"]
    with env.session() as db:
        assert db.query(AuditArchiveBlock).one().payload == payload
    assert env.get(stray).ip_address == "203.0.113.9" and env.rewrite_seals() == []
    assert env.removal_row(asked["id"]).status == vr.PENDING
    assert _values(env)[kept] == ("203.0.113.9", "Mozilla/5.0 test")


def test_a_day_a_later_release_archived_holds_a_removal_and_its_card_says_so(env, monkeypatch):
    """A day archived in a later release's block format (a rollback): a removal cannot complete in this release; it
    waits there with no finding, and its row (which its card shows) says why it waits."""
    from app.core import audit_archive_format as af
    hot = env.put(T0 - timedelta(hours=30))
    env.put(_at(3, 5))
    env.run_until_sealed()
    monkeypatch.setattr(af, "FORMAT", 2)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    monkeypatch.setattr(af, "FORMAT", 1)
    seen = {}
    monkeypatch.setattr(ai, "report_failures", lambda st, f, found, *a, **k: seen.update(found))
    asked = env.ask_removal()
    env.week()
    env.passes(24)
    row = env.removal_row(asked["id"])
    assert row.status == vr.PENDING and seen == {}
    assert row.waiting == (f"It waits: {DAY.isoformat()} is archived in a later release's block format, which "
                           "this release does not change, so this release cannot complete it.")
    assert env.get(hot).ip_address == "203.0.113.9"
    assert vr.entry_of(row, env.st.view)["waiting"] == row.waiting
