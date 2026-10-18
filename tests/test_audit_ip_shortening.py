"""Keeping full addresses in audit rows for a number of days only (audit_ip_full_days, app/core/audit_rewrite.py),
offline, on a throwaway SQLite database with a chain of its own (tests/_removal_env.py):

- with no limit (the default) nothing changes;
- with a number, each address recorded in full (the column and the details classified as addresses) is shortened to
  its network once its row is that many days old, as rows and in archived days: rewrite seals of reason shorten-ip,
  the stable roots and ids kept, fresh nonces, verify clean; a row younger stays until it is old enough; a pass
  with nothing to do writes nothing; a transaction takes the hours of one day, an hour that does not check out
  leaves the hours before it shortened, and an archived day with nothing to shorten is passed over; a legal hold
  or a restore's grace holds it;
- setting a number in the panel deletes sooner: it waits the reduction delay; no limit again applies at once;
- verify refuses a shortening while there is no limit, over rows younger than the days, or naming a request;
- the setting is a chain setting whose lower values delete sooner, in .env, the host tool and the docs.
"""
import json
from datetime import datetime, time, timedelta
from pathlib import Path

import pytest

from _audit_chain_env import T0, failures
from _removal_env import RemovalEnv, until
from app.core import audit_archive as arc
from app.core import audit_chain_format as fmt
from app.core import audit_chain_policy as pol
from app.core import audit_chain_policy_seals as ps
from app.core import audit_integrity as ai
from app.core import audit_rewrite as rw
from app.core import person_erase as pe
from app.core import retention
from app.core import settings_registry as reg
from app.core.models import AuditArchiveBlock, AuditLog

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _env(monkeypatch, tmp_path, days=None):
    e = RemovalEnv(monkeypatch, tmp_path, audit_archive_start_after_days=0,
                   **({"audit_ip_full_days": days} if days is not None else {}))
    if days is not None:
        # The chain's first policy seal takes the .env input (the environment, as the server reads it).
        monkeypatch.setenv("AUDIT_IP_FULL_DAYS", str(days))
    arc._marker_checked.clear()
    arc._figures.clear()
    return e


@pytest.fixture
def env30(monkeypatch, tmp_path):
    e = _env(monkeypatch, tmp_path, 30)
    yield e
    e.close()


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = _env(monkeypatch, tmp_path)
    yield e
    e.close()


def _shortened(row):
    return row.ip_address is None and (row.recorded or {}).get("ip") == "203.0.113.0/24"


def test_with_no_limit_nothing_is_shortened(env):
    old = env.put(T0 - timedelta(days=60))
    env.run_until_sealed()
    env.passes(48)
    assert env.get(old).ip_address == "203.0.113.9" and env.rewrite_seals() == []


def test_addresses_older_than_the_days_are_shortened_and_the_chain_still_verifies(env30):
    env = env30
    old = [env.put(T0 - timedelta(days=40, minutes=m), details={"client_ip": "198.51.100.4", "n": 1}) for m in (5, 10)]
    old.append(env.put(T0 - timedelta(days=35)))
    young = env.put(T0 - timedelta(days=29, hours=12))
    already = env.put(T0 - timedelta(days=40, minutes=20), ip_address=None, recorded={"ip": "203.0.113.0/24"})
    env.run_until_sealed()
    nonces = {i: bytes(env.get(i).seal_nonce) for i in old + [young, already]}
    stable = {s.period_start: (bytes(s.root_s), bytes(s.ids_digest)) for s in env.seals()
              if s.kind == "hour" and s.period_end - s.period_start == timedelta(hours=1)}
    assert pol.value_of(env.st.view.newest_state(), rw.FULL_DAYS_KEY) == 30
    env.passes(6)
    for i in old:
        row = env.get(i)
        assert _shortened(row) and bytes(row.seal_nonce) != nonces[i]
    assert env.get(old[0]).details == {"n": 1}
    assert env.get(old[0]).recorded == {"ip": "203.0.113.0/24", "details": {"client_ip": "198.51.100.0/24"}}
    assert env.get(young).ip_address == "203.0.113.9" and bytes(env.get(young).seal_nonce) == nonces[young]
    assert bytes(env.get(already).seal_nonce) == nonces[already]
    seals = env.rewrite_seals()
    assert len(seals) == 2 and {s.detail["reason"] for s in seals} == {"shorten-ip"}
    assert all(s.detail["request_seq"] is None and "final" not in s.detail for s in seals)
    for s in seals:
        for h in s.detail["hours"]:
            assert (bytes.fromhex(h[4]), bytes.fromhex(h[6])) == stable[fmt.parse_time_text(h[0])]
    with env.session() as db:
        pruned = [r for r in db.query(AuditLog).filter(AuditLog.action == "retention_pruned").all()
                  if (r.details or {}).get("job") == "audit_ip_shortening"]
    assert sum(r.details.get("cleared", 0) for r in pruned) == 3
    report = env.verify()
    assert failures(report) == [], report.findings
    # Nothing more to do: no seal. The young row's turn comes once it is old enough.
    count = len(env.seals())
    env.passes(6)
    assert len(env.rewrite_seals()) == 2 and all(s.kind != "rewrite" for s in env.seals()[count:])
    assert until(env, lambda: _shortened(env.get(young)), hours=24 * 3)
    assert failures(env.verify()) == []


def test_each_transaction_reads_the_rows_of_one_day(env30):
    env = env30
    for d in (40, 39, 38):
        for h in (1, 2):
            env.put(T0 - timedelta(days=d, hours=h))
    env.run_until_sealed()
    scope = rw.Scope(rw.SHORTEN, ai.hour_floor(T0 - timedelta(days=30)), rw.shortened,
                     rw.prefilter(AuditLog, {"ip": "shortened"}))
    with env.session() as db:
        first = rw._next_hot_hours(db, scope, rw._EPOCH)
        assert first == [ai.hour_floor(T0 - timedelta(days=40, hours=2)), ai.hour_floor(T0 - timedelta(days=40, hours=1))]
        assert rw._next_hot_hours(db, scope, first[-1] + timedelta(hours=1)) == [
            ai.hour_floor(T0 - timedelta(days=39, hours=2)), ai.hour_floor(T0 - timedelta(days=39, hours=1))]
        assert rw._next_hot_hours(db, scope, scope.before) == []


def test_an_hour_that_does_not_check_out_is_reported_and_the_others_are_shortened(env30):
    env = env30
    bad = env.put(T0 - timedelta(days=40))
    good = env.put(T0 - timedelta(days=39))
    env.run_until_sealed()
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == bad).update({AuditLog.username: "mallory"})
        db.commit()
    env.passes(6)
    assert env.get(bad).ip_address == "203.0.113.9" and _shortened(env.get(good))
    assert "rows-altered" in ((env.st.head_store().load() or {}).get("failures") or {})


def test_an_hour_that_does_not_check_out_after_one_shortened_the_same_day_leaves_that_one_sealed(env30):
    """The hours of one day go in one transaction: an hour that does not check out after one already shortened in
    it leaves that one shortened under its rewrite seal, and is reported."""
    env = env30
    day = (T0 - timedelta(days=40)).date()
    good = env.put(datetime.combine(day, time(3, 5)))
    bad = env.put(datetime.combine(day, time(4, 5)))
    env.run_until_sealed()
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == bad).update({AuditLog.username: "mallory"})
        db.commit()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert _shortened(env.get(good)) and env.get(bad).ip_address == "203.0.113.9"
    assert [[e[0] for e in s.detail["hours"]] for s in env.rewrite_seals()] == [
        [fmt.hour_text(datetime.combine(day, time(3)))]]
    assert "rows-altered" in ((env.st.head_store().load() or {}).get("failures") or {})


def test_a_transaction_never_takes_the_hours_of_two_days(env30, monkeypatch):
    """A rewrite seal covers hours of one day (verify holds every rewrite seal to that): handed hours that run into
    the next day, a transaction stops at the end of the first and the next one takes the rest."""
    env = env30
    days = [(T0 - timedelta(days=d)).date() for d in (41, 40)]
    rows = [env.put(datetime.combine(d, time(h, 5))) for d in days for h in (3, 22)]
    env.run_until_sealed()
    hours = sorted(ai.hour_floor(env.get(r).timestamp) for r in rows)
    monkeypatch.setattr(rw, "_next_hot_hours", lambda db, scope, cursor, limit=48: [h for h in hours if h >= cursor])
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert [sorted({fmt.parse_time_text(e[0]).date() for e in s.detail["hours"]}) for s in env.rewrite_seals()] == [
        [days[0]], [days[1]]]
    assert all(_shortened(env.get(r)) for r in rows)
    assert failures(env.verify()) == []


DAY = (T0 - timedelta(days=100)).date()


def test_archived_days_are_shortened_in_their_blocks(env30):
    env = env30
    ids = [env.put(datetime.combine(DAY, time(3, 5))), env.put(datetime.combine(DAY, time(3, 15)), seal_nonce=None),
           env.put(datetime.combine(DAY, time(7, 5)), ip_address=None)]
    env.run_until_sealed()
    nonces = {i: env.get(i).seal_nonce for i in ids}
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditArchiveBlock).count() == 1
        assert db.query(AuditLog).filter(AuditLog.id.in_(ids)).count() == 0
    env.passes(6)
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        part = env.st.view.archives[block.day].parts[0]
        rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day, part).rows()}
    for i in ids[:2]:
        assert rows[i]["ip_address"] is None and json.loads(rows[i]["recorded"]) == {"ip": "203.0.113.0/24"}
        assert rows[i]["seal_nonce"] is not None and rows[i]["seal_nonce"] != nonces[i]     # a fresh one
    assert rows[ids[2]]["recorded"] is None and rows[ids[2]]["seal_nonce"] == bytes(nonces[ids[2]])
    seal = env.rewrite_seals()[0]
    after = next(s for s in env.seals() if s.seq == seal.seq + 1)
    assert after.kind == "archive" and after.detail["cause"] == "rewrite" and after.detail["after_seq"] == seal.seq
    report = env.verify()
    assert failures(report) == [], report.findings


def test_an_archived_day_with_nothing_to_shorten_is_passed_over_and_the_rows_after_it_are_reached(env30):
    env = env30
    env.put(datetime.combine(DAY, time(3, 5)), ip_address=None)
    row = env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        payload = db.query(AuditArchiveBlock).one().payload
    assert env.get(row) is not None
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert _shortened(env.get(row))
    with env.session() as db:
        assert db.query(AuditArchiveBlock).one().payload == payload
    assert [[e[0] for e in s.detail["hours"]] for s in env.rewrite_seals()] == [
        [fmt.hour_text(ai.hour_floor(T0 - timedelta(days=40)))]]
    assert failures(env.verify()) == []


def _change(env, actor, value):
    with ps.change_transaction(env.engine) as w:
        return ps.change(w, rw.FULL_DAYS_KEY, value, actor, now=env.clock())


def test_setting_a_number_waits_the_delay_and_no_limit_again_applies_at_once(env):
    old = env.put(T0 - timedelta(days=60))
    fresh = env.put(T0 - timedelta(days=20))
    env.run_until_sealed()
    ada = env.admin("ada")
    assert _change(env, ada, 30).status == "pending"
    env.passes(24 * 6)
    assert env.get(old).ip_address == "203.0.113.9" and env.rewrite_seals() == []
    assert until(env, lambda: _shortened(env.get(old)), hours=24 * 3)
    assert env.get(fresh).ip_address == "203.0.113.9"
    # No limit again keeps more: it applies at once, and the row that has meanwhile grown old enough stays full.
    assert _change(env, ada, 0).status == "applied"
    env.passes(24 * 5)
    assert env.clock() - (T0 - timedelta(days=20)) > timedelta(days=31)
    assert env.get(fresh).ip_address == "203.0.113.9"
    assert failures(env.verify()) == []


class _Seal:
    def __init__(self, seq, detail, sealed_at):
        self.seq, self.kind, self.detail, self.sealed_at = seq, "rewrite", detail, sealed_at


def test_verify_refuses_a_shortening_out_of_its_setting(env30):
    env30.run_until_sealed()
    view = env30.st.view
    at = env30.clock()
    old = fmt.hour_text(ai.hour_floor(at - timedelta(days=31)))
    young = fmt.hour_text(ai.hour_floor(at - timedelta(days=30)))
    good = {"reason": "shorten-ip", "policy_seq": view.newest_policy()[0], "request_seq": None, "hours": [[old]]}
    assert rw.rewrite_problem(view, _Seal(view.position + 1, good, at)) is None
    assert "younger" in rw.rewrite_problem(view, _Seal(view.position + 1, dict(good, hours=[[young]]), at))
    assert "naming a request" in rw.rewrite_problem(view, _Seal(view.position + 1, dict(good, request_seq=3), at))
    assert "naming a request" in rw.rewrite_problem(view, _Seal(view.position + 1, dict(good, final=True), at))
    assert "no hours" in rw.rewrite_problem(view, _Seal(view.position + 1, dict(good, hours=[]), at))


def test_verify_refuses_a_shortening_while_there_is_no_limit(env):
    env.run_until_sealed()
    view = env.st.view
    at = env.clock()
    detail = {"reason": "shorten-ip", "policy_seq": view.newest_policy()[0], "request_seq": None,
              "hours": [[fmt.hour_text(ai.hour_floor(at - timedelta(days=400)))]]}
    assert "no limit" in rw.rewrite_problem(view, _Seal(view.position + 1, detail, at))


def test_the_setting_is_a_chain_setting_kept_in_step_with_env_example_the_host_tool_and_the_docs():
    spec = reg.spec_for(rw.FULL_DAYS_KEY)
    assert spec.reduction == reg.LOWER and spec.unlimited == 0 and spec.editable == reg.ADMIN
    assert rw.FULL_DAYS_KEY in pol.chain_setting_keys()
    assert reg.is_reduction(spec, 0, 30) and reg.is_reduction(spec, 30, 7)
    assert not reg.is_reduction(spec, 30, 0) and not reg.is_reduction(spec, 7, 30)
    from app.core.config import Settings
    assert Settings.model_fields["audit_ip_full_days"].default == 0
    assert "# AUDIT_IP_FULL_DAYS=0" in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    import dockvault
    assert ("audit_ip_full_days", "AUDIT_IP_FULL_DAYS", "0") in dockvault.RETENTION_ENV_KEYS
    assert "`AUDIT_IP_FULL_DAYS`" in (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")


def test_an_archived_day_the_days_reach_into_is_shortened_only_before_them(monkeypatch, tmp_path):
    env = _env(monkeypatch, tmp_path, 100)
    try:
        cut = ai.hour_floor(T0 - timedelta(days=100))
        early, late = env.put(cut - timedelta(hours=3)), env.put(cut + timedelta(hours=3))
        env.run_until_sealed()
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
        with env.session() as db:
            assert db.query(AuditLog).filter(AuditLog.id.in_([early, late])).count() == 0
        rw.shorten_job(retention.Pass(env.session, now=env.clock()))
        with env.session() as db:
            block = db.query(AuditArchiveBlock).one()
            part = env.st.view.archives[block.day].parts[0]
            rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day, part).rows()}
        assert rows[early]["ip_address"] is None and rows[late]["ip_address"] == "203.0.113.9"
        assert failures(env.verify()) == []
    finally:
        env.close()


def test_a_transaction_stops_at_the_batch_and_the_rest_follows(env30):
    env = env30
    first = env.put(T0 - timedelta(days=40, hours=2))
    second = env.put(T0 - timedelta(days=40, hours=1))
    env.run_until_sealed()
    p = retention.Pass(env.session, now=env.clock(), batch_rows=1)
    rw.shorten_job(p)
    seals = env.rewrite_seals()
    assert [len(s.detail["hours"]) for s in seals] == [1, 1]
    assert _shortened(env.get(first)) and _shortened(env.get(second))
    assert failures(env.verify()) == []


def test_an_hour_the_prefilter_takes_but_with_nothing_to_shorten_is_passed_over(env30):
    env = env30
    nothing = env.put(T0 - timedelta(days=41), ip_address=None, details={"client_ip": None})
    real = env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    nonce = bytes(env.get(nothing).seal_nonce)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert _shortened(env.get(real)) and bytes(env.get(nothing).seal_nonce) == nonce
    assert [len(s.detail["hours"]) for s in env.rewrite_seals()] == [1]


def test_a_rewrite_that_would_change_more_than_the_values_writes_nothing(env30, monkeypatch):
    env = env30
    row = env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    before = len(env.seals())
    real = rw._write_row

    def also_the_action(db, row_id, new, nonce):
        real(db, row_id, new, nonce)
        db.query(AuditLog).filter(AuditLog.id == row_id).update({AuditLog.action: "file_deleted"},
                                                                synchronize_session=False)
    monkeypatch.setattr(rw, "_write_row", also_the_action)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row).ip_address == "203.0.113.9" and env.get(row).action == "file_uploaded"
    assert len(env.seals()) == before
    assert "rows-altered" in ((env.st.head_store().load() or {}).get("failures") or {})
    monkeypatch.setattr(rw, "_write_row", lambda db, row_id, new, nonce: None)
    rw._cursors.clear()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row).ip_address == "203.0.113.9" and len(env.seals()) == before
    assert "unjustified" in ((env.st.head_store().load() or {}).get("failures") or {})


def test_once_done_a_pass_reads_only_what_has_aged_since(env30, monkeypatch):
    env = env30
    env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    key = next(iter(rw._cursors))
    assert rw._cursors[key] == ai.hour_floor(env.clock() - timedelta(days=30))
    seen = []
    real = rw.step
    monkeypatch.setattr(rw, "step", lambda p, w, scope, cursor: seen.append(cursor) or real(p, w, scope, cursor))
    env.clock.advance(hours=6)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert seen == [ai.hour_floor(T0 - timedelta(days=30))]


def test_a_legal_hold_or_a_restore_s_grace_holds_the_shortening(env30, monkeypatch):
    """A registered rule (legal holds, open cases) and the grace after a restore each hold the shortening: nothing is
    shortened while one holds, and it goes on once neither does."""
    env = env30
    row = env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    monkeypatch.setattr(pe, "WAIT_RULES", [lambda db, now: "a legal hold is in force"])
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row).ip_address == "203.0.113.9" and env.rewrite_seals() == []
    monkeypatch.setattr(pe, "WAIT_RULES", [])
    real = type(env.st).holds_deletion
    monkeypatch.setattr(type(env.st), "holds_deletion", lambda self: "the grace after a restore runs until later")
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row).ip_address == "203.0.113.9" and env.rewrite_seals() == []
    monkeypatch.setattr(type(env.st), "holds_deletion", real)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert _shortened(env.get(row)) and len(env.rewrite_seals()) == 1


def test_an_hour_another_writer_sealed_waits_for_the_host(env30, monkeypatch):
    """An hour whose seal another writer appended and the host has not acknowledged is left as it is, and the run
    waits there (its rows may have been edited and sealed over); once acknowledged, it goes on."""
    env = env30
    held_row, later = env.put(T0 - timedelta(days=40)), env.put(T0 - timedelta(days=35))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(days=40))
    real = ai.hour_held
    monkeypatch.setattr(ai, "hour_held", lambda view, record, h: 77 if h == hour else real(view, record, h))
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(held_row).ip_address == "203.0.113.9" and env.get(later).ip_address == "203.0.113.9"
    assert env.rewrite_seals() == []
    monkeypatch.setattr(ai, "hour_held", real)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert _shortened(env.get(held_row)) and _shortened(env.get(later))


def test_an_archived_rewrite_that_would_change_more_than_the_values_writes_nothing(env30, monkeypatch):
    env = env30
    row = env.put(datetime.combine(DAY, time(3, 5)))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        before = db.query(AuditArchiveBlock).one().payload
    seals = len(env.seals())
    real = rw.shortened
    monkeypatch.setattr(rw, "shortened", lambda r: dict(real(r) or {}, action="file_deleted") if real(r) else None)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditArchiveBlock).one().payload == before
    assert len(env.seals()) == seals
    assert "rows-altered" in ((env.st.head_store().load() or {}).get("failures") or {})
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- archived days, and the edges of the days

class _Steps(retention.Pass):
    """A pass with time for ``n`` transactions of a job, so that a run can be taken a unit at a time."""

    def __init__(self, env, n=1):
        super().__init__(env.session, now=env.clock())
        self.left = n

    def time_left(self):
        self.left -= 1
        return self.left >= 0


def _at(hour, minute=0):
    return datetime.combine(DAY, time(hour, minute))


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
        assert db.query(AuditLog).filter(AuditLog.id.in_(late)).count() == 3
    return early, late


def _addresses(env):
    """{id: ip_address} of every row, as rows and in the archived days' blocks."""
    out = {}
    with env.session() as db:
        for r in db.query(AuditLog).all():
            out[r.id] = r.ip_address
        for day, entry in env.st.view.archives.items():
            for part in entry.parts:
                for r in arc.PartReader(db, env.st.view, day, part).rows():
                    out[r["id"]] = r["ip_address"]
    return out


def test_a_day_archived_in_part_is_shortened_in_its_block_and_in_the_hours_still_held_as_rows(env30, monkeypatch):
    env = env30
    early, late = _half_archived(env, monkeypatch)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    addresses = _addresses(env)
    assert [i for i in early + late if addresses[i] is not None] == []
    assert [[e[0] for e in s.detail["hours"]] for s in env.rewrite_seals()] == [
        [fmt.hour_text(_at(2))], [fmt.hour_text(_at(9))]]
    assert failures(env.verify()) == []


def test_the_archive_finishing_a_day_between_two_shortening_steps_has_the_day_taken_again(env30, monkeypatch):
    """The archive job archives a day's later hours after the shortening rewrote its first block, in the same
    process: the day is taken again for them, and every address of it is shortened."""
    env = env30
    early, late = _half_archived(env, monkeypatch)
    rw.shorten_job(_Steps(env, 1))
    addresses = _addresses(env)
    assert [addresses[i] for i in early] == [None] * 3 and [addresses[i] for i in late] == ["203.0.113.9"] * 3
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(late)).count() == 0
    env.clock.advance(hours=1)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    addresses = _addresses(env)
    assert [i for i in early + late if addresses[i] is not None] == []
    assert failures(env.verify()) == []


def test_rows_left_in_an_archived_hour_are_reported_and_the_rows_after_the_day_are_shortened(env30, monkeypatch):
    """A row of audit_logs in an hour a block holds (no path of the app writes one there): the day is reported
    (row-in-archived-day) and left as it is, and the shortening goes on after it."""
    env = env30
    kept = env.put(_at(3, 5))
    after = env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    stray = env.put(_at(3, 30))
    with env.session() as db:
        payload = db.query(AuditArchiveBlock).one().payload
    seen = {}
    monkeypatch.setattr(ai, "report_failures", lambda st, f, found, *a, **k: seen.update(found))
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert f"nothing in {DAY.isoformat()} was rewritten; its addresses were not shortened" in seen.get(
        "row-in-archived-day", "")
    with env.session() as db:
        assert db.query(AuditArchiveBlock).one().payload == payload
    addresses = _addresses(env)
    assert addresses[kept] == "203.0.113.9" and addresses[stray] == "203.0.113.9"
    assert _shortened(env.get(after))
