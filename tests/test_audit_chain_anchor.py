"""A head kept outside the server, checked with and without the key (app/core/audit_chain_verify.py), offline:

- without the key, a matching anchor authenticates every seal up to it, and a later prune that changes an hour
  the anchor covered is a warning, "not authenticated"; a prune of hours sealed after the anchor is not; with
  the key, or against a later anchor, nothing is reported;
- after a restore, an anchor whose seal the restore lost is reported against the restore seal (information
  when this check verified that seal, a warning off the server without the key); an anchor on a seal the
  restore kept, or at the lost head with another link, is still anchor-mismatch; a chain rewritten from some
  seal loses everything after its last matching recorded link; a whole backup restored loses the replaced
  record's seals after the bundle's chain.

Runs on a throwaway SQLite database (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_restore as restore
from app.core.models import AuditLog
from test_audit_chain_guards import _forge, _off
from test_audit_chain_restore import _accept, _cut_from, _host, _restore_bundle, _sealed_day, _snapshot
from test_audit_chain_trust import _run_to

pytestmark = pytest.mark.unit

KB = 1024


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


@pytest.fixture
def capped(monkeypatch, tmp_path):
    """A chain whose size cap (1 MB) prunes once a delay has passed."""
    e = Env(monkeypatch, tmp_path, audit_log_max_mb=1)
    monkeypatch.setenv("AUDIT_LOG_MAX_MB", "1")
    yield e
    e.close()


def _found(report, kind):
    return [f for f in report.findings if f.kind == kind]


def _pruned_after_the_anchor(env):
    """Rows over the cap, sealed; the head then (the anchor); the size cap's prune after the delay."""
    old = [env.row(T0 - timedelta(days=30, hours=h), details={"blob": "x" * (500 * KB)}) for h in range(3)]
    env.run_until_sealed()
    anchor = env.verify().head
    _run_to(env, T0 + timedelta(days=8, hours=2))
    prunes = [s for s in env.seals() if s.kind == "prune"]
    with env.session() as db:
        assert prunes and db.query(AuditLog).filter(AuditLog.id.in_(old)).count() < len(old)
    return anchor, prunes


def test_without_the_key_a_prune_of_an_hour_the_anchor_covered_is_not_authenticated(capped):
    anchor, prunes = _pruned_after_the_anchor(capped)
    report = _off(capped, anchor=anchor)
    assert "anchor-mismatch" not in failures(report)
    warned = {(f.seq, f.hour) for f in _found(report, "changed-after-anchor")}
    assert warned == {(p.seq, h[0]) for p in prunes for h in p.detail["hours"]}
    assert all(f.severity == "warning" and "not authenticated" in f.message
               for f in _found(report, "changed-after-anchor"))
    assert report.exit_code == 1
    # The key, or a head kept after the prune, authenticates it.
    assert _found(capped.verify(anchor=anchor), "changed-after-anchor") == []
    assert _found(_off(capped, anchor=capped.verify().head), "changed-after-anchor") == []
    # An anchor that does not match covers nothing: the mismatch is the finding.
    other = fmt.head(fmt.parse_head(anchor)[0], b"\1" * 32)
    assert _found(_off(capped, anchor=other), "changed-after-anchor") == []


def test_a_prune_of_hours_sealed_after_the_anchor_is_not_reported(capped):
    _anchor, prunes = _pruned_after_the_anchor(capped)
    early = fmt.head(2, capped.st.view.link_at(2))           # genesis and its policy seal: no hour yet
    report = _off(capped, anchor=early)
    assert "anchor-mismatch" not in failures(report)
    assert _found(report, "changed-after-anchor") == []


def test_a_matching_anchor_authenticates_every_seal_up_to_it(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    position = env.st.view.position
    unchecked = _found(_off(env), "not-checked")
    assert unchecked and f"{position} seals" in unchecked[0].message
    assert _found(_off(env, anchor=env.verify().head), "not-checked") == []
    early = fmt.head(2, env.st.view.link_at(2))
    assert f"{position - 2} seals" in _found(_off(env, anchor=early), "not-checked")[0].message
    # An anchor that does not match authenticates nothing.
    assert f"{position} seals" in _found(_off(env, anchor=fmt.head(2, b"\1" * 32)), "not-checked")[0].message


def _cut_and_accepted(env):
    _sealed_day(env)
    anchor = env.verify().head
    newest = env.seals()[-1].seq
    _cut_from(env, newest - 3)
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    _accept(env)
    env.clock.advance(hours=3)
    env.seal()                                           # new seals over the lost seqs
    rseq = [s for s in env.seals() if s.kind == "restore"][-1].seq
    return anchor, newest, rseq


def test_an_anchor_a_restore_lost_is_reported_against_the_restore_seal(env):
    anchor, newest, rseq = _cut_and_accepted(env)
    report = env.verify(anchor=anchor)
    assert "anchor-mismatch" not in failures(report)
    lost = _found(report, "anchor-lost")
    assert [(f.severity, f.seq) for f in lost] == [("information", rseq)]
    assert f"lost seals {newest - 3}-{newest}" in lost[0].message
    # Off the server, without the key, the restore seal itself is not authenticated.
    off = _found(_off(env, anchor=anchor), "anchor-lost")
    assert [(f.severity, f.seq) for f in off] == [("warning", rseq)] and "not authenticated" in off[0].message


def test_an_anchor_the_restore_did_not_lose_must_still_match(env):
    _anchor, newest, rseq = _cut_and_accepted(env)
    kept = newest - 5
    assert "anchor-mismatch" in failures(env.verify(anchor=fmt.head(kept, b"\1" * 32)))
    # At the lost head, the restore seal names the head it lost: another link is not explained by it.
    assert "anchor-mismatch" in failures(env.verify(anchor=fmt.head(newest, b"\1" * 32)))
    # Past the lost range.
    far = env.st.view.position + 5
    assert "anchor-mismatch" in failures(env.verify(anchor=fmt.head(far, b"\1" * 32)))


def test_a_rewritten_chain_loses_everything_after_its_last_matching_recorded_link(env):
    _sealed_day(env)
    hour_seal = [s for s in env.seals() if s.kind == "hour" and s.row_count][-1].seq
    rewritten = fmt.head(hour_seal, env.st.view.link_at(hour_seal))
    _cut_from(env, hour_seal)
    _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                        "user_id": None, "request": None})     # another seal in its place, under the key in force
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    record = env.st.head_store().load()
    seen = restore.accept_database_head(env.engine, _host(env), read=True)
    restore.accept_database_head(env.engine, _host(env), expect=seen["state"], confirm=seen["confirm"])
    seal = [s for s in env.seals() if s.kind == "restore"][-1]
    assert seal.detail["lost_from_seq"] <= hour_seal and seal.detail["lost_through_seq"] == int(record["seq"])
    assert seal.detail["lost_head"] == fmt.head(int(record["seq"]), bytes.fromhex(record["link"]))
    report = env.verify(anchor=rewritten)
    assert "anchor-mismatch" not in failures(report) and _found(report, "anchor-lost")


def test_a_whole_backup_restore_of_the_current_state_names_no_lost_seal(env):
    env.row(T0 - timedelta(hours=10))
    env.run_until_sealed()
    snap = _snapshot(env)
    _restore_bundle(env, snap)
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    seal = [s for s in env.seals() if s.kind == "restore"][-1]
    assert (seal.detail["lost_from_seq"], seal.detail["lost_through_seq"]) == (None, None)
    assert seal.detail["lost_head"] == fmt.head(int(snap[1]["seq"]), bytes.fromhex(snap[1]["link"]))
    assert "no seal it could name lost" in _found(env.verify(), "restored")[0].message


def test_an_anchor_a_whole_backup_restore_lost_is_reported_against_its_restore_seal(env):
    env.row(T0 - timedelta(hours=10))
    env.run_until_sealed()
    snap = _snapshot(env)
    bundle_head = env.st.view.position
    env.row(T0 - timedelta(minutes=50))
    _run_to(env, T0 + timedelta(hours=8))
    anchor = env.verify().head
    replaced = env.st.head_store().load()
    _restore_bundle(env, snap)
    env.clock.advance(hours=1)
    env.seal()
    seen = restore.accept_restore(env.engine, _host(env), read=True)
    restore.accept_restore(env.engine, _host(env), expect=seen["state"])
    seal = [s for s in env.seals() if s.kind == "restore"][-1]
    assert seal.detail["lost_from_seq"] <= bundle_head + 1
    assert seal.detail["lost_through_seq"] == int(replaced["seq"])
    report = env.verify(anchor=anchor)
    assert "anchor-mismatch" not in failures(report)
    assert [f.seq for f in _found(report, "anchor-lost")] == [seal.seq]

