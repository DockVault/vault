"""An erased row is checked against its erase seal by every path that checks an hour before it re-roots it.

An erased row counts in its hour's roots by its commitment before the erase (the seal's c_prev), so the roots alone
cannot tell an edit of it: only a comparison with what the erase seal says it wrote (the placeholder, and values
whose commitment under a zero nonce is c_next) can. audit verify and the block reader make it; so must every path
that would otherwise seal over the row as it is now, or verify would be clean afterwards with the edit kept:

- the audit job's prune of an hour (and a second erase in it), which re-roots the hour over the rows it keeps;
- the sealer's late seal of rows that arrived within the late window;
- the host's late-rows command;
- the host's acknowledgment of a rollback's removal, which also must accept an hour an erase changed.

Offline, on a throwaway SQLite database with a chain of its own (tests/_erase_env.py, tests/_audit_chain_env.py).
"""
import uuid
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from _erase_env import EraseEnv
from app.core import audit_archive as arc
from app.core import audit_chain_external as external
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_integrity as ai
from app.core import person_erase as pe
from app.core import retention
from app.core.models import AuditLog, AuditSeal
from test_audit_integrity_events import _request_erase, _run_erase

pytestmark = pytest.mark.unit

EDITS = [{"username": "eve"}, {"details": {"forged": "by the database"}}, {"ip_address": "198.51.100.1"}]


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Archiving far off: the rows stay rows."""
    e = EraseEnv(monkeypatch, tmp_path, audit_archive_start_after_days=1000)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _put(env, when, username="eve", **values):
    row = dict(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=when, username=username,
               ip_address="203.0.113.9", user_agent="Mozilla/5.0 test", endpoint="/vaults/{vault_id}/files",
               details={"n": 1}, seal_nonce=uuid.uuid4().bytes)
    row.update(values)
    with env.session() as db:
        db.add(AuditLog(**row))
        db.commit()
    return row["id"]


def _row(env, rid):
    with env.session() as db:
        return db.get(AuditLog, rid)


def _edit(env, rid, **values):
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == rid).update(values, synchronize_session=False)
        db.commit()


def _erased(env, name="eve"):
    """Ask for an erase of ``name``, let its delay run, and return the request once it has completed."""
    asked = env.ask(name)
    env.passes(24 * 7 + 6)
    assert env.request_row(asked["id"]).status == pe.COMPLETED
    return asked


def _recorded_failures(env):
    return sorted((env.st.head_store().load() or {}).get("failures") or {})


# --------------------------------------------------------------------------- the audit job's prune of an hour

def _partly_pruned_hour(env, monkeypatch, edit):
    """An hour with eve's administration row (kept by its floor once erased) and alice's row, eve erased; then, if
    ``edit``, eve's erased row edited in the database; then the audit job with a retention that takes alice's."""
    at = T0 - timedelta(days=40)
    erased = _put(env, at + timedelta(minutes=5), action="settings_updated")
    plain = _put(env, at + timedelta(minutes=15), username="alice")
    env.run_until_sealed()
    asked = _erased(env)
    assert _row(env, erased).username == asked["placeholder"] and failures(env.verify()) == []
    if edit:
        _edit(env, erased, **edit)
        assert "unjustified" in failures(env.verify())
    monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "30")
    env.settings.audit_log_retention_days = 30
    env.clock.advance(minutes=30)
    retention.run_pass(env.session, now=env.clock())
    return erased, plain


@pytest.mark.parametrize("edit", EDITS, ids=["the name back", "forged details", "an address"])
def test_the_audit_job_does_not_prune_an_hour_whose_erased_row_was_edited(env, monkeypatch, edit):
    erased, plain = _partly_pruned_hour(env, monkeypatch, edit)
    assert _row(env, plain) is not None, "the hour was pruned over an edited erased row"
    assert [s for s in env.seals() if s.kind == "prune"] == []
    assert "unjustified" in _recorded_failures(env)
    assert "unjustified" in failures(env.verify())          # still found: nothing sealed over it


def test_the_audit_job_prunes_an_erased_hour_left_as_the_erase_wrote_it(env, monkeypatch):
    erased, plain = _partly_pruned_hour(env, monkeypatch, None)
    assert _row(env, plain) is None and _row(env, erased) is not None
    assert len([s for s in env.seals() if s.kind == "prune"]) == 1
    assert failures(env.verify()) == []


def test_a_second_erase_in_an_hour_whose_erased_row_was_edited_changes_nothing(env):
    at = T0 - timedelta(days=40)
    eve = _put(env, at + timedelta(minutes=5))
    mallory = _put(env, at + timedelta(minutes=15), username="mallory")
    env.run_until_sealed()
    _erased(env)
    seals = len(env.erase_seals())
    _edit(env, eve, ip_address="198.51.100.1")
    asked = env.ask("mallory")
    env.passes(24 * 7 + 6)
    assert _row(env, mallory).username == "mallory" and _row(env, mallory).ip_address == "203.0.113.9"
    assert len(env.erase_seals()) == seals
    assert env.request_row(asked["id"]).status == pe.PENDING
    assert "unjustified" in _recorded_failures(env)
    assert "unjustified" in failures(env.verify())


# --------------------------------------------------------------------------- the sealer's late seal

@pytest.mark.parametrize("edited", [True, False], ids=["edited", "as erased"])
def test_the_sealers_late_seal_does_not_seal_over_an_edited_erased_row(env, edited):
    """The erase reaches an hour whose root seal is less than six hours old; a row then arrives late in it."""
    _put(env, T0 - timedelta(hours=30), username="alice")
    env.run_until_sealed()
    asked = env.ask("eve")
    not_before = fmt.parse_time_text(env.view().requests[asked["request_seq"]]["not_before"])
    while env.clock() < not_before - timedelta(hours=3):
        env.clock.advance(hours=1)
        env.seal()
    rid = _put(env, env.clock() - timedelta(minutes=10))
    hour = ai.hour_floor(env.clock() - timedelta(minutes=10))
    while env.clock() < not_before + timedelta(minutes=30):
        env.clock.advance(hours=1)
        env.seal()
    entry = env.view().entry_for(hour)
    assert entry is not None
    env.erase_job()
    assert _row(env, rid).username == asked["placeholder"]
    assert env.clock() - entry.root.sealed_at < ai.LATE_WINDOW
    if edited:
        _edit(env, rid, username="eve")
    _put(env, hour + timedelta(minutes=50), username="alice")
    env.clock.advance(minutes=10)
    env.seal()
    lates = [s for s in env.seals() if s.kind == "late" and s.detail.get("hour") == fmt.hour_text(hour)]
    if edited:
        assert lates == [], "the late seal sealed over an edited erased row"
        assert "unjustified" in failures(env.verify())
    else:
        assert len(lates) == 1 and lates[0].detail["by"] == "sealer"
        assert failures(env.verify()) == []


# --------------------------------------------------------------------------- the host's late-rows command

@pytest.mark.parametrize("edited", [True, False], ids=["edited", "as erased"])
def test_the_hosts_late_rows_command_refuses_an_hour_whose_erased_row_was_edited(env, edited):
    at = T0 - timedelta(days=40)
    erased = _put(env, at + timedelta(minutes=5))
    env.run_until_sealed()
    _erased(env)
    if edited:
        _edit(env, erased, username="eve")
    added = _put(env, at + timedelta(minutes=50), username="alice")
    hour = ai.hour_floor(at)
    if edited:
        with pytest.raises(host.Refused) as why:
            host.seal_late_rows(env.engine, env.st, hour, read=True)
        assert "is not what its erase seal says" in str(why.value)
        assert "unjustified" in failures(env.verify())
        return
    plan = host.seal_late_rows(env.engine, env.st, hour, read=True)
    assert any(str(added) in ln for ln in plan["lines"])
    host.seal_late_rows(env.engine, env.st, hour, expect=plan["state"])
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- a rollback's removal

def _host(env):
    st = ai.ChainState(settings=env.settings, clock=env.clock)
    st.process_kind = "host"
    return st


def _rolled_back_after_an_erase(env, eve_at, *, cut=None, edit=None, others=()):
    """Rows over four days and eve's row at ``eve_at``, sealed; eve's row erased; then 0.33.x runs for two days and
    deletes every row before ``cut`` (by default 41 days before then); then 0.34.x again. With ``edit``, eve's erased
    row is then edited in the database. Returns (eve's row, the cut)."""
    for d in range(4):
        for h in (3, 9, 15):
            env.row(T0 - timedelta(days=33 - d, hours=h))
    for when in others:
        env.row(when)
    eve = env.row(eve_at, username="eve")
    env.run_until_sealed()
    req, placeholder = _request_erase(env)
    for _ in range(30):
        env.clock.advance(hours=6)
        env.seal()
    _run_erase(env, req, placeholder, ai.hour_floor(eve_at), [eve])
    assert failures(env.verify()) == []
    env.clock.advance(days=2)                            # the older release ran, and pruned by time
    cut = cut or env.clock() - timedelta(days=41)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.timestamp < cut, AuditLog.action == "file_uploaded").delete()
        db.commit()
    if edit:
        with env.session() as db:
            db.query(AuditLog).filter(AuditLog.id == eve).update(edit, synchronize_session=False)
            db.commit()
    env.seal()
    assert "rows-missing" in failures(env.verify())
    return eve, cut


def _first_kept(env, cut):
    with env.session() as db:
        return db.query(AuditLog.timestamp).filter(AuditLog.timestamp >= cut).order_by(AuditLog.timestamp).first()[0]


@pytest.fixture
def plain(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def test_a_rollbacks_removal_is_acknowledged_after_an_erase_in_a_later_hour(plain):
    env = plain
    _eve, cut = _rolled_back_after_an_erase(env, T0 - timedelta(hours=8, minutes=5))
    before = _first_kept(env, cut)
    seen = external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=41, read=True)
    done = external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=41,
                                               expect=seen["state"])
    assert done["sealed"]
    report = env.verify()
    assert failures(report) == [], report.findings


def test_a_rollbacks_removal_re_roots_a_cutoff_hour_with_an_erased_row_and_verify_is_clean(plain):
    env = plain
    cutoff = ai.hour_floor(T0 - timedelta(days=31))
    eve, cut = _rolled_back_after_an_erase(env, cutoff + timedelta(minutes=40), cut=cutoff + timedelta(minutes=20),
                                           others=[cutoff + timedelta(minutes=10)])
    seen = external.acknowledge_removed_before(env.engine, _host(env), cut, retention_days=40, read=True)
    external.acknowledge_removed_before(env.engine, _host(env), cut, retention_days=40, expect=seen["state"])
    assert failures(env.verify()) == []
    _edit(env, eve, ip_address="198.51.100.1")
    assert failures(env.verify()), "an edit after the new roots must be found against them"


@pytest.mark.parametrize("where", ["after the cutoff hour", "in the cutoff hour"])
def test_a_rollbacks_removal_is_refused_when_an_erased_row_was_edited(plain, where):
    env = plain
    edit = {"username": "eve"}
    if where == "in the cutoff hour":
        cutoff = ai.hour_floor(T0 - timedelta(days=31))
        _eve, cut = _rolled_back_after_an_erase(env, cutoff + timedelta(minutes=40), cut=cutoff + timedelta(minutes=20),
                                                others=[cutoff + timedelta(minutes=10)], edit=edit)
        before, days = cut, 40
    else:
        _eve, cut = _rolled_back_after_an_erase(env, T0 - timedelta(hours=8, minutes=5), edit=edit)
        before, days = _first_kept(env, cut), 41
    with pytest.raises(host.Refused) as why:
        external.acknowledge_removed_before(env.engine, _host(env), before, retention_days=days, read=True)
    assert "is not what its erase seal says" in str(why.value)
    assert [s for s in env.seals() if s.kind == "prune"] == []
    assert "unjustified" in failures(env.verify())


# --------------------------------------------------------------------------- the erase seals are read authenticated

def test_an_erase_seal_changed_after_the_process_accepted_it_is_never_used_to_check_its_hour(env):
    """A database writer who edits an erased row and the erase seal's c_next to match: the seal is read again with
    its link checked, so the change stops the check instead of passing it."""
    at = T0 - timedelta(days=40)
    rid = _put(env, at + timedelta(minutes=5))
    env.run_until_sealed()
    _erased(env)
    hour = ai.hour_floor(at)
    _edit(env, rid, ip_address="198.51.100.1")
    with env.session() as db:
        assert ai.check_hour_rows(db, env.st.view, hour, None).altered == [rid]
        row = next(r for r in ai.iter_rows(db, hour, hour + ai.HOUR) if r["id"] == rid)
        seal = db.query(AuditSeal).filter(AuditSeal.kind == "erase").one()
        detail = dict(seal.detail)
        detail["rows"] = [[detail["rows"][0][0], detail["rows"][0][1], fmt.commitment(fmt.ZERO_NONCE, row).hex()]]
        db.query(AuditSeal).filter(AuditSeal.seq == seal.seq).update({AuditSeal.detail: detail},
                                                                    synchronize_session=False)
        db.commit()
    with env.session() as db:
        with pytest.raises(ai.ChainStopped):
            ai.check_hour_rows(db, env.st.view, hour, None)
        with pytest.raises(arc.NotVerified) as nv:
            arc.erase_entries(db, env.st.view, hour)
        assert nv.value.kind == "link-broken"
