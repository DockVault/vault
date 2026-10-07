"""What the head record keeps for the host's restore commands (app/core/audit_integrity.py,
app/core/audit_head_record.py), offline:

- the retention checkpoints: the newest policy seal with the entries where the honoured state differs from it,
  each cancel with the link of the request it cancels;
- the hour summaries of the last 30 days, with the salt of an hour whose rows have no nonce, and, while sealing
  is stopped, the hours that close, computed from their rows and marked unsealed;
- a digest per day older than the summaries (over every hour's figures, and without the personal values'
  root), computed again when a later seal re-roots one of its hours;
- the link of every 64th seal, by generation.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_integrity as ai
from app.core.models import AuditLog, AuditSeal
from test_audit_chain_trust import _admin, _change, _run_to
from test_audit_chain_dates import _applies_of, _admin_reduction_due

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _record(env):
    return env.st.head_store().load()


def test_the_checkpoints_hold_the_newest_policy_seal_and_each_cancel(env):
    env.run_until_sealed()
    admin = _admin(env)
    assert _change(env, admin, "logs_hold", True).status == "applied"
    outcome = _change(env, admin, "audit_max_days", 400)
    req = [s for s in env.seals() if s.kind == "request"][-1].seq
    from app.core import audit_chain_policy_seals as ps
    with ps.change_transaction(env.engine) as w:
        ps.cancel(w, outcome.change.id, admin)
    cancel = [s for s in env.seals() if s.kind == "cancel"][-1].seq
    cp = _record(env)["checkpoints"]
    newest = env.st.view.newest_policy()
    assert cp["policy"]["seq"] == newest[0] and cp["policy"]["link"] == env.st.view.link_at(newest[0]).hex()
    assert cp["policy"]["state"]["logs_hold"]["value"] is True and cp["policy"]["honoured"] == {}
    assert {"generation": 1, "seq": cancel, "request_seq": req,
            "request_link": env.st.view.link_at(req).hex()} in cp["cancels"]


def test_the_checkpoint_keeps_the_honoured_form_of_a_value_another_writer_set(env):
    env.run_until_sealed()
    req = _admin_reduction_due(env, 90)
    _applies_of(env, req, 90)
    env.clock.advance(minutes=30)
    env.seal()
    cp = _record(env)["checkpoints"]["policy"]
    assert cp["state"]["audit_max_days"]["value"] == 90
    assert cp["honoured"]["audit_max_days"]["value"] == 0      # the pruner keeps the log for ever meanwhile


def test_an_hour_of_rows_without_a_nonce_keeps_its_salt_in_its_summary(env):
    env.row(T0 - timedelta(hours=5), nonce=False)
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=5))
    summary = _record(env)["hours"][fmt.hour_text(hour)]
    with env.session() as db:
        wr = ai.working_row(db, hour)
        assert summary["salt"] == bytes(wr.legacy_salt).hex() and summary["unsealed"] is False
        fig = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), bytes.fromhex(summary["salt"]))
    assert fig.root_c.hex() == summary["root_c"] and fig.count == summary["count"] == 1


def test_while_sealing_is_stopped_the_hours_that_close_are_summarised_unsealed(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    newest = env.seals()[-1].seq
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq == newest).delete()
        db.commit()
    later = env.row(T0 + timedelta(minutes=20), nonce=False)
    env.clock.advance(hours=3)
    assert env.seal().stopped == "head-record-mismatch"
    hour = ai.hour_floor(T0 + timedelta(minutes=20))
    summary = _record(env)["hours"][fmt.hour_text(hour)]
    assert summary["unsealed"] is True and summary["seq"] is None and summary["count"] == 1
    with env.session() as db:
        fig = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), None)
    assert (fig.root_s.hex(), fig.root_c.hex(), fig.ids_digest.hex()) == (
        summary["root_s"], summary["root_c"], summary["ids_digest"])
    assert later is not None


def _rows_digest(env, day):
    """The day's digests recomputed from its rows (every hour of it the chain covers)."""
    start = ai.datetime(day.year, day.month, day.day)
    entries = []
    with env.session() as db:
        for i in range(24):
            h = start + i * ai.HOUR
            if h < env.st.view.first_hour():
                continue
            wr = ai.working_row(db, h)
            salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
            fig = ai.hour_figures(ai.iter_rows(db, h, h + ai.HOUR), salt)
            entries.append((h, h + ai.HOUR, fig.count, fig.root_s, fig.root_c, fig.ids_digest))
    return (fmt.day_digest(entries).hex(),
            fmt.day_digest([(a, b, c, rs, None, i) for a, b, c, rs, _rc, i in entries]).hex())


def test_a_day_older_than_the_summaries_keeps_its_digest_and_a_later_prune_updates_it(env, monkeypatch):
    old_day = (T0 - timedelta(days=45)).date()
    ids = [env.row(T0 - timedelta(days=45, hours=h)) for h in (1, 2, 3)]
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=1))
    days = _record(env)["days"]
    assert old_day.isoformat() in days
    full, stable = _rows_digest(env, old_day)
    assert (days[old_day.isoformat()]["full"], days[old_day.isoformat()]["stable"]) == (full, stable)
    assert fmt.hour_text(ai.hour_floor(T0 - timedelta(days=45, hours=1))) not in _record(env)["hours"]
    # A prune of one of its hours re-roots it: the day's digest follows.
    from app.core import audit_chain_prune
    from app.core import retention
    p = retention.Pass(env.session, now=env.clock())
    audit_chain_prune.prune(p, [AuditLog.id == ids[0]], reason="retention")
    after = _record(env)["days"][old_day.isoformat()]
    assert after["full"] != full and (after["full"], after["stable"]) == _rows_digest(env, old_day)
    assert failures(env.verify()) == []


def test_every_64th_link_is_kept_by_generation(env):
    for h in range(70):
        env.row(T0 - timedelta(hours=80 - h))
    env.run_until_sealed()
    links = _record(env)["links"]
    assert env.st.view.position >= 64
    assert links["1:64"] == env.st.view.link_at(64).hex()
    assert all(k.startswith("1:") for k in links)


def test_the_day_digests_are_computed_a_month_at_a_time(env):
    """A long history is digested 31 days per record write, so a backlog spreads the work; the next write goes
    on from the day the last one reached."""
    env.row(T0 - timedelta(days=90))
    env.run_until_sealed()
    record = {}
    with env.session() as db:
        ai.day_digests(db, env.st.view, record, env.clock(), [])
        assert len(record["days"]) == ai.DAY_DIGESTS_PER_WRITE
        first_through = record["days_through"]
        ai.day_digests(db, env.st.view, record, env.clock(), [])
    assert len(record["days"]) > ai.DAY_DIGESTS_PER_WRITE and record["days_through"] > first_through


def test_the_summaries_hold_the_seals_another_writer_appended_once_accepted(env):
    from test_audit_chain_dates import _forge_hours_across
    env.run_until_sealed()
    _forge_hours_across(env, env.clock() + timedelta(days=1))
    forged = [s for s in env.seals() if s.kind == "hour"][-1]
    with ai.ChainWriter(env.engine, env.st):
        pass                                   # the server reads the chain and accepts them
    summary = env.st.head_store().load()["hours"][fmt.hour_text(forged.period_start)]
    assert summary["seq"] == forged.seq and summary["unsealed"] is False
