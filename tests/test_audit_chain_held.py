"""An hour re-rooted by a seal another writer appended after the head record, not yet acknowledged by the host, is
left as it is by the pruner: its rows may have been edited and sealed over by whoever holds the key, and a prune
would then seal them as genuine and destroy the evidence (app/core/audit_integrity.py hour_held). Offline, on a
throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import datetime, time, timedelta

import pytest
from sqlalchemy import func

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_prune
from app.core import audit_integrity as ai
from app.core import retention
from app.core.models import AuditLog

pytestmark = pytest.mark.unit

RECENT = (T0 - timedelta(days=50)).date()


def at(hour, minute=0, day=RECENT):
    return datetime.combine(day, time(hour, minute))


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _hot(env, day=RECENT):
    with env.session() as db:
        return db.query(func.count()).select_from(AuditLog).filter(
            AuditLog.timestamp >= at(0, day=day), AuditLog.timestamp < at(0, day=day) + timedelta(days=1)).scalar()


def _foreign_late(env, hour, added):
    """A late seal of ``hour`` that another writer holding the key appended: the hour's rows as they are, with
    ``added`` among them."""
    from test_audit_chain_guards import _forge
    with env.session() as db:
        wr = ai.working_row(db, hour)
        salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
        fig = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), salt)
    prev = env.st.view.entry_for(hour).root.seq
    return _forge(env, "late", {"hour": fmt.hour_text(hour), "prev_seq": prev, "added": [str(a) for a in added],
                                "by": "sealer"},
                  period_start=hour, period_end=hour + ai.HOUR, row_count=fig.count, row_bytes=fig.bytes,
                  root_s=fig.root_s, root_c=fig.root_c, ids_digest=fig.ids_digest)


def _ack_by_host(env, seqs):
    seen = host.acknowledge(env.engine, env.st, seqs=list(seqs), failures=False, read=True)
    return host.acknowledge(env.engine, env.st, seqs=list(seqs), failures=False, expect=seen["state"])


def _prune(env):
    p = retention.Pass(env.session, now=env.clock())
    return audit_chain_prune.prune(p, [AuditLog.timestamp < T0 - timedelta(days=40)], reason="retention")


def test_an_hour_another_writer_resealed_is_not_pruned_until_the_host_acknowledges_it(env):
    for h in (3, 5):
        env.row(at(h))
        env.row(at(h, 1))
    env.run_until_sealed()
    extra = env.row(at(3, 30))
    late = _foreign_late(env, at(3), [extra])
    env.clock.advance(minutes=30)
    assert env.seal().stopped is None
    assert ai.hour_held(env.st.view, env.st.head_store().load(), at(3)) == late
    assert ai.hour_held(env.st.view, env.st.head_store().load(), at(5)) is None
    _prune(env)
    assert _hot(env) == 3                            # hour 5 went; hour 3, three rows, waits
    _ack_by_host(env, [late])
    assert ai.hour_held(env.st.view, env.st.head_store().load(), at(3)) is None
    _prune(env)
    assert _hot(env) == 0
    assert failures(env.verify()) == []


def test_an_erase_seal_another_writer_appended_holds_its_hour(env):
    """An erase seal after the hour's root seal holds the hour as well (as the view lists it)."""
    env.row(at(3))
    env.run_until_sealed()
    from app.core.audit_chain_view import to_hours
    env.st.view._erases[to_hours(at(3))] = [77]
    record = {"after_record": [{"generation": env.st.view.generation, "seq": 77, "acknowledged": False}]}
    assert ai.hour_held(env.st.view, record, at(3)) == 77
    record["after_record"][0]["acknowledged"] = True
    assert ai.hour_held(env.st.view, record, at(3)) is None
    assert ai.hour_held(env.st.view, record, at(9)) is None
