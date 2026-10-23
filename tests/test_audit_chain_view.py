"""The audit chain's verified view (app/core/audit_chain_view.py): small enough to keep ten years of seals in
the web process, and every hour's roots read again only through the view's own links.

Runs offline: the view on synthetic seals, and the chain on a throwaway SQLite database
(tests/_audit_chain_env.py)."""
import tracemalloc
import uuid
from datetime import datetime, timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_integrity as ai
from app.core.models import AuditLog, AuditSeal

pytestmark = pytest.mark.unit

START = datetime(2020, 1, 1)


def _hour_seal(seq, start, *, rows=3, nbytes=1200, sealed_at=None):
    return ai.Seal(seq, "hour", start, start + ai.HOUR, fmt.FORMAT, rows, nbytes, b"\x01" * 32, b"\x02" * 32,
                   b"\x03" * 32, {}, "kc1:0000000000000000", sealed_at or start + timedelta(hours=2))


def _genesis():
    detail = {"format": 1, "release": "t", "first_row_hour": fmt.hour_text(START),
              "backlog_through": fmt.hour_text(START), "backlog_rows": 0, "undated_rows": 0, "replaces": None,
              "grace_until": None}
    return ai.Seal(1, "genesis", None, None, fmt.FORMAT, 0, 0, fmt.EMPTY_ROOT, fmt.EMPTY_ROOT, fmt.ids_digest([]),
                   detail, "kc1:0000000000000000", START)


def _build(n_hours):
    view = ai.View()
    view.accept(_genesis(), b"\x00" * 32)
    for i in range(n_hours):
        view.accept(_hour_seal(i + 2, START + i * ai.HOUR), (i + 2).to_bytes(32, "big"))
    return view


def test_the_view_keeps_an_hour_of_history_in_about_a_hundred_bytes():
    n = 20000
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        view = _build(n)
        used = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
    # Ten years of hours (87,600) in under 15 MB, whatever the interpreter adds around the arrays.
    assert used / n < 170, used / n
    assert view.position == n + 1
    assert view.entry_for(START + 5 * ai.HOUR).root.seq == 7


def test_the_view_answers_for_hours_runs_and_late_splits():
    view = _build(4)
    run = ai.Seal(6, "hour", START + 4 * ai.HOUR, START + 10 * ai.HOUR, fmt.FORMAT, 0, 0, fmt.EMPTY_ROOT,
                  fmt.EMPTY_ROOT, fmt.ids_digest([]), {}, "kc1:0000000000000000", START + 12 * ai.HOUR)
    view.accept(run, b"\x06" * 32)
    assert view.entry_for(START + 7 * ai.HOUR).root.seq == 6
    assert view.entry_for(START + 7 * ai.HOUR).is_run
    late = ai.Seal(7, "late", START + 7 * ai.HOUR, START + 8 * ai.HOUR, fmt.FORMAT, 1, 300, b"\x09" * 32,
                   b"\x0a" * 32, b"\x0b" * 32, {"hour": fmt.hour_text(START + 7 * ai.HOUR), "prev_seq": 6,
                                                "added": [], "by": "sealer"}, "kc1:0000000000000000",
                   START + 13 * ai.HOUR)
    view.accept(late, b"\x07" * 32)
    own = view.entry_for(START + 7 * ai.HOUR)
    assert [r.seq for r in own.roots] == [6, 7] and own.root.bytes == 300 and not own.is_run
    # The run's other hours keep the run's seal, on both sides of the split.
    assert view.entry_for(START + 5 * ai.HOUR).root.seq == 6
    assert view.entry_for(START + 9 * ai.HOUR).root.seq == 6
    assert view.entry_for(START + 10 * ai.HOUR) is None
    assert list(view.single_hours())[-1] == START + 7 * ai.HOUR
    assert [(s, e) for s, e, _seq in view.runs()] == [(START + 4 * ai.HOUR, START + 7 * ai.HOUR),
                                                      (START + 8 * ai.HOUR, START + 10 * ai.HOUR)]
    assert view.link_at(7) == b"\x07" * 32 and view.at(7) == START + 13 * ai.HOUR


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def test_an_hours_roots_are_read_again_through_the_views_link(env):
    rid = env.row(T0 - timedelta(hours=8))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=8))
    with env.session() as db:
        root = ai.hour_root(db, env.st.view, hour)
        seal = db.get(AuditSeal, root.seq)
        assert (root.root_s, root.root_c, root.ids_digest) == (bytes(seal.root_s), bytes(seal.root_c),
                                                               bytes(seal.ids_digest))
    # The seal edited with its rows to match, after the view accepted it: the roots are not taken from it.
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == rid).delete()
        db.query(AuditSeal).filter(AuditSeal.seq == root.seq).update(
            {AuditSeal.row_count: 0, AuditSeal.root_s: fmt.EMPTY_ROOT, AuditSeal.root_c: fmt.EMPTY_ROOT,
             AuditSeal.ids_digest: fmt.ids_digest([])})
        db.commit()
    with env.session() as db:
        with pytest.raises(ai.ChainStopped) as stopped:
            ai.hour_root(db, env.st.view, hour)
    assert stopped.value.kind == "link-broken"


def test_a_root_seal_edited_with_its_rows_is_never_pruned_over(env, monkeypatch):
    from app.core import audit_chain_prune as prune_mod
    from app.core import retention
    old = env.row(T0 - timedelta(hours=8))
    keep = env.row(T0 - timedelta(hours=8, minutes=-20))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=8))
    root = env.st.view.entry_for(hour).root
    # Someone without the key deletes one row and re-roots the hour's seal over the row left.
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == old).delete()
        db.commit()
    with env.session() as db:
        fig = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR))
        db.query(AuditSeal).filter(AuditSeal.seq == root.seq).update(
            {AuditSeal.row_count: fig.count, AuditSeal.root_s: fig.root_s, AuditSeal.root_c: fig.root_c,
             AuditSeal.ids_digest: fig.ids_digest, AuditSeal.row_ids: fig.ids})
        db.commit()
    p = retention.Pass(env.session, now=env.clock())
    done = prune_mod.prune(p, [AuditLog.timestamp < T0], reason="retention")
    assert done.deleted == 0
    with env.session() as db:
        assert db.get(AuditLog, keep) is not None
    assert not [s for s in env.seals() if s.kind == "prune"]
