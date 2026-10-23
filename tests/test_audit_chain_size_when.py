"""The size cap's "when" (app/core/audit_chain_size.first_over) against the pruner's own count, offline.

At a moment t to come the window starts at S(t), the earlier of the two timelines' window_start_then(now, t), and
the pruner then counts total(view, S(t), held_back(view, record, S(t))), the functions cap_count uses. "when" must
be the earliest t at which that count passes the limit: at "when" it passes, a microsecond before it it does not,
and on an hourly grid before it it never does; None only when it never passes. Seeded scenarios: old hours, a day
the archive takes, late rows (growth), another writer's inflated figures read at once or hours later, dated ahead,
acknowledged or not, and stops in sealing; each checked against several limits, the count now among them (at a
count equal to the limit the cap deletes nothing), and the retention screen's Storage card against "when" for the
cap. Every third seed also runs the real pruner forward around "when".

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import collections
import random
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_archive as arc
from app.core import audit_chain_size as size
from app.core import audit_chain_times as times
from app.core import audit_integrity as ai
from app.core import retention
from test_audit_chain_guards import _off
from test_audit_chain_size import _big, _inflate, _size_prunes
from test_audit_chain_trust import _ack_by_host, _run_to

pytestmark = pytest.mark.unit

HOUR = 3600 * 1000000
KB = 1024
DELAY = timedelta(days=7)
LENGTH = int(DELAY.total_seconds() * 1000000)


def _start_then(view, record, now_us, t):
    return min(line.window_start_then(now_us, t, LENGTH) for line in times.timelines(view, record))


def _pruner_count(view, record, now_us, t):
    s = _start_then(view, record, now_us, t)
    return size.total(view, s, size.held_back(view, record, s))


def _grid(view, record, now, tag):
    """The pruner's count every hour for 60 days from now; it never falls."""
    now_us = times.us(now)
    assert _pruner_count(view, record, now_us, now_us) == size.cap_count(view, record, now, DELAY)[4], tag
    out, prev = [], None
    for t in range(now_us, now_us + 60 * 24 * HOUR, HOUR):
        c = _pruner_count(view, record, now_us, t)
        assert prev is None or c >= prev, (tag, "the count fell", t, c, prev)
        prev = c
        out.append((t, c))
    return out


def _check(view, record, now, limit, tag, seen, grid):
    """first_over against the pruner's count; returns first_over."""
    now_us = times.us(now)
    over = size.first_over(view, record, now, DELAY, limit)
    first_grid = next((t for t, c in grid if c > limit), None)
    if over is None:
        assert first_grid is None, (tag, "first_over is None but the count passes", first_grid, limit)
        assert _pruner_count(view, record, now_us, now_us + 400 * 24 * HOUR) <= limit, (tag, "it passes later")
        seen["none"] += 1
        return None
    o = times.us(over)
    assert _pruner_count(view, record, now_us, o) > limit, (tag, "not over at when", over, limit)
    if o > now_us:
        assert _pruner_count(view, record, now_us, o - 1) <= limit, (tag, "over a microsecond before when", over)
        seen["later"] += 1
    else:
        seen["now"] += 1
    assert (first_grid is not None and o <= first_grid < o + HOUR + 1) or (o == now_us and first_grid == now_us), (
        tag, over, first_grid)
    return over


def _scenario(env, rnd, seen, forward):
    from app.core import audit_retention as ar
    from app.core import retention_storage as rs
    events = []
    for h in range(rnd.randrange(1, 4)):                     # old hours, not archived
        _big(env, T0 - timedelta(days=30 + rnd.randrange(0, 5), hours=h), rnd.choice([100, 200, 300]))
    if rnd.random() < 0.5:                                   # a day the archive takes
        for h in rnd.sample([1, 3, 4, 6, 9], rnd.randrange(1, 4)):
            _big(env, T0 - timedelta(days=100, hours=-h), rnd.choice([50, 100, 150]))
        events.append("archived-day")
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=rnd.choice([1, 8])))
    old_hours = sorted({ai.hour_floor(T0 - timedelta(days=30 + d, hours=h)) for d in range(5) for h in range(3)}
                       | {ai.hour_floor(T0 - timedelta(days=100, hours=-h)) for h in (1, 3, 4, 6, 9)})
    for _step in range(rnd.randrange(2, 6)):
        kind = rnd.choice(["late", "new", "foreign", "foreign", "stop", "wait"])
        if kind == "late":
            at = env.clock() - timedelta(minutes=10)
            _big(env, at, rnd.choice([20, 100]))
            _run_to(env, env.clock() + timedelta(hours=rnd.choice([2, 3])))
            _big(env, at + timedelta(minutes=5), rnd.choice([50, 250]))     # into the sealed hour: a late seal
            retention.run_pass(env.session, now=env.clock())
        elif kind == "new":
            _big(env, env.clock() - timedelta(minutes=5), rnd.choice([30, 150, 400]))
            _run_to(env, env.clock() + timedelta(hours=3))
        elif kind == "foreign":
            hour = rnd.choice(old_hours)
            if env.st.view.entry_for(hour) is None:
                continue
            body = {}
            if rnd.random() < 0.3:
                body["sealed_at"] = env.clock() + timedelta(minutes=rnd.choice([1, 4]))
            try:
                seq = _inflate(env, hour, rnd.choice([400, 2000, 50 * 1024]) * KB, **body)
            except Exception:  # noqa: BLE001 -- an hour the archive took has no root to inflate
                continue
            env.clock.advance(hours=rnd.choice([0, 0, 5, 11]))
            retention.run_pass(env.session, now=env.clock())
            if rnd.random() < 0.7:
                _ack_by_host(env, [seq])
            events.append("foreign-ahead" if body else "foreign")
        elif kind == "stop":
            env.clock.advance(hours=rnd.choice([13, 30, 60]))
            retention.run_pass(env.session, now=env.clock())
        else:
            _run_to(env, env.clock() + timedelta(days=rnd.choice([1, 3, 6])))
        events.append(kind)
    st = env.st
    view, record, now = st.view, st.known_record(), env.clock()
    count_now = size.cap_count(view, record, now, DELAY)[4]
    peak = _pruner_count(view, record, times.us(now), times.us(now) + 400 * 24 * HOUR)
    limits = {ar.MB, count_now, max(0, peak - 1), max(0, (count_now + peak) // 2), peak}
    grid = _grid(view, record, now, events)
    overs = {limit: _check(view, record, now, limit, (events, limit), seen, grid) for limit in sorted(limits)}
    card = rs.cap_counted(now, st)
    if card and card["now_bytes"] > ar.MB:
        want = overs[ar.MB]
        assert card["over_from"] == (want.isoformat() + "Z" if want is not None else None), (events, card, want)
    seen["events"].update(events)
    if forward and overs[ar.MB] is not None and overs[ar.MB] > now + timedelta(hours=2):
        over = overs[ar.MB]
        _run_to(env, over - timedelta(hours=1))
        assert not _size_prunes(env), (events, "a size-cap prune before when", over)
        _run_to(env, over + timedelta(hours=2))
        assert _size_prunes(env), (events, "no size-cap prune after when", over)
        assert failures(env.verify()) == [] and failures(_off(env)) == []
        seen["forward"] += 1


@pytest.mark.parametrize("seed", range(12))
def test_when_is_the_first_moment_the_pruners_own_count_passes_the_limit(monkeypatch, tmp_path, seed):
    env = Env(monkeypatch, tmp_path, audit_log_max_mb=1, audit_archive_start_after_days=0)
    monkeypatch.setenv("AUDIT_LOG_MAX_MB", "1")
    arc._marker_checked.clear()
    arc._figures.clear()
    seen = collections.Counter()
    seen["events"] = collections.Counter()
    try:
        _scenario(env, random.Random(seed), seen, forward=seed % 3 == 0)
    finally:
        env.close()
