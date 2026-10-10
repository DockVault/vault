"""The audit log's size cap counts the chain's bytes, and growth only after the delay
(app/core/audit_chain_size.py, app/core/audit_retention.py), offline:

- a large row in the current hour, or a late row in an hour sealed recently, deletes nothing before a delay of
  sealing has passed since the seal that took it in;
- growth across a stop: the window counts only time while sealing ran, so a stop of ten days does not make
  the first pass after it delete; the prune that then runs has a window reaching before the stop, and verify
  recomputes its total on the server and off it;
- another writer's inflated byte figures are held back: each counts no more than the hour's entry before it
  counts, until the host acknowledges it and a delay has passed after both its acceptance and its sealed_at;
  a size-cap prune meanwhile lists them, and verify recomputes its total;
- verify rejects a size-cap prune whose total, window or held-back seals the chain does not give.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
from datetime import timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_size as size
from app.core import audit_integrity as ai
from app.core import retention
from app.core.models import AuditLog, AuditSeal
from test_audit_chain_guards import _append, _forge, _off, _why
from test_audit_chain_trust import _ack_by_host, _run_to

pytestmark = pytest.mark.unit

KB = 1024


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_log_max_mb=1)
    monkeypatch.setenv("AUDIT_LOG_MAX_MB", "1")
    yield e
    e.close()


def _big(env, at, kb):
    return env.row(at, details={"blob": "x" * (kb * KB)})


def _kept(env, ids):
    with env.session() as db:
        return {r[0] for r in db.query(AuditLog.id).filter(AuditLog.id.in_(ids)).all()}


def _size_prunes(env):
    return [s for s in env.seals() if s.kind == "prune" and (s.detail or {}).get("reason") == "size-cap"]


def _seal_to(env, when):
    """Sealing every six hours until ``when``, and nothing else (no job deletes)."""
    while env.clock() + timedelta(hours=6) <= when:
        env.clock.advance(hours=6)
        env.seal()


def _counted(env):
    st = env.st
    start = size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=7))
    return size.total(st.view, start, size.held_back(st.view, st.known_record(), start))


def _sealed_at(env, at):
    """When the hour of ``at`` was sealed (its newest root seal), as the view holds it."""
    return env.st.view.entry_for(ai.hour_floor(at)).root.sealed_at


def test_a_large_row_in_the_current_hour_deletes_nothing_before_the_delay(env):
    old = [_big(env, T0 - timedelta(days=30, hours=h), 200) for h in range(3)]    # 0.6 MB
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    assert _kept(env, old) == set(old)
    at = env.clock() - timedelta(minutes=10)
    big = _big(env, at, 700)
    _run_to(env, env.clock() + timedelta(hours=3))
    sealed = _sealed_at(env, at)
    _run_to(env, sealed + timedelta(days=7, hours=-1))
    assert _kept(env, old) == set(old) and not _size_prunes(env)
    _run_to(env, sealed + timedelta(days=7, hours=2))
    assert len(_kept(env, old)) == 1 and big in _kept(env, [big])
    assert failures(env.verify()) == [] and failures(_off(env)) == []


def test_the_bytes_now_take_growth_in_at_once_and_the_cap_deletes_from_its_first_over(env):
    """A large row in the current hour, sealed: the cap's count takes it in only a delay after the hour's seal,
    the bytes now (what the retention screen warns on) at once. first_over names when the count first passes the
    cap: the hour's seal plus the delay. The pruner deletes nothing before then and the oldest rows after it, as
    many as the preview with the bytes now said."""
    from app.core import audit_retention as ar
    old = [_big(env, T0 - timedelta(days=30, hours=h), 200) for h in range(3)]    # 0.6 MB
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    at = env.clock() - timedelta(minutes=10)
    big = _big(env, at, 700)
    _run_to(env, env.clock() + timedelta(hours=3))
    st, now, delay = env.st, env.clock(), timedelta(days=7)
    counted = size.cap_count(st.view, st.known_record(), now, delay)[4]
    grown = size.now_count(st.view, st.known_record(), now)
    assert counted < ar.MB < grown and grown - counted >= 700 * KB
    over = size.first_over(st.view, st.known_record(), now, delay, ar.MB)
    assert over is not None and abs(over - (_sealed_at(env, at) + delay)) < timedelta(seconds=1)
    assert size.first_over(st.view, st.known_record(), now, delay, grown) is None
    with env.session() as db:
        today = ar.preview(db, now, ar.current())["by_size"]["rows"]
        as_counted = ar.preview(db, now, ar.current(), bytes_now=True)["by_size"]["rows"]
    assert (today, as_counted) == (0, 2)
    _run_to(env, over - timedelta(hours=1))
    assert _kept(env, old) == set(old) and not _size_prunes(env)
    _run_to(env, over + timedelta(hours=2))
    assert len(_kept(env, old)) == 1 and big in _kept(env, [big])


def test_growth_across_a_stop_counts_only_once_a_delay_of_sealing_has_run(env):
    old = [_big(env, T0 - timedelta(days=30, hours=h), 200) for h in range(3)]
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    at = env.clock() - timedelta(minutes=10)
    big = _big(env, at, 700)
    _run_to(env, env.clock() + timedelta(hours=3))           # its hour sealed before the stop
    sealing_before = env.clock() - _sealed_at(env, at)
    stop = env.clock()
    env.clock.advance(days=10)                               # the server was stopped
    retention.run_pass(env.session, now=env.clock())
    assert _kept(env, old) == set(old)                       # a calendar window would delete here
    back = env.clock()
    due = back + timedelta(days=7) - sealing_before
    _run_to(env, due - timedelta(hours=1))
    assert _kept(env, old) == set(old)
    _run_to(env, due + timedelta(hours=2))
    assert len(_kept(env, old)) == 1 and big in _kept(env, [big])
    prunes = _size_prunes(env)
    assert prunes and fmt.parse_time_text(prunes[0].detail["size"]["from"]) < stop
    assert failures(env.verify()) == [] and failures(_off(env)) == []


def test_a_late_row_in_an_hour_sealed_recently_counts_nothing_before_the_delay(env):
    old = [_big(env, T0 - timedelta(days=30, hours=h), 200) for h in range(3)]
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    hour = ai.hour_floor(env.clock()) - timedelta(hours=4)   # sealed within the last few hours
    late = _big(env, hour + timedelta(minutes=5), 700)
    retention.run_pass(env.session, now=env.clock())
    assert [s for s in env.seals() if s.kind == "late"]
    sealed = _sealed_at(env, hour)
    _run_to(env, sealed + timedelta(days=7, hours=-1))
    assert _kept(env, old) == set(old)
    _run_to(env, sealed + timedelta(days=7, hours=2))
    assert len(_kept(env, old)) == 1 and late in _kept(env, [late])


def test_a_late_row_in_an_empty_hour_of_the_backlogs_run_counts_nothing_before_the_delay(env):
    """A row put straight into the table, into an empty hour that the first start's backlog sealed as part of a
    run a few minutes before: that hour alone is re-rooted by a late seal, and its bytes wait a delay too."""
    genuine = [env.row(T0 - timedelta(days=30, hours=h)) for h in range(5)]
    env.run_until_sealed()
    assert any(s.period_end - s.period_start > ai.HOUR for s in env.seals() if s.kind == "hour")
    env.clock.advance(minutes=30)
    retention.run_pass(env.session, now=env.clock())
    assert _kept(env, genuine) == set(genuine)
    hour = ai.hour_floor(T0 - timedelta(days=10))
    bulky = _big(env, hour + timedelta(minutes=5), 2000)
    env.clock.advance(minutes=30)
    retention.run_pass(env.session, now=env.clock())
    late = [s for s in env.seals() if s.kind == "late"]
    assert late and late[-1].period_start == hour
    assert _kept(env, genuine) == set(genuine) and _kept(env, [bulky]) == {bulky}
    sealed = late[-1].sealed_at
    _run_to(env, sealed + timedelta(days=7, hours=-1))
    assert _kept(env, genuine) == set(genuine)
    _run_to(env, sealed + timedelta(days=7, hours=2))
    assert _kept(env, genuine) == set()                   # oldest first, once the delay has run


def _inflate(env, hour, nbytes, protected=0):
    """Another writer's prune seal for ``hour`` that keeps its roots and records ``nbytes`` (``protected`` of them
    protected)."""
    with env.session() as db:
        root = ai.hour_root(db, env.st.view, hour)
        newest = db.query(AuditSeal).filter(AuditSeal.kind == "policy").order_by(AuditSeal.seq.desc()).first()
        prev = db.query(AuditSeal).filter(AuditSeal.kind.in_(("hour", "late", "prune"))).order_by(
            AuditSeal.seq.desc()).all()
    prev_seq = root.seq
    for s in prev:
        d = s.detail or {}
        if s.kind == "prune" and any(h[0] == fmt.hour_text(hour) for h in d.get("hours") or []):
            prev_seq = s.seq
            break
    return _forge(env, "prune", {"reason": "retention", "policy_seq": newest.seq, "request_seq": None,
                                 "hours": [[fmt.hour_text(hour), prev_seq, root.count, nbytes, root.root_s.hex(),
                                            root.root_c.hex(), root.ids_digest.hex(), protected]]})


def test_another_writers_inflated_bytes_are_held_back_and_a_size_cap_prune_lists_them(env):
    target = T0 - timedelta(days=20)
    small = _big(env, target, 100)
    others = [_big(env, T0 - timedelta(days=30, hours=h), 300) for h in range(3)]     # 1.0 MB in all
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    counted_before = _counted(env)
    hour = ai.hour_floor(target)
    first = _inflate(env, hour, 50 * 1024 * KB)
    retention.run_pass(env.session, now=env.clock())          # accepted as a warning
    second = _inflate(env, hour, 60 * 1024 * KB)
    retention.run_pass(env.session, now=env.clock())
    assert {first, second} <= ai.unacknowledged_foreign(env.st.view, env.st.known_record())
    assert _counted(env) == counted_before                    # each counts the hour's 0.1 MB at most
    # Rows written now push the total over the cap once they count: the size-cap prune that runs then lists
    # both seals as held back, and deletes only the oldest hour.
    extra = [_big(env, env.clock() - timedelta(minutes=50 - 20 * n), 100) for n in range(2)]
    _run_to(env, env.clock() + timedelta(hours=3))
    _run_to(env, _sealed_at(env, env.clock() - timedelta(hours=3, minutes=50)) + timedelta(days=7, hours=2))
    prunes = _size_prunes(env)
    assert prunes and set(prunes[-1].detail["size"]["held_back"]) == {first, second}
    assert _kept(env, [small] + extra) == set([small] + extra) and len(_kept(env, others)) == 2
    assert failures(env.verify()) == [] and failures(_off(env)) == []


def test_acknowledged_inflated_bytes_count_only_once_a_window_starts_after_their_acceptance(env):
    target = T0 - timedelta(days=20)
    small = _big(env, target, 100)
    others = [_big(env, T0 - timedelta(days=30, hours=h), 300) for h in range(3)]
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    first = _inflate(env, ai.hour_floor(target), 50 * 1024 * KB)
    retention.run_pass(env.session, now=env.clock())
    accepted = env.clock()
    _ack_by_host(env, [first])
    _run_to(env, accepted + timedelta(days=7, hours=-2))
    assert _kept(env, [small] + others) == set([small] + others)
    _run_to(env, accepted + timedelta(days=7, hours=2))
    assert _kept(env, [small]) == set()
    assert failures(env.verify()) == [] and failures(_off(env)) == []


def test_a_released_entry_is_held_back_again_when_a_longer_delay_moves_the_window_before_it(env):
    """An entry appended during a stop, dated at its start and accepted at the restart, is
    acknowledged and released; a longer delay then puts the window's start before its acceptance (the stop,
    a gap, counts whole), and it is held back again, however long ago the delay after its times ran out."""
    _big(env, T0 - timedelta(days=20), 100)
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    target = ai.hour_floor(T0 - timedelta(days=20))
    forged = _inflate(env, target, 400 * KB)                  # dated at the stop's start
    env.clock.advance(days=10)
    retention.run_pass(env.session, now=env.clock())          # accepted at the restart
    _ack_by_host(env, [forged])
    _run_to(env, env.clock() + timedelta(days=7, hours=2))
    st = env.st
    start = size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=7))
    assert forged not in size.held_back(st.view, st.known_record(), start)
    start = size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=9))
    accepted = size.times.us(fmt.parse_time_text(
        [e for e in st.known_record()["after_record"] if e["seq"] == forged][0]["accepted_at"]))
    assert start < accepted
    assert forged in size.held_back(st.view, st.known_record(), start)


def test_a_held_back_entry_counts_no_more_than_the_entry_before_it_counts(env):
    view = ai.View()
    chain = [(5, 100, 1000), (9, 200, 50000), (12, 300, 70000)]
    assert size.counted_entries(chain, {9, 12}) == [(5, 100, 1000), (9, 200, 1000), (12, 300, 1000)]
    assert size.counted_entries(chain, {9}) == [(5, 100, 1000), (9, 200, 1000), (12, 300, 70000)]
    assert size.counted_entries([(7, 100, 900)], {7}) == [(7, 100, 0)]
    # The least over the window: before the window's start, the newest entry sealed by then counts.
    assert size.lagged([(5, 100, 1000), (12, 300, 70000)], 150) == 1000
    assert size.lagged([(5, 100, 1000), (12, 300, 400)], 150) == 400
    assert size.lagged([(5, 100, 1000)], 50) == 0
    assert view.position == 0


def _size_cap_prune(env, **changed):
    """A size-cap prune the server's writer appends with ``changed`` size figures, for an hour that holds
    rows, as the server would have written it otherwise."""
    st = env.st
    newest = st.view.newest_policy()
    start = size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=7))
    held = size.held_back(st.view, st.known_record(), start)
    figures = {"cap": 1024 * KB, "delay": 7, "from": fmt.time_text(size.times.dt(start)),
               "counted": size.total(st.view, start, held), "held_back": sorted(held)}
    figures.update(changed)
    hour = next(iter(st.view.single_hours()))
    with env.session() as db:
        root = ai.hour_root(db, st.view, hour)
    return _append(env, "prune", {"reason": "size-cap", "policy_seq": newest[0], "request_seq": None,
                                  "size": figures, "hours": [[fmt.hour_text(hour), root.seq, root.count, root.bytes,
                                                              root.root_s.hex(), root.root_c.hex(),
                                                              root.ids_digest.hex(), 0]]})


def _shorter_delay(env, _counted):
    """A delay of one day against the policy seal's seven, with its window and counted figure computed honestly
    over that one day (and still over the cap): only the delay is wrong."""
    st = env.st
    start = size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=1))
    held = size.held_back(st.view, st.known_record(), start)
    counted = size.total(st.view, start, held)
    assert counted > 1024 * KB
    return {"delay": 1, "from": fmt.time_text(size.times.dt(start)), "counted": counted, "held_back": sorted(held)}


@pytest.mark.parametrize("change,why", [
    (lambda env, c: {"counted": c + 1}, "counted"),
    (lambda env, c: {"from": fmt.time_text(T0 + timedelta(days=7, hours=20))}, "window is shorter"),
    (lambda env, c: {"held_back": [3]}, "held-back seals"),
    (lambda env, c: {"cap": c + 10 * 1024 * KB}, "under its cap"),
    (lambda env, c: {"cap": 512 * KB}, "cap or delay keeps less than its policy"),
    (_shorter_delay, "cap or delay keeps less than its policy"),
])
def test_verify_rejects_a_size_cap_prune_the_chain_does_not_give(env, change, why):
    for h in range(6):
        _big(env, T0 - timedelta(days=30, hours=h), 300)
    env.run_until_sealed()
    _seal_to(env, T0 + timedelta(days=8))
    counted = _counted(env)
    assert counted > 1024 * KB
    _size_cap_prune(env, **change(env, counted))
    on = _why(env.verify())
    off = _why(_off(env))
    assert any(why in m for m in on), on
    if why != "held-back seals":
        assert any(why in m for m in off), off


def test_a_size_cap_prune_as_the_chain_gives_it_verifies(env):
    for h in range(6):
        _big(env, T0 - timedelta(days=30, hours=h), 300)
    env.run_until_sealed()
    _seal_to(env, T0 + timedelta(days=8))
    _size_cap_prune(env)
    assert failures(env.verify()) == [] and failures(_off(env)) == []


# --------------------------------------------------------------------------- the window

def test_the_window_takes_in_a_gap_still_open(env):
    """Three days with no seal at all (a stop not yet over): the window reaches back the delay and the stop."""
    from app.core.audit_chain_view import from_us
    _big(env, T0 - timedelta(days=20), 100)
    env.run_until_sealed()
    view, record = env.st.view, env.st.known_record()
    now = view.newest_at() + timedelta(days=3)
    start = from_us(size.window_start(view, record, now, timedelta(days=7)))
    assert abs(start - (now - timedelta(days=10))) < timedelta(minutes=1)


def test_the_servers_window_takes_in_a_stop_another_writers_seals_hid(env):
    """Hour seals another writer appended across a ten-day stop, each dated within 12 hours of the last: the
    chain's own window sees seven days of sealing inside the stop; the server's, with the seals placed where it
    first accepted them (the restart), reaches back before the stop."""
    from app.core.audit_chain_view import from_us
    from test_audit_chain_dates import _forge_hours_across
    _big(env, T0 - timedelta(days=20), 100)
    env.run_until_sealed()
    stop_start = env.clock()
    _forge_hours_across(env, env.clock() + timedelta(days=10))
    retention.run_pass(env.session, now=env.clock())     # the restart accepts them
    view, record = env.st.view, env.st.known_record()
    now = env.clock()
    chain_only = from_us(size.window_start(view, record, now, timedelta(days=7), server=False))
    servers = from_us(size.window_start(view, record, now, timedelta(days=7)))
    assert chain_only > stop_start
    assert servers <= stop_start


# --------------------------------------------------------------------------- the protected bytes the chain binds

def _protected(env, hour, days=7):
    """What the size cap's protected share of ``hour`` may come to at most now: its lagged protected bytes."""
    st = env.st
    start = size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=days))
    return size.protected_hours(st.view, start, size.held_back(st.view, st.known_record(), start)).get(hour, 0)


def test_protected_rows_the_host_seals_into_an_old_hour_count_only_once_a_delay_of_sealing_has_run(env):
    """A protected row written into an old hour, and sealed there by the host's acknowledgment, raises the hour's
    bound like any growth: only once a delay of sealing has passed after the seal that took it in."""
    from app.core import audit_chain_host as host
    from app.core.audit_retention import protected_actions
    target = T0 - timedelta(days=20)
    _big(env, target, 100)
    env.run_until_sealed()
    _seal_to(env, T0 + timedelta(days=8))
    hour = ai.hour_floor(target)
    assert _protected(env, hour) == 0
    env.row(hour + timedelta(minutes=30), action=protected_actions()[0], details={"blob": "y" * (50 * KB)})
    seen = host.seal_late_rows(env.engine, env.st, hour, read=True)
    host.seal_late_rows(env.engine, env.st, hour, expect=seen["state"])
    late = [s for s in env.seals() if s.kind == "late"][-1]
    assert late.detail["protected_bytes"] > 50 * KB
    assert _protected(env, hour) == 0
    _seal_to(env, env.clock() + timedelta(days=6))
    assert _protected(env, hour) == 0
    _seal_to(env, env.clock() + timedelta(days=2))
    assert _protected(env, hour) == late.detail["protected_bytes"]


def test_another_writers_protected_bytes_are_held_back_like_its_bytes(env):
    """Another writer's prune seal that records an hour's bytes as protected counts, unacknowledged, no more than
    the hour's entry before it, however long ago it was sealed."""
    target = T0 - timedelta(days=20)
    _big(env, target, 100)
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    hour = ai.hour_floor(target)
    nbytes = env.st.view.entry_for(hour).root.bytes
    forged = _inflate(env, hour, nbytes, protected=nbytes)
    retention.run_pass(env.session, now=env.clock())          # accepted as a warning
    _seal_to(env, env.clock() + timedelta(days=9))
    assert forged in ai.unacknowledged_foreign(env.st.view, env.st.known_record())
    assert _protected(env, hour) == 0
    # Acknowledged by the host, it counts once a window starts after its acceptance.
    accepted = env.clock()
    _ack_by_host(env, [forged])
    _seal_to(env, accepted + timedelta(days=7, hours=6))
    assert _protected(env, hour) == nbytes


def test_the_view_keeps_an_entrys_protected_bytes_no_larger_than_its_bytes():
    from types import SimpleNamespace
    view = ai.View()
    hour = ai.hour_floor(T0)
    for seq, figure in enumerate((10 ** 6, 40, True, "40", -5, None), 1):
        start = hour + (seq - 1) * ai.HOUR
        detail = {} if figure is None else {"protected_bytes": figure}
        view.accept(SimpleNamespace(seq=seq, kind="hour", period_start=start, period_end=start + ai.HOUR,
                                    row_count=1, row_bytes=100, root_s=b"", root_c=b"", ids_digest=b"",
                                    detail=detail, sealed_at=T0, key_id="k"), b"\0" * 32)
    got = [view.entry_chain(last, protected=True)[0][2] for _s, _e, last in view.units()]
    assert got == [100, 40, 0, 0, 0, 0]
    assert [view.entry_chain(last)[0][2] for _s, _e, last in view.units()] == [100] * 6


@pytest.mark.parametrize("kind,row_bytes,detail,bad", [
    ("hour", 100, {"protected_bytes": 40}, False),
    ("hour", 100, {"protected_bytes": 100}, False),
    ("hour", 0, {"protected_bytes": 0}, False),
    ("hour", 100, {}, True),
    ("hour", 100, {"protected_bytes": 101}, True),
    ("hour", 100, {"protected_bytes": -1}, True),
    ("hour", 100, {"protected_bytes": True}, True),
    ("hour", 100, {"protected_bytes": 4.0}, True),
    ("late", 100, {"hour": "x", "protected_bytes": 7}, False),
    ("late", 100, {"hour": "x"}, True),
    ("prune", 0, {"hours": [["h", 1, 1, 50, "", "", "", 50]]}, False),
    ("prune", 0, {"hours": [["h", 1, 1, 50, "", "", ""]]}, True),
    ("prune", 0, {"hours": [["h", 1, 1, 50, "", "", "", 51]]}, True),
    ("rewrite", 0, {"hours": [["h", 1, 1, 50, "", "", "", 0], ["h", 1, 1, "x", "", "", "", 0]]}, True),
    ("rewrite", 0, {"hours": [["h", 1, 1, 50, "", "", "", 0, 0]]}, True),
    ("archive", 0, {}, False),
])
def test_verify_requires_each_hours_protected_bytes_from_0_to_its_bytes(kind, row_bytes, detail, bad):
    from types import SimpleNamespace
    from app.core import audit_chain_verify as v
    problem = v.protected_problem(SimpleNamespace(kind=kind, row_bytes=row_bytes, detail=detail))
    assert (problem is not None) is bad, problem


def test_a_prune_seal_whose_hour_has_no_protected_bytes_is_unjustified(env):
    env.row(T0 - timedelta(days=20))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(days=20))
    with env.session() as db:
        root = ai.hour_root(db, env.st.view, hour)
    newest = env.st.view.newest_policy()
    _append(env, "prune", {"reason": "retention", "policy_seq": newest[0], "request_seq": None,
                           "hours": [[fmt.hour_text(hour), root.seq, root.count, root.bytes, root.root_s.hex(),
                                      root.root_c.hex(), root.ids_digest.hex()]]})
    assert any("no protected bytes" in m for m in _why(_off(env)))


def test_the_sealers_late_seal_binds_the_protected_bytes_of_the_hours_rows(env):
    from app.core.audit_retention import _row_bytes, protected_actions
    when = T0 - timedelta(hours=3, minutes=20)
    env.row(when)
    env.run_until_sealed()
    hour = ai.hour_floor(when)
    admin = env.row(hour + timedelta(minutes=50), action=protected_actions()[0], details={"blob": "z" * KB})
    env.clock.advance(minutes=30)
    env.seal()
    late = [s for s in env.seals() if s.kind == "late"][-1]
    with env.session() as db:
        admin_bytes = db.query(_row_bytes(AuditLog, "sqlite")).filter(AuditLog.id == admin).scalar()
    assert late.detail["hour"] == fmt.hour_text(hour)
    assert late.detail["protected_bytes"] == admin_bytes > KB and late.row_bytes > admin_bytes
    assert failures(env.verify()) == []
