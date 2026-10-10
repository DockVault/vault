"""Reading archived days (app/services/activity_archive.py), offline, on a throwaway SQLite database with a chain of
its own (tests/_audit_chain_env.py):

- the blocks' aggregates count rows by hour, action, status and channel, as the SQL does;
- the aggregates' predicate matches what build_events_query's category, event, status and channel filters match,
  value for value, and which filters it can answer;
- a search: random filter combinations over a seeded corpus return the same rows, in the same order, from the rows
  before archiving and from rows and archive after it; paging and cursors across the boundary; a range with no start
  reads rows only; the range's bounds (days, rows, bytes); a block altered, missing or unsealed, and one the view
  names but the snapshot holds no block of; rows of an account deleted since; the search's table gone after it;
- the band over archived hours, per bucket and under each filter, against the rows before archiving; the blocks that
  count rows only; aggregates that cannot be read;
- what the export and the other readers say of the archive.

The same, with every filter (address blocks, JSON) and the band through summarize, on Postgres:
tests/test_activity_archive_live.py.
"""
import random
import uuid
from pathlib import Path
from datetime import datetime, time, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy import func

from _audit_chain_env import Env, T0, failures
from app.core import audit_archive as arc
from app.core import audit_archive_format as af
from app.core import audit_chain_format as fmt
from app.core import audit_integrity as ai
from app.core import retention
from app.core.models import AuditArchiveBlock, AuditLog, User, RoleEnum
from app.services import activity_archive as archive
from app.services import activity_events as ev
from app.services import activity_summary as summary

pytestmark = pytest.mark.unit

ARCHIVED = [(T0 - timedelta(days=d)).date() for d in (100, 99, 98, 97)]
HOT = [(T0 - timedelta(days=d)).date() for d in (3, 2)]
V1 = "5f0c8a1e-2b3d-4c6f-9a7b-1d2e3f4a5b6c"
TC1 = uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")


def at(day, hour, minute=0):
    return datetime.combine(day, time(hour, minute))


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _put(env, when, **values):
    row = dict(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=when, username="alice",
               ip_address="203.0.113.9", details={"n": 1}, seal_nonce=uuid.uuid4().bytes)
    row.update(values)
    with env.session() as db:
        db.add(AuditLog(**row))
        db.commit()
    return row["id"]


ACTIONS = ("file_uploaded", "file_upload", "login_success", "login_failure", "vault_created", "legacy_thing")
STATUSES = ("success", "failure", "error", "authorized", "refused")
CHANNELS = ("web", "sftp", None, "public_link")


def _corpus(env, user_id):
    """Rows over the archived and the hot days, with every filterable value varied."""
    rnd = random.Random(20261010)
    ids = []
    for day in ARCHIVED + HOT:
        for hour in (1, 5, 9, 13, 17, 22):
            for k in range(3):
                values = dict(action=rnd.choice(ACTIONS), status=rnd.choice(STATUSES), channel=rnd.choice(CHANNELS),
                              username=rnd.choice(("alice", "bob", "carol", None)),
                              ip_address=rnd.choice(("203.0.113.9", "198.51.100.7", None)),
                              error_message=rnd.choice((None, "error: refused upload")),
                              details=rnd.choice(({"n": 1}, {"vault_id": V1}, {"file": "upload"})),
                              user_id=None,
                              temp_credential_id=rnd.choice((None, None, TC1)))
                if user_id is not None and rnd.random() < 0.3:      # a row of the account, under its name
                    values.update(user_id=user_id, username="dana")
                ids.append(_put(env, at(day, hour, 7 * k + 1), **values))
    return ids


def _user(env, name="dana"):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username=name, password_hash="x", role=RoleEnum.USER))
        db.commit()
    return uid


def _archive_all(env):
    env.run_until_sealed()
    assert failures(env.verify()) == []
    for _ in range(4):
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        archived_days = {d for (d,) in db.query(AuditArchiveBlock.day).all()}
    assert {arc._as_date(d) for d in archived_days} == set(ARCHIVED)
    assert failures(env.verify()) == []


FILTER_POOL = dict(
    categories=([], ["files"], ["sign_in"], ["legacy"], ["files", "legacy"], ["no-such-category"]),
    channels=([], ["web"], ["unknown"], ["sftp", "unknown"], ["bogus"]),
    statuses=([], ["failed"], ["success"], ["authorized"], ["bogus"]),
    actions=([], ["login_failure"], ["file_upload", "vault_created"], ["legacy_thing"]),
    username=(None, "ali", "BOB"),
    user_exact=(False, True),
    no_account=(False, True),
    ip=(None, "203.0.113.9", "198.51.100.7"),
    text=(None, "upload", "bob", "refused"),
    vault_id=(None, V1),
    temp_credential_id=(None, str(TC1)),
)


def _filters(rnd):
    f = {k: rnd.choice(v) for k, v in FILTER_POOL.items()}
    # Most combinations narrow to nothing: keep about half of the filters off.
    for k in list(f):
        if rnd.random() < 0.55:
            f[k] = FILTER_POOL[k][0]
    return f


def _ids(db, entity, filters):
    q = ev.build_events_query(db.query(entity.id), entity, **filters)
    return [r[0] for r in q.order_by(entity.timestamp.desc(), entity.id.desc()).all()]


# --------------------------------------------------------------------------- aggregates

def test_the_aggregates_count_rows_by_hour_action_status_and_channel(env):
    uid = _user(env)
    _corpus(env, uid)
    with env.session() as db:
        want = {}
        for t, a, s, c in db.query(AuditLog.timestamp, AuditLog.action, AuditLog.status, AuditLog.channel).filter(
                AuditLog.timestamp < at(ARCHIVED[-1], 0) + timedelta(days=1)).all():
            key = (fmt.hour_text(ai.hour_floor(t)), a, s, c)
            want[key] = want.get(key, 0) + 1
    _archive_all(env)
    got = {}
    with env.session() as db:
        for (agg,) in db.query(AuditArchiveBlock.aggregates).all():
            for h, a, s, c, n in agg["by_hour"]:
                got[(h, a, s, c)] = got.get((h, a, s, c), 0) + n
    assert got == want and sum(want.values()) == 4 * 6 * 3


def test_the_aggregates_predicate_matches_what_build_events_query_matches(env):
    combos = [(a, s, c) for a in ACTIONS + ("x",) for s in STATUSES + ("bogus",) for c in CHANNELS + ("bogus",)]
    by_id = {}
    for a, s, c in combos:
        by_id[_put(env, T0 - timedelta(hours=1), action=a, status=s, channel=c)] = (a, s, c)
    pools = [dict(categories=c, channels=ch, statuses=st, actions=ac)
             for c in FILTER_POOL["categories"] for ch in FILTER_POOL["channels"]
             for st in FILTER_POOL["statuses"] for ac in FILTER_POOL["actions"]]
    with env.session() as db:
        for f in pools:
            want = set(r[0] for r in ev.build_events_query(db.query(AuditLog.id), AuditLog, **f).all())
            match = ev.aggregate_match(**f)
            got = {i for i, (a, s, c) in by_id.items() if match(a, s, c)}
            assert got == want, f
    assert len(pools) == 6 * 5 * 5 * 4


@pytest.mark.parametrize("filters, countable", [
    ({}, True), ({"categories": ["files"], "statuses": ["failed"], "channels": ["web"], "actions": ["x"]}, True),
    ({"start": T0, "end": T0, "username": None, "user_exact": False, "no_account": False, "ids": []}, True),
    ({"username": "a"}, False), ({"ip": "203.0.113.9"}, False), ({"text": "t"}, False), ({"vault_id": V1}, False),
    ({"no_account": True}, False), ({"ids": ["x"]}, False), ({"temp_credential_id": "x"}, False),
    ({"temp_credential": "x"}, False), ({"user_exact": True}, False)])
def test_the_filters_the_aggregates_answer(filters, countable):
    assert ev.aggregate_countable(filters) is countable


# --------------------------------------------------------------------------- the search

def _search(env, start, end=None):
    p = archive.plan(start, end, env.st)
    assert p is not None
    return archive.search(env.engine, p, env.st)


def test_random_filters_return_the_same_rows_from_rows_and_from_the_archive(env):
    uid = _user(env)
    _corpus(env, uid)
    rnd = random.Random(7)
    ranges = [(at(ARCHIVED[0], 0), None), (at(ARCHIVED[1], 6), at(HOT[0], 12)), (at(ARCHIVED[2], 0), at(ARCHIVED[3], 9)),
              (at(ARCHIVED[0], 0), at(ARCHIVED[0], 10))]
    cases = []
    with env.session() as db:
        for i in range(120):
            f = _filters(rnd)
            f["start"], f["end"] = ranges[i % len(ranges)]
            if i % 10 == 0:
                some = _ids(db, AuditLog, {"start": f["start"], "end": f["end"]})
                f["ids"] = [str(x) for x in rnd.sample(some, min(5, len(some)))]
            cases.append((f, _ids(db, AuditLog, f)))
    assert sum(1 for _f, ids in cases if ids) > 40          # not a test of empty results
    _archive_all(env)
    for start, end in ranges:
        with _search(env, start, end) as s:
            assert s.unreadable == {}
            for f, want in cases:
                if (f["start"], f["end"]) != (start, end):
                    continue
                assert _ids(s.db, s.entity, f) == want, f
                assert ev.build_events_query(s.db.query(s.entity), s.entity, **f).order_by(None).count() == len(want)


def test_pages_and_cursors_cross_the_boundary(env):
    uid = _user(env)
    _corpus(env, uid)
    start = at(ARCHIVED[2], 0)
    with env.session() as db:
        every = [(r.id, r.timestamp) for r in ev.build_events_query(db.query(AuditLog), AuditLog, start=start)
                 .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).all()]
    ids = [i for i, _t in every]
    _archive_all(env)
    with _search(env, start) as s:
        base = ev.build_events_query(s.db.query(s.entity), s.entity, start=start)
        walked, cursor = [], None
        while True:
            rows = ev.after_cursor(base, s.entity, cursor).order_by(s.entity.timestamp.desc(),
                                                                    s.entity.id.desc()).limit(7).all()
            walked += [r.id for r in rows]
            if len(rows) < 7:
                break
            cursor = (rows[-1].timestamp, rows[-1].id)
        assert walked == ids
        total = base.order_by(None).count()
        assert total == len(ids) > 30
        paged = []
        for page in range(1, ev.page_count(total, 10) + 1):
            rows, _more = ev.numbered_page(base, s.entity, page, 10, total)
            paged += [r.id for r in rows]
        assert paged == ids
        anchor = at(ARCHIVED[3], 12)
        newer = ev.newer_than(base, s.entity, (anchor, uuid.UUID(int=0)))
        assert [r.id for r in newer.order_by(s.entity.timestamp, s.entity.id).all()] == \
            [i for i, t in reversed(every) if t > anchor]


def test_a_range_with_no_start_or_that_reaches_no_archived_day_reads_rows_only(env):
    _corpus(env, None)
    _archive_all(env)
    assert archive.plan(None, None, env.st) is None
    assert archive.plan(at(HOT[0], 0), None, env.st) is None
    assert archive.plan(at(ARCHIVED[3], 23, 30), None, env.st) is not None          # its last hour
    assert archive.plan(at(ARCHIVED[3], 0) + timedelta(days=1), None, env.st) is None
    with env.session() as db:
        with archive.source(db, None, None, env.st) as src:
            assert src.db is db and src.entity is AuditLog
            assert src.note == {"oldest_day": ARCHIVED[0].isoformat(), "newest_day": ARCHIVED[-1].isoformat(),
                                "days": 4, "searched": False, "unreadable": [], "max_days": archive.MAX_DAYS}
        with archive.source(db, at(HOT[0], 0), None, env.st) as src:
            assert src.db is db and src.entity is AuditLog and src.note is None
        with archive.source(db, at(ARCHIVED[1], 0), at(ARCHIVED[2], 0), env.st) as src:
            assert src.db is not db and src.note["searched"] and src.note["searched_days"] == 1


def test_a_search_reads_at_most_so_many_days_rows_and_bytes(env, monkeypatch):
    _corpus(env, None)
    _archive_all(env)
    start = at(ARCHIVED[0], 0)
    monkeypatch.setattr(archive, "MAX_DAYS", 3)
    with pytest.raises(archive.TooBroad, match="reaches 4 archived days; a search reads at most 3"):
        archive.plan(start, None, env.st)
    assert archive.plan(at(ARCHIVED[1], 0), None, env.st) is not None
    monkeypatch.setattr(archive, "MAX_DAYS", 31)
    monkeypatch.setattr(archive, "MAX_ROWS", 4 * 18 - 1)
    with pytest.raises(archive.TooBroad, match="hold 72 events"):
        archive.plan(start, None, env.st)
    monkeypatch.setattr(archive, "MAX_ROWS", 4 * 18)
    p = archive.plan(start, None, env.st)
    monkeypatch.setattr(archive, "MAX_BYTES", p.length - 1)
    with pytest.raises(archive.TooBroad, match="bytes compressed"):
        archive.plan(start, None, env.st)
    monkeypatch.setattr(archive, "MAX_BYTES", p.length)
    assert archive.plan(start, None, env.st) is not None
    # The search checks again, against the view it reads after its snapshot.
    monkeypatch.setattr(archive, "MAX_BYTES", p.length - 1)
    with pytest.raises(archive.TooBroad):
        with archive.search(env.engine, p, env.st):
            pass


def _edit_block(env, day, **values):
    with env.session() as db:
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == day).update(values, synchronize_session=False)
        db.commit()


def test_a_block_that_does_not_check_out_is_left_out_and_named(env, monkeypatch):
    _corpus(env, None)
    start = at(ARCHIVED[0], 0)
    with env.session() as db:
        want = _ids(db, AuditLog, {"start": start})
        day1 = set(_ids(db, AuditLog, {"start": at(ARCHIVED[1], 0), "end": at(ARCHIVED[2], 0)}))
    _archive_all(env)
    with env.session() as db:
        (payload,) = db.query(AuditArchiveBlock.payload).filter(AuditArchiveBlock.day == ARCHIVED[1]).one()
    _edit_block(env, ARCHIVED[1], payload=bytes(payload)[:-1] + bytes([payload[-1] ^ 1]))
    loads = []
    real = archive._load
    monkeypatch.setattr(archive, "_load", lambda *a, **k: loads.append(1) or real(*a, **k))
    monkeypatch.setattr(archive, "RETRY_PAUSE", 0)
    with _search(env, start) as s:
        assert s.unreadable == {ARCHIVED[1].isoformat(): "block-altered"}
        assert _ids(s.db, s.entity, {"start": start}) == [i for i in want if i not in day1]
    assert len(loads) == 2                                   # taken again once before it is reported
    with env.session() as db:
        with archive.source(db, start, None, env.st) as src:
            assert src.note["unreadable"] == [{"day": ARCHIVED[1].isoformat(), "reason": "block-altered"}]


def test_a_block_whose_rows_are_not_its_count_is_left_out(env, monkeypatch):
    _corpus(env, None)
    _archive_all(env)
    entries = archive.archives(env.st)
    entry = entries[ARCHIVED[2]]
    (part,) = entry.parts
    import dataclasses
    wrong = dataclasses.replace(part, rows=part.rows + 1)
    monkeypatch.setattr(archive, "archives", lambda st=None: {**entries, ARCHIVED[2]: dataclasses.replace(
        entry, parts=(wrong,))})
    monkeypatch.setattr(archive, "RETRY_PAUSE", 0)
    p = archive.Plan(at(ARCHIVED[0], 0), None, tuple(archive.parts_between(archive.archives(), at(ARCHIVED[0], 0),
                                                                             None)))
    with archive.search(env.engine, p, env.st) as s:
        assert s.unreadable == {ARCHIVED[2].isoformat(): "block-altered"}
        n = s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar()
        assert n == 3 * 18                                   # the other three days, and nothing of that one


def test_a_missing_block_is_named_unless_its_rows_are_rows(env, monkeypatch):
    _corpus(env, None)
    _archive_all(env)
    monkeypatch.setattr(archive, "RETRY_PAUSE", 0)
    with env.session() as db:
        rows = [r for r in arc.iter_full_rows(db, at(ARCHIVED[3], 0), at(ARCHIVED[3], 0) + timedelta(days=1))]
    assert rows == []
    with env.session() as db:
        blk = db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == ARCHIVED[3]).one()
        block = arc.open_part(db, ARCHIVED[3], next(iter(archive.archives(env.st)[ARCHIVED[3]].parts)), bytes(blk.payload))
        archived_rows = list(block.rows())
    with env.session() as db:
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == ARCHIVED[3]).delete()
        db.commit()
    with _search(env, at(ARCHIVED[3], 0)) as s:
        assert s.unreadable[ARCHIVED[3].isoformat()] == "block-missing"
    # Its rows back as rows (an unarchive the view has not read yet): nothing is missing.
    with env.session() as db:
        arc._insert_rows(db, archived_rows)
        db.commit()
    with _search(env, at(ARCHIVED[3], 0)) as s:
        assert ARCHIVED[3].isoformat() not in s.unreadable
        assert len(_ids(s.db, s.entity, {"start": at(ARCHIVED[3], 0), "end": at(ARCHIVED[3], 0) + timedelta(days=1)})) \
            == len(archived_rows)


def test_a_block_the_view_does_not_name_is_named_and_not_read(env, monkeypatch):
    _corpus(env, None)
    _archive_all(env)
    monkeypatch.setattr(archive, "RETRY_PAUSE", 0)
    with env.session() as db:
        blk = db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == ARCHIVED[0]).one()
        db.add(AuditArchiveBlock(day=blk.day, part=9, first_hour=blk.first_hour, last_hour=blk.last_hour,
                                 row_count=blk.row_count, codec=blk.codec, format=blk.format, payload=blk.payload,
                                 raw_bytes=blk.raw_bytes, aggregates=blk.aggregates, created_at=T0))
        db.commit()
    with _search(env, at(ARCHIVED[0], 0), at(ARCHIVED[1], 0)) as s:
        assert s.unreadable == {ARCHIVED[0].isoformat(): "block-unsealed"}
        assert len(_ids(s.db, s.entity, {"start": at(ARCHIVED[0], 0), "end": at(ARCHIVED[1], 0)})) == 18


def test_a_later_releases_block_is_named_and_not_read(env, monkeypatch):
    _corpus(env, None)
    monkeypatch.setattr(af, "FORMAT", 2)
    _archive_all(env)
    monkeypatch.setattr(af, "FORMAT", 1)
    monkeypatch.setattr(archive, "RETRY_PAUSE", 0)
    with _search(env, at(ARCHIVED[0], 0)) as s:
        assert s.unreadable == {d.isoformat(): "block-later-format" for d in ARCHIVED}
        assert s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar() == 0


def test_rows_of_an_account_deleted_since_they_were_archived_have_no_account(env):
    uid = _user(env, "erin")
    ids = [_put(env, at(ARCHIVED[1], h), user_id=uid, username="erin") for h in (2, 3)]
    _corpus(env, None)
    _archive_all(env)
    with env.session() as db:
        db.query(User).filter(User.id == uid).delete()
        db.commit()
    with _search(env, at(ARCHIVED[0], 0)) as s:
        got = _ids(s.db, s.entity, {"no_account": True, "username": "erin", "user_exact": True})
        assert sorted(got) == sorted(ids)
        assert {r.user_id for r in s.db.query(s.entity).filter(s.entity.id.in_(ids)).all()} == {None}


def test_the_searchs_table_goes_with_it(env):
    _corpus(env, None)
    _archive_all(env)
    with _search(env, at(ARCHIVED[0], 0)) as s:
        assert s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar() == 4 * 18
    with env.engine.connect() as c:
        assert archive.SEARCH_TABLE not in sa.inspect(c).get_table_names()
        assert not c.execute(sa.text("SELECT name FROM sqlite_temp_master WHERE name = :n"),
                             {"n": archive.SEARCH_TABLE}).fetchall()
    # And a second search on the same pooled connection starts clean.
    with _search(env, at(ARCHIVED[0], 0)) as s:
        assert s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar() == 4 * 18


def test_a_search_reads_only_the_archived_rows_of_its_range(env):
    _corpus(env, None)
    _archive_all(env)
    # From noon of the second day (its 13:00, 17:00 and 22:00 rows) to 09:00 of the fourth (its 01:00 and 05:00).
    with _search(env, at(ARCHIVED[1], 12), at(ARCHIVED[3], 9)) as s:
        assert s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar() == 9 + 18 + 6


_open_part = arc.open_part


def _altered(monkeypatch, change):
    """open_part, with each block it opens changed by ``change(block)`` once its digest has been checked."""
    real = _open_part

    def opened(db, day, part, payload=None):
        block = real(db, day, part, payload)
        change(block)
        return block
    monkeypatch.setattr(arc, "open_part", opened)


def test_a_block_that_says_it_is_another_part_or_holds_a_row_of_another_hour_is_left_out(env, monkeypatch):
    _corpus(env, None)
    _archive_all(env)
    monkeypatch.setattr(archive, "RETRY_PAUSE", 0)
    _altered(monkeypatch, lambda block: block.header.__setitem__("part", 7))
    with _search(env, at(ARCHIVED[3], 0)) as s:
        assert s.unreadable == {ARCHIVED[3].isoformat(): "block-altered"}
        assert s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar() == 0

    def moved(block):
        rows = block.rows

        def shifted():
            for i, row in enumerate(rows()):
                if i == 4:
                    row = dict(row, timestamp=row["timestamp"] - timedelta(days=1))
                yield row
        block.rows = shifted
    _altered(monkeypatch, moved)
    with _search(env, at(ARCHIVED[3], 0)) as s:
        assert s.unreadable == {ARCHIVED[3].isoformat(): "block-altered"}
        assert s.db.query(func.count()).select_from(sa.table(archive.SEARCH_TABLE)).scalar() == 0


# --------------------------------------------------------------------------- the band

def _band_want(env, win, filters, lo, hi, block="events"):
    with env.session() as db:
        q = ev.build_events_query(db.query(AuditLog.timestamp, AuditLog.action, AuditLog.status), AuditLog, **filters)
        rows = q.filter(AuditLog.timestamp >= lo, AuditLog.timestamp < hi).all()
    out = {}
    for t, a, s in rows:
        key = win.bucket_of(ai.hour_floor(t)) if block == "events" else None
        if block == "events" and key is None:
            continue
        cell = out.setdefault((key, a), [0, 0])
        cell[0] += 1
        cell[1] += 1 if s in summary.FAILED_STATUSES else 0
    return out


def _band_got(rows):
    out = {}
    for bucket, action, n, failed, unowned, unowned_failed in rows:
        assert unowned == 0 and unowned_failed == 0
        cell = out.setdefault((bucket, action), [0, 0])
        cell[0] += n
        cell[1] += failed
    return out


@pytest.mark.parametrize("offset", [0, 120, -300])
def test_the_band_counts_archived_hours_per_bucket_as_the_rows_did(env, offset):
    _corpus(env, None)
    lo, hi = at(ARCHIVED[0], 0) - timedelta(days=2), T0
    win = summary.custom_window(lo, hi, tz_offset_minutes=offset)
    filter_sets = [{}, {"categories": ["files", "legacy"]}, {"statuses": ["failed"], "channels": ["web", "unknown"]},
                   {"actions": ["login_failure", "vault_created"]}, {"categories": ["no-such"]}]
    archived_hi = at(ARCHIVED[-1], 0) + timedelta(days=1)
    wants = [_band_want(env, win, f, lo, archived_hi) for f in filter_sets]
    _archive_all(env)
    with env.session() as db:
        for f, want in zip(filter_sets, wants):
            per_block = summary.block_filters(dict(f, start=None, end=None))
            got, note = archive.band_archive(db, win, per_block, lo, None, T0, env.st)
            assert _band_got(got.get("events", [])) == want, f
            assert note["counted"] == ["events", "categories", "sign_ins"]
            assert note["rows_only"] == ["people", "addresses"]
            assert note["oldest_day"] == ARCHIVED[0].isoformat() and note["unreadable"] == []
    assert any(wants)


def test_a_block_of_the_band_counts_hours_inside_its_own_time_filter(env):
    _corpus(env, None)
    lo = at(ARCHIVED[0], 0)
    win = summary.custom_window(lo, T0)
    picked = (at(ARCHIVED[1], 9), at(ARCHIVED[2], 9))
    # The category mix leaves out its own filter (the category) and keeps the time picked on the chart.
    want = _band_want(env, win, {}, *picked, block="categories")
    _archive_all(env)
    with env.session() as db:
        per_block = summary.block_filters({"categories": ["files"], "start": picked[0], "end": picked[1]})
        got, _note = archive.band_archive(db, win, per_block, lo, None, T0, env.st)
    assert _band_got(got["categories"]) == want != {}
    assert sum(n for _b, _a, n, _f, _u, _uf in got["events"]) < 4 * 18      # the events block: files only


def test_the_band_counts_archived_hours_from_its_start_and_to_its_end_only(env):
    _corpus(env, None)
    _archive_all(env)
    # From noon of the third day (its 13:00, 17:00 and 22:00 rows) on; then to 09:00 of the fourth (its 01:00, 05:00).
    lo = at(ARCHIVED[2], 12)
    win = summary.custom_window(lo, T0)
    with env.session() as db:
        got, note = archive.band_archive(db, win, summary.block_filters({"categories": ["files"]}), lo, None, T0,
                                         env.st)
        # The category mix leaves out the category filter: every archived row from the start on.
        assert sum(r[2] for r in got["categories"]) == 9 + 18
        assert note["oldest_day"] == ARCHIVED[0].isoformat()    # where the archive is, not where the band starts
        until = at(ARCHIVED[3], 9)
        got, _note = archive.band_archive(db, summary.custom_window(lo, until),
                                          summary.block_filters({"categories": ["files"]}), lo, until, T0, env.st)
        assert sum(r[2] for r in got["categories"]) == 9 + 6


def test_under_a_filter_the_aggregates_cannot_answer_a_block_counts_rows_only(env):
    _corpus(env, None)
    _archive_all(env)
    lo = at(ARCHIVED[0], 0)
    win = summary.custom_window(lo, T0)
    with env.session() as db:
        got, note = archive.band_archive(db, win, summary.block_filters({"username": "bob"}), lo, None, T0, env.st)
        assert got == {} and note["counted"] == [] and "events" in note["rows_only"]
        # The category mix leaves out only its own filter: a person filter keeps it on rows.
        got, note = archive.band_archive(db, win, summary.block_filters({"actions": ["login_failure"]}), lo, None, T0,
                                         env.st)
        assert note["counted"] == ["events", "categories", "sign_ins"]
        got, note = archive.band_archive(db, win, summary.block_filters({"ip": "203.0.113.9"}), lo, None, T0, env.st)
        assert note["counted"] == [] and note["rows_only"] == list(summary.OWN_FILTERS)
        # A range that reaches no archived hour: nothing to say.
        hot = summary.window("30d", T0)
        assert archive.band_archive(db, hot, summary.block_filters({}), hot.start, None, T0, env.st) == ({}, None)


@pytest.mark.parametrize("edit", [
    lambda agg: {k: v for k, v in agg.items() if k != "by_hour"},
    lambda agg: dict(agg, by_hour=[["2001-01-01T00:00:00Z", "x", "success", None, 1]]),
    lambda agg: dict(agg, by_hour=[agg["by_hour"][0][:4] + [0]]),
    lambda agg: dict(agg, by_hour=[agg["by_hour"][0][:4] + ["7"]]),
    lambda agg: dict(agg, by_hour=[agg["by_hour"][0][:3]]),
    lambda agg: dict(agg, by_hour="x"),
])
def test_aggregates_that_cannot_be_read_count_nothing_of_their_part(env, edit):
    _corpus(env, None)
    _archive_all(env)
    with env.session() as db:
        (agg,) = db.query(AuditArchiveBlock.aggregates).filter(AuditArchiveBlock.day == ARCHIVED[1]).one()
    _edit_block(env, ARCHIVED[1], aggregates=edit(dict(agg)))
    lo = at(ARCHIVED[0], 0)
    win = summary.custom_window(lo, T0)
    with env.session() as db:
        got, note = archive.band_archive(db, win, summary.block_filters({}), lo, None, T0, env.st)
    assert note["unreadable"] == [ARCHIVED[1].isoformat()]
    assert sum(r[2] for r in got["events"]) == 3 * 18


def test_all_time_starts_at_the_oldest_archived_part_the_events_block_counts(env):
    _corpus(env, None)
    _archive_all(env)
    assert archive.oldest_archived({}, None, env.st) == at(ARCHIVED[0], 1)
    assert archive.oldest_archived({"categories": ["files"]}, None, env.st) == at(ARCHIVED[0], 1)
    assert archive.oldest_archived({"username": "bob"}, None, env.st) is None
    assert archive.oldest_archived({}, at(ARCHIVED[0], 0), env.st) is None


# --------------------------------------------------------------------------- what the others say

def test_the_export_names_the_archived_days_it_left_out():
    note = {"oldest_day": "2026-07-01", "newest_day": "2026-07-04", "days": 4, "searched": False, "unreadable": [],
            "max_days": 31}
    lines = list(ev.export_lines(lambda after: ([], None), "csv", 0, head=None, archive=note))
    assert lines[-1].startswith("# Days up to 2026-07-04 are archived and not in this export.")
    searched = dict(note, searched=True, unreadable=[{"day": "2026-07-02", "reason": "block-altered"}])
    lines = list(ev.export_lines(lambda after: ([], None), "ndjson", 0, head=None, archive=searched))
    assert lines == ['{"archive": true, "message": "The archived day 2026-07-02 could not be read (block-altered), '
                     'so its events are not in this export."}\n']
    assert list(ev.export_lines(lambda after: ([], None), "ndjson", 0, head=None,
                                archive=dict(searched, unreadable=[]))) == []


def test_the_other_readers_are_told_where_the_archive_is(env):
    _corpus(env, None)
    assert archive.headers_for(None, None, env.st) == {}
    _archive_all(env)
    assert archive.headers_for(None, None, env.st) == {"X-Audit-Archive-Oldest-Day": ARCHIVED[0].isoformat(),
                                                      "X-Audit-Archive-Newest-Day": ARCHIVED[-1].isoformat()}
    assert archive.headers_for(at(HOT[0], 0), None, env.st) == {}
    assert archive.headers_for(None, at(ARCHIVED[0], 0), env.st) == {}
    assert archive.headers_for(at(ARCHIVED[2], 5), at(ARCHIVED[2], 6), env.st) != {}


def test_the_readers_of_rows_only_send_the_headers():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    api = (root / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    for route in ('@app.get("/audit/events")', '@app.get("/audit/log")'):
        body = api.split(route, 1)[1].split("\n@app.", 1)[0]
        assert body.count("activity_archive.headers_for(") == 1, route
    users = (root / "app" / "api" / "user_management_api.py").read_text(encoding="utf-8")
    body = users.split("async def get_user_activity(", 1)[1].split("\n@router.", 1)[0]
    assert "**activity_archive.headers_for(date_threshold.replace(tzinfo=None), None)" in body
    dash = (root / "app" / "api" / "dashboard_api.py").read_text(encoding="utf-8")
    body = dash.split("async def get_recent_events(", 1)[1].split("\n@router.", 1)[0]
    assert "response.headers.update(activity_archive.headers_for())" in body


def test_the_archived_days_an_export_read_are_recorded_as_a_count():
    from app.core import audit_privacy
    assert audit_privacy.kind_of("archived_days") == audit_privacy.IDENTIFIER
    from pathlib import Path
    api = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = api.split('@app.get("/activity/export")', 1)[1].split("\n@app.", 1)[0]
    assert '**({"archived_days": src.note["searched_days"]} if searched else {})' in body
    events = api.split('@app.get("/activity/events")', 1)[1].split("\n@app.", 1)[0]
    assert "except archive.TooBroad as exc:" in events and "status_code=400" in events
    assert 'out["archive"] = src.note' in events


def test_an_exports_close_waits_for_a_batch_in_flight_and_ends_the_search_once():
    import contextlib
    import threading
    closes = []
    stack = contextlib.ExitStack()
    stack.callback(lambda: closes.append(threading.current_thread().name))
    held = archive.Held(stack)
    started, release = threading.Event(), threading.Event()
    order = []

    def batch():
        started.set()
        release.wait(5)
        order.append("batch")
        return "rows"
    reader = threading.Thread(target=lambda: order.append(held.read(batch)), name="reader")
    reader.start()
    assert started.wait(5)
    closer = threading.Thread(target=lambda: (held.close(), order.append("closed")), name="closer")
    closer.start()
    closer.join(0.3)
    assert closer.is_alive() and closes == []           # the close waits for the batch in flight
    release.set()
    reader.join(5)
    closer.join(5)
    assert order == ["batch", "rows", "closed"] and closes == ["closer"]
    assert held.read(lambda: "more") is None             # nothing is read after the close
    held.close()
    assert closes == ["closer"]                          # closed once
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    export = src.split('@app.get("/activity/export")', 1)[1].split("\n@app.", 1)[0]
    assert "return held.read(lambda: from_search(after)) or ([], None)" in export
    assert "background=BackgroundTask(held.close)" in export
