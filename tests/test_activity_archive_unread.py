"""The readers of the chain's view in a process that has not read the chain through yet (app/services/activity_archive.py
"Before the view is read", app/core/audit_integrity.py read_view and read_at_start), offline, on a throwaway SQLite
database with a chain of its own (tests/_audit_chain_env.py):

- a process that has just started reads the chain before it answers a read of an archived day: the Events list's
  source reads the day's rows from the archive, the archive's summary names the day;
- while it cannot read it (the chain lock held past the wait, a chain that does not check out), every read that
  could reach an archived day is refused with a message that says why, and every read that cannot is answered from
  rows: a range younger than the shortest row window, a read of rows that are all rows; the readers of rows only
  send the unread header instead; a block in the table after a range's start makes the range one that could reach;
- a check that stops while the view holds seals up to the head record it has not verified leaves the view unread;
- the start's read, bounded, and what it says; the web process runs it before it serves;
- the routes: the Events list, the summary band and the export answer 503 with Retry-After (the export before it
  records or sends anything), the previews 503, and the erase and removal lists say a request is not known yet.

The same through a web process that has just started, on Postgres: tests/test_activity_archive_unread_live.py.
"""
import uuid
from datetime import datetime, time, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _audit_chain_env import Env, T0
from app.core import audit_archive as arc
from app.core import audit_integrity as ai
from app.core import retention
from app.core.models import AuditArchiveBlock
from app.services import activity_archive as archive

pytestmark = pytest.mark.unit

ARCHIVED = (T0 - timedelta(days=100)).date()
HOT = (T0 - timedelta(days=2)).date()


def at(day, hour, minute=0):
    return datetime.combine(day, time(hour, minute))


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _archived(env):
    """Rows on an archived day (three) and on a recent one (two), sealed and the old day archived. Returns the ids
    of the archived day's rows."""
    ids = {env.row(at(ARCHIVED, h, 17)) for h in (3, 9, 15)}
    for h in (8, 12):
        env.row(at(HOT, h, 5))
    env.run_until_sealed()
    for _ in range(3):
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert {arc._as_date(d) for (d,) in db.query(AuditArchiveBlock.day).all()} == {ARCHIVED}
    return ids


def _ids(src, start, end):
    e = src.entity
    return {r.id for r in src.db.query(e).filter(e.timestamp >= start, e.timestamp < end).all()}


class _Held:
    """The chain lock's mutex held by someone else, so that no read of the chain gets it."""

    def __init__(self, st, monkeypatch):
        monkeypatch.setattr(ai, "READ_WAIT_SECONDS", 0.05)
        self.st = st

    def __enter__(self):
        assert self.st.mutex.acquire(timeout=5)
        return self

    def __exit__(self, *exc):
        self.st.mutex.release()


# --------------------------------------------------------------------------- read before answering

def test_a_process_that_has_just_started_reads_the_chain_before_it_reads_an_archived_day(env):
    ids = _archived(env)
    st = env.fresh_process()
    assert st.view_read is False and st.view.position == 0
    lo, hi = at(ARCHIVED, 0), at(ARCHIVED, 0) + timedelta(days=1)
    with env.session() as db:
        with archive.source(db, lo, hi, st) as src:
            assert _ids(src, lo, hi) == ids
            assert src.note["searched"] is True and src.note["days"] == 1 and src.note["unreadable"] == []
    assert st.view_read is True and st.view.position == len(env.seals())
    summary = arc.summary(st)
    assert (summary["read"], summary["days"], summary["oldest_day"]) == (True, 1, ARCHIVED.isoformat())


def test_the_band_and_the_all_time_start_read_the_chain_first_too(env):
    _archived(env)
    st = env.fresh_process()
    with env.session() as db:
        assert archive.reaches_archive(at(ARCHIVED, 0), None, st, db=db) is True
    assert st.view_read is True
    st = env.fresh_process()
    with env.session() as db:
        assert archive.oldest_archived({}, None, st, db=db) == at(ARCHIVED, 3)
    st = env.fresh_process()
    from app.services import activity_summary as summary
    win = summary.custom_window(at(ARCHIVED, 0), at(HOT, 0), 0, None)
    with env.session() as db:
        got, note = archive.band_archive(db, win, summary.block_filters({}), at(ARCHIVED, 0), None, T0, st)
    assert sum(n for _b, _a, n, *_r in got["events"]) == 3 and note["days"] == 1


def test_the_archive_summary_says_it_is_not_known_until_the_chain_is_read(env):
    _archived(env)
    st = env.fresh_process()
    out = arc.summary(st)
    assert out["read"] is False
    assert all(out[k] is None for k in ("days", "oldest_day", "newest_day", "blocks", "bytes", "rows",
                                        "first_start", "starts_on"))
    assert out["hot_days"] == 90
    assert ai.read_view(env.engine, st) is True
    out = arc.summary(st)
    assert (out["read"], out["days"], out["blocks"], out["rows"]) == (True, 1, 1, 3)


# --------------------------------------------------------------------------- while the chain cannot be read

def test_while_the_chain_cannot_be_read_a_read_that_could_reach_an_archived_day_is_refused(env, monkeypatch):
    ids = _archived(env)
    st = env.fresh_process()
    hot = at(HOT, 0)
    with _Held(st, monkeypatch), env.session() as db:
        with pytest.raises(archive.Unread) as refused:
            with archive.source(db, at(ARCHIVED, 0), None, st):
                pass
        assert "has not finished reading the audit log's integrity chain" in str(refused.value)
        since = arc.unarchived_from(env.clock())
        assert f"choose a range that starts on or after {since:%Y-%m-%d}" in str(refused.value)
        with pytest.raises(archive.Unread):
            with archive.source(db, None, None, st):          # all time
                pass
        with pytest.raises(archive.Unread):
            with archive.source(db, since - timedelta(hours=1), None, st):
                pass
        # A range no archived day can reach, and a read of rows that are all rows, are answered from rows.
        with archive.source(db, hot, None, st) as src:
            assert src.note is None and src.db is db and len(_ids(src, hot, T0 + timedelta(days=1))) == 2
        with archive.source(db, since, None, st) as src:
            assert src.note is None
        with archive.source(db, None, None, st, rows_only=True) as src:
            assert src.note is None
        # The band, and what it is charted from.
        from app.services import activity_summary as summary
        win = summary.custom_window(at(ARCHIVED, 0), at(HOT, 0), 0, None)
        with pytest.raises(archive.Unread):
            archive.band_archive(db, win, summary.block_filters({}), at(ARCHIVED, 0), None, T0, st)
        with pytest.raises(archive.Unread):
            archive.band_archive(db, win, summary.block_filters({}), None, None, T0, st)
        recent = summary.window("7d", T0, 0, None)
        assert archive.band_archive(db, recent, summary.block_filters({}), recent.start, None, T0, st) == ({}, None)
        with pytest.raises(archive.Unread):
            archive.oldest_archived({}, None, st, db=db)
        with pytest.raises(archive.Unread):
            archive.reaches_archive(None, T0, st, db=db)
        assert archive.reaches_archive(hot, T0, st, db=db) is False
        with pytest.raises(archive.Unread):
            archive.archives(st)
        with pytest.raises(archive.Unread):
            archive.plan(at(ARCHIVED, 0), None, st)
        # The readers of rows only are never refused: they say the archived days are not known.
        assert archive.headers_for(None, None, st, db=db) == {archive.UNREAD_HEADER: "1"}
        assert archive.headers_for(at(ARCHIVED, 0), None, st, db=db) == {archive.UNREAD_HEADER: "1"}
        assert archive.headers_for(hot, None, st, db=db) == {}
    assert st.view_read is False
    # Once the lock is free, the same reads read the chain and answer from rows and archive.
    with env.session() as db:
        with archive.source(db, at(ARCHIVED, 0), at(ARCHIVED, 0) + timedelta(days=1), st) as src:
            assert _ids(src, at(ARCHIVED, 0), at(ARCHIVED, 0) + timedelta(days=1)) == ids
        assert archive.headers_for(None, None, st, db=db) == {archive.ARCHIVE_HEADERS[0]: ARCHIVED.isoformat(),
                                                             archive.ARCHIVE_HEADERS[1]: ARCHIVED.isoformat()}


def test_a_block_after_the_start_of_a_range_makes_it_one_that_could_reach_an_archived_day(env):
    _archived(env)
    early = at(ARCHIVED, 0) + timedelta(days=10)          # a clock that reads ten days after the archived day
    with env.session() as db:
        assert arc.unarchived_from(early) < at(ARCHIVED, 0)
        assert archive.could_reach(db, at(ARCHIVED, 0), None, early) is True       # the block is there
        assert archive.could_reach(db, at(ARCHIVED, 0) + timedelta(days=1), None, early) is False
        assert archive.could_reach(db, at(ARCHIVED, 0) - timedelta(days=1), at(ARCHIVED, 0), early) is False
        assert archive.could_reach(db, None, None, early) is True
        assert archive.could_reach(None, at(ARCHIVED, 0), None, early) is False     # with no table, the date only


def test_the_shortest_row_window_bounds_the_archived_days(env):
    assert arc.HOT_DAYS_LEAST == 31
    from app.core import settings_registry as reg
    assert reg.spec_for(arc.HOT_DAYS_KEY).minimum == arc.HOT_DAYS_LEAST
    assert arc.unarchived_from(datetime(2026, 11, 8, 13, 30)) == datetime(2026, 10, 8)
    # The archive job takes no day younger than the row window, whatever the clock: none from that day on.
    _archived(env)
    with env.session() as db:
        newest = max(r for (r,) in db.query(AuditArchiveBlock.last_hour).all())
    assert newest < arc.unarchived_from(env.clock())


# --------------------------------------------------------------------------- a chain that does not check out

def _tamper_one_seal(env, seq=2):
    with env.engine.begin() as c:
        c.exec_driver_sql(f"UPDATE audit_seals SET row_bytes = row_bytes + 1 WHERE seq = {seq}")


def test_a_check_that_stops_before_the_record_s_link_leaves_the_view_unread(env):
    _archived(env)
    rec_seq = len(env.seals())
    _tamper_one_seal(env)
    st = env.fresh_process()
    assert ai.read_view(env.engine, st) is False
    # It accepted the seals before the record's own, and stopped there: none of them is trusted.
    assert st.view.position == rec_seq - 1 and st.read_stopped == "head-record-mismatch"
    assert st.view_read is False
    with env.session() as db:
        with pytest.raises(archive.Unread) as refused:
            with archive.source(db, at(ARCHIVED, 0), None, st):
                pass
    text = str(refused.value)
    assert "does not check out (head-record-mismatch)" in text and "Try again" not in text
    assert arc.summary(st)["read"] is False


def _sealed_elsewhere(env):
    """Another process seals more and moves the head record on. Returns the newest seal before and after."""
    other = ai.ChainState(settings=env.settings, clock=env.clock)
    env.row(env.clock() - timedelta(minutes=30))
    env.clock.advance(hours=3)
    before = len(env.seals())
    for _ in range(20):
        r = ai.seal_pass(env.session, engine=env.engine, st=other, now=env.clock())
        if r.stopped or not r.sealed:
            break
    after = len(env.seals())
    assert after >= before + 2
    return before, after


def test_a_view_read_before_is_unread_again_when_a_later_check_stops_on_the_seals_it_accepted(env):
    _archived(env)
    first = env.st
    assert first.view_read is True
    before, after = _sealed_elsewhere(env)
    _tamper_one_seal(env, before + 1)               # a seal before the new head, changed
    with pytest.raises(ai.ChainStopped) as stop:
        with ai.ChainWriter(env.engine, first, check_key=False):
            pass
    assert stop.value.kind == "head-record-mismatch"
    assert first.view_read is False and first.view.position == after - 1


def test_a_check_that_stops_before_it_accepts_a_seal_leaves_a_read_view_as_it_was(env):
    """What the view holds was verified when it was read: a check that stops before it accepts anything more takes
    nothing from it, whether it stops before it reads the seals after the view's (the view's own seal gone) or on
    the first of them (a gap)."""
    _archived(env)
    first = env.st
    assert first.view_read is True
    before, after = _sealed_elsewhere(env)
    with env.engine.begin() as c:
        c.exec_driver_sql(f"DELETE FROM audit_seals WHERE seq = {before + 1}")
    with pytest.raises(ai.ChainStopped) as stop:
        with ai.ChainWriter(env.engine, first, check_key=False):
            pass
    assert stop.value.kind == "seq-gap"
    assert first.view_read is True and first.view.position == before
    with env.engine.begin() as c:
        c.exec_driver_sql(f"DELETE FROM audit_seals WHERE seq = {before}")
    with pytest.raises(ai.ChainStopped) as stop:
        with ai.ChainWriter(env.engine, first, check_key=False):
            pass
    assert stop.value.kind == "head-record-mismatch"
    assert first.view_read is True and first.view.position == before


def test_a_check_that_starts_the_view_again_leaves_it_unread_until_it_has_read_it_through(env):
    """A head record of a later generation (a restore accepted, a discard) starts the view again from the first seal:
    until a check has read it through, it is not read, however it was before."""
    import json
    _archived(env)
    st = env.st
    assert st.view_read is True
    path = st.head_store().path
    with open(path, encoding="utf-8") as fh:
        record = json.load(fh)
    record["discards"] = int(record.get("discards") or 0) + 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh)
    with env.engine.begin() as c:
        c.exec_driver_sql("DELETE FROM audit_seals WHERE seq = 1")
    with pytest.raises(ai.ChainStopped) as stop:
        with ai.ChainWriter(env.engine, st, check_key=False):
            pass
    assert stop.value.kind == "seq-gap"
    assert st.view.position == 0 and st.view_read is False


def test_the_status_takes_the_seals_warnings_from_the_record_while_the_view_is_not_read(env):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    env.row(ai.hour_floor(T0 - timedelta(hours=3, minutes=10)) + timedelta(minutes=40))
    env.clock.advance(minutes=20)
    assert env.seal().late == 1
    late = env.st.view.late_seqs[-1]
    assert late == len(env.seals())                       # the newest seal
    _tamper_one_seal(env, 1)
    st = env.fresh_process()
    assert ai.read_view(env.engine, st) is False and st.view.position == late - 1
    assert ai.status(st)["warnings"]["late"]["seqs"] == [late]


def test_the_storage_card_counts_nothing_from_a_view_that_is_not_read(env, monkeypatch):
    from app.core import audit_retention as ar
    from app.core import retention_storage
    _archived(env)
    monkeypatch.setattr(ar, "current", lambda: ar.Numbers(0, 0, 0, 100))
    assert retention_storage.cap_counted(env.clock(), env.st)["counted_bytes"] is not None
    _tamper_one_seal(env)
    st = env.fresh_process()
    assert ai.read_view(env.engine, st) is False and st.view.position > 0
    assert retention_storage.cap_counted(env.clock(), st)["counted_bytes"] is None


# --------------------------------------------------------------------------- the start's read

def test_the_start_reads_the_chain_and_says_so(env, capsys):
    _archived(env)
    st = env.fresh_process()
    assert ai.read_at_start(env.engine, st, timeout=10) is True
    assert st.view_read is True and st.view.position == len(env.seals())
    assert f"[OK] The audit log's integrity chain was read ({len(env.seals())} seals" in capsys.readouterr().out


def test_a_start_whose_read_does_not_finish_in_time_goes_on_and_says_so(env, capsys):
    _archived(env)
    st = env.fresh_process()
    assert st.mutex.acquire(timeout=5)
    try:
        assert ai.read_at_start(env.engine, st, timeout=0.2) is False
        assert st.view_read is False
    finally:
        st.mutex.release()
    out = capsys.readouterr().out
    assert "was not read within 0 s of the start" in out or "could not be read at the start;" in out
    assert ai.read_view(env.engine, st) is True


def test_a_start_whose_chain_does_not_check_out_goes_on_and_says_why(env, capsys):
    _archived(env)
    _tamper_one_seal(env)
    st = env.fresh_process()
    assert ai.read_at_start(env.engine, st, timeout=10) is False
    assert "could not be read at the start (sealing would stop: head-record-mismatch)" in capsys.readouterr().out
    assert st.stopped is None                 # the pruner's pass decides and reports the stop, as before


def test_a_reader_that_comes_while_the_chain_is_being_read_waits_for_it(env):
    import threading
    _archived(env)
    st = env.fresh_process()
    assert st.mutex.acquire(timeout=5)                    # a read under way (the start's, a pass)
    threading.Timer(0.5, st.mutex.release).start()
    with env.session() as db:
        with archive.source(db, at(ARCHIVED, 0), None, st) as src:
            assert src.note["searched"] is True
    assert st.view_read is True


def test_a_read_finds_no_chain_on_a_new_database_and_that_is_a_read_view(env):
    st = env.fresh_process()
    assert ai.read_view(env.engine, st) is True and st.view.position == 0
    with env.session() as db:
        with archive.source(db, None, None, st) as src:
            assert src.note is None


def test_the_web_process_reads_the_chain_before_it_serves():
    from pathlib import Path
    api = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = api.split("async def lifespan(app: FastAPI):", 1)[1].split("\n    yield\n", 1)[0]
    call = "await asyncio.to_thread(audit_integrity.read_at_start, _require_engine())"
    assert body.count(call) == 1
    assert body.index("settings_registry.start()") < body.index(call)


# --------------------------------------------------------------------------- the routes

ADMIN = SimpleNamespace(id="a-1", username="alice", role="admin")


class _Db:
    """A request's session that reads nothing: no engine to read the chain over."""

    def query(self, *_a):
        return None

    def rollback(self):
        pass


@pytest.fixture
def unread(monkeypatch):
    """The process's chain state, not read, with no way to read it."""
    st = ai.ChainState()
    monkeypatch.setattr(ai, "_state", st)
    return st


def test_the_events_list_and_the_band_answer_503_while_the_archived_days_cannot_be_told(unread, monkeypatch):
    from app.api import activity_search_router as r
    from app.services import activity_summary as summary
    monkeypatch.setattr(summary, "_cache", type(summary._cache)())
    with pytest.raises(HTTPException) as refused:
        r.search_events(body=r.EventsSearch(), request=None, current_user=ADMIN, db=_Db())
    assert refused.value.status_code == 503 and refused.value.headers == {"Retry-After": "60"}
    assert refused.value.detail.startswith("The archived days of the audit log cannot be read yet")
    with pytest.raises(HTTPException) as refused:
        r.search_summary(body=r.SummarySearch(range="all"), current_user=ADMIN, db=_Db())
    assert refused.value.status_code == 503 and refused.value.headers == {"Retry-After": "60"}
    assert summary._cache == {}


def test_an_export_that_could_reach_an_archived_day_is_refused_before_it_is_recorded(unread, monkeypatch):
    from app.api import activity_search_router as r
    from app.api import api_server as api
    written = []

    class _Logger:
        def __init__(self, _db):
            pass

        def log_action(self, **row):
            written.append(row)

    monkeypatch.setattr(api, "AuditLogger", _Logger)
    with pytest.raises(HTTPException) as refused:
        r.export_events(body=r.ExportSearch(), request=None, current_user=ADMIN, db=_Db())
    assert refused.value.status_code == 503 and refused.value.headers == {"Retry-After": "60"}
    assert written == []


def test_the_previews_answer_503_while_the_chain_cannot_be_read(unread):
    from app.api import audit_integrity_router as r
    with pytest.raises(HTTPException) as refused:
        r.require_chain_read(SimpleNamespace(get_bind=lambda: None), "What an erase would change")
    assert refused.value.status_code == 503 and refused.value.headers == {"Retry-After": "60"}
    assert refused.value.detail == ("What an erase would change cannot be told yet: this server has not finished "
                                    "reading the audit log's integrity chain since it started. Try again in a minute.")
    unread.read_stopped = "seq-gap"
    with pytest.raises(HTTPException) as refused:
        r.require_chain_read(SimpleNamespace(get_bind=lambda: None), "What an erase would change")
    assert "(seq-gap)" in refused.value.detail and "Try again" not in refused.value.detail
    unread.view_read = True
    assert r.require_chain_read(SimpleNamespace(get_bind=lambda: None), "What an erase would change") is None


def test_the_routes_that_read_the_view_read_the_chain_first():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "app" / "api"

    def body(path, head):
        text = (root / path).read_text(encoding="utf-8")
        return text.split(head, 1)[1].split("\n@router.", 1)[0]
    for path, head, call in (
            ("audit_integrity_router.py", 'def get_integrity(', "audit_integrity.read_view(db.get_bind())"),
            ("managed_settings_router.py", "def get_managed_settings(", "audit_integrity.read_view(db.get_bind())"),
            ("managed_settings_router.py", "def managed_storage(", "audit_integrity.read_view(db.get_bind())"),
            ("managed_settings_router.py", "def preview_audit_retention(",
             'require_chain_read(db, "What the audit job would delete")'),
            ("person_erase_router.py", "def list_erase_requests(", "audit_integrity.read_view(db.get_bind())"),
            ("person_erase_router.py", "def preview_erase(", "require_chain_read(db, "),
            ("value_removal_router.py", "def list_removals(", "audit_integrity.read_view(db.get_bind())"),
            ("value_removal_router.py", "def preview_removal(", "require_chain_read(db, ")):
        b = body(path, head)
        assert b.count(call) == 1, (path, head)


def test_a_request_the_view_does_not_hold_is_not_known_until_the_chain_is_read(env):
    from app.core import audit_value_removal as removal
    from app.core import person_erase as pe
    now = env.clock()
    erase = SimpleNamespace(id=uuid.uuid4(), status="pending", placeholder="erased-0000abcd", requested_by_name="a",
                            requested_at=now, effective_at=now, started_at=None, completed_at=None,
                            decided_by_name=None, decided_at=None, waiting=None, counts=None)
    remove = SimpleNamespace(id=uuid.uuid4(), status="pending", levels={"ip": "none"}, before=now,
                             requested_by_name="a", requested_at=now, effective_at=now, started_at=None,
                             completed_at=None, decided_by_name=None, decided_at=None, waiting=None, counts=None)

    class _Rows:
        def __init__(self, rows):
            self.rows = rows

        def query(self, *_a):
            rows = self.rows
            return SimpleNamespace(order_by=lambda *_x: SimpleNamespace(
                limit=lambda _n: SimpleNamespace(all=lambda: rows)))
    st = ai.ChainState(settings=env.settings, clock=env.clock)
    assert [e["status"] for e in pe.listing(_Rows([erase]), st)] == [pe.UNREAD]
    assert [e["status"] for e in removal.listing(_Rows([remove]), st)] == [removal.UNREAD]
    assert pe.listing(_Rows([erase]), st)[0]["cancellable"] is False
    st.view_read = True
    assert [e["status"] for e in pe.listing(_Rows([erase]), st)] == ["not recorded"]
    assert [e["status"] for e in removal.listing(_Rows([remove]), st)] == ["not recorded"]


def test_the_pages_say_what_is_not_known_yet():
    from pathlib import Path
    js = Path(__file__).resolve().parents[1] / "static" / "js"
    for name in ("settings-erase.js", "settings-removal.js"):
        text = (js / name).read_text(encoding="utf-8")
        assert text.count("unread: 'Not known yet'") == 1, name
        assert text.count("status === 'unread'") == 1, name
    for name in ("audit-integrity.js", "settings-integrity.js", "settings-retention.js"):
        text = (js / name).read_text(encoding="utf-8")
        assert text.count("a.read === false") == 1, name
        assert text.count("Which audit days are archived is not known yet") == 1, name
