"""The retention screen's Storage card (app/core/retention_storage.py, GET /settings/managed/storage), offline, on a
throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py): the rows and the archive, what the
size cap counts and the warning from 80 % of it, the files' volume, and whether the install ran before this
release. And the screen's page (static/js/settings-retention.js, static/index.html): where it is, what it reads,
and that it builds the page with text only."""
import re
from datetime import datetime, time, timedelta
from pathlib import Path

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_archive as arc
from app.core import audit_retention as ar
from app.core import retention
from app.core import retention_storage as rs
from app.core.models import AuditArchiveBlock

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
OLD = (T0 - timedelta(days=100)).date()


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _rows(env, day, n):
    for i in range(n):
        env.row(datetime.combine(day, time(3, i % 60)))


def test_rows_archive_and_no_cap(env, tmp_path):
    _rows(env, OLD, 6)
    _rows(env, (T0 - timedelta(days=2)).date(), 4)
    env.run_until_sealed()
    with env.session() as db:
        out = rs.summary(db, T0, str(tmp_path), env.st)
    assert out["rows"] == {"count": 10, "exact": True, "bytes": None,
                           "oldest": datetime.combine(OLD, time(3, 0)).isoformat() + "Z"}
    assert out["archive"] == {"blocks": 0, "rows": 0, "bytes": 0, "table_bytes": None}
    assert out["cap"] is None and out["database_volume"] is None
    assert out["storage_volume"]["total"] >= out["storage_volume"]["free"] > 0
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        out = rs.summary(db, T0, str(tmp_path), env.st)
        (length,) = db.query(arc._length(AuditArchiveBlock.payload, db)).one()
    assert out["rows"]["count"] == 4
    assert out["rows"]["oldest"] == datetime.combine((T0 - timedelta(days=2)).date(), time(3, 0)).isoformat() + "Z"
    assert out["archive"] == {"blocks": 1, "rows": 6, "bytes": length, "table_bytes": None}
    assert failures(env.verify()) == []


def test_the_cap_and_what_it_counts_with_a_warning_from_80_percent(env, tmp_path, monkeypatch):
    for d in range(3, 9):
        _rows(env, (T0 - timedelta(days=d)).date(), 5)
    env.run_until_sealed()
    # The cap counts an hour's bytes once sealing has run for a delay (seven days) after it.
    end = env.clock() + timedelta(days=8)
    while env.clock() + timedelta(hours=6) <= end:
        env.clock.advance(hours=6)
        env.seal()
    monkeypatch.setattr(ar, "current", lambda: ar.Numbers(0, 0, 365, 1))
    now = env.clock()
    with env.session() as db:
        cap = rs.summary(db, now, str(tmp_path), env.st)["cap"]
    assert cap["cap_bytes"] == ar.MB and cap["counted_bytes"] > 0
    assert cap["fraction"] == round(cap["counted_bytes"] / ar.MB, 4) and cap["warn"] is False
    # From 80 % of the cap on, the page warns; below it, it does not.
    counted = cap["counted_bytes"]
    monkeypatch.setattr(rs, "WARN_AT", counted / ar.MB)
    assert rs.cap_counted(now, env.st)["warn"] is True                # exactly at it
    monkeypatch.setattr(rs, "WARN_AT", counted / ar.MB + 1e-9)
    assert rs.cap_counted(now, env.st)["warn"] is False
    monkeypatch.setattr(rs, "WARN_AT", 0.8)
    monkeypatch.setattr(ar, "MB", int(counted / 0.8))
    assert rs.cap_counted(now, env.st)["warn"] is True
    monkeypatch.setattr(ar, "MB", int(counted / 0.8) + 2)
    assert rs.cap_counted(now, env.st)["warn"] is False


def test_the_card_counts_what_the_pruner_counts_with_another_writers_inflated_hour_held_back(env, monkeypatch):
    """Another writer's prune seal records 50 MB for an hour of 0.1 MB, and the host has not acknowledged it: the
    card counts the hour's 0.1 MB, as the pruner's plan does (on the server, with the seal held back), not 50 MB
    as a count without the held-back seals, or off the server, would."""
    from app.core import audit_integrity as ai
    from app.core.models import AuditLog
    from test_audit_chain_size import KB, _big, _inflate
    from test_audit_chain_trust import _run_to
    target = T0 - timedelta(days=20)
    _big(env, target, 100)
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    monkeypatch.setattr(ar, "current", lambda: ar.Numbers(0, 0, 365, 1))
    before = rs.cap_counted(env.clock(), env.st)["counted_bytes"]
    assert 100 * KB <= before < ar.MB
    inflated = _inflate(env, ai.hour_floor(target), 50 * 1024 * KB)
    retention.run_pass(env.session, now=env.clock())          # accepted as a warning, not acknowledged
    assert inflated in ai.unacknowledged_foreign(env.st.view, env.st.known_record())
    now = env.clock()
    shown = rs.cap_counted(now, env.st)
    with env.session() as db:
        plan = ar.chain_size_plan(db, AuditLog, env.st.view, env.st.known_record(), now, ar.current(), ar._delay())
    assert shown["counted_bytes"] == plan.counted_bytes == before and inflated in plan.size["held_back"]
    assert shown["warn"] is False


def test_the_warning_is_on_the_bytes_now_and_says_when_the_cap_would_start_deleting(env, monkeypatch, tmp_path):
    """A large row lands in the current hour: before it is sealed the bytes now count it and the card warns at once,
    though the cap counts nothing new; once sealed, the card says from when the cap would delete (the hour's seal
    plus the delay)."""
    from test_audit_chain_size import KB, _big, _sealed_at
    from test_audit_chain_trust import _run_to
    for h in range(3):
        _big(env, T0 - timedelta(days=30, hours=h), 200)
    env.run_until_sealed()
    _run_to(env, T0 + timedelta(days=8))
    monkeypatch.setattr(ar, "current", lambda: ar.Numbers(0, 0, 365, 1))

    def card():
        with env.session() as db:
            return rs.summary(db, env.clock(), str(tmp_path), env.st)["cap"]
    quiet = card()
    assert 0 < quiet["counted_bytes"] <= quiet["now_bytes"] < 0.8 * ar.MB and quiet["warn"] is False
    assert quiet["over_from"] is None
    at = env.clock() - timedelta(minutes=10)
    _big(env, at, 700)
    grown = card()
    assert grown["counted_bytes"] == quiet["counted_bytes"]
    assert grown["now_bytes"] >= quiet["now_bytes"] + 700 * KB and grown["warn"] is True
    assert grown["fraction"] == round(grown["now_bytes"] / ar.MB, 4) and grown["over_from"] is None
    assert rs.cap_counted(env.clock(), env.st)["now_bytes"] < quiet["now_bytes"] + 700 * KB  # rows not sealed left out
    _run_to(env, env.clock() + timedelta(hours=3))
    sealed = card()
    assert sealed["counted_bytes"] < ar.MB < sealed["now_bytes"] and sealed["warn"] is True
    over = datetime.fromisoformat(sealed["over_from"].rstrip("Z"))
    assert abs(over - (_sealed_at(env, at) + timedelta(days=7))) < timedelta(seconds=1)


def test_when_the_cap_would_start_deleting_counts_the_archived_days_too(env, monkeypatch):
    """Archived days count their parts' figures, which do not change; a large row in the current hour then
    takes the count over a limit from its hour's seal plus the delay, and over the bytes now never, on what is
    sealed now. The figure is the earliest: the pruner's own count is at most the limit just before it and over
    it just after."""
    from app.core import audit_chain_size as size
    from test_audit_chain_size import KB, _big, _sealed_at
    from test_audit_chain_trust import _run_to
    import os
    for h in range(4):              # what does not compress: an archived part counts its block's length
        env.row(datetime.combine(OLD, time(h, 0)), details={"blob": os.urandom(75 * KB).hex()})
    env.run_until_sealed()
    for _ in range(3):
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.st.view.archives, "nothing was archived"
    _run_to(env, T0 + timedelta(days=8))
    at = env.clock() - timedelta(minutes=10)
    _big(env, at, 300)
    _run_to(env, env.clock() + timedelta(hours=3))
    st, now, delay = env.st, env.clock(), timedelta(days=7)
    parts = sum(c for _d, _p, c, _h in size.counted(st.view, size.window_start(st.view, st.known_record(), now,
                                                                                delay), set())[1])
    grown = size.now_count(st.view, st.known_record(), now)
    counted = size.cap_count(st.view, st.known_record(), now, delay)[4]
    assert parts >= 200 * KB and counted < grown and grown - counted >= 300 * KB
    limit = grown - 100 * KB                 # passed only once the large row counts, and only with the archive
    over = size.first_over(st.view, st.known_record(), now, delay, limit)
    assert over is not None and abs(over - (_sealed_at(env, at) + delay)) < timedelta(seconds=1)
    assert size.first_over(st.view, st.known_record(), now, delay, grown) is None
    assert size.first_over(st.view, st.known_record(), now, delay, counted - 1) == now
    _run_to(env, over - timedelta(hours=1))
    assert size.cap_count(st.view, st.known_record(), env.clock(), delay)[4] <= limit
    _run_to(env, over + timedelta(hours=1))
    assert size.cap_count(st.view, st.known_record(), env.clock(), delay)[4] > limit


def test_a_cap_before_the_chain_has_a_view_counts_nothing_yet(env, monkeypatch):
    monkeypatch.setattr(ar, "current", lambda: ar.Numbers(0, 0, 365, 5))
    env.fresh_process()
    assert rs.cap_counted(T0, env.st) == {"cap_bytes": 5 * ar.MB, "counted_bytes": None, "now_bytes": None,
                                          "fraction": None, "warn": False, "over_from": None}


def test_a_volume_that_cannot_be_read_is_unknown(tmp_path):
    assert rs.volume(str(tmp_path / "nowhere")) is None
    assert set(rs.volume(str(tmp_path))) == {"total", "used", "free"}


def test_an_install_with_rows_from_before_this_release_is_told_what_changed(env):
    with env.session() as db:
        assert rs.existing_install(db, env.st) is False          # nothing sealed yet
    _rows(env, OLD, 2)
    env.run_until_sealed()
    with env.session() as db:
        assert rs.existing_install(db, env.st) is True


def test_an_install_that_started_with_this_release_is_not(env):
    env.run_until_sealed()                                       # genesis on an empty log
    env.clock.advance(hours=3)
    _rows(env, env.clock().date(), 1)
    env.clock.advance(hours=3)
    env.run_until_sealed()
    with env.session() as db:
        assert rs.existing_install(db, env.st) is False


def test_the_route_is_admin_only_bounded_and_reads_the_storage_path():
    src = (ROOT / "app" / "api" / "managed_settings_router.py").read_text(encoding="utf-8")
    body = src.split('@router.get("/settings/managed/storage")', 1)[1].split("\n@router.", 1)[0]
    assert "Depends(require_interactive_admin)" in body and "limit_statements(db)" in body
    assert "config.settings.file_storage_path" in body and body.count("retention_storage.summary(") == 1


def test_the_page_has_the_screen_and_builds_it_with_text_only():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    tab = html.split('id="settings-tab-records"', 1)[1]
    for marker in ('id="retention-banner"', 'id="retention-groups"', 'id="retention-pending"',
                   'id="retention-storage"'):
        assert marker in tab, marker
    assert tab.index('id="retention-card"') < tab.index('id="recording-levels-card"')
    assert re.search(r'<script src="/static/js/settings-retention\.js\?v=\d+[a-z]"></script>', html)
    js = (ROOT / "static" / "js" / "settings-retention.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js
    for route in ("'/settings/managed'", "'/settings/managed/storage'", "/settings/managed/audit/preview?",
                  "/settings/managed/changes/", "'/activity/integrity'"):
        assert route in js, route
