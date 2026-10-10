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


def test_a_cap_before_the_chain_has_a_view_counts_nothing_yet(env, monkeypatch):
    monkeypatch.setattr(ar, "current", lambda: ar.Numbers(0, 0, 365, 5))
    env.fresh_process()
    assert rs.cap_counted(T0, env.st) == {"cap_bytes": 5 * ar.MB, "counted_bytes": None, "fraction": None,
                                          "warn": False}


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
