"""Whether every SFTP server process runs this version (app/core/sftp_versions.py), offline.

Each SFTP process records its version in sftp_processes at start and while it runs, on a thread of its
own; the web app's sftp_same_version() answers yes when SFTP is off or every live process runs its
version, and no when a live process runs another or, while the deployment runs SFTP, none has recorded
itself (an older release never does). These run on a throwaway SQLite database;
test_sftp_versions_live.py checks the SFTP container of a running stack.
"""
import inspect
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import sftp_versions as SV  # noqa: E402
from app.core.models import SftpProcess  # noqa: E402

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 12, 1, 12, 0, 0)
# The web process's environment in each layout. The split profile and the trial compose start the web
# app on its own, beside an SFTP container; the trial compose does so with .env.example's values, which
# name the combined profile and leave RUN_SFTP empty. run_combined.py marks what it starts.
SPLIT = {"COMPOSE_PROFILES": "split", "RUN_SFTP": ""}
TRIAL = {"COMPOSE_PROFILES": "combined", "RUN_SFTP": ""}
COMBINED_WITH_SFTP = {"COMPOSE_PROFILES": "combined", "RUN_SFTP": "1", SV.COMBINED_SFTP_ENV: "on"}
NO_SFTP = {"COMPOSE_PROFILES": "combined", "RUN_SFTP": "", SV.COMBINED_SFTP_ENV: "off"}


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'sftp.db'}")
        SftpProcess.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _row(db, version, seen_seconds_ago, pid=None):
    seen = NOW - timedelta(seconds=seen_seconds_ago)
    db.add(SftpProcess(id=pid or f"p-{version}-{seen_seconds_ago}", version=version, host="h", started_at=seen,
                       seen_at=seen))
    db.commit()


def _check(factory, environ, version="0.34.0"):
    db = factory()
    try:
        return SV.sftp_same_version(db, now=NOW, environ=environ, version=version)
    finally:
        db.close()


# --------------------------------------------------------------------------- the answer

@pytest.mark.parametrize("environ", [SPLIT, TRIAL, COMBINED_WITH_SFTP, NO_SFTP])
def test_an_older_sftp_process_registered_and_live_means_no(factory, environ):
    db = factory()
    _row(db, "0.34.0", 10)
    _row(db, "0.33.9", 20)
    db.close()
    check = _check(factory, environ)
    assert (check.ok, check.reason, check.versions) == (False, SV.OTHER_VERSION, ("0.33.9",))
    assert "another version is running (0.33.9)" in check.explain()


@pytest.mark.parametrize("environ", [SPLIT, TRIAL, COMBINED_WITH_SFTP])
def test_none_registered_while_the_deployment_runs_sftp_means_no(factory, environ):
    # TRIAL is the trial compose: an SFTP container runs beside the web one whatever .env says, and one of
    # an older release never records itself. Answering "off" there would let the change through.
    check = _check(factory, environ)
    assert (check.ok, check.reason) == (False, SV.NONE_LIVE)
    assert "No SFTP server has reported its version" in check.explain()


def test_only_stale_rows_count_as_none(factory):
    db = factory()
    _row(db, "0.34.0", SV.LIVE_WITHIN_SECONDS + 1)
    _row(db, "0.33.9", SV.LIVE_WITHIN_SECONDS + 60)
    db.close()
    assert _check(factory, SPLIT).reason == SV.NONE_LIVE
    assert _check(factory, TRIAL).reason == SV.NONE_LIVE
    assert _check(factory, NO_SFTP) == SV.VersionCheck(True, SV.OFF)


def test_the_same_version_everywhere_means_yes(factory):
    db = factory()
    _row(db, "0.34.0", 5, pid="a")
    _row(db, "0.34.0", SV.LIVE_WITHIN_SECONDS - 1, pid="b")
    db.close()
    for environ in (SPLIT, TRIAL, COMBINED_WITH_SFTP, NO_SFTP):
        check = _check(factory, environ)
        assert (check.ok, check.reason, check.versions) == (True, SV.SAME, ("0.34.0",))


def test_sftp_off_and_nothing_registered_means_yes(factory):
    check = _check(factory, NO_SFTP)
    assert (check.ok, check.reason) == (True, SV.OFF)


@pytest.mark.parametrize("environ,runs", [
    # A web process that run_combined.py did not start: an SFTP container may run beside it, whatever
    # RUN_SFTP and COMPOSE_PROFILES say.
    ({}, True), (SPLIT, True), (TRIAL, True), ({"RUN_SFTP": "0"}, True), ({"COMPOSE_PROFILES": "combined"}, True),
    # Started by run_combined.py, which says whether it started SFTP beside it.
    (NO_SFTP, False), ({SV.COMBINED_SFTP_ENV: " Off "}, False), (COMBINED_WITH_SFTP, True),
    ({SV.COMBINED_SFTP_ENV: ""}, True), ({SV.COMBINED_SFTP_ENV: "0"}, True), ({SV.COMBINED_SFTP_ENV: "no"}, True),
])
def test_whether_the_deployment_runs_sftp(environ, runs):
    assert SV.deployment_runs_sftp(environ) is runs


def test_the_combined_launcher_says_whether_it_starts_sftp_and_the_web_app_reads_it(monkeypatch):
    import importlib
    import os
    import sys
    sys.path.insert(0, str(_ROOT))
    run_combined = importlib.import_module("run_combined")
    monkeypatch.setenv(SV.COMBINED_SFTP_ENV, "")          # so monkeypatch restores whatever the test writes
    monkeypatch.setenv("RUN_SFTP", "")
    assert run_combined.mark_combined_sftp() == "off"
    assert SV.deployment_runs_sftp(os.environ) is False
    # A value inherited from outside never stands: the launcher writes its own every time.
    monkeypatch.setenv("RUN_SFTP", "1")
    assert run_combined.mark_combined_sftp() == "on"
    assert os.environ[SV.COMBINED_SFTP_ENV] == "on"
    assert SV.deployment_runs_sftp(os.environ) is True
    monkeypatch.setenv("RUN_SFTP", "")
    monkeypatch.setenv(SV.COMBINED_SFTP_ENV, "on")
    assert run_combined.mark_combined_sftp() == "off"
    # ...and it does so before the first child is started, which takes a copy of the environment.
    src = inspect.getsource(run_combined.main)
    assert src.count("mark_combined_sftp()") == 1
    assert src.index("mark_combined_sftp()") < src.index("_spawn(")


def test_the_version_is_the_images_own_not_the_brands(monkeypatch):
    monkeypatch.setenv("BRAND_APP_VERSION", "9.9.9")
    assert SV.code_version() == (_ROOT / "VERSION").read_text(encoding="utf-8").strip()


# --------------------------------------------------------------------------- recording

def test_a_process_records_itself_then_refreshes_its_row(factory):
    db = factory()
    SV.record(db, "p1", version="0.34.0", host="c1", now=NOW - timedelta(seconds=90))
    SV.record(db, "p1", version="0.34.0", host="c1", now=NOW)
    row = db.get(SftpProcess, "p1")
    assert (row.version, row.host, row.started_at, row.seen_at) == ("0.34.0", "c1", NOW - timedelta(seconds=90), NOW)
    assert db.query(SftpProcess).count() == 1
    db.close()


def test_old_rows_are_pruned_and_a_stopping_process_forgets_its_own(factory):
    db = factory()
    _row(db, "0.33.9", SV.PRUNE_AFTER_DAYS * 86400 + 1, pid="gone")
    _row(db, "0.34.0", 60, pid="mine")
    _row(db, "0.34.0", 60, pid="theirs")
    assert SV.prune(db, now=NOW) == 1
    SV.forget(db, "mine")
    assert [r.id for r in db.query(SftpProcess).all()] == ["theirs"]
    db.close()


def test_the_recorder_records_at_once_and_again_on_its_own_thread(factory):
    recorder = SV.Recorder(factory, interval=0.05)
    thread = recorder.start()
    try:
        assert thread.daemon and thread.name == "version-record"
        deadline = time.monotonic() + 5
        seen = []
        while len(set(seen)) < 3 and time.monotonic() < deadline:
            db = factory()
            row = db.get(SftpProcess, recorder.process_id)
            if row is not None:
                seen.append(row.seen_at)
            db.close()
            time.sleep(0.02)
        assert len(set(seen)) >= 3, "the row was not refreshed"
        db = factory()
        row = db.get(SftpProcess, recorder.process_id)
        assert row.version == SV.code_version() and row.host == recorder.host
        db.close()
    finally:
        recorder.stop()
    assert not thread.is_alive() and recorder.recorded
    db = factory()
    assert db.get(SftpProcess, recorder.process_id) is None        # forgotten when it stopped
    db.close()


def test_the_recorder_prunes_when_it_starts(factory):
    db = factory()
    old = datetime.utcnow() - timedelta(days=SV.PRUNE_AFTER_DAYS + 1)
    db.add(SftpProcess(id="gone", version="0.33.9", started_at=old, seen_at=old))
    db.commit()
    db.close()
    recorder = SV.Recorder(factory, interval=10)
    recorder.start()
    try:
        deadline = time.monotonic() + 5
        while not recorder.recorded and time.monotonic() < deadline:
            time.sleep(0.02)
        db = factory()
        assert [r.id for r in db.query(SftpProcess).all()] == [recorder.process_id]
        db.close()
    finally:
        recorder.stop()


def test_a_database_that_does_not_answer_never_holds_up_the_server():
    entered, release = threading.Event(), threading.Event()

    def hanging():
        entered.set()
        release.wait(10)
        raise RuntimeError("no database")

    recorder = SV.Recorder(hanging, interval=10)
    t0 = time.monotonic()
    recorder.start()
    assert time.monotonic() - t0 < 1                     # start returns at once
    assert entered.wait(5)
    t0 = time.monotonic()
    recorder.stop()
    assert time.monotonic() - t0 < 2.5                   # and a stop never hangs on the database
    assert not recorder.recorded
    release.set()


def test_a_failed_record_is_tried_again_at_the_next_turn(factory):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("not yet")
        return factory()

    recorder = SV.Recorder(flaky, interval=0.05)
    recorder.start()
    try:
        deadline = time.monotonic() + 5
        while not recorder.recorded and time.monotonic() < deadline:
            time.sleep(0.02)
        assert recorder.recorded and len(calls) >= 2
    finally:
        recorder.stop()


# --------------------------------------------------------------------------- wiring

def test_the_sftp_server_records_its_version_and_forgets_it_when_it_stops():
    from app.sftp import sftp_server
    source = inspect.getsource(sftp_server.start_sftp_server)
    assert source.count("version_recorder = Recorder()") == 1 and source.count("version_recorder.start()") == 1
    # Started before the server listens, stopped after it has stopped accepting.
    assert source.index("version_recorder.start()") < source.index("server_socket.listen(")
    assert source.index("version_recorder.stop()") > source.index("server_socket.close()")


def test_the_heartbeat_thread_is_left_alone():
    # The heartbeat must never wait on the database: the version is recorded on a thread of its own.
    from app.sftp import heartbeat, sftp_server
    assert "sftp_versions" not in inspect.getsource(heartbeat)
    assert "sftp_versions" not in inspect.getsource(sftp_server._Liveness)
