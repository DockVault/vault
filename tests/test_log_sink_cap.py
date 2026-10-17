"""The log-access file's size (LOG_PULL_SINK_MAX_MB), offline.

The file the log pull reads, with its two older copies, holds LOG_PULL_SINK_MAX_MB in all (15 by default, 3 to
1000), read in both places that write it: the combined launcher (run_combined.py) and the web app's own writer in
the split layout (app/services/log_sink.py). A value outside the bounds is read as the default there (the web app
refuses to start with it). Whatever the cap, a log pull reads at most the newest 5 MB of the file, from a whole
line. The recording notice says how much the file keeps, and how long notifications are kept.
"""
import importlib
import json
import logging
import logging.handlers
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MB = 1024 * 1024


def _sink():
    return importlib.import_module("app.services.log_sink")


@pytest.mark.parametrize("given, per_file", [
    (None, 5 * MB), ("15", 5 * MB), ("30", 10 * MB), ("3", MB), ("1000", 1000 * MB // 3), (" 60 ", 20 * MB)])
def test_the_cap_is_split_over_the_file_and_its_two_older_copies(given, per_file):
    env = {} if given is None else {"LOG_PULL_SINK_MAX_MB": given}
    assert _sink().sink_limits(env) == (per_file, 2)


@pytest.mark.parametrize("given", ["", "abc", "2", "1001", "-5", "1e3", "15.5", "0"])
def test_a_value_outside_the_bounds_is_read_as_the_default(given):
    assert _sink().sink_limits({"LOG_PULL_SINK_MAX_MB": given}) == (5 * MB, 2)


def test_both_writers_read_the_cap_from_the_environment(tmp_path):
    code = ("import json, run_combined\nfrom app.services import log_sink\n"
            "print(json.dumps([run_combined._SINK_MAX_BYTES, run_combined._SINK_BACKUPS, log_sink._SINK_MAX_BYTES, "
            "log_sink._SINK_BACKUPS]))")
    for given, want in (("30", 10 * MB), (None, 5 * MB)):
        env = {k: v for k, v in os.environ.items() if k != "LOG_PULL_SINK_MAX_MB"}
        env["LOG_PULL_SINK_PATH"] = str(tmp_path / "combined.log")
        if given is not None:
            env["LOG_PULL_SINK_MAX_MB"] = given
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True,
                             timeout=60)
        assert out.returncode == 0, out.stderr
        assert json.loads(out.stdout.strip().splitlines()[-1]) == [want, 2, want, 2]


def _fill(write, lines):
    for i in range(lines):
        write(f"[web] 2026-10-20T12:00:00.000000Z line {i:07d} " + "x" * 200)


def _sizes(tmp_path):
    return {p.name: p.stat().st_size for p in tmp_path.iterdir()}


def test_the_launchers_sink_stops_growing_at_its_cap(tmp_path, monkeypatch):
    rc = importlib.import_module("run_combined")
    per_file, backups = _sink().sink_limits({"LOG_PULL_SINK_MAX_MB": "3"})
    monkeypatch.setattr(rc, "_SINK_PATH", str(tmp_path / "combined.log"))
    monkeypatch.setattr(rc, "_SINK_MAX_BYTES", per_file)
    monkeypatch.setattr(rc, "_SINK_BACKUPS", backups)
    monkeypatch.setattr(rc, "_sink_logger", None)
    rc._init_sink()
    try:
        _fill(rc._sink_logger.info, 40000)          # about 9 MB through a 3 MB cap
    finally:
        for h in list(rc._sink_logger.handlers):
            h.close()
        rc._sink_logger.handlers = []
    sizes = _sizes(tmp_path)
    assert sorted(sizes) == ["combined.log", "combined.log.1", "combined.log.2"]
    assert sum(sizes.values()) <= 3 * MB and sum(sizes.values()) > 2 * MB
    assert all(size <= per_file for size in sizes.values())


def test_the_web_apps_own_sink_stops_growing_at_its_cap(tmp_path, monkeypatch):
    sink = _sink()
    per_file, backups = sink.sink_limits({"LOG_PULL_SINK_MAX_MB": "3"})
    monkeypatch.setattr(sink, "_SINK_PATH", str(tmp_path / "combined.log"))
    monkeypatch.setattr(sink, "_SINK_MAX_BYTES", per_file)
    monkeypatch.setattr(sink, "_SINK_BACKUPS", backups)
    monkeypatch.setattr(sink, "_active", False)
    monkeypatch.setattr(sink, "_sink_logger", None)
    monkeypatch.setattr(sink, "_writer_started", True)      # no writer thread: the test writes itself
    assert sink.init_sink() is True
    logger = sink._sink_logger
    try:
        _fill(logger.info, 40000)
    finally:
        for h in list(logger.handlers):
            h.close()
        logger.handlers = []
    sizes = _sizes(tmp_path)
    assert sorted(sizes) == ["combined.log", "combined.log.1", "combined.log.2"]
    assert sum(sizes.values()) <= 3 * MB and sum(sizes.values()) > 2 * MB


def _lines_file(path, count, width=100):
    with open(path, "wb") as f:
        for i in range(count):
            f.write((f"[web] line {i:07d} ".ljust(width - 1, "y") + "\n").encode())


def test_a_small_file_is_read_whole(tmp_path):
    path = tmp_path / "combined.log"
    _lines_file(path, 50)
    text = _sink().read_tail(str(path))
    assert text == path.read_text(encoding="utf-8")


def test_a_pull_reads_at_most_the_newest_5_mb_from_a_whole_line(tmp_path, monkeypatch):
    path = tmp_path / "combined.log"
    _lines_file(path, 120000, width=101)           # about 12 MB, lines of 101 bytes
    text = _sink().read_tail(str(path))
    assert len(text.encode()) <= 5 * MB
    lines = text.split("\n")
    assert lines[-1] == ""                          # the file ends with a line break
    assert lines[-2].startswith("[web] line 0119999 ")
    assert all(len(line) == 100 and line.startswith("[web] line ") for line in lines[:-1])
    # The web app's reader is the same read, split on line breaks only.
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.api import api_server as api
    monkeypatch.setattr(api, "_LOG_SINK_PATH", str(path))
    assert api._read_sink_lines() == lines


@pytest.mark.parametrize("window, first", [(30, 7), (25, 8), (31, 7), (29, 8)])
def test_the_window_keeps_a_line_that_starts_at_its_edge_and_drops_a_partial_one(tmp_path, window, first):
    path = tmp_path / "combined.log"
    path.write_bytes(b"".join(b"%09d\n" % i for i in range(10)))     # ten lines of 10 bytes
    text = _sink().read_tail(str(path), max_bytes=window)
    # 30 bytes start exactly at line 7, 31 one byte before it (that byte ends line 6); 25 and 29 inside line 7.
    assert text.split("\n") == ["%09d" % i for i in range(first, 10)] + [""]


def test_a_line_longer_than_the_window_gives_nothing_rather_than_a_fragment(tmp_path):
    path = tmp_path / "combined.log"
    path.write_bytes(b"[web] " + b"z" * 1000 + b"\n")
    assert _sink().read_tail(str(path), max_bytes=100) == ""


def test_an_absent_file_reads_as_no_lines(tmp_path, monkeypatch):
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.api import api_server as api
    monkeypatch.setattr(api, "_LOG_SINK_PATH", str(tmp_path / "missing.log"))
    assert api._read_sink_lines() == []


def test_the_notice_says_how_much_the_file_keeps_and_how_long_notifications_are_kept(monkeypatch):
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.core import recording_notice as rn
    from app.core import settings_registry
    real = settings_registry.resolve
    kept = {s.key: s for s in rn.STORES}
    assert kept["log_access_file"].kept() == "Up to 15 MB; the oldest lines go first."
    assert kept["notifications"].kept() == "Until you dismiss them."
    values = {"log_pull_sink_max_mb": 60, "notification_retention_days": 90}
    monkeypatch.setattr(settings_registry, "resolve", lambda key: values[key] if key in values else real(key))
    assert kept["log_access_file"].kept() == "Up to 60 MB; the oldest lines go first."
    assert kept["notifications"].kept() == "Until you dismiss them, or 90 days after they arrive."
