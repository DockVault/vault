"""Unit coverage for the in-app log-pull sink writer (offline).

Proves the stored line is byte-compatible with the pull filter (tag first, then timestamp, then the
raw line, newline-stripped) and that a real init+emit round-trips to a file the pull filter accepts.
"""
import time

import pytest

from app.services import log_sink
from app.services.log_pull import filter_service_lines

pytestmark = pytest.mark.unit


def test_sink_line_is_tag_first_then_ts_then_raw():
    line = log_sink._sink_line("web", "GET /x -> 200\r\n", "2026-08-23T00:00:00.000000Z")
    assert line == "[web] 2026-08-23T00:00:00.000000Z GET /x -> 200"   # CRLF stripped, tag leads


def test_sink_line_survives_the_pull_filter():
    line = log_sink._sink_line("web", "GET /vaults -> 200 10.0.0.1 5ms", "2026-08-23T00:00:00Z")
    assert filter_service_lines([line], "web") == [line]
    assert filter_service_lines([line], "sftp") == []   # a [web] line is not served as sftp


def test_emit_before_init_is_a_silent_noop():
    # inactive by default in a fresh process; emitting must neither raise nor require a logger
    if not log_sink.is_active():
        log_sink.emit("web", "dropped silently")   # must not raise


def test_init_then_emit_round_trips_to_a_readable_file(tmp_path, monkeypatch):
    monkeypatch.setattr(log_sink, "_SINK_PATH", str(tmp_path / "combined.log"))
    monkeypatch.setattr(log_sink, "_active", False)
    monkeypatch.setattr(log_sink, "_sink_logger", None)
    monkeypatch.setattr(log_sink, "_writer_started", False)
    assert log_sink.init_sink() is True
    assert log_sink.is_active() is True
    log_sink.emit("web", "GET /probe -> 200 1.2.3.4 3ms")
    path = tmp_path / "combined.log"
    for _ in range(60):   # the daemon writer flushes off-thread
        if path.exists() and path.read_text(encoding="utf-8").strip():
            break
        time.sleep(0.05)
    content = path.read_text(encoding="utf-8")
    assert "GET /probe -> 200" in content
    served = filter_service_lines(content.splitlines(), "web")
    assert served and served[0].startswith("[web] ")
