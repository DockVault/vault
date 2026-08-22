"""Shared log-pull sink writer.

The log-pull endpoint (`GET /logs?service=<component>`) reads a rotating FILE of tagged lines
(`[web] <ISO-8601-Z ts> <raw>` / `[sftp] ...`). In the COMBINED run shape `run_combined.py` writes
that file by capturing each child's stdout; but a SPLIT deployment runs the API directly, so nothing
writes it and `/logs?service=web` comes back empty. This module lets the API self-write its own
`[web]` access lines when it is NOT running under `run_combined`, so web log-pull works in every shape.

The line format is byte-identical to `run_combined._sink_line` (tag FIRST so the log-pull
`filter_service_lines` prefix match works; then the UTC timestamp; then the raw line, `\\r\\n`-stripped).
Writing is best-effort and never blocks the event loop: `emit()` only `put_nowait`s onto a bounded
queue and a daemon thread does the disk write, exactly like the launcher's pump.
"""
import logging
import logging.handlers
import os
import queue
import threading
from datetime import datetime, timezone

# Same default + caps as run_combined.py, so both run shapes produce an identical, size-capped file.
_SINK_PATH = os.environ.get("LOG_PULL_SINK_PATH", "./logs/combined.log")
_SINK_MAX_BYTES = 5 * 1024 * 1024
_SINK_BACKUPS = 2
_SINK_QUEUE: "queue.Queue" = queue.Queue(maxsize=20000)
_SINK_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO-8601 UTC, trailing Z

_sink_logger = None
_active = False
_writer_started = False


def _sink_line(label: str, line: str, ts: str) -> str:
    """The stored line: `[label]` tag FIRST (line-start prefix the pull filter matches), then the
    timestamp, then the raw line. Byte-identical to run_combined._sink_line — do not reorder."""
    return f"[{label}] {ts} " + line.rstrip("\r\n")


def _writer_loop() -> None:
    while True:
        rec = _SINK_QUEUE.get()
        if rec is None:
            return
        if _sink_logger is not None:
            try:
                _sink_logger.info(rec)
            except Exception:  # noqa: BLE001 — a failed disk write must not kill the writer
                pass


def init_sink() -> bool:
    """Best-effort: set up the size-capped rotating sink file and start the writer thread. Returns
    True only on ACTUAL success (so the caller advertises availability only when it can really write —
    a read-only-logs deployment stays honestly unavailable). Idempotent."""
    global _sink_logger, _writer_started, _active
    if _active:
        return True
    try:
        d = os.path.dirname(_SINK_PATH) or "."
        os.makedirs(d, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            _SINK_PATH, maxBytes=_SINK_MAX_BYTES, backupCount=_SINK_BACKUPS, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))  # store the raw tagged line
        lg = logging.getLogger("dockvault.logsink.app")
        lg.setLevel(logging.INFO)
        lg.propagate = False
        lg.handlers = [handler]
        _sink_logger = lg
        if not _writer_started:
            threading.Thread(target=_writer_loop, daemon=True).start()
            _writer_started = True
        _active = True
        return True
    except Exception:  # noqa: BLE001 — sink is optional; never block startup on it
        _sink_logger = None
        return False


def is_active() -> bool:
    return _active


def emit(label: str, line: str) -> None:
    """Enqueue a tagged, timestamped line WITHOUT blocking. No-op when the sink is inactive; drops the
    line if the queue is full (a slow/failed disk must never stall the request path)."""
    if not _active or _sink_logger is None:
        return
    try:
        ts = datetime.now(timezone.utc).strftime(_SINK_TS_FMT)
        _SINK_QUEUE.put_nowait(_sink_line(label, line, ts))
    except queue.Full:
        pass
    except Exception:  # noqa: BLE001
        pass
