"""Shared log-pull sink writer.

The log-pull endpoint (`GET /logs?service=<component>`) reads a rotating FILE of tagged lines
(`[web] <ISO-8601-Z ts> <raw>` / `[sftp] ...`). In the COMBINED run shape `run_combined.py` writes
that file by capturing each child's stdout; but a SPLIT deployment runs the API directly, so nothing
writes it and `/logs?service=web` comes back empty. This module lets the API self-write its own
`[web]` access lines when it is NOT running under `run_combined`, so web log-pull works in every shape.

The line format is byte-identical to `run_combined._sink_line` (tag FIRST so the log-pull
`filter_service_lines` prefix match works; then the UTC timestamp; then the raw line). Writing is
best-effort and never blocks the event loop: `emit()` only `put_nowait`s onto a bounded queue and a
daemon thread does the disk write, exactly like the launcher's pump.
"""
import logging
import logging.handlers
import os
import queue
import threading
from datetime import datetime, timezone

# The whole sink (the file and its two older copies) holds at most LOG_PULL_SINK_MAX_MB: 15 by default, 3 to 1000
# (app/core/working_records.py lists it; a value outside that refuses to start the web app, and is read here as
# the default). run_combined.py reads the same limits, so both run shapes produce the same size-capped files.
SINK_DEFAULT_MB = 15
SINK_MIN_MB = 3
SINK_MAX_MB = 1000
SINK_BACKUPS = 2
# A log pull reads at most this much of the newest file, whatever the cap: the pull returns 5000 lines at most,
# and reading a larger file would hold the web app's event loop.
SINK_READ_BYTES = 5 * 1024 * 1024


def sink_limits(environ=None) -> tuple:
    """(the most bytes one file holds, how many older files are kept) for LOG_PULL_SINK_MAX_MB in ``environ``
    (the process's environment by default): the cap split evenly over the file and its older copies."""
    env = os.environ if environ is None else environ
    raw = str(env.get("LOG_PULL_SINK_MAX_MB", "") or "").strip()
    mb = int(raw) if raw.isdigit() else SINK_DEFAULT_MB
    if not SINK_MIN_MB <= mb <= SINK_MAX_MB:
        mb = SINK_DEFAULT_MB
    return mb * 1024 * 1024 // (SINK_BACKUPS + 1), SINK_BACKUPS


def read_tail(path: str, max_bytes: int = SINK_READ_BYTES) -> str:
    """The last ``max_bytes`` of the file at ``path`` from the first whole line in them, or all of it when it
    is no larger. Raises OSError as open() does."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        start = max(0, size - max_bytes)
        # One byte more before the window, to know whether the window starts a line.
        f.seek(max(0, start - 1))
        data = f.read(size - max(0, start - 1))
    if start:
        # The byte before the window ends a line, or the window begins inside one: drop that partial line.
        cut = data.find(b"\n")
        data = data[cut + 1:] if cut >= 0 else b""
    return data.decode("utf-8", errors="replace")


# Same path and limits as run_combined.py.
_SINK_PATH = os.environ.get("LOG_PULL_SINK_PATH", "./logs/combined.log")
_SINK_MAX_BYTES, _SINK_BACKUPS = sink_limits()
_SINK_QUEUE: "queue.Queue" = queue.Queue(maxsize=20000)
_SINK_TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO-8601 UTC, trailing Z

# Every character a log consumer (or _read_sink_lines, which splits on '\n') could treat as a line
# break. This writer builds its line from request fields, so scrub ALL of these to a space: an
# embedded separator must not be able to split one record into a second forged [tag] line or smuggle
# a fake entry (the same hazard _read_sink_lines guards against on read).
_LINE_SEPARATORS = str.maketrans({c: " " for c in "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"})

_sink_logger = None
_active = False
_writer_started = False


def _sink_line(label: str, line: str, ts: str) -> str:
    """The stored line: `[label]` tag FIRST (line-start prefix the pull filter matches), then the
    timestamp, then the raw line with every line-separator neutralised. Prefix/timestamp layout is
    byte-identical to run_combined._sink_line — do not reorder."""
    return f"[{label}] {ts} " + line.translate(_LINE_SEPARATORS).rstrip()


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
