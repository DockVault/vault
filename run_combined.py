"""Combined entrypoint: run the FastAPI web/API server AND (optionally) the SFTP server
in ONE container.

Used for provisioned single-vault deployments so a customer gets BOTH the web app
(port 8000) and SFTP (port 2222) backed by the SAME storage/keys volume and the SAME
database — the two processes interoperate exactly as the split dev-stack containers do
(shared /app/storage + /app/keys, the same DATABASE_URL, ENCRYPTION_KEY, JWT_SECRET_KEY,
and Redis). Running them in one process tree avoids the per-component-volume problem that
would otherwise stop the web and SFTP halves from sharing files.

The SFTP half starts ONLY when RUN_SFTP is truthy in the environment (provisioning sets
it for single-vault deployments). Without it, this launcher runs the web app alone — so a
vault image used as a plain web component (e.g. a multi-container bundle's 'app') does not
spin up an unpublished SFTP listener or couple its liveness to one.

If a running child exits, this launcher terminates the other and exits non-zero so the
container's restart policy recreates the whole thing — rather than silently running
degraded with one half down (the image HEALTHCHECK only probes the HTTP /health).

The dev stack and the bundle composer run the two processes as separate containers by
overriding the command, so this default-CMD launcher does not affect them.
"""
import logging
import logging.handlers
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import urllib.request

# (target, Popen) for each supervised child.
_PROCS: list = []

# Serialize the tagging writers so a web line and an sftp line can never interleave mid-line
# on the shared parent stdout.
_STDOUT_LOCK = threading.Lock()

# --- log sink ---------------------------------------------------------------------
# The API server that serves the pull endpoint runs as a SEPARATE child process; it
# cannot read this launcher's stdout (where the tagged lines go for `docker logs`) nor the
# other child's stdout. So we ALSO append every tagged line to a bounded, rotating FILE that
# the in-container API can tail. Writing to that file must NEVER block a `_pump` reader — a
# blocked reader lets the child's ~64 KB stdout pipe fill and wedges the whole container — so
# the pumps only `put_nowait` onto a bounded queue (dropping on overflow), and a dedicated
# daemon thread does the actual (potentially slow) disk write. The file is best-effort: if its
# directory is not writable the sink is simply disabled and stdout tagging is unaffected.
_SINK_PATH = os.environ.get("LOG_PULL_SINK_PATH", "./logs/combined.log")
_SINK_MAX_BYTES = 5 * 1024 * 1024   # per file
_SINK_BACKUPS = 2                   # + 2 rotations -> ~15 MB hard cap
_SINK_QUEUE: "queue.Queue[str]" = queue.Queue(maxsize=20000)
_sink_logger = None


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _init_sink() -> None:
    """Best-effort: set up the size-capped rotating sink file. Leaves the sink disabled
    (``_sink_logger`` None) if the directory is not writable — the pumps then skip it and keep
    tagging stdout, so a read-only-logs deployment degrades to 'operator docker-logs only'."""
    global _sink_logger
    try:
        d = os.path.dirname(_SINK_PATH) or "."
        os.makedirs(d, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            _SINK_PATH, maxBytes=_SINK_MAX_BYTES, backupCount=_SINK_BACKUPS, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))  # store the raw tagged line
        lg = logging.getLogger("dockvault.logsink")
        lg.setLevel(logging.INFO)
        lg.propagate = False
        lg.handlers = [handler]
        _sink_logger = lg
    except Exception:  # noqa: BLE001 — sink is optional; never block startup on it
        _sink_logger = None


def _sink_writer_loop() -> None:
    """Drain the sink queue to disk on a dedicated daemon thread, so the `_pump` readers never
    block on file I/O. Ends when a ``None`` sentinel is enqueued (shutdown)."""
    while True:
        rec = _SINK_QUEUE.get()
        if rec is None:
            return
        if _sink_logger is not None:
            try:
                _sink_logger.info(rec)
            except Exception:  # noqa: BLE001 — a failed disk write must not kill the writer
                pass


def _sink_emit(label: str, line: str) -> None:
    """Enqueue a tagged line for the sink WITHOUT blocking. Drops the line if the queue is full
    (a slow/failed disk must never stall a pump). No-op when the sink is disabled."""
    if _sink_logger is None:
        return
    try:
        _SINK_QUEUE.put_nowait(f"[{label}] " + line.rstrip("\r\n"))
    except queue.Full:
        pass  # drop under sustained pressure rather than block the pump
    except Exception:  # noqa: BLE001
        pass


def _pump(label: str, stream) -> None:
    """Continuously drain a child's merged stdout/stderr, re-emitting each line with a
    ``[label]`` tag so ``docker logs`` (and the operator's per-service log view) can tell the
    web and SFTP halves apart in the single combined container.

    This reader MUST never stop draining while the child is alive: a child writes to a pipe
    with a small kernel buffer (~64 KB), so if this loop blocked or died the child would hang
    on its next write with the whole container wedged. Therefore every per-line write is
    guarded and the loop only ends at EOF (child exit / stream close)."""
    try:
        for line in stream:  # text mode -> one line per newline, WITH the trailing '\n'
            try:
                with _STDOUT_LOCK:
                    sys.stdout.write(f"[{label}] {line}")
                    sys.stdout.flush()
            except Exception:  # noqa: BLE001 — never stop draining because a write failed
                pass
            _sink_emit(label, line)  # non-blocking; the disk write happens on the writer thread
    except Exception:  # noqa: BLE001 — stream closed/errored; the supervise loop handles exit
        pass


def _spawn(target: str, label: str) -> None:
    """Start a supervised child, tagging each of its log lines ``[label]`` via a daemon reader
    thread. stderr is merged into stdout so one reader tags everything the child emits;
    PYTHONUNBUFFERED keeps lines timely (a per-block buffer would defeat the tag); text mode
    with errors='replace' means a stray non-UTF-8 byte can't kill the reader (and risk a
    pipe-fill hang). ``target`` is a module name run via ``python -m`` (the packaged
    servers), or a script path when it ends in ``.py`` (used by tests; note a script run by
    path gets its OWN directory as sys.path[0], so package-importing modules under
    app/ must use the module form)."""
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    argv = [sys.executable, target] if target.endswith(".py") else [sys.executable, "-m", target]
    p = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
    )
    threading.Thread(target=_pump, args=(label, p.stdout), daemon=True).start()
    _PROCS.append((target, p))


def _wait_api_ready(timeout: float = 60.0) -> bool:
    """Poll the API's /health until it answers, so the SFTP server starts only AFTER the
    API's lifespan has created/migrated the schema the SFTP path reads. Returns False on
    timeout (we start SFTP anyway — it fails closed on DB errors, never serving stale)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # Stop early if the API process already died — the supervise loop will handle it.
        if _PROCS and _PROCS[0][1].poll() is not None:
            return False
        try:
            with urllib.request.urlopen("http://localhost:8000/health", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001 — not up yet
            pass
        time.sleep(1)
    return False


def _terminate_all() -> None:
    for _label, p in _PROCS:
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:  # noqa: BLE001
                pass
    deadline = time.monotonic() + 10
    for _label, p in _PROCS:
        while p.poll() is None and time.monotonic() < deadline:
            time.sleep(0.2)
    for _label, p in _PROCS:
        if p.poll() is None:
            try:
                p.kill()
            except Exception:  # noqa: BLE001
                pass


def _on_signal(signum, _frame):
    _terminate_all()
    sys.exit(128 + signum)


def main() -> None:
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    # Set up the log sink (best-effort) and its writer thread BEFORE spawning children,
    # so no tagged line is enqueued with no drainer running (the bounded queue would just fill
    # and drop — safe — but starting the writer first captures early startup lines too).
    _init_sink()
    threading.Thread(target=_sink_writer_loop, daemon=True).start()
    # Start the API first — its lifespan runs the schema create/migrations the SFTP
    # server relies on.
    _spawn("app.api.api_server", "web")
    if _truthy(os.environ.get("RUN_SFTP")):
        # Wait for the API to be ready (schema migrated) before starting SFTP, so an
        # early SFTP client can't hit a not-yet-migrated DB. Bounded; falls through on
        # timeout (SFTP fails closed on DB errors rather than serving wrong data).
        if not _wait_api_ready():
            print("[run_combined] API not ready within timeout; starting SFTP anyway", flush=True)
        _spawn("app.sftp.sftp_server", "sftp")
    # Supervise: if a running child exits, take the whole container down so it restarts
    # (don't limp along with only one half running).
    while True:
        for label, p in _PROCS:
            rc = p.poll()
            if rc is not None:
                print(f"[run_combined] {label} exited with code {rc}; stopping the container",
                      flush=True)
                _terminate_all()
                sys.exit(rc if rc != 0 else 1)
        time.sleep(2)


if __name__ == "__main__":
    main()
