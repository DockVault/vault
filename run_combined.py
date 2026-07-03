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
import os
import signal
import subprocess
import sys
import time
import urllib.request

# (label, Popen) for each supervised child.
_PROCS: list = []


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _spawn(script: str) -> None:
    _PROCS.append((script, subprocess.Popen([sys.executable, script])))


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
    # Start the API first — its lifespan runs the schema create/migrations the SFTP
    # server relies on.
    _spawn("api_server.py")
    if _truthy(os.environ.get("RUN_SFTP")):
        # Wait for the API to be ready (schema migrated) before starting SFTP, so an
        # early SFTP client can't hit a not-yet-migrated DB. Bounded; falls through on
        # timeout (SFTP fails closed on DB errors rather than serving wrong data).
        if not _wait_api_ready():
            print("[run_combined] API not ready within timeout; starting SFTP anyway", flush=True)
        _spawn("sftp_server.py")
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
