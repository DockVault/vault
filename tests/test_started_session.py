"""A background thread never initializes the process's runtime (app/core/database.started_session).

SessionLocal() initializes the runtime when nothing has yet, which installs a newly read value of every
setting over the shared settings object. The managed-settings refresh and the SFTP version record run on
threads of their own, so if either were the first to ask for a session it would overwrite, at a moment
nobody chose, what the process had set since: the SFTP server read its write-progress watchdog setting
after starting both, and got the value from the environment instead of its own. Each asks
started_session(), which refuses until the process has initialized its runtime, and skips that turn.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from _bare_api_env import _FERNET_KEY

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]

_BOTH_THREADS = r'''
import json, threading, time
import app.core.database as D
from app.core import config, settings_registry
from app.core.sftp_versions import Recorder

asked = []
real = D.started_session
def counted():
    asked.append(threading.current_thread().name)
    return real()
D.started_session = counted

config.settings.sftp_write_progress_timeout_seconds = 0      # what the process set for itself
refresher = settings_registry.start(load_now=False, interval=0.05)
recorder = Recorder(interval=0.05)
recorder.start()
deadline = time.monotonic() + 10
while time.monotonic() < deadline and not {"managed-settings-refresh", "version-record"} <= set(asked):
    time.sleep(0.05)
time.sleep(0.3)                                                # several turns more
out = {
    "initialized": config.runtime_is_initialized(),
    "value": config.settings.sftp_write_progress_timeout_seconds,
    "asked_by": sorted(set(asked)),
    "turns": len(asked),
    "refreshed_now": settings_registry.refresh(),
    "stamp": settings_registry.stamp(),
    "recorded": recorder.recorded,
    "threads_alive": [refresher.is_alive(), recorder.thread.is_alive()],
}
recorder.stop()
settings_registry.stop()
print(json.dumps(out))
'''


def _bare_env():
    env = dict(os.environ)
    env.update({
        "DATABASE_URL": "postgresql://x:x@localhost:5432/x",
        "REDIS_URL": "redis://localhost:6379/0",
        "SECRET_KEY": "t" * 32,
        "ENCRYPTION_KEY": _FERNET_KEY,
        "JWT_SECRET_KEY": "t" * 32,
        "PYTHONPATH": str(ROOT),
    })
    env.pop("SFTP_WRITE_PROGRESS_TIMEOUT_SECONDS", None)
    return env


def test_neither_background_thread_initializes_the_runtime(tmp_path):
    # A fresh interpreter, whose environment holds everything initializing the runtime needs, in a
    # directory with no .env: a thread that initialized it would succeed, and set the value back to 120.
    r = subprocess.run([sys.executable, "-c", _BOTH_THREADS], cwd=str(tmp_path), env=_bare_env(),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["initialized"] is False, out
    assert out["value"] == 0, out
    # Both threads did take turns, and each was refused: nothing loaded, nothing recorded, and a refused
    # turn is not the end of either thread.
    assert out["asked_by"] == ["managed-settings-refresh", "version-record"], out
    assert out["turns"] >= 4, out
    assert out["refreshed_now"] is False and out["stamp"] is None, out
    assert out["recorded"] is False, out
    assert out["threads_alive"] == [True, True], out
    # A refused turn is quiet: it is the process not having started, not a failure to report.
    assert "not refreshed" not in r.stdout, r.stdout


def test_a_session_is_given_once_the_runtime_is_initialized(monkeypatch):
    from app.core import database
    from app.core.config import RuntimeNotReady
    given = object()
    monkeypatch.setattr(database, "SessionLocal", lambda: given)
    monkeypatch.setattr(database, "runtime_is_initialized", lambda: False)
    with pytest.raises(RuntimeNotReady):
        database.started_session()
    monkeypatch.setattr(database, "runtime_is_initialized", lambda: True)
    assert database.started_session() is given
