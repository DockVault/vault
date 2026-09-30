"""Which version each SFTP server process runs, so the web app can tell whether they all run its own.

In the split profile and the trial compose the SFTP server is a container of its own, and nothing stops
it running an older image than the web container after an update of only one of them. Some changes are safe only while no
older SFTP process can act on the same data (an older one may delete what the newer web app keeps), so
the web app asks before it makes one.

Each SFTP process records itself in ``sftp_processes`` (an id of its own, its host and its version) when
it starts and every RECORD_SECONDS after, on a thread of its own, so a database that does not answer never
holds up the server or its heartbeat (app/sftp/heartbeat.py). A process counts as live while it has
recorded itself within LIVE_WITHIN_SECONDS. It removes its own row when it stops cleanly, and rows no
process has refreshed for PRUNE_AFTER_DAYS are removed when a process starts.

sftp_same_version() answers whether SFTP is off, or every live SFTP process runs this version:

- a live process of another version: no;
- live processes, all of this version: yes;
- none live, where no SFTP server runs: yes. Only one layout proves that: run_combined.py started this
  web process and no SFTP server beside it (RUN_SFTP not set), and says so in VAULT_COMBINED_SFTP;
- none live anywhere else: no. A web process started on its own (the split profile, the trial compose)
  has an SFTP container beside it whatever .env says, and an SFTP server of a release before this one
  never records itself, so it may be running unseen.

The version is the one baked into the image (its VERSION file), not the brand's display version, which
.env can override for both containers alike.
"""
from __future__ import annotations

import os
import socket
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

RECORD_SECONDS = 30.0
LIVE_WITHIN_SECONDS = 120
PRUNE_AFTER_DAYS = 7

SAME = "same"
OFF = "off"
OTHER_VERSION = "other_version"
NONE_LIVE = "none_live"


def code_version() -> str:
    """This code's version: the VERSION file baked into the image at /app, else the one at the repository
    root; ``unknown`` when neither can be read (which matches no recorded version but itself)."""
    here = Path(__file__).resolve()
    for path in (Path("/app/VERSION"), here.parents[2] / "VERSION"):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return "unknown"


# Set by run_combined.py on the processes it starts, over anything inherited: ``off`` when it starts no
# SFTP server beside them, ``on`` when it does. An internal marker, not a setting.
COMBINED_SFTP_ENV = "VAULT_COMBINED_SFTP"


def deployment_runs_sftp(environ=None) -> bool:
    """Whether an SFTP server may be running beside this web process: yes, unless run_combined.py started
    it and started no SFTP server (COMBINED_SFTP_ENV is ``off``). RUN_SFTP and COMPOSE_PROFILES do not
    decide it: the trial compose runs an SFTP container whatever they say, and a web process started on
    its own cannot see what runs in another container."""
    env = os.environ if environ is None else environ
    return str(env.get(COMBINED_SFTP_ENV) or "").strip().lower() != "off"


@dataclass(frozen=True)
class VersionCheck:
    ok: bool
    reason: str
    versions: tuple = field(default_factory=tuple)

    def explain(self) -> str:
        """The answer in plain words, for a refusal."""
        if self.reason == OTHER_VERSION:
            return ("An SFTP server of another version is running ("
                    + ", ".join(self.versions) + "); update it to this version first.")
        if self.reason == NONE_LIVE:
            return ("No SFTP server has reported its version, and one may be running: an SFTP server of an "
                    "older release does not report it. Update it to this version and wait a minute.")
        return "Every SFTP server runs this version." if self.reason == SAME else "This deployment runs no SFTP server."


def sftp_same_version(db, *, now: Optional[datetime] = None, environ=None, version: Optional[str] = None) -> VersionCheck:
    """Whether SFTP is off, or every live SFTP process runs this version (see the module's docstring)."""
    from app.core.models import SftpProcess
    now = now or datetime.utcnow()
    version = version or code_version()
    since = now - timedelta(seconds=LIVE_WITHIN_SECONDS)
    live = sorted({v for (v,) in db.query(SftpProcess.version).filter(SftpProcess.seen_at >= since).all()})
    others = tuple(v for v in live if v != version)
    if others:
        return VersionCheck(False, OTHER_VERSION, others)
    if live:
        return VersionCheck(True, SAME, tuple(live))
    if not deployment_runs_sftp(environ):
        return VersionCheck(True, OFF)
    return VersionCheck(False, NONE_LIVE)


def record(db, process_id: str, *, version: Optional[str] = None, host: Optional[str] = None,
           now: Optional[datetime] = None) -> None:
    """Record, or refresh, one SFTP process in ``db`` and commit."""
    from app.core.models import SftpProcess
    now = now or datetime.utcnow()
    row = db.get(SftpProcess, process_id)
    if row is None:
        db.add(SftpProcess(id=process_id, version=version or code_version(), host=(host or "")[:255] or None,
                           started_at=now, seen_at=now))
    else:
        row.seen_at = now
    db.commit()


def prune(db, *, now: Optional[datetime] = None) -> int:
    """Remove the rows no process has refreshed for PRUNE_AFTER_DAYS, and commit. Returns how many."""
    from app.core.models import SftpProcess
    now = now or datetime.utcnow()
    gone = db.query(SftpProcess).filter(
        SftpProcess.seen_at < now - timedelta(days=PRUNE_AFTER_DAYS)).delete(synchronize_session=False)
    db.commit()
    return gone


def forget(db, process_id: str) -> None:
    """Remove this process's row, and commit: it is stopping."""
    from app.core.models import SftpProcess
    db.query(SftpProcess).filter(SftpProcess.id == process_id).delete(synchronize_session=False)
    db.commit()


class Recorder:
    """The SFTP process's record of itself, kept on a daemon thread of its own."""

    def __init__(self, session_factory=None, *, interval: float = RECORD_SECONDS):
        self.process_id = str(uuid.uuid4())
        self.host = socket.gethostname()
        self.interval = interval
        self._factory = session_factory
        self._stop = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.recorded = False

    def _session(self):
        if self._factory is not None:
            return self._factory()
        # Never the call that initializes this process's runtime (see started_session): a turn before
        # the process has done so fails, and the next turn tries again.
        from app.core.database import started_session
        return started_session()

    def _once(self, first: bool) -> bool:
        """One record (the first also prunes). Never raises: a failure is tried again at the next turn."""
        db = None
        try:
            db = self._session()
            if first:
                prune(db)
            record(db, self.process_id, host=self.host)
            return True
        except Exception:  # noqa: BLE001 - the next turn tries again; the server never waits on this
            try:
                if db is not None:
                    db.rollback()
            except Exception:  # noqa: BLE001
                pass
            return False
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:  # noqa: BLE001
                    pass

    def _run(self):
        first = True
        while True:
            if self._once(first):
                first = False
                self.recorded = True
            if self._stop.wait(self.interval):
                return

    def start(self) -> threading.Thread:
        self.thread = threading.Thread(target=self._run, name="version-record", daemon=True)
        self.thread.start()
        return self.thread

    def stop(self, *, forget_row: bool = True) -> None:
        """End the recording, and remove this process's row, if it made one, so it no longer counts as
        live. Waits at most a second for the thread: a stop never hangs on the database."""
        self._stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
        if forget_row and self.recorded:
            db = None
            try:
                db = self._session()
                forget(db, self.process_id)
            except Exception:  # noqa: BLE001 - its row goes stale on its own
                pass
            finally:
                if db is not None:
                    try:
                        db.close()
                    except Exception:  # noqa: BLE001
                        pass
