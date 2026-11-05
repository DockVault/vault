"""When each vault was last opened (``Vault.last_accessed``), written at most once a minute per vault, off the
event loop.

Every request that works in a vault opens it through ``VaultService.get_vault``: a listing, a download, an upload,
an SFTP command. It used to set the vault's ``last_accessed`` and commit, each time. In the web server that ran on
the event loop, which answers every request: the commit waits for the disk, 0.6 to 1.6 s on a disk busy with
uploads, and nobody else was answered meanwhile. The write also took the vault's row lock, so a listing waited
for any transaction that held the row.

Now ``get_vault`` calls ``opened(db, vault)``, which writes nothing itself:

- when the stored time is within a minute (``EVERY_SECONDS``) of now, there is nothing to write: what is stored
  is at most a minute behind;
- otherwise the time goes to this module's writer, one thread per process, which writes it in a short
  transaction of its own, on a connection of its own. The write moves the stored time only when it is more than
  a minute behind the time being written (or more than a minute ahead of the writer's clock: a time stored by a
  clock that was later set back). So the web server and the SFTP server, each with its writer, write at most
  once a minute between them, and a write that is late never puts back a later time another wrote meanwhile;
- a write that fails (the database away, the row locked past the connection's lock_timeout) is tried again,
  ``RETRY_SECONDS`` later, up to ``ATTEMPTS`` times in all; and what is still waiting when the process stops is
  written then, for up to ``EXIT_SECONDS``.

So the stored time is never more than about a minute behind the vault's most recent opening.

``last_access(vault_id, stored)`` is what a reader reports: the later of the stored time and the last time this
process opened the vault. A vault just opened shows that time, as it did when every opening was written.

The write sets ``updated_at`` with ``last_accessed``, as the ORM's update did when every opening was written.

Only a session bound to an engine (every session of the web and SFTP servers) has a time written; a session
bound to anything else (a test's stand-in) has nothing written here.
"""
import atexit
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

EVERY_SECONDS = 60
RETRY_SECONDS = 5
ATTEMPTS = 4
EXIT_SECONDS = 5.0
# The vaults whose last opening this process remembers for the readers; past it, the older half is forgotten
# (by then the stored time has caught up with them).
KEEP = 4096

_EVERY = timedelta(seconds=EVERY_SECONDS)
_log = logging.getLogger(__name__)

_cond = threading.Condition()
_seen = {}          # vault id -> the most recent time this process opened the vault
_waiting = {}       # vault id -> _Write, for the writer
_writing = 0        # writes in progress
_thread = None


class _Write:
    __slots__ = ("when", "bind", "attempts", "not_before")

    def __init__(self, when, bind):
        self.when, self.bind, self.attempts, self.not_before = when, bind, 0, 0.0


def _utc(value):
    """``value`` as a naive UTC datetime, as the column holds it; None stays None."""
    if value is not None and value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _due(stored, when):
    """Whether the stored time is more than a minute away from ``when``, either way."""
    return stored is None or stored < when - _EVERY or stored > when + _EVERY


def _engine_of(db):
    from sqlalchemy.engine import Engine
    try:
        bind = db.get_bind()
    except Exception:  # noqa: BLE001 -- a session that cannot say what it is bound to has nothing written
        return None
    return bind if isinstance(bind, Engine) else None


def _remember(vault_id, when):
    """Under _cond."""
    if vault_id not in _seen or when > _seen[vault_id]:
        _seen[vault_id] = when
    if len(_seen) > KEEP:
        for key, _ in sorted(_seen.items(), key=lambda kv: kv[1])[:len(_seen) // 2]:
            del _seen[key]


def opened(db, vault, when=None):
    """``vault`` (as ``db`` just read it) was opened at ``when`` (now when not given). Remembered for the readers,
    and its time handed to the writer when the stored one is more than a minute away from it. Returns at once."""
    global _thread
    when = _utc(when) or _now()
    vault_id = vault.id
    stored = _utc(getattr(vault, "last_accessed", None))
    with _cond:
        _remember(vault_id, when)
        if not _due(stored, when):
            return
        engine = _engine_of(db)
        if engine is None:
            return
        queued = _waiting.get(vault_id)
        if queued is None:
            _waiting[vault_id] = _Write(when, engine)
        elif when > queued.when:
            queued.when, queued.bind = when, engine
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_run, name="vault-access-writer", daemon=True)
            _thread.start()
        _cond.notify_all()


def last_access(vault_id, stored):
    """When the vault was last opened, as far as this process knows: the later of ``stored`` (the column) and
    this process's own last opening of it."""
    stored = _utc(stored)
    with _cond:
        seen = _seen.get(vault_id)
    if seen is None:
        return stored
    return seen if stored is None or seen > stored else stored


def _next():
    """Under _cond: wait for a write that is due, take it out of _waiting and return (vault id, _Write)."""
    global _writing
    while True:
        if _waiting:
            vault_id, item = min(_waiting.items(), key=lambda kv: kv[1].not_before)
            wait = item.not_before - time.monotonic()
            if wait <= 0:
                del _waiting[vault_id]
                _writing += 1
                return vault_id, item
            _cond.wait(wait)
        else:
            _cond.wait()


def _write(vault_id, item):
    """Write ``item.when`` as the vault's last access, if the stored one is more than a minute away from it (or
    more than a minute ahead of now). True when the statement committed (whether or not it changed the row)."""
    from sqlalchemy import or_, update
    from sqlalchemy.orm import Session
    from app.core.models import Vault
    now = _now()
    try:
        with Session(bind=item.bind) as session:
            session.execute(
                update(Vault)
                .where(Vault.id == vault_id,
                       or_(Vault.last_accessed.is_(None),
                           Vault.last_accessed < item.when - _EVERY,
                           Vault.last_accessed > now + _EVERY))
                .values(last_accessed=item.when, updated_at=now)
                .execution_options(synchronize_session=False))
            session.commit()
        return True
    except Exception as exc:  # noqa: BLE001 -- tried again, below; the class only (a message can carry values)
        _log.warning("A vault's last access could not be recorded (%s); trying again.", type(exc).__name__)
        return False


def _run():
    global _writing
    while True:
        with _cond:
            vault_id, item = _next()
        done = _write(vault_id, item)
        with _cond:
            _writing -= 1
            if not done:
                item.attempts += 1
                if item.attempts < ATTEMPTS:
                    later = _waiting.get(vault_id)
                    if later is not None and later.when > item.when:
                        item.when, item.bind = later.when, later.bind
                    item.not_before = time.monotonic() + RETRY_SECONDS
                    _waiting[vault_id] = item
                else:
                    _log.warning("A vault's last access was not recorded after %d attempts.", ATTEMPTS)
            _cond.notify_all()


def flush(timeout):
    """Wait until every time handed to the writer is written (or given up on), for up to ``timeout`` seconds.
    True when nothing is left."""
    deadline = time.monotonic() + timeout
    with _cond:
        while _waiting or _writing:
            if _thread is None or not _thread.is_alive():
                return False
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            _cond.wait(left)
        return True


@atexit.register
def _flush_at_exit():
    try:
        flush(EXIT_SECONDS)
    except Exception:  # noqa: BLE001 -- the process is stopping; nothing more to do
        pass
