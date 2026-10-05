"""A signal for each committed audit row, so the Activity page can show new events as they happen.

When a transaction that added audit rows commits, the id and the category of each row go out on a Redis
channel, and nothing else: no name, no address, no details. The web socket forwards the signal only to
signed-in administrators who can open the Activity page (app/core/socket_frames.py), and the page then
fetches the rows through the Events API, which applies the viewer's own name rules. So what a row says
never travels over the socket.

This covers every row, whichever way it was written: AuditLogger.log_action commits its own row, and a
row from AuditLogger.build_row commits with its caller's change. Both go through a session's flush and
commit, which is where this listens (``install``). A row that is rolled back, whole or inside a savepoint,
sends nothing.

Nothing here runs on the request. After the commit the ids go on a bounded in-process queue, and one
background thread publishes them, several rows to a message, behind the Redis guard. When Redis is down,
or the queue is full because it has been down for a while, signals are dropped: the rows are in the
database and the page's own poll finds them.
"""
import json
import logging
import os
import queue
import threading
import uuid
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

CHANNEL = "audit_signal"
# The most signals waiting to be published. Past it, new ones are dropped (see the module docstring).
MAX_QUEUE = 2000
# The most rows one published message names.
MAX_BATCH = 200

_INFO_KEY = "_audit_signal_rows"
# Set on a factory once install() has added the listeners to it.
_INSTALLED = "_audit_signal_installed"

_queue: "queue.Queue[Tuple[str, str]]" = queue.Queue(maxsize=MAX_QUEUE)
_worker_lock = threading.Lock()
_worker_pid: Optional[int] = None
dropped = 0     # signals dropped because the queue was full (read by tests and for diagnosis)


def category_of(action: Optional[str]) -> str:
    """The catalog category of a stored action name; "legacy" for a name the catalog does not know."""
    from app.core import audit_catalog
    entry = audit_catalog.lookup(action or "")
    return entry.category if entry else "legacy"


# --- Collecting the rows a transaction commits ------------------------------------------------------

def _after_flush(session, _flush_context):
    from app.core.models import AuditLog
    rows = [obj for obj in session.new if isinstance(obj, AuditLog)]
    if rows:
        # The id and the action are read now, while they are loaded: after the commit every attribute is
        # expired, and reading one would cost a query per row.
        session.info.setdefault(_INFO_KEY, []).extend((obj, obj.id, obj.action) for obj in rows)


def _after_commit(session):
    from sqlalchemy import inspect
    rows = session.info.pop(_INFO_KEY, None)
    if not rows:
        return
    # A row flushed inside a savepoint that was then rolled back has lost its identity key: it was
    # never committed, so it sends nothing.
    for obj, row_id, action in rows:
        if row_id is not None and inspect(obj).key is not None:
            enqueue(str(row_id), category_of(action))


def _after_transaction_end(session, transaction):
    # The outermost transaction ended (committed, rolled back or closed): whatever was collected and not
    # sent was not committed.
    if transaction.parent is None:
        session.info.pop(_INFO_KEY, None)


def install(target) -> bool:
    """Listen on a session factory (or a Session class) for committed audit rows. Idempotent. Returns
    False, and listens to nothing, for anything else (a stand-in factory in a test).

    Whether a factory already listens is marked on the factory itself. SQLAlchemy's own record
    (event.contains) is keyed by the target's address, so a new factory that takes the address of a
    freed one would be reported as already listening, and would never get the listeners."""
    from sqlalchemy import event
    from sqlalchemy.orm import Session, sessionmaker
    if not (isinstance(target, sessionmaker) or (isinstance(target, type) and issubclass(target, Session))):
        return False
    if getattr(target, _INSTALLED, False):
        return True
    for name, fn in (("after_flush", _after_flush), ("after_commit", _after_commit),
                     ("after_transaction_end", _after_transaction_end)):
        event.listen(target, name, fn)
    setattr(target, _INSTALLED, True)
    return True


# --- Publishing, off the request ----------------------------------------------------------------------

def enqueue(row_id: str, category: str) -> bool:
    """Queue one signal. Never blocks and never raises: a full queue drops the signal."""
    global dropped
    try:
        _ensure_worker()
        _queue.put_nowait((row_id, category))
        return True
    except queue.Full:
        dropped += 1
        return False
    except Exception:  # noqa: BLE001 - a signal must never fail the commit that sent it
        return False


def message(batch: List[Tuple[str, str]]) -> str:
    """The published message for a batch of signals."""
    return json.dumps({"events": [{"id": i, "category": c} for i, c in batch]})


def parse_message(raw) -> List[dict]:
    """The signals in a published message, each checked: an id that is a UUID and a category that is a
    short word. Anything else in the message is ignored, so only these two fields can reach a socket."""
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (TypeError, ValueError):
        return []
    events = data.get("events") if isinstance(data, dict) else None
    out = []
    for e in events if isinstance(events, list) else ():
        if not isinstance(e, dict):
            continue
        cat = e.get("category")
        try:
            row_id = str(uuid.UUID(str(e.get("id"))))
        except (TypeError, ValueError, AttributeError):
            continue
        if isinstance(cat, str) and 0 < len(cat) <= 40 and cat.replace("_", "").isalnum():
            out.append({"id": row_id, "category": cat})
        if len(out) >= MAX_BATCH:
            break
    return out


def _publish(text: str) -> None:
    from app.core import redis_guard
    from app.core.database import redis_client
    redis_guard.best_effort("audit_signal.publish", lambda: redis_client.publish(CHANNEL, text))


def _drain_batch(first) -> List[Tuple[str, str]]:
    batch = [first]
    while len(batch) < MAX_BATCH:
        try:
            batch.append(_queue.get_nowait())
        except queue.Empty:
            break
    return batch


def _run() -> None:
    while True:
        batch = []
        try:
            batch = _drain_batch(_queue.get())
            _publish(message(batch))
        except Exception:  # noqa: BLE001 - the worker outlives any one failed publish
            logger.debug("audit signal publish failed", exc_info=True)
        finally:
            for _ in batch:
                _queue.task_done()


def flush(timeout: float) -> bool:
    """Wait, at most `timeout` seconds, until every queued signal has been handed to Redis. For a
    short-lived process (the host account tool), which would otherwise exit before they go out."""
    import time
    deadline = time.monotonic() + timeout
    while _queue.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.02)
    return not _queue.unfinished_tasks


def _ensure_worker() -> None:
    """Start the publishing thread, once per process (a forked child starts its own)."""
    global _worker_pid
    pid = os.getpid()
    if _worker_pid == pid:
        return
    with _worker_lock:
        if _worker_pid == pid:
            return
        threading.Thread(target=_run, name="audit-signal", daemon=True).start()
        _worker_pid = pid
