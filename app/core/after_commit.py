"""Work that waits for a transaction's commit: the one pair of session listeners every module shares.

A step queues what it wants done once its transaction commits with ``later(db, kind, item)``. When the outermost
transaction commits, the handler registered for each kind receives the items queued for it, in the order they
were queued; when it ends any other way (a rollback, a close), they are dropped, so nothing is done for a step
that did not happen. A handler that fails is reported and never undoes the commit.

Why one dispatcher: SQLAlchemy runs a session's ``after_commit`` listeners from a list it is iterating, and adding
a listener to the Session class while it does breaks that commit with "deque mutated during iteration", raised
by commit() after the rows are already in the database. A module that added its own listener when it was first
imported did exactly that whenever its first import happened inside another listener (a notice's delivery
imports the web app, which imports more modules). So the listeners are added here, once, when this module is
first imported, which app/core/models.py does: before any session of the app exists. A module that needs work
after a commit registers a handler (``handler(kind, fn)``), which changes nothing SQLAlchemy iterates, whenever it
is imported.
"""
from __future__ import annotations

from typing import Callable, Dict, List

_HANDLERS: Dict[str, Callable[[List], None]] = {}
_INFO_KEY = "_after_commit_work"
# Set on the Session class once install() has added the listeners to it.
_INSTALLED = "_after_commit_dispatcher_installed"


def handler(kind: str, fn: Callable[[List], None]) -> None:
    """Have ``fn(items)`` run after each commit that queued items of ``kind``. A later registration of the same
    kind replaces the earlier one (a module imported again registers again)."""
    _HANDLERS[kind] = fn


def later(db, kind: str, item) -> None:
    """Queue ``item`` for the handler of ``kind``, to run once ``db``'s transaction commits."""
    db.info.setdefault(_INFO_KEY, {}).setdefault(kind, []).append(item)


def pending(db, kind: str) -> list:
    """What ``db`` has queued for ``kind`` and not yet handed over (a copy)."""
    return list((db.info.get(_INFO_KEY) or {}).get(kind) or ())


def _after_commit(session):
    work = session.info.pop(_INFO_KEY, None)
    if not work:
        return
    for kind, items in work.items():
        fn = _HANDLERS.get(kind)
        if fn is None:
            print(f"Warning: nothing handles the work queued after a commit ({kind})")
            continue
        try:
            fn(items)
        except Exception as exc:  # noqa: BLE001 -- work after a commit never undoes it
            print(f"Warning: the work queued after a commit failed ({kind}: {type(exc).__name__})")


def _after_transaction_end(session, transaction):
    # The outermost transaction ended without the commit taking the work: it was never committed.
    if transaction.parent is None:
        session.info.pop(_INFO_KEY, None)


def install() -> None:
    """Listen on every session for the end of its transactions. Idempotent; done when this module is imported."""
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    if getattr(Session, _INSTALLED, False):
        return
    event.listen(Session, "after_commit", _after_commit)
    event.listen(Session, "after_transaction_end", _after_transaction_end)
    setattr(Session, _INSTALLED, True)


install()
