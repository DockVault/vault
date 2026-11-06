"""Blocking work on stored bytes, run off the web server's event loop, and always to its end.

The web server is one process with one event loop, and its handlers are async: blocking work inside a
handler holds every other request until it ends. Finishing an upload is such work. Its staged chunks are
read, encrypted and written into the file, and the file is forced to the disk; on a 1 GiB file that took 8
to 10 seconds, and every other request (the health check, a listing, a sign-in) waited that long. Every
step that finishes stored bytes inside an async handler runs here instead, in a thread of this module's
own pool: an upload's encryption, assembly, close and sync, the row that lists its file, a copy or a move
between vaults, and the removal of a file that never got its row.

``run_to_end(fn, *args, **kwargs)`` runs ``fn`` in that pool, with the caller's context variables, and
returns what it returns or raises what it raises. Once called, the work runs to its end and the request
waits for it:

- a cancellation of the request while the work runs (the server stopping) does not abandon it: the work
  goes on, the request waits for its end, and the cancellation is passed on after it. So what one call
  does, a file forced to the disk and the row that lists it committed, happens whole or not at all, and
  nothing the request does next (its error handling, closing its database session) runs beside it;
- a cancellation that was already asked for when the call is made does not stop it either; it is passed
  on at the request's next pause after the call.

Three rules for what is run here, which every caller keeps:

- ``fn`` must not need the event loop (no awaiting, no loop-bound objects);
- work on the request's database session (``run_to_end_on_session``) runs only under a transfer slot (an
  upload's completion, a copy, a move to another vault, a folder copy: app/core/transfer_admission.py; a move
  within one vault is a reparent, which copies no bytes, takes no slot and runs on the loop), taken while the request
  holds no connection. Each such call holds its request's connection until it ends, and calls past this
  pool's threads wait here still holding theirs; the slots bound how many there are, and the database pool is
  sized beyond them (app/core/database.py), so they never take the connections the event loop's own requests
  need. Unbounded, a burst of copies held every connection, and the next request's first query waited for
  one on the loop;
- no database row lock is held across a call, nor after one that failed. A lock taken on the loop and held
  while the request waits here would let another request on the loop wait for that lock synchronously,
  stopping the loop; and a lock released only after the call would then never be released. Work that takes
  a lock takes it, and commits, inside ``fn``. Work that uses the request's database session runs through
  ``run_to_end_on_session``, which rolls the session back in the pool's thread when ``fn`` raises: a lock
  taken before the error is released before the request goes on, so its error handling (which may wait here
  again, to remove a file that got no row) holds none, and commits nothing ``fn`` left half done.

The pool is this module's own: not the event loop's default executor, which the /ws/monitor poller parks
threads in, and not the thread pool Starlette runs synchronous endpoints and dependencies in, which work
this long would take from every other request. More calls than it has threads wait their turn there, off
the loop.

It is sized from the transfer ceiling (``workers``): a thread for each transfer the ceilings admit, each of which
holds its thread for as long as its work runs (a folder copy for minutes), and HEADROOM more for what runs here
without a slot (a chunk's sync, a direct upload's chunk write, the brand image), which is short. At a fixed 32,
a raised ceiling let admitted copies and completions take every thread, and every chunk sync then waited behind
them.
"""
import asyncio
import concurrent.futures
import contextvars
import functools
import threading

import anyio

from app.core.transfer_admission import admitted_at_most

# Threads beyond the transfers the ceilings admit, for the short work that runs here without a slot.
HEADROOM = 12
# The least the pool has, as it always had: 20 transfers and 12 more at the default ceiling of 16.
MIN_WORKERS = 32

_pool = None
_pool_size = None
_pool_lock = threading.Lock()


def workers(max_concurrent_transfers) -> int:
    """The pool's threads for the transfer ceiling configured as ``max_concurrent_transfers``: one for each transfer
    the two ceilings admit, and HEADROOM more; never fewer than MIN_WORKERS."""
    return max(MIN_WORKERS, admitted_at_most(max_concurrent_transfers) + HEADROOM)


def _executor():
    """The pool, made at its first use, sized from the ceiling this process was configured with."""
    global _pool, _pool_size
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                from app.core.config import settings
                _pool_size = workers(settings.max_concurrent_transfers)
                _pool = concurrent.futures.ThreadPoolExecutor(max_workers=_pool_size,
                                                              thread_name_prefix="stored-bytes")
    return _pool


def pool_size() -> int:
    """How many threads the pool has."""
    _executor()
    return _pool_size


async def run_to_end(fn, /, *args, **kwargs):
    """Run ``fn(*args, **kwargs)`` in this module's thread pool and return its result; see the module."""
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(_executor(), functools.partial(contextvars.copy_context().run, fn, *args,
                                                                 **kwargs))
    cancelled = None
    # Shielded from the cancellation the web framework asks for, which it would otherwise ask again at every
    # pause until the request ended. A cancellation of the task itself still arrives, once: it is kept, and
    # passed on once the work has ended. asyncio.wait never cancels the work, and never raises its error.
    with anyio.CancelScope(shield=True):
        while not future.done():
            try:
                await asyncio.wait({future})
            except asyncio.CancelledError as exc:
                cancelled = exc
    if cancelled is not None:
        raise cancelled
    return future.result()


async def run_to_end_on_session(db, fn, /, *args, **kwargs):
    """``run_to_end`` for work that uses the request's database session ``db``: when ``fn`` raises, ``db`` is
    rolled back in the pool's thread, before the error comes back to the request. What ``fn`` raises is what
    comes back, also when the rollback fails."""
    return await run_to_end(_rolled_back_when_it_fails, db, fn, *args, **kwargs)


def _rolled_back_when_it_fails(db, fn, /, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except BaseException:
        try:
            db.rollback()
        except Exception:  # noqa: BLE001 -- the error fn raised is the one the request answers for
            pass
        raise
