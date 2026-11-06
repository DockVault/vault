"""How many transfers a deployment will carry at once.

Every transfer now costs a bounded, roughly constant amount of memory -- about 40 MB for an HTTP
transfer of any size, one or two records for an open SFTP handle. What was never bounded is how
many of them happen at the same time. A hundred simultaneous downloads were all attempted, and the
count that existed fed a dashboard statistic and gated nothing.

Bounding one transfer and not their number leaves the same failure available, reached a different
way: the per-transfer figure is what makes a limit meaningful, not what makes it unnecessary.

The rules this implements:

- **Nothing is silently dropped.** A caller that arrives while the deployment is full waits for a
  slot. Only when it has waited too long, or when even the waiting room is full, is it turned away.
- **Being turned away does not look like a failed transfer.** It is a distinct status with a
  `Retry-After`, so a client can tell "come back shortly" from "this file is broken" -- a
  distinction the caller cannot make if both arrive as a five hundred.
- **Waiting is bounded too.** An unbounded queue is an unbounded memory cost of its own, and a
  caller left waiting indefinitely is a worse experience than a prompt refusal it can act on.
"""

import asyncio
import math
import threading


def ceiling(limit) -> int:
    """The slots a ceiling configured as ``limit`` has: at least one."""
    return max(1, int(limit))


def link_ceiling(limit) -> int:
    """The slots of the anonymous upload links' completions beside a ceiling configured as ``limit``: a
    quarter of it, at least one (receiver_transfer_admission in app/api/api_server.py)."""
    return max(1, int(limit) // 4)


def copy_share(limit) -> int:
    """The slots one account's copies, moves to another vault and folder copies may hold at once, beside a ceiling
    configured as ``limit``: a quarter of it, at least one. A copy needs no slow client to last: one account's
    folder copies of a large tree held every slot for minutes, and everyone else's downloads and uploads waited,
    then were refused."""
    return max(1, int(limit) // 4)


def admitted_at_most(limit) -> int:
    """The most transfers the two ceilings admit at once, for a ceiling configured as ``limit``. Each may hold
    a database connection while it runs (a download, an upload's completion, a copy or a move, finished in a
    thread of app/core/off_loop.py), so app/core/database.py sizes its pool by this."""
    return ceiling(limit) + link_ceiling(limit)


class TransferBusy(Exception):
    """The deployment is carrying as many transfers as it will, and this one waited long enough.

    Carries the interval a caller should wait before trying again, so the refusal is actionable
    rather than merely a rejection.
    """

    def __init__(self, retry_after: int, waiting: int, limit: int):
        super().__init__(
            f"The server is handling its maximum of {limit} concurrent transfers")
        self.retry_after = retry_after
        self.waiting = waiting
        self.limit = limit


class ShareBusy(TransferBusy):
    """One holder (an account) already holds its share of the slots, and the acquires of its own waiting for one of
    them fill its waiting room, or one of them waited for its share as long as it may.

    Not the deployment being full: it may have slots free. So it says whose share is in use, and is not counted as
    load the deployment shed (``refused``): an operator reading that count sizes the ceiling by it, and one account
    at its share says nothing about the ceiling."""

    def __init__(self, retry_after: int, share: int):
        TransferBusy.__init__(self, retry_after, waiting=0, limit=share)
        self.args = (f"This account already has its share of {share} transfers running",)
        self.share = share


class TransferAdmission:
    """A bounded number of transfer slots, with a bounded queue for the overflow.

    Slots are taken and released explicitly rather than through a context manager, because the
    thing that holds one is a streaming response: it outlives the endpoint that started it, and is
    released in the generator's own teardown. That is the same shape as the operation registry
    beside it, deliberately.
    """

    # A wait long enough that nobody is coming back for the answer. Configuring one is the same
    # mistake as configuring no timeout at all, and it has to be bounded somewhere: the refusal
    # carries a Retry-After, which is an integer number of seconds, so an unbounded float here
    # turns every refusal into a server error instead of a "come back shortly".
    MAX_WAIT_SECONDS = 3600.0

    def __init__(self, limit: int, max_waiting: int, wait_seconds: float):
        self._limit = ceiling(limit)
        # holder -> [a semaphore of its share, the acquires using it, those of them waiting for it]: see acquire().
        # Touched on the loop only, as the semaphores are.
        self._holders = {}
        self._holder_of = {}
        self._max_waiting = max(0, int(max_waiting))
        self._wait_seconds = self._usable_wait(wait_seconds)
        self._semaphore = asyncio.Semaphore(self._limit)
        # A token per admitted transfer, rather than a count. A count cannot tell a release by the
        # holder from a release by something that never held anything, and it is wrong in a way
        # that is hard to see: a stray release hands out a slot nobody took, quietly raising the
        # real ceiling above the configured one. It also cannot be read correctly while a waiter is
        # between being woken and being counted.
        #
        # Guarded by a plain lock rather than an asyncio primitive because the statistics are read
        # by an endpoint that is not necessarily on the loop this gate runs on.
        self._counter_lock = threading.Lock()
        self._live = set()
        self._waiting = 0
        # Acquires waiting for their holder's share, in their holders' own rooms (see acquire()).
        self._waiting_for_share = 0
        self._refused_over_share = 0
        # Counted since start, so an operator can tell "sized correctly" from "shed load all
        # afternoon". Without it the only trace of a refusal is a 503 in the access log, which
        # says nothing about how close to the ceiling the deployment usually runs.
        self._refused = 0
        self._peak_in_flight = 0
        # Every slot ever handed out. Read beside the refusal count it is the shed-load ratio, and
        # it is the only external evidence of how many times a request was admitted -- which is
        # how a caller can tell one transfer from several sharing a request.
        self._admitted = 0

    @classmethod
    def _usable_wait(cls, wait_seconds) -> float:
        """The configured wait, as a number of seconds this can actually act on.

        A float field accepts `inf` and `nan`, and both arrive here intact. `inf` reads as "wait
        as long as it takes", which is honoured up to the ceiling above rather than allowed to
        break the refusal path; `nan` is not a duration at all and reads as no wait.
        """
        value = float(wait_seconds)
        if math.isnan(value):
            return 0.0
        return min(cls.MAX_WAIT_SECONDS, max(0.0, value))

    async def acquire(self, holder=None, share=None):
        """Take a slot, waiting if the deployment is full. Raises :class:`TransferBusy` if not.

        Returns a token, which is what gives the slot back. The waiting room is checked before
        joining it, so a burst that is never going to be served is refused now rather than after a
        timeout each.

        With a ``holder`` (an account), at most ``share`` of the slots are held by that holder's
        acquires at once: one past its share waits for one of its own to end, within the same wait as for
        a slot, in a waiting room of the holder's own, as large as the deployment's. So one account's copies
        cannot hold every slot while everyone else waits, nor fill the deployment's waiting room so that
        everyone else is refused at once: only an acquire that holds its share waits there (for a slot),
        at most ``share`` of them for a holder. One past its share when the holder's own room is full, or
        that waited for its share as long as it may, is refused with :class:`ShareBusy`.
        """
        if holder is None:
            await self._take(self._semaphore, self._wait_seconds)
        else:
            loop = asyncio.get_running_loop()
            started = loop.time()
            entry = self._holders.get(holder)
            if entry is None:
                entry = self._holders[holder] = [asyncio.Semaphore(ceiling(share)), 0, 0]
            entry[1] += 1
            try:
                await self._take_share(entry, ceiling(share), self._wait_seconds)
                try:
                    await self._take(self._semaphore, self._wait_seconds - (loop.time() - started))
                except BaseException:
                    entry[0].release()
                    raise
            except BaseException:
                self._let_go(holder, entry)
                raise

        token = object()
        with self._counter_lock:
            self._live.add(token)
            if holder is not None:
                self._holder_of[token] = holder
            self._admitted += 1
            self._peak_in_flight = max(self._peak_in_flight, len(self._live))
        return token

    async def _take(self, semaphore, wait):
        """Take ``semaphore``: at once when it is free, otherwise through the waiting room, for up to ``wait``
        seconds. Raises :class:`TransferBusy` when the waiting room is full or the wait runs out."""
        if not semaphore.locked():
            await semaphore.acquire()
            return
        with self._counter_lock:
            if self._waiting >= self._max_waiting:
                waiting = self._waiting
                self._refused += 1
                raise TransferBusy(
                    retry_after=self._retry_after(), waiting=waiting, limit=self._limit)
            self._waiting += 1
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=max(0.0, wait))
        except asyncio.TimeoutError:
            with self._counter_lock:
                # Minus this caller: it is being refused, not left waiting, and reporting
                # itself as one of the queue makes a deployment look busier than it is.
                waiting = max(0, self._waiting - 1)
                self._refused += 1
            raise TransferBusy(
                retry_after=self._retry_after(), waiting=waiting, limit=self._limit)
        finally:
            with self._counter_lock:
                self._waiting -= 1

    async def _take_share(self, entry, share, wait):
        """Take the holder's share (``entry``): at once when it is free, otherwise through the holder's own waiting
        room, for up to ``wait`` seconds. Raises :class:`ShareBusy` when that room is full or the wait runs out."""
        semaphore = entry[0]
        if not semaphore.locked():
            await semaphore.acquire()
            return
        with self._counter_lock:
            if entry[2] >= self._max_waiting:
                self._refused_over_share += 1
                raise ShareBusy(retry_after=self._retry_after(), share=share)
            entry[2] += 1
            self._waiting_for_share += 1
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=max(0.0, wait))
        except asyncio.TimeoutError:
            with self._counter_lock:
                self._refused_over_share += 1
            raise ShareBusy(retry_after=self._retry_after(), share=share)
        finally:
            with self._counter_lock:
                entry[2] -= 1
                self._waiting_for_share -= 1

    def _let_go(self, holder, entry):
        """One acquire of ``holder`` no longer uses its share; the entry goes once none does."""
        entry[1] -= 1
        if entry[1] <= 0 and self._holders.get(holder) is entry:
            del self._holders[holder]

    def release(self, token) -> None:
        """Give a slot back. Anything other than a token from a live acquire does nothing."""
        with self._counter_lock:
            if token not in self._live:
                return
            self._live.discard(token)
            holder = self._holder_of.pop(token, None)
        self._semaphore.release()
        if holder is not None:
            entry = self._holders.get(holder)
            if entry is not None:
                entry[0].release()
                self._let_go(holder, entry)

    def _retry_after(self) -> int:
        """Seconds to suggest. Long enough to be worth honouring, short enough to be useful."""
        return max(1, int(self._wait_seconds))

    @property
    def limit(self) -> int:
        return self._limit

    def stats(self) -> dict:
        with self._counter_lock:
            return {
                "limit": self._limit,
                "in_flight": len(self._live),
                "waiting": self._waiting,
                "max_waiting": self._max_waiting,
                "wait_seconds": self._wait_seconds,
                "peak_in_flight": self._peak_in_flight,
                "refused": self._refused,
                "admitted": self._admitted,
                # Waiting for, and refused past, an account's own share: not the deployment's load.
                "waiting_for_share": self._waiting_for_share,
                "refused_over_share": self._refused_over_share,
            }
