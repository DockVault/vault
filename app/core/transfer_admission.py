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
import threading


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


class TransferAdmission:
    """A bounded number of transfer slots, with a bounded queue for the overflow.

    Slots are taken and released explicitly rather than through a context manager, because the
    thing that holds one is a streaming response: it outlives the endpoint that started it, and is
    released in the generator's own teardown. That is the same shape as the operation registry
    beside it, deliberately.
    """

    def __init__(self, limit: int, max_waiting: int, wait_seconds: float):
        self._limit = max(1, int(limit))
        self._max_waiting = max(0, int(max_waiting))
        self._wait_seconds = max(0.0, float(wait_seconds))
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

    async def acquire(self):
        """Take a slot, waiting if the deployment is full. Raises :class:`TransferBusy` if not.

        Returns a token, which is what gives the slot back. The waiting room is checked before
        joining it, so a burst that is never going to be served is refused now rather than after a
        timeout each.
        """
        if self._semaphore.locked():
            with self._counter_lock:
                if self._waiting >= self._max_waiting:
                    raise TransferBusy(
                        retry_after=self._retry_after(), waiting=self._waiting, limit=self._limit)
                self._waiting += 1
            try:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=self._wait_seconds)
            except asyncio.TimeoutError:
                raise TransferBusy(
                    retry_after=self._retry_after(), waiting=self._waiting, limit=self._limit)
            finally:
                with self._counter_lock:
                    self._waiting -= 1
        else:
            await self._semaphore.acquire()

        token = object()
        with self._counter_lock:
            self._live.add(token)
        return token

    def release(self, token) -> None:
        """Give a slot back. Anything other than a token from a live acquire does nothing."""
        with self._counter_lock:
            if token not in self._live:
                return
            self._live.discard(token)
        self._semaphore.release()

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
            }
