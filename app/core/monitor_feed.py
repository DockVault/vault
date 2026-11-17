"""One live socket's subscription to the Redis channels it forwards (the /ws/monitor endpoint).

A redis-py PubSub is not safe across threads, and the socket calls it from executor threads: the subscription,
a poll every tenth of a second, and the teardown. Cancelling the task that polls does not stop a poll already
running in its thread.

So every call goes through one lock: close() never runs beside a poll in flight, it runs once, and a poll or a
subscribe that starts after it touches nothing, so nothing uses the subscription's connection once it is back in
its pool. The subscription is also made from a client of its own (database.monitor_redis_client), whose
connections the rest of the server never takes.
"""
import threading

# How many live sockets one account may hold open at once in one server process. A temporary credential's
# sockets are counted apart, each credential on its own (slot_key), so they never take the places of the account
# it belongs to.
SOCKETS_PER_ACCOUNT = 10

# What a socket past that number is told before it is closed.
# The close code of a socket refused for that (a private-use code): the web app tries again after a minute.
SOCKET_REFUSED_CLOSE = 4429
TOO_MANY_SOCKETS = "Too many live connections for this account; close another tab."


def slot_key(user_id, temporary_credential_id=None) -> str:
    """What a socket's place is counted against: the account, or, for a temporary credential's session, that
    credential (its token names the account it belongs to, so the account's id would put its sockets among the
    account's own)."""
    if temporary_credential_id is not None:
        return f"temporary-credential:{temporary_credential_id}"
    return f"account:{user_id}"


class SocketSlots:
    """The live sockets each account holds open, counted per process. take() before the socket subscribes;
    give_back() once for each take() that succeeded, whichever way the socket ends."""

    def __init__(self, per_account: int = SOCKETS_PER_ACCOUNT):
        self._per_account = per_account
        self._lock = threading.Lock()
        self._held = {}

    def take(self, account) -> bool:
        key = str(account)
        with self._lock:
            held = self._held.get(key, 0)
            if held >= self._per_account:
                return False
            self._held[key] = held + 1
            return True

    def give_back(self, account) -> None:
        key = str(account)
        with self._lock:
            held = self._held.get(key, 0) - 1
            if held > 0:
                self._held[key] = held
            else:
                self._held.pop(key, None)

    def held(self, account) -> int:
        with self._lock:
            return self._held.get(str(account), 0)


# The process's own count, shared by every socket the server opens.
SOCKET_SLOTS = SocketSlots()


class MonitorFeed:
    """The subscription of one socket, used from any thread, one call at a time."""

    def __init__(self, client, channels):
        self._lock = threading.Lock()
        self._channels = tuple(channels)
        self._pubsub = client.pubsub()
        self._closed = False

    def subscribe(self) -> None:
        with self._lock:
            if not self._closed:
                self._pubsub.subscribe(*self._channels)

    def poll(self, timeout: float):
        """The next message, or None (nothing within `timeout` seconds, or the feed is closed)."""
        with self._lock:
            if self._closed:
                return None
            return self._pubsub.get_message(True, timeout)

    def close(self) -> None:
        """Unsubscribe and close, once: after a poll in flight has finished, and before any later one."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._pubsub.unsubscribe()
            except Exception:
                pass
            try:
                self._pubsub.close()
            except Exception:
                pass
