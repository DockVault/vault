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
