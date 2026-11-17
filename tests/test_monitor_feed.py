"""A live socket's subscription is used one call at a time, and from a Redis client of its own, offline.

The /ws/monitor endpoint polls its subscription from executor threads and closes it in another. Cancelling the
polling task leaves a poll running in its thread, so the close must wait for it: two calls on one redis-py
PubSub at once let the poll open the closed subscription's connection again after it went back to the pool,
under whoever took it next. app/core/monitor_feed.py holds one lock across every call; a poll after the close
touches nothing. The subscription is made from database.monitor_redis_client, whose pool is not the one the
server's commands use.
"""
import ast
import threading
import time
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


class _Watched:
    """A PubSub that records each call, and any call made while another is still running."""

    def __init__(self, poll_seconds=0.3):
        self.calls = []
        self.overlaps = []
        self._inside = 0
        self._guard = threading.Lock()
        self.poll_seconds = poll_seconds
        self.polling = threading.Event()

    def _enter(self, name):
        with self._guard:
            if self._inside:
                self.overlaps.append(name)
            self._inside += 1
            self.calls.append(name)

    def _leave(self):
        with self._guard:
            self._inside -= 1

    def subscribe(self, *channels):
        self._enter("subscribe")
        self._leave()

    def get_message(self, ignore_subscribe_messages, timeout):
        self._enter("get_message")
        self.polling.set()
        time.sleep(self.poll_seconds)
        self._leave()
        return None

    def unsubscribe(self):
        self._enter("unsubscribe")
        self._leave()

    def close(self):
        self._enter("close")
        self._leave()


class _Client:
    def __init__(self, pubsub):
        self._pubsub = pubsub

    def pubsub(self):
        return self._pubsub


def test_the_close_waits_for_a_poll_in_flight_and_no_later_poll_touches_the_subscription():
    from app.core.monitor_feed import MonitorFeed
    watched = _Watched()
    feed = MonitorFeed(_Client(watched), ["a", "b"])
    feed.subscribe()
    poller = threading.Thread(target=feed.poll, args=(0.1,))
    poller.start()
    assert watched.polling.wait(5)
    # The socket goes: its teardown closes the feed while the poll is still running in its thread.
    feed.close()
    poller.join(5)
    assert watched.overlaps == [], watched.calls
    assert watched.calls == ["subscribe", "get_message", "unsubscribe", "close"]
    # A poll that starts after the close (a cancelled task's thread that only now runs) does nothing.
    assert feed.poll(0.1) is None
    feed.close()
    assert watched.calls == ["subscribe", "get_message", "unsubscribe", "close"]


def test_many_polls_and_a_close_from_many_threads_never_overlap():
    from app.core.monitor_feed import MonitorFeed
    watched = _Watched(poll_seconds=0.01)
    feed = MonitorFeed(_Client(watched), ["a"])
    feed.subscribe()
    threads = [threading.Thread(target=feed.poll, args=(0.01,)) for _ in range(20)]
    for t in threads:
        t.start()
    feed.close()
    for t in threads:
        t.join(5)
    assert watched.overlaps == [], watched.calls
    assert watched.calls.count("close") == 1 and watched.calls[-1] == "close"


def test_the_subscriptions_client_has_a_pool_of_its_own():
    from app.core import database
    shared = database._require_redis_client()
    own = database.monitor_redis_client()
    assert own is not shared
    assert own.connection_pool is not shared.connection_pool
    assert own is database.monitor_redis_client()
    # The same settings as the server's client.
    keys = ("host", "port", "db", "password", "decode_responses", "socket_connect_timeout", "socket_timeout",
            "socket_keepalive", "health_check_interval")
    mine, theirs = own.connection_pool.connection_kwargs, shared.connection_pool.connection_kwargs
    assert {k: mine.get(k) for k in keys} == {k: theirs.get(k) for k in keys}
    assert own.connection_pool.connection_class is shared.connection_pool.connection_class


def _handler():
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.AsyncFunctionDef) and n.name == "websocket_monitor_endpoint")


def test_the_socket_subscribes_through_the_feed_on_its_own_client_and_closes_it():
    handler = _handler()
    src = ast.unparse(handler)
    # No subscription of the server's shared client, and no call on a bare PubSub.
    assert "redis_client.pubsub" not in src and "pubsub." not in src
    assert "MonitorFeed(monitor_redis_client()" in src
    # Every use of the subscription goes through the feed: subscribe, poll and close, each off the event loop.
    for call in ("feed.subscribe", "feed.poll", "feed.close"):
        assert f"run_in_executor(None, {call}" in src, call
    final = next(n for n in ast.walk(handler) if isinstance(n, ast.Try) and n.finalbody)
    assert "feed.close" in ast.unparse(final.finalbody[0])
