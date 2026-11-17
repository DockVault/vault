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
    # After the socket's slot is given back (its first statement), the feed is closed.
    assert "feed.close" in ast.unparse(final.finalbody[1])


def test_a_subscribe_that_runs_after_the_close_touches_nothing():
    # The executor thread of a subscribe may start only after the socket has gone and the feed was closed.
    from app.core.monitor_feed import MonitorFeed
    watched = _Watched()
    feed = MonitorFeed(_Client(watched), ["a"])
    feed.close()
    feed.subscribe()
    assert watched.calls == ["unsubscribe", "close"], watched.calls


# --- How many live sockets an account may hold, and how often a socket asks whether its session still stands ---

def test_an_account_holds_at_most_its_number_of_sockets_and_each_ending_gives_one_back():
    from app.core.monitor_feed import SOCKETS_PER_ACCOUNT, SocketSlots
    assert SOCKETS_PER_ACCOUNT == 10
    slots = SocketSlots()
    assert all(slots.take("ana") for _ in range(SOCKETS_PER_ACCOUNT))
    assert slots.take("ana") is False, "one socket past the number was let in"
    # Another account is counted on its own.
    assert slots.take("quinn") is True
    slots.give_back("ana")
    assert slots.held("ana") == SOCKETS_PER_ACCOUNT - 1
    assert slots.take("ana") is True and slots.take("ana") is False
    for _ in range(SOCKETS_PER_ACCOUNT):
        slots.give_back("ana")
    assert slots.held("ana") == 0
    # Giving back more than was taken never goes below nothing, nor lets in more than the number.
    slots.give_back("ana")
    assert slots.held("ana") == 0
    assert all(slots.take("ana") for _ in range(SOCKETS_PER_ACCOUNT)) and slots.take("ana") is False


def test_sockets_taken_and_given_back_from_many_threads_keep_the_count():
    from app.core.monitor_feed import SocketSlots
    slots = SocketSlots(per_account=10)
    got = []

    def one():
        if slots.take("ana"):
            got.append(1)
            time.sleep(0.01)
            slots.give_back("ana")

    threads = [threading.Thread(target=one) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert slots.held("ana") == 0 and got


def _try_with_finally(handler):
    return next(n for n in handler.body if isinstance(n, ast.Try) and n.finalbody)


def test_the_socket_takes_a_slot_after_its_session_is_checked_and_always_gives_it_back():
    handler = _handler()
    src = ast.unparse(handler)
    # Nothing holds a slot before the socket's session is checked; the slot is taken before the socket
    # subscribes, and a socket past the number is told why and closed.
    assert src.index("slot_of = None") < src.index("try:")
    take = src.index("if not SOCKET_SLOTS.take(slot_key(user_id, temporary_credential_id if is_temporary else None)):")
    assert src.index("verify_access_token(token)") < take < src.index("MonitorFeed(")
    refusal = src[take:src.index("slot_of = slot_key(user_id, temporary_credential_id if is_temporary else None)")]
    assert "'message': TOO_MANY_SOCKETS" in refusal and "return" in refusal
    # Closed with a code of its own, after the sentence, so the web app can tell it from any other close.
    assert refusal.index("'message': TOO_MANY_SOCKETS") < refusal.index("websocket.close(code=SOCKET_REFUSED_CLOSE)")
    assert refusal.count("websocket.close(") == 1
    from app.core.monitor_feed import SOCKET_REFUSED_CLOSE
    assert SOCKET_REFUSED_CLOSE == 4429
    # Every way out of the handler's try runs its finally, whose first statement gives the slot back.
    first = ast.unparse(_try_with_finally(handler).finalbody[0])
    assert first == "if slot_of is not None:\n    SOCKET_SLOTS.give_back(slot_of)", first
    from app.core.monitor_feed import TOO_MANY_SOCKETS
    assert TOO_MANY_SOCKETS == "Too many live connections for this account; close another tab."


def test_the_socket_asks_whether_its_session_stands_every_five_seconds_by_the_clock():
    src = ast.unparse(_handler())
    assert "loops" not in src
    assert "if _ws_time.monotonic() - checked_at >= 5:" in src
    send_events = src[src.index("async def send_events"):src.index("async def receive_messages")]
    assert send_events.index("checked_at = _ws_time.monotonic()") < send_events.index("_ws_session_invalid")


def test_the_live_sockets_pool_states_its_size():
    from app.core import database
    assert database.MONITOR_MAX_CONNECTIONS == 100
    own = database.monitor_redis_client()
    assert own.connection_pool.max_connections == database.MONITOR_MAX_CONNECTIONS



# --- Where the slot is taken and given back, and the timed check (each a statement of its own) ---

def test_the_socket_takes_its_slot_once_and_gives_it_back_once():
    src = ast.unparse(_handler())
    assert src.count("SOCKET_SLOTS.take(") == 1
    assert src.count("SOCKET_SLOTS.give_back(") == 1


def test_the_slot_is_taken_after_every_session_check_and_recorded_at_once():
    handler = _handler()
    body = _try_with_finally(handler).body
    takes = [k for k, n in enumerate(body) if isinstance(n, ast.If) and "SOCKET_SLOTS.take(" in ast.unparse(n.test)]
    assert len(takes) == 1, "the take is not a statement of the handler's own try"
    i = takes[0]
    checks = [n for n in body[:i] if isinstance(n, ast.Try)
              and any(h.type is not None and ast.unparse(h.type) == "ValueError" for h in n.handlers)]
    assert checks and "Account inactive or locked" in ast.unparse(checks[-1])
    assert ast.unparse(body[i + 1]) == "slot_of = slot_key(user_id, temporary_credential_id if is_temporary else None)"


def test_the_timed_check_restarts_its_clock_each_time():
    send_events = next(n for n in ast.walk(_handler())
                       if isinstance(n, ast.AsyncFunctionDef) and n.name == "send_events")
    ifs = [n for n in ast.walk(send_events) if isinstance(n, ast.If) and "checked_at >= 5" in ast.unparse(n.test)]
    assert len(ifs) == 1 and ast.unparse(ifs[0].body[0]) == "checked_at = _ws_time.monotonic()"


def test_the_live_sockets_pool_takes_its_size_from_the_constant(monkeypatch):
    from app.core import database
    monkeypatch.setattr(database, "_monitor_redis_client", None)
    monkeypatch.setattr(database, "MONITOR_MAX_CONNECTIONS", 7)
    assert database.monitor_redis_client().connection_pool.max_connections == 7


# --- A temporary credential's sockets: counted on their own, and given nothing to forward ---

def test_a_temporary_credentials_sockets_are_counted_apart_from_the_account_it_belongs_to():
    from app.core.monitor_feed import SOCKETS_PER_ACCOUNT, SocketSlots, slot_key
    assert slot_key("u1") == "account:u1"
    assert slot_key("u1", "c1")[0] == "temporary-credential:c1"
    assert slot_key("u1", "c1") != slot_key("u1") and slot_key("u1", "c1") != slot_key("u1", "c2")
    slots = SocketSlots()
    assert all(slots.take(slot_key("u1")) for _ in range(SOCKETS_PER_ACCOUNT))
    # The account's places are full; its temporary credential still has its own, and they run out on their own.
    assert all(slots.take(slot_key("u1", "c1")) for _ in range(SOCKETS_PER_ACCOUNT))
    assert slots.take(slot_key("u1", "c1")) is False and slots.take(slot_key("u1")) is False
    assert slots.take(slot_key("u1", "c2")) is True


def test_an_accounts_temporary_credentials_hold_at_most_their_total_together():
    # Each temporary credential has ten places of its own, and all of one account's credentials share a total, so
    # an account with many credentials cannot hold sockets without bound. The account's own places are apart.
    from app.core.monitor_feed import SOCKETS_PER_ACCOUNT, TEMPORARY_SOCKETS_PER_ACCOUNT, SocketSlots, slot_key
    assert TEMPORARY_SOCKETS_PER_ACCOUNT == 2 * SOCKETS_PER_ACCOUNT == 20
    assert slot_key("u1", "c1")[1] == slot_key("u1", "c2")[1] == "temporary-credentials-of:u1"
    slots = SocketSlots()
    for credential in ("c1", "c2"):
        assert all(slots.take(slot_key("u1", credential)) for _ in range(SOCKETS_PER_ACCOUNT))
    assert slots.held("temporary-credentials-of:u1") == TEMPORARY_SOCKETS_PER_ACCOUNT
    assert slots.take(slot_key("u1", "c3")) is False, "a third credential's first socket is past the total"
    # A refused socket holds nothing, not even its credential's own place.
    assert slots.held("temporary-credential:c3") == 0
    # The account's own ten are untouched, and another account's credentials have their own total.
    assert all(slots.take(slot_key("u1")) for _ in range(SOCKETS_PER_ACCOUNT))
    assert slots.take(slot_key("u2", "c9")) is True
    # A credential's socket that ends frees a place in the total too.
    slots.give_back(slot_key("u1", "c1"))
    assert slots.held("temporary-credential:c1") == SOCKETS_PER_ACCOUNT - 1
    assert slots.take(slot_key("u1", "c3")) is True
    assert slots.take(slot_key("u1", "c3")) is False and slots.take(slot_key("u1", "c1")) is False


def test_the_handler_counts_a_temporary_session_by_its_credential():
    src = ast.unparse(_handler())
    assert "temporary_credential_id = _sess[1]" in src
    # Read from the session row the handshake has just checked, before the slot is taken.
    assert src.index("temporary_credential_id = _sess[1]") < src.index("SOCKET_SLOTS.take(")


def test_a_temporary_session_builds_no_feed_and_polls_nothing():
    handler = _handler()
    body = _try_with_finally(handler).body
    feed_if = [n for n in body if isinstance(n, ast.If) and "MonitorFeed(" in ast.unparse(n)]
    assert len(feed_if) == 1 and ast.unparse(feed_if[0].test) == "not is_temporary", "the feed is built for every session"
    assert not feed_if[0].orelse
    send_events = next(n for n in ast.walk(handler) if isinstance(n, ast.AsyncFunctionDef) and n.name == "send_events")
    src = ast.unparse(send_events)
    # With no feed the loop waits and checks again, before it would poll; the token's end and the timed session
    # check come before that, so a socket with no feed is still closed when its session ends.
    no_feed = src.index("if feed is None:")
    assert src.index("if token_exp and _ws_time.time() >= token_exp:") < no_feed
    assert src.index("if _ws_time.monotonic() - checked_at >= 5:") < no_feed < src.index("feed.poll")
    branch = next(n for n in ast.walk(send_events) if isinstance(n, ast.If) and ast.unparse(n.test) == "feed is None")
    first = branch.body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Await), ast.unparse(first)
    call = first.value.value
    assert ast.unparse(call.func) == "asyncio.sleep" and len(call.args) == 1
    assert isinstance(call.args[0], ast.Constant) and call.args[0].value >= 0.1, ast.unparse(call)
    assert ast.unparse(branch.body[-1]) == "continue"
    assert "if feed is not None:" in ast.unparse(_try_with_finally(handler).finalbody)


def test_a_refused_socket_is_logged_without_naming_its_session():
    # The refusal's log line is one plain sentence: no account, credential or other value formatted into it.
    handler = _handler()
    take = next(n for n in ast.walk(handler) if isinstance(n, ast.If) and "SOCKET_SLOTS.take(" in ast.unparse(n.test))
    prints = [n for n in ast.walk(take) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "print"]
    assert len(prints) == 1 and not prints[0].keywords and len(prints[0].args) == 1
    arg = prints[0].args[0]
    assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), ast.unparse(arg)


# --- The session's end ---

def test_the_socket_closes_at_its_tokens_end():
    handler = _handler()
    src = ast.unparse(handler)
    assert "token_exp = payload.get('exp')" in src
    send_events = ast.unparse(next(n for n in ast.walk(handler)
                                   if isinstance(n, ast.AsyncFunctionDef) and n.name == "send_events"))
    end = send_events.index("if token_exp and _ws_time.time() >= token_exp:")
    assert send_events[end:].split("\n", 2)[1].strip() == "break"
    assert end < send_events.index("checked_at >= 5")


class _Rows:
    """A database session that answers the re-check's two queries: the session row, then the account."""

    def __init__(self, session_row, account):
        self._answers = [session_row, account]

    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        return self._answers.pop(0)

    def close(self):
        pass


@pytest.mark.parametrize("revoked, is_active, temporary, ends", [
    (True, False, False, True),    # revoked and inactive
    (False, True, False, False),   # a session in force
    (True, True, False, True),     # revoked
    (False, False, False, False),  # a regular session's row inactive, not revoked: superseded or idle, still valid
    (False, False, True, True),    # a temporary credential invalidated
])
def test_the_re_check_ends_a_session_as_requests_are_ended(monkeypatch, revoked, is_active, temporary, ends):
    import uuid
    from types import SimpleNamespace
    from app.api import api_server
    from app.core import database
    from app.services import auth_service
    account = SimpleNamespace(is_active=True)
    monkeypatch.setattr(auth_service, "is_token_denylisted", lambda token: False)
    monkeypatch.setattr(auth_service, "admin_locked", lambda user: False)
    monkeypatch.setattr(database, "SessionLocal", lambda: _Rows((revoked, is_active), account))
    assert api_server._ws_session_invalid("tok", str(uuid.uuid4()), temporary) is ends
