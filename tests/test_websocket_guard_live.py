"""The live socket against the running deployment.

Before, uvicorn's defaults let a client offer per-message compression and send a 16 MiB first message,
which /ws/monitor parsed before it knew who was calling (measured in-process: a second of event loop
and 400 MiB for one message), and nothing limited how often one address opened a socket. Now the
server takes no compression and messages of at most a few KiB, the application refuses a message over
its own smaller limit before parsing it, and connects are counted per address. The page's sign-in and
the Activity signal it listens for still work. tests/test_websocket_guard.py covers the same offline.
"""
import http.client
import json
import os
import struct
import subprocess
import threading
import time
from urllib.parse import urlsplit

import pytest

from conftest import ApiClient, BASE_URL
from test_request_body_limit_live import _Memory

websocket = pytest.importorskip("websocket")   # websocket-client

pytestmark = [pytest.mark.integration, pytest.mark.websocket]

KiB, MiB = 1024, 1024 * 1024
_REDIS = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _by_address(url):
    """Resolving "localhost" can take seconds on some hosts (an IPv6 attempt first), which would
    show up as a slow server; the connect flood below must also fit inside the limit's window."""
    return url.replace("://localhost:", "://127.0.0.1:")


def _url(base_url):
    return _by_address(base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/monitor")


class _Health:
    """The slowest /health answer while something else runs: a frozen event loop shows here."""

    def __init__(self):
        parts = urlsplit(_by_address(BASE_URL))
        self.host, self.port = parts.hostname, parts.port
        self.https = parts.scheme == "https"
        self.worst, self.stopping = 0.0, False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stopping:
            cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
            conn = cls(self.host, self.port, timeout=60)
            started = time.monotonic()
            try:
                conn.request("GET", "/health")
                conn.getresponse().read()
                self.worst = max(self.worst, time.monotonic() - started)
            except OSError:
                self.worst = max(self.worst, 60.0)
            finally:
                conn.close()
            time.sleep(0.1)

    def stop(self):
        self.stopping = True
        self.thread.join(70)
        return self.worst


def _close_code(ws, seconds=5):
    """The code of the close frame the server sends within `seconds`, or None if the connection simply
    dropped. Data frames before it are skipped."""
    ws.settimeout(seconds)
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            opcode, frame = ws.recv_data_frame(True)
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                return struct.unpack("!H", frame.data[:2])[0] if len(frame.data) >= 2 else None
    except (websocket.WebSocketConnectionClosedException, ConnectionError, OSError):
        return None
    raise AssertionError(f"the socket was still open after {seconds} s")


def _send_quietly(ws, text):
    """Send one text message; the server may cut the connection before the client has finished."""
    try:
        ws.send(text)
    except (websocket.WebSocketConnectionClosedException, ConnectionError, OSError):
        pass


def _redis(*args):
    return subprocess.run(["docker", "exec", _REDIS, "redis-cli", *args],
                          capture_output=True, text=True, timeout=30)


def _clear_connect_counts():
    keys = _redis("--scan", "--pattern", "rate_limit:ws_connect:*").stdout.split()
    if keys:
        _redis("del", *keys)


def _connect_limit():
    out = subprocess.run(["docker", "exec", _API, "printenv", "RATE_LIMIT_WS_CONNECT"],
                         capture_output=True, text=True, timeout=30).stdout.strip()
    return int(out) if out else 120


def test_the_server_takes_no_per_message_compression(base_url):
    ws = websocket.create_connection(
        _url(base_url), timeout=10,
        header=["Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits"])
    try:
        headers = {k.lower(): v for k, v in (ws.getheaders() or {}).items()}
        assert "sec-websocket-extensions" not in headers, headers
    finally:
        ws.close()


def test_a_first_message_over_the_servers_limit_is_refused_at_once_and_costs_no_memory(base_url):
    memory, health = _Memory(), _Health()
    try:
        ws = websocket.create_connection(_url(base_url), timeout=10)
        started = time.monotonic()
        try:
            # Just under uvicorn's old 16 MiB default: read whole and parsed before; refused now on
            # the frame's header, before its payload is read.
            _send_quietly(ws, '{"type":"auth","token":"' + "t" * (15 * MiB) + '"}')
            code = _close_code(ws)
        finally:
            seconds = time.monotonic() - started
            ws.close()
    finally:
        worst = health.stop()
        rise = memory.rise()
    print(f"closed with {code} after {seconds:.2f} s; memory +{rise / MiB:.1f} MiB; /health worst {worst:.2f} s")
    assert code in (1009, None), code
    assert seconds < 5, f"refusing the message took {seconds:.1f} s"
    assert rise < 8 * MiB, f"the API's memory rose {rise / MiB:.1f} MiB for a refused message"
    assert worst < 1, f"/health took {worst:.1f} s to answer while the message was refused"


def test_a_first_message_over_the_applications_limit_is_closed_with_1009_before_it_is_parsed(base_url):
    """Under the server's limit but over the application's: the guard closes the socket before the
    handler parses it, so the handler never answers it."""
    ws = websocket.create_connection(_url(base_url), timeout=10)
    try:
        ws.send('{"type":"auth","token":"x","pad":[' + ",".join(["{}"] * 3000) + "]}")   # about 9 KiB
        ws.settimeout(5)
        opcode, frame = ws.recv_data_frame(True)
        assert opcode == websocket.ABNF.OPCODE_CLOSE, (opcode, frame.data[:200])
        assert struct.unpack("!H", frame.data[:2])[0] == 1009
    finally:
        ws.close()


def test_a_sign_in_opens_the_socket_and_the_activity_signal_still_arrives(base_url, admin):
    ws = websocket.create_connection(_url(base_url), timeout=10)
    other = admin.create_user(role="user")
    try:
        ws.send(json.dumps({"type": "auth", "token": admin.token}))
        ws.settimeout(8)
        first = json.loads(ws.recv())
        assert first["type"] == "connected", first
        ws.send(json.dumps({"type": "ping"}))
        # Something happens: another person signs in, which writes an audit row and signals it.
        ApiClient().login(other["_username"], other["_password"])
        deadline, frames = time.monotonic() + 10, []
        while time.monotonic() < deadline:
            try:
                frames.append(json.loads(ws.recv()))
            except websocket.WebSocketTimeoutException:
                continue
            if any(f.get("type") == "activity" for f in frames):
                break
        assert any(f.get("type") == "pong" for f in frames), frames
        assert any(f.get("type") == "activity" for f in frames), frames
    finally:
        ws.close()
        admin.delete_user(other["id"])


def test_a_flood_of_connects_from_one_address_is_cut_off_and_the_count_resets(base_url, admin):
    """Every test here connects from the same address, so the count is cleared before and after."""
    limit = _connect_limit()
    if limit <= 0:
        pytest.skip("RATE_LIMIT_WS_CONNECT is 0 on this deployment: connects are not limited")
    _clear_connect_counts()
    opened, refused, seconds = 0, None, None
    try:
        for _ in range(limit + 5):
            started = time.monotonic()
            try:
                ws = websocket.create_connection(_url(base_url), timeout=10)
            except websocket.WebSocketBadStatusException as exc:
                refused, seconds = exc.status_code, time.monotonic() - started
                break
            opened += 1
            ws.close()
        assert refused == 403, f"{opened} connects from one address, none refused"
        assert 0 < opened <= limit, opened
        assert seconds < 2, f"a refused connect took {seconds:.1f} s"
    finally:
        _clear_connect_counts()
    ws = websocket.create_connection(_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": admin.token}))
        ws.settimeout(8)
        assert json.loads(ws.recv())["type"] == "connected"
    finally:
        ws.close()
