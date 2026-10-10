"""A WebSocket handshake's query reaches no line on a running stack, only its names.

uvicorn writes a handshake, with its path and query, to its error log rather than the access log, so the
access-log filter never saw it. A handshake to the live monitor (accepted before it asks for a token) and
one to a path that has no WebSocket (refused) are both sent here with a value in the query; neither value
reaches the server's output (``docker logs``) or the log-access copy of it.
test_websocket_handshake_log.py covers the rules offline.
"""
import base64
import os
import socket
import subprocess
import time
import uuid
from urllib.parse import urlsplit

import pytest

from _account_change_helpers import psql
from conftest import BASE_URL

pytestmark = pytest.mark.integration


def _api_container():
    return os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _output_since(since):
    r = subprocess.run(["docker", "logs", "--since", since, _api_container()], capture_output=True, text=True,
                       timeout=60, encoding="utf-8", errors="replace")
    return r.stdout + r.stderr


def _sink():
    r = subprocess.run(["docker", "exec", _api_container(), "sh", "-c", "cat /app/logs/*.log* 2>/dev/null"],
                       capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
    return r.stdout


def _handshake(target):
    """Open a WebSocket handshake to `target` by hand and close it: the status line the server answers."""
    url = urlsplit(BASE_URL)
    if url.scheme != "http":
        pytest.skip("the handshake is sent over plain http")
    host, port = url.hostname, url.port or 80
    key = base64.b64encode(os.urandom(16)).decode()
    request = (f"GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {BASE_URL}\r\n\r\n")
    with socket.create_connection((host, port), timeout=10) as conn:
        conn.sendall(request.encode("ascii"))
        answer = conn.recv(4096).decode("latin-1")
    return answer.split("\r\n", 1)[0]


def test_a_handshake_query_reaches_no_line_but_its_names():
    marker = uuid.uuid4().hex[:12]
    value = f"handshake-{marker}"
    since = psql("SELECT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    accepted = _handshake(f"/ws/monitor?x={value}&token={value}")
    assert " 101 " in accepted + " ", accepted
    refused = _handshake(f"/ws/no-such-socket?x={value}")
    assert " 101 " not in refused + " ", refused
    lines = ('"WebSocket /ws/monitor?x&token"', '"WebSocket /ws/no-such-socket?x"')
    for _ in range(20):                       # the lines are written as the handshakes are answered
        output, sink = _output_since(since), _sink()
        if all(line in output or line in sink for line in lines):
            break
        time.sleep(0.5)
    for line in lines:
        assert line in output or line in sink, f"the handshake line {line!r} was not found"
    assert marker not in output, "the handshake's query value reached the server's output"
    assert marker not in sink, "the handshake's query value reached the log-access copy"
