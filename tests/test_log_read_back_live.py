"""Log access serves each access line as the query's names only, on a running stack: a line written before query
values were dropped, reduced on the way out, and a line this release writes, as it was written.

Lines of the first kind are placed in the log file the way such lines were written: a request whose query holds a
raw quote (a client can send one; a browser encodes it), a request sent as HTTP/1.0, and a WebSocket handshake to a
path no socket serves (logged as refused). GET /logs?service=web serves each with its target reduced to the query's
names, and no value.

Lines of the second kind are written by the server for requests sent here. In the single-container shape
(run_combined.py, the image's default command) the file holds the web server's own output: request lines with
their HTTP version, and WebSocket handshake lines. Those lines already hold names only, and log access serves each
exactly as it was written, its names kept. In the shape that starts the web server on its own, the file holds the
server's own access line instead, which log access serves as written as well.
test_access_line_query_names.py and test_websocket_handshake_log.py hold the rules offline.

Runs only where the log-pull ceiling is on (PLAN_LOG_PULL with a LOG_TOKEN_PEPPER of 32 characters or
more); skips otherwise, as test_api_web_log_pull.py does.
"""
import base64
import os
import socket
import subprocess
import time
import uuid
from urllib.parse import urlsplit

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")


def _container():
    return os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _append_to_the_log_file(lines):
    r = subprocess.run(["docker", "exec", "-i", _container(), "sh", "-c", "cat >> /app/logs/combined.log"],
                       input="".join(line + "\n" for line in lines), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


def _log_file_lines():
    """The lines of the file log access reads, split as it splits them."""
    r = subprocess.run(["docker", "exec", _container(), "sh", "-c", "cat /app/logs/combined.log 2>/dev/null"],
                       capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
    return r.stdout.split("\n")


def _single_container_shape():
    """True when the container runs run_combined.py, which writes the web server's own output to the file."""
    r = subprocess.run(["docker", "exec", _container(), "cat", "/proc/1/cmdline"], capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return b"run_combined.py" in r.stdout


def _web_token(admin):
    admin.put("/settings/logs", json={"flags": {"web": True}})
    minted = admin.post("/settings/logs", json={"name": unique("readback"), "scope": ["web"]})
    if minted.status_code in (403, 404):
        pytest.skip("log-pull ceiling off (set PLAN_LOG_PULL=true + LOG_TOKEN_PEPPER>=32 to test)")
    assert minted.status_code == 200, minted.text
    return minted.json()["token"]


def _served(token):
    pull = requests.get(f"{BASE}/logs", params={"service": "web", "tail": 5000},
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if pull.status_code == 404:
        pytest.skip("log endpoint off (set PLAN_LOG_PULL=true + LOG_TOKEN_PEPPER>=32 to test)")
    assert pull.status_code == 200, pull.text[:300]
    return pull.json()["lines"]


def _send_raw(request):
    """Send a request by hand and return the status line of the answer."""
    url = urlsplit(BASE)
    if url.scheme != "http":
        pytest.skip("the request is sent over plain http")
    with socket.create_connection((url.hostname, url.port or 80), timeout=10) as conn:
        conn.sendall(request.encode("ascii"))
        answer = conn.recv(4096).decode("latin-1")
    return answer.split("\r\n", 1)[0]


def _host():
    url = urlsplit(BASE)
    return f"{url.hostname}:{url.port or 80}"


def _handshake(target):
    key = base64.b64encode(os.urandom(16)).decode()
    return _send_raw(f"GET {target} HTTP/1.1\r\nHost: {_host()}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {BASE}\r\n\r\n")


def test_a_line_from_before_the_change_is_served_with_names_only(admin):
    token = _web_token(admin)

    marker = uuid.uuid4().hex[:12]
    _append_to_the_log_file([
        f'[web] INFO:     172.18.0.1:40112 - "GET /activity/events?q=it\'s+{marker}a&user={marker}b HTTP/1.1" 200 OK',
        f'[web] INFO:     172.18.0.1:40112 - "POST /activity/events/search?q=x"{marker}c&ip={marker}d HTTP/1.1" 200',
        f'[web] INFO:     172.18.0.1:40112 - "WebSocket /ws/no-such-socket?x={marker}e&y=\'{marker}f" 403',
        f'[web] INFO:     172.18.0.1:40112 - "WebSocket /ws/monitor?x=a"{marker}g&z={marker}h" [accepted]',
        f'[web] INFO:     172.18.0.1:40112 - "GET /activity/events?ip={marker}i&q HTTP/1.0" 200 OK',
    ])

    served = _served(token)
    for target in ('"GET /activity/events?q&user HTTP/1.1"', '"POST /activity/events/search?q&ip HTTP/1.1"',
                   '"WebSocket /ws/no-such-socket?x&y" 403', '"WebSocket /ws/monitor?x&z" [accepted]',
                   '"GET /activity/events?ip&<value> HTTP/1.0"'):
        assert any(target in line for line in served), f"{target} was not served"
    leaked = [line for line in served if marker in line]
    assert not leaked, f"a value was served: {leaked}"


def test_a_line_this_release_writes_is_served_as_it_was_written(admin):
    """Requests sent here with values in their query: a search with a name that does not look like one and a part
    with no "=", a request sent as HTTP/1.0, and two WebSocket handshakes. Their names carry one marker and their
    values another. Each line the server writes for them holds the names only, and log access serves it exactly
    as written: the names are kept, and no value is served."""
    token = _web_token(admin)
    n, v = uuid.uuid4().hex[:10], uuid.uuid4().hex[:10]
    combined = _single_container_shape()

    search = f"/activity/events?q{n}=quarterly+{v}&user{n}=alice.{v}%40example.com&al%20ice={v}&{v}"
    assert requests.get(BASE + search, timeout=30).status_code < 500
    status = _send_raw(f"GET /health?h{n}={v} HTTP/1.0\r\nHost: {_host()}\r\n\r\n")
    assert status.startswith("HTTP/") and int(status.split()[1]) < 500, status
    if combined:
        accepted = _handshake(f"/ws/monitor?x{n}={v}&{v}")
        assert " 101 " in accepted + " ", accepted
        refused = _handshake(f"/ws/no-such-socket?y{n}={v}")
        assert " 101 " not in refused + " ", refused

    search_names = f"/activity/events?q{n}&user{n}&<name>&<value>"
    if combined:
        expected = (f'"GET {search_names} HTTP/1.1"', f'"GET /health?h{n} HTTP/1.0"',
                    f'"WebSocket /ws/monitor?x{n}&<value>" [accepted]', f'"WebSocket /ws/no-such-socket?y{n}" 403')
    else:
        expected = (f"GET {search_names} -> ", f"GET /health?h{n} -> ")
    written = []
    for _ in range(40):                       # the lines are written as the answers go out
        written = [line for line in _log_file_lines() if n in line]
        if all(any(e in line for line in written) for e in expected):
            break
        time.sleep(0.5)
    for e in expected:
        assert any(e in line for line in written), f"{e} was not written: {written}"
    assert not [line for line in written if v in line], f"a value was written: {written}"

    served = _served(token)
    for line in written:
        assert line in served, f"{line!r} was not served as written: {[s for s in served if n in s]}"
    assert not [line for line in served if v in line], "a value was served"
