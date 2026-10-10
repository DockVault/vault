"""A line written before query values were dropped is served through log access with the query's names only,
on a running stack.

Lines of that kind are placed in the log file the way such lines were written: a request whose query holds a
raw quote (a client can send one; a browser encodes it) and a WebSocket handshake to a path no socket serves
(logged as refused). GET /logs?service=web serves each with its target reduced to the query's names, and no
value. test_access_line_query_names.py and test_websocket_handshake_log.py hold the rules offline.

Runs only where the log-pull ceiling is on (PLAN_LOG_PULL with a LOG_TOKEN_PEPPER of 32 characters or
more); skips otherwise, as test_api_web_log_pull.py does.
"""
import os
import subprocess
import uuid

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration

BASE = os.environ.get("VAULT_BASE_URL", "http://localhost:8200")


def _append_to_the_log_file(lines):
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    r = subprocess.run(["docker", "exec", "-i", container, "sh", "-c", "cat >> /app/logs/combined.log"],
                       input="".join(line + "\n" for line in lines), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


def test_a_line_from_before_the_change_is_served_with_names_only(admin):
    admin.put("/settings/logs", json={"flags": {"web": True}})
    minted = admin.post("/settings/logs", json={"name": unique("readback"), "scope": ["web"]})
    if minted.status_code in (403, 404):
        pytest.skip("log-pull ceiling off (set PLAN_LOG_PULL=true + LOG_TOKEN_PEPPER>=32 to test)")
    assert minted.status_code == 200, minted.text
    token = minted.json()["token"]

    marker = uuid.uuid4().hex[:12]
    _append_to_the_log_file([
        f'[web] INFO:     172.18.0.1:40112 - "GET /activity/events?q=it\'s+{marker}a&user={marker}b HTTP/1.1" 200 OK',
        f'[web] INFO:     172.18.0.1:40112 - "POST /activity/events/search?q=x"{marker}c&ip={marker}d HTTP/1.1" 200',
        f'[web] INFO:     172.18.0.1:40112 - "WebSocket /ws/no-such-socket?x={marker}e&y=\'{marker}f" 403',
        f'[web] INFO:     172.18.0.1:40112 - "WebSocket /ws/monitor?x=a"{marker}g&z={marker}h" [accepted]',
    ])

    pull = requests.get(f"{BASE}/logs", params={"service": "web", "tail": 5000},
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if pull.status_code == 404:
        pytest.skip("log endpoint disabled (ceiling) - not testable on this round")
    assert pull.status_code == 200, pull.text[:300]
    served = pull.json()["lines"]
    for target in ('"GET /activity/events?q&user HTTP/1.1"', '"POST /activity/events/search?q&ip HTTP/1.1"',
                   '"WebSocket /ws/no-such-socket?x&y" 403', '"WebSocket /ws/monitor?x&z" [accepted]'):
        assert any(target in line for line in served), f"{target} was not served"
    leaked = [line for line in served if marker in line]
    assert not leaked, f"a value was served: {leaked}"
