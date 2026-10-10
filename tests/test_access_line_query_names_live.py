"""What an Activity search typed in its query reaches no line on a running stack, only its names.

GET /activity/events takes its filters in the query (the web app posts them in the body; an API client may
still use the query). A search for a name, an address and free text reaches neither the server's output
(``docker logs``) nor the log-access copy of it: the request line carries the parameter names only.
test_access_line_query_names.py covers the rules offline.
"""
import subprocess
import time
import uuid

import pytest

from _account_change_helpers import psql

pytestmark = pytest.mark.integration


def _api_container():
    import os
    return os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _output_since(since):
    r = subprocess.run(["docker", "logs", "--since", since, _api_container()], capture_output=True, text=True,
                       timeout=60, encoding="utf-8", errors="replace")
    return r.stdout + r.stderr


def _sink():
    r = subprocess.run(["docker", "exec", _api_container(), "sh", "-c", "cat /app/logs/*.log* 2>/dev/null"],
                       capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace")
    return r.stdout


def test_an_activity_search_in_the_query_reaches_no_line_but_its_names(admin):
    """Sent with GET, POST and HEAD: a request line carries any method, and each prints the names only."""
    marker = uuid.uuid4().hex[:10]
    name = f"searched.{marker}@example.com"
    address = f"198.18.{int(marker[:2], 16)}.{int(marker[2:4], 16)}"
    text = f"quarterly {marker} draft"
    params = {"user": name, "ip": address, "q": text, "category": "auth"}
    since = psql("SELECT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    r = admin.get("/activity/events", params=params)
    assert r.status_code == 200, r.text[:200]
    r = admin.post("/activity/events/search", params=params, json={"category": ["auth"]})
    assert r.status_code == 200, r.text[:200]
    r = admin.session.head(admin._url("/activity/events"), params=params, timeout=30)
    assert r.status_code < 500, r.status_code
    names = "?user&ip&q&category"
    lines = (f"GET /activity/events{names}", f"POST /activity/events/search{names}", f"HEAD /activity/events{names}")
    for _ in range(20):                       # the lines are written as the responses go out
        output, sink = _output_since(since), _sink()
        if all(line in output or line in sink for line in lines):
            break
        time.sleep(0.5)
    for line in lines:
        assert line in output or line in sink, f"the access line {line!r} was not found"
    for value in (marker, name, address):
        assert value not in output, f"{value!r} reached the server's output"
        assert value not in sink, f"{value!r} reached the log-access copy"
