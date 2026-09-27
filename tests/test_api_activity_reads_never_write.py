"""API: reading the Activity page never writes an audit row, against a running vault.

The page re-reads its list, band and "now" panel as events arrive. A read that wrote an audit row would
signal a new event, which the page would read, which would write another: a loop that fills the log.
The only Activity request that writes a row is an export, which a person asks for and which is
recorded on purpose. Every GET route under /activity is called here (the list of them is read from the
source, so a new one is covered or this test fails), and then no row may name one of them."""
import re
import time
from pathlib import Path

from conftest import unique

API = Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py"
# Recorded on purpose: an export is a request a person makes, and who exported what is audited.
WRITES_ON_PURPOSE = {"/activity/export"}


def _activity_get_routes():
    return sorted(set(re.findall(r'@app\.get\("(/activity[^"]*)"\)', API.read_text(encoding="utf-8"))))


def test_every_activity_read_leaves_the_log_as_it_was(admin):
    routes = _activity_get_routes()
    assert "/activity/events" in routes and "/activity/summary" in routes      # the scan found them
    me = admin.user["username"]
    some = admin.get("/activity/events", params={"limit": 1}).json()["events"]
    # The log's newest row now, by the server's clock: what is written after it is what these reads wrote.
    newest = some[0]["id"] if some else None
    calls = {
        "/activity/catalog": [{}],
        "/activity/events": [{}, {"page": 2, "limit": 25}, {"q": unique("nothing")},
                             {"after": some[0]["id"] if some else "none"},
                             {"ids": some[0]["id"] if some else "none", "count_only": "true"}],
        "/activity/events/{event_id}": [{}],
        "/activity/summary": [{"range": "24h"}, {"range": "7d"}, {"range": "30d"}],
        "/activity/now": [{}],
        "/activity/usernames": [{"q": "a"}],
        "/activity/temp-credentials": [{"q": "temp_"}],
        "/activity/saved-searches": [{}],
    }
    missing = [r for r in routes if r not in calls and r not in WRITES_ON_PURPOSE]
    assert not missing, f"call these reads here too: {missing}"
    for route, variants in calls.items():
        path = route.replace("{event_id}", some[0]["id"] if some else "00000000-0000-0000-0000-000000000000")
        for params in variants:
            r = admin.get(path, params=params)
            assert r.status_code in (200, 404), (path, params, r.status_code, r.text[:200])
    time.sleep(0.5)
    # This administrator's own session's rows only: a temporary credential's refused request (one of
    # the administrator's, from an earlier test) is recorded on purpose.
    written = admin.get("/activity/events", params={"after": newest, "user": me, "user_match": "exact",
                                                    "limit": 200}).json()["events"] if newest else []
    by_reads = [(e["action"], e["method"], e["endpoint"]) for e in written
                if (e["endpoint"] or "").startswith("/activity") and e["endpoint"] not in WRITES_ON_PURPOSE
                and not e["temp_credential_id"]]
    assert by_reads == [], by_reads
