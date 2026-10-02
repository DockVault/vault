"""Activity searches with what was typed in the body, on a running stack.

With names typed at sign-in recorded as fingerprints, a failed sign-in's row is found by a posted search for the
name, and by its fingerprint. What the search typed reaches neither the server's output, nor the log-access copy
of it, nor the export's audit row, nor a saved search. The levels are set back afterwards.
test_activity_search.py covers the rules offline.
"""
import subprocess
import uuid

import pytest
import requests

from conftest import BASE_URL, unique
from _account_change_helpers import psql, reset_sign_in_throttle
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture

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


def test_what_a_search_typed_reaches_no_log_no_export_row_and_no_saved_search(admin, levels_restored):
    version = store(dict(levels_restored, signin_names="fingerprint"))
    reset_sign_in_throttle()
    typed = unique("typedname")
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": typed, "password": "wrong-password"}, timeout=30)
    assert r.status_code in (401, 429)
    row = wait_for(lambda: psql("SELECT id, recorded->>'signin_name' FROM audit_logs WHERE action = 'login_failure' "
                                f"AND privacy_version = {version} AND recorded->>'signin_name' IS NOT NULL "
                                "ORDER BY timestamp DESC LIMIT 1"))
    row_id, fingerprint = row.split("|")
    since = psql("SELECT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
    before_sink = _sink().count(typed)

    found = admin.post("/activity/events/search", json={"user": typed, "user_match": "exact"})
    assert found.status_code == 200, found.text[:200]
    assert row_id in {e["id"] for e in found.json()["events"]}
    by_fp = admin.post("/activity/events/search", json={"user": fingerprint})
    assert row_id in {e["id"] for e in by_fp.json()["events"]}
    band = admin.post("/activity/summary/search", json={"user": typed, "range": "24h"})
    assert band.status_code == 200, band.text[:200]
    export = admin.post("/activity/export", json={"user": typed, "format": "csv"})
    assert export.status_code == 200 and fingerprint in export.text
    created = admin.post("/activity/saved-searches", json={"name": f"probe {uuid.uuid4().hex[:6]}",
                                                          "filters": {"user": typed}})
    assert created.status_code in (200, 201), created.text[:200]
    saved_id = created.json()["id"]
    try:
        assert created.json()["filters"]["user"].startswith("fp1:")
        assert typed not in psql(f"SELECT filters::text FROM activity_saved_searches WHERE id = '{saved_id}'")
        exported = wait_for(lambda: psql("SELECT details::text, coalesce(recorded::text, '') FROM audit_logs "
                                         "WHERE action = 'audit_exported' ORDER BY timestamp DESC LIMIT 1"))
        assert typed not in exported and fingerprint in exported
        assert typed not in _output_since(since)
        assert _sink().count(typed) == before_sink
    finally:
        admin.delete(f"/activity/saved-searches/{saved_id}")
    reset_sign_in_throttle()
