"""Positive-path coverage for the security-alert admin endpoints.

The list + resolve endpoints (/api/security/alerts, /api/security/alerts/{id}/resolve) were tested
only for 403 (non-admin) -- never that an admin can actually list an alert and that resolving one
marks it resolved. A row is seeded directly so the test doesn't depend on trigger thresholds/timing.
"""
import os
import subprocess
import uuid

import pytest

from conftest import skip_if_container_absent

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    """Run SQL in the vault DB, returning the CompletedProcess. Skips (rather than errors) when
    docker/psql isn't reachable -- matching the seeding convention of the other db-backed suites."""
    try:
        return subprocess.run(
            ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
            capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")


def test_admin_can_list_and_resolve_a_security_alert(admin, admin_creds):
    aid = str(uuid.uuid4())
    seed = _psql("INSERT INTO security_alerts (id, event_type, severity, message, timestamp, resolved) "
                 "VALUES ('%s', 'test_probe', 'warning', 'positive-path test alert', now(), false)" % aid)
    skip_if_container_absent(seed, _DB)
    assert seed.returncode == 0, "failed to seed the alert row: %s" % (seed.stderr[:200])
    try:
        # LIST: the admin sees the (unresolved) alert
        listed = admin.get("/api/security/alerts", params={"limit": 200})
        assert listed.status_code == 200, listed.text
        assert aid in listed.text, "the seeded alert did not appear in the admin alert list"

        # RESOLVE: marks it resolved and records who + notes
        r = admin.post(f"/api/security/alerts/{aid}/resolve", params={"notes": "handled by the test"})
        assert r.status_code == 200, r.text
        row = _psql("SELECT resolved || '|' || coalesce(resolved_by,'') || '|' || "
                    "coalesce(resolution_notes,'') FROM security_alerts WHERE id='%s'" % aid).stdout.strip()
        resolved, who, notes = row.split("|", 2)
        assert resolved == "true", "resolve did not set resolved=true (%r)" % row
        assert who == admin_creds["username"], \
            "resolved_by was not the acting admin (%r, expected %r)" % (who, admin_creds["username"])
        assert notes == "handled by the test"
    finally:
        _psql("DELETE FROM security_alerts WHERE id='%s'" % aid)
