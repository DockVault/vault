"""The pruner and the managed retention settings on a running stack (app/core/retention.py,
app/core/setting_changes.py, app/api/managed_settings_router.py).

Changing a managed setting asks for the password every time. Turning the hold switch on applies at once;
turning it off deletes sooner, so it waits, every administrator is told, and any administrator can cancel
it. Each change and each cancel is sealed in the audit log's integrity chain in its own transaction, and a
waiting change applies only from its seal: its time edited in the database changes nothing (the offline tests
apply one once its delay has run). A pass deletes old resolved alerts and the sign-in throttle's old fallback
rows and writes a retention_pruned row for each job that deleted something; the hold switch stops the jobs
over logs and security records and not the working-record jobs; and while another runner holds the pruner's
lock, a pass does nothing. test_retention.py and test_setting_changes.py cover the rules offline.
"""
import json
import subprocess
import threading
import time
import uuid

import pytest

from _account_change_helpers import DB, in_api_container, notifications, psql, second_admin

pytestmark = pytest.mark.integration

ACTION = "admin.retention.write"
LOCK = (0x7265, 1)


def _receipt(client, password):
    r = client.post("/auth/second-factor/step-up", json={"action": ACTION, "method": "password", "code": password})
    assert r.status_code == 200, r.text
    return r.json()["receipt"]


def _put(client, password, key, value):
    return client.put(f"/settings/managed/{key}", json={"value": value},
                      headers={"X-Second-Factor": _receipt(client, password)})


def _row(client, key):
    return {r["key"]: r for r in client.get("/settings/managed").json()["settings"]}[key]


def _wait_for(check, timeout=20.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


def _clear(key):
    """Put ``key`` back to the deployment's value the way the registry stores a clear, and end its waiting
    changes, so the stack is left as it was."""
    psql("UPDATE managed_setting_changes SET status = 'cancelled', reason = 'test cleanup' "
         f"WHERE key = '{key}' AND status = 'pending'")
    psql(f"UPDATE managed_settings SET value = NULL, version = (SELECT max(version) + 1 FROM managed_settings) "
         f"WHERE key = '{key}'")


@pytest.fixture(autouse=True, scope="module")
def chain_started():
    """The web process's pruner starts the audit chain a minute after the server starts; a change that
    deletes sooner is refused until it has."""
    ok = _wait_for(lambda: psql("SELECT count(*) FROM audit_seals WHERE kind = 'policy'") not in ("", "0"),
                   timeout=240, step=3)
    assert ok, "the audit chain never started"


def _run_pass():
    """One pass of the pruner inside the web container, retried while the web app's own runner holds the
    lock. Returns {job: deleted, or None when the job did not run}."""
    source = ("import json\n"
              "from app.core import retention\n"
              "done = retention.run_pass()\n"
              "print(json.dumps(None if done is None else {n: (r.deleted if r else None) for n, r in done}))\n")
    for _ in range(30):
        out = json.loads(in_api_container(source).stdout.strip().splitlines()[-1])
        if out is not None:
            return out
        time.sleep(1)
    raise AssertionError("the pruner's lock never came free")


def _alert(when, resolved):
    alert_id = str(uuid.uuid4())
    psql("INSERT INTO security_alerts (id, event_type, severity, message, timestamp, resolved, details) "
         f"VALUES ('{alert_id}', 'failed_login', 'warning', 'retention test', '{when}', {str(resolved).lower()}, '{{}}')")
    return alert_id


def _alive(alert_id):
    return psql(f"SELECT count(*) FROM security_alerts WHERE id = '{alert_id}'") == "1"


def test_changing_a_managed_setting_asks_for_the_password(admin):
    with second_admin(admin) as (_account, client):
        r = client.put("/settings/managed/logs_hold", json={"value": True})
        assert r.status_code == 403, r.text
        detail = r.json()["detail"]
        assert (detail["second_factor_required"], detail["action"], detail["reason"]) == (
            True, ACTION, "step_up_required")
        assert "password" in detail["methods"]
        r = client.put("/settings/managed/logs_hold", json={"value": True},
                       headers={"X-Second-Factor": "not-a-receipt"})
        assert r.status_code == 403


def test_the_hold_goes_on_at_once_and_off_only_after_the_wait_unless_cancelled(admin):
    seen = {n["id"] for n in notifications(admin, "retention_change")}
    try:
        with second_admin(admin) as (account, client):
            r = _put(client, account["_password"], "logs_hold", True)
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "applied"
            assert _wait_for(lambda: _row(admin, "logs_hold")["value"] is True)
            assert _row(admin, "logs_hold")["source"] == "admin"

            r = _put(client, account["_password"], "logs_hold", False)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "pending" and body["setting"]["value"] is True
            change = body["change"]
            assert (change["new"], change["status"], change["requested_by"]) == (False, "pending",
                                                                                 account["_username"])
            pending = admin.get("/settings/managed").json()["pending"]
            assert [p["id"] for p in pending if p["key"] == "logs_hold"] == [change["id"]]

            told = _wait_for(lambda: [n for n in notifications(admin, "retention_change") if n["id"] not in seen])
            titles = [n["title"] for n in told]
            assert "A change that deletes records sooner is waiting" in titles, titles

            r = admin.post(f"/settings/managed/changes/{change['id']}/cancel")
            assert r.status_code == 200, r.text
            assert r.json()["change"]["decided_by"] == admin.get("/users/me").json()["username"]
            assert admin.post(f"/settings/managed/changes/{change['id']}/cancel").status_code == 409
            assert _row(admin, "logs_hold")["value"] is True

        rows = psql("SELECT action FROM audit_logs WHERE resource_type = 'setting' AND resource_id = 'logs_hold' "
                    f"AND timestamp > now() - interval '5 minutes' ORDER BY timestamp").splitlines()
        assert rows[-3:] == ["setting_changed", "setting_change_requested", "setting_change_cancelled"], rows
    finally:
        _clear("logs_hold")


def test_a_waiting_change_is_sealed_and_its_time_edited_in_the_database_changes_nothing(admin):
    try:
        with second_admin(admin) as (account, client):
            assert _put(client, account["_password"], "logs_hold", True).status_code == 200
            change = _put(client, account["_password"], "logs_hold", False).json()["change"]
        sealed = json.loads(psql("SELECT detail::text FROM audit_seals WHERE kind = 'request' "
                                 f"AND detail->>'request' = '{change['id']}'"))
        assert (sealed["setting"], sealed["old"], sealed["new"], sealed["by"]) == ("logs_hold", True, False, "admin")
        psql(f"UPDATE managed_setting_changes SET effective_at = now() - interval '1 minute' "
             f"WHERE id = '{change['id']}'")
        _run_pass()
        assert psql(f"SELECT status FROM managed_setting_changes WHERE id = '{change['id']}'") == "pending"
        assert _row(admin, "logs_hold")["value"] is True
    finally:
        _clear("logs_hold")


def test_a_pass_deletes_old_resolved_alerts_and_old_throttle_rows_and_records_it():
    old_resolved = _alert("2001-01-01 00:00:00", True)
    old_open = _alert("2001-01-01 00:00:00", False)
    identifier = f"retention-test-{uuid.uuid4().hex[:8]}"
    psql("INSERT INTO rate_limit_records (id, identifier, action, attempt_count, window_start, last_attempt) "
         f"VALUES ('{uuid.uuid4()}', '{identifier}', 'login', 1, now() - interval '3 hours', now() - interval '3 hours')")
    try:
        # The web app's own pruner may take a pass meanwhile: what the rows became is what counts.
        _run_pass()
        assert not _alive(old_resolved) and _alive(old_open)
        assert psql(f"SELECT count(*) FROM rate_limit_records WHERE identifier = '{identifier}'") == "0"
        recorded = psql("SELECT details->>'job' FROM audit_logs WHERE action = 'retention_pruned' "
                        "AND timestamp > now() - interval '5 minutes'").splitlines()
        assert {"security_alerts", "rate_limit_records"} <= set(recorded), recorded
    finally:
        psql(f"DELETE FROM security_alerts WHERE id IN ('{old_resolved}', '{old_open}')")


def test_the_hold_stops_the_log_jobs_and_not_the_working_records(admin):
    old_resolved = _alert("2001-01-01 00:00:00", True)
    identifier = f"retention-test-{uuid.uuid4().hex[:8]}"
    psql("INSERT INTO rate_limit_records (id, identifier, action, attempt_count, window_start, last_attempt) "
         f"VALUES ('{uuid.uuid4()}', '{identifier}', 'login', 1, now() - interval '3 hours', now() - interval '3 hours')")
    try:
        with second_admin(admin) as (account, client):
            assert _put(client, account["_password"], "logs_hold", True).status_code == 200
        # The pass runs in a process of its own, which reads the table at its start.
        done = _run_pass()
        assert done["security_alerts"] is None and done["audit_logs"] is None, done
        assert done["rate_limit_records"] is not None, done
        assert _alive(old_resolved)
        assert psql(f"SELECT count(*) FROM rate_limit_records WHERE identifier = '{identifier}'") == "0"
    finally:
        _clear("logs_hold")
        psql(f"DELETE FROM security_alerts WHERE id = '{old_resolved}'")


def test_while_another_runner_holds_the_lock_a_pass_does_nothing():
    holder = subprocess.Popen(["docker", "exec", "-i", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
                               f"SELECT pg_advisory_lock({LOCK[0]}, {LOCK[1]}); SELECT pg_sleep(25);"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        held = _wait_for(lambda: psql("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
                                      f"AND classid = {LOCK[0]} AND objid = {LOCK[1]}") == "1", timeout=15)
        assert held, "the test could not take the pruner's lock"
        out = in_api_container("import json\nfrom app.core import retention\n"
                               "print(json.dumps(retention.run_pass()))\n").stdout.strip().splitlines()[-1]
        assert out == "null"
    finally:
        holder.terminate()
        holder.wait(30)
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' "
             f"AND classid = {LOCK[0]} AND objid = {LOCK[1]}")
    assert _run_pass() is not None
