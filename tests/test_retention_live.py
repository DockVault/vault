"""The pruner and the managed retention settings on a running stack (app/core/retention.py,
app/core/setting_changes.py, app/api/managed_settings_router.py).

Changing a managed setting asks for the password every time. A change that keeps records longer applies at
once; one that deletes sooner waits, every administrator is told, and any administrator can cancel it. Each
change and each cancel is sealed in the audit log's integrity chain in its own transaction, and a waiting change
applies only from its seal: its time edited in the database changes nothing (the offline tests apply one once
its delay has run). The stack's changes are made to the minimum age of administration rows, raised by one day:
every one of them is sealed, so the stack's chain and database agree afterwards, and nothing else on the stack
reads it.

A pass deletes old resolved alerts and the sign-in throttle's old fallback rows and writes a retention_pruned
row for each job that deleted something; and while another runner holds the pruner's lock, a pass does nothing.
The hold switch runs on a throwaway database of its own: turned on, it applies at once and stops the jobs over
logs and security records and not the working-record jobs, and the chain's hold holds them even once the
database's value is cleared behind its back (only a waiting change turns it off, which a test cannot wait for,
so on the stack it would hold every job over logs from then on). test_retention.py and test_setting_changes.py
cover the rules offline.
"""
import json
import subprocess
import threading
import time
import uuid

import pytest

from _account_change_helpers import DB, in_api_container, notifications, psql, second_admin
from _chain_read import wait_for_chain_read
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

ACTION = "admin.retention.write"
LOCK = (0x7265, 1)
# The setting the stack's changes are made to: raising it keeps administration rows longer and applies at once,
# lowering it back deletes sooner and waits.
KEY = "audit_admin_min_days"


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


def _cancel_waiting(admin, key):
    """End every waiting change of ``key`` the way an administrator does, through the route, so each cancel is
    sealed and the stack's chain and database still agree."""
    for change in admin.get("/settings/managed").json()["pending"]:
        if change["key"] == key:
            admin.post(f"/settings/managed/changes/{change['id']}/cancel")


@pytest.fixture(autouse=True, scope="module")
def chain_started(admin):
    """The web process's pruner starts the audit chain a minute after the server starts, and reads it at its first
    pass after any start: a change that deletes sooner is refused, and the panel shows no value of a setting the
    chain records as in force, until it has."""
    ok = _wait_for(lambda: psql("SELECT count(*) FROM audit_seals WHERE kind = 'policy'") not in ("", "0"),
                   timeout=240, step=3)
    assert ok, "the audit chain never started"
    wait_for_chain_read(admin)


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
    raised = _row(admin, KEY)["value"] + 1
    with second_admin(admin) as (_account, client):
        r = client.put(f"/settings/managed/{KEY}", json={"value": raised})
        assert r.status_code == 403, r.text
        detail = r.json()["detail"]
        assert (detail["second_factor_required"], detail["action"], detail["reason"]) == (
            True, ACTION, "step_up_required")
        assert "password" in detail["methods"]
        r = client.put(f"/settings/managed/{KEY}", json={"value": raised},
                       headers={"X-Second-Factor": "not-a-receipt"})
        assert r.status_code == 403
    assert _row(admin, KEY)["value"] == raised - 1


def test_a_change_that_keeps_more_applies_at_once_and_one_that_deletes_sooner_waits_unless_cancelled(admin):
    seen = {n["id"] for n in notifications(admin, "retention_change")}
    start = _row(admin, KEY)["value"]
    try:
        with second_admin(admin) as (account, client):
            r = _put(client, account["_password"], KEY, start + 1)
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "applied"
            assert _wait_for(lambda: _row(admin, KEY)["value"] == start + 1)
            assert _row(admin, KEY)["source"] == "admin"

            r = _put(client, account["_password"], KEY, start)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "pending" and body["setting"]["value"] == start + 1
            change = body["change"]
            assert (change["new"], change["status"], change["requested_by"]) == (start, "pending",
                                                                                 account["_username"])
            pending = admin.get("/settings/managed").json()["pending"]
            assert [p["id"] for p in pending if p["key"] == KEY] == [change["id"]]

            told = _wait_for(lambda: [n for n in notifications(admin, "retention_change") if n["id"] not in seen])
            titles = [n["title"] for n in told]
            assert "A change that deletes records sooner is waiting" in titles, titles

            r = admin.post(f"/settings/managed/changes/{change['id']}/cancel")
            assert r.status_code == 200, r.text
            assert r.json()["change"]["decided_by"] == admin.get("/users/me").json()["username"]
            assert admin.post(f"/settings/managed/changes/{change['id']}/cancel").status_code == 409
            assert _row(admin, KEY)["value"] == start + 1

        rows = psql(f"SELECT action FROM audit_logs WHERE resource_type = 'setting' AND resource_id = '{KEY}' "
                    f"AND timestamp > now() - interval '5 minutes' ORDER BY timestamp").splitlines()
        assert rows[-3:] == ["setting_changed", "setting_change_requested", "setting_change_cancelled"], rows
    finally:
        _cancel_waiting(admin, KEY)


def test_a_waiting_change_is_sealed_and_its_time_edited_in_the_database_changes_nothing(admin):
    start = _row(admin, KEY)["value"]
    try:
        with second_admin(admin) as (account, client):
            assert _put(client, account["_password"], KEY, start + 1).status_code == 200
            change = _put(client, account["_password"], KEY, start).json()["change"]
        sealed = json.loads(psql("SELECT detail::text FROM audit_seals WHERE kind = 'request' "
                                 f"AND detail->>'request' = '{change['id']}'"))
        assert (sealed["setting"], sealed["old"], sealed["new"], sealed["by"]) == (KEY, start + 1, start, "admin")
        psql(f"UPDATE managed_setting_changes SET effective_at = now() - interval '1 minute' "
             f"WHERE id = '{change['id']}'")
        _run_pass()
        assert psql(f"SELECT status FROM managed_setting_changes WHERE id = '{change['id']}'") == "pending"
        assert _row(admin, KEY)["value"] == start + 1
    finally:
        _cancel_waiting(admin, KEY)


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


HOLD = PREAMBLE + r'''
from types import SimpleNamespace
from app.core import audit_chain_policy_seals as chain_seals, settings_registry as registry

def jobs():
    done = retention.run_pass(SessionLocal, engine=engine)
    return None if done is None else {n: (r.deleted if r else None) for n, r in done}

def add_old_rows():
    with engine.begin() as c:
        c.execute(text("INSERT INTO security_alerts (id, event_type, severity, message, timestamp, resolved, "
                       "details) VALUES (gen_random_uuid(), 'failed_login', 'warning', 'hold test', "
                       "'2001-01-01 00:00:00', true, '{}')"))
        c.execute(text("INSERT INTO rate_limit_records (id, identifier, action, attempt_count, window_start, "
                       "last_attempt) VALUES (gen_random_uuid(), 'hold-test', 'login', 1, now() - interval "
                       "'3 hours', now() - interval '3 hours')"))

def left():
    with engine.begin() as c:
        return [c.execute(text("SELECT count(*) FROM security_alerts WHERE message = 'hold test'")).scalar(),
                c.execute(text("SELECT count(*) FROM rate_limit_records WHERE identifier = 'hold-test'")).scalar()]

out = {"first": jobs()}          # the chain starts here, at the first pass
add_old_rows()
with chain_seals.change_transaction(engine) as w:
    outcome = chain_seals.change(w, "logs_hold", True, SimpleNamespace(id=None, username="hold-test"))
out["status"] = outcome.status
registry.refresh(SessionLocal)
out["held"] = jobs()
out["left_held"] = left()
# The database's value cleared, as no seal records: the chain's hold still holds every job over logs, and the
# pass reports the database's value as one it does not act on.
with engine.begin() as c:
    c.execute(text("UPDATE managed_settings SET value = NULL, version = (SELECT max(version) + 1 FROM "
                   "managed_settings) WHERE key = 'logs_hold'"))
add_old_rows()
out["cleared"] = jobs()
out["left_cleared"] = left()
out["database_hold"] = retention.hold_in_force()
out["failures"] = sorted(ai.status(st)["failures"])
print(json.dumps(out))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_the_hold_applies_at_once_and_stops_the_log_jobs_and_not_the_working_records(throwaway):
    out = run_in(throwaway, HOLD)
    assert out["first"] is not None and out["first"]["security_alerts"] is not None, out
    assert out["status"] == "applied"
    held = out["held"]
    assert held["security_alerts"] is None and held["security_records"] is None and held["audit_logs"] is None, held
    assert held["rate_limit_records"] is not None, held
    assert out["left_held"] == [1, 0]
    cleared = out["cleared"]
    assert out["database_hold"] is False
    assert cleared["security_alerts"] is None and cleared["audit_logs"] is None, cleared
    assert cleared["rate_limit_records"] is not None, cleared
    assert out["left_cleared"] == [2, 0]
    assert "unjustified-input" in out["failures"], out["failures"]


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
