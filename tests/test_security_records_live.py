"""The security record on a running stack (app/core/security_records.py).

A failed web sign-in, a rejected second-factor code and a failed SFTP password each write a security
record with the name as typed, the address and the way in, in the commit of the failure's audit row; a record
the database refuses costs neither the audit row nor the answer, and raises an alert instead, and a lookup
of the name typed that fails costs neither of them. An alert raised by repeated failures holds placeholders
instead of the name and the address, is shown with them filled in, and is linked from the records that
raised it. A pass of the pruner deletes records past the window and clears the names and addresses of
alerts past it, resolved or not. test_security_records.py covers the rules offline.
"""
import json
import os
import time
import uuid

import paramiko
import pytest

from conftest import ApiClient, BASE_URL, unique
from _account_change_helpers import in_api_container, psql, reset_sign_in_throttle
from _sf_helpers import enroll_totp

pytestmark = pytest.mark.integration

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
WRONG = "definitely-not-the-password"


def _web(username, password):
    return ApiClient(BASE_URL).session.post(f"{BASE_URL}/auth/login", timeout=30,
                                            json={"username": username, "password": password})


def _records(name):
    """[(kind, account_id, address, channel, reason, alert_id)] for ``name``, oldest first."""
    out = psql("SELECT kind, coalesce(account_id::text, ''), coalesce(address, ''), coalesce(channel, ''), "
               "coalesce(reason, ''), coalesce(alert_id::text, '') FROM security_records "
               f"WHERE name = '{name}' ORDER BY at")
    return [tuple(line.split("|")) for line in out.splitlines() if line]


def _wait_for(check, timeout=20.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


def _run_pass():
    """One pass of the pruner inside the web container, retried while the web app's own runner holds the
    lock."""
    source = ("import json\n"
              "from app.core import retention\n"
              "done = retention.run_pass()\n"
              "print(json.dumps(done is not None))\n")
    for _ in range(30):
        if json.loads(in_api_container(source).stdout.strip().splitlines()[-1]):
            return
        time.sleep(1)
    raise AssertionError("the pruner's lock never came free")


def test_a_failed_web_sign_in_writes_its_record(temp_user):
    reset_sign_in_throttle()
    name, uid = temp_user["_username"], temp_user["id"]
    assert _web(name, WRONG).status_code == 401
    ghost = unique("nobody")
    assert _web(ghost, WRONG).status_code == 401
    (mine,) = _records(name)
    kind, account, address, channel, reason, _ = mine
    assert (kind, account, channel) == ("login_failure", uid, "web")
    assert address and reason
    (theirs,) = _records(ghost)
    assert theirs[0] == "login_failure" and theirs[1] == "" and theirs[2] == address
    # The audit row of the same failure was written in the same commit.
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'login_failure' AND username = '{ghost}'") == "1"
    reset_sign_in_throttle()


def test_a_rejected_second_factor_code_writes_its_record(temp_user, temp_user_client):
    reset_sign_in_throttle()
    enroll_totp(temp_user, temp_user_client)
    fresh = ApiClient()
    r = fresh.session.post(f"{BASE_URL}/auth/login",
                           json={"username": temp_user["_username"], "password": temp_user["_password"]})
    assert r.status_code == 200 and r.json()["second_factor_required"] is True, r.text
    ph = {"Authorization": f"Bearer {r.json()['pre_auth_token']}"}
    assert fresh.session.post(f"{BASE_URL}/auth/second-factor/verify", headers=ph,
                              json={"method": "totp", "code": "000000"}).status_code == 401
    (rec,) = _records(temp_user["_username"])
    assert rec[:2] == ("second_factor_failure", temp_user["id"])
    assert rec[2] and rec[3] == "web" and rec[4] == "second factor (totp)"


def test_a_failed_sftp_password_writes_its_record(temp_user):
    reset_sign_in_throttle()
    name = temp_user["_username"]
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        with pytest.raises(paramiko.AuthenticationException):
            t.connect(username=name, password=WRONG)
    finally:
        t.close()
    rec = _wait_for(lambda: _records(name))
    assert len(rec) == 1, rec
    kind, account, address, channel, reason, _ = rec[0]
    assert (kind, account, channel) == ("login_failure", temp_user["id"], "sftp")
    assert address and reason
    reset_sign_in_throttle()


def _refuse_records_for(name):
    """Make the database refuse every security record for ``name`` (a trigger that raises, as a fault in that
    one table would), and return the undo. Only this name's records are refused, so nothing else running on
    the stack is touched."""
    tag = uuid.uuid4().hex[:12]
    psql(f"CREATE FUNCTION refuse_record_{tag}() RETURNS trigger LANGUAGE plpgsql AS "
         "$$BEGIN RAISE EXCEPTION 'security record refused'; END$$")
    psql(f"CREATE TRIGGER refuse_record_{tag} BEFORE INSERT ON security_records FOR EACH ROW "
         f"WHEN (NEW.name = '{name}') EXECUTE FUNCTION refuse_record_{tag}()")

    def undo():
        psql(f"DROP TRIGGER IF EXISTS refuse_record_{tag} ON security_records")
        psql(f"DROP FUNCTION IF EXISTS refuse_record_{tag}()")
    return undo


def _failure_rows(name, since):
    """The ways in and actions of ``name``'s failed sign-in and second-factor rows since ``since``."""
    out = psql("SELECT coalesce(channel, '') || '|' || action FROM audit_logs "
               f"WHERE action IN ('login_failure', 'second_factor_failed') AND username = '{name}' "
               f"AND timestamp >= '{since}' ORDER BY timestamp")
    return [line for line in out.splitlines() if line]


def test_a_record_the_database_refuses_never_costs_the_audit_row_or_the_answer(temp_user, temp_user_client):
    reset_sign_in_throttle()
    name = temp_user["_username"]
    since = psql("SELECT now() AT TIME ZONE 'utc'")
    undo = _refuse_records_for(name)
    try:
        # A wrong password is answered as always (401, not a 500), over SFTP refused as always ...
        assert _web(name, WRONG).status_code == 401
        t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        t.banner_timeout = 30
        try:
            with pytest.raises(paramiko.AuthenticationException):
                t.connect(username=name, password=WRONG)
        finally:
            t.close()
        # ... and so is a wrong second-factor code.
        enroll_totp(temp_user, temp_user_client)
        fresh = ApiClient()
        r = fresh.session.post(f"{BASE_URL}/auth/login",
                               json={"username": name, "password": temp_user["_password"]})
        assert r.status_code == 200 and r.json()["second_factor_required"] is True, r.text
        ph = {"Authorization": f"Bearer {r.json()['pre_auth_token']}"}
        assert fresh.session.post(f"{BASE_URL}/auth/second-factor/verify", headers=ph,
                                  json={"method": "totp", "code": "000000"}).status_code == 401
        rows = _wait_for(lambda: len(_failure_rows(name, since)) >= 3 and _failure_rows(name, since))
    finally:
        undo()
    # Every failure kept its audit row; only the records are missing, and an alert says so, without the name.
    assert sorted(rows or []) == ["sftp|login_failure", "web|login_failure", "web|second_factor_failed"]
    assert _records(name) == []
    message = _wait_for(lambda: psql(
        "SELECT message FROM security_alerts WHERE event_type = 'audit_recording_degraded' "
        "AND details->>'reason' = 'security_record' "
        "AND timestamp >= (now() AT TIME ZONE 'utc') - interval '11 minutes' ORDER BY timestamp DESC LIMIT 1"))
    assert "could not be written" in message and name not in message
    # With the table writable again, the next failure writes its record as before.
    reset_sign_in_throttle()
    assert _web(name, WRONG).status_code == 401
    assert [rec[0] for rec in _records(name)] == ["login_failure"]
    reset_sign_in_throttle()


# Inside the web container, on the application's own engine: the statement that looks up the name a failed
# sign-in typed (as an account's, or as a temporary credential's) fails once at the server, as one waiting past
# the connections' lock timeout behind a change to its table does. On PostgreSQL that aborts the transaction the
# failure's audit row is written in, unless the lookup ran under a savepoint of it.
_LOOKUP_FAILS = r'''
import json
from datetime import datetime
from sqlalchemy import event
from app.core.database import SessionLocal, _require_engine
from app.core.models import AuditLog, SecurityRecord
from app.services.audit_logger import AuditLogger

LOCK_TIMEOUT = ("DO $$ BEGIN RAISE EXCEPTION 'canceling statement due to lock timeout' "
                "USING ERRCODE = 'lock_not_available'; END $$")
armed = []

@event.listens_for(_require_engine(), "before_cursor_execute", retval=True)
def _fail_once(conn, cursor, statement, parameters, context, executemany):
    if armed and armed[0] in statement:
        armed.clear()
        return LOCK_TIMEOUT, {}
    return statement, parameters

out = {}
for case, name, marker in CASES:
    start = datetime.utcnow()
    db = SessionLocal()
    armed[:] = [marker]
    try:
        record_id = AuditLogger(db).log_login_failure(name, "198.51.100.61", "Invalid credentials")
        answer = "answered"
    except Exception as exc:
        record_id, answer = None, "raised " + type(exc).__name__
        db.rollback()
    finally:
        db.close()
    check = SessionLocal()
    rows = check.query(AuditLog).filter(AuditLog.action == "login_failure", AuditLog.timestamp >= start).count()
    record = check.get(SecurityRecord, record_id) if record_id is not None else None
    out[case] = {"failed": not armed, "answer": answer, "rows": rows,
                 "record": record.name if record is not None else None}
    check.close()
    armed.clear()
print("OUTCOME=" + json.dumps(out))
'''


def test_a_lookup_that_fails_never_costs_the_audit_row_or_the_answer(temp_user):
    account, credential = temp_user["_username"], unique("temp_gone")
    cases = [("account", account, "ORDER BY CASE"), ("credential", credential, "FROM temporary_credentials")]
    r = in_api_container(f"CASES = {cases!r}\n" + _LOOKUP_FAILS)
    out = json.loads([line for line in r.stdout.splitlines() if line.startswith("OUTCOME=")][-1][len("OUTCOME="):])
    try:
        for case, name, _marker in cases:
            # The lookup's statement did fail; the failure was answered all the same, with its audit row and
            # its security record.
            assert out[case] == {"failed": True, "answer": "answered", "rows": 1, "record": name}, (case, out)
    finally:
        psql(f"DELETE FROM security_records WHERE name IN ('{account}', '{credential}')")


def test_an_alert_is_stored_without_the_name_and_shown_with_it(admin):
    reset_sign_in_throttle()
    ghost = unique("guesser")
    for _ in range(6):                                  # the warning threshold is 5 failures
        assert _web(ghost, WRONG).status_code in (401, 429)
    stored = _wait_for(lambda: psql(f"SELECT id, message FROM security_alerts WHERE username = '{ghost}'"))
    alert_id, message = stored.split("|", 1)
    assert ghost not in message and "{username}" in message and "{ip_address}" in message
    shown = {a["id"]: a for a in admin.get("/api/security/alerts", params={"limit": 200}).json()["alerts"]}
    assert ghost in shown[alert_id]["message"] and "{username}" not in shown[alert_id]["message"]
    linked = [r[5] for r in _records(ghost)]
    assert alert_id in linked, linked
    reset_sign_in_throttle()


def test_a_pass_deletes_old_records_and_clears_old_alerts(admin):
    name, address = unique("old"), "203.0.113.77"
    record_id, old_alert, new_alert = (str(uuid.uuid4()) for _ in range(3))
    psql("INSERT INTO security_records (id, at, kind, name, address) VALUES "
         f"('{record_id}', now() at time zone 'utc' - interval '40 days', 'login_failure', '{name}', '{address}')")
    for alert_id, age in ((old_alert, "40 days"), (new_alert, "1 day")):
        psql("INSERT INTO security_alerts (id, event_type, severity, message, username, ip_address, timestamp, "
             f"resolved, details) VALUES ('{alert_id}', 'multiple_failed_logins', 'warning', "
             f"'WARNING: 7 failures for {name} from {address}', '{name}', '{address}', "
             f"now() at time zone 'utc' - interval '{age}', false, '{{}}')")
    try:
        _run_pass()
        assert psql(f"SELECT count(*) FROM security_records WHERE id = '{record_id}'") == "0"
        cleared = psql(f"SELECT coalesce(username, ''), coalesce(ip_address, ''), message FROM security_alerts "
                       f"WHERE id = '{old_alert}'")
        assert cleared == "||WARNING: 7 failures for {username} from {ip_address}", cleared
        kept = psql(f"SELECT username, ip_address FROM security_alerts WHERE id = '{new_alert}'")
        assert kept == f"{name}|{address}"
        shown = {a["id"]: a for a in admin.get("/api/security/alerts", params={"limit": 500}).json()["alerts"]}
        if old_alert in shown:
            assert shown[old_alert]["message"] == "WARNING: 7 failures for (name removed) from (address removed)"
    finally:
        psql(f"DELETE FROM security_alerts WHERE id IN ('{old_alert}', '{new_alert}')")
        psql(f"DELETE FROM security_records WHERE id = '{record_id}'")
