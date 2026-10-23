"""An administrator's acknowledgment of the audit log's integrity warnings on a running stack
(app/api/audit_integrity_router.py, static/js/settings-integrity.js).

A row written into an hour the stack sealed within the last 6 hours is sealed late at the next pass, a warning
until it is acknowledged. The warnings route shows the late seal with the row it added; the acknowledgment
asks for the password every time (the fixed step-up), refuses a seal that is not a warning an administrator may
acknowledge, and writes an ``ack`` seal naming the administrator, with its audit row; the integrity status then
no longer shows the warning. The stack must have sealed an hour with rows less than 6 hours before (it seals an
hour once it has closed): on a stack started less than an hour before, the test says so and is skipped.
test_audit_integrity_admin.py covers the rules offline.
"""
import json
import time
import uuid

import pytest

from _account_change_helpers import in_api_container, psql, second_admin

pytestmark = pytest.mark.integration

ACTION = "admin.audit_integrity.acknowledge"


def _run_pass():
    source = ("import json\nfrom app.core import retention\ndone = retention.run_pass()\n"
              "print(json.dumps(None if done is None else [n for n, _r in done]))\n")
    for _ in range(30):
        out = json.loads(in_api_container(source).stdout.strip().splitlines()[-1])
        if out is not None:
            return out
        time.sleep(1)
    raise AssertionError("the pruner's lock never came free")


def _recent_sealed_hour():
    """An hour with rows whose own hour seal the stack wrote less than 5 hours ago, or None."""
    return psql("SELECT to_char(period_start, 'YYYY-MM-DD\"T\"HH24:MI:SS') FROM audit_seals WHERE kind = 'hour' "
                "AND period_end - period_start = interval '1 hour' AND row_count > 0 "
                "AND sealed_at > (now() AT TIME ZONE 'utc') - interval '5 hours' ORDER BY seq DESC LIMIT 1") or None


def _receipt(client, password):
    r = client.post("/auth/second-factor/step-up", json={"action": ACTION, "method": "password", "code": password})
    assert r.status_code == 200, r.text
    return r.json()["receipt"]


def test_an_administrator_acknowledges_a_late_seal_after_seeing_its_rows(admin):
    _run_pass()
    hour = _recent_sealed_hour()
    if hour is None:
        pytest.skip("the stack has sealed no hour with rows in the last 5 hours yet (it seals an hour once it has "
                    "closed): run this file on a stack up for more than an hour")
    row_id = str(uuid.uuid4())
    psql("INSERT INTO audit_logs (id, action, status, timestamp, username, details, seal_nonce, privacy_version) "
         f"VALUES ('{row_id}', 'file_uploaded', 'success', '{hour}'::timestamp + interval '59 minutes', "
         f"'late-carol', '{{}}', decode(md5(random()::text), 'hex'), 3)")
    _run_pass()
    late = psql(f"SELECT seq FROM audit_seals WHERE kind = 'late' AND detail::text LIKE '%{row_id}%'")
    assert late, "the pass did not seal the row late"
    late = int(late)

    shown = admin.get("/settings/audit-integrity/warnings")
    assert shown.status_code == 200, shown.text
    entry = [w for w in shown.json()["warnings"] if w["seq"] == late]
    assert entry and entry[0]["kind"] == "late" and entry[0]["added"] == 1, shown.json()
    assert [r["id"] for r in entry[0]["rows"]] == [row_id] and entry[0]["rows"][0]["account"] == "late-carol"
    status = admin.get("/activity/integrity").json()
    assert any(w["kind"] == "late" for w in status["warnings"]), status

    with second_admin(admin) as (account, client):
        r = client.post("/settings/audit-integrity/acknowledge", json={"seqs": [late]})
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["action"] == ACTION
        # Genesis is no warning: refused, whatever the receipt.
        r = client.post("/settings/audit-integrity/acknowledge", json={"seqs": [1]},
                        headers={"X-Second-Factor": _receipt(client, account["_password"])})
        assert r.status_code == 409, r.text
        r = client.post("/settings/audit-integrity/acknowledge", json={"seqs": [late]},
                        headers={"X-Second-Factor": _receipt(client, account["_password"])})
        assert r.status_code == 200, r.text
        assert r.json()["acknowledged"] == [late]
        user_id = account["id"]
    ack = json.loads(psql("SELECT detail::text FROM audit_seals WHERE kind = 'ack' ORDER BY seq DESC LIMIT 1"))
    assert (ack["acknowledges"], ack["by"], ack["user_id"]) == ([late], "admin", str(user_id))
    audit = psql(f"SELECT action FROM audit_logs WHERE id = '{ack['request']}'")
    assert audit == "audit_integrity_acknowledged"
    assert late not in [w["seq"] for w in admin.get("/settings/audit-integrity/warnings").json()["warnings"]]
