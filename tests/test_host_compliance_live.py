"""Live: compliance access from the host, run inside the web container as `dockvault.py cases` runs it
(python -m app.core.host_compliance), following test_host_operator_live.py.

  * the host approves an auditor right only while no independent administrator with an authenticator exists,
    recorded as operator@host; while one exists it refuses, and the refusal is recorded;
  * nothing changes unless the account's username is typed again and matches;
  * the host revokes a right, recorded as operator@host;
  * a case is approved only with its reference typed again, and only while no independent administrator exists;
  * downgrade-blockers lists the records of data an older version cannot read, through the account tool too,
    as `dockvault.py update` asks it;
  * when something stops it (the database out of reach, a start-up that refuses the configuration), it still
    prints its one answer, with exit status 1.

test_host_compliance.py and test_dockvault_cases.py cover the tool and the host side offline.
"""
import json
import secrets
import subprocess
import uuid

import pytest

from conftest import skip_if_container_absent
from _account_change_helpers import API, psql
from _auditor_helpers import audit_rows, compliance_receipt, forget_grants, new_auditor_account, two_admins

pytestmark = pytest.mark.integration

HOST = "operator@host"


def tool(*args, module="app.core.host_compliance"):
    try:
        r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", module, *args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the command did not finish within {exc.timeout} s")
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines, (r.stderr or "")[-800:]
    answer = json.loads(lines[-1])
    assert r.returncode == (0 if answer["ok"] else 2), (r.returncode, answer)
    return answer


@pytest.fixture
def proposed(admin):
    """ada proposed the right for uma; bob is an independent administrator with an authenticator."""
    with two_admins(admin) as admins:
        ada, ada_c, ada_codes = admins["ada"]
        uma, uma_c, _codes = new_auditor_account(admin)
        r = ada_c.post("/compliance/auditor-grants", json={"user_id": uma["id"]},
                       headers=compliance_receipt(ada_c, "compliance.grant.propose", ada["_password"], ada_codes))
        assert r.status_code == 201, r.text
        try:
            yield {"grant": r.json()["id"], "uma": uma, "uma_c": uma_c, "admins": admins}
        finally:
            psql(f"DELETE FROM compliance_cases WHERE auditor_id = '{uma['id']}'")
            forget_grants(uma["id"], ada["id"], admins["bob"][0]["id"])
            admin.delete_user(uma["id"])


def _no_independent_administrator(p):
    """bob's authenticator removed: the approval asks for its code, so bob cannot approve, and nobody can."""
    psql(f"DELETE FROM second_factor_enrollments WHERE user_id = '{p['admins']['bob'][0]['id']}'")


def test_the_host_approves_a_right_only_when_no_administrator_can(admin, proposed):
    uma, grant = proposed["uma"], proposed["grant"]
    answer = tool("grant-approve", "--grant", grant, "--confirm-username", uma["_username"])
    assert answer["ok"] is False and proposed["admins"]["bob"][0]["_username"] in answer["error"]
    rows = audit_rows(admin, "auditor_grant_refused", uma["id"])
    assert rows and rows[0]["username"] == HOST and rows[0]["details"]["action"] == "grant-approve"
    listed = {g["id"]: g for g in tool("list")["grants"]}
    assert listed[grant]["host_may_approve"] is False

    _no_independent_administrator(proposed)
    assert {g["id"]: g for g in tool("list")["grants"]}[grant]["host_may_approve"] is True
    answer = tool("grant-approve", "--grant", grant, "--confirm-username", uma["_username"] + "x")
    assert answer["ok"] is False and "does not match" in answer["error"]
    assert psql(f"SELECT status FROM auditor_grants WHERE id='{grant}'") == "proposed"
    answer = tool("grant-approve", "--grant", grant, "--confirm-username", uma["_username"])
    assert answer["ok"] and answer["granted"]["status"] == "active", answer
    assert psql(f"SELECT approved_by IS NULL, approved_by_operator, approved_by_username FROM auditor_grants "
                f"WHERE id='{grant}'") == f"t|t|{HOST}"
    rows = audit_rows(admin, "auditor_granted", uma["id"])
    assert rows and rows[0]["username"] == HOST and rows[0]["details"]["by"] == "host operator"
    assert proposed["uma_c"].get("/compliance/me").json()["grant"]["live"] is True

    answer = tool("revoke-auditor", "--username", uma["_username"], "--confirm-username", uma["_username"])
    assert answer["ok"] and answer["revoked"]["status"] == "revoked"
    rows = audit_rows(admin, "auditor_revoked", uma["id"])
    assert rows and rows[0]["username"] == HOST


def test_a_case_needs_its_reference_and_no_independent_administrator(admin, proposed):
    uma, grant = proposed["uma"], proposed["grant"]
    case_id = str(uuid.uuid4())
    psql("INSERT INTO compliance_cases (id, status, purpose, legal_basis, justification_enc, owner_note_enc, "
         "auditor_id, auditor_username, grant_id, requested_at, created_at, updated_at) VALUES "
         f"('{case_id}', 'pending', 'investigation', 'legitimate', 'cenc1:x', 'cenc1:x', '{uma['id']}', "
         f"'{uma['_username']}', '{grant}', now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc', "
         "now() AT TIME ZONE 'utc')")
    reference = case_id.replace("-", "")[:8]
    assert [c["reference"] for c in tool("list")["cases"] if c["id"] == case_id] == [reference]
    answer = tool("approve", "--case", case_id, "--confirm-case", reference)
    assert answer["ok"] is False and proposed["admins"]["bob"][0]["_username"] in answer["error"]
    _no_independent_administrator(proposed)
    answer = tool("approve", "--case", case_id, "--confirm-case", "00000000")
    assert answer["ok"] is False and "does not match" in answer["error"]
    answer = tool("approve", "--case", case_id, "--confirm-case", reference)
    # The reference typed again and no administrator able to approve: the host's approval itself runs, and refuses
    # this case, whose auditor's right was only proposed. Each refusal is recorded as the host's.
    assert answer["ok"] is False and "right is not in force" in answer["error"], answer
    assert psql(f"SELECT status, number IS NULL FROM compliance_cases WHERE id='{case_id}'") == "pending|t"
    assert psql("SELECT string_agg(coalesce(username, '') || '/' || status || '/' || (details::jsonb ->> 'reason'), "
                f"',' ORDER BY timestamp) FROM audit_logs WHERE action = 'case_approved' AND case_id = '{case_id}' "
                "AND details::jsonb ->> 'reason' = 'auditor_not_live'") == f"{HOST}/failure/auditor_not_live"


def test_downgrade_blockers_from_both_tools():
    key = f"test-{uuid.uuid4().hex[:8]}"
    psql("INSERT INTO data_requirements (key, requires_at_least, reason, undo, since) VALUES "
         f"('{key}', '0.30.0', 'A test record', 'Nothing to undo', now() AT TIME ZONE 'utc')")
    try:
        for module in ("app.core.host_compliance", "app.core.host_operator"):
            mine = [b for b in tool("downgrade-blockers", "--target", "0.29.9", module=module)["blockers"]
                    if b["key"] == key]
            assert mine == [{"key": key, "requires_at_least": "0.30.0", "reason": "A test record",
                             "undo": "Nothing to undo"}]
            assert not [b for b in tool("downgrade-blockers", "--target", "0.30.0", module=module)["blockers"]
                        if b["key"] == key]
        answer = tool("downgrade-blockers", "--target", "next", module="app.core.host_operator")
        assert answer["ok"] is False
    finally:
        psql(f"DELETE FROM data_requirements WHERE key = '{key}'")


@pytest.mark.parametrize("setting, said", [
    # The database refuses the connection.
    ("DATABASE_URL=postgresql://sftp_user:{made_up}@127.0.0.1:1/sftp_db", "127.0.0.1"),
    # The web app's start-up refuses the configuration and exits.
    ("ENCRYPTION_KEY={made_up}", "encryption-key-invalid"),
])
def test_when_something_stops_it_it_still_prints_one_answer(setting, said):
    # dockvault.py cases reads the one JSON line; it says the tool could not answer, with exit status 1. What
    # happened is on standard error; the made-up value given to it is in neither stream.
    made_up = "Not-A-Real-Value-" + secrets.token_hex(8)
    cmd = ["docker", "exec", "-i", "-e", setting.format(made_up=made_up),
           API, "python", "-m", "app.core.host_compliance", "list"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the command did not finish within {exc.timeout} s")
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert [json.loads(ln) for ln in lines] == [
        {"ok": False, "error": "The compliance tool stopped before it could answer."}], (r.stdout, r.stderr[-800:])
    assert r.returncode == 1
    assert "Traceback" in r.stderr and said in r.stderr, r.stderr[-800:]
    assert made_up not in r.stdout and made_up not in r.stderr
