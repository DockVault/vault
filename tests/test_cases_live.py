"""Compliance cases on a running stack (app/core/cases.py, the case routes in app/api/compliance_router.py): the
full flow, with an auditor right granted by two administrators, a case asked for and approved, the owner told in
the approving transaction (the same transaction id on the case, its hold, the owner's notification, the outbox row
and the audit rows) and by email (an SMTP server kept inside the web container), extended, and closed with a
summary; a fault in the owner's notice that fails the approval; the end of access by the pruner; the host's
approval refused while an administrator could approve; every refusal recorded; an approval whose hold waits for a
deletion in progress, after which the next deletion is kept; an administrator made by whoever created the
auditor's account refused as approver.

test_cases.py covers the rules offline.
"""
import subprocess
import time

import pytest

from _account_change_helpers import API, DB, in_api_container, notifications, psql, signed_in
from _auditor_helpers import (compliance_receipt, forget_grants, grant_right, new_auditor_account, run_pass,
                              two_admins)
from _owner_notice_helpers import mail_to, outbox, owner_with_vault, sender_held, sending_to_sink, wait_for
from _sf_helpers import enroll_totp

pytestmark = pytest.mark.integration

TEXT = {"purpose": "internal_investigation", "legal_basis": "legal_obligation",
        "justification": "Suspected exfiltration of client records, ticket SEC-2041.",
        "owner_note": "Your vault is part of an internal review; nothing is changed in it."}
SUBJECT = "Access to your vaults: case "


@pytest.fixture
def world(admin):
    """ada and bob (independent administrators), uma (an auditor whose right they granted), olga (who owns a
    vault). The cases made are removed afterwards, with their holds and what they kept."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        made = []
        try:
            yield {"admins": admins, "uma": (uma, uma_c, codes), "olga": (olga, olga_c, vid), "cases": made}
        finally:
            for cid in made:
                psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE case_id = '{cid}' AND released_at IS NULL")
            for table in ("held_files", "held_folders", "held_name_history"):
                psql(f"DELETE FROM {table} WHERE vault_id = '{vid}'")
            for cid in made:
                psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
            in_api_container("from app.core import legal_hold_marker\nlegal_hold_marker.check_at_start()\n")
            forget_grants(uma["id"])


def _ask(world, **extra):
    uma, uma_c, codes = world["uma"]
    _olga, _c, vid = world["olga"]
    r = uma_c.post("/compliance/cases", json={"scope": [{"kind": "vault", "target_id": vid}], **TEXT, **extra},
                   headers=compliance_receipt(uma_c, "compliance.case.request", uma["_password"], codes))
    assert r.status_code == 201, r.text
    world["cases"].append(r.json()["id"])
    return r.json()


def _as(world, name):
    account, client, codes = world["admins"][name]
    return account, client, codes


def _approve(world, name, case_id, version):
    account, client, codes = _as(world, name)
    headers = compliance_receipt(client, "compliance.case.approve", account["_password"], codes)
    if version is not None:
        headers["If-Match"] = f'"{version}"'
    return client.post(f"/compliance/cases/{case_id}/approve", headers=headers)


def _failures(action, case_id):
    return psql(f"SELECT string_agg(details->>'reason', ',' ORDER BY timestamp) FROM audit_logs "
                f"WHERE action = '{action}' AND status = 'failure' AND resource_id = '{case_id}'")


def test_the_full_flow(world, admin):
    olga, olga_c, vid = world["olga"]
    uma, uma_c, codes = world["uma"]
    case = _ask(world)
    assert case["status"] == "pending" and case["number"] is None and case["justification"] == TEXT["justification"]
    # Nothing is told to the owner, and nothing is held, before the approval.
    assert outbox(case["id"]) == [] and notifications(olga_c, "compliance_access") == []
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case['id']}'") == "0"

    _bob, bob_c, _ = _as(world, "bob")
    r = bob_c.get(f"/compliance/cases/{case['id']}")
    assert r.status_code == 200 and r.headers["ETag"] == '"1"'
    view = r.json()
    assert view["justification"] == TEXT["justification"] and view["auditor_provenance"]["username"] == uma["_username"]
    assert [v["vault_id"] for v in view["vaults"]] == [vid] and view["you_may"]["approve"]["may"] is True

    # The proposer of the auditor's right may not approve; the refusal is recorded. A stale or missing version is
    # refused before any code is asked for.
    assert _approve(world, "ada", case["id"], 1).status_code == 403
    assert _failures("case_approved", case["id"]) == "proposed"
    _bob, bob_c, bob_codes = _as(world, "bob")
    assert bob_c.post(f"/compliance/cases/{case['id']}/approve").status_code == 428
    assert bob_c.post(f"/compliance/cases/{case['id']}/approve", headers={"If-Match": '"9"'}).status_code == 412

    with sending_to_sink(admin):
        with sender_held():
            r = _approve(world, "bob", case["id"], 1)
            assert r.status_code == 200, r.text
            approved = r.json()
            assert approved["status"] == "active" and approved["number"].startswith("C-") and approved["version"] == 2
            # One transaction gave the access and told the owner.
            xids = psql(
                "SELECT (SELECT xmin::text FROM compliance_cases WHERE id = '{c}') || '|' || "
                "(SELECT string_agg(DISTINCT xmin::text, ',') FROM legal_hold_vaults WHERE case_id = '{c}') || '|' || "
                "(SELECT string_agg(DISTINCT xmin::text, ',') FROM notifications WHERE user_id = '{u}' "
                "AND type = 'compliance_access') || '|' || "
                "(SELECT string_agg(DISTINCT xmin::text, ',') FROM compliance_notice_outbox WHERE case_id = '{c}') "
                "|| '|' || (SELECT string_agg(DISTINCT xmin::text, ',') FROM audit_logs WHERE case_id = '{c}' "
                "AND status = 'success' "
                "AND action IN ('case_approved', 'owner_notice_written', 'hold_placed', 'hold_confirmed'))"
                .format(c=case["id"], u=olga["id"])).split("|")
            assert len(xids) == 5 and len(set(xids)) == 1 and xids[0], xids
            assert outbox(case["id"]) == [["activation", "pending", "0", olga["id"]]]
            assert psql("SELECT confirmed_by_username FROM legal_hold_vaults "
                        f"WHERE case_id = '{case['id']}'") == world["admins"]["bob"][0]["_username"]
        sent = mail_to(olga["email"], SUBJECT + approved["number"])
        assert sent, "the owner's email never arrived"
        assert "An investigation can open 1 of your vaults" in sent[0]["text"]
        assert TEXT["owner_note"] in sent[0]["text"] and TEXT["justification"] not in sent[0]["text"]
        notes = notifications(olga_c, "compliance_access")
        assert [n["title"] for n in notes] == ["An investigation can open 1 of your vaults"]
        assert approved["number"] in notes[0]["body"] and TEXT["owner_note"] not in notes[0]["body"]

        # An extension, by an independent administrator with the version read; the owner is told.
        _bob, bob_c, bob_codes = _as(world, "bob")
        headers = compliance_receipt(bob_c, "compliance.case.approve", _bob["_password"], bob_codes)
        headers["If-Match"] = '"2"'
        r = bob_c.post(f"/compliance/cases/{case['id']}/extend", json={"days": 7}, headers=headers)
        assert r.status_code == 200 and r.json()["total_access_days"] == 21, r.text
        assert [k for k, *_ in outbox(case["id"])] == ["activation", "extension"]
        assert wait_for(lambda: len(mail_to(olga["email"], SUBJECT + approved["number"], timeout=0)) >= 2,
                        timeout=60), "the extension's email never arrived"

        # The auditor closes it: the hold is released (with the release's code) and the owner gets a summary.
        r = uma_c.post(f"/compliance/cases/{case['id']}/close", json={"reason": "Concluded, nothing found."},
                       headers=compliance_receipt(uma_c, "compliance.hold.decide", uma["_password"], codes))
        assert r.status_code == 200 and r.json()["status"] == "closed", r.text
        assert [k for k, *_ in outbox(case["id"])] == ["activation", "extension", "closed"]
        assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case['id']}' "
                    "AND released_at IS NOT NULL AND purge_after IS NOT NULL") == "1"
    assert psql("SELECT count(*) FROM audit_logs WHERE action IN ('case_requested', 'case_approved', "
                f"'case_extended', 'case_closed') AND status = 'success' AND case_id = '{case['id']}'") == "4"


_FAULT = """
CREATE OR REPLACE FUNCTION test_refuse_compliance_notice() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'injected fault'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER test_refuse_compliance_notice BEFORE INSERT ON notifications
FOR EACH ROW WHEN (NEW.type = 'compliance_access') EXECUTE FUNCTION test_refuse_compliance_notice();
"""


def test_a_fault_in_the_owners_notice_fails_the_approval_and_nothing_is_given(world):
    case = _ask(world)
    psql(_FAULT)
    try:
        r = _approve(world, "bob", case["id"], 1)
        assert r.status_code >= 500, r.text
    finally:
        psql("DROP TRIGGER IF EXISTS test_refuse_compliance_notice ON notifications; "
             "DROP FUNCTION IF EXISTS test_refuse_compliance_notice()")
    assert psql(f"SELECT status || '|' || coalesce(number, '') || '|' || (access_starts_at IS NULL)::text "
                f"FROM compliance_cases WHERE id = '{case['id']}'") == "pending||true"
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case['id']}'") == "0"
    assert outbox(case["id"]) == []
    # And with the fault gone, the same version approves.
    assert _approve(world, "bob", case["id"], 1).status_code == 200


def test_the_pruner_ends_access_and_tells_the_owner(world):
    case = _ask(world, hold=False)
    assert _approve(world, "bob", case["id"], 1).status_code == 200
    psql("UPDATE compliance_cases SET access_ends_at = (now() AT TIME ZONE 'utc') - interval '1 second' "
         f"WHERE id = '{case['id']}'")
    assert run_pass()["compliance_cases"] is True
    assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case['id']}'") == "closed"
    assert [k for k, *_ in outbox(case["id"])] == ["activation", "access_ended"]
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'case_access_ended' "
                f"AND case_id = '{case['id']}'") == "1"


def _host(*args):
    r = subprocess.run(["docker", "exec", API, "python", "-m", "app.core.host_compliance", *args],
                       capture_output=True, text=True, timeout=120)
    import json
    return r.returncode, json.loads(r.stdout.strip().splitlines()[-1])


def test_the_host_may_not_approve_while_an_administrator_can(world):
    case = _ask(world)
    ref = case["reference"]
    code, answer = _host("approve", "--case", case["id"], "--confirm-case", ref)
    assert code == 2 and "may not" in answer["error"], answer
    assert _failures("case_approved", case["id"]) == "independent_admin"
    code, answer = _host("reject", "--case", case["id"], "--confirm-case", ref, "--reason", "No grounds.")
    assert code == 2 and "may not" in answer["error"], answer
    assert _failures("case_rejected", case["id"]) == "independent_admin"
    assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case['id']}'") == "pending"


def test_refusals_are_recorded(world, admin):
    uma, uma_c, codes = world["uma"]
    olga, olga_c, vid = world["olga"]
    # An auditor the case would concern.
    own = uma_c.create_vault()
    try:
        r = uma_c.post("/compliance/cases", json={"scope": [{"kind": "vault", "target_id": own["id"]}], **TEXT},
                       headers=compliance_receipt(uma_c, "compliance.case.request", uma["_password"], codes))
        assert r.status_code == 403 and r.json()["detail"]["reason"] == "auditor_concerned"
        assert psql("SELECT count(*) FROM audit_logs WHERE action = 'case_requested' AND status = 'failure' "
                    f"AND user_id = '{uma['id']}' AND details->>'reason' = 'auditor_concerned'") == "1"
    finally:
        uma_c.delete_vault(own["id"])
    # Someone the case does not let in sees nothing of it.
    case = _ask(world)
    assert olga_c.get(f"/compliance/cases/{case['id']}").status_code == 404
    assert olga_c.post(f"/compliance/cases/{case['id']}/withdraw").status_code == 404
    # The vault picker: no name the auditor could not already read, and the look recorded.
    r = uma_c.get("/compliance/vault-picker", params={"owner": olga["_username"]})
    assert r.status_code == 200 and [v["name"] for v in r.json()["vaults"]] == [None]
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'case_picker_viewed' "
                f"AND user_id = '{uma['id']}' AND resource_id = '{olga['id']}'") == "1"
    # Withdrawn by its auditor while it waits.
    r = uma_c.post(f"/compliance/cases/{case['id']}/withdraw")
    assert r.status_code == 200 and r.json()["status"] == "withdrawn"


def _upload(client, vid, name, content):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def test_an_approval_whose_hold_meets_a_deletion_in_progress_waits_and_the_next_deletion_is_kept(world):
    olga, olga_c, vid = world["olga"]
    during = _upload(olga_c, vid, "during.txt", b"deleted while the approval waits")
    after = _upload(olga_c, vid, "after.txt", b"deleted after the approval")
    case = _ask(world)
    assert case["hold"] is True
    bob, bob_c, bob_codes = _as(world, "bob")
    headers = compliance_receipt(bob_c, "compliance.case.approve", bob["_password"], bob_codes)
    headers["If-Match"] = '"1"'
    # A deletion's transaction holds the vault's row (FOR NO KEY UPDATE, as every deleting path takes it), deletes a
    # file and commits three seconds later.
    holder = subprocess.Popen(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
                               f"BEGIN; SELECT id FROM vaults WHERE id = '{vid}' FOR NO KEY UPDATE; "
                               f"DELETE FROM files WHERE id = '{during}'; SELECT pg_sleep(3); COMMIT;"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and psql(
                "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(3)%' AND state = 'active' "
                "AND pid <> pg_backend_pid()") == "0":
            time.sleep(0.1)
        started = time.monotonic()
        r = bob_c.post(f"/compliance/cases/{case['id']}/approve", headers=headers)
        waited = time.monotonic() - started
    finally:
        holder.wait(timeout=30)
    assert r.status_code == 200 and r.json()["status"] == "active", r.text
    assert waited >= 1.5, f"the approval did not wait for the deletion's lock ({waited:.2f}s)"
    # That deletion committed before the hold did; every one after it is kept.
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case['id']}' "
                "AND released_at IS NULL") == "1"
    assert psql(f"SELECT count(*) FROM files WHERE id = '{during}'") == "0"
    assert olga_c.post(f"/vaults/{vid}/files/{after}/delete").status_code == 200
    assert psql(f"SELECT kept_reason FROM held_files WHERE id = '{after}'") == "deleted"


def test_an_administrator_made_by_whoever_created_the_auditors_account_may_not_approve(admin):
    """ada creates uma's account and makes bea an administrator; bob approves uma's right, which ada proposed; uma
    asks for a case on olga's vault. bea may not approve it (a stand-in administrator and a stand-in account
    combined): refused (403) before any code, and recorded."""
    with two_admins(admin) as admins:
        ada, ada_c, _ada_codes = admins["ada"]
        uma, uma_c, codes = new_auditor_account(ada_c)
        bea = ada_c.create_user(role="admin")
        made = []
        try:
            assert psql(f"SELECT created_by FROM users WHERE id = '{uma['id']}'") == ada["id"]
            # bea of long standing, with a password of her own, still made by ada.
            psql("UPDATE admin_grants SET granted_at = (now() AT TIME ZONE 'utc') - interval '15 days' "
                 f"WHERE user_id = '{bea['id']}'")
            psql(f"UPDATE users SET password_set_by = NULL, password_set_by_other_at = NULL WHERE id = '{bea['id']}'")
            assert ada["id"] in psql(f"SELECT lineage::text FROM admin_grants WHERE user_id = '{bea['id']}'")
            bea_c = signed_in(bea)
            _s, bea_codes = enroll_totp(bea, bea_c)
            grant_right(admins, uma["id"])
            _olga, _olga_c, vid = owner_with_vault(admin)
            r = uma_c.post("/compliance/cases", json={"scope": [{"kind": "vault", "target_id": vid}], **TEXT},
                           headers=compliance_receipt(uma_c, "compliance.case.request", uma["_password"], codes))
            assert r.status_code == 201, r.text
            case = r.json()
            made.append(case["id"])
            view = admins["bob"][1].get(f"/compliance/cases/{case['id']}").json()
            assert bea["_username"] not in view["independent_approvers"]
            headers = compliance_receipt(bea_c, "compliance.case.approve", bea["_password"], bea_codes)
            headers["If-Match"] = '"1"'
            r = bea_c.post(f"/compliance/cases/{case['id']}/approve", headers=headers)
            assert r.status_code == 403 and r.json()["detail"]["reason"] == "made_by_creator", r.text
            assert _failures("case_approved", case["id"]) == "made_by_creator"
            assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case['id']}'") == "pending"
        finally:
            for cid in made:
                psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
            forget_grants(uma["id"])
            admin.delete_user(bea["id"])
