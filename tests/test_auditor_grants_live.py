"""The auditor right on a running stack: proposed by one administrator, approved by an independent one, each
with their password and an authenticator code (app/core/auditor_rights.py, app/api/compliance_router.py).

  * the full flow: an account that set its own password and has an authenticator is proposed and approved, the
    grant is bound to its authenticator, recorded at each step, and every administrator and the account are told;
  * a one-person grant (the proposer approving) is refused and recorded;
  * an account that does not meet the preconditions is refused and recorded, before any code is asked for;
  * a proposal past its 7 days lapses, and the periodic job writes it;
  * one administrator revokes, and a new proposal can follow.

test_auditor_grants.py covers the rules offline.
"""
import json
import time

import pytest

from _account_change_helpers import (in_api_container, make_independent, notifications, own_password, psql,
                                     second_admin, signed_in)
from _sf_helpers import enroll_totp

pytestmark = pytest.mark.integration


def compliance_receipt(client, action, password, codes):
    """A receipt for a compliance step: the password and a recovery code, both, every time."""
    r = client.post("/auth/second-factor/step-up", json={"action": action, "method": "recovery",
                                                         "code": codes.pop(0), "password": password})
    assert r.status_code == 200, r.text
    return {"X-Second-Factor": r.json()["receipt"]}


def run_pass():
    """One pass of the pruner in the web container, retried while the web app's own runner holds its lock.
    Returns {job: whether it ran}."""
    source = ("import json\n"
              "from app.core import retention\n"
              "done = retention.run_pass()\n"
              "print(json.dumps(None if done is None else {n: r is not None for n, r in done}))\n")
    for _ in range(30):
        out = json.loads(in_api_container(source).stdout.strip().splitlines()[-1])
        if out is not None:
            return out
        time.sleep(1)
    raise AssertionError("the pruner's lock never came free")


def _audit(admin, action, uid):
    rows = admin.get("/audit/log", params={"action": action, "limit": 500}).json()
    return [a for a in rows if a["resource_id"] == uid]


@pytest.fixture
def auditors(admin):
    """Two independent administrators of long standing (ada proposes, bob approves), each with their own
    password and an authenticator, and an account (uma) that set its own password and has one."""
    with second_admin(admin, independent=True) as (ada, ada_c), second_admin(admin, independent=True) as (bob, bob_c):
        _ada_secret, ada_codes = enroll_totp(ada, ada_c)
        _bob_secret, bob_codes = enroll_totp(bob, bob_c)
        uma = own_password(admin.create_user(role="user"))
        uma_c = signed_in(uma)
        enroll_totp(uma, uma_c)
        try:
            yield {"ada": (ada, ada_c, ada_codes), "bob": (bob, bob_c, bob_codes), "uma": (uma, uma_c)}
        finally:
            psql(f"DELETE FROM auditor_grants WHERE user_id IN ('{uma['id']}', '{ada['id']}', '{bob['id']}')")
            admin.delete_user(uma["id"])


def _propose(client, account, codes, user_id):
    return client.post("/compliance/auditor-grants", json={"user_id": user_id, "note": "Annual access review"},
                       headers=compliance_receipt(client, "compliance.grant.propose", account["_password"], codes))


def test_the_full_flow_two_people_bound_to_the_authenticator_recorded_and_told(admin, auditors):
    ada, ada_c, ada_codes = auditors["ada"]
    bob, bob_c, bob_codes = auditors["bob"]
    uma, uma_c = auditors["uma"]
    # Without the code and the password, nothing is proposed.
    r = ada_c.post("/compliance/auditor-grants", json={"user_id": uma["id"]})
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "step_up_required", r.text
    r = _propose(ada_c, ada, ada_codes, uma["id"])
    assert r.status_code == 201, r.text
    grant = r.json()
    assert grant["status"] == "proposed" and grant["you_may_approve"] is False
    assert grant["provenance"]["password_set_by_other"] is False and grant["provenance"]["authenticator"]
    # The proposer may not approve: a one-person grant is refused and recorded.
    r = ada_c.post(f"/compliance/auditor-grants/{grant['id']}/approve",
                   headers=compliance_receipt(ada_c, "compliance.grant.approve", ada["_password"], ada_codes))
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "asked", r.text
    refused = _audit(admin, "auditor_grant_refused", uma["id"])
    assert refused and refused[0]["username"] == ada["_username"] and refused[0]["details"]["reason"] == "asked"
    # The independent administrator sees why they may and approves with their own code.
    listed = {g["id"]: g for g in bob_c.get("/compliance/auditors").json()["grants"]}
    assert listed[grant["id"]]["you_may_approve"] is True and listed[grant["id"]]["host_approval"] is False
    r = bob_c.post(f"/compliance/auditor-grants/{grant['id']}/approve",
                   headers=compliance_receipt(bob_c, "compliance.grant.approve", bob["_password"], bob_codes))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active" and r.json()["approved_by"] == bob["_username"]
    enrollment = psql(f"SELECT id FROM second_factor_enrollments WHERE user_id='{uma['id']}' AND status='active'")
    assert psql(f"SELECT second_factor_enrollment_id, confirmed_role, approved_by_operator, "
                f"(expires_at - approved_at) = interval '365 days' FROM auditor_grants WHERE id='{grant['id']}'") == \
        f"{enrollment}|user|f|t"
    assert uma_c.get("/compliance/me").json()["grant"]["status"] == "active"
    for action, who in (("auditor_grant_proposed", ada), ("auditor_granted", bob)):
        rows = _audit(admin, action, uma["id"])
        assert rows and rows[0]["username"] == who["_username"] and rows[0]["details"]["grant_id"] == grant["id"]
        assert "Annual access review" not in str(rows[0]["details"]), "free text stays sealed"
    assert "Annual access review" not in psql(f"SELECT note_enc FROM auditor_grants WHERE id='{grant['id']}'")
    # Everyone concerned was told: the account, and the administrators.
    for client in (uma_c, ada_c, bob_c, admin):
        titles = [n["title"] for n in notifications(client, "auditor_right")]
        assert "Auditor right granted" in titles and "Auditor right proposed" in titles
    # One administrator revokes; a new proposal can follow.
    r = admin.delete(f"/users/{uma['id']}/auditor", json={"reason": "End of the review"})
    assert r.status_code == 200 and r.json()["status"] == "revoked", r.text
    assert uma_c.get("/compliance/me").json() == {"grant": None}
    assert "Auditor right revoked" in [n["title"] for n in notifications(uma_c, "auditor_right")]
    assert _propose(ada_c, ada, ada_codes, uma["id"]).status_code == 201


def test_an_unfit_account_is_refused_before_any_code_and_recorded(admin, auditors):
    ada, ada_c, ada_codes = auditors["ada"]
    fresh = admin.create_user(role="user")       # the administrator chose its password; no authenticator
    try:
        before = len(ada_codes)
        r = ada_c.post("/compliance/auditor-grants", json={"user_id": fresh["id"]})
        assert r.status_code == 409, r.text
        assert [x["reason"] for x in r.json()["detail"]["reasons"]] == ["no_totp", "password_not_own"]
        assert len(ada_codes) == before
        rows = _audit(admin, "auditor_grant_refused", fresh["id"])
        assert rows and rows[0]["details"]["reasons"] == ["no_totp", "password_not_own"]
        assert psql(f"SELECT count(*) FROM auditor_grants WHERE user_id='{fresh['id']}'") == "0"
    finally:
        admin.delete_user(fresh["id"])


def test_a_proposal_lapses_after_seven_days_and_the_periodic_job_writes_it(admin, auditors):
    ada, ada_c, ada_codes = auditors["ada"]
    bob, bob_c, bob_codes = auditors["bob"]
    uma, _uma_c = auditors["uma"]
    grant = _propose(ada_c, ada, ada_codes, uma["id"]).json()
    psql(f"UPDATE auditor_grants SET proposed_at = proposed_at - interval '7 days 1 minute' WHERE id='{grant['id']}'")
    r = bob_c.post(f"/compliance/auditor-grants/{grant['id']}/approve")
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "lapsed", r.text
    assert run_pass()["auditor_grants"] is True
    assert psql(f"SELECT status, ended_at IS NOT NULL FROM auditor_grants WHERE id='{grant['id']}'") == "lapsed|t"
    rows = _audit(admin, "auditor_grant_lapsed", uma["id"])
    assert rows and rows[0]["username"] is None


def test_turning_down_takes_another_administrator_and_a_reason(admin, auditors):
    ada, ada_c, ada_codes = auditors["ada"]
    bob, bob_c, bob_codes = auditors["bob"]
    uma, _uma_c = auditors["uma"]
    grant = _propose(ada_c, ada, ada_codes, uma["id"]).json()
    r = ada_c.post(f"/compliance/auditor-grants/{grant['id']}/reject", json={"reason": "never mind"})
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "asked", r.text
    r = bob_c.post(f"/compliance/auditor-grants/{grant['id']}/reject", json={"reason": "Not needed"},
                   headers=compliance_receipt(bob_c, "compliance.grant.approve", bob["_password"], bob_codes))
    assert r.status_code == 200 and r.json()["status"] == "rejected", r.text
    detail = admin.get(f"/compliance/auditor-grants/{grant['id']}").json()
    assert detail["reject_reason"] == "Not needed" and detail["rejected_by"] == bob["_username"]
