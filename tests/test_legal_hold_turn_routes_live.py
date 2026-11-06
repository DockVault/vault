"""A hold, its confirmation, an undone release and a case asked for, through their routes on a running stack, while a
deletion step holds the turn of holds and deletions (app/core/legal_holds.py take_turn; app/api/compliance_router.py
_take_the_turn).

A deletion step holds the turn shared for its whole transaction (an archived day's scan or rewrite can take
seconds); the connection's lock_timeout is 5 s. Here a process in the web container takes the turn as a deletion
step does (compliance_retention.holds_back) and keeps it:

- for longer than the lock_timeout, less than legal_holds.TURN_WAIT_SECONDS: the step waits for it and is taken;
- for longer than TURN_WAIT_SECONDS: the step is refused, 409 deletion_running with Retry-After, the refusal
  recorded, nothing written, and the step-up's code not used: the same receipt takes the step once the deletion
  step has ended. Until then no further deletion step starts (legal_holds.want_turn), so the step asked again waits
  only for the one that held the turn.
"""
import json
import subprocess
import time

import pytest

from _account_change_helpers import API, in_api_container, psql
from _auditor_helpers import compliance_receipt, two_admins
from conftest import unique
from test_cases_live import TEXT as CASE_TEXT
from test_cases_live import world  # noqa: F401 -- the case fixture
from test_legal_holds_live import TEXT, _forget

pytestmark = pytest.mark.integration

HOLDER = r'''
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("hold-turn-test")
import sys, time
from datetime import datetime
from app.core.database import SessionLocal
from app.core import compliance_retention as cr
db = SessionLocal()
print("checked:", cr.holds_back(db, datetime.utcnow()), flush=True)
time.sleep(float(sys.argv[1]))
db.rollback()
db.close()
print("ended", flush=True)
'''


def _turn_wait_seconds() -> float:
    r = in_api_container("from app.core import legal_holds\nprint(legal_holds.TURN_WAIT_SECONDS)\n")
    return float(r.stdout.strip().splitlines()[-1])


class _DeletionStep:
    """A process in the web container holding the turn shared for ``seconds``, as a deletion step does."""

    def __init__(self, seconds: float):
        self.proc = subprocess.Popen(["docker", "exec", "-i", API, "python", "-c", HOLDER, str(seconds)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()           # the turn is held from here (whatever the check found)
        assert line.startswith("checked:"), (line, self.proc.stderr.read()[-800:] if not line else "")
        self.checked = line[len("checked:"):].strip()
        if seconds <= 0:
            self.wait()

    def wait(self):
        # Read through the same buffered pipe as the first line (communicate() reads the descriptor itself and
        # would miss what that read buffered); the process says only two short lines.
        self.proc.wait(timeout=180)
        out, err = self.proc.stdout.read(), self.proc.stderr.read()
        assert "ended" in out, err[-800:]


@pytest.fixture
def admins(admin):
    with two_admins(admin) as people:
        yield people


@pytest.fixture
def vault(admin):
    made = admin.create_vault(name=unique("turn"))
    cases = []
    try:
        yield made["id"], cases
    finally:
        _forget(cases, [made["id"]])
        admin.delete_vault(made["id"])


def _place(who, vault_id, headers=None):
    account, client, codes = who
    headers = headers or compliance_receipt(client, "compliance.hold.place", account["_password"], codes)
    t0 = time.monotonic()
    r = client.post("/compliance/holds", json={"vault_ids": [vault_id], **TEXT}, headers=headers)
    return r, round(time.monotonic() - t0, 2), headers


def _refusals(action, reason):
    return int(psql(f"SELECT count(*) FROM audit_logs WHERE action = '{action}' AND status = 'failure' "
                    f"AND details->>'reason' = '{reason}'"))


def _busy(r, waited, bound):
    assert r.status_code == 409, (r.status_code, r.text)
    assert r.json()["detail"]["reason"] == "deletion_running" and "try again" in r.json()["detail"]["text"]
    assert int(r.headers["Retry-After"]) > 0
    assert bound - 1 <= waited <= bound + 8, waited


def test_a_hold_waits_for_a_deletion_step_that_holds_the_turn_past_the_lock_timeout(admins, vault):
    vid, cases = vault
    step = _DeletionStep(10)
    r, waited, _h = _place(admins["ada"], vid)
    step.wait()
    assert r.status_code == 201, (r.status_code, waited, r.text)
    cases.append(r.json()["id"])
    assert waited >= 6, waited                                  # past the connection's 5 s lock_timeout


def test_a_hold_a_deletion_step_keeps_waiting_past_the_bound_is_refused_and_its_code_kept_for_after(admins, vault):
    vid, cases = vault
    bound = _turn_wait_seconds()
    before = _refusals("hold_placed", "deletion_running")
    step = _DeletionStep(bound + 12)
    r, waited, headers = _place(admins["ada"], vid)
    _busy(r, waited, bound)
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE vault_id = '{vid}'") == "0"
    assert _refusals("hold_placed", "deletion_running") == before + 1
    step.wait()
    # Until it is asked again, no further deletion step starts: it waits only for the one that held the turn.
    assert _DeletionStep(0).checked == "a legal hold or a compliance case is being asked for"
    r, _waited, _h = _place(admins["ada"], vid, headers=headers)            # the same receipt: not used before
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])
    assert _DeletionStep(0).checked != "a legal hold or a compliance case is being asked for"


def _hold_released(admins, vid, cases):
    """A hold placed by ada, confirmed by bob and released by ada: its release can be undone."""
    r, _w, _h = _place(admins["ada"], vid)
    assert r.status_code == 201, r.text
    case = r.json()
    cases.append(case["id"])
    for who, step, body in (("bob", "confirm", None), ("ada", "release", {"reason": "The claim was withdrawn."})):
        account, client, codes = admins[who]
        r = client.post(f"/compliance/cases/{case['id']}/hold/{step}", json=body,
                        headers=compliance_receipt(client, "compliance.hold.decide", account["_password"], codes))
        assert r.status_code == 200, r.text
    return case["id"]


def _confirm(admins, case_id, headers=None):
    account, client, codes = admins["bob"]
    headers = headers or compliance_receipt(client, "compliance.hold.decide", account["_password"], codes)
    t0 = time.monotonic()
    r = client.post(f"/compliance/cases/{case_id}/hold/confirm", headers=headers)
    return r, round(time.monotonic() - t0, 2), headers


def test_a_confirmation_waits_for_a_deletion_step_or_is_refused_past_the_bound_with_its_code_kept(admins, vault):
    """From its confirmation a hold holds back every deletion step (until then it holds none back), so the
    confirmation takes the turn as a placing does."""
    vid, cases = vault
    r, _w, _h = _place(admins["ada"], vid)
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    bound = _turn_wait_seconds()
    before = _refusals("hold_confirmed", "deletion_running")
    step = _DeletionStep(bound + 12)
    r, waited, headers = _confirm(admins, case_id)
    _busy(r, waited, bound)
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' "
                "AND confirmed_at IS NOT NULL") == "0"
    assert _refusals("hold_confirmed", "deletion_running") == before + 1
    step.wait()
    step = _DeletionStep(10)
    r, waited, _h = _confirm(admins, case_id, headers=headers)                # the same receipt
    step.wait()
    assert r.status_code == 200, (r.status_code, waited, r.text)
    assert r.json()["holds"][0]["confirmed_by"] == admins["bob"][0]["_username"], r.text
    assert waited >= 6, waited


def _undo(admins, case_id, headers=None):
    account, client, codes = admins["bob"]
    headers = headers or compliance_receipt(client, "compliance.hold.decide", account["_password"], codes)
    t0 = time.monotonic()
    r = client.post(f"/compliance/cases/{case_id}/hold/undo-release", headers=headers)
    return r, round(time.monotonic() - t0, 2), headers


def test_an_undone_release_waits_for_a_deletion_step_or_is_refused_past_the_bound_with_its_code_kept(admins, vault):
    vid, cases = vault
    case_id = _hold_released(admins, vid, cases)
    bound = _turn_wait_seconds()
    step = _DeletionStep(bound + 12)
    r, waited, headers = _undo(admins, case_id)
    _busy(r, waited, bound)
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' AND released_at IS NULL") == "0"
    step.wait()
    step = _DeletionStep(10)
    r, waited, _h = _undo(admins, case_id, headers=headers)                # the same receipt
    step.wait()
    assert r.status_code == 200 and r.json()["holds"][0]["standing"] is True, (r.status_code, waited, r.text)
    assert waited >= 6, waited


def _ask(world, headers=None):
    uma, uma_c, codes = world["uma"]
    _olga, _c, vid = world["olga"]
    headers = headers or compliance_receipt(uma_c, "compliance.case.request", uma["_password"], codes)
    t0 = time.monotonic()
    r = uma_c.post("/compliance/cases", json={"scope": [{"kind": "vault", "target_id": vid}], **CASE_TEXT},
                   headers=headers)
    if r.status_code == 201:
        world["cases"].append(r.json()["id"])
    return r, round(time.monotonic() - t0, 2), headers


def test_a_case_asked_for_waits_for_a_deletion_step_or_is_refused_past_the_bound_with_its_code_kept(world):
    uma = world["uma"][0]
    bound = _turn_wait_seconds()
    step = _DeletionStep(bound + 12)
    r, waited, headers = _ask(world)
    _busy(r, waited, bound)
    assert psql(f"SELECT count(*) FROM compliance_cases WHERE auditor_id = '{uma['id']}'") == "0"
    step.wait()
    step = _DeletionStep(10)
    r, waited, _h = _ask(world, headers=headers)                             # the same receipt
    step.wait()
    assert r.status_code == 201, (r.status_code, waited, r.text)
    assert waited >= 6, waited
    assert json.loads(psql(f"SELECT json_agg(status) FROM compliance_cases WHERE auditor_id = '{uma['id']}'")) == \
        ["pending"]
