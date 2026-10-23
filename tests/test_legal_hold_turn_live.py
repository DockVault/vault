"""Legal holds and the deletions they hold back take turns, on a running stack's Postgres (a throwaway database of
its own, tests/_throwaway_db.py): app/core/legal_holds.py take_turn and app/core/compliance_retention.py holds_back.

- A hold being placed (the turn taken exclusively, the hold written, not yet committed) makes a deletion's check
  wait until it commits, and the check then sees the hold: it cannot read the database as it was just before.
- A deletion that has checked (the turn taken shared, nothing holding) makes a hold being placed wait until the
  deletion's transaction ends: the hold is then written after what the deletion did, not beside it.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration


@pytest.fixture
def db_name():
    yield from throwaway_database()


SCENARIO = PREAMBLE + r'''
import threading, time
from app.core import compliance_retention as cr, legal_holds
from app.core.models import ComplianceCase, LegalHoldVault, RoleEnum, User
out = {}
with SessionLocal() as s:
    auditor = User(id=uuid.uuid4(), username="aud-" + uuid.uuid4().hex[:6], email=None, password_hash="x",
                   role=RoleEnum.USER, is_active=True)
    s.add(auditor)
    s.flush()
    case = ComplianceCase(id=uuid.uuid4(), status="closed", purpose="internal_investigation", legal_basis="f",
                          justification_enc="x", owner_note_enc="x", auditor_id=auditor.id,
                          auditor_username=auditor.username, closed_at=now - timedelta(days=3000))
    s.add(case)
    s.commit()
    case_id = case.id


def check(result, key):
    db = SessionLocal()
    try:
        t0 = time.monotonic()
        result[key] = cr.holds_back(db, now)
        result[key + "_seconds"] = round(time.monotonic() - t0, 2)
    finally:
        db.rollback()
        db.close()


# A hold being placed: the check waits for it, and sees it.
placing = SessionLocal()
legal_holds.take_turn(placing, shared=False)
placing.add(LegalHoldVault(case_id=case_id, vault_id=uuid.uuid4(), placed_by_username="aud", placed_at=now))
placing.flush()
t = threading.Thread(target=check, args=(out, "during_placing"))
t.start()
time.sleep(2.0)
out["check_waited_for_the_hold"] = t.is_alive()
placing.commit()
placing.close()
t.join(20)
check(out, "after_placing")

# Released: a deletion checks first and holds its turn; a hold being placed waits for its transaction to end.
with SessionLocal() as s:
    s.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id).update(
        {LegalHoldVault.released_at: now}, synchronize_session=False)
    s.commit()
deleting = SessionLocal()
out["deletion_checked"] = cr.holds_back(deleting, now)
placed = {}


def place():
    db = SessionLocal()
    try:
        t0 = time.monotonic()
        legal_holds.take_turn(db, shared=False)
        placed["seconds"] = round(time.monotonic() - t0, 2)
        db.add(LegalHoldVault(case_id=case_id, vault_id=uuid.uuid4(), placed_by_username="aud", placed_at=now))
        db.commit()
    finally:
        db.close()
p = threading.Thread(target=place)
p.start()
time.sleep(2.0)
out["placing_waited_for_the_deletion"] = p.is_alive()
deleting.rollback()
deleting.close()
p.join(20)
out["placed_after_seconds"] = placed.get("seconds")
check(out, "after_the_new_hold")
print(json.dumps(out))
'''


def test_a_hold_and_a_deletions_check_take_turns_on_postgres(db_name):
    out = run_in(db_name, SCENARIO)
    assert out["check_waited_for_the_hold"] is True, out
    assert out["during_placing"] == "a legal hold stands" and out["during_placing_seconds"] >= 1.5, out
    assert out["after_placing"] == "a legal hold stands", out
    assert out["deletion_checked"] is None, out
    assert out["placing_waited_for_the_deletion"] is True and out["placed_after_seconds"] >= 1.5, out
    assert out["after_the_new_hold"] == "a legal hold stands", out
