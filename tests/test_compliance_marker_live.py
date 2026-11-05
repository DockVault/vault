"""The rollback marker of the records of compliance access on real Postgres (app/core/compliance_marker.py), on a
throwaway database of the stack's server. A marker an older compliance row keeps, about to reach
COMPLIANCE_RECORD_MIN_DAYS: a transaction writes a new row of the compliance category and is still open when a
sync() in another transaction, which cannot see that row yet, finds the older row past the floor. sync() leaves the
marker as it is rather than remove it, so the new row, once committed, is still covered; a later sync() keeps the
marker for it, and removes it once that row is past the floor too. Writing the marker flushes nothing the caller has
not written yet. A change whose marker cannot be written still commits, and the next sync() writes the marker.
test_compliance_marker.py covers the rest offline.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

SCRIPT = PREAMBLE + r'''
from app.core import compliance_marker as marker
from app.core import compliance_retention as cr
from app.core.models import AuditLog, RoleEnum, User
from app.services.audit_logger import AuditLogger

def marked():
    with engine.connect() as c:
        return [r[0] for r in c.execute(text("SELECT key FROM data_requirements ORDER BY key"))]

floor = cr.floor_days()
later = now + timedelta(days=2)
out = {"before": marked()}
# An older compliance row, a day inside the floor now and past it two days later, keeps the marker.
with SessionLocal() as s:
    s.add(AuditLog(id=uuid.uuid4(), action="auditor_revoked", status="success",
                   timestamp=now - timedelta(days=floor - 1)))
    s.commit()
with SessionLocal() as s:
    out["sync_old_row"] = marker.sync(s, now=now)
    s.commit()
out["kept_for_the_old_row"] = marked()
# A transaction writes a new compliance row and stays open. What it has not written yet stays unwritten: the marker's
# write flushes nothing of the caller's.
writer = SessionLocal()
pending = User(id=uuid.uuid4(), username="cond-pending", email="pending@example.com", password_hash="x",
               role=RoleEnum.USER, is_active=True)
writer.add(pending)
row = AuditLogger(writer).build_row(action="auditor_granted", status="success", username="cond-admin")
out["still_pending"] = pending in writer.new
writer.add(row)
writer.flush()
# Two days later another transaction syncs: it sees the old row past the floor and not the new one.
with SessionLocal() as s:
    out["sync_while_open"] = marker.sync(s, now=later)
    s.commit()
out["while_open"] = marked()
writer.commit()
writer.close()
with SessionLocal() as s:
    out["sync_after_the_commit"] = marker.sync(s, now=later)
    s.commit()
out["kept_for_the_new_row"] = marked()
with SessionLocal() as s:
    out["sync_past_the_floor"] = marker.sync(s, now=now + timedelta(days=floor + 1))
    s.commit()
out["past_the_floor"] = marked()
# A change whose marker cannot be written (the table is locked meanwhile) still commits its row.
locker = engine.connect()
tx = locker.begin()
locker.execute(text("LOCK TABLE data_requirements IN ACCESS EXCLUSIVE MODE"))
change = SessionLocal()
change.execute(text("SET LOCAL lock_timeout = '500ms'"))
second = AuditLogger(change).build_row(action="case_requested", status="success", username="cond-aud")
second_id = second.id
change.add(second)
change.commit()
change.close()
tx.rollback()
locker.close()
with SessionLocal() as s:
    out["second_committed"] = s.get(AuditLog, second_id) is not None
out["after_the_failed_write"] = marked()
with SessionLocal() as s:
    out["sync_writes_it"] = marker.sync(s)
    s.commit()
out["after_the_sync"] = marked()
print(json.dumps(out))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_sync_never_removes_the_marker_while_a_transaction_that_wrote_a_compliance_row_is_open(throwaway):
    out = run_in(throwaway, SCRIPT)
    assert out["before"] == []
    assert out["sync_old_row"] is True and out["kept_for_the_old_row"] == ["compliance-records"]
    assert out["still_pending"] is True, "building the row flushed what the caller had not written"
    assert out["sync_while_open"] is None, "left as it was: a transaction that wrote a compliance row is open"
    assert out["while_open"] == ["compliance-records"]
    assert out["sync_after_the_commit"] is True and out["kept_for_the_new_row"] == ["compliance-records"]
    assert out["sync_past_the_floor"] is False and out["past_the_floor"] == []
    assert out["second_committed"] is True and out["after_the_failed_write"] == []
    assert out["sync_writes_it"] is True and out["after_the_sync"] == ["compliance-records"]
