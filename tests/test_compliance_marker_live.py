"""The rollback marker of the records of compliance access on real Postgres (app/core/compliance_marker.py), on a
throwaway database of the stack's server. A marker an older compliance row keeps, about to reach
COMPLIANCE_RECORD_MIN_DAYS: a transaction writes a new row of the compliance category and is still open when a
sync() in another transaction, which cannot see that row yet, finds the older row past the floor. sync() leaves the
marker as it is rather than remove it, so the new row, once committed, is still covered; a later sync() keeps the
marker for it, and removes it once that row is past the floor too. Writing the marker flushes nothing the caller has
not written yet. A change whose marker cannot be written still commits, and the next sync() writes the marker. An
ordinary account's refused case read and refused hold, and a vault owner's own step, write their rows and no marker.
A counted row left without its marker (its write gave up) is named by downgrade-blockers, which writes the marker.
A day ``audit unarchive`` restores, which reads in one snapshot (repeatable read), writes the marker for the rows it
puts back, also when another transaction committed one after its snapshot, and holds the lock so that a sync() which
cannot see those rows leaves the marker; any other error of that write is raised, so the day stays archived.
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


NOT_COUNTED = PREAMBLE + r'''
from app.core import case_access, legal_holds
from app.core import compliance_marker as marker
from app.core.models import AuditLog, RoleEnum, User
from app.services.audit_logger import AuditLogger

def marked():
    with engine.connect() as c:
        return [r[0] for r in c.execute(text("SELECT key FROM data_requirements ORDER BY key"))]

out = {"before": marked()}
with SessionLocal() as s:
    user = User(id=uuid.uuid4(), username="cond-plain", email="plain@example.com", password_hash="x",
                role=RoleEnum.USER, is_active=True)
    s.add(user)
    s.commit()
    uid = user.id
    # A signed-in account with no right: a read of a case that does not exist, a legal hold it may not place.
    case_access.record_refused(s, uuid.uuid4(), user, case_access.Refused(case_access.NO_CASE))
    legal_holds.record_refusal(s, "hold_placed", None, actor=user, reason=legal_holds.NOT_ALLOWED)
    # The owner of a vault with a password shows its names on Access to my vaults.
    s.add(AuditLogger(s).build_row(action="owner_access_unlocked", status="success", user=user, resource_type="vault",
                                   resource_id=str(uuid.uuid4()), details={}))
    s.commit()
with SessionLocal() as s:
    out["rows"] = sorted([a, st] for a, st in s.query(AuditLog.action, AuditLog.status)
                         .filter(AuditLog.user_id == uid).all())
out["after_them"] = marked()
with SessionLocal() as s:
    out["sync"] = marker.sync(s)
    s.commit()
out["after_the_sync"] = marked()
with SessionLocal() as s:
    s.add(AuditLogger(s).build_row(action="auditor_granted", status="success", username="cond-admin"))
    s.commit()
out["after_a_step_taken"] = marked()
print(json.dumps(out))
'''


RESTORED = PREAMBLE + r'''
from sqlalchemy.exc import DBAPIError
from app.core import compliance_marker as marker
from app.core import recording_marker

def marked():
    with engine.connect() as c:
        return [r[0] for r in c.execute(text("SELECT key FROM data_requirements ORDER BY key"))]

def a_day():
    """The transaction of a day audit unarchive restores: one snapshot, taken by its first read."""
    day = SessionLocal()
    day.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
    day.execute(text("SELECT key FROM data_requirements")).all()
    return day

with SessionLocal() as s:
    recording_marker._ensure_table(s)
    s.commit()
out = {"before": marked()}
# Nothing marked: the day writes the marker for a restored row that keeps it.
day = a_day()
out["written"] = marker.restored(day, now, now=now)
day.commit()
day.close()
out["after_the_day"] = marked()
# The marker is there: a sync() meanwhile, which cannot see the rows the day puts back, leaves it.
day = a_day()
out["again"] = marker.restored(day, now, now=now)
with SessionLocal() as s:
    out["sync_while_restoring"] = marker.sync(s, now=now)
    s.commit()
day.commit()
day.close()
out["after_the_sync"] = marked()
# Removed, then committed again by a step taken after the day's snapshot: the day's write finds it there.
with SessionLocal() as s:
    out["sync_alone"] = marker.sync(s, now=now)
    s.commit()
out["removed"] = marked()
day = a_day()
with SessionLocal() as other:
    marker.ensure(other)
    other.commit()
out["restored_over_a_later_one"] = marker.restored(day, now, now=now)
day.commit()
day.close()
out["after_both"] = marked()
# Any other error of the write is raised, so the day stays archived: here a trigger refuses every new requirement.
with SessionLocal() as s:
    out["cleared"] = marker.sync(s, now=now)
    s.commit()
with engine.begin() as c:
    c.execute(text("CREATE FUNCTION refuse_requirement() RETURNS trigger LANGUAGE plpgsql AS "
                   "$$BEGIN RAISE EXCEPTION 'requirement refused'; END$$"))
    c.execute(text("CREATE TRIGGER refuse_requirement BEFORE INSERT ON data_requirements FOR EACH ROW "
                   "EXECUTE FUNCTION refuse_requirement()"))
day = a_day()
try:
    marker.restored(day, now, now=now)
    out["refused"] = None
except DBAPIError as exc:
    out["refused"] = [getattr(exc.orig, "pgcode", None), "requirement refused" in str(exc.orig)]
day.rollback()
day.close()
out["after_the_refusal"] = marked()
with engine.begin() as c:
    c.execute(text("DROP TRIGGER refuse_requirement ON data_requirements"))
day = a_day()
out["written_once_it_can_be"] = marker.restored(day, now, now=now)
day.commit()
day.close()
out["at_last"] = marked()
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


def test_a_refused_request_or_an_owners_own_step_writes_no_marker(throwaway):
    out = run_in(throwaway, NOT_COUNTED)
    assert out["before"] == []
    assert out["rows"] == [["case_access_refused", "failure"], ["hold_placed", "failure"],
                           ["owner_access_unlocked", "success"]], "the rows are written all the same"
    assert out["after_them"] == [] and out["sync"] is False and out["after_the_sync"] == []
    assert out["after_a_step_taken"] == ["compliance-records"]


def test_a_restored_day_writes_the_marker_under_its_snapshot_and_the_lock(throwaway):
    out = run_in(throwaway, RESTORED)
    assert out["before"] == []
    assert out["written"] is True and out["after_the_day"] == ["compliance-records"]
    assert out["again"] is True and out["sync_while_restoring"] is None, "left as it was: the day holds the lock"
    assert out["after_the_sync"] == ["compliance-records"]
    assert out["sync_alone"] is False and out["removed"] == []
    assert out["restored_over_a_later_one"] is True and out["after_both"] == ["compliance-records"]
    assert out["cleared"] is False
    assert out["refused"] == ["P0001", True], "another error of the write was taken for the marker being there"
    assert out["after_the_refusal"] == []
    assert out["written_once_it_can_be"] is True and out["at_last"] == ["compliance-records"]


UNWRITTEN = PREAMBLE + r'''
from app.core import compliance_marker as marker
from app.core import host_compliance

def marked():
    with engine.connect() as c:
        return [r[0] for r in c.execute(text("SELECT key FROM data_requirements ORDER BY key"))]

out = {}
# A step of compliance access whose own write of the marker gave up: its row committed, no marker.
with engine.begin() as c:
    c.execute(text("INSERT INTO audit_logs (id, action, status, timestamp) VALUES (:id, 'auditor_granted', 'success', "
                   ":t)"), {"id": uuid.uuid4(), "t": now - timedelta(days=1)})
out["before"] = marked()
# Another transaction holds the marker's lock alone meanwhile, as a sync() does.
holder = engine.connect()
tx = holder.begin()
holder.execute(text("SELECT pg_advisory_xact_lock(:c, :k)"), {"c": marker.LOCK[0], "k": marker.LOCK[1]})
with SessionLocal() as s:
    out["blockers"] = [b["key"] for b in host_compliance.downgrade_blockers(s, "0.33.5")]
    out["none_for_this_release"] = host_compliance.downgrade_blockers(s, "0.34.0")
tx.rollback()
holder.close()
out["after"] = marked()
print(json.dumps(out))
'''


def test_downgrade_blockers_write_and_name_the_marker_a_counted_row_was_left_without(throwaway):
    """A counted row committed without its marker (the step's own write gave up), and the marker's lock held alone
    by another transaction: downgrade-blockers still names the records and writes the marker."""
    out = run_in(throwaway, UNWRITTEN)
    assert out["before"] == [], out
    assert out["blockers"] == ["compliance-records"] and out["none_for_this_release"] == [], out
    assert out["after"] == ["compliance-records"], out
