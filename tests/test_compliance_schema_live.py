"""The compliance tables on a running stack's Postgres (app/core/models.py, app/core/case_numbers.py).

The start built every compliance table, the open-grant and open-hold indexes are partial, and the partial
index on audit_logs.case_id was built in the background and is valid. Approvals taking case numbers at the
same moment, one of them rolled back, get distinct numbers with no gap. test_compliance_schema.py checks
the model, the start's statements and the numbers offline.
"""
import json
import time
import uuid

from _account_change_helpers import in_api_container, psql

TABLES = ("auditor_grants", "compliance_cases", "compliance_case_scopes", "compliance_case_vaults",
          "compliance_case_people", "compliance_case_counters", "compliance_exports", "compliance_reveals",
          "compliance_notice_outbox", "legal_hold_vaults", "held_name_history")


def _wait_for(check, timeout=120.0, step=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(step)
    return check()


def test_the_start_built_every_compliance_table():
    found = set(psql("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() "
                     "AND table_name IN (" + ", ".join(f"'{t}'" for t in TABLES) + ")").splitlines())
    assert found == set(TABLES)
    columns = psql("SELECT column_name || ':' || data_type FROM information_schema.columns "
                   "WHERE table_schema = current_schema() AND table_name = 'auditor_grants'").splitlines()
    assert "second_factor_enrollment_id:uuid" in columns
    assert "credential_changers:json" in columns


def test_the_open_grant_and_open_hold_indexes_are_partial():
    rows = dict(line.split("|", 1) for line in psql(
        "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() "
        "AND indexname IN ('uq_auditor_grant_open', 'idx_legal_hold_vault_open')").splitlines())
    assert "CREATE UNIQUE INDEX uq_auditor_grant_open ON" in rows["uq_auditor_grant_open"]
    assert "WHERE ((status)::text = ANY" in rows["uq_auditor_grant_open"]
    assert rows["idx_legal_hold_vault_open"].endswith("WHERE (released_at IS NULL)")


def test_the_case_index_is_built_in_the_background_and_valid():
    assert _wait_for(lambda: psql(
        "SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        "WHERE c.relname = 'ix_audit_logs_case_id' AND i.indisvalid") == "1")
    definition = psql("SELECT indexdef FROM pg_indexes WHERE indexname = 'ix_audit_logs_case_id'")
    assert definition.endswith("USING btree (case_id) WHERE (case_id IS NOT NULL)"), definition


# Approvals in threads of their own, each taking a number in its own transaction and holding it a moment
# before it commits. The first takes its number before the others start and rolls back once they wait on it.
# Prints what each got, and whether it committed.
_CONCURRENT = """
import json, sys, threading, time
from datetime import datetime
from app.core import case_numbers
from app.core.database import SessionLocal
year = int(sys.argv[1])
out = []
lock = threading.Lock()
first_taken = threading.Event()

def approve(i):
    if i:
        first_taken.wait(20)
    db = SessionLocal()
    try:
        number = case_numbers.allocate(db, datetime(year, 6, 1))
        if not i:
            first_taken.set()
            time.sleep(1.0)
            db.rollback()
        else:
            time.sleep(0.15)
            db.commit()
        with lock:
            out.append({"i": i, "number": number, "committed": bool(i)})
    finally:
        db.close()

threads = [threading.Thread(target=approve, args=(i,)) for i in range(12)]
for t in threads:
    t.start()
for t in threads:
    t.join(60)
print("RESULT" + json.dumps(out))
"""


def test_numbers_taken_at_the_same_moment_are_distinct_and_leave_no_gap():
    year = 2900 + uuid.uuid4().int % 90
    psql(f"DELETE FROM compliance_case_counters WHERE year = {year}")
    try:
        r = in_api_container(_CONCURRENT.replace("int(sys.argv[1])", str(year)))
        got = json.loads(r.stdout.split("RESULT", 1)[1])
        assert len(got) == 12
        committed = sorted(x["number"] for x in got if x["committed"])
        assert committed == [f"C-{year}-{n:04d}" for n in range(1, 12)]
        assert psql(f"SELECT last_number FROM compliance_case_counters WHERE year = {year}") == "11"
        rolled_back = [x["number"] for x in got if not x["committed"]]
        assert rolled_back == [f"C-{year}-0001"], "the first approval took the first number, then rolled back"
    finally:
        psql(f"DELETE FROM compliance_case_counters WHERE year = {year}")
