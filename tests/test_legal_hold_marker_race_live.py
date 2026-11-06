"""The legal holds' rollback marker when two transactions write it at once, on a running stack's Postgres (a throwaway
database of its own, tests/_throwaway_db.py): app/core/legal_hold_marker.py sync.

At READ COMMITTED a removal that waits for the row's lock checks again only that row, not the holds. So:

- The purge's last transaction finds no hold and no kept row while a placing has refreshed the marker and not yet
  committed: the purge waits for the placing, then sees its hold, and the marker stays.
- No marker, and two placings write it at once: the second waits for the first, and neither fails on the key.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration


@pytest.fixture
def db_name():
    yield from throwaway_database()


SCENARIO = PREAMBLE + r'''
import threading, time
from sqlalchemy import text as sql
from app.core import legal_hold_marker as marker, legal_holds
from app.core.models import ComplianceCase, LegalHoldVault, RoleEnum, User
out = {}
with SessionLocal() as s:
    # The detect query reads the three kept tables; only their rows matter here.
    for table in ("held_files", "held_folders", "held_name_history"):
        s.execute(sql(f"CREATE TABLE IF NOT EXISTS {table} (id uuid)"))
    auditor = User(id=uuid.uuid4(), username="aud-" + uuid.uuid4().hex[:6], email=None, password_hash="x",
                   role=RoleEnum.USER, is_active=True)
    s.add(auditor)
    s.flush()
    case = ComplianceCase(id=uuid.uuid4(), status="hold_only", purpose="litigation_hold", legal_basis="c",
                          justification_enc="x", owner_note_enc="x", auditor_id=auditor.id,
                          auditor_username=auditor.username)
    s.add(case)
    s.commit()
    case_id = case.id


def hold(db):
    db.add(LegalHoldVault(case_id=case_id, vault_id=uuid.uuid4(), placed_by_username="ada", placed_at=now))


def marker_rows():
    with SessionLocal() as s:
        return s.execute(sql("SELECT count(*) FROM data_requirements WHERE key = 'legal-holds'")).scalar()


# The marker of holds that are all gone, as the purge's last transaction finds it: nothing held, nothing kept.
with SessionLocal() as s:
    hold(s)
    marker.sync(s)
    s.commit()
    s.execute(sql("DELETE FROM legal_hold_vaults"))
    s.commit()
out["before"] = marker_rows()


def purge_sync(result):
    db = SessionLocal()
    try:
        t0 = time.monotonic()
        result["purge_says"] = marker.sync(db)
        db.commit()
        result["purge_seconds"] = round(time.monotonic() - t0, 2)
    except Exception as exc:
        db.rollback()
        result["purge_says"] = type(exc).__name__
    finally:
        db.close()


# A placing refreshed the marker (its row locked until the placing commits); the purge syncs meanwhile.
placing = SessionLocal()
legal_holds.take_turn(placing, shared=False)
hold(placing)
marker.sync(placing)
t = threading.Thread(target=purge_sync, args=(out,))
t.start()
time.sleep(2.0)
out["purge_waited"] = t.is_alive()
placing.commit()
placing.close()
t.join(20)
out["after_the_purge"] = marker_rows()

# No marker, and two placings write it at once.
with SessionLocal() as s:
    s.execute(sql("DELETE FROM data_requirements WHERE key = 'legal-holds'"))
    s.commit()
first = SessionLocal()
hold(first)
marker.sync(first)


def second_writer(result):
    db = SessionLocal()
    try:
        hold(db)
        marker.sync(db)
        db.commit()
        result["second"] = "ok"
    except Exception as exc:
        db.rollback()
        result["second"] = type(exc).__name__
    finally:
        db.close()


t = threading.Thread(target=second_writer, args=(out,))
t.start()
time.sleep(2.0)
out["second_waited"] = t.is_alive()
first.commit()
first.close()
t.join(20)
out["after_two_writers"] = marker_rows()
print(json.dumps(out))
'''


def test_the_marker_stays_when_the_purge_meets_a_placing_and_two_first_writers_both_write_it(db_name):
    out = run_in(db_name, SCENARIO)
    assert out["before"] == 1, out
    assert out["purge_waited"] is True and out["purge_seconds"] >= 1.5, out
    assert out["purge_says"] is True, out
    assert out["after_the_purge"] == 1, out
    assert out["second_waited"] is True and out["second"] == "ok", out
    assert out["after_two_writers"] == 1, out
