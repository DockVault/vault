"""The SFTP version check while legal holds keep anything, on real Postgres (app/core/legal_holds.py, sftp_while_held),
on a throwaway database of the stack's server: with nothing held nobody is told of an SFTP server of another version;
once a hold keeps a file's old name, every active administrator gets one notice in the app, and asking again the same
day writes no second one. On a database whose kept tables a start skipped, the check fails, and Postgres aborts the
transaction it fails in: the pruner's legal_holds job still commits what it did before the check and still purges.
test_sftp_while_held.py covers the rest offline.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

SCRIPT = PREAMBLE + r'''
from app.core import kept_tables, legal_holds
from app.core.models import HeldNameHistory, Notification, RoleEnum, SftpProcess, User
with SessionLocal() as k:
    kept_tables.install(k)
    k.commit()
db = SessionLocal()
people = {}
for name, role, active in (("cond-admin-1", RoleEnum.ADMIN, True), ("cond-admin-2", RoleEnum.ADMIN, True),
                           ("cond-admin-off", RoleEnum.ADMIN, False), ("cond-user", RoleEnum.USER, True)):
    u = User(id=uuid.uuid4(), username=name, email=name + "@example.com", password_hash="x", role=role,
             is_active=active)
    db.add(u)
    people[str(u.id)] = name
db.add(SftpProcess(id=str(uuid.uuid4()), version="0.33.5-probe", host="probe", started_at=now, seen_at=now))
db.commit()

def notices():
    with SessionLocal() as s:
        return sorted((people.get(str(n.user_id)), n.type, n.title) for n in s.query(Notification).all())

out = {"nothing_held": legal_holds.sftp_while_held(db, now) is None}
out["told_with_nothing_held"] = notices()
db.add(HeldNameHistory(object_id=uuid.uuid4(), vault_id=uuid.uuid4(), kind="file", enc_name="zk2:old",
                       name_key_version=1))
db.commit()
first = legal_holds.sftp_while_held(db, now)
out["answer"] = [first.ok, first.reason, list(first.versions)]
again = legal_holds.sftp_while_held(db, now + timedelta(seconds=30))
out["told"] = notices()
db.close()
print(json.dumps(out))
'''


NO_KEPT_TABLES = PREAMBLE + r'''
from app.core import legal_holds, retention

def lapse_due(session, when):
    session.execute(text("INSERT INTO system_settings (key, value) VALUES ('cond-lapsed', '{}')"))

purged = []
legal_holds.lapse_due = lapse_due
legal_holds.prompt_reviews = lambda session, when: None
legal_holds.purge = lambda *a, **k: purged.append(True)
out = {}
try:
    retention.run_legal_holds(retention.Pass(SessionLocal, now=now))
    out["raised"] = None
except Exception as exc:
    out["raised"] = type(exc).__name__
with engine.connect() as c:
    out["lapsed"] = c.execute(text("SELECT count(*) FROM system_settings WHERE key = 'cond-lapsed'")).scalar()
    out["kept_tables"] = c.execute(text("SELECT to_regclass('held_files') IS NOT NULL")).scalar()
out["purged"] = purged
print(json.dumps(out))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_the_administrators_hear_of_an_sftp_server_of_another_version_while_a_hold_keeps_anything(throwaway):
    out = run_in(throwaway, SCRIPT)
    assert out["nothing_held"] is True and out["told_with_nothing_held"] == []
    assert out["answer"] == [False, "other_version", ["0.33.5-probe"]]
    title = "An SFTP server of another version may be running"
    assert out["told"] == [["cond-admin-1", "legal_hold", title], ["cond-admin-2", "legal_hold", title]]


def test_a_check_that_fails_on_postgres_leaves_the_rest_of_the_pass(throwaway):
    out = run_in(throwaway, NO_KEPT_TABLES)
    assert out["kept_tables"] is False, "a start that skipped the kept tables"
    assert out["raised"] is None and out["lapsed"] == 1 and out["purged"] == [True]
