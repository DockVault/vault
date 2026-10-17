"""The detect queries kept for the release commit's upgrade-matrix conditions (tests/_release_conditions.py), run
on real Postgres: on a throwaway database of the stack's server, with the app's schema, each query finds rows only
once rows it is about are seeded, and counts exactly those. The seeded rows are old audit rows, an old security
alert with a name and an address, ended invitations, reset links and codes beside live ones, an archived day and
a value set in the panel. test_release_conditions.py checks the queries offline.
"""
import json

import pytest

import _release_conditions as rc
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

SCRIPT = PREAMBLE + r'''
from datetime import date
from app.core.models import (AccountInvitation, AuditArchiveBlock, AuditLog, EmailChangeCode, ManagedSetting,
                             OtpCode, PasswordResetToken, RoleEnum, SecurityAlert, User)
QUERIES = json.loads(__QUERIES__)

def run_all():
    out = {}
    with engine.begin() as c:
        for cid, sql in QUERIES.items():
            rows = c.execute(text(sql)).mappings().all()
            out[cid] = [{k: (str(v) if v is not None else None) for k, v in r.items()} for r in rows]
    return out

out = {"before": run_all()}
ago = lambda days: now - timedelta(days=days)
db = SessionLocal()
person = User(id=uuid.uuid4(), username="cond-person", email="cond@example.com", password_hash="x",
              role=RoleEnum.USER, is_active=True)
db.add(person)
db.flush()
for days in (120, 100, 10):
    db.add(AuditLog(id=uuid.uuid4(), action="file_upload", status="success", timestamp=ago(days)))
db.add(SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning", message="m", timestamp=ago(40),
                     username="someone", ip_address="203.0.113.9", resolved=False, details={}))
db.add(SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning", message="m", timestamp=ago(40),
                     resolved=False, details={}))
db.add(SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning", message="m", timestamp=ago(5),
                     username="someone", ip_address="203.0.113.9", resolved=False, details={}))
for i, (expires, accepted) in enumerate(((ago(40), None), (now + timedelta(days=5), ago(31)),
                                         (now + timedelta(days=1), None), (ago(10), None))):
    db.add(AccountInvitation(id=uuid.uuid4(), username=f"cond-inv-{i}", role="user", token_prefix=f"p{i}",
                             token_hash=uuid.uuid4().hex * 2, expires_at=expires, accepted_at=accepted))
for i, (expires, consumed) in enumerate(((ago(40), None), (ago(31) + timedelta(minutes=5), ago(31)),
                                         (now + timedelta(minutes=10), None))):
    db.add(PasswordResetToken(id=uuid.uuid4(), user_id=person.id, token_prefix=f"r{i}", token_hash=uuid.uuid4().hex * 2,
                              expires_at=expires, consumed_at=consumed))
db.add(OtpCode(id=uuid.uuid4(), purpose="cond", user_id=person.id, code_hash="a" * 64, attempts=0, max_attempts=3,
               expires_at=ago(45)))
db.add(OtpCode(id=uuid.uuid4(), purpose="cond", user_id=person.id, code_hash="b" * 64, attempts=0, max_attempts=3,
               expires_at=now + timedelta(minutes=10)))
db.add(EmailChangeCode(id=uuid.uuid4(), user_id=person.id, new_email="n@example.com", code_hash="c" * 64,
                       expires_at=ago(60)))
for part in (0, 1):
    db.add(AuditArchiveBlock(day=date(2026, 1, 2), part=part, first_hour=datetime(2026, 1, 2),
                             last_hour=datetime(2026, 1, 2, 23), row_count=5, codec="zstd", format=1, payload=b"x",
                             raw_bytes=1, aggregates={}, created_at=now))
db.add(AuditArchiveBlock(day=date(2026, 1, 3), part=0, first_hour=datetime(2026, 1, 3),
                         last_hour=datetime(2026, 1, 3, 23), row_count=2, codec="zstd", format=1, payload=b"x",
                         raw_bytes=1, aggregates={}, created_at=now))
db.add(ManagedSetting(key="audit_hot_days", value=120, version=1, updated_at=now))
db.add(ManagedSetting(key="logs_hold", value=None, version=2, updated_at=now))
db.commit()
db.close()
out["after"] = run_all()
print(json.dumps(out))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def _int(rows, column):
    return int(rows[0][column]) if rows else 0


def test_each_detect_query_finds_what_was_seeded_and_only_that(throwaway):
    out = run_in(throwaway, SCRIPT.replace("__QUERIES__", repr(json.dumps(rc.DETECT))))
    before, after = out["before"], out["after"]
    assert set(before) == set(after) == set(rc.DETECT)

    q = "audit-history-compressed-after-90-days"
    assert _int(after[q], "rows_to_archive") - _int(before[q], "rows_to_archive") == 2
    q = "audit-retention-runs-on-a-timer"
    assert _int(after[q], "audit_rows") - _int(before[q], "audit_rows") == 3 and after[q][0]["oldest"]
    q = "alert-names-and-addresses-cleared-after-30-days"
    assert before[q] == [] and _int(after[q], "alerts") == 1
    q = "ended-invitations-and-codes-deleted-after-30-days"
    assert before[q] == []
    assert {k: int(v) for k, v in after[q][0].items()} == {"invitations": 2, "reset_links": 2, "codes": 1,
                                                           "email_codes": 1}
    q = "archived-audit-history-hidden"
    assert before[q] == []
    assert after[q] == [{"days": "2", "rows": "12", "first_day": "2026-01-02", "last_day": "2026-01-03"}]
    q = "panel-retention-not-read"
    assert before[q] == [] and after[q] == [{"key": "audit_hot_days", "value": "120"}]
