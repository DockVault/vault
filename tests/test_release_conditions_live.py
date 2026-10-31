"""The detect queries kept for the release commit's upgrade-matrix conditions (tests/_release_conditions.py), run
on real Postgres: on a throwaway database of the stack's server, with the app's schema, each query finds rows only
once rows it is about are seeded, and counts exactly those. The seeded rows sit on each side of every threshold
and each branch alone: audit rows of the days archiving moves when it starts and of the days just after; old
security alerts with a name and an address, a name only, an address only or neither, one a day past 30 days
and one just inside them; invitations ended by acceptance, revocation or expiry 31 days ago and 29 days ago, and
a pending one; reset links, codes and email-change codes used 31 days ago before an expiry still ahead, or
expired, beside ones that ended 29 days ago and live ones; an archived day and a value set in the panel; accounts
with an encryption key whose sign-in details were changed 1 to 13 days ago, the first change an email change (from
an address, or of an account that had none) or another kind, beside accounts without a key (which the hold covers
once they set one up, and which no query can count), a change 15 days ago and changes never applied, counted as
the hold's own code counts them. test_release_conditions.py checks the queries offline.
"""
import json

import pytest

import _release_conditions as rc
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

SCRIPT = PREAMBLE + r'''
from datetime import date
from app.core.models import (AccountInvitation, AuditArchiveBlock, AuditLog, CredentialChange, EmailChangeCode,
                             ManagedSetting, OtpCode, PasswordResetToken, RoleEnum, SecurityAlert, User, UserKeyPair)
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
for days in (120, 100, 77, 76, 75, 10):
    db.add(AuditLog(id=uuid.uuid4(), action="file_upload", status="success", timestamp=ago(days)))

def alert(days, username, ip_address):
    db.add(SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning", message="m",
                         timestamp=ago(days), username=username, ip_address=ip_address, resolved=False, details={}))
for days, username, ip_address in ((40, "someone", "203.0.113.9"), (40, "someone", None), (40, None, "203.0.113.9"),
                                   (40, None, None), (31, "someone", None), (29, "someone", "203.0.113.9"),
                                   (5, "someone", "203.0.113.9")):
    alert(days, username, ip_address)
ahead = now + timedelta(days=1)
for i, (expires, accepted, revoked) in enumerate((
        (ahead, ago(31), None), (ahead, None, ago(31)), (ago(31), None, None),          # ended 31 days ago
        (ahead, ago(29), None), (ahead, None, ago(29)), (ago(29), None, None),          # ended 29 days ago
        (ahead, None, None), (ago(10), None, None))):                                   # pending, ended lately
    db.add(AccountInvitation(id=uuid.uuid4(), username=f"cond-inv-{i}", role="user", token_prefix=f"p{i}",
                             token_hash=uuid.uuid4().hex * 2, expires_at=expires, accepted_at=accepted,
                             revoked_at=revoked))
# Used 31 days ago before an expiry still ahead, or expired 31 days ago; ended 29 days ago; live.
ENDED = ((ahead, ago(31)), (ago(45), None), (ahead, ago(29)), (ago(29), None), (now + timedelta(minutes=10), None))
for i, (expires, consumed) in enumerate(ENDED):
    db.add(PasswordResetToken(id=uuid.uuid4(), user_id=person.id, token_prefix=f"r{i}", token_hash=uuid.uuid4().hex * 2,
                              expires_at=expires, consumed_at=consumed))
    db.add(OtpCode(id=uuid.uuid4(), purpose="cond", user_id=person.id, code_hash=uuid.uuid4().hex * 2, attempts=0,
                   max_attempts=3, expires_at=expires, consumed_at=consumed))
    db.add(EmailChangeCode(id=uuid.uuid4(), user_id=person.id, new_email=f"n{i}@example.com",
                           code_hash=uuid.uuid4().hex * 2, expires_at=expires, consumed_at=consumed))
for part in (0, 1):
    db.add(AuditArchiveBlock(day=date(2026, 1, 2), part=part, first_hour=datetime(2026, 1, 2),
                             last_hour=datetime(2026, 1, 2, 23), row_count=5, codec="zstd", format=1, payload=b"x",
                             raw_bytes=1, aggregates={}, created_at=now))
db.add(AuditArchiveBlock(day=date(2026, 1, 3), part=0, first_hour=datetime(2026, 1, 3),
                         last_hour=datetime(2026, 1, 3, 23), row_count=2, codec="zstd", format=1, payload=b"x",
                         raw_bytes=1, aggregates={}, created_at=now))
db.add(ManagedSetting(key="audit_hot_days", value=120, version=1, updated_at=now))
db.add(ManagedSetting(key="logs_hold", value=None, version=2, updated_at=now))
# Accounts and the changes of their sign-in details: (has a key, [(kind, status, days ago)]).
ACCOUNTS = {
    "password-3-days": (True, [("password", "made", 3)]),                         # held, host only
    "email-then-password": (True, [("email", "made", 5), ("password", "made", 1)]),  # held, the code reaches it
    "email-then-ssh-key": (True, [("email", "made", 8), ("ssh_key", "made", 3)]),    # held, the code reaches it
    "password-then-email": (True, [("password", "made", 6), ("email", "made", 2)]),  # held, host only
    "approved-ssh-key": (True, [("ssh_key", "approved", 10)]),                     # held, host only
    "email-13-days": (True, [("email", "made", 13)]),                              # held, the code reaches it
    "email-to-no-address": (True, [("email", "made", 4)]),                         # held, host only: none before
    "no-key": (False, [("password", "made", 2)]),                                  # not counted, held with a key
    "no-key-15-days": (False, [("password", "made", 15)]),                         # not counted, the hold ended
    "15-days": (True, [("password", "made", 15)]),                                 # the hold has ended
    "held-for-approval": (True, [("password", "held", 1)]),                        # never applied
    "denied": (True, [("reset_link", "denied", 1)]),                               # never applied
}
from app.core import credential_changes as cc, envelope_hold
for name, (key, changes) in ACCOUNTS.items():
    account = User(id=uuid.uuid4(), username="cond-" + name, email=name + "@example.com", password_hash="x",
                   role=RoleEnum.USER, is_active=True)
    db.add(account)
    db.flush()
    if key:
        db.add(UserKeyPair(user_id=account.id, public_key="P", fingerprint="f" * 64, encrypted_private_key="E"))
    for kind, status, days in changes:
        # An applied email change keeps the address before and after, as 0.33.x recorded it.
        payload = None
        if kind == "email" and status in ("made", "approved"):
            before = None if name == "email-to-no-address" else "before-" + name + "@example.com"
            payload = cc.applied_email_payload({"old_email": before, "new_email": name + "@example.com"})
        db.add(CredentialChange(target_user_id=account.id, kind=kind, status=status, requested_by_name="admin",
                                requested_at=ago(days), payload=payload,
                                applied_at=ago(days) if status in ("made", "approved") else None))
db.commit()
# What the code itself says of each account with a key: whether the hold covers it now, and whether a code can be
# sent (envelope_hold.code_destination, which the code route reads).
code = {"held_accounts": 0, "released_only_by_the_host": 0}
# And the accounts without a key the hold covers all the same, which no query can count: held once they set one up.
out["held_once_a_key_is_set_up"] = []
for account in db.query(User).filter(User.username.like("cond-%")).order_by(User.username).all():
    if db.query(UserKeyPair).filter(UserKeyPair.user_id == account.id).first() is None:
        if envelope_hold.holding_changes(db, account.id, now):
            out["held_once_a_key_is_set_up"].append(account.username)
        continue
    if envelope_hold.holding_changes(db, account.id, now):
        code["held_accounts"] += 1
        if not (envelope_hold.code_destination(db, account, now) or "").strip():
            code["released_only_by_the_host"] += 1
out["by_the_code"] = {k: str(v) for k, v in code.items()}
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

    # The rows of the days before the day 76 days ago: 120, 100 and 77 days old, not 76 or 75 days old.
    q = "audit-history-compressed-after-90-days"
    assert _int(after[q], "rows_to_archive") - _int(before[q], "rows_to_archive") == 3
    q = "audit-retention-runs-on-a-timer"
    assert _int(after[q], "audit_rows") - _int(before[q], "audit_rows") == 6 and after[q][0]["oldest"]
    # Older than 30 days with a name and an address, a name only, or an address only, 40 days old and one 31 days
    # old (a day past the threshold); none 29 days old.
    q = "alert-names-and-addresses-cleared-after-30-days"
    assert before[q] == [] and _int(after[q], "alerts") == 4
    # Each table's rows that ended 31 days ago, each way it can end; none of 29 days, none live.
    q = "ended-invitations-and-codes-deleted-after-30-days"
    assert before[q] == []
    assert {k: int(v) for k, v in after[q][0].items()} == {"invitations": 3, "reset_links": 2, "codes": 2,
                                                           "email_codes": 2}
    q = "archived-audit-history-hidden"
    assert before[q] == []
    assert after[q] == [{"days": "2", "rows": "12", "first_day": "2026-01-02", "last_day": "2026-01-03"}]
    q = "panel-retention-not-read"
    assert before[q] == [] and after[q] == [{"key": "audit_hot_days", "value": "120"}]
    # Seven accounts with a key and an applied change in the last 14 days; of them, the three whose first such change
    # was not an email change, and the one whose email change gave it its first address, only the server's operator
    # can release (were the latest change to decide, two whose email change came first would count too, and one
    # whose came last would not): what the hold's own code says of the same accounts.
    q = "zk-envelope-held-after-admin-reset"
    assert before[q] == []
    assert after[q] == [{"held_accounts": "7", "released_only_by_the_host": "4"}]
    assert after[q][0] == out["by_the_code"]
    # The account without a key changed 2 days ago is held as soon as it sets one up; the query does not count it,
    # and the condition's text says so. The one changed 15 days ago is not held.
    assert out["held_once_a_key_is_set_up"] == ["cond-no-key"]
