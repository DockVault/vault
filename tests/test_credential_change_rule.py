"""The rule on administrators' changes to someone else's sign-in credentials, on a real database.

One change to an account may be made within 14 days. A second change in that window, by the same
administrator or any other, is held for a DIFFERENT administrator to approve and expires after 7 days;
with nobody else to approve it, it is refused. The host operator is the way round the rule. These run
app/core/credential_changes.py against the real users and credential_changes tables in a throwaway
SQLite database. test_credential_change_rule_live.py drives the same through every route on a
running stack.
"""
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import credential_changes as cc  # noqa: E402
from app.core.models import CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'changes.db'}")
        User.__table__.create(engine)
        CredentialChange.__table__.create(engine)
        # The application's own session flags: nothing is flushed before a query unless asked.
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, role=RoleEnum.USER, **kw):
    u = User(username=kw.pop("username", f"u_{uuid.uuid4().hex[:8]}"), password_hash="x", role=role,
             is_active=kw.pop("is_active", True), is_locked=kw.pop("is_locked", False), **kw)
    db.add(u)
    db.commit()
    return u


def _made(db, target, requester, kind=cc.PASSWORD, now=None):
    return cc.record_made(db, kind=kind, target_id=target.id, requester_id=requester.id,
                          requester_name=requester.username, now=now)


def test_the_first_change_in_the_window_may_be_made(db):
    alice, _bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    assert cc.decide(db, requester_id=alice.id, target_id=carol.id) is None


@pytest.mark.parametrize("kind", [cc.PASSWORD, cc.RESET_LINK, cc.SECOND_FACTOR, cc.EMAIL, cc.SSH_KEY])
def test_a_second_change_of_any_kind_is_held_by_anyone(db, kind):
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    first = _made(db, carol, alice, kind=kind)
    db.commit()
    # The same administrator, and a different one: both are the second change to this account.
    assert cc.decide(db, requester_id=alice.id, target_id=carol.id).id == first.id
    assert cc.decide(db, requester_id=bob.id, target_id=carol.id).id == first.id


def test_a_change_in_the_same_request_counts_before_the_commit(db):
    # An address and a password saved together are two changes. The sessions here do not flush before
    # a query on their own, so the first must be written when it is recorded or the second is made too.
    alice, _bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    first = _made(db, carol, alice, kind=cc.EMAIL)
    assert cc.decide(db, requester_id=alice.id, target_id=carol.id).id == first.id


def test_the_window_is_fourteen_days(db):
    alice, _bob, carol, dave = (_user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db), _user(db))
    now = cc.utcnow()
    _made(db, carol, alice, now=now - timedelta(days=14, minutes=1))
    _made(db, dave, alice, now=now - timedelta(days=13, hours=23))
    db.commit()
    assert cc.decide(db, requester_id=alice.id, target_id=carol.id, now=now) is None
    assert cc.decide(db, requester_id=alice.id, target_id=dave.id, now=now) is not None
    assert cc.window_ends(cc.last_applied(db, dave.id, now)) > now


def test_only_changes_that_took_effect_open_the_window(db):
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    for status in (cc.DENIED, cc.WITHDRAWN, cc.EXPIRED):
        held = cc.hold(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id,
                       requester_name=alice.username, summary="s", payload={"email": "x@example.com"})
        cc.deny(held, decider_id=bob.id, decider_name=bob.username)
        held.status = status
    db.commit()
    assert cc.decide(db, requester_id=alice.id, target_id=carol.id) is None


def test_with_nobody_else_to_approve_the_second_change_is_refused(db):
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    # Administrators who could not approve: deactivated, or locked by an administrator.
    _user(db, RoleEnum.ADMIN, is_active=False)
    _user(db, RoleEnum.ADMIN, is_locked=True, locked_until=None)
    first = _made(db, carol, alice)
    db.commit()
    with pytest.raises(cc.NoApprover) as refused:
        cc.decide(db, requester_id=alice.id, target_id=carol.id)
    assert refused.value.last_change.id == first.id


def test_a_lock_that_runs_out_does_not_stop_an_administrator_approving(db):
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    timed = _user(db, RoleEnum.ADMIN, is_locked=True, locked_until=cc.utcnow() + timedelta(minutes=10))
    assert [a.id for a in cc.approvers(db, alice.id)] == [timed.id]


def test_the_host_operator_is_never_held(db):
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    _made(db, carol, alice)
    db.commit()
    assert cc.decide(db, requester_id=None, target_id=carol.id) is None


def test_the_administrator_who_asked_cannot_approve(db):
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    held = cc.hold(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id,
                   requester_name=alice.username, summary="s", payload={"password_hash": "h"})
    assert not cc.may_approve(held, alice.id)
    assert cc.may_approve(held, bob.id)
    assert cc.may_approve(held, None), "the host operator may approve any request"


def test_a_decision_clears_what_the_request_held(db):
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    approved = cc.hold(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id,
                       requester_name=alice.username, summary="s", payload={"password_hash": "h"})
    cc.approve(approved, approver_id=bob.id, approver_name=bob.username)
    assert (approved.status, approved.payload, approved.decided_by_name) == (cc.APPROVED, None, bob.username)
    assert approved.applied_at is not None, "an approved change took effect, so it opens the window"

    denied = cc.hold(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id,
                     requester_name=alice.username, summary="s", payload={"email": "x@example.com"})
    assert cc.deny(denied, decider_id=bob.id, decider_name=bob.username) == cc.DENIED
    assert denied.payload is None and denied.applied_at is None

    withdrawn = cc.hold(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id,
                        requester_name=alice.username, summary="s", payload={"email": "y@example.com"})
    assert cc.deny(withdrawn, decider_id=alice.id, decider_name=alice.username) == cc.WITHDRAWN
    db.commit()
    # Gone from the table too, not kept as a JSON null.
    stored = db.execute(sa.text("SELECT count(*) FROM credential_changes WHERE payload IS NOT NULL")).scalar()
    assert stored == 0


def test_a_held_request_expires_after_seven_days(db):
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    old = cc.hold(db, kind=cc.SSH_KEY, target_id=carol.id, requester_id=alice.id,
                  requester_name=alice.username, summary="s", payload={"fingerprint": "f"},
                  now=now - timedelta(days=7, seconds=1))
    fresh = cc.hold(db, kind=cc.SSH_KEY, target_id=carol.id, requester_id=alice.id,
                    requester_name=alice.username, summary="s", payload={"fingerprint": "g"},
                    now=now - timedelta(days=6, hours=23))
    db.commit()
    assert fresh.expires_at - fresh.requested_at == timedelta(days=7)
    assert not cc.is_open(old, now) and cc.is_open(fresh, now)
    assert [c.id for c in cc.open_requests(db, now)] == [fresh.id]

    expired = cc.expire_due(db, now)
    assert [c.id for c in expired] == [old.id]
    assert (old.status, old.payload) == (cc.EXPIRED, None)
    assert fresh.status == cc.HELD and fresh.payload == {"fingerprint": "g"}
    db.commit()
    assert cc.expire_due(db, now) == [], "an expired request is not expired twice"


def test_recent_by_account_gives_each_account_its_newest_change(db):
    alice, carol, dave, erin = _user(db, RoleEnum.ADMIN), _user(db), _user(db), _user(db)
    now = cc.utcnow()
    _made(db, carol, alice, kind=cc.EMAIL, now=now - timedelta(days=3))
    newest = _made(db, carol, alice, kind=cc.SSH_KEY, now=now - timedelta(days=1))
    _made(db, dave, alice, now=now - timedelta(days=20))
    db.commit()
    recent = cc.recent_by_account(db, [carol.id, dave.id, erin.id], now)
    assert set(recent) == {carol.id}
    assert recent[carol.id].id == newest.id


def test_a_waiting_change_is_named_by_what_it_asks_for():
    assert cc.request_label(cc.SSH_KEY) == "Add an SSH key"
    assert cc.label(cc.SSH_KEY) == "SSH key added"
    assert {cc.request_label(k) for k in cc.KIND_LABELS} == {
        "Set a new password", "Create a password reset link", "Reset the second factor",
        "Change the email address", "Add an SSH key"}


def test_the_host_operator_name_cannot_be_a_username():
    # The records name the host operator by a string no account can carry.
    from app.api.api_server import _validate_new_username
    with pytest.raises(ValueError):
        _validate_new_username(cc.HOST_OPERATOR)



def test_records_nothing_reads_any_more_are_pruned_after_fourteen_days(db):
    # A change applied, or a request decided, more than 14 days ago is read by nothing, and its summary
    # names an address or a key that may never have been applied. The audit log keeps the history.
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    old, recent = now - timedelta(days=14, seconds=1), now - timedelta(days=13, hours=23)

    def held(at, summary):
        return cc.hold(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id,
                       requester_name=alice.username, summary=summary, payload={"email": "x@example.com"},
                       now=at - timedelta(days=1))

    keep, gone = [], []
    gone.append(_made(db, carol, alice, now=old))
    keep.append(_made(db, carol, alice, now=recent))
    approved_old, approved_recent = held(old, "approved old"), held(recent, "approved recent")
    cc.approve(approved_old, approver_id=bob.id, approver_name=bob.username, now=old)
    cc.approve(approved_recent, approver_id=bob.id, approver_name=bob.username, now=recent)
    gone.append(approved_old)
    keep.append(approved_recent)
    for decide_by in (bob, alice):     # denied by another, withdrawn by the one who asked
        o, r = held(old, "decided old"), held(recent, "decided recent")
        cc.deny(o, decider_id=decide_by.id, decider_name=decide_by.username, now=old)
        cc.deny(r, decider_id=decide_by.id, decider_name=decide_by.username, now=recent)
        gone.append(o)
        keep.append(r)
    expired_old = held(old - timedelta(days=6), "expired old")
    cc.expire_due(db, old)
    gone.append(expired_old)
    still_open = cc.hold(db, kind=cc.SSH_KEY, target_id=carol.id, requester_id=alice.id,
                         requester_name=alice.username, summary="open", payload={"fingerprint": "f"},
                         now=now - timedelta(days=1))
    keep.append(still_open)
    db.commit()
    keep_ids, gone_ids = [c.id for c in keep], [c.id for c in gone]
    assert expired_old.status == cc.EXPIRED

    assert cc.prune_done(db, now) == len(gone_ids)
    db.commit()
    left = {row[0] for row in db.query(CredentialChange.id).all()}
    assert left == set(keep_ids)
    assert cc.prune_done(db, now) == 0


def test_the_periodic_cleanup_prunes_the_records():
    # The cleanup loop cannot run offline (it sleeps five minutes first); pin that it calls the prune,
    # once, inside the loop that expires held requests.
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index("async def cleanup_expired_sessions(")
    ends = [i for i in (src.find("\ndef ", start + 1), src.find("\nasync def ", start + 1)) if i > 0]
    body = src[start:min(ends)]
    assert body.count(".prune_done(db)") == 1
    assert body.index("_expire_held_credential_changes(db)") < body.index(".prune_done(db)")


def test_an_approved_change_opens_a_new_window_from_its_approval(db):
    # A held change took effect when it was approved, so the 14 days run from then: a change asked for
    # after the first one's window closed still waits, because the approved one opened another.
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    first = _made(db, carol, alice, now=now - timedelta(days=13))
    held = cc.hold(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id,
                   requester_name=alice.username, summary="s", payload={"email": "x@example.com"},
                   now=now - timedelta(days=2))
    cc.approve(held, approver_id=bob.id, approver_name=bob.username, now=now - timedelta(days=1))
    db.commit()
    later = now + timedelta(days=5)          # 18 days after the first change, 6 after the approval
    assert cc.window_ends(first) < later
    assert cc.last_applied(db, carol.id, later).id == held.id
    assert cc.decide(db, requester_id=bob.id, target_id=carol.id, now=later).id == held.id
    assert cc.recent_by_account(db, [carol.id], later)[carol.id].id == held.id


@pytest.fixture
def two_sessions():
    """Two sessions on one database: two administrators deciding at the same moment."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'race.db'}")
        User.__table__.create(engine)
        CredentialChange.__table__.create(engine)
        factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        first, second = factory(), factory()
        yield first, second
        first.close()
        second.close()
        engine.dispose()


def _held_in(session):
    alice, bob, dave, carol = (_user(session, RoleEnum.ADMIN), _user(session, RoleEnum.ADMIN),
                               _user(session, RoleEnum.ADMIN), _user(session))
    held = cc.hold(session, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id,
                   requester_name=alice.username, summary="s", payload={"delivery": "copy"})
    session.commit()
    return held.id, bob, dave


def test_only_one_of_two_approvals_claims_a_request(two_sessions):
    # Both read the request while it was held. The first claims it and commits (as minting a reset link
    # does part-way through an approval); the second, holding its stale copy, claims nothing.
    s1, s2 = two_sessions
    change_id, bob, dave = _held_in(s1)
    mine = s1.get(CredentialChange, change_id)
    theirs = s2.get(CredentialChange, change_id)
    assert mine.status == theirs.status == cc.HELD
    assert cc.claim_approval(s1, mine, approver_id=bob.id, approver_name=bob.username) is True
    assert (mine.status, mine.payload, mine.decided_by_name) == (cc.APPROVED, None, bob.username)
    assert mine.applied_at is not None
    s1.commit()
    assert cc.claim_approval(s2, theirs, approver_id=dave.id, approver_name=dave.username) is False
    s2.rollback()
    row = s2.get(CredentialChange, change_id)
    assert (row.status, row.decided_by_name) == (cc.APPROVED, bob.username)


def test_an_expired_or_decided_request_cannot_be_claimed(db):
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    old = cc.hold(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id, requester_name=alice.username,
                  summary="s", payload={"password_hash": "h"}, now=now - timedelta(days=8))
    denied = cc.hold(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id, requester_name=alice.username,
                     summary="s", payload={"password_hash": "h"}, now=now)
    cc.deny(denied, decider_id=bob.id, decider_name=bob.username, now=now)
    db.commit()
    assert cc.claim_approval(db, old, approver_id=bob.id, approver_name=bob.username, now=now) is False
    assert cc.claim_approval(db, denied, approver_id=bob.id, approver_name=bob.username, now=now) is False
    db.rollback()
    assert (old.status, denied.status) == (cc.HELD, cc.DENIED)
