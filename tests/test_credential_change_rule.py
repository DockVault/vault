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
from app.core.models import AdminGrant, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'changes.db'}")
        User.__table__.create(engine)
        CredentialChange.__table__.create(engine)
        AdminGrant.__table__.create(engine)
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
    dave = _user(db, RoleEnum.ADMIN)       # who may approve bob's: alice made the first change
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


def test_a_second_change_asked_for_by_someone_who_is_not_an_administrator_is_refused_not_held(db):
    # A user given the permission to manage users may make the first change to an ordinary user's
    # account. A second one used to be held, and could never be approved: an approval needs the one who
    # asked to be an administrator who can act. It is refused when asked for instead, while bob could
    # still approve the same second change asked for by an administrator.
    alice, _bob, dana, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db), _user(db)
    assert cc.decide(db, requester_id=dana.id, target_id=carol.id) is None, "the first change is made"
    first = _made(db, carol, dana)
    db.commit()
    with pytest.raises(cc.NotAnAdministrator) as refused:
        cc.decide(db, requester_id=dana.id, target_id=carol.id)
    assert refused.value.last_change.id == first.id
    assert cc.decide(db, requester_id=alice.id, target_id=carol.id).id == first.id, "an administrator's is held"


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
    _user(db, RoleEnum.ADMIN)              # who may approve bob's: alice asked, bob approved
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
        AdminGrant.__table__.create(engine)
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


# --------------------------------------------------------------------------- who may approve

def _grant(db, user, by, now=None):
    from app.core import admin_grants
    admin_grants.record(db, user.id, granted_by_id=by.id if by is not None else None,
                        granted_by_name=by.username if by is not None else cc.HOST_OPERATOR, now=now)
    db.commit()


def _held_by(db, requester, target, now=None):
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=target.id, requester_id=requester.id,
                     requester_name=requester.username, summary="s", payload={"delivery": "copy"}, now=now)
    db.commit()
    return change


def test_an_administrator_the_requester_made_cannot_approve(db):
    # The review's scenario: one administrator makes a second administrator account and approves their
    # own held change with it. Made before the request or after, directly or through another one.
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    puppet, grandchild = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN)
    _grant(db, puppet, alice, now=now - timedelta(days=30))
    _grant(db, grandchild, puppet, now=now - timedelta(days=29))
    change = _held_by(db, alice, carol, now=now)
    assert cc.approval_refusal(db, change, puppet.id) == cc.MADE_BY_REQUESTER
    assert cc.approval_refusal(db, change, grandchild.id) == cc.MADE_BY_REQUESTER
    assert cc.approval_refusal(db, change, alice.id) == cc.ASKED
    assert cc.approval_refusal(db, change, bob.id) is None, "an administrator alice did not make may"
    assert cc.approval_refusal(db, change, None) is None, "the host operator may approve any"
    assert [a.id for a in cc.approvers(db, alice.id, change)] == [bob.id]


def test_an_administrator_made_after_the_request_cannot_approve_it(db):
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    change = _held_by(db, alice, carol, now=now - timedelta(hours=1))
    late = _user(db, RoleEnum.ADMIN)
    _grant(db, late, bob, now=now)                      # made by someone else, but after the request
    assert cc.approval_refusal(db, change, late.id) == cc.BECAME_ADMIN_AFTER
    early = _user(db, RoleEnum.ADMIN)
    _grant(db, early, bob, now=now - timedelta(days=15))
    assert cc.approval_refusal(db, change, early.id) is None
    assert {a.id for a in cc.approvers(db, alice.id, change)} == {bob.id, early.id}


def test_an_approver_must_have_been_an_administrator_for_fourteen_days_before_the_request(db):
    # Rule 4. Closes an administrator made for the purpose by someone the lineage does not lead to.
    alice, bob, carol = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    change = _held_by(db, alice, carol, now=now)
    for days, reason in ((13, cc.NEW_ADMIN), (15, None)):
        x = _user(db, RoleEnum.ADMIN)
        _grant(db, x, bob, now=now - timedelta(days=days))
        assert cc.approval_refusal(db, change, x.id) == reason, days
    # Measured to the request, not to the approval: made 13 days before it, 20 days before now.
    older = _held_by(db, alice, carol, now=now - timedelta(days=7))
    y = _user(db, RoleEnum.ADMIN)
    _grant(db, y, bob, now=now - timedelta(days=20))
    assert cc.approval_refusal(db, older, y.id) == cc.NEW_ADMIN
    # An administrator from before the records existed, and the first one, have no record: long-standing.
    assert cc.approval_refusal(db, change, bob.id) is None


def test_the_administrator_who_made_the_first_change_cannot_approve_the_second(db):
    # Rule 2, the mirror: alice makes the first change and an administrator account, asks for the
    # second as that account and approves it as herself. Also an administrator she did not make.
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    _made(db, carol, alice, now=now - timedelta(days=1))
    db.commit()
    puppet, independent = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN)
    _grant(db, puppet, alice, now=now - timedelta(days=30))
    _grant(db, independent, None, now=now - timedelta(days=30))
    for asker in (puppet, independent):
        change = _held_by(db, asker, carol, now=now)
        expected = cc.MADE_REQUESTER if asker is puppet else cc.CHANGED_ACCOUNT
        assert cc.approval_refusal(db, change, alice.id) == expected, asker.username
    # Who approved an earlier held change made it too; so is one made 14 days before the request.
    dave, erin = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN)
    held = _held_by(db, independent, carol, now=now - timedelta(days=3))
    cc.approve(held, approver_id=dave.id, approver_name=dave.username, now=now - timedelta(days=2))
    db.commit()
    change = _held_by(db, independent, carol, now=now)
    assert cc.approval_refusal(db, change, dave.id) == cc.CHANGED_ACCOUNT
    assert cc.approval_refusal(db, change, erin.id) is None
    assert cc.approval_refusal(db, change, alice.id) == cc.CHANGED_ACCOUNT
    old = _user(db)
    _made(db, old, alice, now=now - timedelta(days=15))
    db.commit()
    assert cc.approval_refusal(db, _held_by(db, independent, old, now=now), alice.id) is None


def test_the_mirror_is_refused_outright_when_nobody_else_may_approve(db):
    # The review's first bypass: alice, the only real administrator, makes the first change and an
    # administrator account; the second change asked for as that account had alice as its approver.
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    puppet = _user(db, RoleEnum.ADMIN, username="puppet")
    _grant(db, puppet, alice, now=now - timedelta(days=30))
    _made(db, carol, alice, now=now - timedelta(hours=1))
    db.commit()
    with pytest.raises(cc.NoApprover) as refused:
        cc.decide(db, requester_id=puppet.id, target_id=carol.id, now=now)
    assert refused.value.refusals == [(alice.username, cc.MADE_REQUESTER)]


def test_neither_may_be_in_the_others_lineage(db):
    # Rule 3, both ways: an administrator the asker made, and the administrator who made the asker.
    root, carol = _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    mid, leaf = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN)
    _grant(db, mid, root, now=now - timedelta(days=40))
    _grant(db, leaf, mid, now=now - timedelta(days=30))
    by_leaf = _held_by(db, leaf, carol, now=now)
    assert cc.approval_refusal(db, by_leaf, mid.id) == cc.MADE_REQUESTER
    assert cc.approval_refusal(db, by_leaf, root.id) == cc.MADE_REQUESTER
    by_root = _held_by(db, root, carol, now=now)
    assert cc.approval_refusal(db, by_root, leaf.id) == cc.MADE_BY_REQUESTER


def test_siblings_made_for_the_purpose_cannot_approve_each_other_for_fourteen_days(db):
    # The review's second bypass: alice makes P1 and P2; P2 asks and P1 approves. Neither is in the
    # other's lineage, so rule 4 is what refuses it. After 14 days it is the accepted residual: every
    # administrator was told of each new one, and the user of every change.
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    now = cc.utcnow()
    p1, p2 = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN)
    _grant(db, p1, alice, now=now - timedelta(days=1))
    _grant(db, p2, alice, now=now - timedelta(days=1))
    assert cc.approval_refusal(db, _held_by(db, p2, carol, now=now), p1.id) == cc.NEW_ADMIN
    later = now + timedelta(days=15)
    assert cc.approval_refusal(db, _held_by(db, p2, carol, now=later), p1.id, now=later) is None


def test_a_second_change_nobody_may_approve_carries_why_each_may_not(db):
    alice, carol = _user(db, RoleEnum.ADMIN, username="alice"), _user(db)
    now = cc.utcnow()
    made = _user(db, RoleEnum.ADMIN, username="made")
    _grant(db, made, alice, now=now - timedelta(days=30))
    fresh = _user(db, RoleEnum.ADMIN, username="fresh")
    _grant(db, fresh, None, now=now - timedelta(days=2))
    changer = _user(db, RoleEnum.ADMIN, username="changer")
    _user(db, RoleEnum.ADMIN, username="locked", is_locked=True, locked_until=None)
    _made(db, carol, changer, now=now - timedelta(days=1))
    db.commit()
    with pytest.raises(cc.NoApprover) as refused:
        cc.decide(db, requester_id=alice.id, target_id=carol.id, now=now)
    assert refused.value.refusals == [("changer", cc.CHANGED_ACCOUNT), ("fresh", cc.NEW_ADMIN),
                                      ("made", cc.MADE_BY_REQUESTER)], "an administrator's lock is left out"


def test_one_administrator_with_accounts_they_made_is_refused_a_second_change(db):
    # A deployment with one real administrator stays unable to approve its own second change: only the
    # host operator can make it. Accounts that administrator made do not count as another.
    alice, carol = _user(db, RoleEnum.ADMIN), _user(db)
    for _ in range(2):
        _grant(db, _user(db, RoleEnum.ADMIN), alice)
    _made(db, carol, alice)
    db.commit()
    with pytest.raises(cc.NoApprover):
        cc.decide(db, requester_id=alice.id, target_id=carol.id)


def test_a_demotion_forgets_who_made_the_administrator(db):
    from app.core import admin_grants
    alice, bob, carol, x = _user(db, RoleEnum.ADMIN), _user(db, RoleEnum.ADMIN), _user(db), _user(db, RoleEnum.ADMIN)
    now = cc.utcnow()
    _grant(db, x, alice, now=now - timedelta(days=30))
    admin_grants.forget(db, x.id)
    db.commit()
    _grant(db, x, bob, now=now - timedelta(days=20))    # made one again, by bob this time
    change = _held_by(db, alice, carol, now=now)
    assert cc.approval_refusal(db, change, x.id) is None
    assert admin_grants.of(db, [x.id])[x.id].lineage == [str(bob.id)]
