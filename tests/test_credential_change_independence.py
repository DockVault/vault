"""Who may approve a held credential change, when the records it was held under have changed since, offline
on a real database.

An approval is refused unless the approver is independent of the change (app/core/credential_changes.py).
That used to be read only from the records as they stood at approval time, so:
  * demoting the administrator who asked deleted their lineage, and deleting them deleted it and their
    name on the account's earlier change: the administrator who made them could then approve;
  * the person the change was for counted as an approver of it, so with two administrators one could
    make an administrator account, ask as it, and approve through a demotion;
  * a lineage was cut at 64 administrators, so the end of a longer chain no longer led back to its
    start.

Now the held row keeps what the rule read when it was held, and an approval is checked against that and
the records as they stand; a request whose asker is no longer an active administrator is never approved,
and every route that demotes, deactivates, locks or deletes an administrator withdraws their open requests;
and the person a change is for never approves it. test_credential_change_rule_live.py drives the routes on
a running stack.
"""
import ast
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core.models import AccountInvitation, AdminGrant, AuditLog, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit

APP = Path(__file__).resolve().parent.parent / "app"


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'independence.db'}")
        for model in (User, AdminGrant, CredentialChange, AuditLog, AccountInvitation):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role=RoleEnum.ADMIN):
    u = User(username=name, email=None, password_hash="x", role=role, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def approve(db, monkeypatch):
    """The real approve route, its step-up stubbed and the change's application recorded instead of made.
    Returns (approve(change_id, as_user), what was applied)."""
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    applied = []

    def fake_apply(db_, change, target, *, approver, request=None):
        applied.append((change.id, approver.username))
        return {"reset_link": "https://vault.example.com/?reset=x"}

    monkeypatch.setattr(api, "_approve_credential_change", fake_apply)

    def run(change_id, user):
        return run_coroutine(api.approve_credential_request(
            change_id=change_id, request=SimpleNamespace(headers={}, client=None), current_user=user, db=db))

    return run, applied


def _puppet_request(db, target=None):
    """alice and bob are long-standing administrators. alice makes the administrator p now. p makes the
    first change to the account (free: the first in the window) and asks for the second, which is held
    because bob may approve it. Returns (alice, bob, target, p, the held change)."""
    alice, bob = _user(db, "alice"), _user(db, "bob")
    target = target or _user(db, "carol", role=RoleEnum.USER)
    p = _user(db, "puppet")
    api._record_admin_grant(db, p, by=alice)
    db.commit()
    assert cc.decide(db, requester_id=p.id, target_id=target.id) is None
    cc.record_made(db, kind=cc.EMAIL, target_id=target.id, requester_id=p.id, requester_name="puppet")
    db.commit()
    assert cc.decide(db, requester_id=p.id, target_id=target.id) is not None, "held: bob may approve"
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=target.id, requester_id=p.id, requester_name="puppet",
                     summary="s", payload={"delivery": "copy"})
    db.commit()
    assert cc.approval_refusal(db, change, alice.id) == cc.MADE_REQUESTER
    assert [a.username for a in cc.approvers(db, p.id, change)] == ["bob"]
    return alice, bob, target, p, change


def _refused(approve_run, change_id, user):
    with pytest.raises(HTTPException) as refused:
        approve_run(change_id, user)
    return refused.value


# --------------------------------------------------------------------------- the one who asked is gone

def test_demoting_the_asker_does_not_let_their_maker_approve(db, approve):
    run, applied = approve
    alice, bob, _carol, p, change = _puppet_request(db)
    admin_grants.forget(db, p.id)                   # what a demotion does to the records
    p.role = RoleEnum.USER
    db.commit()
    for who in (alice, bob):
        refused = _refused(run, change.id, who)
        assert refused.status_code == 403 and "is not an active administrator" in refused.detail, refused.detail
    assert applied == []
    assert db.get(CredentialChange, change.id).status == cc.HELD
    reasons = [r.details["reason"] for r in db.query(AuditLog)
               .filter(AuditLog.action == "credential_change_approval_refused").all()]
    assert reasons == [cc.REQUESTER_GONE, cc.REQUESTER_GONE]


@pytest.mark.parametrize("how", ["deactivated", "locked"])
def test_a_deactivated_or_locked_asker_has_nothing_approved(db, approve, how):
    run, applied = approve
    _alice, bob, _carol, p, change = _puppet_request(db)
    if how == "deactivated":
        p.is_active = False
    else:
        p.is_locked, p.locked_until = True, None    # an administrator's lock
    db.commit()
    assert _refused(run, change.id, bob).status_code == 403
    assert applied == []


def test_a_lock_that_wrong_passwords_armed_leaves_the_asker_able(db, approve):
    # A timed lock runs out by itself: the asker is still an administrator who can act.
    run, applied = approve
    _alice, bob, _carol, p, change = _puppet_request(db)
    p.is_locked, p.locked_until = True, cc.utcnow() + timedelta(minutes=10)
    db.commit()
    run(change.id, bob)
    assert applied == [(change.id, "bob")]


def test_deleting_the_asker_does_not_let_their_maker_approve(db, approve):
    run, applied = approve
    alice, bob, _carol, p, change = _puppet_request(db)
    # What deleting the account does in the database: its record goes with it, and its name on the
    # change it made and on the one it asked for becomes NULL.
    pid = p.id
    db.query(AdminGrant).filter(AdminGrant.user_id == pid).delete()
    db.query(CredentialChange).filter(CredentialChange.requested_by_id == pid).update(
        {"requested_by_id": None}, synchronize_session=False)
    db.execute(sa.delete(User.__table__).where(User.__table__.c.id == pid))
    db.commit()
    db.expire_all()
    for who in (alice, bob):
        assert _refused(run, change.id, who).status_code == 403
    assert applied == []


# --------------------------------------------------------------------------- what was kept when it was held

def test_the_held_row_keeps_the_askers_lineage_and_who_changed_the_account(db):
    alice, _bob, carol, p, change = _puppet_request(db)
    kept = db.get(CredentialChange, change.id).approval_snapshot
    assert kept == {"requester": str(p.id), "lineage": [str(alice.id)], "changed": [str(p.id)]}
    made = db.query(CredentialChange).filter(CredentialChange.status == cc.MADE).one()
    assert made.approval_snapshot is None, "a change made at once keeps nothing"


def test_the_lineage_kept_refuses_the_maker_after_the_askers_record_is_gone(db, approve):
    # The asker is still an administrator, but their record no longer names alice: made one again by
    # someone else, say, without the request being withdrawn. What was kept still refuses her.
    run, applied = approve
    alice, bob, carol, p, change = _puppet_request(db)
    dave = _user(db, "dave")
    admin_grants.forget(db, p.id)
    admin_grants.record(db, p.id, granted_by_id=dave.id, granted_by_name="dave")
    db.commit()
    assert not admin_grants.made_by(admin_grants.of(db, [p.id])[p.id], alice.id)
    assert cc.approval_refusal(db, change, alice.id) == cc.MADE_REQUESTER
    assert [a.username for a in cc.approvers(db, p.id, change)] == ["bob"]
    assert api._credential_request_dict(change, "carol", alice.id, db=db)["can_approve"] is False
    refused = _refused(run, change.id, alice)
    assert refused.status_code == 403 and "You made puppet an administrator" in refused.detail
    assert applied == []
    run(change.id, bob)
    assert applied == [(change.id, "bob")]


def test_a_change_pruned_before_the_approval_still_refuses_who_made_it(db):
    # Rule 2 reads the changes made in the 14 days before the request. The periodic prune deletes a
    # change 14 days after it was made, which can come before the approval; the held row kept its maker.
    alice, bob, carol = _user(db, "alice"), _user(db, "bob"), _user(db, "carol", role=RoleEnum.USER)
    now = cc.utcnow()
    cc.record_made(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                   now=now - timedelta(days=13))
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=bob.id, requester_name="bob",
                     summary="s", payload={}, now=now)
    db.commit()
    later = now + timedelta(days=5)
    assert cc.prune_done(db, now=later) == 1
    db.commit()
    assert cc.changers(db, carol.id, now - cc.WINDOW) == set(), "the record of alice's change is gone"
    assert cc.approval_refusal(db, change, alice.id, now=later) == cc.CHANGED_ACCOUNT


def test_a_demotion_and_a_promotion_by_the_maker_refuse_the_maker_again(db):
    alice, _bob, _carol, p, change = _puppet_request(db)
    admin_grants.forget(db, p.id)
    db.commit()
    api._record_admin_grant(db, p, by=alice)
    db.commit()
    assert cc.approval_refusal(db, change, alice.id) == cc.MADE_REQUESTER


# --------------------------------------------------------------------------- withdrawn when the asker leaves

@pytest.fixture
def told(monkeypatch):
    """The notices sent, as (recipients, type, title, text)."""
    out = []
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title, body=None, target=None, **_k:
                        out.append((sorted(ids), ntype, title, body)))
    monkeypatch.setattr(api, "_notify_account_change", lambda _db, user, *, ntype, title, change, by, **_k:
                        out.append(([str(user.id)], ntype, title, f"{change} By: {by}")))
    return out


@pytest.mark.parametrize("because,words", [("demoted", "is no longer an administrator"),
                                           ("deactivated", "was deactivated"),
                                           ("locked", "was locked by an administrator"),
                                           ("deleted", "was deleted")])
def test_an_asker_who_leaves_has_their_open_requests_withdrawn(db, approve, told, because, words):
    run, applied = approve
    alice, bob, carol, p, change = _puppet_request(db)
    other = cc.hold(db, kind=cc.EMAIL, target_id=bob.id, requester_id=alice.id, requester_name="alice",
                    summary="s", payload={"email": "x@example.com"})
    db.commit()
    withdrawn = api._withdraw_requests_of(db, p, actor=alice, because=because)
    db.commit()
    assert [c.id for c, *_ in withdrawn] == [change.id]
    row = db.get(CredentialChange, change.id)
    assert (row.status, row.decided_by_name, row.payload) == (cc.WITHDRAWN, "alice", None)
    assert db.get(CredentialChange, other.id).status == cc.HELD, "only the leaver's own requests"
    (audit,) = db.query(AuditLog).filter(AuditLog.action == "credential_change_withdrawn").all()
    assert audit.user_id == alice.id and audit.resource_id == str(carol.id)
    assert audit.details["withdrawn_because"] == because and audit.details["requested_by"] == "puppet"

    api._announce_withdrawn_requests(db, withdrawn)
    (to_approvers, to_user) = told
    assert to_approvers[:3] == ([str(bob.id)], "credential_change_withdrawn", "A request was withdrawn")
    assert f"because puppet {words}" in to_approvers[3], to_approvers[3]
    assert to_user[:3] == ([str(carol.id)], "credential_change_withdrawn",
                           "A requested change to your account was withdrawn")
    assert f"the administrator who asked {words}. Nothing was changed." in to_user[3], to_user[3]

    refused = _refused(run, change.id, bob)
    assert refused.status_code == 409 and "withdrawn" in refused.detail
    assert applied == []


def test_withdrawing_is_read_before_the_leaver_changes(db, told):
    # Who was asked to approve is read as the records stand: called after the demotion is set, nobody
    # would be left to tell. The routes call it first.
    alice, bob, _carol, p, _change = _puppet_request(db)
    withdrawn = api._withdraw_requests_of(db, p, actor=alice, because="demoted")
    assert withdrawn[0][2] == [str(bob.id)]


def test_an_asker_with_nothing_open_withdraws_nothing(db, told):
    alice, bob = _user(db, "alice"), _user(db, "bob")
    assert api._withdraw_requests_of(db, bob, actor=alice, because="deleted") == []
    assert db.query(AuditLog).count() == 0


def _functions_calling(tree, name):
    out = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == name:
                    out.add(fn.name)
    return out


@pytest.mark.parametrize("path", ["api/api_server.py", "api/user_management_api.py"])
def test_every_route_that_can_take_an_administrator_away_withdraws_their_requests(path):
    # A route that demotes, deactivates, locks or deletes an administrator checks that one who can act
    # remains (removes_last_admin). Each such route must withdraw the leaver's requests and tell of it.
    tree = ast.parse((APP / path).read_text(encoding="utf-8"))
    removing = _functions_calling(tree, "removes_last_admin")
    assert removing, "no route found: the check moved"
    assert _functions_calling(tree, "_withdraw_requests_of") - {"_withdraw_requests_of"} == removing
    assert _functions_calling(tree, "_announce_withdrawn_requests") - {"_announce_withdrawn_requests"} == removing


def test_withdrawing_your_own_request_tells_who_was_asked_to_approve(db, told, monkeypatch):
    alice, bob, carol = _user(db, "alice"), _user(db, "bob"), _user(db, "carol", role=RoleEnum.USER)
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={})
    db.commit()
    run_coroutine(api.deny_credential_request(change_id=change.id, current_user=alice, db=db))
    assert db.get(CredentialChange, change.id).status == cc.WITHDRAWN
    to_approvers = [t for t in told if t[2] == "A request was withdrawn"]
    assert [t[0] for t in to_approvers] == [[str(bob.id)]]
    assert "alice withdrew their request" in to_approvers[0][3]


# --------------------------------------------------------------------------- never the person it is for

def test_with_two_administrators_neither_approves_a_change_to_their_own_account(db):
    # The review's two-administrator case: alice makes p, p changes bob once and asks for a second
    # change to bob. Only bob could have approved it, and a change to his own account is not his to
    # approve: it is refused outright, with the host tool the way round.
    alice, bob = _user(db, "alice"), _user(db, "bob")
    p = _user(db, "puppet")
    api._record_admin_grant(db, p, by=alice)
    cc.record_made(db, kind=cc.EMAIL, target_id=bob.id, requester_id=p.id, requester_name="puppet")
    db.commit()
    assert cc.approvers(db, p.id, target_id=bob.id) == []
    with pytest.raises(cc.NoApprover) as refused:
        cc.decide(db, requester_id=p.id, target_id=bob.id)
    assert sorted(refused.value.refusals) == [("alice", cc.MADE_REQUESTER), ("bob", cc.OWN_ACCOUNT)]
    text = api._no_approver_text(refused.value.refusals, "bob")
    assert text == "bob may not approve a change to their own account; alice made you an administrator", text


def test_the_person_a_held_change_is_for_cannot_approve_it(db, approve):
    run, applied = approve
    alice, bob, dave = _user(db, "alice"), _user(db, "bob"), _user(db, "dave")
    cc.record_made(db, kind=cc.EMAIL, target_id=bob.id, requester_id=alice.id, requester_name="alice")
    db.commit()
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=bob.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"delivery": "copy"})
    db.commit()
    assert cc.approval_refusal(db, change, bob.id) == cc.OWN_ACCOUNT
    assert [a.username for a in cc.approvers(db, alice.id, change)] == ["dave"]
    as_bob = api._credential_request_dict(change, "bob", bob.id, db=db)
    assert as_bob["cannot_approve"] == "You cannot approve this: it is a change to your own account."
    refused = _refused(run, change.id, bob)
    assert refused.status_code == 403 and "change to your own account" in refused.detail
    assert applied == []
    run(change.id, dave)
    assert applied == [(change.id, "dave")]


def test_a_single_administrator_still_cannot_get_a_second_change_held(db):
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    p = _user(db, "puppet")
    api._record_admin_grant(db, p, by=alice)
    cc.record_made(db, kind=cc.EMAIL, target_id=carol.id, requester_id=p.id, requester_name="puppet")
    db.commit()
    with pytest.raises(cc.NoApprover):
        cc.decide(db, requester_id=p.id, target_id=carol.id)


# --------------------------------------------------------------------------- the lineage, whole

def test_a_long_chain_still_leads_back_to_its_first_maker(db):
    # A chain of 100 administrators, each made by the one before, 15 days ago: the last one's lineage
    # still names alice, so it may not approve her second change. Cut at 64, it did not.
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    old = cc.utcnow() - timedelta(days=15)
    chain, prev = [], alice
    for i in range(100):
        a = _user(db, f"a{i}")
        admin_grants.record(db, a.id, granted_by_id=prev.id, granted_by_name=prev.username, now=old)
        db.commit()
        chain.append(a)
        prev = a
    last = admin_grants.of(db, [chain[-1].id])[chain[-1].id]
    assert len(last.lineage) == 100 and last.lineage[-1] == str(alice.id)
    assert admin_grants.lineage_through(db, chain[-1].id)[-1] == str(alice.id)
    cc.record_made(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id, requester_name="alice")
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={})
    db.commit()
    assert cc.approval_refusal(db, change, chain[-1].id) == cc.MADE_BY_REQUESTER
    assert cc.approval_refusal(db, change, chain[0].id) == cc.MADE_BY_REQUESTER


def test_exactly_fourteen_days_as_an_administrator_is_long_enough(db):
    alice, _bob = _user(db, "alice"), _user(db, "bob")
    carol = _user(db, "carol", role=RoleEnum.USER)
    now = cc.utcnow()
    q, q2 = _user(db, "q"), _user(db, "q2")
    admin_grants.record(db, q.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=now - timedelta(days=14))
    admin_grants.record(db, q2.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                        now=now - timedelta(days=14) + timedelta(microseconds=1))
    cc.record_made(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                   now=now - timedelta(days=1))
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={}, now=now)
    db.commit()
    assert cc.approval_refusal(db, change, q.id) is None
    assert cc.approval_refusal(db, change, q2.id) == cc.NEW_ADMIN


@pytest.mark.parametrize("reason,short,long", [
    (cc.OWN_ACCOUNT, "it is a change to your own account", "This is a change to your own account"),
    # "not", never "no longer": the one who asked may never have been one (a user who manages users).
    (cc.REQUESTER_GONE, "alice is not an active administrator",
     "alice, who asked for this change, is not an active administrator, so nobody can approve it."),
])
def test_the_new_refusals_say_their_rule_in_plain_words(reason, short, long):
    assert short in api._approval_refusal_text(reason, "alice", short=True)
    assert long in api._approval_refusal_text(reason, "alice")
