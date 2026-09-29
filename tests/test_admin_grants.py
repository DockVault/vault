"""Who made each administrator one, and the notice every administrator gets of a new one, offline on a
real database.

The two-administrator rule refuses an approval from an administrator the one who asked made
(directly, or through an administrator they made), or one made after the request; that reads the
records here. Every other administrator is told, in the app and by email, when an account becomes an
administrator. test_credential_change_rule.py covers the rule; test_credential_change_rule_live.py
drives the routes on a running stack."""
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core.models import AdminGrant, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'grants.db'}")
        for model in (User, AdminGrant, CredentialChange):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role=RoleEnum.ADMIN, active=True, email=None):
    u = User(username=name, email=email, password_hash="x", role=role, is_active=active, is_locked=False)
    db.add(u)
    db.commit()
    return u


def test_a_grant_records_its_whole_lineage_nearest_first(db):
    root, a, b, c = _user(db, "root"), _user(db, "a"), _user(db, "b"), _user(db, "c")
    admin_grants.record(db, a.id, granted_by_id=root.id, granted_by_name="root")
    admin_grants.record(db, b.id, granted_by_id=a.id, granted_by_name="a")
    admin_grants.record(db, c.id, granted_by_id=b.id, granted_by_name="b")
    db.commit()
    grants = admin_grants.of(db, [a.id, b.id, c.id, root.id])
    assert root.id not in grants, "the first administrator the server set up has no record"
    assert grants[c.id].lineage == [str(b.id), str(a.id), str(root.id)]
    assert grants[c.id].granted_by_name == "b"
    assert admin_grants.made_by(grants[c.id], root.id) and not admin_grants.made_by(grants[a.id], c.id)


def test_the_host_operators_grant_has_no_lineage_and_a_new_grant_replaces_an_old_one(db):
    a, b, x = _user(db, "a"), _user(db, "b"), _user(db, "x")
    admin_grants.record(db, x.id, granted_by_id=a.id, granted_by_name="a")
    admin_grants.record(db, x.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR)
    db.commit()
    (grant,) = db.query(AdminGrant).all()
    assert (grant.granted_by_id, grant.granted_by_name, grant.lineage) == (None, cc.HOST_OPERATOR, [])
    admin_grants.record(db, x.id, granted_by_id=b.id, granted_by_name="b")
    db.commit()
    assert db.query(AdminGrant).one().lineage == [str(b.id)]


def test_a_lineage_is_kept_whole_and_never_names_the_account_itself(db):
    # Cut at 64, the end of a longer chain no longer led back to its start (test_credential_change_
    # independence.py has what that let through).
    users = [_user(db, f"u{i}") for i in range(70)]
    for parent, child in zip(users, users[1:]):
        admin_grants.record(db, child.id, granted_by_id=parent.id, granted_by_name=parent.username)
    db.commit()
    last = admin_grants.of(db, [users[-1].id])[users[-1].id]
    assert last.lineage == [str(u.id) for u in reversed(users[:-1])]
    # A made b, b makes a an administrator again: a's lineage does not loop back to a.
    a, b = users[0], users[1]
    admin_grants.record(db, a.id, granted_by_id=b.id, granted_by_name=b.username)
    db.commit()
    assert str(a.id) not in admin_grants.of(db, [a.id])[a.id].lineage


def test_every_other_administrator_is_told_of_a_new_one_in_the_app_and_by_email(db, monkeypatch):
    alice = _user(db, "alice", email="alice@example.com")
    bob = _user(db, "bob", email="bob@example.com")
    dora = _user(db, "dora")                            # no address: told in the app only
    _user(db, "gone", active=False, email="gone@example.com")
    _user(db, "carol", role=RoleEnum.USER, email="carol@example.com")
    new = _user(db, "newadmin", email="new@example.com")
    told, mailed = [], []
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title, body=None, target=None, **_k:
                        told.append((sorted(ids), ntype, title, body, target)))
    monkeypatch.setattr(api, "_fire_action_email_bulk", lambda _db, key, recipients, ctx=None:
                        mailed.append((key, list(recipients), ctx)))
    api._announce_admin_granted(db, new, by_name="alice", how="created")
    ((ids, ntype, title, body, target),) = told
    assert ids == sorted([str(alice.id), str(bob.id), str(dora.id)]), "active administrators but the new one"
    assert (ntype, title, target) == ("administrator_added", "A new administrator", "#users")
    assert "alice created the administrator account newadmin" in body
    # One time, the notice's own, shown beside it in the reader's zone: none in the text. The email,
    # with no other time, says when.
    assert "UTC" not in body and "When:" not in body, body
    ((key, recipients, ctx),) = mailed
    assert key == "administrator_added"
    assert sorted(r for r in recipients if r[0]) == [("alice@example.com", "alice"), ("bob@example.com", "bob")]
    assert "newadmin" in ctx["change"] and ctx["by"] == "alice" and "UTC" in ctx["when"]


@pytest.mark.parametrize("how,words", [("promoted", "alice made newadmin an administrator"),
                                       ("invited", "newadmin accepted an invitation from alice")])
def test_a_promotion_and_an_invitation_are_told_in_their_own_words(db, monkeypatch, how, words):
    _user(db, "alice")
    new = _user(db, "newadmin")
    told = []
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title, body=None, **_k: told.append(body))
    monkeypatch.setattr(api, "_fire_action_email_bulk", lambda *a, **k: None)
    api._announce_admin_granted(db, new, by_name="alice", how=how)
    assert words in told[0]


def test_the_list_says_why_an_administrator_may_not_approve(db):
    alice, bob, carol = _user(db, "alice"), _user(db, "bob"), _user(db, "carol", role=RoleEnum.USER)
    puppet = _user(db, "puppet")
    admin_grants.record(db, puppet.id, granted_by_id=alice.id, granted_by_name="alice")
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"delivery": "copy"})
    db.commit()
    as_puppet = api._credential_request_dict(change, "carol", puppet.id, db=db)
    assert (as_puppet["can_approve"], as_puppet["is_mine"]) == (False, False)
    assert as_puppet["cannot_approve"] == "You cannot approve this: alice made you an administrator."
    as_bob = api._credential_request_dict(change, "carol", bob.id, db=db)
    assert (as_bob["can_approve"], as_bob["cannot_approve"]) == (True, None)
    as_alice = api._credential_request_dict(change, "carol", alice.id, db=db)
    assert (as_alice["can_approve"], as_alice["is_mine"], as_alice["cannot_approve"]) == (False, True, None)


def test_the_new_administrator_email_is_a_system_email_carrying_what_happened():
    from app.core import email_actions as ea
    spec = ea.SPEC_BY_KEY["administrator_added"]
    assert spec["category"] == ea.SYSTEM
    assert "action.change" in spec["default_body_html"]


def test_the_approve_route_refuses_an_administrator_the_asker_made_and_records_it(db, monkeypatch):
    from fastapi import HTTPException
    from _async_run import run_coroutine
    from app.core.models import AuditLog
    AuditLog.__table__.create(db.get_bind())
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    applied = []
    monkeypatch.setattr(api, "_approve_credential_change", lambda *a, **k: applied.append(a) or {})
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    puppet = _user(db, "puppet")
    admin_grants.record(db, puppet.id, granted_by_id=alice.id, granted_by_name="alice")
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"delivery": "copy"})
    db.commit()
    change_id = change.id

    def approve(user):
        return run_coroutine(api.approve_credential_request(
            change_id=change_id, request=SimpleNamespace(headers={}, client=None), current_user=user, db=db))

    with pytest.raises(HTTPException) as refused:
        approve(puppet)
    assert refused.value.status_code == 403 and "alice made you an administrator" in refused.value.detail
    with pytest.raises(HTTPException) as own:
        approve(alice)
    assert own.value.status_code == 403 and "withdraw" in own.value.detail
    assert applied == []
    assert db.get(CredentialChange, change_id).status == cc.HELD
    rows = db.query(AuditLog).filter(AuditLog.action == "credential_change_approval_refused").all()
    assert len(rows) == 1 and rows[0].user_id == puppet.id and rows[0].details["reason"] == cc.MADE_BY_REQUESTER


def test_the_refusal_of_a_second_change_says_no_other_administrator_may_approve(db):
    """Alice is the only administrator but for one she made, who may not approve her change. The
    refusal used to say there was no other ACTIVE administrator, which read as wrong beside the active
    one on the Users page: it says that no other may approve."""
    from fastapi import HTTPException
    from app.core.models import AuditLog
    AuditLog.__table__.create(db.get_bind())
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    puppet = _user(db, "puppet")
    admin_grants.record(db, puppet.id, granted_by_id=alice.id, granted_by_name="alice")
    cc.record_made(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id, requester_name="alice")
    db.commit()
    with pytest.raises(HTTPException) as refused:
        api._credential_change(db, alice, carol, cc.RESET_LINK, summary="s", payload={"delivery": "copy"})
    assert refused.value.status_code == 409
    detail = refused.value.detail
    assert "no other administrator may approve it" in detail and "dockvault.py accounts" in detail, detail
    assert "active" not in detail, detail
    assert "you made puppet an administrator" in detail, "it says which rule applied, to whom"


def test_a_second_change_by_a_user_who_manages_users_is_refused_and_points_to_an_administrator(db):
    """Their second change within 14 days used to be held, and every administrator was then refused its
    approval ("is no longer an administrator"), so it waited seven days to expire. It is refused when
    asked for, pointing to an administrator, and recorded; nothing is held."""
    from fastapi import HTTPException
    from app.core.models import AuditLog
    AuditLog.__table__.create(db.get_bind())
    _alice, _bob = _user(db, "alice"), _user(db, "bob")
    dana, carol = _user(db, "dana", role=RoleEnum.USER), _user(db, "carol", role=RoleEnum.USER)
    cc.record_made(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=dana.id, requester_name="dana")
    db.commit()
    with pytest.raises(HTTPException) as refused:
        api._credential_change(db, dana, carol, cc.RESET_LINK, summary="s", payload={"delivery": "copy"})
    detail = refused.value.detail
    assert refused.value.status_code == 409, detail
    assert detail.startswith("You already changed carol's sign-in details on "), detail
    assert "must be made by an administrator and approved by another, so ask an administrator" in detail, detail
    assert "dockvault.py accounts" in detail, detail
    assert db.query(CredentialChange).filter(CredentialChange.status == cc.HELD).count() == 0
    (row,) = db.query(AuditLog).filter(AuditLog.action == "credential_change_refused").all()
    assert row.user_id == dana.id and row.resource_id == str(carol.id)
    assert row.details == {"kind": cc.RESET_LINK, "target_username": "carol",
                           "reason": "only an administrator may ask for a second change"}


def test_the_refusal_of_a_second_change_names_each_rule_that_applied(db):
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    now = cc.utcnow()
    fresh = _user(db, "fresh")
    admin_grants.record(db, fresh.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                        now=now - timedelta(days=3))
    maker = _user(db, "maker")
    admin_grants.record(db, alice.id, granted_by_id=maker.id, granted_by_name="maker",
                        now=now - timedelta(days=40))
    changer = _user(db, "changer")
    cc.record_made(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=changer.id, requester_name="changer")
    db.commit()
    from fastapi import HTTPException
    from app.core.models import AuditLog
    AuditLog.__table__.create(db.get_bind())
    with pytest.raises(HTTPException) as refused:
        api._credential_change(db, alice, carol, cc.RESET_LINK, summary="s", payload={"delivery": "copy"})
    detail = refused.value.detail
    assert refused.value.status_code == 409, detail
    for words in ("maker made you an administrator", "changer changed carol's sign-in details in the last 14 days",
                  "fresh became an administrator less than 14 days ago"):
        assert words in detail, (words, detail)
    (row,) = db.query(AuditLog).filter(AuditLog.action == "credential_change_refused").all()
    assert row.details["approver_refusals"] == sorted([cc.MADE_REQUESTER, cc.CHANGED_ACCOUNT, cc.NEW_ADMIN])


def test_the_refusal_names_several_administrators_in_plain_words():
    text = api._no_approver_text([("a", cc.MADE_BY_REQUESTER), ("b", cc.MADE_BY_REQUESTER), ("c", cc.NEW_ADMIN),
                                  ("d", cc.BECAME_ADMIN_AFTER)], "carol")
    assert text == "you made a and b administrators; c and d became administrators less than 14 days ago"
    many = [(f"x{i}", cc.CHANGED_ACCOUNT) for i in range(7)]
    said = api._no_approver_text(many, "carol")
    assert said == "x0, x1, x2, x3, x4 and 2 more changed carol's sign-in details in the last 14 days"
    assert api._no_approver_text([], "carol") == "there is no other administrator who can sign in"


@pytest.mark.parametrize("reason,short,long", [
    (cc.MADE_BY_REQUESTER, "alice made you an administrator", "alice made you an administrator"),
    (cc.MADE_REQUESTER, "you made alice an administrator", "You made alice an administrator"),
    (cc.CHANGED_ACCOUNT, "you changed this account's sign-in details in the last 14 days",
     "within 14 days of this request"),
    (cc.BECAME_ADMIN_AFTER, "after it was asked for", "after this request was made"),
    (cc.NEW_ADMIN, "for less than 14 days", "for less than 14 days when this request was made"),
])
def test_each_refusal_of_an_approval_says_its_rule_in_plain_words(reason, short, long):
    assert short in api._approval_refusal_text(reason, "alice", short=True)
    text = api._approval_refusal_text(reason, "alice")
    assert long in text and "dockvault.py accounts" in text, text


def test_the_list_says_when_the_viewer_changed_the_account_or_is_new(db):
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    changer, fresh = _user(db, "changer"), _user(db, "fresh")
    admin_grants.record(db, fresh.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                        now=cc.utcnow() - timedelta(days=1))
    cc.record_made(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=changer.id, requester_name="changer")
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                     summary="s", payload={"delivery": "copy"})
    db.commit()
    as_changer = api._credential_request_dict(change, "carol", changer.id, db=db)
    assert as_changer["can_approve"] is False and "changed this account" in as_changer["cannot_approve"]
    as_fresh = api._credential_request_dict(change, "carol", fresh.id, db=db)
    assert as_fresh["can_approve"] is False and "less than 14 days" in as_fresh["cannot_approve"]


def test_the_approve_route_refuses_the_mirror_and_records_why(db, monkeypatch):
    # Alice made the first change and the account that asks for the second; she may not approve it.
    from fastapi import HTTPException
    from _async_run import run_coroutine
    from app.core.models import AuditLog
    AuditLog.__table__.create(db.get_bind())
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(api, "_approve_credential_change", lambda *a, **k: pytest.fail("approved"))
    alice, carol = _user(db, "alice"), _user(db, "carol", role=RoleEnum.USER)
    puppet = _user(db, "puppet")
    admin_grants.record(db, puppet.id, granted_by_id=alice.id, granted_by_name="alice")
    cc.record_made(db, kind=cc.PASSWORD, target_id=carol.id, requester_id=alice.id, requester_name="alice")
    change = cc.hold(db, kind=cc.RESET_LINK, target_id=carol.id, requester_id=puppet.id,
                     requester_name="puppet", summary="s", payload={"delivery": "copy"})
    db.commit()
    with pytest.raises(HTTPException) as refused:
        run_coroutine(api.approve_credential_request(
            change_id=change.id, request=SimpleNamespace(headers={}, client=None), current_user=alice, db=db))
    assert refused.value.status_code == 403
    assert "You made puppet an administrator" in refused.value.detail, refused.value.detail
    (row,) = db.query(AuditLog).filter(AuditLog.action == "credential_change_approval_refused").all()
    assert row.details["reason"] == cc.MADE_REQUESTER


def test_an_invitation_keeps_its_inviters_lineage_through_a_demotion_or_a_deletion(db):
    # Two bypasses: the inviter's record went with a demotion, or the
    # inviter with a deletion, before the invitation was accepted, and the new administrator lost the
    # administrators the inviter descended from. The invitation keeps that lineage from when it was made.
    alice, p = _user(db, "alice"), _user(db, "p")
    admin_grants.record(db, p.id, granted_by_id=alice.id, granted_by_name="alice")
    db.commit()
    kept = admin_grants.lineage_through(db, p.id)
    assert kept == [str(p.id), str(alice.id)]
    assert admin_grants.lineage_through(db, None) == [], "the host operator's invitation has none"

    admin_grants.forget(db, p.id)                                   # p demoted
    demoted = _user(db, "via-demoted")
    admin_grants.record(db, demoted.id, granted_by_id=p.id, granted_by_name="p", inherited=kept)
    assert admin_grants.of(db, [demoted.id])[demoted.id].lineage == [str(p.id), str(alice.id)]

    deleted = _user(db, "via-deleted")                              # p deleted: no maker left to read
    admin_grants.record(db, deleted.id, granted_by_id=None, granted_by_name="an administrator since deleted",
                        inherited=kept)
    grant = admin_grants.of(db, [deleted.id])[deleted.id]
    assert grant.lineage == [str(p.id), str(alice.id)]
    assert admin_grants.made_by(grant, alice.id)
    # And the kept lineage never names the account itself, nor repeats anyone.
    admin_grants.record(db, alice.id, granted_by_id=p.id, granted_by_name="p", inherited=kept + [str(p.id)])
    assert admin_grants.of(db, [alice.id])[alice.id].lineage == [str(p.id)]


def test_an_invitation_that_keeps_no_lineage_stores_null(db):
    # A user's invitation keeps none: SQL NULL, not a JSON null, so "no lineage" reads the same way in
    # the database as for an invitation made before the column existed.
    import sqlalchemy as sa
    from datetime import datetime
    from app.core.models import AccountInvitation
    AccountInvitation.__table__.create(db.get_bind())
    db.add(AccountInvitation(username="plain", role="user", token_prefix="p", token_hash="h",
                             expires_at=datetime(2030, 1, 1), inviter_lineage=None))
    db.commit()
    assert db.execute(sa.text("SELECT inviter_lineage IS NULL FROM account_invitations")).scalar() == 1
