"""The auditor right granted by two people, offline on a real database (app/core/auditor_rights.py and its routes
in app/api/compliance_router.py).

Who may hold it: an active account, not locked by an administrator, whose role is user or administrator (an
administrator only while COMPLIANCE_AUDITOR_NOT_ADMIN is off), with an authenticator app (an email code never
counts), a password of its own, and no change to its sign-in details by someone else in 14 days. Who may approve:
an independent administrator by the one rule (app/core/independence.py), while the proposer can still act; a
one-person grant is refused and recorded. A proposal lapses after 7 days, a grant expires after
COMPLIANCE_AUDITOR_GRANT_DAYS. Every step is recorded and told after its commit, never before.
test_auditor_grants_live.py drives the routes on a running stack.
"""
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import compliance_router as cr  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import independence as ind  # noqa: E402
from app.core.models import (AdminGrant, AuditLog, AuditorGrant, CredentialChange, RoleEnum,  # noqa: E402
                             SecondFactorEnrollment, User)
from app.core.security import open_case_field  # noqa: E402

pytestmark = pytest.mark.unit

OLD = timedelta(days=400)
# The real delivery, before the fixture below stands in for it.
DELIVER = rights.deliver


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'grants.db'}")
        copies = sa.MetaData()
        for model in (User, AdminGrant, CredentialChange, AuditLog, AuditorGrant, SecondFactorEnrollment):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                # Postgres' "now() AT TIME ZONE 'utc'" as SQLite's own default.
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def told(monkeypatch):
    """What deliver() was handed after each commit, instead of sending it."""
    out = []
    monkeypatch.setattr(rights, "deliver", lambda notices: out.extend(notices))
    return out


@pytest.fixture
def settings(monkeypatch):
    """The compliance settings in force, as a dict a test may change."""
    values = {key: cs.current(key) for key in cs.KEYS}
    monkeypatch.setattr(cs, "current", lambda key: values[key])
    return values


@pytest.fixture
def steps(monkeypatch):
    """The compliance step-ups, passed and recorded instead of asking for a code."""
    asked = []
    for name in ("STEP_UP_GRANT_PROPOSE", "STEP_UP_GRANT_APPROVE", "STEP_UP_GRANT_RECONFIRM"):
        check = getattr(cr, name)
        monkeypatch.setattr(cr, name, lambda db_, user, request, _a=check.action: asked.append((_a, user.username)))
    return asked


def _user(db, name, role=RoleEnum.USER, *, created_by=None, totp=True, admin_for=OLD, by=None):
    u = User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
             is_locked=False, created_by=created_by)
    db.add(u)
    db.commit()
    if role == RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=by.id if by is not None else None,
                            granted_by_name=by.username if by is not None else cc.HOST_OPERATOR,
                            now=rights.utcnow() - admin_for)
    if totp:
        _enroll(db, u)
    db.commit()
    return u


def _enroll(db, user, method="totp", status="active"):
    e = SecondFactorEnrollment(user_id=user.id, method=method, secret_enc="sealed", status=status)
    db.add(e)
    db.commit()
    return e


def _request():
    return SimpleNamespace(headers={}, client=None)


def _refused(fn, *args, **kwargs):
    with pytest.raises(HTTPException) as refused:
        fn(*args, **kwargs)
    return refused.value


def _rows(db, action):
    return db.query(AuditLog).filter(AuditLog.action == action).all()


def _propose(db, user, proposer, note=None):
    return cr.propose_auditor_grant(cr.Proposal(user_id=user.id, note=note), _request(), current_user=proposer,
                                    db=db)


def _approve(db, grant_id, approver):
    return cr.approve_auditor_grant(uuid.UUID(str(grant_id)), _request(), current_user=approver, db=db)


@pytest.fixture
def people(db):
    """ada and bob are long-standing administrators, made by the host operator; uma is a user ada created
    long ago, who set her own password and has an authenticator."""
    ada = _user(db, "ada", RoleEnum.ADMIN)
    bob = _user(db, "bob", RoleEnum.ADMIN)
    uma = _user(db, "uma", created_by=None)
    return SimpleNamespace(ada=ada, bob=bob, uma=uma)


# --------------------------------------------------------------------------- who may hold it

def test_a_fit_account_meets_every_precondition(db, people, settings):
    assert rights.preconditions(db, people.uma) == []
    assert rights.preconditions(db, people.ada) == []


@pytest.mark.parametrize("how,expected", [
    ("no factor", [rights.NO_TOTP]),
    ("email codes", [rights.NO_TOTP]),
    ("not confirmed", [rights.NO_TOTP]),
    ("password set by another", [rights.PASSWORD_NOT_OWN]),
    ("changed by an administrator 13 days ago", [rights.RECENT_CHANGE]),
    ("deactivated", [rights.INACTIVE]),
    ("locked by an administrator", [rights.LOCKED]),
    ("an external account", [rights.ROLE]),
])
def test_each_precondition_refuses(db, people, settings, how, expected):
    uma = people.uma
    if how in ("no factor", "email codes", "not confirmed"):
        db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == uma.id).delete()
        db.commit()
        if how == "email codes":
            _enroll(db, uma, method="email")
        if how == "not confirmed":
            _enroll(db, uma, status="unconfirmed")
    elif how == "password set by another":
        uma.password_set_by, uma.password_set_by_other_at = people.ada.id, rights.utcnow()
    elif how == "changed by an administrator 13 days ago":
        change = cc.record_made(db, kind=cc.EMAIL, target_id=uma.id, requester_id=people.ada.id,
                                requester_name="ada")
        change.applied_at = rights.utcnow() - timedelta(days=13)
    elif how == "deactivated":
        uma.is_active = False
    elif how == "locked by an administrator":
        uma.is_locked, uma.locked_until = True, None
    elif how == "an external account":
        uma.role = RoleEnum.EXTERNAL
    db.commit()
    assert rights.preconditions(db, uma) == expected


def test_what_does_not_stand_in_the_way(db, people, settings):
    uma = people.uma
    # A lock that wrong passwords armed runs out by itself; a change 15 days ago is outside the window.
    uma.is_locked, uma.locked_until = True, rights.utcnow() + timedelta(minutes=5)
    change = cc.record_made(db, kind=cc.EMAIL, target_id=uma.id, requester_id=people.ada.id, requester_name="ada")
    change.applied_at = rights.utcnow() - timedelta(days=15)
    db.commit()
    assert rights.preconditions(db, uma) == []


def test_an_administrator_holds_it_only_while_the_deployment_allows(db, people, settings):
    settings[cs.AUDITOR_NOT_ADMIN] = True
    assert rights.preconditions(db, people.ada) == [rights.ADMIN_NOT_ALLOWED]
    assert rights.preconditions(db, people.uma) == []


# --------------------------------------------------------------------------- who may approve

def _proposed(db, user, proposer, at=None):
    grant = rights.propose(db, user, proposer=proposer, now=at)
    db.commit()
    return grant


def test_an_independent_administrator_may_approve(db, people, settings):
    grant = _proposed(db, people.uma, people.ada)
    assert rights.approver_refusal(db, grant, people.bob) is None
    assert [a.username for a in rights.independent_approvers(db, grant)] == ["bob"]


@pytest.mark.parametrize("case", ["one person", "own account", "stand-in admin", "stand-in account", "fresh admin",
                                  "changed before", "changer while it stood", "password not own", "maker of proposer",
                                  "proposer left", "not an administrator"])
def test_who_may_not_approve(db, people, settings, case):
    ada, bob, uma = people.ada, people.bob, people.uma
    expected = {"one person": ind.ASKED, "own account": ind.OWN_ACCOUNT, "stand-in admin": ind.MADE_BY_REQUESTER,
                "stand-in account": ind.CREATED_SUBJECT, "fresh admin": ind.NEW_ADMIN,
                "changed before": ind.CHANGED_ACCOUNT, "changer while it stood": ind.CHANGED_SUBJECT,
                "password not own": ind.PASSWORD_NOT_OWN, "maker of proposer": ind.MADE_REQUESTER,
                "proposer left": rights.PROPOSER_GONE, "not an administrator": rights.NOT_ABLE}[case]
    subject, approver = uma, bob
    if case == "one person":
        approver = ada
    elif case == "own account":
        subject = _user(db, "ann", RoleEnum.ADMIN)
        approver = subject
    elif case == "stand-in admin":
        admin_grants.record(db, bob.id, granted_by_id=ada.id, granted_by_name="ada",
                            now=rights.utcnow() - OLD)
    elif case == "stand-in account":
        uma.created_by = bob.id
    elif case == "fresh admin":
        admin_grants.record(db, bob.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                            now=rights.utcnow() - timedelta(days=13))
    elif case == "changed before":
        change = cc.record_made(db, kind=cc.EMAIL, target_id=uma.id, requester_id=bob.id, requester_name="bob")
        change.applied_at = rights.utcnow() - timedelta(days=10)
    elif case == "password not own":
        bob.password_set_by, bob.password_set_by_other_at = None, rights.utcnow()
    elif case == "maker of proposer":
        admin_grants.record(db, ada.id, granted_by_id=bob.id, granted_by_name="bob", now=rights.utcnow() - OLD)
    db.commit()
    grant = _proposed(db, subject, ada)
    if case == "changer while it stood":
        grant.credential_changers = [{"id": str(bob.id).upper(), "name": "bob", "kind": "email", "at": "x"}]
    elif case == "proposer left":
        ada.role = RoleEnum.USER
    elif case == "not an administrator":
        bob.role = RoleEnum.USER
    db.commit()
    assert rights.approver_refusal(db, grant, approver) == expected
    if approver.role == RoleEnum.ADMIN:
        assert approver not in rights.independent_approvers(db, grant)


def test_the_lineage_kept_at_the_proposal_still_refuses_after_the_record_changes(db, people, settings):
    ada, bob, uma = people.ada, people.bob, people.uma
    # bob made ada an administrator; ada proposes. Then ada's record is rewritten (demoted and promoted again by
    # the host): her record no longer names bob, but the proposal kept it.
    admin_grants.record(db, ada.id, granted_by_id=bob.id, granted_by_name="bob", now=rights.utcnow() - OLD)
    db.commit()
    grant = _proposed(db, uma, ada)
    assert grant.proposal_snapshot["lineage"] == [str(bob.id)]
    admin_grants.record(db, ada.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=rights.utcnow() - OLD)
    db.commit()
    assert rights.approver_refusal(db, grant, bob) == ind.MADE_REQUESTER


def test_a_change_pruned_since_the_proposal_still_refuses_who_made_it(db, people, settings):
    ada, bob, uma = people.ada, people.bob, people.uma
    change = cc.record_made(db, kind=cc.EMAIL, target_id=uma.id, requester_id=bob.id, requester_name="bob")
    change.applied_at = rights.utcnow() - timedelta(days=10)
    db.commit()
    grant = _proposed(db, uma, ada)
    db.delete(change)
    db.commit()
    assert rights.approver_refusal(db, grant, bob) == ind.CHANGED_ACCOUNT


def test_the_changes_are_read_as_they_stand_too_not_only_from_the_snapshot(db, people, settings):
    ada, bob, uma = people.ada, people.bob, people.uma
    change = cc.record_made(db, kind=cc.EMAIL, target_id=uma.id, requester_id=bob.id, requester_name="bob")
    change.applied_at = rights.utcnow() - timedelta(days=10)
    db.commit()
    grant = _proposed(db, uma, ada)
    grant.proposal_snapshot = None
    db.commit()
    assert rights.approver_refusal(db, grant, bob) == ind.CHANGED_ACCOUNT


@pytest.fixture
def creators(db, people):
    """The account's creator's lineage, either way: zed made ada an administrator, ada created uma's account and
    made bea an administrator; carl, independent of them all, proposes uma's right."""
    zed = _user(db, "zed", RoleEnum.ADMIN)
    admin_grants.record(db, people.ada.id, granted_by_id=zed.id, granted_by_name="zed", now=rights.utcnow() - OLD)
    bea = _user(db, "bea", RoleEnum.ADMIN, by=people.ada)
    carl = _user(db, "carl", RoleEnum.ADMIN)
    people.uma.created_by = people.ada.id
    db.commit()
    return SimpleNamespace(zed=zed, bea=bea, carl=carl)


@pytest.mark.parametrize("who,expected", [("bea", ind.MADE_BY_CREATOR), ("zed", ind.MADE_CREATOR), ("bob", None)])
def test_an_administrator_in_the_lineage_of_the_accounts_creator_may_not_approve(db, people, settings, creators,
                                                                                  who, expected):
    """A stand-in administrator and a stand-in account combined: the creator made the approver an administrator,
    or the approver made the creator one. Neither proposed the grant."""
    grant = _proposed(db, people.uma, creators.carl)
    approver = {"bea": creators.bea, "zed": creators.zed, "bob": people.bob}[who]
    assert rights.approver_refusal(db, grant, approver) == expected
    assert (approver in rights.independent_approvers(db, grant)) is (expected is None)
    if expected is not None:
        assert rights.text(expected) != expected, "said in plain words"


def test_the_creator_kept_at_the_proposal_still_refuses_after_the_creator_is_deleted_or_demoted(db, people, settings,
                                                                                                creators):
    grant = _proposed(db, people.uma, creators.carl)
    assert grant.proposal_snapshot["creator"] == str(people.ada.id)
    assert grant.proposal_snapshot["creator_lineage"] == [str(creators.zed.id)]
    # Deleting ada clears the account's creator; demoting her deletes her lineage.
    people.uma.created_by = None
    admin_grants.forget(db, people.ada.id)
    db.commit()
    assert rights.approver_refusal(db, grant, creators.bea) == ind.MADE_BY_CREATOR
    assert rights.approver_refusal(db, grant, creators.zed) == ind.MADE_CREATOR
    # Without what the proposal kept, the records alone no longer refuse them.
    grant.proposal_snapshot = {**grant.proposal_snapshot, "creator": None, "creator_lineage": []}
    db.commit()
    assert rights.approver_refusal(db, grant, creators.bea) is None
    assert rights.approver_refusal(db, grant, creators.zed) is None


def test_the_creators_lineage_is_read_as_it_stands_too_not_only_from_the_snapshot(db, people, settings, creators):
    grant = _proposed(db, people.uma, creators.carl)
    grant.proposal_snapshot = None
    db.commit()
    assert rights.approver_refusal(db, grant, creators.bea) == ind.MADE_BY_CREATOR
    assert rights.approver_refusal(db, grant, creators.zed) == ind.MADE_CREATOR


def test_an_approver_without_an_authenticator_is_not_counted_independent(db, people, settings):
    grant = _proposed(db, people.uma, people.ada)
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == people.bob.id).delete()
    db.commit()
    assert rights.approver_refusal(db, grant, people.bob) is None
    assert rights.independent_approvers(db, grant) == []


# --------------------------------------------------------------------------- the routes

def test_a_proposal_that_meets_the_preconditions_is_recorded_and_told_after_its_commit(db, people, settings, steps,
                                                                                     told):
    out = _propose(db, people.uma, people.ada, note="Quarterly review of the finance team")
    assert steps == [("compliance.grant.propose", "ada")]
    assert out["status"] == "proposed" and out["proposed_by"] == "ada" and out["username"] == "uma"
    assert out["you_may_approve"] is False and out["why_not"]["reason"] == ind.ASKED
    assert out["host_approval"] is False and out["provenance"]["password_set_by_other"] is False
    grant = db.get(AuditorGrant, uuid.UUID(out["id"]))
    assert open_case_field(grant.id, grant.note_enc, "grant_note") == "Quarterly review of the finance team"
    rows = _rows(db, "auditor_grant_proposed")
    assert len(rows) == 1 and rows[0].username == "ada" and rows[0].resource_id == str(people.uma.id)
    assert rows[0].details["grant_id"] == out["id"] and "Quarterly" not in str(rows[0].details)
    assert [n["event"] for n in told] == ["proposed"] and told[0]["holder"] == "uma"


def test_a_proposal_for_an_unfit_account_is_refused_and_recorded_before_any_code(db, people, settings, steps, told):
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == people.uma.id).delete()
    people.uma.password_set_by_other_at = rights.utcnow()
    db.commit()
    refused = _refused(_propose, db, people.uma, people.ada)
    assert refused.status_code == 409
    assert [r["reason"] for r in refused.detail["reasons"]] == [rights.NO_TOTP, rights.PASSWORD_NOT_OWN]
    assert steps == [] and db.query(AuditorGrant).count() == 0 and told == []
    row = _rows(db, "auditor_grant_refused")[0]
    assert row.status == "failure" and row.details["action"] == "propose"
    assert row.details["reasons"] == [rights.NO_TOTP, rights.PASSWORD_NOT_OWN]


def test_an_account_has_one_open_grant(db, people, settings, steps):
    _propose(db, people.uma, people.ada)
    refused = _refused(_propose, db, people.uma, people.bob)
    assert refused.status_code == 409 and refused.detail["reason"] == rights.OPEN_GRANT
    assert db.query(AuditorGrant).count() == 1
    assert ("compliance.grant.propose", "bob") not in steps, "refused before any code is asked for"


def test_nothing_is_proposed_or_approved_while_compliance_access_is_off(db, people, settings, steps):
    out = _propose(db, people.uma, people.ada)
    settings[cs.ACCESS] = cs.DISABLED
    assert _refused(_propose, db, people.bob, people.ada).status_code == 409
    assert _refused(_approve, db, out["id"], people.bob).status_code == 409
    assert db.get(AuditorGrant, uuid.UUID(out["id"])).status == "proposed"
    # Revoking only removes power: it still works.
    cr.revoke_auditor_right(people.uma.id, None, current_user=people.bob, db=db)
    assert db.get(AuditorGrant, uuid.UUID(out["id"])).status == "revoked"


def test_a_one_person_grant_is_refused_and_recorded(db, people, settings, steps, told):
    out = _propose(db, people.uma, people.ada)
    del told[:]
    refused = _refused(_approve, db, out["id"], people.ada)
    assert refused.status_code == 403 and refused.detail["reason"] == ind.ASKED
    assert db.get(AuditorGrant, uuid.UUID(out["id"])).status == "proposed"
    row = [r for r in _rows(db, "auditor_grant_refused") if r.details["action"] == "approve"][0]
    assert row.username == "ada" and row.details["reason"] == ind.ASKED and row.details["grant_id"] == out["id"]
    assert steps == [("compliance.grant.propose", "ada")], "no code is asked for a step that is refused"
    assert told == []
    # Proposing yourself does not let you approve yourself either.
    mine = _propose(db, people.bob, people.bob)
    assert _refused(_approve, db, mine["id"], people.bob).detail["reason"] == ind.ASKED


def test_the_independent_approval_binds_the_grant_to_the_authenticator(db, people, settings, steps, told):
    settings[cs.AUDITOR_GRANT_DAYS] = 200
    out = _propose(db, people.uma, people.ada)
    del told[:]
    approved = _approve(db, out["id"], people.bob)
    assert steps[-1] == ("compliance.grant.approve", "bob")
    grant = db.get(AuditorGrant, uuid.UUID(out["id"]))
    totp = rights.active_totp(db, people.uma.id)
    assert grant.status == "active" and grant.second_factor_enrollment_id == totp.id
    assert grant.approved_by == people.bob.id and grant.approved_by_username == "bob"
    assert grant.approved_by_operator is False and grant.confirmed_role == "user"
    assert grant.expires_at - grant.approved_at == timedelta(days=200)
    assert approved["status"] == "active" and approved["expires_at"].startswith(grant.expires_at.isoformat()[:10])
    row = _rows(db, "auditor_granted")[0]
    assert row.username == "bob" and row.details["proposed_by"] == "ada"
    assert [n["event"] for n in told] == ["granted"] and told[0]["by"] == "bob"


def test_an_approval_rechecks_the_account(db, people, settings, steps):
    out = _propose(db, people.uma, people.ada)
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == people.uma.id).delete()
    db.commit()
    refused = _refused(_approve, db, out["id"], people.bob)
    assert refused.status_code == 409 and refused.detail["reason"] == rights.NO_TOTP
    assert db.get(AuditorGrant, uuid.UUID(out["id"])).status == "proposed"


def test_an_approval_rechecks_after_the_code(db, people, settings, monkeypatch):
    """What changes while the approver gives their code is read again before the approval."""
    out = _propose_with_steps(db, people, monkeypatch)

    def meanwhile(db_, user, request):
        people.uma.password_set_by_other_at = rights.utcnow()
        db_.commit()

    monkeypatch.setattr(cr, "STEP_UP_GRANT_APPROVE", meanwhile)
    refused = _refused(_approve, db, out["id"], people.bob)
    assert refused.detail["reason"] == rights.PASSWORD_NOT_OWN
    assert db.get(AuditorGrant, uuid.UUID(out["id"])).status == "proposed"


def _propose_with_steps(db, people, monkeypatch):
    monkeypatch.setattr(cr, "STEP_UP_GRANT_PROPOSE", lambda *a: None)
    return _propose(db, people.uma, people.ada)


def test_a_proposal_lapses_after_seven_days(db, people, settings, steps):
    grant = _proposed(db, people.uma, people.ada, at=rights.utcnow() - timedelta(days=7, seconds=1))
    refused = _refused(_approve, db, grant.id, people.bob)
    assert refused.status_code == 409 and refused.detail["reason"] == rights.LAPSED
    young = _proposed(db, people.bob, people.ada, at=rights.utcnow() - timedelta(days=6, hours=23))
    assert rights.is_lapsed(young) is False
    # To the second: the proposal lapses at seven days exactly.
    assert rights.is_lapsed(young, young.proposed_at + timedelta(days=7)) is True
    assert rights.is_lapsed(young, young.proposed_at + timedelta(days=7, seconds=-1)) is False


def test_turning_a_proposal_down(db, people, settings, steps, told):
    out = _propose(db, people.uma, people.ada)
    assert _refused(cr.reject_auditor_grant, uuid.UUID(out["id"]), cr.Reason(reason="no"), _request(),
                    current_user=people.ada, db=db).detail["reason"] == ind.ASKED
    del told[:]
    done = cr.reject_auditor_grant(uuid.UUID(out["id"]), cr.Reason(reason="Not needed this year"), _request(),
                                   current_user=people.bob, db=db)
    grant = db.get(AuditorGrant, uuid.UUID(out["id"]))
    assert done["status"] == "rejected" and grant.rejected_by == people.bob.id and grant.ended_at is not None
    assert open_case_field(grant.id, grant.reject_reason_enc, "grant_reject_reason") == "Not needed this year"
    assert [n["event"] for n in told] == ["rejected"]
    assert _refused(_approve, db, out["id"], people.bob).detail["reason"] == rights.NOT_PROPOSED


def test_the_account_a_proposal_is_for_cannot_turn_it_down(db, people, settings, steps):
    out = _propose(db, people.bob, people.ada)
    refused = _refused(cr.reject_auditor_grant, uuid.UUID(out["id"]), cr.Reason(reason="no"), _request(),
                       current_user=people.bob, db=db)
    assert refused.status_code == 403 and refused.detail["reason"] == ind.OWN_ACCOUNT
    assert db.get(AuditorGrant, uuid.UUID(out["id"])).status == "proposed"
    assert ("compliance.grant.approve", "bob") not in steps


def test_revoking_takes_one_administrator_and_ends_a_proposal_too(db, people, settings, steps, told):
    out = _propose(db, people.uma, people.ada)
    _approve(db, out["id"], people.bob)
    del told[:]
    done = cr.revoke_auditor_right(people.uma.id, cr.OptionalReason(reason="Left the audit team"),
                                   current_user=people.ada, db=db)
    grant = db.get(AuditorGrant, uuid.UUID(out["id"]))
    assert done["status"] == "revoked" and grant.revoked_by == people.ada.id and grant.ended_at is not None
    assert open_case_field(grant.id, grant.revoke_reason_enc, "revoke_reason") == "Left the audit team"
    assert _rows(db, "auditor_revoked")[0].details["status"] == "active"
    assert [n["event"] for n in told] == ["revoked"]
    assert _refused(cr.revoke_auditor_right, people.uma.id, None, current_user=people.ada, db=db).status_code == 404
    # A new proposal can follow.
    assert _propose(db, people.uma, people.ada)["status"] == "proposed"


def test_the_list_and_the_callers_own_right(db, people, settings, steps):
    out = _propose(db, people.uma, people.ada)
    listed = cr.list_auditor_grants(current_user=people.bob, db=db)
    row = listed["grants"][0]
    assert row["id"] == out["id"] and row["you_may_approve"] is True and row["why_not"] is None
    assert listed["grant_days"] == cs.current(cs.AUDITOR_GRANT_DAYS) and listed["proposal_days"] == 7
    assert cr.my_auditor_right(current_user=people.uma, db=db)["grant"]["status"] == "proposed"
    assert cr.my_auditor_right(current_user=people.bob, db=db) == {"grant": None}
    detail = cr.get_auditor_grant(uuid.UUID(out["id"]), current_user=people.bob, db=db)
    assert detail["provenance"]["username"] == "uma"
    assert _refused(cr.get_auditor_grant, uuid.uuid4(), current_user=people.bob, db=db).status_code == 404


def test_only_the_server_operator_approves_when_nobody_independent_exists(db, people, settings, steps):
    out = _propose(db, people.uma, people.ada)
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == people.bob.id).delete()
    db.commit()
    row = cr.list_auditor_grants(current_user=people.ada, db=db)["grants"][0]
    assert row["host_approval"] is True and row["id"] == out["id"]


def test_provenance_says_who_created_the_account_and_set_its_password(db, people, settings):
    made = _user(db, "mia", created_by=people.ada.id)
    made.password_set_by, made.password_set_by_other_at = people.ada.id, rights.utcnow()
    db.commit()
    seen = rights.provenance(db, made)
    assert seen["created_by"] == "ada" and seen["password_set_by"] == "ada" and seen["password_set_by_other"]
    assert seen["authenticator"] is not None and seen["role"] == "user"


# --------------------------------------------------------------------------- time

def test_the_periodic_job_lapses_proposals_and_expires_grants(db, people, settings, told):
    stale = _proposed(db, people.uma, people.ada, at=rights.utcnow() - timedelta(days=8))
    grant = _proposed(db, people.bob, people.ada)
    rights.approve(db, grant, approver=None)
    grant.approved_at = rights.utcnow() - timedelta(days=366)
    grant.expires_at = grant.approved_at + timedelta(days=365)
    db.commit()
    del told[:]
    assert rights.end_due(db) == 2
    db.commit()
    assert db.get(AuditorGrant, stale.id).status == "lapsed" and db.get(AuditorGrant, grant.id).status == "expired"
    assert len(_rows(db, "auditor_grant_lapsed")) == 1 and len(_rows(db, "auditor_grant_expired")) == 1
    assert _rows(db, "auditor_grant_expired")[0].user_id is None, "written by the server, with no person acting"
    assert sorted(n["event"] for n in told) == ["expired", "lapsed"]
    assert rights.end_due(db) == 0


def test_a_lowered_grant_lifetime_shortens_grants_already_given(db, people, settings):
    grant = _proposed(db, people.uma, people.ada)
    rights.approve(db, grant, approver=people.bob)
    grant.approved_at = rights.utcnow() - timedelta(days=100)
    grant.expires_at = grant.approved_at + timedelta(days=365)
    db.commit()
    assert not rights.is_expired(grant)
    settings[cs.AUDITOR_GRANT_DAYS] = 90
    assert rights.effective_expiry(grant) == grant.approved_at + timedelta(days=90)
    assert rights.is_expired(grant) and rights.shown_status(grant) == "expired"
    settings[cs.AUDITOR_GRANT_DAYS] = 730
    assert rights.effective_expiry(grant) == grant.expires_at, "a raised lifetime never lengthens a grant"


def test_the_host_operator_approval_is_recorded_as_the_host(db, people, settings, told):
    grant = _proposed(db, people.uma, people.ada)
    rights.approve(db, grant, approver=None)
    db.commit()
    assert grant.approved_by is None and grant.approved_by_operator and grant.approved_by_username == cc.HOST_OPERATOR
    row = _rows(db, "auditor_granted")[0]
    assert row.username == cc.HOST_OPERATOR and row.user_id is None and row.details["by"] == "host operator"


# --------------------------------------------------------------------------- telling

def test_a_notice_goes_after_the_commit_and_never_after_a_rollback(db, people, settings, told):
    rights.propose(db, people.uma, proposer=people.ada)
    assert told == []
    db.rollback()
    assert told == [] and db.query(AuditorGrant).count() == 0
    db.commit()
    assert told == [], "a rolled-back step is never told, even by a later commit"
    rights.propose(db, people.uma, proposer=people.ada)
    db.commit()
    assert [n["event"] for n in told] == ["proposed"]


def test_only_the_end_of_the_outermost_transaction_drops_the_notices(db, people, settings, told):
    rights.propose(db, people.uma, proposer=people.ada)
    # A savepoint ending (its transaction has a parent) keeps them; the outermost one ending drops them.
    from app.core import after_commit
    after_commit._after_transaction_end(db, SimpleNamespace(parent=object()))
    assert len(after_commit.pending(db, rights._NOTICES)) == 1
    after_commit._after_transaction_end(db, SimpleNamespace(parent=None))
    assert after_commit.pending(db, rights._NOTICES) == []


def test_the_email_always_goes_and_says_what_changed():
    from app.core import email_actions
    spec = email_actions.SPEC_BY_KEY[rights.EMAIL_ACTION]
    assert spec["category"] == email_actions.SYSTEM, "no switch turns it off"
    assert "{{action.change}}" in spec["default_body_html"]


def test_every_active_administrator_and_the_account_are_told_in_the_app_and_by_email(db, people, monkeypatch):
    from contextlib import contextmanager
    from app.api import api_server as api
    from app.core import database
    gone = _user(db, "gil", RoleEnum.ADMIN)
    gone.is_active = False
    db.commit()
    sent = {}

    @contextmanager
    def same_db():
        yield db

    monkeypatch.setattr(database, "get_db_context", same_db)
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title, body, target: sent.setdefault(
        "app", []).append((sorted(ids), ntype, title, target)))
    monkeypatch.setattr(api, "_fire_action_email_bulk", lambda db_, key, recipients, ctx: sent.setdefault(
        "email", []).append((key, sorted(recipients), ctx["change"])))
    DELIVER([{"event": "granted", "holder_id": str(people.uma.id), "holder": "uma", "by": "bob",
              "proposed_by": "ada", "expires_at": "2027-10-06T00:00:00Z"}])
    expected = sorted(str(u.id) for u in (people.ada, people.bob, people.uma))
    assert sent["app"] == [(expected, "auditor_right", "Auditor right granted", "#compliance")]
    key, recipients, change = sent["email"][0]
    assert key == "auditor_right" and change.startswith("uma now holds the auditor right")
    assert recipients == sorted((u.email, u.username) for u in (people.ada, people.bob, people.uma))


@pytest.mark.parametrize("event", ["proposed", "granted", "rejected", "revoked", "lapsed", "expired", "suspended",
                                   "ended", "reconfirmed"])
def test_each_notice_says_who_and_what_in_plain_words(event):
    title, body = rights.notice_text({"event": event, "holder": "uma", "by": "bob", "proposed_by": "ada",
                                      "lapses_at": "2026-10-13T00:00:00Z", "expires_at": "2027-10-06T00:00:00Z"})
    assert title.startswith("Auditor right") and "uma" in body
    assert "operator" in rights.notice_text({"event": "granted", "holder": "uma", "by": cc.HOST_OPERATOR})[1]
