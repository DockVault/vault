"""Whether an auditor's right is in force, computed on every request, and what suspends, ends and reconfirms it,
offline on a real database (app/core/auditor_rights.py: auditor_live, the hooks, settle, reconfirm; the
dependency require_live_auditor in app/api/compliance_router.py).

Each change to the holder's account suspends the right at once through a hook in the change's own transaction,
and every administrator and the holder are told: a change someone else makes to its sign-in details (a password,
a reset link, an email address, an SSH key), the account deactivated, locked by an administrator, demoted or
deleted, its role changed to one that may not hold the right. A second-factor reset or removal ends it: only a
new grant, by two people, gives it again. Each trigger is also refused with its hook removed: the computed check
reads the account as it stands, and the periodic job writes what the hook missed. Reconfirming takes the
holder's password and a code from the authenticator the right is bound to, after they set a password of their
own when an administrator set it.
"""
import ast
import inspect
import tempfile
import textwrap
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

from app.api import api_server as api  # noqa: E402
from app.api import compliance_router as cr  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import password_origin  # noqa: E402
from app.core.models import (AccountInvitation, AdminGrant, AuditLog, AuditorGrant, CredentialChange,  # noqa: E402
                             PasswordResetToken, RoleEnum, SecondFactorEnrollment, SecondFactorRecoveryCode, User,
                             UserSSHKey)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
OLD = timedelta(days=400)


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'live.db'}")
        copies = sa.MetaData()
        for model in (User, AdminGrant, CredentialChange, AuditLog, AuditorGrant, SecondFactorEnrollment,
                      SecondFactorRecoveryCode, UserSSHKey, AccountInvitation, PasswordResetToken):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def world(monkeypatch):
    """Stand-ins for what is not the database: what would be told, and sessions that would end."""
    out = SimpleNamespace(told=[])
    monkeypatch.setattr(rights, "deliver", lambda notices: out.told.extend(notices))
    monkeypatch.setattr(api, "_revoke_sessions", lambda db, **kw: 0)
    return out


@pytest.fixture
def settings(monkeypatch):
    values = {key: cs.current(key) for key in cs.KEYS}
    monkeypatch.setattr(cs, "current", lambda key: values[key])
    return values


@pytest.fixture
def no_hooks(monkeypatch):
    """Every hook removed: only the computed check and the periodic job remain."""
    for name in ("after_credential_change", "after_lost_standing", "after_own_factor_removed"):
        monkeypatch.setattr(rights, name, lambda *a, **k: None)


def _user(db, name, role=RoleEnum.USER, *, totp=True):
    u = User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
             is_locked=False)
    db.add(u)
    db.commit()
    if role == RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=rights.utcnow() - OLD)
    if totp:
        db.add(SecondFactorEnrollment(user_id=u.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()
    return u


@pytest.fixture
def held(db, settings, world):
    """uma (a user) holds the right: proposed by ada, approved by bob an hour ago."""
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN)
    uma = _user(db, "uma")
    grant = rights.propose(db, uma, proposer=ada, now=rights.utcnow() - timedelta(hours=2))
    rights.approve(db, grant, approver=bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    del world.told[:]
    return SimpleNamespace(ada=ada, bob=bob, uma=uma, grant=grant)


def _live(db, user):
    """The dependency a route an auditor uses depends on: the user, or the 403's reason."""
    try:
        cr.require_live_auditor(current_user=user, db=db)
        return None
    except HTTPException as refused:
        assert refused.status_code == 403
        return refused.detail["reason"]


def _rows(db, action):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == action).all()


def _status(db, grant):
    db.expire_all()
    return db.get(AuditorGrant, grant.id).status


# --------------------------------------------------------------------------- in force

def test_an_approved_grant_is_in_force(db, held):
    assert _live(db, held.uma) is None
    standing = rights.auditor_live(db, held.uma)
    assert standing.live and standing.grant.id == held.grant.id


def test_what_is_not_in_force(db, held, settings):
    assert _live(db, held.ada) == rights.NO_GRANT
    temp = SimpleNamespace(id=held.uma.id, _is_temp_session=True)
    assert rights.auditor_live(db, temp).reason == rights.TEMPORARY
    other = _user(db, "oli")
    rights.propose(db, other, proposer=held.ada)
    db.commit()
    assert _live(db, other) == rights.NOT_APPROVED


def test_compliance_access_off_is_a_suspension_computed_on_each_request(db, held, settings):
    settings[cs.ACCESS] = cs.DISABLED
    assert _live(db, held.uma) == rights.DISABLED
    rights.settle(db)
    db.commit()
    assert _status(db, held.grant) == "active", "nothing is written: turning it on again needs no migration"
    settings[cs.ACCESS] = cs.ENABLED
    assert _live(db, held.uma) is None


def test_a_grant_past_its_end_is_not_in_force(db, held):
    held.grant.expires_at = rights.utcnow() - timedelta(seconds=1)
    db.commit()
    assert _live(db, held.uma) == rights.EXPIRED


# --------------------------------------------------------------------------- each trigger, with and without its hook

def _set_password(db, h):
    api._apply_credential_change(db, cc.PASSWORD, h.uma, {"password_hash": "h"}, actor_id=h.ada.id, actor_name="ada")
    cc.record_made(db, kind=cc.PASSWORD, target_id=h.uma.id, requester_id=h.ada.id, requester_name="ada")


def _email(db, h):
    api._apply_credential_change(db, cc.EMAIL, h.uma, {"email": "new@example.test"}, actor_id=h.ada.id,
                                 actor_name="ada")
    cc.record_made(db, kind=cc.EMAIL, target_id=h.uma.id, requester_id=h.ada.id, requester_name="ada")


def _reset_link(db, h):
    api._apply_credential_change(db, cc.RESET_LINK, h.uma, {"delivery": "copy"}, actor_id=h.ada.id, actor_name="ada")
    cc.record_made(db, kind=cc.RESET_LINK, target_id=h.uma.id, requester_id=h.ada.id, requester_name="ada")


def _ssh_key(db, h):
    api._apply_credential_change(db, cc.SSH_KEY, h.uma, {"name": "k", "key_type": "ssh-ed25519",
                                                         "public_key": "ssh-ed25519 AAAA", "fingerprint": "SHA256:x"},
                                 actor_id=h.ada.id, actor_name="ada")


def _factor_reset(db, h):
    api._apply_credential_change(db, cc.SECOND_FACTOR, h.uma, {}, actor_id=h.ada.id, actor_name="ada")


def _host_factor_reset(db, h):
    api._apply_credential_change(db, cc.SECOND_FACTOR, h.uma, {}, actor_id=None, actor_name=cc.HOST_OPERATOR)


def _own_factor_removed(db, h):
    # What DELETE /users/me/second-factor does.
    db.query(SecondFactorRecoveryCode).filter(SecondFactorRecoveryCode.user_id == h.uma.id).delete()
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == h.uma.id).delete()
    rights.after_own_factor_removed(db, h.uma)


def _deactivated(db, h):
    api._account_lost_standing(db, h.uma, actor=h.ada, because="deactivated")
    h.uma.is_active = False


def _locked(db, h):
    api._account_lost_standing(db, h.uma, actor=h.ada, because="locked")
    h.uma.is_locked, h.uma.locked_until = True, None


def _demoted(db, h):
    # The holder is an administrator, demoted to a user.
    h.uma.role = RoleEnum.ADMIN
    h.grant.confirmed_role = "admin"
    db.commit()
    api._account_lost_standing(db, h.uma, actor=h.ada, because="demoted")
    h.uma.role = RoleEnum.USER


def _external(db, h):
    h.uma.role = RoleEnum.EXTERNAL


# (trigger, the reason a hook writes (None: no hook), the computed reason, whether the grant ends)
TRIGGERS = {
    "password set by an administrator": (_set_password, cc.PASSWORD, rights.PASSWORD_NOT_OWN, False),
    "email changed by an administrator": (_email, cc.EMAIL, rights.CREDENTIAL_CHANGE, False),
    "reset link made by an administrator": (_reset_link, cc.RESET_LINK, rights.CREDENTIAL_CHANGE, False),
    "SSH key added by an administrator": (_ssh_key, cc.SSH_KEY, rights.SSH_KEY, False),
    "second factor reset by an administrator": (_factor_reset, rights.FACTOR_RESET, rights.SECOND_FACTOR, True),
    "second factor reset on the host": (_host_factor_reset, rights.FACTOR_RESET, rights.SECOND_FACTOR, True),
    "second factor removed by its holder": (_own_factor_removed, rights.FACTOR_REMOVED, rights.SECOND_FACTOR, True),
    "deactivated": (_deactivated, "deactivated", rights.INACTIVE, False),
    "locked by an administrator": (_locked, "locked", rights.LOCKED, False),
    "demoted": (_demoted, "demoted", rights.DEMOTED, False),
    "made an external account": (_external, None, rights.ROLE, False),
}


@pytest.fixture
def links(monkeypatch):
    """A reset link is made without the reset machinery: its row is what counts."""
    def mint(db_, user, base_url, *, created_by_id, made_by_other=False):
        return "https://vault.example.test/?reset=x"
    monkeypatch.setattr(api, "_mint_reset_link", mint)
    monkeypatch.setattr(api, "_password_reset_policy", lambda db_: (True, 30))


@pytest.mark.parametrize("trigger", list(TRIGGERS))
def test_each_trigger_suspends_or_ends_the_right_at_once_and_tells(db, held, world, links, trigger):
    apply, written, _computed, ends = TRIGGERS[trigger]
    apply(db, held)
    db.commit()
    if written is None:
        assert _status(db, held.grant) == "active", "no hook: the computed check and the job cover it"
        assert _live(db, held.uma) is not None
        return
    assert _status(db, held.grant) == ("ended" if ends else "suspended")
    grant = db.get(AuditorGrant, held.grant.id)
    assert grant.suspend_reason == written
    assert _live(db, held.uma) is not None
    row = _rows(db, "auditor_suspended")[-1]
    assert row.details["reason"] == written and row.details["outcome"] == ("ended" if ends else "suspended")
    assert [n["event"] for n in world.told] == ["ended" if ends else "suspended"]
    assert world.told[0]["holder"] == "uma"


@pytest.mark.parametrize("trigger", list(TRIGGERS))
def test_each_trigger_is_refused_with_its_hook_removed_and_the_job_writes_it(db, held, world, links, no_hooks,
                                                                             trigger):
    apply, _written, computed, ends = TRIGGERS[trigger]
    apply(db, held)
    db.commit()
    assert _status(db, held.grant) == "active", "the hook is gone"
    assert _live(db, held.uma) == computed
    rights.settle(db)
    db.commit()
    assert _status(db, held.grant) == ("ended" if ends else "suspended")
    assert _live(db, held.uma) is not None


def test_a_deleted_account_ends_its_right_and_the_job_ends_one_the_hook_missed(db, held, world, no_hooks):
    other = _user(db, "oli")
    grant = rights.propose(db, other, proposer=held.ada)
    rights.approve(db, grant, approver=held.bob)
    db.commit()
    grant.user_id = None        # what the foreign key does when the account is deleted
    db.commit()
    rights.settle(db)
    db.commit()
    assert _status(db, grant) == "ended" and db.get(AuditorGrant, grant.id).suspend_reason == rights.DELETED


def test_deleting_the_holder_ends_the_right(db, held, world):
    api._account_lost_standing(db, held.uma, actor=held.ada, because="deleted")
    db.commit()
    assert _status(db, held.grant) == "ended" and db.get(AuditorGrant, held.grant.id).suspend_reason == rights.DELETED


def test_a_change_to_another_account_or_by_the_holder_suspends_nothing(db, held, world, links):
    api._apply_credential_change(db, cc.EMAIL, held.ada, {"email": "a2@example.test"}, actor_id=held.bob.id,
                                 actor_name="bob")
    held.uma.role = RoleEnum.ADMIN
    db.commit()
    # An administrator holder changing their own email through an administrator's route.
    api._apply_credential_change(db, cc.EMAIL, held.uma, {"email": "u2@example.test"}, actor_id=held.uma.id,
                                 actor_name="uma", for_someone_else=False)
    db.commit()
    assert _status(db, held.grant) == "active" and world.told == []
    assert db.get(AuditorGrant, held.grant.id).credential_changers == []


def test_whoever_changes_the_holders_sign_in_details_joins_the_grants_changers(db, held):
    _email(db, held)
    db.commit()
    changers = db.get(AuditorGrant, held.grant.id).credential_changers
    assert [(c["id"], c["name"], c["kind"]) for c in changers] == [(str(held.ada.id), "ada", cc.EMAIL)]


def test_a_held_change_adds_who_asked_and_who_approved(db, held):
    api._apply_credential_change(db, cc.EMAIL, held.uma, {"email": "z@example.test"}, actor_id=held.ada.id,
                                 actor_name="ada", link_maker_id=held.bob.id)
    api._apply_credential_change(db, cc.SSH_KEY, held.uma, {"name": "k2", "key_type": "ssh-ed25519",
                                                            "public_key": "ssh-ed25519 BBBB", "fingerprint": "SHA256:y"},
                                 actor_id=held.ada.id, actor_name="ada", link_maker_id=None)
    db.commit()
    changers = db.get(AuditorGrant, held.grant.id).credential_changers
    assert [(c["id"], c["name"]) for c in changers] == [
        (str(held.ada.id), "ada"), (str(held.bob.id), "bob"), (str(held.ada.id), "ada"), (None, cc.HOST_OPERATOR)]


def test_changes_to_a_proposal_join_its_changers_and_suspend_nothing(db, settings, world):
    ada, bob, uma = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN), _user(db, "uma")
    grant = rights.propose(db, uma, proposer=ada)
    db.commit()
    api._apply_credential_change(db, cc.EMAIL, uma, {"email": "q@example.test"}, actor_id=bob.id, actor_name="bob")
    db.commit()
    grant = db.get(AuditorGrant, grant.id)
    assert grant.status == "proposed" and [c["name"] for c in grant.credential_changers] == ["bob"]
    assert rights.approver_refusal(db, grant, bob) is not None, "the changer may not approve it"


def test_a_proposer_who_loses_standing_has_their_proposals_withdrawn(db, settings, world):
    ada, bob, uma = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob", RoleEnum.ADMIN), _user(db, "uma")
    grant = rights.propose(db, uma, proposer=ada)
    db.commit()
    api._account_lost_standing(db, ada, actor=bob, because="demoted")
    db.commit()
    grant = db.get(AuditorGrant, grant.id)
    assert grant.status == "revoked" and grant.revoked_by == bob.id
    assert _rows(db, "auditor_revoked")[0].details["withdrawn_because"] == "demoted"


# --------------------------------------------------------------------------- promotion

def test_an_auditor_is_not_made_an_administrator_while_the_deployment_forbids_it(db, held, settings):
    settings[cs.AUDITOR_NOT_ADMIN] = True
    with pytest.raises(HTTPException) as refused:
        api._record_admin_grant(db, held.uma, by=held.ada)
    assert refused.value.status_code == 409 and "Revoke the right first" in refused.value.detail
    assert db.get(AdminGrant, held.uma.id) is None
    other = _user(db, "oli")
    api._record_admin_grant(db, other, by=held.ada)
    assert db.get(AdminGrant, other.id) is not None
    settings[cs.AUDITOR_NOT_ADMIN] = False
    api._record_admin_grant(db, held.uma, by=held.ada)
    assert db.get(AdminGrant, held.uma.id) is not None


def test_an_administrator_holder_once_the_deployment_forbids_it_is_refused_and_suspended(db, held, settings):
    held.uma.role = RoleEnum.ADMIN
    held.grant.confirmed_role = "admin"
    db.commit()
    settings[cs.AUDITOR_NOT_ADMIN] = True
    assert _live(db, held.uma) == rights.ADMIN_NOT_ALLOWED
    rights.settle(db)
    db.commit()
    assert _status(db, held.grant) == "suspended"
    assert db.get(AuditorGrant, held.grant.id).suspend_reason == rights.ADMIN_NOT_ALLOWED


# --------------------------------------------------------------------------- reconfirming

@pytest.fixture
def steps(monkeypatch):
    asked = []
    monkeypatch.setattr(cr, "STEP_UP_GRANT_RECONFIRM", lambda db_, user, request: asked.append(user.username))
    return asked


def _reconfirm(db, grant, user):
    return cr.reconfirm_auditor_grant(grant.id, SimpleNamespace(headers={}, client=None), current_user=user, db=db)


def _refused(fn, *args, **kwargs):
    with pytest.raises(HTTPException) as refused:
        fn(*args, **kwargs)
    return refused.value


def test_after_an_email_change_the_holder_reconfirms_with_password_and_code(db, held, world, steps):
    _email(db, held)
    db.commit()
    assert _live(db, held.uma) == rights.SUSPENDED
    del world.told[:]
    out = _reconfirm(db, held.grant, held.uma)
    assert out["status"] == "active" and steps == ["uma"]
    assert _live(db, held.uma) is None, "the change before the reconfirmation no longer counts"
    assert _rows(db, "auditor_reconfirmed")[0].details["reason"] == cc.EMAIL
    assert [n["event"] for n in world.told] == ["reconfirmed"]


def test_after_an_administrator_set_the_password_the_holder_sets_their_own_first(db, held, steps):
    _set_password(db, held)
    db.commit()
    refused = _refused(_reconfirm, db, held.grant, held.uma)
    assert refused.status_code == 409 and refused.detail["reason"] == rights.PASSWORD_NOT_OWN
    assert steps == [], "no code is asked for while the password is not their own"
    assert _rows(db, "auditor_grant_refused")[0].details["action"] == "reconfirm"
    password_origin.set_by_self(held.uma)
    db.commit()
    assert _reconfirm(db, held.grant, held.uma)["status"] == "active"
    assert _live(db, held.uma) is None


def test_after_a_factor_reset_the_right_has_ended_and_cannot_be_reconfirmed(db, held, steps):
    _factor_reset(db, held)
    db.commit()
    db.add(SecondFactorEnrollment(user_id=held.uma.id, method="totp", secret_enc="new", status="active"))
    db.commit()
    assert _live(db, held.uma) == rights.NO_GRANT
    assert _refused(_reconfirm, db, held.grant, held.uma).detail["reason"] == rights.NOT_SUSPENDED
    assert steps == []


def test_a_new_authenticator_never_reconfirms_a_suspended_right(db, held, steps, no_hooks):
    _email(db, held)
    rights.suspend(db, db.get(AuditorGrant, held.grant.id), cc.EMAIL)
    db.query(SecondFactorEnrollment).filter(SecondFactorEnrollment.user_id == held.uma.id).delete()
    db.add(SecondFactorEnrollment(user_id=held.uma.id, method="totp", secret_enc="new", status="active"))
    db.commit()
    refused = _refused(_reconfirm, db, held.grant, held.uma)
    assert refused.detail["reason"] == rights.SECOND_FACTOR and steps == []


def test_after_reactivation_and_unlocking_the_holder_reconfirms(db, held, steps):
    _locked(db, held)
    db.commit()
    assert _refused(_reconfirm, db, held.grant, held.uma).detail["reason"] == rights.LOCKED
    held.uma.is_locked = False
    db.commit()
    assert _reconfirm(db, held.grant, held.uma)["status"] == "active"
    _deactivated(db, held)
    db.commit()
    assert _refused(_reconfirm, db, held.grant, held.uma).detail["reason"] == rights.INACTIVE
    held.uma.is_active = True
    db.commit()
    assert _reconfirm(db, held.grant, held.uma)["status"] == "active"


def test_a_demoted_holder_reconfirms_in_their_new_role(db, held, steps):
    _demoted(db, held)
    db.commit()
    assert _reconfirm(db, held.grant, held.uma)["status"] == "active"
    grant = db.get(AuditorGrant, held.grant.id)
    assert grant.confirmed_role == "user" and _live(db, held.uma) is None


def test_only_the_holder_reconfirms_and_only_a_suspended_right(db, held, steps):
    assert _refused(_reconfirm, db, held.grant, held.uma).detail["reason"] == rights.NOT_SUSPENDED
    _email(db, held)
    db.commit()
    assert _refused(_reconfirm, db, held.grant, held.ada).status_code == 404
    held.grant.expires_at = rights.utcnow() - timedelta(seconds=1)
    db.commit()
    assert _refused(_reconfirm, db, held.grant, held.uma).detail["reason"] == rights.EXPIRED


def test_what_changed_while_the_code_was_given_is_read_again(db, held, monkeypatch):
    _email(db, held)
    db.commit()

    def meanwhile(db_, user, request):
        held.uma.password_set_by_other_at = rights.utcnow()
        db_.commit()

    monkeypatch.setattr(cr, "STEP_UP_GRANT_RECONFIRM", meanwhile)
    assert _refused(_reconfirm, db, held.grant, held.uma).detail["reason"] == rights.PASSWORD_NOT_OWN
    assert _status(db, held.grant) == "suspended"


def test_the_callers_own_right_says_whether_it_is_in_force_and_how_to_reconfirm(db, held):
    me = cr.my_auditor_right(current_user=held.uma, db=db)["grant"]
    assert me["live"] is True and me["reason"] is None and me["may_reconfirm"] is False
    _set_password(db, held)
    db.commit()
    me = cr.my_auditor_right(current_user=held.uma, db=db)["grant"]
    assert me["live"] is False and me["status"] == "suspended" and me["may_reconfirm"] is False
    assert me["reconfirm_problem"]["reason"] == rights.PASSWORD_NOT_OWN


# --------------------------------------------------------------------------- where the hooks are

def _calls(fn) -> set:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    return {(n.func.value.id if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) else None,
             n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None))
            for n in ast.walk(tree) if isinstance(n, ast.Call)}


def test_each_hook_is_called_where_the_change_is_made():
    assert ("auditor_rights", "after_credential_change") in _calls(api._apply_credential_change)
    assert ("auditor_rights", "after_lost_standing") in _calls(api._account_lost_standing)
    assert ("auditor_rights", "promotion_refusal") in _calls(api._record_admin_grant)
    assert ("auditor_rights", "after_own_factor_removed") in _calls(inspect.unwrap(api.disable_second_factor))
    # Every credential change goes through the wrapper: the change itself is called from nowhere else.
    callers = [path for path in (ROOT / "app").rglob("*.py")
               if "_make_credential_change(" in path.read_text(encoding="utf-8")]
    assert [p.name for p in callers] == ["api_server.py"]
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert source.count("_make_credential_change(") == 2      # its definition, and the wrapper's call


def _enrollment_deletions():
    """(file, function) of every place that deletes second-factor enrollments, and whether it deletes only
    unconfirmed ones."""
    found = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "delete"
                        and "SecondFactorEnrollment" in ast.unparse(node.func.value)):
                    found.append((path.name, fn.name, "unconfirmed" in ast.unparse(node.func.value)))
    return found


def test_every_deletion_of_a_second_factor_reaches_the_grant():
    """A grant is bound to an enrollment: whatever deletes an active one ends the grant through a hook (the
    computed check refuses it anyway)."""
    sites = {(f, fn) for f, fn, unconfirmed in _enrollment_deletions() if not unconfirmed}
    assert sites == {("api_server.py", "_make_credential_change"), ("api_server.py", "disable_second_factor")}
