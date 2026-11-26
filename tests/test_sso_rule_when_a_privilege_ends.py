"""An account that stops being an administrator, or whose auditor grant ends, follows its providers' password rule
again (app/core/sso_only.py settle_when_a_privilege_ends, after_a_grant_ended; app/api/api_server.py _set_role;
app/core/auditor_rights.py).

An administrator and the holder of an auditor grant keep a password of their own whatever their providers say. An
account made at its first sign-in through a provider that lets such accounts set no password signs in only
through that provider; made an administrator, it loses the flag and is sent a link to choose a password. Demoted
before the person chose one, it was left with no flag and a password nobody knew: a reset link then gave whoever
asked for it a password, and the provider's word was no longer needed, for good. The demotion now settles the
rule in its own transaction, and the role it set stays as set: read again from the database there, it came back
as the administrator's, with the grant record and the permissions already gone. Offline, on a database with every
table. tests/test_sso_leavers_live.py does the promotion and the demotion on PostgreSQL."""
import contextlib
import uuid
from datetime import datetime, timedelta

import pytest

from test_password_origin import _user, api, world  # noqa: F401
from test_sso_unlink_meets_the_password_rule import _another, db  # noqa: F401

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _an_address_single_sign_on_can_use(monkeypatch):
    """The vault's address can carry single sign-on, so the sign-in page shows the providers' buttons, and the
    sentences here name them. Without such an address no provider is available, and none is named
    (tests/test_sso_freshness.py, tests/test_sso_only.py)."""
    from app.services import sso_sign_in
    monkeypatch.setattr(sso_sign_in, "address_refusal", lambda: None)

RANDOM = "argon2:of-random-bytes"


def _made_here(db, role, *, own_password=False, policy=None):
    """Jay, made at a first sign-in through Contoso, which lets such accounts set no password; with ``role``
    now, and (unless ``own_password``) the password nobody knows that a promotion leaves behind."""
    from app.core import password_origin
    from app.core.models import ExternalIdentity, SsoProvider
    provider = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name="contoso", label="Contoso",
                           issuer="https://idp.example/", client_id="c", client_secret_enc="e", policy=policy)
    db.add(provider)
    jay = _user(db, "jay", role)
    if not own_password:
        jay.password_hash = RANDOM
        password_origin.set_by_other(jay, None)
        password_origin.mark_nobody_knows(jay)
    db.add(ExternalIdentity(user_id=jay.id, provider_id=provider.id, issuer="https://idp.example/", subject="s-1",
                            subject_source="oidc:sub", linked_by="jit"))
    db.commit()
    return provider, jay


class _Told(list):
    """What each account was told, and beside it (``advice``) the advice each telling was given."""
    def __init__(self):
        super().__init__()
        self.advice = []


def _told(monkeypatch):
    from app.api import sso_providers_router
    told = _Told()

    def tell(users, title, change, advice=None):
        told.append((list(users), title, change))
        told.advice.append(advice)
    monkeypatch.setattr(sso_providers_router, "_tell_accounts", tell)
    return told


def _as_it_stands(db, account_id):
    from app.core import password_origin
    from app.core.models import User
    after = _another(db)
    try:
        account = after.get(User, account_id)
        return (account.role.value, bool(account.sso_only), password_origin.nobody_knows(account),
                account.sftp_password_auth)
    finally:
        after.close()


def _held_again_records(db, account_id) -> list:
    """What Activity holds of an account made to sign in only through its provider by a lost standing."""
    from app.core.models import AuditLog
    after = _another(db)
    try:
        rows = after.query(AuditLog).filter(AuditLog.action == "user_updated",
                                            AuditLog.resource_id == str(account_id)).all()
        return [dict(row.details) for row in rows if (row.details or {}).get("made_sso_only")]
    finally:
        after.close()


def test_a_demotion_holds_an_account_made_at_a_first_sign_in_to_its_provider_again_and_the_role_stays(
        db, world, monkeypatch):
    from app.core import sso_only
    from app.core.models import RoleEnum, User
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.ADMIN)
    root = _user(db, "root", RoleEnum.ADMIN)
    target = db.query(User).filter(User.id == jay.id).first()
    assert sso_only.should_be_sso_only(db, target) is False              # an administrator keeps a password
    api._set_role(db, target, RoleEnum.USER, actor=root)
    assert told == []                                                    # told once it is committed, not before
    db.commit()
    assert _as_it_stands(db, jay.id) == ("user", True, True, False)      # demoted, and held to Contoso again
    assert _held_again_records(db, jay.id) == [{"updated_username": "jay", "made_sso_only": True, "reason": "demoted"}]
    assert told == [([(jay.id, "jay", "jay@example.com")], "Your account signs in only through Contoso", (
        "Your account is no longer an administrator. It signs in only through Contoso from now on: its password "
        "and its SFTP password sign-in no longer work."))]


def test_a_demotion_of_a_turned_off_account_settles_it_and_tells_it_nothing(db, world, monkeypatch):
    """The account is turned off when it is demoted. It is held to its provider again all the same; told that
    "its password no longer works", by email to the address it holds, it was told of a password that signed it
    in nowhere already."""
    from app.core.models import RoleEnum, User
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.ADMIN)
    root = _user(db, "root", RoleEnum.ADMIN)
    target = db.query(User).filter(User.id == jay.id).first()
    target.is_active = False
    api._set_role(db, target, RoleEnum.USER, actor=root)
    db.commit()
    assert _as_it_stands(db, jay.id) == ("user", True, True, False)      # settled as any account is
    assert told == []


def test_a_demotion_that_is_rolled_back_changes_nothing_and_tells_nobody(db, world, monkeypatch):
    from app.core.models import RoleEnum, User
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.ADMIN)
    target = db.query(User).filter(User.id == jay.id).first()
    api._set_role(db, target, RoleEnum.USER, actor=None)
    db.rollback()
    assert _as_it_stands(db, jay.id)[:3] == ("admin", False, True) and told == []
    assert _held_again_records(db, jay.id) == []


@pytest.mark.parametrize("case", ["a password of its own", "the provider lets it set one", "linked by its owner",
                                  "to another role than an administrator's"])
def test_a_demotion_leaves_an_account_the_rule_does_not_hold(db, world, monkeypatch, case):
    from app.core.models import ExternalIdentity, RoleEnum, User
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.ADMIN if case != "to another role than an administrator's" else RoleEnum.USER,
                               own_password=case == "a password of its own",
                               policy={"sso_jit_password": True} if case == "the provider lets it set one" else None)
    if case == "linked by its owner":
        db.query(ExternalIdentity).update({"linked_by": "self"})
        db.commit()
    target = db.query(User).filter(User.id == jay.id).first()
    before = _as_it_stands(db, jay.id)
    api._set_role(db, target, RoleEnum.EXTERNAL if case == "to another role than an administrator's" else RoleEnum.USER,
                  actor=None)
    db.commit()
    after = _as_it_stands(db, jay.id)
    if case == "to another role than an administrator's":
        # No privilege ended: the rule is not asked here (it is asked where the account's links change).
        assert after == ("external",) + before[1:] and told == []
    else:
        assert after == ("user", False) + before[2:] and told == []


def test_what_the_caller_set_and_did_not_write_is_not_read_again(db, world):
    from app.core import sso_only
    from app.core.models import RoleEnum, User
    provider, jay = _made_here(db, RoleEnum.ADMIN)
    target = db.query(User).filter(User.id == jay.id).first()
    other = _another(db)
    other.get(User, jay.id).sso_only = True                              # committed by somebody else meanwhile
    other.commit()
    other.close()
    target.role = RoleEnum.USER                                          # set here, not written
    sso_only.read_again(db, target, ["sso_only", "role"])
    assert target.role == RoleEnum.USER and target.sso_only is True
    db.flush()                                                           # written: it is read again like the rest
    other = _another(db)
    other.close()
    sso_only.read_again(db, target, ["sso_only", "role"])
    assert target.role == RoleEnum.USER
    # A stand-in with no session behind it is left as it is.
    from types import SimpleNamespace
    sso_only.read_again(SimpleNamespace(), SimpleNamespace(role="x"), ["role"])


def _grant(db, account, status, **dates):
    from app.core.models import AuditorGrant
    grant = AuditorGrant(id=uuid.uuid4(), user_id=account.id, username_at_grant=account.username, status=status,
                         proposed_by_username="root", credential_changers=[], **dates)
    db.add(grant)
    db.commit()
    return grant


@pytest.fixture
def settled_after(db, monkeypatch):
    """The settling after a commit runs in a transaction of its own: on this test's database."""
    from app.core import after_commit, database
    from app.core import auditor_rights as rights
    from app.core import security

    @contextlib.contextmanager
    def fresh():
        session = _another(db)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    monkeypatch.setattr(database, "get_db_context", fresh)
    monkeypatch.setitem(after_commit._HANDLERS, rights._NOTICES, lambda notices: None)
    monkeypatch.setattr(security, "seal_case_field", lambda *a, **k: "sealed")


@pytest.mark.parametrize("how", ["revoked", "rejected", "ended", "lapsed", "expired"])
def test_an_auditor_grant_that_is_no_longer_open_has_the_rule_settled_once_it_is_committed(
        db, world, monkeypatch, settled_after, how):
    from app.core import after_commit, sso_only
    from app.core import auditor_rights as rights
    from app.core.models import RoleEnum, User
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.USER)
    root = _user(db, "root", RoleEnum.ADMIN)
    now = datetime.utcnow()
    long_ago = now - timedelta(days=3650)
    grant = _grant(db, jay, "proposed" if how in ("rejected", "lapsed") else "active",
                   proposed_at=long_ago if how == "lapsed" else now,
                   approved_at=long_ago if how == "expired" else (None if how in ("rejected", "lapsed") else now),
                   expires_at=now - timedelta(days=1) if how == "expired" else None)
    target = db.query(User).filter(User.id == jay.id).first()
    assert sso_only.should_be_sso_only(db, target) is False              # the grant keeps it a password of its own
    if how == "revoked":
        rights.revoke(db, grant, actor=root)
    elif how == "rejected":
        rights.reject(db, grant, rejecter=root, reason="not now")
    elif how == "ended":
        rights.end(db, grant, rights.SECOND_FACTOR)
    else:
        assert rights.end_due(db) == 1
    assert grant.status == how
    assert after_commit.pending(db, sso_only._GRANT_ENDED) == [str(jay.id)]
    assert _as_it_stands(db, jay.id)[:2] == ("user", False) and told == []      # nothing before the commit
    assert _held_again_records(db, jay.id) == []
    db.commit()
    assert _as_it_stands(db, jay.id) == ("user", True, True, False)
    assert _held_again_records(db, jay.id) == [
        {"updated_username": "jay", "made_sso_only": True, "reason": "auditor_right_ended"}]
    assert told == [([(jay.id, "jay", "jay@example.com")], "Your account signs in only through Contoso", (
        "Your account no longer holds the auditor right. It signs in only through Contoso from now on: its "
        "password and its SFTP password sign-in no longer work."))]
    # The right also ends with nobody's doing (it expired, or its proposal lapsed): the advice says what to do, and
    # not that an administrator made a change.
    assert told.advice == [sso_only.AUDITOR_RIGHT_ADVICE]
    assert "did not expect" not in sso_only.AUDITOR_RIGHT_ADVICE


def test_an_administrator_whose_auditor_grant_ends_keeps_its_password(db, world, monkeypatch, settled_after):
    from app.core import auditor_rights as rights
    from app.core.models import RoleEnum
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.ADMIN)
    grant = _grant(db, jay, "active", approved_at=datetime.utcnow())
    rights.revoke(db, grant, actor=None)
    db.commit()
    assert _as_it_stands(db, jay.id)[:3] == ("admin", False, True) and told == []
    assert _held_again_records(db, jay.id) == []


def test_a_grant_whose_end_is_rolled_back_settles_nothing(db, world, monkeypatch, settled_after):
    from app.core import after_commit, sso_only
    from app.core import auditor_rights as rights
    from app.core.models import RoleEnum
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.USER)
    grant = _grant(db, jay, "active", approved_at=datetime.utcnow())
    rights.revoke(db, grant, actor=None)
    db.rollback()
    assert after_commit.pending(db, sso_only._GRANT_ENDED) == []
    assert _as_it_stands(db, jay.id)[:2] == ("user", False) and told == []
    # A grant of an account that is gone asks for nothing.
    sso_only.after_a_grant_ended(db, None)
    assert after_commit.pending(db, sso_only._GRANT_ENDED) == []


def test_a_database_without_the_identity_tables_settles_nothing(monkeypatch):
    """A role is changed on every vault, also on a database built with only the tables a test needs: the rule
    asks nothing of one that links nobody to a provider."""
    from types import SimpleNamespace
    from app.core import sso_only, table_presence
    monkeypatch.setattr(table_presence, "has_table", lambda db, table: table != "external_identities")

    def settle(db, user, **kw):
        raise AssertionError("asked of a database without the tables")
    monkeypatch.setattr(sso_only, "settle", settle)
    assert sso_only.settle_when_a_privilege_ends(SimpleNamespace(info={}), SimpleNamespace(),
                                                 standing=sso_only.WAS_AN_ADMINISTRATOR) is None


def test_what_signs_in_between_a_grants_end_and_its_settling_is_settled_with_the_account(db, world, monkeypatch,
                                                                                         settled_after):
    """The grant's end commits, and the account's rule is settled a moment later, in a transaction of its own. A
    sign-in written in between meets an account that is neither privileged nor flagged yet. The settling that
    follows still flags the account, ends the session a password made and leaves the one that came through the
    provider."""
    from app.core import after_commit, sso_only
    from app.core import auditor_rights as rights
    from app.core.models import ActiveSession, RoleEnum, SsoSession, User
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.USER)
    grant = _grant(db, jay, "active", approved_at=datetime.utcnow())
    waiting = []
    monkeypatch.setitem(after_commit._HANDLERS, sso_only._GRANT_ENDED, lambda ids: waiting.extend(ids))
    rights.revoke(db, grant, actor=None)
    db.commit()
    assert waiting == [str(jay.id)] and _as_it_stands(db, jay.id)[:2] == ("user", False)       # the moment between
    # In that moment: a session through the provider, and one a password made.
    other = _another(db)
    through, by_password = (ActiveSession(id=uuid.uuid4(), session_token=uuid.uuid4().hex, user_id=jay.id,
                                          ip_address="192.0.2.9", is_active=True, revoked=False) for _ in range(2))
    other.add_all([through, by_password])
    other.flush()
    other.add(SsoSession(session_id=through.id, provider_id=provider.id, idp_sid="s-1", idp_sub="s-1"))
    other.commit()
    ids = {"through the provider": through.id, "by a password": by_password.id}
    other.close()
    ended = []
    monkeypatch.setattr(api, "_revoke_sessions", lambda session, **kw: ended.extend(kw.get("session_ids") or []) or 0)
    sso_only._settle_after_a_grant_ended(waiting)
    assert _as_it_stands(db, jay.id) == ("user", True, True, False)
    assert _held_again_records(db, jay.id) == [
        {"updated_username": "jay", "made_sso_only": True, "reason": "auditor_right_ended"}]
    assert ended == [ids["by a password"]]
    assert [title for _users, title, _change in told] == ["Your account signs in only through Contoso"]


def test_a_record_that_cannot_be_written_leaves_the_settling_as_it_is(db, world, monkeypatch):
    """The audit log cannot take the row. The account is held to its provider again all the same, and told: a
    lost standing is never left with a password of its own because its record failed."""
    from app.core import sso_only
    from app.core.models import RoleEnum, User
    from app.services import audit_logger
    told = _told(monkeypatch)
    provider, jay = _made_here(db, RoleEnum.ADMIN)
    root = _user(db, "root", RoleEnum.ADMIN)
    target = db.query(User).filter(User.id == jay.id).first()

    class Down:
        def __init__(self, db_):
            raise RuntimeError("the audit log is down")
    monkeypatch.setattr(audit_logger, "AuditLogger", Down)
    assert sso_only.settle_when_a_privilege_ends.__name__ == "settle_when_a_privilege_ends"
    target.role = RoleEnum.USER
    assert sso_only.settle_when_a_privilege_ends(db, target, standing=sso_only.WAS_AN_ADMINISTRATOR) == sso_only.MADE
    db.commit()
    assert _as_it_stands(db, jay.id)[1:] == (True, True, False) and len(told) == 1
    assert sso_only.DEMOTED == "demoted" and sso_only.AUDITOR_RIGHT_ENDED == "auditor_right_ended"
