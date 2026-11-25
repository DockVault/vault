"""A link and a change of what the link is decided on, made to meet (app/services/sso_sign_in.py link_identity,
decide_in_the_accounts_turn): the link takes the account's turn before it reads anything of the account, and
decides on the flag and the role as they are committed.

A provider's save that lets the account hold a password again, committed while the link waits: the link reads the
flag again and holds the account to the provider it links. Decided on the flag it read before, it changed nothing,
and the account stayed linked to a provider whose people hold no password with a password it could set again. A
promotion committed while the link waits: the link reads the role again and refuses a provider whose people hold
no password. Offline, on a database with every table; the turn itself is PostgreSQL's and is stood in for by what
runs when it is asked for. tests/test_sso_lock_order_live.py makes the two meet on PostgreSQL."""
import types
import uuid

import pytest

from test_password_origin import _user, api, world  # noqa: F401
from test_sso_unlink_meets_the_password_rule import _another, _as_left, db  # noqa: F401

pytestmark = pytest.mark.unit

NO_PASSWORDS = {"sso_password_login": "disabled"}


def _provider(db, name, policy=None):
    from app.core.models import SsoProvider
    row = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name=name, label=name.title(),
                      issuer=f"https://{name}.example/", client_id="c", client_secret_enc="e", policy=policy)
    db.add(row)
    db.flush()
    return row


def _answer(row, subject="s-new"):
    return types.SimpleNamespace(issuer=row.issuer, subject=subject, tenant_id=None, email=None, display_name=None)


def _held_by(db, provider):
    """Alice, linked to ``provider`` and held by it to no password."""
    from app.core import password_origin
    from app.core.models import ExternalIdentity
    alice = _user(db, "alice")
    alice.sso_only, alice.password_hash = True, "argon2:of-random-bytes"
    password_origin.mark_nobody_knows(alice)
    db.add(ExternalIdentity(user_id=alice.id, provider_id=provider.id, issuer=provider.issuer, subject="s-1",
                            subject_source="oidc:sub", linked_by="self"))
    db.commit()
    return alice


def test_a_restore_committed_while_the_link_waits_is_what_the_link_decides_on(db, world, monkeypatch):
    from app.core.models import SsoProvider, User
    from app.services import sso_sign_in as sso
    contoso, fabrikam = _provider(db, "contoso", NO_PASSWORDS), _provider(db, "fabrikam", NO_PASSWORDS)
    alice = _held_by(db, contoso)
    me = db.query(User).filter(User.id == alice.id).first()         # the request's own read: held
    assert me.sso_only is True
    turns = []

    def the_save_commits_while_the_link_waits(session, owner):
        turns.append(str(owner))
        if len(turns) > 1:
            return
        # An administrator allowed passwords again for Contoso: the save held Alice's turn, found her linked to
        # Contoso alone and let her hold a password again. It commits, and the link is given the turn.
        other = _another(db)
        other.get(SsoProvider, contoso.id).policy = {"sso_password_login": "allowed"}
        other.get(User, alice.id).sso_only = False
        other.commit()
        other.close()
    monkeypatch.setattr(api, "_sessions_turn", the_save_commits_while_the_link_waits)
    sso.link_identity(db, db.get(SsoProvider, fabrikam.id), me, _answer(fabrikam), linked_by="self")
    db.commit()
    assert turns and turns[0] == str(alice.id)
    assert _as_left(db, alice) == (True, 2)              # linked to both, and held by the one she linked


def test_a_promotion_committed_while_the_link_waits_keeps_the_account_off_a_provider_without_passwords(
        db, world, monkeypatch):
    from app.core.models import RoleEnum, SsoProvider, User
    from app.services import sso_sign_in as sso
    fabrikam = _provider(db, "fabrikam", NO_PASSWORDS)
    alice = _user(db, "alice")
    db.commit()
    me = db.query(User).filter(User.id == alice.id).first()
    assert me.role == RoleEnum.USER

    def the_promotion_commits_while_the_link_waits(session, owner):
        other = _another(db)
        other.get(User, alice.id).role = RoleEnum.ADMIN
        other.commit()
        other.close()
    monkeypatch.setattr(api, "_sessions_turn", the_promotion_commits_while_the_link_waits)
    with pytest.raises(sso.Refusal) as refused:
        sso.link_identity(db, db.get(SsoProvider, fabrikam.id), me, _answer(fabrikam), linked_by="self")
    assert refused.value.code == sso.PRIVILEGED_ON_PASSWORD_LESS
    db.rollback()
    assert _as_left(db, alice) == (False, 0)             # an administrator, with her password, on no such provider


def test_the_turn_comes_before_anything_of_the_account_is_read_and_waits_a_short_time(db, world, monkeypatch):
    from app.core.models import SsoProvider, User
    from app.services import sign_in
    from app.services import sso_sign_in as sso
    fabrikam = _provider(db, "fabrikam", NO_PASSWORDS)
    alice = _user(db, "alice")
    db.commit()
    order = []
    monkeypatch.setattr(api, "_sessions_turn", lambda session, owner: order.append("the turn"))
    short = sign_in.with_a_short_wait
    monkeypatch.setattr(sign_in, "with_a_short_wait", lambda session, take: (
        order.append("a short wait"), short(session, take))[1])
    monkeypatch.setattr(sso, "_password_less_refusal", lambda session, row, user: order.append("the role is judged"))
    monkeypatch.setattr(sso, "subject_owner", lambda session, row, answer: order.append("the subject is looked up"))
    from app.core import sso_only
    monkeypatch.setattr(sso_only, "settle", lambda session, user, **kw: order.append("the rule is applied"))
    me = db.query(User).filter(User.id == alice.id).first()
    sso.link_identity(db, db.get(SsoProvider, fabrikam.id), me, _answer(fabrikam), linked_by="self")
    assert order == ["a short wait", "the turn", "the role is judged", "the subject is looked up",
                     "the rule is applied"], order
    # An account that is not written yet has no turn to take.
    del order[:]
    sso.decide_in_the_accounts_turn(db, types.SimpleNamespace(id=None))
    assert order == []


def test_a_turn_held_for_longer_than_a_link_waits_refuses_the_link_as_busy(db, world, monkeypatch):
    from sqlalchemy.exc import OperationalError
    from app.core.models import SsoProvider, User
    from app.services import oidc_client as oc
    from app.services import sso_sign_in as sso
    fabrikam = _provider(db, "fabrikam")
    alice = _user(db, "alice")
    db.commit()
    me = db.query(User).filter(User.id == alice.id).first()

    def held(code):
        def turn(session, owner):
            raise OperationalError("select", {}, types.SimpleNamespace(pgcode=code))
        return turn
    monkeypatch.setattr(api, "_sessions_turn", held("55P03"))                    # lock_not_available
    with pytest.raises(sso.Refusal) as refused:
        sso.link_identity(db, db.get(SsoProvider, fabrikam.id), me, _answer(fabrikam), linked_by="self")
    assert (refused.value.code, refused.value.detail) == ("busy", "account_busy")
    assert sso.BUSY == "busy" != oc.TEMPORARILY_UNAVAILABLE
    db.rollback()
    assert _as_left(db, alice) == (False, 0)
    # Anything else the database says is not a busy turn.
    monkeypatch.setattr(api, "_sessions_turn", held("40P01"))
    with pytest.raises(OperationalError):
        sso.link_identity(db, db.get(SsoProvider, fabrikam.id), me, _answer(fabrikam), linked_by="self")


def test_the_link_by_address_tells_that_the_password_stopped_from_the_flag_as_committed(db, world, monkeypatch):
    """The flag was read before the turn once: restored meanwhile and ended again by this link, the account was
    told nothing of a password that had just stopped working."""
    from app.core.models import SsoProvider, User
    from app.services import sso_sign_in as sso
    contoso, fabrikam = _provider(db, "contoso", NO_PASSWORDS), _provider(db, "fabrikam", NO_PASSWORDS)
    alice = _held_by(db, contoso)
    me = db.query(User).filter(User.id == alice.id).first()
    monkeypatch.setattr(sso, "_email_match", lambda session, row, answer, policy: me)
    turns = []

    def the_save_commits_while_the_link_waits(session, owner):
        turns.append(str(owner))
        if len(turns) > 1:
            return
        other = _another(db)
        other.get(SsoProvider, contoso.id).policy = {"sso_password_login": "allowed"}
        other.get(User, alice.id).sso_only = False
        other.commit()
        other.close()
    monkeypatch.setattr(api, "_sessions_turn", the_save_commits_while_the_link_waits)
    found = sso._link_by_email(db, db.get(SsoProvider, fabrikam.id), _answer(fabrikam), {})
    db.commit()
    assert found.linked_now is True and found.password_stopped is True
    assert _as_left(db, alice) == (True, 2)


def test_the_link_reads_again_the_flag_and_the_role_and_never_what_its_caller_has_just_set(db, world, monkeypatch):
    """What a link is decided on, read again in the turn: the flag and the role, and nothing else of the account
    (the password's mark is read again where the flag is settled, when a change is due). Each is left alone when
    the caller has set it and not written it yet: read again, the caller's change would be undone with no word."""
    import inspect
    from app.core import sso_only
    from app.core.models import RoleEnum, User
    from app.services import sso_sign_in as sso
    source = inspect.getsource(sso.decide_in_the_accounts_turn)
    assert 'sso_only.read_again(db, user, ["sso_only", "role"])' in source and "refresh(" not in source
    assert 'read_again(db, user, ["sso_only", "role", "password_hash", "password_nobody_knows", '            '"had_a_password_at"])' in inspect.getsource(sso_only.settle)
    alice = _user(db, "alice")
    db.commit()
    me = db.query(User).filter(User.id == alice.id).first()
    monkeypatch.setattr(api, "_sessions_turn", lambda session, owner: None)
    other = _another(db)
    theirs = other.get(User, alice.id)
    theirs.sso_only, theirs.role = True, RoleEnum.EXTERNAL
    other.commit()
    other.close()
    sso.decide_in_the_accounts_turn(db, me)
    assert me.sso_only is True and me.role == RoleEnum.EXTERNAL            # both as committed
    me.role = RoleEnum.ADMIN                                               # the caller's change, not written yet
    sso.decide_in_the_accounts_turn(db, me)
    assert me.role == RoleEnum.ADMIN and me.sso_only is True
