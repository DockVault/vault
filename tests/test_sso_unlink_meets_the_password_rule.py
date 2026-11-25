"""An unlink and a change of the provider's password rule that meet (app/api/sso_router.py unlink_my_identity,
app/core/sso_only.py settle): whichever is given the account's turn second decides on what the first one left.

The rule saved first: the unlink, given the turn, reads the account as it is committed (held to no password now)
and refuses to remove its only way in. The unlink first: the settling of the rule takes the turn before it reads
the account's identities, finds none, and does not hold the account to no password. Either order used to leave an
account that signs in only through a provider and is linked to none, which nothing brought back. Offline, on a
database with every table; the turn itself is PostgreSQL's and is stood in for by what runs when it is asked for."""
import uuid

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from test_password_origin import _request, _user, api, world  # noqa: F401

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def _another(db):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=db.get_bind())()


def _linked(db, policy=None):
    """Alice, with a password of her own and one identity, on a provider that is on."""
    from app.core.models import ExternalIdentity, SsoProvider
    provider = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name="contoso", label="Contoso",
                           issuer="https://idp.example/", client_id="c", client_secret_enc="e", policy=policy)
    db.add(provider)
    alice = _user(db, "alice")
    identity = ExternalIdentity(user_id=alice.id, provider_id=provider.id, issuer="https://idp.example/",
                                subject="s-1", subject_source="oidc:sub", linked_by="self")
    db.add(identity)
    db.commit()
    return provider, alice, identity


def _as_left(db, alice):
    from app.core.models import ExternalIdentity, User
    after = _another(db)
    try:
        account = after.get(User, alice.id)
        return bool(account.sso_only), after.query(ExternalIdentity).filter(
            ExternalIdentity.user_id == alice.id).count()
    finally:
        after.close()


def test_the_rule_saved_while_the_unlink_waits_is_what_the_unlink_decides_on(db, world, monkeypatch):
    from app.api import sso_router
    from app.core import password_origin
    from app.core.models import SsoProvider, User
    from app.services import sign_in
    provider, alice, identity = _linked(db)
    # The request: the account is loaded in the request's session, as the check of the session does.
    me = db.query(User).filter(User.id == alice.id).first()
    assert sign_in.has_a_password_it_can_type(me)
    monkeypatch.setattr(sso_router, "_tell_owner", lambda *a, **k: None)
    monkeypatch.setattr(sso_router, "_audit", lambda *a, **k: None)
    turns = []

    def the_rule_commits_while_the_unlink_waits(session, owner):
        turns.append(str(owner))
        if len(turns) > 1:
            return
        # An administrator turned password sign-in off for the provider: its settling held Alice's turn and made
        # her account sign in only through it. It commits, and the unlink is given the turn.
        other = _another(db)
        account = other.get(User, alice.id)
        other.get(SsoProvider, provider.id).policy = {"sso_password_login": "disabled"}
        account.sso_only = True
        account.password_hash = "argon2:of-random-bytes"
        password_origin.mark_nobody_knows(account)
        other.commit()
        other.close()
    monkeypatch.setattr(api, "_sessions_turn", the_rule_commits_while_the_unlink_waits)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(sso_router.unlink_my_identity(identity_id=identity.id, request=_request(),
                                                    current_user=me, db=db))
    assert refused.value.status_code == 409, refused.value.detail
    assert "no other identity on a provider that is on can sign you in now" in refused.value.detail
    assert refused.value.detail.startswith("Your account signs in only through single sign-on")
    assert turns and turns[0] == str(alice.id)
    db.rollback()
    assert _as_left(db, alice) == (True, 1)              # held to no password, and still linked: a way in


def test_the_unlink_done_while_the_rule_waits_is_what_the_rule_settles_on(db, world, monkeypatch):
    from app.core import sso_only
    from app.core.models import ExternalIdentity, User
    provider, alice, identity = _linked(db, policy={"sso_password_login": "disabled"})
    saving = _another(db)
    target = saving.get(User, alice.id)
    assert sso_only.should_be_sso_only(saving, target) is True       # as the links stand before the unlink
    turns = []

    def the_unlink_commits_while_the_rule_waits(session, owner):
        turns.append(str(owner))
        if len(turns) > 1:
            return
        # Alice, who has a password, unlinked her only identity: the unlink held her turn. It commits, and the
        # settling of the rule is given the turn.
        other = _another(db)
        other.query(ExternalIdentity).filter(ExternalIdentity.id == identity.id).delete(synchronize_session=False)
        other.commit()
        other.close()
    monkeypatch.setattr(api, "_sessions_turn", the_unlink_commits_while_the_rule_waits)
    outcome = sso_only.settle(saving, target)
    saving.commit()
    saving.close()
    assert outcome is None and turns == [str(alice.id)], (outcome, turns)
    assert _as_left(db, alice) == (False, 0)             # her password still hers; linked to nothing, held by nothing


def test_an_account_not_yet_written_is_settled_without_a_turn(db, world, monkeypatch):
    """An account being made at its first sign-in has no id yet, and no sessions to take a turn at."""
    from types import SimpleNamespace
    from app.core import sso_only
    turns = []
    monkeypatch.setattr(api, "_sessions_turn", lambda session, owner: turns.append(owner))
    monkeypatch.setattr(sso_only, "should_be_sso_only", lambda *a, **k: False)
    assert sso_only.settle(db, SimpleNamespace(id=None, sso_only=False)) is None and turns == []


def test_an_account_whose_flag_already_says_what_its_links_say_is_settled_without_a_turn(db, world, monkeypatch):
    """A save settles every account linked to the provider. Where nothing is to change for an account, no turn is
    taken for it: a provider with thousands of accounts would otherwise hold thousands of turns to one commit."""
    from app.core import sso_only
    from app.core.models import User
    provider, alice, identity = _linked(db)                 # passwords allowed: she keeps hers, and is not held
    turns = []
    monkeypatch.setattr(api, "_sessions_turn", lambda session, owner: turns.append(str(owner)))
    assert sso_only.settle(db, db.get(User, alice.id)) is None and turns == []


def test_a_promotion_made_while_the_settling_waits_for_its_turn_is_what_it_decides_on(db, world, monkeypatch):
    """The rule's settling read Alice as a user. While it waits for her turn she is made an administrator, who
    must keep a password of her own. The decision is made again in the turn, on her role as it is committed: she
    is not held to no password. Decided on the role read before, an administrator was left with a password nobody
    knows until the next start."""
    from app.core import sso_only
    from app.core.models import User
    provider, alice, identity = _linked(db, policy={"sso_password_login": "disabled"})
    saving = _another(db)
    target = saving.get(User, alice.id)
    assert sso_only.should_be_sso_only(saving, target) is True
    turns = []

    def a_promotion_commits_while_the_rule_waits(session, owner):
        turns.append(str(owner))
        if len(turns) > 1:
            return
        other = _another(db)
        other.get(User, alice.id).role = api.RoleEnum.ADMIN
        other.commit()
        other.close()
    monkeypatch.setattr(api, "_sessions_turn", a_promotion_commits_while_the_rule_waits)
    outcome = sso_only.settle(saving, target)
    saving.commit()
    saving.close()
    assert outcome is None and turns == [str(alice.id)], (outcome, turns)
    assert _as_left(db, alice) == (False, 1)


def _quiet(monkeypatch):
    from app.api import sso_router
    monkeypatch.setattr(sso_router, "_tell_owner", lambda *a, **k: None)
    monkeypatch.setattr(sso_router, "_audit", lambda *a, **k: None)
    monkeypatch.setattr(api, "_sessions_turn", lambda session, owner: None)
    return sso_router


def test_the_identity_an_account_was_made_with_is_not_unlinked_by_its_owner_while_its_provider_holds_it(
        db, world, monkeypatch):
    """An account made at its first sign-in holds no password while the provider that made it says so. Its owner,
    who has linked another provider meanwhile, does not unlink the one that made it: the account would then be
    held by nothing, and could set itself a password. Once that provider lets such accounts set a password (the
    save settles them), the identity is unlinked as any other."""
    from app.core import password_origin
    from app.core.models import ExternalIdentity, SsoProvider, User
    sso_router = _quiet(monkeypatch)
    provider, alice, identity = _linked(db)
    identity.linked_by, alice.sso_only = "jit", True
    password_origin.set_by_other(alice, None)
    password_origin.mark_nobody_knows(alice)
    other = SsoProvider(id=uuid.uuid4(), state="enabled", kind="oidc", name="fabrikam", label="Fabrikam",
                        issuer="https://idp2.example/", client_id="c", client_secret_enc="e", policy=None)
    db.add(other)
    db.add(ExternalIdentity(user_id=alice.id, provider_id=other.id, issuer="https://idp2.example/", subject="s-2",
                            subject_source="oidc:sub", linked_by="email"))
    db.commit()
    me = db.query(User).filter(User.id == alice.id).first()
    with pytest.raises(HTTPException) as refused:
        run_coroutine(sso_router.unlink_my_identity(identity_id=identity.id, request=_request(),
                                                    current_user=me, db=db))
    assert refused.value.status_code == 409, refused.value.detail
    assert refused.value.detail.startswith("Your account was made at its first sign-in through Contoso, which stays")
    db.rollback()
    assert _as_left(db, alice) == (True, 2)
    # The provider lets the accounts it makes set a password, and its save has settled this one.
    provider.policy, me.sso_only = {"sso_jit_password": True, "sso_lapse_ends_sign_in": False}, None
    db.commit()
    run_coroutine(sso_router.unlink_my_identity(identity_id=identity.id, request=_request(), current_user=me, db=db))
    assert _as_left(db, alice) == (False, 1)


def test_an_account_held_to_its_providers_sign_in_adds_no_other_way_in(db, world, monkeypatch):
    """From a session its password made before the days ran out, a held account starts no link to another
    provider and finishes none: that provider's sign-in would let the person back in without the one that asks."""
    from datetime import datetime, timedelta
    from app.core.models import User
    from app.services import sso_freshness
    sso_router = _quiet(monkeypatch)
    provider, alice, identity = _linked(db)
    identity.last_sign_in_at = datetime.utcnow() - timedelta(days=40)
    db.commit()
    me = db.query(User).filter(User.id == alice.id).first()
    assert sso_freshness.held_to_a_provider(db, me) is not None
    for route, how in ((sso_router.start_link, {"provider_id": str(provider.id)}), (sso_router.finish_link, {})):
        with pytest.raises(HTTPException) as refused:
            run_coroutine(route(body=None, request=_request(), current_user=me, db=db, **how))
        assert refused.value.status_code == 409, (route.__name__, refused.value.detail)
        assert refused.value.detail["reason"] == "sso_sign_in_due"
        assert refused.value.detail["message"].startswith("Sign in through contoso: ")
    # Inside its days the account is not refused for that (the link then meets its own checks).
    identity.last_sign_in_at = datetime.utcnow()
    db.commit()
    for route, how in ((sso_router.start_link, {"provider_id": str(provider.id)}), (sso_router.finish_link, {})):
        with pytest.raises(Exception) as other:                   # noqa: PT011 -- whatever the link asks next
            run_coroutine(route(body=None, request=_request(), current_user=me, db=db, **how))
        assert "sso_sign_in_due" not in str(getattr(other.value, "detail", other.value)), route.__name__


def test_a_promotion_decides_on_the_flag_as_it_is_committed_when_its_turn_comes(db, world, monkeypatch):
    """An account made at a first sign-in is loaded while its provider lets such accounts set a password: not
    flagged. A save of that setting flags it and commits before the promotion's turn comes. The promotion reads
    the flag again in its turn and ends it. Decided on what was loaded, it wrote nothing to the flag, and left an
    administrator who signs in only through a provider, with a password nobody knows."""
    from app.core import password_origin
    from app.core.models import User
    provider, alice, identity = _linked(db)
    identity.linked_by = "jit"
    password_origin.set_by_other(alice, None)
    password_origin.mark_nobody_knows(alice)
    db.commit()
    me = db.query(User).filter(User.id == alice.id).first()
    assert not me.sso_only
    other = _another(db)
    other.get(User, alice.id).sso_only = True              # the save of the provider's setting, settled
    other.commit()
    other.close()
    api._record_admin_grant(db, me, by=None)
    db.commit()
    assert _as_left(db, alice) == (False, 1)
