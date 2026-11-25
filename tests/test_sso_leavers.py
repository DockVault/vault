"""A person who has left: what stops working when the identity provider no longer vouches for them.

Two rules. An account made at its first sign-in through a provider signs in only through its provider, whatever the
provider's password setting, unless the provider lets such accounts set a password (app/core/sso_only.py). And an
account whose sign-in through its provider has lapsed, or that the provider refused, is refused every way in that
goes through no provider, where the provider says so, as it does unless an administrator turns that off
(app/services/sso_freshness.py): the password on the web and over SFTP, a passkey by itself, "Stay signed in" on a
session no provider made, and an SFTP connection that is already open. Never an account that keeps a password of
its own (an administrator, a holder of the auditor right). Offline."""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import test_sso_freshness as fresh  # noqa: E402
from app.core import sso_policy  # noqa: E402
from app.core.models import ActiveSession, ExternalIdentity, SsoProvider, User  # noqa: E402
from app.services import sso_freshness as F  # noqa: E402
from test_sftp_policy_fails_closed import world  # noqa: E402,F401  (a fixture)
from test_sso_freshness import DAY, NOW, told  # noqa: E402,F401  (told: a fixture)
from test_sso_resolution import JIT, Resolving, _sign_in  # noqa: E402
from test_sso_sign_in import DB, _identity, _provider, _user  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _an_address_single_sign_on_can_use(monkeypatch):
    """The vault's address can carry single sign-on, so the sign-in page shows the providers' buttons, and the
    sentences here name them. Without such an address no provider is available, and none is named
    (tests/test_sso_freshness.py, tests/test_sso_only.py)."""
    from app.services import sso_sign_in
    monkeypatch.setattr(sso_sign_in, "address_refusal", lambda: None)

LONG_AGO = timedelta(days=40)          # past the thirty days a provider asks for unless it says otherwise
# Said of the provider as its button names it ({0}).
NOT_AVAILABLE = ("Your account signs in only through {0} until it has signed in there again, and {0} is not "
                 "available on this vault right now. Ask your administrator.")


def _world(*, policy=None, role="user", signed_in=None, refused=None, state="enabled", linked_by="self", **account):
    """One account linked to one provider, its last sign-in there forty days ago unless the test says otherwise."""
    alice = _user(role=role, **account)
    p = _provider(policy=policy, state=state, name="Contoso")
    i = _identity(alice, p, linked_by=linked_by, refused_at=refused,
                  last_sign_in_at=signed_in if signed_in is not None else datetime.utcnow() - LONG_AGO)
    return alice, p, i, DB({User: [alice], SsoProvider: [p], ExternalIdentity: [i], ActiveSession: []})


# --------------------------------------------------------------------------- the two settings

def test_the_two_settings_as_they_stand_when_nothing_is_stored_and_what_a_save_may_hold():
    assert sso_policy.DEFAULTS["sso_jit_password"] is False and sso_policy.DEFAULTS["sso_lapse_ends_sign_in"] is True
    for stored in (None, {}, {"sso_jit_password": "yes", "sso_lapse_ends_sign_in": 0}):
        policy = sso_policy.effective(stored)
        assert policy["sso_jit_password"] is False and policy["sso_lapse_ends_sign_in"] is True, stored
    turned = sso_policy.effective({"sso_jit_password": True, "sso_lapse_ends_sign_in": False})
    assert turned["sso_jit_password"] is True and turned["sso_lapse_ends_sign_in"] is False
    assert sso_policy.validate({"sso_jit_password": True, "sso_lapse_ends_sign_in": False}) == {
        "sso_jit_password": True, "sso_lapse_ends_sign_in": False}
    for key in ("sso_jit_password", "sso_lapse_ends_sign_in"):
        with pytest.raises(sso_policy.PolicyInvalid) as refused:
            sso_policy.validate({key: "on"})
        assert refused.value.key == key
    from app.services import sso_providers
    assert sso_providers.LABELS["policy.sso_jit_password"] and sso_providers.LABELS["policy.sso_lapse_ends_sign_in"]


# --------------------------------------------------------------------------- an account whose provider sign-in lapsed

def test_a_missed_deadline_closes_the_other_ways_in_where_the_provider_says_so():
    alice, p, i, db = _world()
    held = F.held_to_a_provider(db, alice)
    assert held is not None and held.identity_id == str(i.id) and held.ends_sign_in is True and not held.refused
    # From the moment the days have run out, and not a second before.
    assert F.held_to_a_provider(db, alice, now=held.due) is not None
    assert F.held_to_a_provider(db, alice, now=held.due - timedelta(seconds=1)) is None
    # Inside the days: nothing is closed.
    i.last_sign_in_at = datetime.utcnow() - timedelta(days=29)
    assert F.held_to_a_provider(db, alice) is None
    i.last_sign_in_at = datetime.utcnow() - LONG_AGO
    # A provider that only pauses the keys: they pause, and the account is not held.
    p.policy = {"sso_lapse_ends_sign_in": False}
    assert F.held_to_a_provider(db, alice) is None and F.lapsed(db, alice.id) is not None
    assert F.deadlines(db, alice.id)[0].ends_sign_in is False
    # A stored value that is no switch is read as the setting stands by itself: on.
    p.policy = {"sso_lapse_ends_sign_in": "no"}
    assert F.held_to_a_provider(db, alice) is not None
    # The days turned off: only a refusal holds, at once, and a sign-in the provider admits answers it.
    p.policy = {"sso_freshness_days": 0}
    assert F.held_to_a_provider(db, alice) is None
    i.refused_at = datetime.utcnow() - timedelta(hours=1)
    assert F.held_to_a_provider(db, alice).refused is True
    i.last_sign_in_at = datetime.utcnow()
    assert F.held_to_a_provider(db, alice) is None
    # A refusal holds at once, also well inside the days.
    p.policy, i.last_sign_in_at = None, datetime.utcnow() - timedelta(days=1)
    held = F.held_to_a_provider(db, alice)
    assert held is not None and held.refused and held.due > datetime.utcnow()
    # While the provider is turned off its days close nothing (nobody can sign in through it); the keys still pause.
    i.last_sign_in_at, i.refused_at, p.policy = datetime.utcnow() - LONG_AGO, None, None
    for state in ("disabled", "draft"):
        p.state = state
        assert F.held_to_a_provider(db, alice) is None and F.lapsed(db, alice.id) is not None, state
        assert F.deadlines(db, alice.id)[0].provider_on is False
        assert F.closes_a_connection(db, alice, by_password=True) is False
        assert F.closes_a_connection(db, alice, by_password=False) is True
        assert F.closes_the_other_ways_in(db, alice, F.deadlines(db, alice.id)[0]) is False
    # Turned on again, the days count as they stand.
    p.state = "enabled"
    assert F.held_to_a_provider(db, alice) is not None and F.deadlines(db, alice.id)[0].provider_on is True
    # Nobody, and an account linked to nothing.
    assert F.held_to_a_provider(db, None) is None and F.held_to_a_provider(db, _user("bob")) is None


@pytest.mark.parametrize("who", ["an administrator", "a holder of the auditor right"])
def test_an_account_that_keeps_a_password_of_its_own_is_never_held(monkeypatch, who):
    """Its keys pause as anybody's do; its password stays the way in while the provider cannot be reached."""
    from app.core import auditor_rights
    alice, p, i, db = _world(role="admin" if who == "an administrator" else "user")
    monkeypatch.setattr(auditor_rights, "_has_grants", lambda db: True)
    grant = types.SimpleNamespace(status="active") if who == "a holder of the auditor right" else None
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: grant)
    found = F.lapsed(db, alice.id)
    assert found is not None and found.ends_sign_in is True
    assert F.may_be_held(db, alice) is False
    assert F.held_to_a_provider(db, alice) is None and F.closes_the_other_ways_in(db, alice, found) is False
    assert F.closes_a_connection(db, alice, by_password=True) is False
    assert F.closes_a_connection(db, alice, by_password=False) is True
    assert "keeps a password of their own" in F.password_after_a_refusal(db, alice)


@pytest.mark.parametrize("status", ["proposed", "suspended"])
def test_a_proposal_for_the_auditor_right_or_a_right_that_is_suspended_exempts_nobody(monkeypatch, status):
    """Neither lets the account do anything yet that needs its password. Counted as exempt, an account with a
    proposal waiting unlinked its provider in one step, and after the proposal lapsed it was an ordinary account
    with no identity, which nothing holds. Held, told so, and asked for the provider's confirmation at an unlink:
    one rule for the three."""
    from app.core import auditor_rights, privileged_accounts
    from app.services import sso_sign_in as sso
    erin, p, i, db = _world()
    monkeypatch.setattr(auditor_rights, "_has_grants", lambda db: True)
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: types.SimpleNamespace(status=status))
    assert privileged_accounts.kind(db, erin) == privileged_accounts.AUDITOR_RIGHT       # still that, for a link
    found = F.lapsed(db, erin.id)
    assert F.may_be_held(db, erin) is True
    assert F.held_to_a_provider(db, erin) is not None and F.closes_the_other_ways_in(db, erin, found) is True
    assert F.closes_a_connection(db, erin, by_password=True) is True
    assert "no longer sign them in either" in F.password_after_a_refusal(db, erin)
    assert sso.unlink_asks_the_provider(db, erin, i, p) is True
    # With no grant at all, the same; with the right in force, none of it.
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: None)
    assert F.may_be_held(db, erin) is True and sso.unlink_asks_the_provider(db, erin, i, p) is True
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: types.SimpleNamespace(status="active"))
    assert F.may_be_held(db, erin) is False and F.held_to_a_provider(db, erin) is None
    assert sso.unlink_asks_the_provider(db, erin, i, p) is False
    assert F.may_be_held(db, None) is False                                   # nobody is nobody to hold
    # What the administrators are told of the password follows the same rule: an account with a proposal, on a
    # provider that only pauses keys, is told of as any ordinary account, not as one that keeps a password.
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: types.SimpleNamespace(status=status))
    frank, _p, _i, pauses = _world(policy={"sso_lapse_ends_sign_in": False})
    assert "does not close the other ways in" in F.password_after_a_refusal(pauses, frank)
    # Where the grants are not kept (a database from before them), nobody holds one: asked of a real session.
    session = types.SimpleNamespace(get_bind=lambda: None)
    monkeypatch.setattr(auditor_rights, "_has_grants", lambda db: False)
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: pytest.fail("no grants are kept"))
    assert F.may_be_held(session, erin) is True


def test_turning_a_provider_off_hands_nobody_a_password_back():
    """What held an account before the turn-off goes on holding it: a refusal, and days that had already run out,
    which the turn-off records as one (hold_lapsed). An account inside its days when the provider went off is not
    held however long it stays off, and is held by its days again from the moment it is turned on."""
    from app.services import sso_providers as providers
    lapsed, p, i, db = _world()
    fresh_one = _user("bob")
    j = _identity(fresh_one, p, subject="subject-2", last_sign_in_at=datetime.utcnow() - timedelta(days=20))
    refused_one = _user("carol")
    k = _identity(refused_one, p, subject="subject-3", last_sign_in_at=datetime.utcnow() - timedelta(days=2),
                  refused_at=datetime.utcnow() - timedelta(days=1))
    db.tables[User] += [fresh_one, refused_one]
    db.tables[ExternalIdentity] += [j, k]
    assert providers.hold_lapsed(db, p) == 1 and i.refused_at is not None
    assert getattr(j, "refused_at", None) is None
    p.state = "disabled"
    assert F.held_to_a_provider(db, lapsed).refused and F.held_to_a_provider(db, refused_one).refused
    assert F.way_in_text(db, F.held_to_a_provider(db, lapsed)) == NOT_AVAILABLE.format("Sign in with Contoso")
    assert F.held_to_a_provider(db, fresh_one) is None
    # Sixty days off: the account that was inside its days is still not held, though its keys have paused.
    later = datetime.utcnow() + timedelta(days=60)
    assert F.held_to_a_provider(db, fresh_one, now=later) is None and F.lapsed(db, fresh_one.id, now=later) is not None
    # Turned on then: its days count as they stand, and the administrator is told how many that is.
    p.state = "enabled"
    assert F.held_to_a_provider(db, fresh_one, now=later) is not None
    assert providers.due_at_turn_on(db, p, now=later) == 1 and providers.due_at_turn_on(db, p) == 0
    p.policy = {"sso_lapse_ends_sign_in": False}
    assert providers.due_at_turn_on(db, p, now=later) == 0


def test_the_provider_that_holds_the_account_is_the_one_it_is_told_about():
    """Each provider asks on its own. One that only pauses keys holds nobody, though its deadline was missed first."""
    alice, p, i, db = _world(policy={"sso_lapse_ends_sign_in": False})
    q = _provider(name="Fabrikam", label="Sign in with Fabrikam")
    j = _identity(alice, q, subject="subject-2", last_sign_in_at=datetime.utcnow() - timedelta(days=35))
    db.tables[SsoProvider].append(q)
    db.tables[ExternalIdentity].append(j)
    assert F.lapsed(db, alice.id).provider_id == str(p.id)
    held = F.held_to_a_provider(db, alice)
    assert held.provider_id == str(q.id) and held.provider_name == "Fabrikam"
    assert held.provider_label == "Sign in with Fabrikam"
    assert F.way_in_text(db, held).startswith("Sign in through Sign in with Fabrikam: ")
    # Of two that hold the account, the one whose days ran out first is named.
    r = _provider(name="Northwind", label="Sign in with Northwind")
    k = _identity(alice, r, subject="subject-3", last_sign_in_at=datetime.utcnow() - timedelta(days=31))
    db.tables[SsoProvider].append(r)
    db.tables[ExternalIdentity].append(k)
    assert F.held_to_a_provider(db, alice).provider_id == str(q.id)
    # Asked of one provider alone: the deadline kept there, when it is one that holds the account. The provider
    # that only pauses keys holds nobody, though the account is held (by another).
    assert F.held_to_a_provider(db, alice, provider_id=r.id).provider_id == str(r.id)
    assert F.held_to_a_provider(db, alice, provider_id=str(q.id)).provider_id == str(q.id)
    assert F.held_to_a_provider(db, alice, provider_id=p.id) is None


def test_what_the_person_is_told_names_the_provider_and_how_to_reach_it():
    alice, p, i, db = _world()
    held = F.held_to_a_provider(db, alice)
    assert F.way_in_text(db, held) == (
        "Sign in through Sign in with Contoso: your account has not signed in there within the time your "
        "organisation allows, so its password and passkeys do not sign it in until it does. Use the “Sign in with "
        "Contoso” button on the sign-in page.")
    p.show_on_sign_in = False
    assert F.way_in_text(db, held).endswith("until it does. Use the sign-in link your organisation gave you.")
    p.show_on_sign_in, p.label = True, ""
    assert F.way_in_text(db, held).endswith("Use the “Contoso” button on the sign-in page.")
    i.refused_at = datetime.utcnow()
    refused = F.held_to_a_provider(db, alice)
    # A hold on record is the provider's refusal, or the vault's own from a turn-off while the days had run out:
    # the row does not say which, and the sentence is true of both.
    assert refused.refused and F.way_in_text(db, refused) == (
        "Your account is held to a sign-in through Contoso: its password and passkeys do not sign it in until "
        "Contoso admits it. Use the “Contoso” button on the sign-in page. If Contoso does not admit you, ask your "
        "administrator.")
    assert "did not admit your account" not in F.way_in_text(db, refused)
    p.show_on_sign_in = False
    assert "Use the sign-in link your organisation gave you. If Contoso does not admit you" in F.way_in_text(db, refused)
    p.show_on_sign_in = True
    # A provider that is off sends nobody to a button that is not there (an account held before it went off).
    p.state = "disabled"
    gone = NOT_AVAILABLE.format("Contoso")              # (its button has shown its name since the label went)
    assert F.way_in_text(db, held) == gone and F.way_in_text(db, refused) == gone
    p.state = "draft"                                    # nor one that is not finished
    assert F.way_in_text(db, refused) == gone
    db.tables[SsoProvider].clear()                       # no row to read: the name the deadline carries
    assert F.way_in_text(db, held) == NOT_AVAILABLE.format(held.provider_label)


def test_the_person_is_told_of_another_provider_of_theirs_that_lets_them_in():
    """Dana is linked to Contoso, which refused her (or is off), and to Fabrikam, which is on. The door said "ask
    your administrator", though a sign-in through Fabrikam lets her in: a sign-in through any provider the account
    is linked to does. The sentence names that way. Not a provider that is off, one that refused her too, or one
    she is not linked to; and where the holding provider itself can be reached, it alone is named. Each is named
    as its button names it."""
    alice, p, i, db = _world()
    p.label = ""                                         # Contoso's button shows its name
    fabrikam = _provider(name="Fabrikam", label="Staff sign-in")
    adatum = _provider(name="Adatum", label="")
    fabrikam.id, adatum.id = uuid.uuid4(), uuid.uuid4()
    db.tables[SsoProvider].extend([fabrikam, adatum])
    hers = _identity(alice, fabrikam, subject="s-fab", last_sign_in_at=datetime.utcnow())
    db.tables[ExternalIdentity].append(hers)
    i.refused_at = datetime.utcnow()
    refused = F.held_to_a_provider(db, alice)
    assert refused.refused and refused.provider_id == str(p.id)
    assert F.way_in_text(db, refused) == (
        "Your account is held to a sign-in through Contoso: its password and passkeys do not sign it in until "
        "Contoso admits it. You can sign in through Staff sign-in instead: Use the “Staff sign-in” button on the "
        "sign-in page.")
    assert F.another_way_in(db, refused) == (
        "You can sign in through Staff sign-in instead: Use the “Staff sign-in” button on the sign-in page.")
    fabrikam.show_on_sign_in = False
    assert F.way_in_text(db, refused).endswith(
        "You can sign in through Staff sign-in instead: Use the sign-in link your organisation gave you.")
    fabrikam.show_on_sign_in = True
    # The holding provider off: the same way is named in the place of the administrator.
    p.state = "disabled"
    assert F.way_in_text(db, refused) == (
        "Your account signs in only through Contoso until it has signed in there again, and Contoso is not "
        "available on this vault right now. You can sign in through Staff sign-in instead: Use the “Staff sign-in” "
        "button on the sign-in page.")
    p.state = "enabled"
    # A provider she is not linked to is no way in, whatever its state and whoever else is linked to it.
    bob = _user(username="bob")
    db.tables[User].append(bob)
    db.tables[ExternalIdentity].append(_identity(bob, adatum, subject="s-bob", last_sign_in_at=datetime.utcnow()))
    assert "Adatum" not in F.way_in_text(db, refused)
    # Two ways: the first as their buttons name them, the same each time.
    also = _identity(alice, adatum, subject="s-ada", last_sign_in_at=datetime.utcnow())
    db.tables[ExternalIdentity].append(also)
    assert F.another_way_in(db, refused) == (
        "You can sign in through Adatum instead: Use the “Adatum” button on the sign-in page.")
    # One that is off, or that refused her too, is none.
    adatum.state = "disabled"
    assert F.another_way_in(db, refused).startswith("You can sign in through Staff sign-in instead")
    hers.refused_at = datetime.utcnow()
    assert F.another_way_in(db, refused) is None
    assert F.way_in_text(db, refused).endswith("If Contoso does not admit you, ask your administrator.")
    # A refusal she has answered since (Fabrikam refused her once and admitted her the next day) holds nobody:
    # Fabrikam lets her in, and is named.
    hers.refused_at = datetime.utcnow() - timedelta(days=2)
    hers.last_sign_in_at = datetime.utcnow() - timedelta(days=1)
    assert F.another_way_in(db, refused) == (
        "You can sign in through Fabrikam instead: Use the “Staff sign-in” button on the sign-in page.")
    hers.last_sign_in_at = datetime.utcnow()
    adatum.state, hers.refused_at = "enabled", None
    # Where the provider that holds the account can be reached, it is the one named, and no other.
    i.refused_at = None
    lapsed = F.held_to_a_provider(db, alice)
    assert lapsed is not None and not lapsed.refused
    said = F.way_in_text(db, lapsed)
    assert said.startswith("Sign in through Contoso: ") and "Staff sign-in" not in said and "Adatum" not in said


# --------------------------------------------------------------------------- the password door

def _door(monkeypatch, db):
    from app.core import sign_in_lockout
    from app.services import auth_service as A
    monkeypatch.setattr(A, "verify_password", lambda plain, hashed: plain == "pw")
    monkeypatch.setattr(A, "account_locked", lambda user: False)
    for name in ("release_expired", "lock_in_force", "count_at_limit", "clear_after_success"):
        monkeypatch.setattr(sign_in_lockout, name, lambda *a, **k: None)
    svc = A.AuthService(db)
    counted, made = [], []
    monkeypatch.setattr(svc, "_record_failed_login", lambda name, ip, user=None: counted.append(name))
    monkeypatch.setattr(svc, "_terminate_existing_sessions", lambda user_id, commit=True: None)
    monkeypatch.setattr(svc, "_create_session", lambda user, *a, **k: made.append(k.get("channel")) or "session-token")
    return A, svc, counted, made


def test_the_password_door_refuses_a_held_account_after_the_password_and_writes_no_session(monkeypatch):
    alice, p, i, db = _world()
    A, svc, counted, made = _door(monkeypatch, db)
    with pytest.raises(A.SignInThroughProviderError) as due:
        svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9")
    assert due.value.message == F.way_in_text(db, F.held_to_a_provider(db, alice)) and due.value.account is alice
    assert not isinstance(due.value, A.InvalidCredentialsError)          # no wrong credential: nothing counts it
    assert made == [] and counted == [] and ("commit",) in db.log
    # Before the password is right the door says what it says to anybody, and counts the guess.
    with pytest.raises(A.InvalidCredentialsError) as wrong:
        svc._authenticate_in_turn(alice, "alice", "nope", "203.0.113.9")
    assert str(wrong.value) == "Invalid username or password" and counted == ["alice"] and made == []
    # Over SFTP the same door.
    with pytest.raises(A.SignInThroughProviderError):
        svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9", channel=A.AuthService.SFTP)
    assert made == []
    # The password as a step of a provider's own sign-in is that sign-in, the way back.
    assert svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9", through_provider=True) == (alice, "session-token")
    assert made == [A.AuthService.WEB]
    # A provider that only pauses the keys leaves the password as it is.
    p.policy = {"sso_lapse_ends_sign_in": False}
    assert svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9")[1] == "session-token"
    # An account that is turned off is answered as one: its state comes first.
    p.policy, alice.is_active = None, False
    with pytest.raises(A.InvalidCredentialsError) as inactive:
        svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9")
    assert str(inactive.value) == "Account is not active"


def test_the_right_password_of_a_held_account_is_no_guess_for_the_throttle(monkeypatch):
    from app.core import sign_in_lockout
    alice, p, i, db = _world()
    A, svc, counted, made = _door(monkeypatch, db)
    given = []
    monkeypatch.setattr(svc, "_check_rate_limit", lambda name, ip: "the-charge")
    monkeypatch.setattr(svc, "_give_back", lambda charge: given.append(charge))
    monkeypatch.setattr(sign_in_lockout, "take_turn", lambda db, user_id: None)
    with pytest.raises(A.SignInThroughProviderError):
        svc.authenticate_user("alice", "pw", "203.0.113.9")
    assert given == ["the-charge"] and db.log[-1] == ("rollback",)
    with pytest.raises(A.InvalidCredentialsError):
        svc.authenticate_user("alice", "nope", "203.0.113.9")
    assert given == ["the-charge"]                                       # a wrong password keeps its charge


# --------------------------------------------------------------------------- every other proof without a provider

def test_a_passkey_by_itself_and_any_proof_that_came_through_no_provider_is_refused(monkeypatch):
    """Where a sign-in is finished, held for a step, written in the account's turn and where a factor is set up at
    a held sign-in, one rule is asked (refuse_without_the_provider): the passkey door and every held step meet it."""
    from app.api import api_server as api
    from app.services import sign_in
    alice, p, i, db = _world()
    seen, dropped = [], []

    class _Audit:
        def __init__(self, db):
            pass

        def log_login_failure(self, username, ip, reason, *, account=None, login_identifier="username"):
            seen.append((username, reason, login_identifier, account))

    monkeypatch.setattr(api, "AuditLogger", _Audit)
    monkeypatch.setattr(sign_in, "delete_session_by_token", lambda db, token: dropped.append(token))
    text = F.way_in_text(db, F.held_to_a_provider(db, alice))
    key = sign_in.SignInResult(alice, [sign_in.HARDWARE_KEY], "203.0.113.9", user_verified=True,
                               passwordless_allowed=True)
    with pytest.raises(sign_in.ProviderOnly) as refused:
        sign_in.refuse_without_the_provider(db, key)
    assert refused.value.status_code == 403 and refused.value.detail == text
    assert seen == [("alice", sign_in.PROVIDER_DUE_REASON, "passkey", alice)] and dropped == []
    # A session the proof made (the password door's own) goes with the refusal.
    form = sign_in.SignInResult(alice, [sign_in.PASSWORD], "203.0.113.9", session_token="made-by-the-door")
    with pytest.raises(sign_in.ProviderOnly):
        sign_in.refuse_without_the_provider(db, form)
    assert dropped == ["made-by-the-door"] and form.session_token is None
    assert seen[-1][1:3] == (sign_in.PROVIDER_DUE_REASON, "username")
    # What came through a provider is the provider's sign-in; a temporary credential has its own rule.
    through = sign_in.SignInResult(alice, [], "203.0.113.9", provider_id=str(p.id))
    temporary = sign_in.SignInResult(alice, [sign_in.PASSWORD], "203.0.113.9", is_temporary=True)
    assert sign_in.refuse_without_the_provider(db, through) is None
    assert sign_in.refuse_without_the_provider(db, temporary) is None
    # A provider that only pauses the keys refuses no proof.
    p.policy = {"sso_lapse_ends_sign_in": False}
    assert sign_in.refuse_without_the_provider(db, key) is None and len(seen) == 2
    assert sign_in.PROVIDER_DUE_REASON != sign_in.PROVIDER_ONLY_REASON


# --------------------------------------------------------------------------- SFTP

def test_sftp_refuses_the_right_password_of_a_held_account_and_records_why(world, monkeypatch):  # noqa: F811
    import paramiko
    import test_sftp_policy_fails_closed as sftp_tests
    from app.services import sign_in
    from app.services.auth_service import SignInThroughProviderError
    S = sftp_tests.S
    world({"mfa_sftp_policy": "allow"})
    account = types.SimpleNamespace(username="alice")

    class _Refusing:
        def __init__(self, db):
            pass

        def authenticate_user(self, username, password, ip, **kw):
            raise SignInThroughProviderError("Sign in through Contoso.", account=account)

    monkeypatch.setattr(S, "AuthService", _Refusing)
    server = S.SFTPServer("203.0.113.9")
    assert server.check_auth_password("alice", "right-password") == paramiko.AUTH_FAILED
    assert server.user is None and server.session_token is None
    assert sftp_tests._Audit.calls[-1] == ("failure", "alice", sign_in.PROVIDER_DUE_REASON)


def test_an_open_sftp_connection_goes_no_further_once_what_made_it_would_be_refused(monkeypatch):
    """Asked on every operation, where the account's state is: a password's connection stops when the account is
    held to its provider, a key's and a temporary credential's when the account's keys pause."""
    from app.sftp import sftp_server as S
    alice, p, i, db = _world()
    monkeypatch.setattr(S, "_user_requires_temp_cred_for_sftp", lambda db, user, **kw: False)

    def principal(*, key=None, temporary=False):
        made_by = types.SimpleNamespace(_is_temp_session=temporary)
        server = types.SimpleNamespace(user_id=alice.id, user=made_by, _key_id=key, client_address="203.0.113.9")
        handler = types.SimpleNamespace(server=server, _SCOPE_ATTRS=("_is_temp_session",))
        return S.SFTPServerInterface._load_principal(handler, db)

    a_key = uuid.uuid4()
    assert principal() is None and principal(key=a_key) is None and principal(temporary=True) is None
    # The provider only pauses keys: the password's connection goes on, the other two do not.
    p.policy = {"sso_lapse_ends_sign_in": False}
    assert principal() is alice and principal(key=a_key) is None and principal(temporary=True) is None
    # Signed in through the provider again: everything goes on.
    p.policy, i.last_sign_in_at = None, datetime.utcnow()
    assert principal() is alice and principal(key=a_key) is alice and principal(temporary=True) is alice


def test_which_rule_an_open_connection_follows():
    alice, p, i, db = _world()
    assert F.closes_a_connection(db, alice, by_password=True) and F.closes_a_connection(db, alice, by_password=False)
    p.policy = {"sso_lapse_ends_sign_in": False}
    assert not F.closes_a_connection(db, alice, by_password=True) and F.closes_a_connection(db, alice, by_password=False)
    i.last_sign_in_at = datetime.utcnow()
    assert not F.closes_a_connection(db, alice, by_password=True)
    assert not F.closes_a_connection(db, alice, by_password=False)


# --------------------------------------------------------------------------- what people are told

def test_the_warning_and_the_notices_say_that_the_password_stops_too_where_it_does(told):  # noqa: F811
    admin = fresh._user("root")
    told.admins.append(admin)
    alice, carol = fresh._user("alice"), fresh._user("carol")
    p = fresh._provider(30)
    ia, ic = fresh._identity(alice, p, signed_in=NOW - 27 * DAY), fresh._identity(carol, p, signed_in=NOW - 31 * DAY)
    db = fresh._db([admin, alice, carol], [p], [ia, ic])
    assert F.sweep(db, NOW) == {"warned": 1, "lapsed": 1}
    due = (NOW + 3 * DAY).strftime("%d %B %Y, %H:%M UTC")
    warning, paused, wave = told.notices
    assert warning[3].startswith(f"Your password and passkeys stop signing you in on {due}, and your SSH keys")
    assert told.emails[0][2]["change"] == F.warning_text(F.deadlines(db, alice.id)[0], due, sign_in_too=True)
    assert "your password and passkeys stop signing you in then" in told.emails[0][2]["change"]
    assert paused[2] == "Sign in through contoso: nothing else signs you in now"
    how = F.how_to_sign_in(F.deadlines(db, carol.id)[0])
    assert paused[3] == F.LAPSE_MESSAGE_ALL.format(provider="contoso") + " " + how and "your password" in paused[3]
    assert "For 1 of them the password and passkeys no longer sign in either" in wave[3]
    assert [details["ends_sign_in"] for _, _, details in told.audits] == [True, True]
    # The two texts differ, so a person is never told the wrong one.
    found = F.deadlines(db, alice.id)[0]
    assert F.refusal_text(found) == F.LAPSE_MESSAGE.format(provider="contoso") != F.refusal_text(found, sign_in_too=True)
    assert F.warning_text(found, due) != F.warning_text(found, due, sign_in_too=True)


def test_the_administrators_are_told_how_many_of_a_wave_lost_their_password_too(told):  # noqa: F811
    """Three accounts pause in one pass: two users, whose password and passkeys stop with their keys, and an
    administrator, who keeps a password of their own and loses the keys alone. The administrators' notice counts
    the first two, not all three: said of all, it told them that an administrator could no longer sign in."""
    from app.core.models import RoleEnum
    admin = fresh._user("root")
    told.admins.append(admin)
    carol, dave = fresh._user("carol"), fresh._user("dave")
    boss = fresh._user("boss", role=RoleEnum.ADMIN)
    p = fresh._provider(30)
    lapsed = [fresh._identity(who, p, signed_in=NOW - 31 * DAY) for who in (carol, dave, boss)]
    db = fresh._db([admin, carol, dave, boss], [p], lapsed)
    assert F.sweep(db, NOW) == {"warned": 0, "lapsed": 3}
    wave = told.notices[-1]
    assert wave[2] == "3 account(s) paused for want of a provider sign-in"
    assert "For 2 of them the password and passkeys no longer sign in either" in wave[3]
    assert sorted(details["ends_sign_in"] for _, _, details in told.audits) == [False, True, True]
    # A wave of administrators alone: the sentence about passwords is left out.
    del told.notices[:], told.audits[:]
    other = fresh._user("chief", role=RoleEnum.ADMIN)
    db2 = fresh._db([admin, other], [p], [fresh._identity(other, p, signed_in=NOW - 31 * DAY)])
    assert F.sweep(db2, NOW) == {"warned": 0, "lapsed": 1}
    assert "no longer sign in either" not in told.notices[-1][3]


def test_the_decision_made_again_in_the_accounts_turn_is_told_of_the_link_being_made(monkeypatch):
    """A link settles the account before its identity is written: the rule is told of the provider being linked
    and of how the account came to it. Where a change is to be made the account's turn is taken and the decision
    made again in it, on the account as it then is. Made again without the provider, or without how the account
    came, the second decision found the account linked to nothing that holds it and changed nothing: an account
    made at its first sign-in was left with a password it may set, though its provider lets it set none."""
    from app.api import api_server as api
    from app.core import password_origin, privileged_accounts, sso_only
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    turns, made = [], []
    monkeypatch.setattr(api, "_sessions_turn", lambda db, user_id: turns.append(user_id))
    monkeypatch.setattr(sso_only, "make_sso_only", lambda db, user, **kw: made.append(user.username))
    for came_by in ("jit", "invitation"):
        alice, p = _user(password_hash="random-bytes"), _provider()
        password_origin.mark_nobody_knows(alice)
        nothing_linked = DB({User: [alice], SsoProvider: [p], ExternalIdentity: []})
        del turns[:], made[:]
        assert sso_only.settle(nothing_linked, alice, also=p, also_by=came_by) == sso_only.MADE, came_by
        assert turns == [alice.id] and made == [alice.username]
    # An account that linked itself to that provider is not held by it: nothing to change, and no turn taken.
    del turns[:], made[:]
    assert sso_only.settle(nothing_linked, alice, also=p, also_by="self") is None and turns == [] and made == []


def test_what_the_administrators_are_told_about_the_password_when_a_provider_refuses_a_person(monkeypatch):
    from app.core import auditor_rights
    refused_at = datetime.utcnow() - timedelta(hours=1)
    alice, p, i, db = _world(refused=refused_at)
    assert F.password_after_a_refusal(db, alice).startswith(" Their password and passkeys no longer sign them in either")
    p.policy = {"sso_lapse_ends_sign_in": False}
    said = F.password_after_a_refusal(db, alice)
    assert said.startswith(" Their password still signs them in to the web app: this provider does not close")
    p.policy = None
    alice.sso_only = True
    assert F.password_after_a_refusal(db, alice) == ""
    root, q, j, db2 = _world(role="admin", refused=refused_at)
    monkeypatch.setattr(auditor_rights, "_has_grants", lambda db: False)
    assert "an administrator or an auditor keeps a password of their own" in F.password_after_a_refusal(db2, root)


def test_a_sign_in_that_would_link_a_busy_account_says_that_signing_in_is_busy(monkeypatch):
    """A sign-in through a provider that would link the account by its address, while the account's turn is held
    by a change of it: the provider was reached and answered. The person is told that signing in is busy, in the
    words every other door uses, not that the provider could not be reached; nothing is linked."""
    from test_sso_sign_in import _call
    from app.services import oidc_client as oc
    from app.services import sign_in
    from app.services import sso_sign_in as sso
    bob = _user("bob")
    other = _provider(name="fabrikam", label="Sign in with Fabrikam",
                      policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [bob], [other])

    def busy(db, user):
        raise sso.Refusal(sso.BUSY, sso.ACCOUNT_BUSY)
    monkeypatch.setattr(sso, "decide_in_the_accounts_turn", busy)
    location, _ = _sign_in(h, other, sub="bob-at-fabrikam", email="bob@example.test")
    assert location == "/#sso-error=busy", location
    assert len(h.identities()) == 0
    assert [a for a in h.audits if a[0] == "sso_sign_in_refused"][-1][2]["reason"] == "busy"
    _status, body, _headers = _call(h.S, "GET", "/auth/sso/reasons")
    assert body["reasons"]["busy"] == sign_in.BUSY == "Signing in is busy right now. Try again in a moment."
    assert body["reasons"][oc.TEMPORARILY_UNAVAILABLE] == "The provider could not be reached. Try again in a moment."


def test_a_held_account_with_a_factor_of_its_own_is_told_that_it_is_held_not_to_use_its_password(monkeypatch):
    """An account with a second factor of its own is never linked by its address: it is told to sign in with its
    password and link from its profile. For an account that is held, both are refused: it is told that it is
    held, which is what it can act on. The hold is asked before the factor."""
    from app.services import sso_sign_in as sso
    bob = _user("bob")
    holding = _provider(name="contoso")
    other = _provider(name="fabrikam", label="Sign in with Fabrikam",
                      policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    held_by = _identity(bob, holding, subject="bob-at-contoso", last_sign_in_at=datetime.utcnow() - LONG_AGO)
    h = Resolving(monkeypatch, [bob], [holding, other], identities=[held_by])
    monkeypatch.setattr(sso, "set_up_its_own_factor", lambda db, user: True)
    assert F.held_to_a_provider(h.db, bob) is not None
    location, _ = _sign_in(h, other, sub="bob-at-fabrikam", email="bob@example.test")
    assert location == "/#sso-error=held_to_a_provider", location
    # Not held, the same account is sent to its profile, as before.
    held_by.last_sign_in_at = datetime.utcnow()
    location, _ = _sign_in(h, other, sub="bob-at-fabrikam", email="bob@example.test")
    assert location == "/#sso-error=" + sso.LINK_FROM_PROFILE, location


def test_a_held_account_is_not_linked_by_its_verified_email_at_another_provider(monkeypatch):
    """A second provider that links by a verified address would give a held account a way back in: the sign-in
    that made the link would finish as a provider's own. Refused where the link is decided, as the link from Your
    account is, with the reason in the record; an account that is not held is linked as before."""
    from app.services import sso_sign_in as sso
    bob, root = _user("bob"), _user("root", role="admin")
    holding = _provider(name="contoso")
    other = _provider(name="fabrikam", label="Sign in with Fabrikam",
                      policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    held_by = _identity(bob, holding, subject="bob-at-contoso", last_sign_in_at=datetime.utcnow() - LONG_AGO)
    h = Resolving(monkeypatch, [bob, root], [holding, other], identities=[held_by])
    assert F.held_to_a_provider(h.db, bob) is not None
    location, _ = _sign_in(h, other, sub="bob-at-fabrikam", email="bob@example.test")
    assert location == "/#sso-error=held_to_a_provider", location
    assert len(h.identities()) == 1
    assert [a for a in h.audits if a[0] == "sso_sign_in_refused"][-1][2]["reason"] == sso.HELD_TO_A_PROVIDER
    assert "signs in only through the sign-in it already uses" in sso.REASON_TEXTS[sso.HELD_TO_A_PROVIDER]
    # The owner is told what works: the holding provider first, in the words its own doors use, and only then the
    # link. Not "link it under Your account", which is refused for a held account, as its password is.
    (ids, title, body), = [n for n in h.notice_bodies if n[1].endswith("with your address was kept out")]
    assert ids == [str(bob.id)] and title == "A sign-in through Sign in with Fabrikam with your address was kept out"
    assert F.way_in_text(h.db, F.held_to_a_provider(h.db, bob)) in body
    assert "Once your account has signed in there, you can link Sign in with Fabrikam under Your account." in body
    assert "If that was you, link it there" not in body
    # The administrators are told: a person who can no longer sign in through one provider and tries another.
    (ids, title, body), = [n for n in h.notice_bodies if "tried to reach bob's account" in n[1]]
    assert ids == [str(root.id)] and "signs in only through contoso until it has signed in there again" in body
    assert "Nobody was signed in and nothing was linked." in body
    # What a test sign-in at that provider says of the same person.
    told = sso.would_do(h.db, other, types.SimpleNamespace(
        issuer=other.issuer, subject="bob-at-fabrikam", tenant_id=None, email="bob@example.test", email_verified=True,
        hosted_domain=None, groups=None, groups_overage=False, display_name=None, preferred_username=None))
    assert "signs in only through a provider it is already linked to" in told["would"], told
    # Inside its days at the first provider, the account is linked by its address as any other.
    held_by.last_sign_in_at = datetime.utcnow()
    location, _ = _sign_in(h, other, sub="bob-at-fabrikam", email="bob@example.test")
    assert location.startswith("/#sso="), location
    assert sorted(i.linked_by for i in h.identities()) == ["email", "self"]


# --------------------------------------------------------------------------- an account made at a first sign-in

@pytest.mark.parametrize("policy, provider_only", [
    ({}, True),
    ({"sso_jit_password": True}, False),
    ({"sso_jit_password": True, "sso_password_login": "disabled"}, True),
])
def test_an_account_made_at_a_first_sign_in_signs_in_only_through_its_provider_unless_the_provider_says_otherwise(
        monkeypatch, policy, provider_only):
    root = _user("root", role="admin")
    p = _provider(policy={**JIT, **policy})
    h = Resolving(monkeypatch, [root], [p])
    location, _ = _sign_in(h, p, preferred_username="alice.e")
    assert location.startswith("/#sso="), location
    (user,) = h.users_named("alice.e")
    (identity,) = h.identities()
    assert identity.linked_by == "jit"
    assert user.sso_only is provider_only and user.sftp_password_auth is (not provider_only)
    # The sign-in it was made at finishes, and the next one finds it as it was made.
    status, _body = h.finish(location)
    assert status == 200
    _sign_in(h, p, preferred_username="alice.e")
    assert user.sso_only is provider_only


def test_which_accounts_a_provider_holds_to_no_password():
    from app.core import password_origin, sso_only
    alice, p = _user(password_hash="random-bytes"), _provider()
    password_origin.mark_nobody_knows(alice)
    assert sso_only.MADE_AT_A_FIRST_SIGN_IN == "jit" and sso_only.MADE_BY_AN_INVITATION == "invitation"
    assert sso_only.MADE_THROUGH_THE_PROVIDER == ("jit", "invitation")
    # The accounts the provider made: at a first sign-in, or when an invitation was accepted through it. The
    # vault met their person through the provider alone, and their password is one nobody knows.
    for made in ("jit", "invitation"):
        assert sso_only.holds_to_no_password(p, alice, made) is True, made
    for by in ("self", "email", "admin", None):
        assert sso_only.holds_to_no_password(p, alice, by) is False, by
    p.policy = {"sso_jit_password": True}
    for made in ("jit", "invitation"):
        assert sso_only.holds_to_no_password(p, alice, made) is False and not sso_only.made_here_holds_no_password(p)
    p.policy = {"sso_jit_password": "yes"}                  # no switch: read as the setting stands by itself
    for made in ("jit", "invitation"):
        assert sso_only.holds_to_no_password(p, alice, made) is True, made
    # A password of its own, once it has one: the account is no longer held, whatever the setting says.
    alice.password_hash = "chosen-by-its-owner"
    for made in ("jit", "invitation"):
        assert sso_only.holds_to_no_password(p, alice, made) is False, made
    # A provider whose people hold no password holds everybody linked to it.
    p.policy = {"sso_password_login": "disabled", "sso_jit_password": True}
    assert sso_only.holds_to_no_password(p, alice, "self") is True


def test_a_link_tells_the_rule_how_the_account_came_to_the_provider(monkeypatch):
    """The identity being linked is not yet in the database when the rule is asked (nothing is flushed for it), so
    the rule is told of it, and of how it came: without that an account made at a first sign-in would be judged as
    linked to nothing."""
    from app.core import password_origin, privileged_accounts, sso_only
    from app.services import sso_sign_in as sso
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    alice, p = _user(password_hash="random-bytes"), _provider()
    password_origin.mark_nobody_knows(alice)
    nothing_linked = DB({User: [alice], SsoProvider: [p], ExternalIdentity: []})
    assert sso_only.should_be_sso_only(nothing_linked, alice) is False
    assert sso_only.should_be_sso_only(nothing_linked, alice, also=p, also_by="jit") is True
    assert sso_only.should_be_sso_only(nothing_linked, alice, also=p, also_by="invitation") is True
    assert sso_only.should_be_sso_only(nothing_linked, alice, also=p, also_by="self") is False
    assert sso_only.should_be_sso_only(nothing_linked, alice, also=p) is False
    # An account that must keep a password of its own is never held, however it came to the provider.
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: "administrator")
    for came_by in ("jit", "invitation"):
        assert sso_only.should_be_sso_only(nothing_linked, alice, also=p, also_by=came_by) is False, came_by
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    # ...and one already linked by an invitation is found held by the rule when its provider is saved.
    invited = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, provider_id=p.id, linked_by="invitation")
    linked = DB({User: [alice], SsoProvider: [p], ExternalIdentity: [invited]})
    assert sso_only.should_be_sso_only(linked, alice) is True
    p.policy = {"sso_jit_password": True}
    assert sso_only.should_be_sso_only(linked, alice) is False
    p.policy = None
    seen = []
    monkeypatch.setattr(sso_only, "settle", lambda db, user, **kw: seen.append(kw))
    monkeypatch.setattr(sso, "subject_owner", lambda db, row, answer: None)
    answer = types.SimpleNamespace(issuer="https://idp.example", subject="s", tenant_id=None, email=None,
                                   display_name=None)
    sso.link_identity(nothing_linked, p, alice, answer, linked_by="jit")
    assert seen == [{"also": p, "also_by": "jit", "keep_session": None}]


def _made_and_linked(monkeypatch):
    """Three accounts on one provider: one made at a first sign-in that never had a password, one made there that
    has set its own since, one that linked itself."""
    from app.api import api_server as api
    from app.core import password_origin, privileged_accounts, security
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    monkeypatch.setattr(api, "_sessions_turn", lambda db, user_id: None)
    made, own, linked = (_user("made", sso_only=True, password_hash="r1"), _user("own", password_hash="r2"),
                         _user("linked"))
    for user in (made, own):
        user.password_set_by, user.password_set_by_other_at = None, None
        password_origin.mark_nobody_knows(user)
    own.password_hash = "chosen-by-its-owner"
    p = _provider(state="disabled")
    rows = [_identity(made, p, subject="s1", linked_by="jit"), _identity(own, p, subject="s2", linked_by="jit"),
            _identity(linked, p, subject="s3")]
    db = DB({User: [made, own, linked], SsoProvider: [p], ExternalIdentity: rows, ActiveSession: []})
    return made, own, linked, p, db


def test_the_setting_settles_the_accounts_the_provider_made_both_ways(monkeypatch):
    from app.core import password_origin, sso_only
    made, own, linked, p, db = _made_and_linked(monkeypatch)
    assert sso_only.apply_password_login(db, p) == {"made_sso_only": [], "restored": []}
    p.policy = {"sso_jit_password": True}
    assert sso_only.apply_password_login(db, p) == {"made_sso_only": [], "restored": ["made"]}
    assert made.sso_only is False and password_origin.nobody_knows(made)          # nothing is minted
    p.policy = {"sso_jit_password": False}
    assert sso_only.apply_password_login(db, p) == {"made_sso_only": ["made"], "restored": []}
    assert made.sso_only is True and made.sftp_password_auth is False
    # A password a person set is theirs: turning the setting off again takes nothing from them.
    assert own.sso_only is False and own.password_hash == "chosen-by-its-owner" and linked.sso_only is False


def test_an_account_that_has_had_a_password_is_let_go_with_the_others_when_passwords_are_allowed_again(monkeypatch):
    """Made at a first sign-in, it set a password of its own. The provider's people then hold no password for a
    while. Allowed again, it is let go with the accounts that linked themselves: the rule for accounts made at a
    first sign-in was over for it the day it had a password, though that password is gone. The account that
    never had one stays held."""
    from app.core import password_origin, sso_only
    made, own, linked, p, db = _made_and_linked(monkeypatch)
    assert own.had_a_password_at is None
    p.policy = {"sso_password_login": "disabled"}
    assert sso_only.apply_password_login(db, p) == {"made_sso_only": ["linked", "own"], "restored": []}
    assert own.sso_only is True and password_origin.nobody_knows(own) and own.had_a_password_at is not None
    assert linked.had_a_password_at is not None and made.had_a_password_at is None
    first = own.had_a_password_at
    p.policy = {"sso_password_login": "allowed"}
    assert sso_only.apply_password_login(db, p) == {"made_sso_only": [], "restored": ["linked", "own"]}
    assert own.sso_only is False and password_origin.nobody_knows(own)            # nothing is minted
    assert made.sso_only is True and own.had_a_password_at == first               # the first time is kept
    # And again: an account restored with a password nobody knows is not taken for one that never had any.
    p.policy = {"sso_password_login": "disabled"}
    assert sso_only.apply_password_login(db, p)["made_sso_only"] == ["linked", "own"]
    p.policy = None
    assert sso_only.apply_password_login(db, p) == {"made_sso_only": [], "restored": ["linked", "own"]}
    assert own.had_a_password_at == first


def test_an_account_that_has_had_a_password_is_let_go_when_it_leaves_a_provider_without_passwords(monkeypatch):
    """The other way a password of its own goes: the account links a provider whose people hold none, and leaves
    it later."""
    from app.core import sso_only
    made, own, linked, p, db = _made_and_linked(monkeypatch)
    strict = _provider(name="strict", policy={"sso_password_login": "disabled"})
    db.rows_of(SsoProvider).append(strict)
    there = _identity(own, strict, subject="s-strict")
    db.rows_of(ExternalIdentity).append(there)
    assert sso_only.settle(db, own) == sso_only.MADE and own.had_a_password_at is not None
    assert sso_only.settle(db, own, without=there) == sso_only.RESTORED and own.sso_only is False
    # The account that never had a password, through the same two steps, stays held by the provider that made it.
    made.sso_only = False                                # as the provider's option left it for a while
    theirs = _identity(made, strict, subject="s-strict-2")
    db.rows_of(ExternalIdentity).append(theirs)
    assert sso_only.settle(db, made) == sso_only.MADE and made.had_a_password_at is None
    assert sso_only.settle(db, made, without=theirs) is None and made.sso_only is True


def test_that_an_account_has_had_a_password_is_recorded_where_one_somebody_knew_is_replaced(monkeypatch):
    from datetime import datetime
    from app.core import password_origin, privileged_accounts, security, sso_only
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    monkeypatch.setattr(sso_only, "end_sessions_no_provider_made", lambda db, user, keep=None: 0)
    at = datetime(2026, 11, 1, 12, 0, 0)
    # A password somebody could type: recorded once, and the first time stays.
    alice = _user("alice", password_hash="chosen")
    password_origin.note_it_was_known(alice, at)
    assert alice.had_a_password_at == at and password_origin.has_had_one(alice)
    password_origin.note_it_was_known(alice, datetime(2027, 1, 1))
    assert alice.had_a_password_at == at
    # One nobody knows: nothing to record, whatever replaces it.
    bob = _user("bob", password_hash="random")
    password_origin.mark_nobody_knows(bob)
    password_origin.note_it_was_known(bob, at)
    assert bob.had_a_password_at is None and not password_origin.has_had_one(bob)
    sso_only.make_sso_only(None, bob)
    sso_only.allow_password_sign_in(None, bob)
    assert bob.had_a_password_at is None
    # Each place that replaces a password asks before it writes the new hash.
    carol = _user("carol", password_hash="chosen")
    sso_only.make_sso_only(None, carol)
    assert carol.had_a_password_at is not None and password_origin.nobody_knows(carol)
    dave = _user("dave", password_hash="chosen", sso_only=True)          # flagged by an earlier release, with a password
    sso_only.allow_password_sign_in(None, dave)
    assert dave.had_a_password_at is not None
    erin = _user("erin", password_hash="chosen", sso_only=True)          # a privileged account keeps its password
    sso_only.allow_password_sign_in(None, erin, keep_password=True)
    assert erin.had_a_password_at is None and erin.password_hash == "chosen"
    # The rule asks both: the password is one nobody knows, and none somebody knew came before it.
    p = _provider()
    assert sso_only.holds_to_no_password(p, bob, "jit") is True
    assert sso_only.holds_to_no_password(p, carol, "jit") is False
    assert sso_only.holds_to_no_password(p, alice, "jit") is False


def test_a_save_of_the_setting_settles_the_linked_accounts(monkeypatch):
    from app.core import sso_only
    from app.services import sso_providers as providers
    made, own, linked, p, db = _made_and_linked(monkeypatch)
    settled = []
    monkeypatch.setattr(sso_only, "apply_password_login",
                        lambda db, row, **kw: settled.append(dict(row.policy)) or {"made_sso_only": [], "restored": ["made"]})
    monkeypatch.setattr(providers, "fingerprint", lambda row: "same")
    changes = {"policy": {"sso_jit_password": True}}
    outcome = providers.apply(db, p, changes, providers.check(db, p, changes, account_policy={}))
    assert settled == [{"sso_jit_password": True}]                 # asked with the row as it now stands
    assert outcome["restored"] == ["made"] and outcome["changed"] == ["policy.sso_jit_password"]
    # A setting that settles nobody asks nothing.
    changes = {"policy": {"sso_lapse_ends_sign_in": False}}
    outcome = providers.apply(db, p, changes, providers.check(db, p, changes, account_policy={}))
    assert len(settled) == 1 and outcome["changed"] == ["policy.sso_lapse_ends_sign_in"]


def test_a_provider_is_not_removed_over_accounts_it_made_and_holds_to_no_password(monkeypatch):
    from app.services import sso_providers as providers
    made, own, linked, p, db = _made_and_linked(monkeypatch)
    assert providers.made_here_and_held(db, p) == 1
    made.sso_only = False                      # not held in fact (promoted, say): not counted
    assert providers.made_here_and_held(db, p) == 0
    made.sso_only = True
    refusal = providers.remove_refusal(db, p)
    assert refusal.reason == providers.ONLY_WAY_IN
    assert str(refusal) == ("1 account made at a first sign-in through this provider holds no password because of "
                            "it. Let such accounts set a password first (Access), so they can set one.")
    # Once the provider lets them set one (the save settles them), nothing is in the way.
    p.policy = {"sso_jit_password": True}
    made.sso_only = False
    assert providers.made_here_and_held(db, p) == 0 and providers.remove_refusal(db, p) is None
    # A provider whose people hold no password is refused in its own words.
    p.policy = {"sso_password_login": "disabled"}
    made.sso_only = True
    assert providers.made_here_and_held(db, p) == 0
    assert "Allow password sign-in for this provider first" in str(providers.remove_refusal(db, p))


def test_an_account_made_at_a_first_sign_in_is_promoted_and_then_chooses_a_password(monkeypatch):
    """The promotion is an administrator's word for the person. The flag ends with it; the password stays the one
    nobody knows, marked as set by somebody else, which is what makes the promotion take it back: the sessions end
    and the person is sent a link to choose one. An account a provider holds to no password at all is refused."""
    import app.api.api_server as S
    from fastapi import HTTPException
    from app.core import admin_grants, auditor_rights, password_origin, security
    from app.services import sign_in
    monkeypatch.setattr(auditor_rights, "promotion_refusal", lambda db, user: None)
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    monkeypatch.setattr(S, "hash_password", lambda secret: "argon2:" + secret, raising=False)
    recorded, revoked, turns = [], [], []
    monkeypatch.setattr(admin_grants, "record", lambda db, user_id, **kw: recorded.append(user_id))
    monkeypatch.setattr(S, "_sessions_turn", lambda db, user_id: turns.append((user_id, users[user_id].sso_only)))
    monkeypatch.setattr(S, "_revoke_reset_links_outranked_by", lambda db, user, actor: None)
    monkeypatch.setattr(S, "_revoke_sessions", lambda db, **kw: revoked.append(kw["user_id"]) or 1)
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda db, user_id: 0)

    class _Audit:
        def __init__(self, db):
            pass

        def build_row(self, **kw):
            return types.SimpleNamespace(**kw)

    monkeypatch.setattr(S, "AuditLogger", _Audit)
    root = _user("root", role="admin")
    alice, p, i, db = _world(linked_by="jit", sso_only=True, password_set_by=None, password_set_by_other_at=None)
    users = {alice.id: alice}
    monkeypatch.setattr(db, "add", lambda row: None)
    from app.services import sign_in
    spent = []
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda session, user_id: spent.append(user_id))
    S._record_admin_grant(db, alice, by=root)
    assert recorded == [alice.id] and alice.sso_only is False
    assert turns[0] == (alice.id, True)                 # the account's turn, before the account was changed
    assert revoked == [alice.id] and spent == [alice.id]            # her sessions end with the promotion
    assert password_origin.nobody_knows(alice) and password_origin.is_set_by_other(alice)
    assert S._take_back_password_at_promotion(db, alice, by=root) == {"user_id": alice.id}
    assert revoked == [alice.id, alice.id]
    # Held by a provider whose people hold no password: an administrator needs one, so the setting changes first.
    bob, q, j, db2 = _world(policy={"sso_password_login": "disabled"}, username="bob", sso_only=True)
    users[bob.id] = bob
    with pytest.raises(HTTPException) as refused:
        S._record_admin_grant(db2, bob, by=root)
    assert refused.value.status_code == 409 and "allow password sign-in on the provider first" in refused.value.detail
    assert bob.sso_only is True and recorded == [alice.id]
    assert turns == [(alice.id, True), (bob.id, True)]        # the turn comes first, also where it is refused
    # An account that is not flagged takes the turn as every promotion does, and is changed in nothing.
    carol, r, k, db3 = _world(username="carol")
    users[carol.id] = carol
    before = carol.password_hash
    S._record_admin_grant(db3, carol, by=root)
    assert recorded == [alice.id, carol.id] and turns[-1] == (carol.id, False) and len(turns) == 3
    assert carol.password_hash == before


def test_the_provider_page_sends_both_settings():
    import pathlib
    page = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "settings-sso.js").read_text("utf-8")
    assert "sso_jit_password: madeHere.box.checked" in page and "tick('sso-jit-password'" in page
    assert "sso_lapse_ends_sign_in: lapse.box.checked" in page and "tick('sso-lapse'" in page
    assert "policy.sso_jit_password" in page and "policy.sso_lapse_ends_sign_in" in page


def test_the_host_tool_refuses_a_reset_for_a_provider_only_account_before_anything_is_written():
    """The account tool in the container, as it is written: an account that signs in only through its provider is
    refused a password reset in words, before the change is recorded or a link made; a refusal the web app's own
    code raises is answered as a refusal, not as a tool that stopped; and the account's view names its providers."""
    import inspect
    from fastapi import HTTPException
    from app.core import host_operator
    source = inspect.getsource(host_operator)
    reset = source[source.index('if args.action == "reset-password":'):source.index('if args.action == "unlock":')]
    assert reset.index('if getattr(user, "sso_only", False):') < reset.index(
        "return _refuse(PROVIDER_ONLY.format(name=user.username, remedy=sso_only.password_remedy(db, user)))") \
        < reset.index("api._credential_change(db, None, user, cc.PASSWORD") < reset.index("api._credential_change(db, None, user, cc.RESET_LINK")
    assert reset.count("except HTTPException as exc:\n                    db.rollback()\n                    return _refuse(_refusal_text(exc))") == 1
    assert reset.count("except HTTPException as exc:\n                db.rollback()\n                return _refuse(_refusal_text(exc))") == 1
    factor = source[source.index('if args.action == "reset-second-factor":'):source.index('return _refuse("Nothing to do.")')]
    assert "except HTTPException as exc:" in factor and '"sso_only": bool(getattr(user, "sso_only", False))' in factor
    said = host_operator.PROVIDER_ONLY.format(name="bob", remedy="allow password sign-in on Contoso")
    assert said.startswith("bob signs in only through its organisation's provider and holds no password")
    assert "An administrator can allow password sign-in on Contoso (Settings, Sign-in)" in said
    # A refusal's words, whatever shape the web app's code gave it.
    text = host_operator._refusal_text
    assert text(HTTPException(status_code=409, detail="No password to change.")) == "No password to change."
    assert text(HTTPException(status_code=409, detail={"reason": "x", "message": "Said in words."})) == "Said in words."
    assert text(HTTPException(status_code=409, detail={"reason": "only_a_reason"})) == "only_a_reason"
    import types
    assert text(types.SimpleNamespace(detail=None)) == "The change was refused. Nothing was changed."
    # What the tool shows of an account.
    from app.core.models import ExternalIdentity, SsoProvider
    from _memory_db import MemoryDB
    import uuid
    bob = types.SimpleNamespace(id=uuid.uuid4())
    on = types.SimpleNamespace(id=uuid.uuid4(), name="fabrikam", state="enabled")
    off = types.SimpleNamespace(id=uuid.uuid4(), name="Contoso", state="disabled")
    gone = uuid.uuid4()
    db = MemoryDB({SsoProvider: [on, off], ExternalIdentity: [
        types.SimpleNamespace(user_id=bob.id, provider_id=on.id), types.SimpleNamespace(user_id=bob.id, provider_id=off.id),
        types.SimpleNamespace(user_id=bob.id, provider_id=gone), types.SimpleNamespace(user_id=uuid.uuid4(), provider_id=on.id)]})
    assert host_operator.linked_providers(db, bob) == [{"name": "Contoso", "on": False}, {"name": "fabrikam", "on": True}]
    assert host_operator.linked_providers(MemoryDB({}), bob) == []
    described = inspect.getsource(host_operator._describe)
    assert '"sso_only": bool(getattr(user, "sso_only", False))' in described and '"providers": linked_providers(db, user)' in described


def test_no_reset_link_is_made_for_an_account_that_signs_in_only_through_its_provider(monkeypatch):
    """A reset link asked for an account while it could hold a password, held for a second administrator, and
    approved after its provider stopped passwords: the link was made, the change recorded and the person told,
    and the link then answered "invalid or expired". The change itself refuses, in the words the two routes
    that ask for a link use, and makes nothing. An account that may hold a password gets its link as before."""
    from fastapi import HTTPException
    from app.core import credential_changes as cc
    import app.api.api_server as S
    minted = []
    monkeypatch.setattr(S, "_mint_reset_link", lambda db, target, base_url, **kw: minted.append(target.username) or "the-link")
    monkeypatch.setattr(S, "_public_base_url", lambda: "https://vault.example.test")
    root = _user("root", role="admin")
    held, _p, _i, db = _world(sso_only=True)
    with pytest.raises(HTTPException) as refused:
        S._make_credential_change(db, cc.RESET_LINK, held, {"delivery": "copy"}, actor_id=root.id, actor_name="root")
    assert refused.value.status_code == 409 and minted == []
    assert refused.value.detail == (
        "This account signs in only through its organisation's provider and holds no password, so no reset link is "
        "made for it; allow password sign-in on its provider first.")
    # Emailed or copied: refused before either.
    with pytest.raises(HTTPException) as refused:
        S._make_credential_change(db, cc.RESET_LINK, held, {"delivery": "email"}, actor_id=root.id, actor_name="root")
    assert refused.value.status_code == 409 and minted == []
    free, _q, _j, db2 = _world(sso_only=False, username="bob")
    made = S._make_credential_change(db2, cc.RESET_LINK, free, {"delivery": "copy"}, actor_id=root.id, actor_name="root")
    assert minted == ["bob"] and made["reset_link"] == "the-link"
    # The two routes that ask for a link say the same sentence, and nothing else writes it.
    import inspect
    source = inspect.getsource(S)
    assert source.count("raise _no_reset_link_for_a_provider_only_account(db, ") == 3
    assert source.count("so no reset link \"\n        f\"is made for it") == 1


def test_a_refusal_names_what_would_let_this_account_hold_a_password(monkeypatch):
    """Every refusal for an account that signs in only through its provider said "allow password sign-in on the
    provider". For an account held only because a provider made it (at a first sign-in, or through an
    invitation), password sign-in on that provider is allowed already: the administrator found nothing to change.
    The refusal names the setting that holds this account: the provider's password sign-in, or its setting for
    the accounts it makes."""
    from fastapi import HTTPException
    import app.api.api_server as S
    from app.core import credential_changes as cc
    from app.core import host_operator, password_origin, sso_only
    monkeypatch.setattr(S, "_sessions_turn", lambda db, user_id: None)
    root = _user("root", role="admin")
    # Linked itself to a provider whose people hold no password.
    less, p_less, _i, db_less = _world(policy={"sso_password_login": "disabled"}, sso_only=True, username="less")
    assert sso_only.password_remedy(db_less, less) == "allow password sign-in on Contoso"
    # Made at its first sign-in through a provider that lets its people hold a password, with one nobody knows.
    for came_by in ("jit", "invitation"):
        made, p_made, _j, db_made = _world(linked_by=came_by, sso_only=True, username="made",
                                           password_hash="random-bytes")
        password_origin.mark_nobody_knows(made)
        assert sso_only.password_remedy(db_made, made) == (
            "let the accounts made through Contoso set a password (its setting for the accounts it makes)"), came_by
    # Flagged, and no provider that holds it is found (a state the next settle mends): the plain sentence.
    odd, _p, _k, db_odd = _world(sso_only=True, username="odd")
    assert sso_only.password_remedy(db_odd, odd) == "allow password sign-in on its provider"
    # A password set by an administrator, a reset link, SFTP password sign-in: each says the one for its account.
    with pytest.raises(HTTPException) as refused:
        S._make_credential_change(db_made, cc.PASSWORD, made, {"password_hash": "h"}, actor_id=root.id, actor_name="root")
    assert refused.value.detail == (
        "This account signs in only through its organisation's provider and holds no password; let the accounts "
        "made through Contoso set a password (its setting for the accounts it makes) first.")
    with pytest.raises(HTTPException) as refused:
        S._make_credential_change(db_less, cc.PASSWORD, less, {"password_hash": "h"}, actor_id=root.id, actor_name="root")
    assert refused.value.detail.endswith("holds no password; allow password sign-in on Contoso first.")
    with pytest.raises(HTTPException) as refused:
        S._make_credential_change(db_made, cc.RESET_LINK, made, {"delivery": "copy"}, actor_id=root.id, actor_name="root")
    assert refused.value.detail.endswith(
        "so no reset link is made for it; let the accounts made through Contoso set a password (its setting for "
        "the accounts it makes) first.")
    with pytest.raises(HTTPException) as refused:
        S._refuse_sftp_password_for_sso_only(db_made, made, True)
    assert refused.value.detail.endswith(
        "use an SSH key, or let the accounts made through Contoso set a password (its setting for the accounts it "
        "makes) first.")
    said = host_operator.PROVIDER_ONLY.format(name="made", remedy=sso_only.password_remedy(db_made, made))
    assert "An administrator can let the accounts made through Contoso set a password" in said
    # Two providers that hold it: both are named, each once.
    from app.core.models import ExternalIdentity, SsoProvider
    other = _provider(policy={"sso_password_login": "disabled"}, name="Fabrikam")
    other.id = uuid.uuid4()
    db_less.tables[SsoProvider].append(other)
    db_less.tables[ExternalIdentity].extend([_identity(less, other, subject="s-2"), _identity(less, p_less, subject="s-3")])
    assert sso_only.password_remedy(db_less, less) == "allow password sign-in on Contoso and Fabrikam"


def test_a_held_account_with_no_password_to_type_is_not_told_it_can_link_under_your_account(monkeypatch):
    """A sign-in through another provider carried the address of an account that is held to its own provider.
    Its owner is told what works. "You can link it under Your account" is true for an account with a password it
    can type: a link is started with that password. An account that signs in only through its provider was told
    the same, and never could."""
    from app.services import sign_in
    for types_one in (True, False):
        bob, root = _user("bob"), _user("root", role="admin")
        holding = _provider(name="contoso")
        other = _provider(name="fabrikam", label="Sign in with Fabrikam",
                          policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
        held_by = _identity(bob, holding, subject="bob-at-contoso", last_sign_in_at=datetime.utcnow() - LONG_AGO)
        h = Resolving(monkeypatch, [bob, root], [holding, other], identities=[held_by])
        monkeypatch.setattr(sign_in, "has_a_password_it_can_type", lambda user, _answer=types_one: _answer)
        location, _ = _sign_in(h, other, sub="bob-at-fabrikam", email="bob@example.test")
        assert location == "/#sso-error=held_to_a_provider", location
        (ids, title, body), = [n for n in h.notice_bodies if n[1].endswith("with your address was kept out")]
        said = "Once your account has signed in there, you can link Sign in with Fabrikam under Your account."
        assert (said in body) is types_one, body
        assert body.endswith("If it was not you, your address at Sign in with Fabrikam may be in someone else's "
                             "hands: tell an administrator.")
        assert "  " not in body
