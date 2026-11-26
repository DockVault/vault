"""Who the person is at the single sign-on callback (app/services/sso_sign_in.py, resolve_account): the provider's
restriction judged first for every purpose but a test; an invitation accepted through the provider (the start
carries it into the login state; the invited account is made at the callback with a password nobody knows and
this identity, and the invitation is claimed once); an existing account linked by its verified email when the
provider allows it and is restricted; every refusal in between; what a test sign-in says it would do; the words
the sign-in page fetches for each reason. Offline: fake stores, the records observed."""
import time
import types
import uuid
from datetime import datetime, timedelta
from urllib.parse import parse_qs

import pytest

from test_sso_sign_in import Harness, _call, _claims, _h, _identity, _provider, _user

pytestmark = pytest.mark.unit


class Resolving(Harness):
    """The sign-in harness plus the account-making machinery the memory store cannot run: the address lookups
    the database folds, the permission grants, the administrator's grant record and announcement, the password
    hash; an account policy of the test's choosing."""

    def __init__(self, monkeypatch, users, providers, identities=(), invitations=(), account_policy=None):
        super().__init__(monkeypatch, users, providers, identities=identities, invitations=invitations)
        S = self.S
        from app.core import email_identity, endpoint_permissions, security
        from app.core.models import SystemSetting, User

        def by_email(db, email):
            if not email:
                return None
            rows = [u for u in db.rows_of(User) if (u.email or "").lower() == email.strip().lower()]
            return rows[0] if len(rows) == 1 else None

        monkeypatch.setattr(email_identity, "find_user_by_email", by_email)
        monkeypatch.setattr(email_identity, "email_in_use", lambda db, email, exclude_user_id=None: any(
            (u.email or "").lower() == (email or "").strip().lower() for u in db.rows_of(User) if email))
        monkeypatch.setattr(S, "_email_has_pending_invite", lambda db, email: False)
        monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + _h(secret))
        self.grants, self.admin_grants, self.announcements = [], [], []
        monkeypatch.setattr(endpoint_permissions, "grant_default_permissions_for_role",
                            lambda user_id, role, db, commit=True: self.grants.append((user_id, str(role), commit)) or [])
        monkeypatch.setattr(S, "_record_admin_grant", lambda db, user, *, by, by_name=None, inherited=None: (
            self.admin_grants.append((user.username, by_name, inherited))))
        monkeypatch.setattr(S, "_announce_admin_granted", lambda db, user, *, by_name, how: (
            self.announcements.append((user.username, by_name, how))))
        if account_policy is not None:
            self.db.rows_of(SystemSetting).append(types.SimpleNamespace(key=S._SETTINGS_KEY, value=dict(account_policy)))

    def invite(self, username="newbie", role="user", email=None, created_by=None, **extra):
        """A pending invitation, as an administrator minted it: the token and the row."""
        from app.core import invitations
        from app.core.models import AccountInvitation
        token, prefix = invitations.mint_invite()
        fields = dict(id=uuid.uuid4(), username=username, email=email, role=role, token_prefix=prefix,
                      token_hash=invitations.hash_invite_token(token, self.S._invite_pepper()),
                      expires_at=datetime.utcnow() + timedelta(hours=24), accepted_at=None, accepted_user_id=None,
                      revoked_at=None, created_at=datetime.utcnow(), created_by=created_by, inviter_lineage=None)
        fields.update(extra)
        inv = types.SimpleNamespace(**fields)
        self.db.rows_of(AccountInvitation).append(inv)
        return token, inv

    def users_named(self, username):
        from app.core.models import User
        return [u for u in self.db.rows_of(User) if u.username == username]

    def codes(self):
        return [k for k in self.redis.rows if k.startswith("signin:code:") or k.startswith("sso:handover:")]


def _sign_in(h, p, token=None, **claims):
    """A start (with an invitation when given) and the callback: (location, the state's record)."""
    body = {"invitation": token} if token else {}
    status, out = h.start(p, **body)
    assert status == 200, out
    state, record = h.state_of(out["authorization_url"])
    h.claims_override = claims
    status, location, _ = h.callback(p, state)
    assert status == 302
    return location, record


def _accept(h, p, token, **claims):
    """An invitation accepted through the provider by the tab that started it: the start with the invitation, the
    callback (which writes nothing), and the code redeemed. (location, the state's record, the finish's answer)."""
    location, record = _sign_in(h, p, token, **claims)
    assert location.startswith("/#sso="), location
    status, body = h.finish(location)
    assert status == 200, body
    return location, record, body


# --------------------------------------------------------------------------- an invitation accepted through the provider

def test_an_invitation_is_accepted_through_the_provider(monkeypatch):
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id)
    location, record = _sign_in(h, p, token)
    assert record["extras"] == {"invitation_id": str(inv.id)} and "invite_accept_prefix" in h.limiter
    assert location.startswith("/#sso="), location
    # The callback wrote nothing: whoever reached it may be anybody the start address was handed to. The account
    # is made when the tab that started the sign-in redeems the code with its verifier.
    assert h.users_named("newbie") == [] and h.identities() == [] and inv.accepted_at is None
    assert ("commit",) not in h.db.log and h.emails == [] and h.grants == []
    assert not any(a[0] == "account_invitation_accepted" for a in h.audits)
    status, body = h.finish(location)
    assert status == 200, body
    (user,) = h.users_named("newbie")
    from app.core.models import RoleEnum
    assert user.role == RoleEnum.USER and user.email == "alice@example.test" and user.created_by == root.id
    # Made through the provider, with a password nobody knows: it signs in only through the provider, as the
    # accounts made at a first sign-in do, unless the provider lets the accounts it makes set a password.
    assert user.password_hash.startswith("argon2:") and user.sso_only is True and user.sftp_password_auth is False
    (identity,) = h.identities()
    assert identity.user_id == user.id and identity.linked_by == "invitation" and identity.subject == "subject-1"
    assert inv.accepted_at is not None and inv.accepted_user_id == user.id
    assert h.grants == [(str(user.id), str(user.role), False)] and h.admin_grants == []
    assert ("account_invitation_accepted", "success",
            {"username": "newbie", "role": str(user.role), "token_prefix": inv.token_prefix, "method": "sso",
             "provider_id": str(p.id)}) in h.audits, h.audits
    (identity,) = h.identities()
    # ("made_sso_only" in this record says that a password the account had was stopped by the link: this account
    # is new and had none, as one made at a first sign-in.)
    assert ("sso_identity_linked", "success", {"provider_id": str(p.id), "linked_by": "invitation",
                                               "identity_id": str(identity.id), "made_sso_only": False}) in h.audits
    assert ("account_welcome", "alice@example.test", None) in h.emails
    assert h.notices == []                                        # an invitation is the owner's own doing: no notice
    # Made, linked and claimed in one commit, and the same call signs the account in.
    assert ("commit",) in h.db.log
    assert _claims(body["access_token"])["sub"] == str(user.id) and ("login_success", "newbie", []) in h.audits
    # The code is spent with the acceptance: it makes nothing twice.
    assert h.finish(location)[0] == 401 and len(h.users_named("newbie")) == 1
    # The invitation is spent: the token starts nothing now.
    status, out = h.start(p, invitation=token)
    assert status == 404 and out["detail"]["reason"] == "invitation_unusable"


def test_the_callback_looks_at_an_invitation_and_the_acceptance_holds_what_it_decides_on(monkeypatch):
    """The look at the callback reads and holds nothing. The acceptance holds the inviter's row until it commits:
    an inviter demoted in between does not leave an account their invitation made."""
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id)
    held = []
    can_act = h.S._invitation_inviter_can_act
    monkeypatch.setattr(h.S, "_invitation_inviter_can_act",
                        lambda db, inv, lock=False: (held.append(lock), can_act(db, inv, lock=lock))[1])
    location, _ = _sign_in(h, p, token)
    assert held == [False, False]                        # the start's look and the callback's: neither holds
    assert h.finish(location)[0] == 200 and held == [False, False, True]


def test_an_acceptance_that_cannot_be_committed_leaves_nothing_and_says_so(monkeypatch):
    """A name or an address taken in the same moment surfaces at the commit: the whole acceptance is undone, the
    invitation stays pending, and the refusal is recorded."""
    from sqlalchemy.exc import IntegrityError
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id)
    location, _ = _sign_in(h, p, token)
    commit = h.db.commit

    def taken_meanwhile():
        monkeypatch.setattr(h.db, "commit", commit)
        raise IntegrityError("insert", {}, Exception("duplicate key"))
    monkeypatch.setattr(h.db, "commit", taken_meanwhile)
    status, body = h.finish(location)
    assert status == 409 and body["detail"]["reason"] == "invitation_unusable", body
    assert h.users_named("newbie") == [] and h.identities() == []
    assert any(a[0] == "account_invitation_accept_failed" and a[2]["reason"] == "commit_conflict" for a in h.audits)
    assert not any(a[0] == "account_invitation_accepted" for a in h.audits) and h.emails == []


def test_a_first_sign_in_reached_by_another_browser_makes_only_the_providers_own_account(monkeypatch):
    """What is written at the callback without an invitation is decided by the provider's answer alone. Mallory
    starts a sign-in and hands the address to a colleague: the account that is made is the colleague's own (their
    subject, their name and address from the token), nothing of Mallory's is on it, and the code that comes back
    signs nobody in without the verifier of the tab that started it."""
    root = _user("root", role="admin")
    p = _provider(policy={"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [root], [p])
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    status, out = h.start(p, verifier="mallory-tab")
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "victim-subject", "email": "victim@example.test", "preferred_username": "victim"}
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso="), location
    (victim,) = h.users_named("victim")
    (identity,) = h.identities()
    assert identity.user_id == victim.id and identity.subject == "victim-subject" and identity.linked_by == "jit"
    assert victim.email == "victim@example.test" and h.users_named("mallory") == []
    assert h.finish(location, verifier="victim-tab")[0] == 401 and h.finish(location, verifier="mallory-tab")[0] == 401


JIT = {"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]}


@pytest.mark.parametrize("links, holder, outcome", [
    (True, "an account that may be linked", "linked"),
    (False, "an account that may be linked", "its owner links it"),
    (True, "an administrator", "its owner links it"),
    (False, "an administrator", "its owner links it"),
    (True, "an account that set up its own factor", "link_from_profile"),
    (False, "an account that set up its own factor", "its owner links it"),
    (False, "an account that is turned off", "its owner links it"),
    (True, "an account that never confirmed the address", "no_account"),
    (False, "an account that never confirmed the address", "its owner links it"),
    (True, "nobody", "made"),
    (False, "nobody", "made"),
])
def test_a_first_sign_in_makes_no_second_account_for_an_address_that_has_one(monkeypatch, links, holder, outcome):
    """A provider that makes an account at a first sign-in, with and without the link by address. The account that
    holds the provider's verified address is linked where it may be, and refused for its own reason where it may
    not; in no case is another account made beside it. Made all the same, it carried no address or was refused
    for want of one the provider had sent, and the identity could no longer be linked to the real account."""
    root = _user("root", role="admin")
    fields = {"an administrator": {"role": "admin"}, "an account that is turned off": {"is_active": False},
              "an account that never confirmed the address": {"email_confirmed_at": None}}.get(holder, {})
    bob = _user("bob", **fields)
    p = _provider(policy={**JIT, "sso_link_by_email": links})
    h = Resolving(monkeypatch, [root] + ([bob] if holder != "nobody" else []), [p],
                  account_policy={"email_requirement": "optional"})
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    if holder == "an account that set up its own factor":
        _factor(h, bob, "authenticator")
    location, _ = _sign_in(h, p, sub="s-bob", email="bob@example.test", preferred_username="bob")
    accounts = sorted(u.username for u in h.users_named("bob") + h.users_named("bob-2"))
    if outcome == "made":
        assert location.startswith("/#sso="), location
        assert accounts == ["bob"] and [i.linked_by for i in h.identities()] == ["jit"]
        return
    assert accounts == ["bob"] and h.users_named("bob") == [bob]          # never a second account
    if outcome == "linked":
        assert location.startswith("/#sso="), location
        (identity,) = h.identities()
        assert identity.user_id == bob.id and identity.linked_by == "email"
        return
    assert h.identities() == [] and h.codes() == []
    if outcome == "its owner links it":
        assert location == "/#sso-error=link_from_your_account", location
        because = {"an administrator": "privileged_account:administrator",
                   "an account that never confirmed the address": "address_on_an_unconfirmed_account"}
        expected = because.get(holder, "address_has_an_account")
        if holder == "an administrator" and not links:
            expected = "address_has_an_account"          # the creation's own refusal: the link was not asked
        assert any(a[0] == "sso_sign_in_refused" and a[2].get("refused_because") == expected for a in h.audits), h.audits
        assert ([str(bob.id)], "A sign-in through Contoso with your address was kept out") in h.notices
    else:
        assert location == f"/#sso-error={outcome}", location


def test_an_address_the_provider_did_not_verify_says_nothing_about_whose_it_is(monkeypatch):
    """Anybody can write any address at a provider that does not verify it. It is no reason to refuse a first
    sign-in, and no reason to speak of the account that holds it: the account is made without an address."""
    root, bob = _user("root", role="admin"), _user("bob")
    p = _provider(policy=JIT)
    h = Resolving(monkeypatch, [root, bob], [p], account_policy={"email_requirement": "optional"})
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    # (The organisation's hosted-domain claim admits the sign-in; the address itself is not verified.)
    location, _ = _sign_in(h, p, sub="s-carol", email="bob@example.test", email_verified=False, hd="example.test",
                           preferred_username="carol")
    assert location.startswith("/#sso="), location
    (carol,) = h.users_named("carol")
    assert carol.email is None and not any(n[0] == [str(bob.id)] for n in h.notices)


def test_a_tenant_the_issuer_names_makes_and_links_no_account_at_a_sign_in(monkeypatch):
    """Held at the sign-in too, for a row saved before the rule or edited by hand: a provider whose only rule is
    the tenant its issuer already names is not restricted, so nobody is given an account at a first sign-in and
    no account is linked by its address. A required group makes it one."""
    from app.services import sso_sign_in as sso
    T = "8f0d6c3a-1111-4222-8333-444455556666"
    bob = _user("bob")
    wanted = {"sso_account_creation": "jit", "sso_link_by_email": True, "sso_allowed_tenants": [T]}
    p = _provider(issuer=f"https://login.microsoftonline.com/{T}/v2.0", policy=dict(wanted))
    h = Resolving(monkeypatch, [bob], [p], account_policy={"email_requirement": "optional"})
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)

    def answer(email, name):
        return sso.ProviderAnswer(claims={"preferred_username": name}, subject="s-" + name, issuer=p.issuer,
                                  tenant_id=T, email=email, email_verified=True, display_name=None, auth_time=None,
                                  groups=["staff"])
    for said in (answer("bob@example.test", "bob"), answer("guest@elsewhere.test", "guest")):
        assert sso._email_match(h.db, p, said, sso.policy_of(p)) is None
        assert sso._create_account(h.db, p, said, sso.policy_of(p)) is None
        with pytest.raises(sso.Refusal) as refused:
            sso.resolve_account(h.db, p, said)
        assert refused.value.code == sso.NO_ACCOUNT
    assert h.identities() == [] and h.users_named("guest") == []
    # With a group required, it says who may sign in: the account that holds the address is linked.
    p.policy = {**wanted, "sso_required_groups": ["staff"]}
    assert sso._email_match(h.db, p, answer("bob@example.test", "bob"), sso.policy_of(p)) is bob
    made = sso._create_account(h.db, p, answer("new@example.test", "newcomer"), sso.policy_of(p))
    assert made is not None and made.created is True


def test_the_administrators_are_told_of_a_first_sign_in_that_met_an_unconfirmed_address(monkeypatch):
    """The address on that account may be the person's own, or somebody typed a colleague's on theirs. Nobody is
    given a second account either way, and nobody is left to find out alone: the administrators can correct it."""
    root, bob = _user("root", role="admin"), _user("bob", email_confirmed_at=None)
    p = _provider(policy=JIT)
    h = Resolving(monkeypatch, [root, bob], [p], account_policy={"email_requirement": "optional"})
    told = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None,
                        once=False: told.append((list(ids), title, body, target, once)) or list(ids))
    location, _ = _sign_in(h, p, sub="s-bob", email="bob@example.test", preferred_username="bob")
    assert location == "/#sso-error=link_from_your_account", location
    (admins,) = [t for t in told if t[0] == [str(root.id)]]
    assert admins[1] == "A first sign-in through Sign in with Contoso made no account" and admins[3] == "#users"
    assert "written on bob's account, which never confirmed it" in admins[2] and admins[4] is True
    assert "correct it on the Users page" in admins[2]


@pytest.mark.parametrize("over_the_limit_by, fresh", [(2, False), (-5, True)])
def test_a_links_sign_in_is_fresh_for_as_long_as_a_confirmation_is_and_no_longer(monkeypatch, over_the_limit_by, fresh):
    """The provider says when it signed the person in. A link takes that sign-in while it is no older than a
    confirmation may be (a minute), and refuses one older: with a wider window, a link answered from somebody
    else's provider session of some minutes ago was taken as theirs."""
    from app.services import sso_sign_in as sso_rules
    alice = _user()
    p = _provider(last_test={"outcome": "ok", "auth_time_present": True})
    h = Resolving(monkeypatch, [alice], [p])
    h.current_user = alice
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    age = sso_rules.REAUTH_MAX_AGE_SECONDS + over_the_limit_by
    h.claims_override = {"sub": "alice-at-corp", "email": "alice@corp.example", "auth_time": int(time.time()) - age}
    location = h.callback(p, state)[1]
    if fresh:
        assert not location.startswith("/#sso-error="), location
    else:
        assert location == "/#sso-error=reauth_stale" and h.identities() == []
    assert sso_rules.REAUTH_MAX_AGE_SECONDS == 60


def test_a_link_asks_the_provider_for_a_fresh_sign_in_and_says_who_was_linked(monkeypatch):
    """What is linked is the identity of whoever is at the provider in that browser. So a link asks the provider
    to sign the person in again, refuses an answer the provider gave from a session it already had (where the
    provider says when it signed the person in), and shows the owner which identity now stands on their account:
    in the answer, in the list and in the notice."""
    alice = _user()
    p = _provider(last_test={"outcome": "ok", "auth_time_present": True})
    quiet = _provider(name="quiet", label="Quiet", last_test={"outcome": "ok", "auth_time_present": False})
    h = Resolving(monkeypatch, [alice], [p, quiet])
    h.current_user = alice
    status, out = h.start_link(p)
    assert status == 200 and "prompt=login" in out["authorization_url"] and "max_age=0" in out["authorization_url"]
    # Somebody else was still signed in at the provider, and it answered from that session, three days old.
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "somebody-else", "email": "other@corp.example", "auth_time": int(time.time()) - 3 * 86400}
    assert h.callback(p, state)[1] == "/#sso-error=reauth_stale"
    assert h.codes() == [] and h.identities() == []
    assert any(a[0] == "sso_flow_refused" and a[2].get("reason") == "reauth_stale" and a[2].get("purpose") == "link"
               for a in h.audits), h.audits
    # A token that does not say when is no fresh sign-in either.
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"auth_time": ...}
    assert h.callback(p, state)[1] == "/#sso-error=reauth_stale" and h.identities() == []
    # Signed in again just now: linked, and the owner is shown as whom.
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "alice-at-corp", "email": "alice@corp.example", "name": "Alice Example",
                         "auth_time": int(time.time()) - 5}
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked="), location
    status, body = h.finish_link(location)
    assert status == 200 and body["identity"]["email"] == "alice@corp.example", body
    assert body["identity"]["display_name"] == "Alice Example"
    said = [text for ids, title, text in h.notice_bodies if ids == [str(alice.id)]]
    assert said and said[-1].startswith("You linked your account to Contoso as alice@corp.example: ")
    status, listed, _ = _call(h.S, "GET", "/users/me/identities")
    assert status == 200 and [(i["email"], i["display_name"]) for i in listed["identities"]] == [
        ("alice@corp.example", "Alice Example")]
    # A provider that never said when it signed anybody in: the request is made all the same, and nothing is
    # judged that cannot be.
    status, out = h.start_link(quiet)
    assert "prompt=login" in out["authorization_url"] and "max_age=0" in out["authorization_url"]
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "alice-at-quiet", "email": ..., "name": "Alice Q", "auth_time": int(time.time()) - 3 * 86400}
    status, location, _ = h.callback(quiet, state)
    assert location.startswith("/#sso-linked="), location
    status, body = h.finish_link(location)
    assert status == 200 and body["identity"]["email"] is None and body["identity"]["display_name"] == "Alice Q"
    said = [text for ids, title, text in h.notice_bodies if ids == [str(alice.id)]]
    assert said[-1].startswith("You linked your account to Quiet as Alice Q: ")


def test_who_an_identity_is_shown_as():
    from app.services import sso_sign_in as sso
    shown = sso.identity_shown
    assert shown(types.SimpleNamespace(email_at_link=" a@corp.example ", display_name="A")) == "a@corp.example"
    assert shown(types.SimpleNamespace(email_at_link=None, display_name=" A B ")) == "A B"
    assert shown(types.SimpleNamespace(email_at_link="  ", display_name=None)) == ""
    assert shown(types.SimpleNamespace()) == ""


def test_what_an_invitations_code_keeps_of_the_providers_answer():
    """The identity's key and display data, the groups, and what the sign-in that follows carries; never a token
    but the provider's logout hint, encrypted, where the provider's logout wants it. More groups than are kept
    are kept as "too many to say", never as "member of nothing"."""
    from app.core import sign_in_codes
    from app.services import sso_sign_in as sso
    p = _provider(policy={"sso_idp_logout": False})
    answer = sso.ProviderAnswer(claims={"secret": "claim"}, subject="s-1", issuer="https://idp.example/", tenant_id="t1",
                                email="a@example.test", email_verified=True, display_name="A", auth_time=None,
                                sid="sid-1", id_token="the-id-token", groups=["fin", 7])
    held = sso.held_invitation(p, answer, invitation_id="i-1", provider_id=p.id, client_ip="203.0.113.9",
                               began_at=1000.5, verifier_hash="h", code_challenge=None, purpose="sign_in")
    assert held.user_id == "" and held.methods == [] and held.provider_id == str(p.id)
    assert held.provider_sid == "sid-1" and held.provider_sub == "s-1" and held.provider_answered_at == 1000.5
    assert held.provider_logout_hint_enc is None and held.verifier_hash == "h"
    assert held.invitation == {"invitation_id": "i-1", "answer": {
        "subject": "s-1", "issuer": "https://idp.example/", "tenant_id": "t1", "email": "a@example.test",
        "email_verified": True, "display_name": "A", "groups": ["fin", "7"], "groups_overage": False}}
    assert "the-id-token" not in str(held) and "claim" not in str(held)
    assert sign_in_codes.Handover.from_payload(held.__dict__) is not None
    back = sso.answer_of_an_invitation(held.invitation)
    assert (back.subject, back.issuer, back.tenant_id, back.email, back.email_verified, back.display_name) == (
        "s-1", "https://idp.example/", "t1", "a@example.test", True, "A")
    assert back.groups == ["fin", "7"] and back.groups_overage is False
    # No groups claim stays "no claim"; the provider's own overage marker stays one; too many become one.
    answer.groups = None
    none = sso.answer_of_an_invitation(sso.held_invitation(
        p, answer, invitation_id="i-1", provider_id=p.id, client_ip=None, began_at=1.0, verifier_hash="h",
        code_challenge=None, purpose="sign_in").invitation)
    assert none.groups is None and none.groups_overage is False
    answer.groups = [f"g{n}" for n in range(sso.GROUPS_KEPT + 1)]
    many = sso.answer_of_an_invitation(sso.held_invitation(
        p, answer, invitation_id="i-1", provider_id=p.id, client_ip=None, began_at=1.0, verifier_hash="h",
        code_challenge=None, purpose="sign_in").invitation)
    assert many.groups is None and many.groups_overage is True
    answer.groups = [f"g{n}" for n in range(sso.GROUPS_KEPT)]
    kept = sso.answer_of_an_invitation(sso.held_invitation(
        p, answer, invitation_id="i-1", provider_id=p.id, client_ip=None, began_at=1.0, verifier_hash="h",
        code_challenge=None, purpose="sign_in").invitation)
    assert len(kept.groups) == sso.GROUPS_KEPT and kept.groups_overage is False


@pytest.mark.parametrize("arrange", ["unknown", "expired", "revoked", "accepted", "invitations_off", "inviter_demoted", "app",
                                     "reserved_name", "provider_disabled"])
def test_an_invitation_start_is_refused_for_a_token_that_cannot_be_accepted(monkeypatch, arrange):
    root, p = _user("root", role="admin"), _provider(state="disabled" if arrange == "provider_disabled" else "enabled")
    h = Resolving(monkeypatch, [root], [p], account_policy={"invite_enabled": False} if arrange == "invitations_off" else None)
    token, inv = h.invite(created_by=root.id, role="admin" if arrange == "inviter_demoted" else "user")
    now = datetime.utcnow()
    if arrange == "unknown":
        token = "A" * 43
    elif arrange == "expired":
        inv.expires_at = now - timedelta(seconds=1)
    elif arrange == "revoked":
        inv.revoked_at = now
    elif arrange == "accepted":
        inv.accepted_at = now
    elif arrange == "inviter_demoted":
        from app.core.models import RoleEnum
        root.role = RoleEnum.USER
    elif arrange == "reserved_name":
        inv.username = "erased-7"
    if arrange == "app":
        status, out, _ = _call(h.S, "POST", f"/auth/sso/{p.id}/start", {"code_challenge": "c" * 43, "invitation": token})
        assert status == 400 and "browser" in out["detail"]
    elif arrange == "provider_disabled":
        # The provider is judged first: a token is not looked at (nor its limiter spent) for one that cannot serve.
        status, out = h.start(p, invitation=token)
        assert status == 404 and out["detail"]["reason"] == "provider_disabled" and "invite_accept_prefix" not in h.limiter
    else:
        status, out = h.start(p, invitation=token)
        assert status == 404 and out["detail"]["reason"] == "invitation_unusable", out
        assert any(a[0] == "account_invitation_accept_failed" and a[2].get("reason") == "sso_start_unresolved" for a in h.audits)
    assert not [k for k in h.redis.rows if k.startswith("sso:state:")] and h.users_named("newbie") == []


@pytest.mark.parametrize("arrange, reason, detail", [
    ("revoked", "invitation_unusable", "not_pending"),
    ("expired", "invitation_unusable", "not_pending"),
    ("accepted_meanwhile", "invitation_unusable", "not_pending"),
    ("invitations_off", "invitation_unusable", "invitations_off"),
    ("inviter_demoted", "invitation_unusable", "inviter_not_admin"),
    ("user_cap", "account_limit", "user_cap"),
    ("no_verified_email", "email_required", "email_required"),
    ("reserved_name", "invitation_unusable", "username_reserved"),
    ("invitation_address_in_use", "invitation_unusable", "email_in_use"),
    ("username_is_an_address", "invitation_unusable", "username_email_conflict"),
    ("administrator", "administrator_invitation", "administrator_invitation"),
    ("subject_pinned_elsewhere", "already_linked", "subject_linked_elsewhere"),
    ("claim_lost", "invitation_unusable", "claim_lost"),
    ("resent", "invitation_unusable", "not_pending"),
    ("another_address", "invitation_address", "another_address"),
    ("address_not_confirmed", "invitation_address", "address_not_confirmed"),
    ("turned_off_before_the_finish", "provider_disabled", None),
    ("revoked_before_the_finish", "invitation_unusable", "not_pending"),
])
def test_an_invitation_that_cannot_be_completed_at_the_callback_makes_no_account(monkeypatch, arrange, reason, detail):
    root = _user("root", role="admin")
    p = _provider()
    users = [root]
    if arrange == "invitation_address_in_use":
        users.append(_user("holder", email="taken@example.test"))
    if arrange == "username_is_an_address":
        users.append(_user("holder", email="newbie"))
    identities = [_identity(_user("other"), p, tenant_id="t1")] if arrange == "subject_pinned_elsewhere" else []
    h = Resolving(monkeypatch, users, [p], identities=identities)
    admin_role = arrange in ("inviter_demoted", "administrator")
    named = {"invitation_address_in_use": "taken@example.test", "another_address": "invited@example.test",
             "address_not_confirmed": "invited@example.test"}
    token, inv = h.invite(created_by=root.id, role="admin" if admin_role else "user", email=named.get(arrange))
    if admin_role:
        # The start refuses an administrator's invitation outright; the callback is held to the same, for a state
        # that names one all the same.
        from app.core import sso_state
        from app.services import sso_sign_in as sso
        url = sso.start(p, purpose=sso_state.SIGN_IN, source="s", client_ip="203.0.113.9", verifier_hash=_h("tab-verifier"),
                        extras={"invitation_id": str(inv.id)})
    else:
        status, out = h.start(p, invitation=token)
        url = out["authorization_url"]
    state, _ = h.state_of(url)
    now = datetime.utcnow()
    from app.core.models import RoleEnum, SystemSetting
    resent = None
    if arrange == "revoked":
        inv.revoked_at = now
    elif arrange == "resent":
        # Resent between the start and the callback: the resend revokes the old row and makes a new one; the
        # acceptance started with the old link is refused, and the new invitation stays pending.
        inv.revoked_at = now
        _token2, resent = h.invite(created_by=root.id)
    elif arrange == "expired":
        inv.expires_at = now - timedelta(seconds=1)
    elif arrange == "accepted_meanwhile":
        inv.accepted_at, inv.accepted_user_id = now, uuid.uuid4()
    elif arrange == "invitations_off":
        h.db.rows_of(SystemSetting).append(types.SimpleNamespace(key=h.S._SETTINGS_KEY, value={"invite_enabled": False}))
    elif arrange == "inviter_demoted":
        root.role = RoleEnum.USER
    elif arrange == "user_cap":
        monkeypatch.setattr(h.S.settings, "plan_max_users", 1)
    elif arrange == "no_verified_email":
        h.claims_override = {"email_verified": False}
    elif arrange == "reserved_name":
        inv.username = "erased-7"
    elif arrange == "subject_pinned_elsewhere":
        h.claims_override = {"tid": "t2"}
    elif arrange == "claim_lost":
        # Revoked after the acceptance read the invitation as pending and before its atomic claim: the claim finds
        # no pending row. (Staged at a check that sits between the two, the second time it is asked: the first
        # is the callback's look.)
        asked = []

        def kept(name):
            asked.append(name)
            if len(asked) > 1:
                inv.revoked_at = datetime.utcnow()
            return False
        monkeypatch.setattr(h.S, "_username_kept", kept)
    elif arrange == "another_address":
        pass                                # the provider confirms alice@example.test; the invitation names another
    elif arrange == "address_not_confirmed":
        h.claims_override = {"email": "invited@example.test", "email_verified": False}
    status, location, _ = h.callback(p, state)
    if arrange in ("claim_lost", "turned_off_before_the_finish", "revoked_before_the_finish"):
        # The callback's look passed. The acceptance is the finish's, and judges again in its own transaction.
        assert location.startswith("/#sso="), location
        assert h.users_named("newbie") == [] and inv.accepted_at is None
        if arrange == "turned_off_before_the_finish":
            p.state = "disabled"
        elif arrange == "revoked_before_the_finish":
            inv.revoked_at = now
        from app.services import sso_sign_in as texts
        status, body = h.finish(location)
        assert status == 409 and body["detail"] == {"reason": reason, "message": texts.reason_text(reason)}, body
        assert h.finish(location)[0] == 401                            # the code was spent by the refusal
    else:
        assert location == f"/#sso-error={reason}", location
    assert h.users_named("newbie") == [] and len(h.identities()) == len(identities) and h.codes() == []
    assert ("commit",) not in h.db.log                                 # nothing of the attempt was committed
    assert inv.accepted_user_id is None or arrange == "accepted_meanwhile"
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == reason for a in h.audits), h.audits
    assert any(a[0] == "account_invitation_accept_failed"
               and a[2] == {"token_prefix": inv.token_prefix, "reason": detail or reason} for a in h.audits), h.audits
    if arrange in ("another_address", "address_not_confirmed"):
        # Still pending, to be accepted with the form: the sentence says so.
        assert inv.accepted_at is None and inv.revoked_at is None
        from app.services import sso_sign_in as texts
        assert "choose a password there" in texts.reason_text("invitation_address")
    if arrange == "subject_pinned_elsewhere":
        assert inv.accepted_at is None                                 # still pending: the person may be invited again
    if resent is not None:
        assert resent.accepted_at is None and resent.revoked_at is None and resent.accepted_user_id is None


@pytest.mark.parametrize("arrange, expected", [
    ("invitation_address", "invited@example.test"),      # the invitation's address, which the provider confirms
    ("claim_verified", "alice@example.test"),
    ("claim_unverified_optional", None),
    ("claim_domain_denied_optional", None),
    ("claim_in_use_optional", None),
    ("claim_not_an_address_optional", None),          # "root": the stored shape has one '@' with both sides
    ("claim_too_long_optional", None),                 # longer than the column
    ("claim_non_ascii_optional", None),
    ("claim_two_ats_optional", None),
    ("claim_outside_the_domain_list_optional", None),  # hd admits the sign-in; the address is from another domain
])
def test_the_new_accounts_address_is_the_invitations_else_the_providers_verified_one_when_the_policy_admits_it(
        monkeypatch, arrange, expected):
    root = _user("root", role="admin")
    p = _provider(policy={"sso_allowed_domains": ["example.test"]} if arrange == "claim_outside_the_domain_list_optional" else None)
    policy = None
    if arrange.endswith("_optional"):
        policy = {"email_requirement": "optional"}
    if arrange == "claim_domain_denied_optional":
        policy.update({"signup_email_domain_mode": "denylist", "signup_email_domains": ["example.test"]})
    users = [root] + ([_user("holder", email="alice@example.test")] if arrange == "claim_in_use_optional" else [])
    h = Resolving(monkeypatch, users, [p], account_policy=policy)
    token, inv = h.invite(created_by=root.id, email="invited@example.test" if arrange == "invitation_address" else None)
    claims = {"email_verified": False} if arrange == "claim_unverified_optional" else {}
    if arrange == "claim_not_an_address_optional":
        claims = {"email": "root"}
    elif arrange == "claim_too_long_optional":
        claims = {"email": "a" * 250 + "@example.test"}
    elif arrange == "claim_non_ascii_optional":
        claims = {"email": "\u00e5lice@example.test"}
    elif arrange == "claim_two_ats_optional":
        claims = {"email": "a@evil.test@example.test"}
    elif arrange == "claim_outside_the_domain_list_optional":
        claims = {"hd": "example.test", "email": "alice@victim.test"}
    if arrange == "invitation_address":
        claims = {"email": "Invited@Example.test"}        # the same address, as the provider happens to write it
    _accept(h, p, token, **claims)
    (user,) = h.users_named("newbie")
    assert user.email == expected


def test_an_administrators_invitation_is_accepted_with_the_form_never_through_a_provider(monkeypatch):
    """An administrator types the account's password at every sign-in, and an account made through a provider holds
    one nobody knows: the new administrator could never finish a sign-in. So the start says, before anyone is sent
    to the provider, that such an invitation is accepted with a password; and a callback that carries one all the
    same makes no account and leaves the invitation to be used with the form."""
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id, role="admin", inviter_lineage=[str(uuid.uuid4())])
    status, out = h.start(p, invitation=token)
    assert status == 409 and out["detail"]["reason"] == "administrator_invitation", out
    assert "accepted with a password" in out["detail"]["message"]
    assert not [k for k in h.redis.rows if k.startswith("sso:state:")]            # nobody was sent to the provider
    # A state that names the invitation all the same (made before, or by hand).
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    url = sso.start(p, purpose=sso_state.SIGN_IN, source="s", client_ip="203.0.113.9", verifier_hash=_h("tab-verifier"),
                    extras={"invitation_id": str(inv.id)})
    state, _ = h.state_of(url)
    status, location, _ = h.callback(p, state)
    assert location == "/#sso-error=administrator_invitation", location
    assert h.users_named("newbie") == [] and h.identities() == [] and inv.accepted_at is None
    assert h.admin_grants == [] and h.announcements == []
    assert "administrator_invitation" in sso.REASON_TEXTS


def test_an_account_made_through_a_provider_holds_a_password_that_is_not_its_owners(monkeypatch):
    """Made at a first sign-in or from an invitation accepted through the provider, an account holds a hash of
    random bytes. It is marked as a password someone else set, so that the rules for one apply: a later promotion
    takes it back and sends the person a link to choose their own, and until then the account approves no held
    change. An account that existed and was linked keeps what it had."""
    from app.core import password_origin
    root, bob = _user("root", role="admin"), _user("bob", password_set_by=None, password_set_by_other_at=None)
    p = _provider(policy={"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]})
    q = _provider(name="links", policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [root, bob], [p, q])
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    token, _inv = h.invite(username="invited", created_by=root.id)
    _accept(h, p, token, sub="s-invited", email="invited@example.test")
    assert _sign_in(h, p, sub="s-first", email="first@example.test", preferred_username="first")[0].startswith("/#sso=")
    assert _sign_in(h, q, sub="s-bob", email="bob@example.test")[0].startswith("/#sso=")
    (invited,), (first,) = h.users_named("invited"), h.users_named("first")
    for made in (invited, first):
        assert password_origin.is_set_by_other(made) and made.password_set_by is None, made.username
        # And it is marked as one nobody can type, so the account is asked for none.
        assert password_origin.nobody_knows(made) is True, made.username
    assert not password_origin.is_set_by_other(bob) and bob.password_hash == "x"
    assert password_origin.nobody_knows(bob) is False


def test_every_new_account_gets_a_password_hash_of_its_own_that_nobody_knows(monkeypatch):
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token1, _ = h.invite(username="first", created_by=root.id)
    token2, _ = h.invite(username="second", created_by=root.id)
    _accept(h, p, token1)
    _accept(h, p, token2, sub="subject-2", email="second@example.test")
    (first,), (second,) = h.users_named("first"), h.users_named("second")
    assert first.password_hash != second.password_hash
    assert first.password_hash.startswith("argon2:") and first.password_hash != "argon2:" + _h("")
    assert len(first.password_hash) == len("argon2:") + 64          # a hash of a random secret, no plain text


def test_a_code_store_that_fails_costs_one_more_sign_in_and_never_half_an_account(monkeypatch):
    """An invitation: nothing is written before its code is redeemed, so a store that fails at the callback leaves
    the invitation pending and the person starts again. An account made at a first sign-in is the provider
    identity's own and stands before any code is handed out: the next sign-in finds it."""
    root = _user("root", role="admin")
    p = _provider(policy={"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [root], [p])
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    token, inv = h.invite(created_by=root.id)
    from app.core import sign_in_codes

    def unavailable(*a, **kw):
        raise sign_in_codes.Unavailable()
    real_store = sign_in_codes.store
    monkeypatch.setattr(sign_in_codes, "store", unavailable)
    location, _ = _sign_in(h, p, token)
    assert location == "/#sso-error=temporarily_unavailable", location
    assert h.users_named("newbie") == [] and h.identities() == [] and inv.accepted_at is None
    assert ("commit",) not in h.db.log
    location, _ = _sign_in(h, p, sub="s-first", email="first@example.test", preferred_username="first")
    assert location == "/#sso-error=temporarily_unavailable", location
    (first,) = h.users_named("first")
    assert ("commit",) in h.db.log and [i.user_id for i in h.identities()] == [first.id]
    monkeypatch.setattr(sign_in_codes, "store", real_store)
    # The invitation is accepted at the next try; the first sign-in's account is found by the next sign-in.
    _accept(h, p, token)
    assert inv.accepted_at is not None and len(h.users_named("newbie")) == 1
    location, _ = _sign_in(h, p, sub="s-first", email="first@example.test", preferred_username="first")
    assert location.startswith("/#sso=") and len(h.users_named("first")) == 1 and h.finish(location)[0] == 200


@pytest.mark.parametrize("policy, sso_only", [
    ({"sso_password_login": "allowed"}, True),                                 # as a provider stands by itself
    ({"sso_password_login": "allowed", "sso_jit_password": True}, False),      # it lets the accounts it makes set one
    ({"sso_password_login": "disabled"}, True),
    ({"sso_password_login": "disabled", "sso_jit_password": True}, True),      # its people hold no password at all
])
def test_a_user_made_by_an_invitation_is_sso_only_when_the_provider_says_so(monkeypatch, policy, sso_only):
    """An invitation accepted through the provider makes an account whose person the vault met through the
    provider alone, with a password nobody knows. It follows the rule for the accounts a provider makes: held
    to no password unless the provider lets them set one. (It could set a password with "Forgot password" at any
    time before, also after the provider stopped vouching for it, until its days ran out.)"""
    root, p = _user("root", role="admin"), _provider(policy=policy)
    h = Resolving(monkeypatch, [root], [p])
    token, _ = h.invite(created_by=root.id)
    _accept(h, p, token)
    (user,) = h.users_named("newbie")
    assert user.sso_only is sso_only and user.sftp_password_auth is (not sso_only)
    from app.core import password_origin
    assert password_origin.nobody_knows(user)


def test_a_known_identity_signs_in_and_leaves_the_invitation_it_carried_untouched(monkeypatch):
    root, alice, p = _user("root", role="admin"), _user(), _provider()
    h = Resolving(monkeypatch, [root, alice], [p], identities=[_identity(alice, p)])
    token, inv = h.invite(created_by=root.id)
    location, _ = _sign_in(h, p, token)
    status, body = h.finish(location)
    assert status == 200 and _claims(body["access_token"])["sub"] == str(alice.id)
    assert inv.accepted_at is None and h.users_named("newbie") == [] and len(h.identities()) == 1


# --------------------------------------------------------------------------- an account linked by its verified email

def test_an_address_the_vault_never_confirmed_links_nothing(monkeypatch):
    """Mallory writes a colleague's address on her own account (her own password is all that change asks for), and
    the colleague signs in through the provider for the first time, with their own subject and that verified
    address. Nothing is linked: the colleague is told there is no account for them, no code is handed out, nobody
    is told that a sign-in method was added, and the record says why. The same holds for an address typed at self
    sign-up. Once the vault confirmed the address for the account, the same sign-in links it."""
    mallory = _user("mallory", email="victim@example.test", email_confirmed_at=None)
    root = _user("root", role="admin")
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [mallory, root], [p])
    for _ in range(2):                       # the second try finds nothing left behind by the first
        location, _state = _sign_in(h, p, sub="victim-subject", email="victim@example.test")
        assert location == "/#sso-error=no_account", location
        assert h.identities() == [] and h.codes() == [] and h.notices == [] and h.emails == []
    refused = [a[2] for a in h.audits if a[0] == "sso_sign_in_refused"]
    assert len(refused) == 2 and all(r.get("reason") == "no_account" and r.get("refused_because") == "address_not_confirmed"
                                     for r in refused), h.audits
    assert not any(a[0] == "sso_identity_linked" for a in h.audits)
    # A mark alone is not a confirmation of this address: one given for another address the account held before,
    # and left behind by a change made where nothing clears it (a release from before the mark, run for a while
    # after going back to it), links nothing either.
    from app.core import email_confirmation as ec
    mallory.email_confirmed_at = datetime.utcnow()
    mallory.email_confirmed_for = ec.mark_for("mallory@example.test")
    location, _state = _sign_in(h, p, sub="victim-subject", email="victim@example.test")
    assert location == "/#sso-error=no_account" and h.identities() == [], location
    ec.confirm(mallory)
    location, _state = _sign_in(h, p, sub="victim-subject", email="victim@example.test")
    assert location.startswith("/#sso=") and len(h.identities()) == 1


def test_a_verified_email_links_an_existing_account_when_the_provider_allows_it_and_is_restricted(monkeypatch):
    bob, p = _user("bob"), _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    root, other = _user("root", role="admin"), _user("second", role="admin")
    h = Resolving(monkeypatch, [bob, root, other], [p])
    location, _ = _sign_in(h, p, email="bob@example.test")
    assert location.startswith("/#sso="), location
    # A link nobody at the vault asked for: every administrator is told of it, as of an account made at a first sign-in.
    told = [ids for ids, title in h.notices if title == "An account was linked to single sign-on by its email address"]
    assert told == [[str(root.id), str(other.id)]], h.notices
    (identity,) = h.identities()
    assert identity.user_id == bob.id and identity.linked_by == "email" and identity.email_at_link == "bob@example.test"
    assert ("sso_identity_linked", "success", {"provider_id": str(p.id), "linked_by": "email",
                                               "identity_id": str(identity.id), "made_sso_only": False}) in h.audits
    assert ([str(bob.id)], "A sign-in method was added") in h.notices
    # Nobody at the vault made this link: a sign-in at the provider with the person's address did. If it was not
    # them, the address there is in other hands, and only an administrator can act on that.
    (said,) = [body for ids, title, body in h.notice_bodies if title == "A sign-in method was added"]
    assert said.endswith("If you did not sign in through Contoso just now, tell an administrator at once: your "
                         f"address there may be in someone else's hands.")
    assert any(e[0] == "sign_in_method_changed" and e[1] == "bob@example.test" for e in h.emails), h.emails
    status, body = h.finish(location)
    assert status == 200 and _claims(body["access_token"])["sub"] == str(bob.id)
    # Next time it is a known identity: linked once.
    location, _ = _sign_in(h, p, email="bob@example.test")
    assert location.startswith("/#sso=") and len(h.identities()) == 1


@pytest.mark.parametrize("kind, arrange", [
    ("administrator", "role"),
    ("auditor_right", "proposed"),
    ("auditor_right", "active"),
    ("auditor_right", "suspended"),
])
def test_a_privileged_account_is_never_linked_by_its_verified_email(monkeypatch, kind, arrange):
    bob = _user("bob", role="admin" if arrange == "role" else "user")
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [bob], [p])
    if arrange != "role":
        from app.core.models import AuditorGrant
        h.db.rows_of(AuditorGrant).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=bob.id, status=arrange))
    location, _ = _sign_in(h, p, email="bob@example.test")
    # Told what is so: not that the vault is closed to their tenant (it is not), but that the sign-in is not linked
    # and where its owner links it.
    assert location == "/#sso-error=link_from_your_account", location
    from app.services import sso_sign_in as sso
    assert "not open to your tenant" not in sso.reason_text("link_from_your_account")
    assert "link your organisation's sign-in under Your account" in sso.reason_text("link_from_your_account")
    assert h.identities() == [] and h.codes() == [] and h.emails == []
    # The owner is told that it was tried (and nobody else here: there is no other administrator).
    assert h.notices == [([str(bob.id)], "A sign-in through Contoso with your address was kept out")]
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == "link_from_your_account"
               and a[2].get("refused_because") == f"privileged_account:{kind}" for a in h.audits), h.audits
    # An ended grant is no standing: the account links.
    if arrange != "role":
        h.db.rows_of(AuditorGrant)[0].status = "ended"
        location, _ = _sign_in(h, p, email="bob@example.test")
        assert location.startswith("/#sso=") and len(h.identities()) == 1


@pytest.mark.parametrize("arrange", ["off", "unverified", "inactive", "unrestricted", "has_identity",
                                     "no_match", "two_accounts", "address_outside_the_domain_list"])
def test_linking_by_email_happens_in_no_other_case(monkeypatch, arrange):
    policy = {"sso_link_by_email": True, "sso_allowed_tenants": ["t1"]}
    if arrange == "off":
        policy = {"sso_allowed_tenants": ["t1"]}
    elif arrange == "unrestricted":
        policy = {"sso_link_by_email": True}
    elif arrange == "address_outside_the_domain_list":
        policy = {"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]}
    bob, p = _user("bob"), _provider(policy=policy)
    if arrange == "inactive":
        bob.is_active = False
    if arrange == "address_outside_the_domain_list":
        bob.email = "bob@victim.test"           # the hosted domain admits the sign-in; this address is not on the list
    users = [bob] + ([_user("bobby", email="Bob@example.test")] if arrange == "two_accounts" else [])
    identities = [_identity(bob, p, subject="another-subject")] if arrange == "has_identity" else []
    h = Resolving(monkeypatch, users, [p], identities=identities)
    claims = {"tid": "t1", "email": "bob@example.test"}
    if arrange == "unverified":
        claims["email_verified"] = False
    if arrange == "no_match":
        claims["email"] = "nobody@example.test"
    if arrange == "address_outside_the_domain_list":
        claims = {"hd": "example.test", "email": "bob@victim.test"}
    location, _ = _sign_in(h, p, **claims)
    assert location == "/#sso-error=no_account", location
    assert len(h.identities()) == len(identities) and h.codes() == [] and h.notices == []


# --------------------------------------------------------------------------- an account made at the first sign-in

JIT = {"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]}


def test_a_restricted_provider_makes_an_account_at_the_first_sign_in(monkeypatch):
    root = _user("root", role="admin")
    p = _provider(policy={**JIT, "sso_default_role": "external", "sso_password_login": "disabled"})
    h = Resolving(monkeypatch, [root], [p])
    location, _ = _sign_in(h, p, preferred_username="Alice.Example")
    assert location.startswith("/#sso="), location
    (user,) = h.users_named("Alice.Example")
    from app.core.models import RoleEnum
    assert user.role == RoleEnum.EXTERNAL and user.email == "alice@example.test" and user.created_by is None
    assert user.password_hash.startswith("argon2:") and user.sso_only is True and user.sftp_password_auth is False
    (identity,) = h.identities()
    assert identity.user_id == user.id and identity.linked_by == "jit"
    assert h.grants == [(str(user.id), str(user.role), False)]
    assert ("sso_account_created", "success",
            {"username": "Alice.Example", "role": str(user.role), "provider_id": str(p.id)}) in h.audits, h.audits
    (identity,) = h.identities()
    assert ("sso_identity_linked", "success", {"provider_id": str(p.id), "linked_by": "jit",
                                               "identity_id": str(identity.id), "made_sso_only": False}) in h.audits
    assert ([str(root.id)], "An account was created by single sign-on") in h.notices
    assert ("account_welcome", "alice@example.test", None) in h.emails
    status, body = h.finish(location)
    assert status == 200 and _claims(body["access_token"])["sub"] == str(user.id)
    # The next sign-in finds the identity: one account, however many sign-ins.
    location, _ = _sign_in(h, p, preferred_username="Alice.Example")
    assert location.startswith("/#sso=") and len(h.users_named("Alice.Example")) == 1 and len(h.identities()) == 1


@pytest.mark.parametrize("claims, taken, expected", [
    ({"preferred_username": "alice.e"}, [], "alice.e"),
    ({}, [], "alice"),                                                   # the verified address's local part
    ({"preferred_username": "alice@example.test"}, [], "alice"),         # a UPN never qualifies: no '@'
    ({"preferred_username": "bad<name>"}, [], "alice"),
    ({"preferred_username": "erased-7"}, [], "alice"),                   # a reserved prefix
    ({"preferred_username": "two words"}, [], "alice"),
    ({"preferred_username": "ab"}, [], "alice"),                         # too short
    ({"email_verified": False, "tid": "t1"}, [], "subject-1"),           # no address to use: the subject
    ({"email_verified": False, "tid": "t1", "sub": "x" * 80}, [], "x" * 50),   # shortened to the rules
    ({}, ["alice"], "alice-2"),
    ({}, ["alice", "alice-2"], "alice-3"),
    ({"preferred_username": "alice.e"}, ["alice.e"], "alice.e-2"),
])
def test_the_username_comes_from_the_claim_the_address_or_the_subject_with_a_suffix_on_a_collision(
        monkeypatch, claims, taken, expected):
    # An unverified address cannot pass a domain rule, so those cases run under a tenant rule instead.
    policy = JIT if "tid" not in claims else {"sso_account_creation": "jit", "sso_allowed_tenants": ["t1"]}
    root, p = _user("root", role="admin"), _provider(policy=policy)
    h = Resolving(monkeypatch, [root] + [_user(name, email=f"{name}@taken.test") for name in taken], [p],
                  account_policy={"email_requirement": "optional"})
    location, _ = _sign_in(h, p, **claims)
    assert location.startswith("/#sso="), location
    assert len(h.users_named(expected)) == 1


def test_the_username_is_never_an_address_in_use(monkeypatch):
    root, holder, p = _user("root", role="admin"), _user("holder", email="alice@other.test"), _provider(policy=JIT)
    h = Resolving(monkeypatch, [root, holder], [p])
    h.db.rows_of(type(holder))                      # the memory store's address check reads the users' emails
    monkeypatch.setattr(h.S, "_email_has_pending_invite", lambda db, email: False)
    from app.core import email_identity
    monkeypatch.setattr(email_identity, "email_in_use", lambda db, email, exclude_user_id=None: email == "alice")
    location, _ = _sign_in(h, p)
    assert location.startswith("/#sso=") and h.users_named("alice") == [] and len(h.users_named("alice-2")) == 1


@pytest.mark.parametrize("arrange, reason", [
    ("unrestricted", "no_account"),
    ("email_required", "email_required"),
    ("user_cap", "account_limit"),
    ("no_username", "username_unavailable"),
])
def test_creation_at_the_first_sign_in_needs_a_restricted_provider_and_an_admitted_person(monkeypatch, arrange, reason):
    root = _user("root", role="admin")
    policy = {"sso_account_creation": "jit"} if arrange == "unrestricted" else dict(JIT)
    if arrange in ("no_username", "email_required"):
        policy = {"sso_account_creation": "jit", "sso_allowed_tenants": ["t1"]}
    h = Resolving(monkeypatch, [root], [p := _provider(policy=policy)],
                  account_policy={"email_requirement": "optional"} if arrange != "email_required" else None)
    claims = {}
    if arrange == "email_required":
        claims = {"tid": "t1", "email_verified": False}
    elif arrange == "user_cap":
        monkeypatch.setattr(h.S.settings, "plan_max_users", 1)
    elif arrange == "no_username":
        claims = {"tid": "t1", "email_verified": False, "sub": "a<b", "preferred_username": "x<y"}
    location, _ = _sign_in(h, p, **claims)
    assert location == f"/#sso-error={reason}", location
    from app.core.models import User
    assert h.db.rows_of(User) == [root] and h.identities() == [] and h.codes() == []
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == reason for a in h.audits), h.audits
    # The closer cause rides beside the reason under a name the recording levels know: a key they do not know is
    # not recorded, so it is never a bare "detail".
    refused = next(a[2] for a in h.audits if a[0] == "sso_sign_in_refused")
    assert refused.get("refused_because") == (None if arrange == "unrestricted" else arrange), refused
    assert "detail" not in refused
    from app.core import audit_privacy
    assert audit_privacy.kind_of("refused_because") == audit_privacy.IDENTIFIER


def test_a_test_sign_in_says_what_account_it_would_make(monkeypatch):
    root = _user("root", role="admin")
    p = _provider(state="tested", policy=JIT)
    h = Resolving(monkeypatch, [root], [p])
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    h.claims_override = {"preferred_username": "alice.e"}
    status, location, _ = h.callback(p, state)
    status, body = h.finish_test(p, location)
    assert status == 200, body
    assert p.last_test["would"] == ("create the account alice.e at the first sign-in and sign it in "
                                    "(it signs in only through this provider)")
    assert h.users_named("alice.e") == [] and h.identities() == []        # a test makes nothing


# --------------------------------------------------------------------------- the provider's MFA

@pytest.mark.parametrize("policy, claims, trusted", [
    ({}, {"amr": ["pwd", "mfa"], "acr": "2"}, False),
    ({"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]}, {"amr": ["pwd", "mfa"]}, True),
    ({"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]}, {"amr": ["pwd"]}, False),
    ({"sso_trust_idp_mfa": True, "sso_accepted_acr": ["2"]}, {"acr": "2"}, True),
    ({"sso_trust_idp_mfa": True, "sso_accepted_acr": ["2"]}, {"acr": "1"}, False),
])
def test_the_providers_mfa_is_the_second_factor_only_when_the_policy_trusts_the_values(monkeypatch, policy, claims, trusted):
    alice, p = _user(), _provider(policy=policy)
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    location, _ = _sign_in(h, p, **claims)
    assert location.startswith("/#sso="), location
    status, body = h.finish(location)
    assert status == 200, body
    token = _claims(body["access_token"])
    assert ("mfa_at" in token) is trusted and token["amr"] == []


def _factor(h, user, kind):
    """Give ``user`` a second factor of its own as real rows, or what is left of one: an authenticator, a passkey,
    an administrator's reset of the factor that was there (its rows gone, its passkeys retired), and the states
    that are no factor (an enrollment never confirmed, a passkey that was retired without a reset)."""
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    now = datetime.utcnow()
    enrollments, passkeys = h.db.rows_of(SecondFactorEnrollment), h.db.rows_of(WebAuthnCredential)
    if kind == "authenticator":
        enrollments.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, method="totp", status="active"))
    elif kind == "enrollment never confirmed":
        enrollments.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, method="totp", status="pending"))
    elif kind == "passkey":
        passkeys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, retired_at=None))
    elif kind == "passkey retired":
        passkeys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, retired_at=now))
    elif kind == "factor reset by an administrator":
        passkeys.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, retired_at=now))
        user.second_factor_reset_at = now
    else:
        raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["authenticator", "passkey", "factor reset by an administrator"])
@pytest.mark.parametrize("passkeys", ["off", "optional"])
def test_an_account_with_its_own_second_factor_is_never_linked_by_email(monkeypatch, kind, passkeys):
    """The attack: somebody holds, at the provider, the verified address of an account that set up its own second
    factor. A link by email would stand from the moment the provider answered, before the account's factor is given.
    Started twice, the second sign-in would come through an identity the vault already knows, on the provider's MFA
    alone; and at a provider whose people hold no password, the account's password would be gone at the first. So
    nothing is linked: no identity, no code, the password and the flag as they were, however often it is tried,
    and the page says where the owner links the provider. An account with no factor of its own is linked as before,
    and the provider's MFA counts for it as the policy says.

    The account's factor is real rows here, of each kind, and counts also while it is between two states: a
    passkey while passkeys are switched off (it is a factor again the day they are switched on), and an
    administrator's reset that the account has not answered yet (its next factor is to be set up behind its own
    password, not by whoever holds its address at the provider)."""
    from app.core import webauthn_settings
    from app.services import sso_sign_in as sso
    monkeypatch.setattr(webauthn_settings, "enabled", lambda: passkeys != "off")
    bob, carol, root = _user("bob"), _user("carol"), _user("root", role="admin")
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"], "sso_trust_idp_mfa": True,
                          "sso_accepted_amr": ["mfa"], "sso_password_login": "disabled"})
    h = Resolving(monkeypatch, [bob, carol, root], [p])
    _factor(h, bob, kind)
    assert sso.set_up_its_own_factor(h.db, bob) is True and sso.set_up_its_own_factor(h.db, carol) is False
    before = (bob.password_hash, bob.sso_only, bob.sftp_password_auth)
    for _ in range(3):                                   # the first try, and the ones that would ride on it
        location, _state = _sign_in(h, p, sub="someone-at-the-provider", email="bob@example.test", amr=["pwd", "mfa"])
        assert location == "/#sso-error=link_from_profile", location
        assert h.identities() == [] and h.codes() == [] and h.emails == []
        assert (bob.password_hash, bob.sso_only, bob.sftp_password_auth) == before
    assert {tuple(told[0]) for told in h.notices} == {(str(bob.id),)}       # only the owner hears of it
    refused = [a[2] for a in h.audits if a[0] == "sso_sign_in_refused"]
    assert len(refused) == 3 and all(r.get("reason") == "link_from_profile"
                                     and r.get("refused_because") == "account_holds_a_factor" for r in refused), h.audits
    assert "under Your account" in sso.REASON_TEXTS[sso.LINK_FROM_PROFILE]
    # The account without a factor of its own: linked, held to no password by the provider's rule, and signed in.
    location, _ = _sign_in(h, p, sub="carol-subject", email="carol@example.test", amr=["pwd", "mfa"])
    assert location.startswith("/#sso="), location
    status, body = h.finish(location)
    assert status == 200 and "mfa_at" in _claims(body["access_token"]), body
    (identity,) = h.identities()
    assert identity.user_id == carol.id and identity.linked_by == "email" and carol.sso_only is True
    # The second sign-in of that account is an ordinary one.
    location, _ = _sign_in(h, p, sub="carol-subject", email="carol@example.test", amr=["pwd", "mfa"])
    status, body = h.finish(location)
    assert status == 200 and "mfa_at" in _claims(body["access_token"]) and len(h.identities()) == 1


@pytest.mark.parametrize("kind", ["enrollment never confirmed", "passkey retired"])
def test_what_is_no_factor_of_the_accounts_own_does_not_keep_a_link_by_email_out(monkeypatch, kind):
    """The control of the rule above: an authenticator the account began to set up and never confirmed, and a
    passkey that was retired, are no factor, and the account is linked as one that has none."""
    from app.services import sso_sign_in as sso
    bob, root = _user("bob"), _user("root", role="admin")
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [bob, root], [p])
    _factor(h, bob, kind)
    assert sso.set_up_its_own_factor(h.db, bob) is False
    location, _ = _sign_in(h, p, sub="bob-subject", email="bob@example.test")
    assert location.startswith("/#sso=") and len(h.identities()) == 1, location


@pytest.mark.parametrize("row", ["names a hosted-domain claim", "is Google"])
@pytest.mark.parametrize("way", ["an account made at the first sign-in", "a link by email", "the sign-up list"])
def test_a_provider_with_a_hosted_domain_claim_is_judged_on_that_claim_and_not_on_the_address(monkeypatch, row, way):
    """Google signs consumer accounts and its organisations' accounts as one issuer, and tells them apart only by
    the hosted-domain claim. A consumer account can carry any verified address, a work address included. So a
    provider row that names such a claim, and Google's own issuer whatever the row says of its claims, is judged
    on that claim alone: a token without it admits nobody on the strength of its address, whichever list restricts
    the provider (its own domains or the vault's sign-up domains), and nobody is made or linked; the same person
    with the claim is admitted. A row with neither has only the verified address to go by, and is judged on it."""
    from app.services import sso_sign_in as sso
    bob, root = _user("bob"), _user("root", role="admin")
    policy = {"sso_allowed_domains": ["example.test"]}
    account_policy = None
    if way == "an account made at the first sign-in":
        policy["sso_account_creation"] = "jit"
        claims = {"sub": "new-subject", "email": "newcomer@example.test", "preferred_username": "newcomer"}
    elif way == "a link by email":
        policy["sso_link_by_email"] = True
        claims = {"sub": "bob-subject", "email": "bob@example.test"}
    else:
        policy = {"sso_use_signup_domains": True, "sso_account_creation": "jit"}
        account_policy = {"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.test"]}
        claims = {"sub": "new-subject", "email": "newcomer@example.test", "preferred_username": "newcomer"}
    shape = {"claims": {"domain": "hd"}} if row == "names a hosted-domain claim" else {"issuer": sso.GOOGLE_ISSUER + "/"}
    p = _provider(policy=policy, **shape)
    plain = _provider(name="plain", label="Plain", policy=policy)
    assert sso.hosted_domain_only(p) is True and sso.hosted_domain_only(plain) is False
    assert sso.hosted_domain_only(_provider(issuer="https://ACCOUNTS.google.com")) is True       # the issuer, folded
    assert sso.hosted_domain_only(_provider(issuer="https://accounts.google.com.example.test")) is False
    assert sso.hosted_domain_only(_provider(claims={"domain": "  "})) is False                   # names no claim
    if row == "is Google":
        # The token's issuer is the test provider's; the row's rule is what is under test, so it is judged here.
        answer = types.SimpleNamespace(tenant_id=None, email=claims["email"], email_verified=True, hosted_domain=None,
                                       groups=None, groups_overage=False)
        h = Resolving(monkeypatch, [bob, root], [p, plain], account_policy=account_policy)
        assert sso.restriction_of(h.db, p, answer) == "restriction_claim_missing"
        answer.hosted_domain = "example.test"
        assert sso.restriction_of(h.db, p, answer) is None
        answer.hosted_domain = None
        assert sso.restriction_of(h.db, plain, answer) is None
        return
    h = Resolving(monkeypatch, [bob, root], [p, plain], account_policy=account_policy)
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    before = (bob.password_hash, bob.sso_only)
    location, _state = _sign_in(h, p, **claims)                                  # a consumer account: no such claim
    assert location == "/#sso-error=restriction_claim_missing", location
    assert h.identities() == [] and h.codes() == [] and h.users_named("newcomer") == []
    assert (bob.password_hash, bob.sso_only) == before
    location, _state = _sign_in(h, p, hd="other.test", **claims)                 # another organisation's account
    assert location == "/#sso-error=restricted", location
    assert h.identities() == [] and h.users_named("newcomer") == []
    location, _state = _sign_in(h, p, hd="example.test", **claims)               # the organisation's own
    assert location.startswith("/#sso="), location
    assert len(h.identities()) == 1


def test_the_owner_is_told_when_a_sign_in_with_their_address_was_kept_out(monkeypatch):
    """The answer at the provider says little. The owner of the account the sign-in was kept away from is told in
    the app, once a day for a provider, with no email (a stranger at the provider cannot send mail at will); for a
    privileged account the other administrators are told as well. An address nobody confirmed, or nobody's, is no
    account's to be told about."""
    from datetime import datetime
    bob, carol = _user("bob"), _user("carol", email_confirmed_at=None)
    root, second, gone = _user("root", role="admin"), _user("second", role="admin"), _user("gone", role="admin", is_active=False)
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [bob, carol, root, second, gone], [p])
    _factor(h, bob, "authenticator")
    told = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None,
                        once=False: told.append((list(ids), ntype, title, body, target, dedup_prefix, once)) or list(ids))
    key = f"sso_kept_out:{p.id}:{datetime.utcnow():%Y-%m-%d}"
    location, _ = _sign_in(h, p, sub="s-1", email="bob@example.test")
    assert location == "/#sso-error=link_from_profile"
    (ids, ntype, title, body, target, dedup, once), = told
    assert (ids, ntype, target, dedup, once) == ([str(bob.id)], "account_changed", "#profile", key, True)
    assert title == "A sign-in through Contoso with your address was kept out"
    assert "Nobody was signed in" in body and "under Your account" in body and "tell an administrator" in body
    # A privileged account: its owner, and the other administrators who are active.
    del told[:]
    location, _ = _sign_in(h, p, sub="s-2", email="root@example.test")
    assert location == "/#sso-error=link_from_your_account"
    owner, others = told
    assert owner[0] == [str(root.id)] and owner[5] == key and owner[6] is True
    assert others[0] == [str(second.id)] and others[4] == "#users" and others[5] == f"{key}:{root.id}" and others[6] is True
    assert "tried to reach root's account" in others[2] and "Nobody was signed in" in others[3]
    # No account the vault can speak for: nobody is told.
    del told[:]
    for address in ("carol@example.test", "nobody@example.test"):
        location, _ = _sign_in(h, p, sub="s-3", email=address)
        assert location == "/#sso-error=no_account", location
    assert told == [] and h.emails == []


@pytest.mark.parametrize("passwords", ["kept", "none"])
def test_an_administrator_kept_out_is_told_how_its_account_is_linked_or_that_it_is_not(monkeypatch, passwords):
    """An administrator's or auditor's account is linked to a provider only from Your account, after its password
    and, where it has one, its second factor. Where the provider's people hold no password, it cannot be linked
    there at all (the link is refused: such an account keeps a password), so its owner is not told to link it."""
    root, second = _user("root", role="admin"), _user("second", role="admin")
    policy = {"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]}
    if passwords == "none":
        policy["sso_password_login"] = "disabled"
    p = _provider(policy=policy)
    h = Resolving(monkeypatch, [root, second], [p])
    told = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None,
                        once=False: told.append((list(ids), ntype, title, body, target)) or list(ids))
    location, _ = _sign_in(h, p, sub="s-root", email="root@example.test")
    assert location == "/#sso-error=link_from_your_account", location
    (body,) = [t[3] for t in told if t[0] == [str(root.id)]]
    assert body.startswith("Someone signed in through Contoso with your email address. Nobody was "
                           "signed in to your account and nothing was linked: an administrator's or auditor's account "
                           "is linked to a provider only from Your account")
    assert body.endswith("your address at Contoso may be in someone else's hands: tell another "
                         "administrator.")
    if passwords == "kept":
        assert "If that was you, link Contoso there." in body
    else:
        assert "link it there" not in body and "link Contoso there" not in body
        assert "so your account cannot be linked to Contoso" in body


def test_a_turned_off_account_whose_identity_is_linked_is_not_told_to_link_it(monkeypatch):
    """A sign-in through an identity linked to an account that is turned off is refused, and recorded under that
    account. Telling its owner to link the provider would be false: it is linked already. Nobody is told."""
    bob, root = _user("bob", is_active=False), _user("root", role="admin")
    p = _provider()
    h = Resolving(monkeypatch, [bob, root], [p], identities=[_identity(bob, p, subject="s-bob")])
    told = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None,
                        once=False: told.append((list(ids), ntype, title, body, target)) or list(ids))
    location, _ = _sign_in(h, p, sub="s-bob", email="bob@example.test")
    assert location == "/#sso-error=account_disabled", location
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == "account_disabled" for a in h.audits), h.audits
    assert told == [] and h.emails == []


@pytest.mark.parametrize("row", ["names a hosted-domain claim", "judged on the address"])
def test_under_the_sign_up_list_a_link_by_email_needs_the_address_itself_on_the_list(monkeypatch, row):
    """The vault's sign-up list restricts the provider. With a hosted-domain claim the sign-in is admitted on the
    claim, and the address it carries has not been judged: a member of the organisation holding, at the
    provider, the address of somebody outside it (a collaborator's account at another domain) is not linked to
    that account. An address on the list links as before; without the claim the address was judged already."""
    inside, outside = _user("inside"), _user("outside", email="outside@partner.test")
    root = _user("root", role="admin")
    shape = {"claims": {"domain": "hd"}} if row == "names a hosted-domain claim" else {}
    p = _provider(policy={"sso_use_signup_domains": True, "sso_link_by_email": True}, **shape)
    h = Resolving(monkeypatch, [inside, outside, root], [p],
                  account_policy={"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.test"]})
    location, _ = _sign_in(h, p, sub="s-1", email="outside@partner.test", hd="example.test")
    if row == "names a hosted-domain claim":
        assert location == "/#sso-error=no_account", location
    else:
        assert location == "/#sso-error=restricted", location           # the address itself is what is judged
    assert h.identities() == []
    location, _ = _sign_in(h, p, sub="s-2", email="inside@example.test", hd="example.test")
    assert location.startswith("/#sso="), location
    assert [i.user_id for i in h.identities()] == [inside.id]


def test_a_link_that_ends_the_password_ends_the_sessions_it_made_and_not_the_one_that_links(monkeypatch):
    """A person links, from Your account, a provider whose people hold no password. The password stops working
    with the link, and the sessions it made elsewhere end with it. The session doing the linking stays: the
    person has just proved themselves at the provider in it, and is shown what changed."""
    from app.core.models import ActiveSession
    alice = _user("alice")
    p = _provider(name="a", label="A", policy={"sso_password_login": "disabled"})
    h = Resolving(monkeypatch, [alice], [p])

    def session(token):
        return types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, is_active=True, revoked=False,
                                     temp_credential_id=None, channel="web", expires_at=None, session_token=token)

    from app.core.session_hash_utils import hash_session_token
    h.session_claims["session_token"] = "this-browsers-token"         # what the request's own token names
    here, elsewhere = session(hash_session_token("this-browsers-token")), session(hash_session_token("another"))
    h.db.rows_of(ActiveSession).extend([here, elsewhere])
    ended = []
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, **kw: ended.append(kw["session_ids"]) or len(kw["session_ids"]))
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked="), location
    assert ended == []                                           # nothing changes before the person is back
    status, out = h.finish_link(location)
    assert status == 200 and out.get("password_stopped") is True and alice.sso_only is True, out
    assert ended == [[elsewhere.id]]


def test_the_pages_offer_a_confirmation_only_where_it_would_let_a_provider_find_the_account(monkeypatch):
    """Confirming an address matters for one thing: a provider that links by email finding the account. The
    account page and the Users page offer it exactly then: the address is there and not confirmed, a provider
    that is on links by email and the account is not linked to it yet, and the account is one such a link may
    reach (not an administrator, no second factor of its own). "A second factor of its own" is the link's own
    question on both pages: a passkey kept while passkeys are switched off keeps a link out, so no confirmation
    is offered for its account either (it would count as a change to the account and change nothing)."""
    from app.core import webauthn_settings
    from app.services import sso_sign_in as sso
    open_, done = _user("open", email_confirmed_at=None), _user("done")
    bare = _user("bare", email=None, email_confirmed_at=None)
    root = _user("root", role="admin", email_confirmed_at=None)
    guarded, linked = _user("guarded", email_confirmed_at=None), _user("linked", email_confirmed_at=None)
    # An administrator reset this one's second factor, and it has not set a new one up yet: a link by email
    # stays out until it has (its next factor is set up behind its own password).
    resetting = _user("resetting", email_confirmed_at=None, second_factor_reset_at=datetime.utcnow())
    links = _provider(name="links", label="Links", policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    plain = _provider(name="plain", label="Plain")
    keyed, retired = _user("keyed", email_confirmed_at=None), _user("retired", email_confirmed_at=None)
    started = _user("started", email_confirmed_at=None)        # an authenticator begun and never confirmed: none
    people = [open_, done, bare, root, guarded, linked, resetting, keyed, retired, started]
    h = Resolving(monkeypatch, people, [links, plain],
                  identities=[_identity(linked, links, subject="s-linked"), _identity(open_, plain, subject="s-open")])
    _factor(h, guarded, "authenticator")
    _factor(h, keyed, "passkey")
    _factor(h, retired, "passkey retired")
    _factor(h, started, "enrollment never confirmed")
    monkeypatch.setattr(h.S, "_smtp_configured", lambda db: True)

    def wanted():
        one_by_one = {u.username for u in people if sso.confirmed_address_wanted(h.db, u)}
        together = sso.confirmed_address_wanted_among(h.db, people)
        assert {u.username for u in people if u.id in together} == one_by_one
        return one_by_one

    assert wanted() == {"open", "retired", "started"}
    # With passkeys switched off the kept key is no factor for a sign-in, and still keeps a link by email out.
    switched_on = webauthn_settings.enabled
    monkeypatch.setattr(webauthn_settings, "enabled", lambda: False)
    assert h.S._passkey_counts(h.db, [keyed.id]) == {} and sso.set_up_its_own_factor(h.db, keyed) is True
    assert wanted() == {"open", "retired", "started"}
    assert sso.accounts_that_set_up_a_factor(h.db, people) == {guarded.id, resetting.id, keyed.id}
    assert sso.accounts_that_set_up_a_factor(h.db, []) == set()
    # The Users page is told the same by its own route, passkeys switched off or on.
    from _async_run import run_coroutine
    import app.core.endpoint_permissions as ep
    monkeypatch.setattr(ep, "check_endpoint_permission", lambda *a, **k: None)
    for user in people:
        user.password_set_by = user.password_set_by_other_at = None

    def listed():
        rows = run_coroutine(h.S.list_users(current_user=root, db=h.db))
        return {row.username for row in rows if row.email_confirm_wanted}

    assert listed() == {"open", "retired", "started"}
    monkeypatch.setattr(webauthn_settings, "enabled", switched_on)
    assert listed() == {"open", "retired", "started"}
    # The account page is told the same, with whether a code can be sent.
    h.current_user = open_
    status, out, _ = _call(h.S, "GET", "/users/me/identities")
    assert status == 200 and out["email"] == {"address": "open@example.test", "can_send_code": True,
                                              "factor_here": True}, out
    monkeypatch.setattr(h.S, "_smtp_configured", lambda db: False)
    assert _call(h.S, "GET", "/users/me/identities")[1]["email"] == {"address": "open@example.test",
                                                                     "can_send_code": False, "factor_here": True}
    # Whether a second factor can be set up under Your account, which the page's hint goes by: not by an account
    # with no password it can type where no passkey can be made (an authenticator asks for the password again).
    from app.services import sign_in
    with monkeypatch.context() as m:
        m.setattr(sign_in, "has_a_password_it_can_type", lambda user: False)
        m.setattr(webauthn_settings, "passkeys_can_be_made", lambda: False)
        assert _call(h.S, "GET", "/users/me/identities")[1]["email"]["factor_here"] is False
        m.setattr(webauthn_settings, "passkeys_can_be_made", lambda: True)
        assert _call(h.S, "GET", "/users/me/identities")[1]["email"]["factor_here"] is True
        # Nor where passkeys are turned off, whatever the address could carry: the registration would refuse.
        m.setattr(webauthn_settings, "enabled", lambda: False)
        assert _call(h.S, "GET", "/users/me/identities")[1]["email"]["factor_here"] is False
        m.setattr(sign_in, "has_a_password_it_can_type", lambda user: True)
        assert _call(h.S, "GET", "/users/me/identities")[1]["email"]["factor_here"] is True      # the authenticator
        m.setattr(webauthn_settings, "enabled", lambda: True)
        m.setattr(webauthn_settings, "passkeys_can_be_made", lambda: False)
        assert _call(h.S, "GET", "/users/me/identities")[1]["email"]["factor_here"] is True
    h.current_user = done
    assert _call(h.S, "GET", "/users/me/identities")[1]["email"] is None
    # No provider links by email (it is off, or its setting is): nothing to offer anybody.
    links.state = "disabled"
    assert wanted() == set()
    links.state = "enabled"
    links.policy = {"sso_allowed_domains": ["example.test"]}
    assert wanted() == set()


def _provider_locks(h):
    from app.core.models import SsoProvider
    return [entry[2] for entry in h.db.log if entry[0] == "lock" and entry[1] is SsoProvider]


def test_a_provider_turned_off_while_it_answered_links_nobody_and_changes_no_account(monkeypatch):
    """The callback waits for the provider's answer, up to the whole wait. An administrator who turns the provider
    off in that time (an incident, or a change to its connection) turns it off for this answer too: the row is
    read again as it stands before the account is looked at. Nobody is linked, no account is made, and the rule of
    a provider whose people hold no password replaces no password; left on, the same sign-ins link the account
    and make the new one."""
    bob, root = _user("bob"), _user("root", role="admin")
    links = _provider(name="links", label="Links", policy={
        "sso_link_by_email": True, "sso_allowed_domains": ["example.test"], "sso_password_login": "disabled"})
    makes = _provider(name="makes", label="Makes", policy={
        "sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [bob, root], [links, makes])
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    before = (bob.password_hash, bob.sso_only, bob.sftp_password_auth)
    tries = [(links, {"sub": "bob-subject", "email": "bob@example.test"}),
             (makes, {"sub": "new-subject", "email": "new@example.test", "preferred_username": "newcomer"})]
    for p, claims in tries:
        h.db.on_lock.append(lambda p=p: setattr(p, "state", "disabled"))      # turned off while the provider answers
        location, _state = _sign_in(h, p, **claims)
        assert location == "/#sso-error=provider_disabled", location
        assert h.identities() == [] and h.codes() == [] and h.users_named("newcomer") == []
        assert (bob.password_hash, bob.sso_only, bob.sftp_password_auth) == before
    # The row was read again for this, with a lock other readers share and a save waits for.
    assert len(_provider_locks(h)) == 2 and all(lock == {"read": True} for lock in _provider_locks(h))
    refused = [a[2] for a in h.audits if a[0] == "sso_sign_in_refused"]
    assert [r.get("reason") for r in refused] == ["provider_disabled", "provider_disabled"]
    # The control: left on, the account is linked and held to the provider's rule, and the new account is made.
    for p, claims in tries:
        p.state = "enabled"
        location, _state = _sign_in(h, p, **claims)
        assert location.startswith("/#sso="), location
    assert len(h.identities()) == 2 and bob.sso_only is True and len(h.users_named("newcomer")) == 1
    # The link ended bob's password: he is not told to change a password he no longer has.
    (said,) = [body for ids, title, body in h.notice_bodies
               if ids == [str(bob.id)] and title == "A sign-in method was added"]
    assert "just now, tell an administrator at once" in said and "change your password" not in said


def test_a_link_from_your_account_is_made_on_the_provider_as_it_stands_when_the_person_is_back(monkeypatch):
    """The person was away at the provider. The link is made on the provider row as it is when they are back, read
    again and held until the link is written: a change of the password rule made meanwhile holds for this link
    (the save waits for the row, so it settles this account with the others), and a provider turned off meanwhile
    links nothing."""
    alice = _user("alice")
    p = _provider(name="a", label="A")
    h = Resolving(monkeypatch, [alice], [p])
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked="), location
    seen = len(_provider_locks(h))
    # While the person was away, the provider's people came to hold no password.
    h.db.on_lock.append(lambda: p.policy.update({"sso_password_login": "disabled"}) if isinstance(p.policy, dict)
                        else setattr(p, "policy", {"sso_password_login": "disabled"}))
    status, out = h.finish_link(location)
    assert status == 200 and out.get("password_stopped") is True and alice.sso_only is True, out
    assert _provider_locks(h)[seen:] == [{"read": True}]
    # Turned off meanwhile: nothing is linked.
    carol = _user("carol")
    q = _provider(name="b", label="B")
    h = Resolving(monkeypatch, [carol], [q])
    status, out = h.start_link(q)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(q, state)
    h.db.on_lock.append(lambda: setattr(q, "state", "disabled"))
    status, out = h.finish_link(location)
    assert status == 409 and out["detail"]["reason"] == "provider_disabled" and h.identities() == [], out


def test_a_provider_row_that_a_save_still_holds_links_nobody_and_says_so(monkeypatch):
    """A save of the provider holds its row; the read that a link is made on gives up after a short wait. The
    sign-in is sent back to the sign-in page as for a provider that did not answer, with a record of it, and the
    link from Your account answers 503: nothing is linked either way, and the person starts again."""
    from app.api import sso_router
    alice = _user("alice")
    p = _provider(name="a", label="A")
    h = Resolving(monkeypatch, [alice], [p])
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked="), location

    def busy(db, provider_id):
        raise sso_router.ProviderRowBusy()
    as_it_is = sso_router._provider_as_it_stands
    monkeypatch.setattr(sso_router, "_provider_as_it_stands", busy)
    status, out = h.finish_link(location)
    assert status == 503 and out["detail"]["reason"] == "temporarily_unavailable", out
    assert "being saved" in out["detail"]["message"] and h.identities() == []
    # A sign-in that comes back while the row is held.
    status, out = h.start(p)
    state, _ = h.state_of(out["authorization_url"])
    before = len(h.audits)
    status, location, _ = h.callback(p, state)
    assert status in (302, 303, 307) and location.endswith("sso-error=temporarily_unavailable"), (status, location)
    assert any("temporarily_unavailable" in str(row) for row in h.audits[before:]), h.audits[before:]
    assert h.identities() == []
    monkeypatch.setattr(sso_router, "_provider_as_it_stands", as_it_is)


def test_an_identity_linked_by_email_does_not_stand_in_for_a_factor_the_account_set_up_later(monkeypatch):
    """The rule in the other order. An account with no factor is linked by its email address, on the provider's
    word, and the provider's trusted MFA counts for it. Later it sets up a factor of its own. From then on a sign-in
    through that identity is asked for the account's factor: the provider's MFA stands in for it only at an
    identity the account itself put there (from its profile), which the same account links afterwards."""
    bob = _user("bob")
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"], "sso_trust_idp_mfa": True,
                          "sso_accepted_amr": ["mfa"]})
    h = Resolving(monkeypatch, [bob], [p])
    location, _ = _sign_in(h, p, email="bob@example.test", amr=["pwd", "mfa"])
    status, body = h.finish(location)
    assert status == 200 and "mfa_at" in _claims(body["access_token"]), body
    (identity,) = h.identities()
    assert identity.linked_by == "email"
    # The account sets up an authenticator of its own.
    _factor(h, bob, "authenticator")
    monkeypatch.setattr(h.S, "_login_second_factor_in_effect", lambda db, user: True)
    monkeypatch.setattr(h.S, "_second_factor_effective", lambda db, user: {"state": "active", "in_effect": True,
                                                                          "required": False})
    monkeypatch.setattr(h.S, "_sf_login_methods", lambda db, user: ["totp", "recovery"])
    location, _ = _sign_in(h, p, email="bob@example.test", amr=["pwd", "mfa"])
    status, body = h.finish(location)
    assert status == 200 and body["access_token"] is None and body["stage"] == "second_factor", body
    # The same identity as the account's own (linked again from its profile): the provider's MFA counts.
    identity.linked_by = "self"
    location, _ = _sign_in(h, p, email="bob@example.test", amr=["pwd", "mfa"])
    status, body = h.finish(location)
    assert status == 200 and "mfa_at" in _claims(body["access_token"]), body


def test_an_account_made_at_its_first_sign_in_comes_in_on_the_providers_trusted_mfa(monkeypatch):
    """An account made at its first sign-in has no factor of its own to ask for: the provider's trusted MFA counts
    from the start."""
    root = _user("root", role="admin")
    q = _provider(name="makes", policy={"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"],
                                        "sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]})
    h = Resolving(monkeypatch, [root], [q])
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    location, _ = _sign_in(h, q, sub="new-subject", email="new@example.test", preferred_username="newcomer", amr=["pwd", "mfa"])
    assert location.startswith("/#sso="), location
    status, body = h.finish(location)
    assert status == 200 and "mfa_at" in _claims(body["access_token"]), body


def test_the_requested_acr_rides_in_the_authorization_request_and_the_test_reports_the_trust(monkeypatch):
    root = _user("root", role="admin")
    p = _provider(policy={"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"], "sso_requested_acr": "urn:example:mfa"})
    h = Resolving(monkeypatch, [root], [p])
    status, out = h.start(p)
    assert status == 200 and "acr_values=urn%3Aexample%3Amfa" in out["authorization_url"], out
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    h.claims_override = {"amr": ["pwd", "mfa"]}
    status, location, _ = h.callback(p, state)
    status, body = h.finish_test(p, location)
    assert status == 200 and p.last_test["mfa_trusted"] is True and p.last_test["amr"] == ["pwd", "mfa"]
    from app.core.models import SsoProvider
    q = _provider(name="plain")
    h.db.rows_of(SsoProvider).append(q)
    assert "acr_values" not in h.start(q)[1]["authorization_url"]


def test_a_privileged_account_never_links_itself_to_a_password_less_provider(monkeypatch):
    root, p = _user("root", role="admin"), _provider(policy={"sso_password_login": "disabled"})
    h = Resolving(monkeypatch, [root], [p])
    # Refused at the start, before anybody is sent to the provider (tests/test_sso_identities_list.py).
    status, out = h.start_link(p)
    assert status == 409 and out["detail"]["reason"] == "privileged_on_password_less", out
    # And on the return, where the provider came to hold its people to no password while the person was there.
    p.policy = {"sso_password_login": "allowed"}
    status, out = h.start_link(p)
    assert status == 200, out
    p.policy = {"sso_password_login": "disabled"}
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location == "/#sso-error=privileged_on_password_less", location
    assert h.identities() == [] and h.codes() == []
    assert any(a[0] == "sso_flow_refused" and a[2].get("reason") == "privileged_on_password_less"
               and a[2].get("purpose") == "link" for a in h.audits), h.audits
    # The same provider with password sign-in allowed takes the link.
    p.policy = {"sso_password_login": "allowed"}
    status, out = h.start_link(p)
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-linked="), location


# --------------------------------------------------------------------------- the restriction comes first

@pytest.mark.parametrize("policy, claims, reason", [
    ({"sso_allowed_tenants": ["t1"]}, {"tid": "t2"}, "restricted"),
    ({"sso_allowed_tenants": ["t1"]}, {}, "restriction_claim_missing"),
    ({"sso_allowed_domains": ["example.test"]}, {"hd": "other.test"}, "restricted"),
    ({"sso_allowed_domains": ["example.test"]}, {"email_verified": False}, "restriction_claim_missing"),
    ({"sso_required_groups": ["g"]}, {"_claim_names": {"groups": "src1"}}, "restriction_claim_missing"),
    ({"sso_required_groups": ["g"]}, {"groups": ["h"]}, "restricted"),
    ({"sso_required_groups": ["g"]}, {"groups": ["g", "h"]}, None),
    ({"sso_required_groups": ["g"]}, {"groups": ["g"], "_claim_names": {"groups": "src1"}}, "restriction_claim_missing"),
    ({"sso_allowed_tenants": ["t1"]}, {"tid": "x" * 600}, "restriction_claim_missing"),      # longer than a tenant id
    ({"sso_allowed_tenants": ["t1"]}, {"tid": " T1 "}, None),
    ({"sso_use_signup_domains": True}, {"email": "alice@other.test"}, "restricted"),
    ({"sso_use_signup_domains": True}, {}, None),
])
def test_the_restriction_is_judged_before_who_the_person_is(monkeypatch, policy, claims, reason):
    alice, p = _user(), _provider(policy=policy)
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)],
                  account_policy={"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.test"]})
    location, _ = _sign_in(h, p, **claims)
    if reason is None:
        assert location.startswith("/#sso="), location
        return
    assert location == f"/#sso-error={reason}", location
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == reason for a in h.audits), h.audits
    assert h.codes() == [] and all(a[0] != "login_success" for a in h.audits)


def test_the_restriction_holds_for_an_app_sign_in_too(monkeypatch):
    alice, p = _user(), _provider(policy={"sso_allowed_tenants": ["t1"]})
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    status, out, _ = _call(h.S, "POST", f"/auth/sso/{p.id}/start", {"code_challenge": "c" * 43})
    assert status == 200, out
    state, record = h.state_of(out["authorization_url"])
    assert record["purpose"] == "app"
    h.claims_override = {"tid": "t2"}
    assert h.callback(p, state)[1] == "/#sso-error=restricted" and h.codes() == []


def test_a_pinned_tenant_is_matched_whole_and_without_case(monkeypatch):
    alice, p = _user(), _provider()
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p, tenant_id="t1")])
    location, _ = _sign_in(h, p, tid=" T1 ")
    assert location.startswith("/#sso="), location
    assert _sign_in(h, p, tid="t10")[0] == "/#sso-error=no_account"
    assert _sign_in(h, p, tid="t")[0] == "/#sso-error=no_account"


def test_the_restriction_holds_for_a_link_and_for_an_invitation_too(monkeypatch):
    root, p = _user("root", role="admin"), _provider(policy={"sso_allowed_tenants": ["t1"]})
    h = Resolving(monkeypatch, [root], [p])
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    url = sso.start(p, purpose=sso_state.LINK, source="s", client_ip="203.0.113.9", verifier_hash=_h("link-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    h.claims_override = {"tid": "t2"}
    assert h.callback(p, state)[1] == "/#sso-error=restricted" and h.codes() == [] and h.identities() == []
    token, inv = h.invite(created_by=root.id)
    location, _ = _sign_in(h, p, token, tid="t2")
    assert location == "/#sso-error=restricted" and inv.accepted_at is None and h.users_named("newbie") == []


# --------------------------------------------------------------------------- a test sign-in says what would happen

def test_a_test_sign_in_reports_the_restriction_and_what_the_vault_would_do(monkeypatch):
    root, bob = _user("root", role="admin"), _user("bob")
    p = _provider(state="tested", policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [root, bob], [p])
    from app.core import sso_state
    from app.services import sso_sign_in as sso

    def run(**claims):
        url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                        user_id=root.id, session_hash="sess-hash")
        state, _ = h.state_of(url)
        h.claims_override = claims
        status, location, _ = h.callback(p, state)
        assert location.startswith("/#sso-test="), location
        status, body = h.finish_test(p, location)
        assert status == 200, body
        return p.last_test

    summary = run(hd="other.test")
    assert summary["restriction"] == "restricted" and summary["would"].startswith("refuse")
    summary = run(email="bob@example.test")
    assert summary["restriction"] == "passes" and summary["would"] == "link the account bob by its verified email address and sign it in"
    assert h.identities() == []                                   # a test links nothing
    # An address the vault never confirmed for the account: the administrator reads why nothing would be linked.
    bob.email_confirmed_at = None
    summary = run(email="bob@example.test")
    assert summary["restriction"] == "passes" and summary["would"].startswith("refuse: an account holds this address, but "
                                                                             "the vault never confirmed"), summary
    __import__("app.core.email_confirmation", fromlist=["confirm"]).confirm(bob)
    # An account that set up its own second factor: the administrator reads where its owner links the provider.
    from app.core.models import SecondFactorEnrollment
    factor = types.SimpleNamespace(id=uuid.uuid4(), user_id=bob.id, method="totp", status="active")
    h.db.rows_of(SecondFactorEnrollment).append(factor)
    summary = run(email="bob@example.test")
    assert summary["would"].startswith("refuse: the account that owns this address set up its own second factor"), summary
    h.db.rows_of(SecondFactorEnrollment).remove(factor)
    summary = run(email="nobody@example.test")
    assert summary["would"].startswith("refuse: no account is linked")
    # Where the provider makes accounts: the link comes first, and an address that has an account gets no second.
    from app.services import sso_sign_in as sso
    made = _provider(name="makes", policy={"sso_account_creation": "jit", "sso_link_by_email": True,
                                           "sso_allowed_domains": ["example.test"]})

    def would(email, **more):
        answer = sso.ProviderAnswer(claims={"preferred_username": email.split("@")[0]}, subject="s-new",
                                    issuer="https://login.example.org", tenant_id=None, email=email,
                                    email_verified=True, display_name=None, auth_time=None)
        return sso.would_do(h.db, made, answer, None)["would"]
    assert would("bob@example.test") == "link the account bob by its verified email address and sign it in"
    made.policy = {"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]}
    assert would("bob@example.test") == (
        "refuse: an account here already holds this verified address, and no second one is made; its owner signs in "
        "to it and links this provider under Your account")
    assert would("nobody@example.test").startswith("create the account nobody at the first sign-in")
    # What the sign-in itself refuses before it makes an account is said by the test too. (A provider that sends
    # no verified address was reported as "create the account", turned on, and then refused everybody.)
    from fastapi import HTTPException
    account_policy = dict(h.S._account_policy(h.db))

    def unverified(email="nobody@example.test"):
        answer = sso.ProviderAnswer(claims={"preferred_username": "nobody"}, subject="s-new",
                                    issuer="https://login.example.org", tenant_id=None, email=email,
                                    email_verified=False, display_name=None, auth_time=None)
        return answer, sso.would_do(h.db, made, answer, None)["would"]

    def the_sign_in_refuses(answer):
        with pytest.raises(sso.Refusal) as real:
            sso._create_account(h.db, made, answer, sso.policy_of(made))
        return real.value.code

    def full(db):
        raise HTTPException(status_code=400, detail="User limit reached")
    with monkeypatch.context() as m:
        m.setattr(h.S, "_account_policy", lambda db: account_policy)
        m.setattr(sso, "restriction_of", lambda db, row, answer: None)
        m.setattr(sso.sso_policy, "is_restricted", lambda policy, account, issuer=None: True)
        account_policy["email_requirement"] = "required"
        written = len(h.db.log)
        answer, said = unverified()
        assert said.startswith("refuse: accounts here need an email address, and the provider's answer carries "
                               "none a new account may have"), said
        assert not [step for step in h.db.log[written:] if step[0] in ("add", "commit", "flush")]   # a test writes nothing
        assert the_sign_in_refuses(answer) == sso.EMAIL_REQUIRED          # the sign-in refuses for the same reason
        account_policy["email_requirement"] = "optional"
        assert unverified()[1].startswith("create the account nobody at the first sign-in")
        # The vault at its number of accounts.
        m.setattr(h.S, "_enforce_user_cap", full)
        answer, said = unverified()
        assert said == "refuse: this vault has reached the number of accounts it may hold"
        assert the_sign_in_refuses(answer) == sso.ACCOUNT_LIMIT
        m.setattr(h.S, "_enforce_user_cap", lambda db: None)
        # The same subject pinned to an account already, under another tenant of the provider.
        m.setattr(sso, "subject_owner", lambda db, row, answer: bob)
        answer, said = unverified()
        assert said == "refuse: this identity is linked to an account already, under another tenant of the provider"
        assert the_sign_in_refuses(answer) == sso.ALREADY_LINKED
        m.setattr(sso, "subject_owner", lambda db, row, answer: None)
        assert unverified()[1].startswith("create the account nobody at the first sign-in")
    assert h.users_named("nobody") == []
    h.db.rows_of(type(h.identities()[0]) if h.identities() else __import__("app.core.models", fromlist=["ExternalIdentity"]).ExternalIdentity).append(_identity(root, p))
    summary = run()
    assert summary["would"] == "sign in the linked account"


# --------------------------------------------------------------------------- the words for each reason

def test_every_reason_has_words_the_sign_in_page_can_fetch(monkeypatch):
    h = Resolving(monkeypatch, [_user()], [_provider()])
    from app.services import oidc_client as oc
    from app.services import sso_sign_in as sso
    status, body, _ = _call(h.S, "GET", "/auth/sso/reasons")
    assert status == 200, body
    reasons = body["reasons"]
    for code in (sso.RESTRICTED, sso.RESTRICTION_CLAIM_MISSING, sso.INVITATION_UNUSABLE, sso.EMAIL_REQUIRED, sso.ACCOUNT_LIMIT,
                 sso.LINK_FROM_PROFILE,
                 sso.NO_ACCOUNT, sso.ACCOUNT_DISABLED, sso.STATE_UNKNOWN, sso.PROVIDER_MIX_UP, sso.PROVIDER_DISABLED,
                 sso.ALREADY_LINKED, sso.NOT_THIS_ACCOUNT, sso.PURPOSE_NOT_READY, oc.PROVIDER_ERROR, oc.ISSUER_MISMATCH,
                 oc.TOKEN_INVALID, oc.NONCE_MISMATCH, oc.ENDPOINT_REFUSED, oc.TEMPORARILY_UNAVAILABLE, oc.DISCOVERY_INVALID):
        assert isinstance(reasons.get(code), str) and reasons[code].strip(), code
    assert sso.reason_text("something-new") == reasons[oc.PROVIDER_ERROR]
    # Every reason a sign-in is refused with in the code has its own words there: one that had none would be shown
    # as "did not complete", whatever it meant. Read from the source, so a new one is found.
    import ast
    import inspect
    from app.api import sso_router
    named = set()
    for module in (sso, sso_router):
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "Refusal"
                    and node.args):
                first = node.args[0]                    # a constant's name; a variable is a reason passed on
                if isinstance(first, ast.Name) and first.id.isupper():
                    named.add(getattr(sso, first.id))
                elif (isinstance(first, ast.Attribute) and first.attr.isupper()
                      and getattr(first.value, "id", None) in ("oc", "sso")):
                    named.add(getattr({"oc": oc, "sso": sso}[first.value.id], first.attr))
    assert {"invitation_address", "link_from_your_account", "held_to_a_provider"} <= named
    assert not [code for code in sorted(named) if not (reasons.get(code) or "").strip()]


# --------------------------------------------------------------------------- whose word an address is

def test_an_address_is_confirmed_only_until_it_changes():
    """The mark belongs to the address, not to the account: any change of the address clears it, whoever makes the
    change and by whatever path (the column's own listener), and only the paths that confirm set it again."""
    from app.core import email_confirmation as ec
    from app.core.models import User
    bob = User(username="bob", email="bob@example.test")
    assert not ec.confirmed(bob)
    ec.confirm(bob)
    assert ec.confirmed(bob)
    bob.email = "Bob@Example.test"                      # the same address in other letters
    assert ec.confirmed(bob)
    bob.email = "victim@example.test"
    assert not ec.confirmed(bob) and bob.email_confirmed_at is None
    ec.confirm(bob)
    bob.email = None
    assert bob.email_confirmed_at is None
    ec.confirm(bob)
    assert bob.email_confirmed_at is None and not ec.confirmed(bob)     # no address: nothing to confirm
    # A mark given before the address is not a mark for it.
    eve = User(email_confirmed_at=datetime.utcnow(), username="eve", email="eve@example.test")
    assert not ec.confirmed(eve)
    # The mark names its address. An address written where the listener does not run (a statement over many rows,
    # an earlier release) leaves the mark and what it was given for: it is no confirmation of the new address, and
    # is one again only if the account holds the old address again.
    from sqlalchemy.orm.attributes import set_committed_value
    carol = User(username="carol", email="carol@example.test")
    ec.confirm(carol)
    assert carol.email_confirmed_for == ec.mark_for("Carol@Example.test ") and len(carol.email_confirmed_for) == 64
    assert "carol" not in carol.email_confirmed_for                 # a digest: no second copy of the address
    set_committed_value(carol, "email", "victim@example.test")
    assert carol.email_confirmed_at is not None and not ec.confirmed(carol)
    set_committed_value(carol, "email", "CAROL@example.test")
    assert ec.confirmed(carol)
    carol.email = "other@example.test"
    assert carol.email_confirmed_at is None and carol.email_confirmed_for is None
    # The mark folds an address as the vault compares addresses: ASCII letters only. Another case of a letter
    # outside ASCII is another address to the vault, and to the mark.
    dora = User(username="dora", email="d\u00c9sir\u00e9e@example.test")
    ec.confirm(dora)
    assert ec.confirmed(dora) and ec.mark_for("D\u00c9SIR\u00e9E@EXAMPLE.test") == dora.email_confirmed_for
    assert ec.mark_for("d\u00e9sir\u00e9e@example.test") != dora.email_confirmed_for
    dora.email = "d\u00e9sir\u00e9e@example.test"
    assert dora.email_confirmed_at is None and not ec.confirmed(dora)


def test_the_addresses_an_invitation_carried_are_confirmed_once_not_at_every_start():
    """At the first start with the mark, an account made from an invitation that carried the address it still holds
    is confirmed. Once: at every start the statement would confirm again an address the account lost and its
    owner then typed back with the password alone, which is the vault's word for nothing."""
    from app.core import email_confirmation as ec
    from app.core.models import SystemSetting

    class _Once:
        def __init__(self):
            self.settings, self.ran, self.commits = [], [], 0

        def query(self, model):
            assert model is SystemSetting
            return self

        def filter(self, *a):
            return self

        def first(self):
            return next((row for row in self.settings if row.key == ec.BACKFILL_MARKER), None)

        def execute(self, statement):
            self.ran.append(str(statement))
            return types.SimpleNamespace(rowcount=3)

        def add(self, row):
            self.settings.append(row)

        def commit(self):
            self.commits += 1
    db = _Once()
    assert ec.backfill_once(db) == 3 and db.ran == [ec.BACKFILL] and db.commits == 1
    assert [(row.key, row.value) for row in db.settings] == [(ec.BACKFILL_MARKER, {"rows": 3})]
    assert ec.backfill_once(db) == 0 and ec.backfill_once(db) == 0
    assert db.ran == [ec.BACKFILL] and len(db.settings) == 1                  # never again
    # At start it is this that runs, not the statement itself among those run at every start.
    import inspect
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.api import api_server as api
    source = inspect.getsource(api)
    assert "email_confirmation.backfill_once(db)" in source and "_EMAIL_CONFIRMATION_BACKFILL" not in source
    # What is not an account object at all is unconfirmed.
    assert not ec.confirmed(types.SimpleNamespace(email="x@example.test"))


def test_an_invitation_confirms_the_address_it_carried_and_a_providers_word_confirms_none(monkeypatch):
    """Accepted through a provider: an address the administrator wrote into the invitation is the vault's own word;
    an address taken from the provider's token, at an invitation without one or at a first sign-in, is the
    provider's word and stays unconfirmed, so another provider never links to the account by it."""
    p = _provider(policy={"sso_account_creation": "jit", "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [], [p], account_policy={"invite_enabled": True})
    monkeypatch.setattr(h.S, "_invitation_inviter_can_act", lambda db, inv, lock=False: True)
    monkeypatch.setattr(h.S, "_username_kept", lambda name: False)
    monkeypatch.setattr(h.S, "_enforce_user_cap", lambda db: None)
    token, inv = h.invite(username="invited", email="invited@example.test")
    _accept(h, p, token, sub="s1", email="invited@example.test")
    token, inv = h.invite(username="typed")
    _accept(h, p, token, sub="s2", email="typed@example.test")
    location, _ = _sign_in(h, p, sub="s3", email="first@example.test", preferred_username="first")
    assert location.startswith("/#sso="), location
    confirmed = {u.username: u.email_confirmed_at is not None for u in h.db.rows_of(type(h.users_named("invited")[0]))}
    assert confirmed == {"invited": True, "typed": False, "first": False}, confirmed
    assert {u.username: u.email for u in h.db.rows_of(type(h.users_named("invited")[0]))} == {
        "invited": "invited@example.test", "typed": "typed@example.test", "first": "first@example.test"}
