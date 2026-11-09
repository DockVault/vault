"""Who the person is at the single sign-on callback (app/services/sso_sign_in.py, resolve_account): the provider's
restriction judged first for every purpose but a test; an invitation accepted through the provider (the start
carries it into the login state; the invited account is made at the callback with a password nobody knows and
this identity, and the invitation is claimed once); an existing account linked by its verified email when the
provider allows it and is restricted; every refusal in between; what a test sign-in says it would do; the words
the sign-in page fetches for each reason. Offline: fake stores, the records observed."""
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


# --------------------------------------------------------------------------- an invitation accepted through the provider

def test_an_invitation_is_accepted_through_the_provider(monkeypatch):
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id)
    location, record = _sign_in(h, p, token)
    assert record["extras"] == {"invitation_id": str(inv.id)} and "invite_accept_prefix" in h.limiter
    assert location.startswith("/#sso="), location
    (user,) = h.users_named("newbie")
    from app.core.models import RoleEnum
    assert user.role == RoleEnum.USER and user.email == "alice@example.test" and user.created_by == root.id
    assert user.password_hash.startswith("argon2:") and user.sso_only is False and user.sftp_password_auth is True
    (identity,) = h.identities()
    assert identity.user_id == user.id and identity.linked_by == "invitation" and identity.subject == "subject-1"
    assert inv.accepted_at is not None and inv.accepted_user_id == user.id
    assert h.grants == [(str(user.id), str(user.role), False)] and h.admin_grants == []
    assert ("account_invitation_accepted", "success",
            {"username": "newbie", "role": str(user.role), "token_prefix": inv.token_prefix, "method": "sso",
             "provider_id": str(p.id)}) in h.audits, h.audits
    assert ("sso_identity_linked", "success", {"provider_id": str(p.id), "linked_by": "invitation"}) in h.audits
    assert ("account_welcome", "alice@example.test", None) in h.emails
    assert h.notices == []                                        # an invitation is the owner's own doing: no notice
    # The account stood before the code was handed out, and the code signs it in.
    assert ("commit",) in h.db.log
    status, body = h.finish(location)
    assert status == 200, body
    assert _claims(body["access_token"])["sub"] == str(user.id) and ("login_success", "newbie", []) in h.audits
    # The invitation is spent: the token starts nothing now.
    status, out = h.start(p, invitation=token)
    assert status == 404 and out["detail"]["reason"] == "invitation_unusable"


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
    ("administrator_without_password", "invitation_unusable", "administrator_on_password_less_provider"),
    ("subject_pinned_elsewhere", "already_linked", "subject_linked_elsewhere"),
    ("claim_lost", "invitation_unusable", "claim_lost"),
])
def test_an_invitation_that_cannot_be_completed_at_the_callback_makes_no_account(monkeypatch, arrange, reason, detail):
    root = _user("root", role="admin")
    p = _provider(policy={"sso_password_login": "disabled"} if arrange == "administrator_without_password" else None)
    users = [root]
    if arrange == "invitation_address_in_use":
        users.append(_user("holder", email="taken@example.test"))
    if arrange == "username_is_an_address":
        users.append(_user("holder", email="newbie"))
    identities = [_identity(_user("other"), p, tenant_id="t1")] if arrange == "subject_pinned_elsewhere" else []
    h = Resolving(monkeypatch, users, [p], identities=identities)
    admin_role = arrange in ("inviter_demoted", "administrator_without_password", "claim_lost")
    token, inv = h.invite(created_by=root.id, role="admin" if admin_role else "user",
                          email="taken@example.test" if arrange == "invitation_address_in_use" else None)
    status, out = h.start(p, invitation=token)
    state, _ = h.state_of(out["authorization_url"])
    now = datetime.utcnow()
    from app.core.models import RoleEnum, SystemSetting
    if arrange == "revoked":
        inv.revoked_at = now
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
        # Revoked between the inviter's locked read and the atomic claim: the claim finds no pending row.
        h.db.on_lock.append(lambda: setattr(inv, "revoked_at", datetime.utcnow()))
    status, location, _ = h.callback(p, state)
    assert location == f"/#sso-error={reason}", location
    assert h.users_named("newbie") == [] and len(h.identities()) == len(identities) and h.codes() == []
    assert ("commit",) not in h.db.log                                 # nothing of the attempt was committed
    assert inv.accepted_user_id is None or arrange == "accepted_meanwhile"
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == reason for a in h.audits), h.audits
    assert any(a[0] == "account_invitation_accept_failed" and a[2] == {"token_prefix": inv.token_prefix, "reason": detail}
               for a in h.audits), h.audits
    if arrange == "subject_pinned_elsewhere":
        assert inv.accepted_at is None                                 # still pending: the person may be invited again


@pytest.mark.parametrize("arrange, expected", [
    ("invitation_address", "invited@example.test"),      # the invitation's address, whatever the provider says
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
    location, _ = _sign_in(h, p, token, **claims)
    assert location.startswith("/#sso="), location
    (user,) = h.users_named("newbie")
    assert user.email == expected


def test_an_administrators_invitation_records_the_grant_keeps_a_password_and_is_announced(monkeypatch):
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id, role="admin", inviter_lineage=[str(uuid.uuid4())])
    location, _ = _sign_in(h, p, token)
    assert location.startswith("/#sso="), location
    (user,) = h.users_named("newbie")
    from app.core.models import RoleEnum
    assert user.role == RoleEnum.ADMIN
    assert user.sso_only is False and user.sftp_password_auth is True       # an administrator always keeps a password
    assert h.admin_grants == [("newbie", "root", inv.inviter_lineage)] and h.announcements == [("newbie", "root", "invited")]


def test_every_new_account_gets_a_password_hash_of_its_own_that_nobody_knows(monkeypatch):
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token1, _ = h.invite(username="first", created_by=root.id)
    token2, _ = h.invite(username="second", created_by=root.id)
    _sign_in(h, p, token1)
    _sign_in(h, p, token2, sub="subject-2", email="second@example.test")
    (first,), (second,) = h.users_named("first"), h.users_named("second")
    assert first.password_hash != second.password_hash
    assert first.password_hash.startswith("argon2:") and first.password_hash != "argon2:" + _h("")
    assert len(first.password_hash) == len("argon2:") + 64          # a hash of a random secret, no plain text


def test_the_account_stands_when_the_code_store_fails_afterwards(monkeypatch):
    root, p = _user("root", role="admin"), _provider()
    h = Resolving(monkeypatch, [root], [p])
    token, inv = h.invite(created_by=root.id)
    from app.core import sign_in_codes

    def unavailable(*a, **kw):
        raise sign_in_codes.Unavailable()
    real_store = sign_in_codes.store
    monkeypatch.setattr(sign_in_codes, "store", unavailable)
    location, _ = _sign_in(h, p, token)
    assert location == "/#sso-error=temporarily_unavailable", location
    (user,) = h.users_named("newbie")
    assert inv.accepted_user_id == user.id and ("commit",) in h.db.log and len(h.identities()) == 1
    # The next sign-in finds the identity: one account, one sign-in more.
    monkeypatch.setattr(sign_in_codes, "store", real_store)
    location, _ = _sign_in(h, p)
    assert location.startswith("/#sso=") and len(h.users_named("newbie")) == 1 and h.finish(location)[0] == 200


@pytest.mark.parametrize("password_login, sso_only", [("allowed", False), ("disabled", True)])
def test_a_user_made_by_an_invitation_is_sso_only_when_the_provider_says_so(monkeypatch, password_login, sso_only):
    root, p = _user("root", role="admin"), _provider(policy={"sso_password_login": password_login})
    h = Resolving(monkeypatch, [root], [p])
    token, _ = h.invite(created_by=root.id)
    _sign_in(h, p, token)
    (user,) = h.users_named("newbie")
    assert user.sso_only is sso_only and user.sftp_password_auth is (not sso_only)


def test_a_known_identity_signs_in_and_leaves_the_invitation_it_carried_untouched(monkeypatch):
    root, alice, p = _user("root", role="admin"), _user(), _provider()
    h = Resolving(monkeypatch, [root, alice], [p], identities=[_identity(alice, p)])
    token, inv = h.invite(created_by=root.id)
    location, _ = _sign_in(h, p, token)
    status, body = h.finish(location)
    assert status == 200 and _claims(body["access_token"])["sub"] == str(alice.id)
    assert inv.accepted_at is None and h.users_named("newbie") == [] and len(h.identities()) == 1


# --------------------------------------------------------------------------- an account linked by its verified email

def test_a_verified_email_links_an_existing_account_when_the_provider_allows_it_and_is_restricted(monkeypatch):
    bob, p = _user("bob"), _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [bob], [p])
    location, _ = _sign_in(h, p, email="bob@example.test")
    assert location.startswith("/#sso="), location
    (identity,) = h.identities()
    assert identity.user_id == bob.id and identity.linked_by == "self" and identity.email_at_link == "bob@example.test"
    assert ("sso_identity_linked", "success", {"provider_id": str(p.id), "linked_by": "self"}) in h.audits
    assert ([str(bob.id)], "A sign-in method was added") in h.notices
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
    assert location == "/#sso-error=restricted", location
    assert h.identities() == [] and h.codes() == [] and h.notices == []
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == "restricted"
               and a[2].get("detail") == f"privileged_account:{kind}" for a in h.audits), h.audits
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
    assert ("sso_identity_linked", "success", {"provider_id": str(p.id), "linked_by": "jit"}) in h.audits
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
    assert p.last_test["would"] == "create the account alice.e at the first sign-in and sign it in"
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
    status, out = h.start_link(p)
    assert status == 200, out
    state, _ = h.state_of(out["authorization_url"])
    status, location, _ = h.callback(p, state)
    assert location == "/#sso-error=privileged_on_password_less", location
    assert h.identities() == [] and h.codes() == []
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == "privileged_on_password_less" for a in h.audits), h.audits
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
    summary = run(email="nobody@example.test")
    assert summary["would"].startswith("refuse: no account is linked")
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
                 sso.NO_ACCOUNT, sso.ACCOUNT_DISABLED, sso.STATE_UNKNOWN, sso.PROVIDER_MIX_UP, sso.PROVIDER_DISABLED,
                 sso.ALREADY_LINKED, sso.NOT_THIS_ACCOUNT, sso.PURPOSE_NOT_READY, oc.PROVIDER_ERROR, oc.ISSUER_MISMATCH,
                 oc.TOKEN_INVALID, oc.NONCE_MISMATCH, oc.ENDPOINT_REFUSED, oc.TEMPORARILY_UNAVAILABLE, oc.DISCOVERY_INVALID):
        assert isinstance(reasons.get(code), str) and reasons[code].strip(), code
    assert sso.reason_text("something-new") == reasons[oc.PROVIDER_ERROR]
