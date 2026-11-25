"""Accounts that sign in only through their provider (app/core/sso_only.py, app/core/privileged_accounts.py): the
unusable password and the SFTP flag, never for a privileged account; the password door refusing the account after
the hash check with the reason in the audit; no reset link minted for it by anyone, a link that outlived the change
refused; no password change; the provider setting's save-time refusal naming the accounts; the setting applied to
the linked accounts both ways. Offline."""
import types
import uuid
from datetime import datetime

import pytest

from _bare_api_env import set_bare_api_env
from test_sso_resolution import Resolving, _sign_in
from test_sso_sign_in import ONE_STEP, _call, _identity, _provider, _user

pytestmark = pytest.mark.unit


def _mod():
    set_bare_api_env()
    from app.core import privileged_accounts, sso_only
    return privileged_accounts, sso_only


def test_an_sso_only_account_has_a_password_nobody_knows_and_no_sftp_password(monkeypatch):
    privileged_accounts, sso_only = _mod()
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    from _memory_db import MemoryDB
    from app.core.models import ActiveSession
    alice = _user(sso_only=False)
    db = MemoryDB({ActiveSession: []})
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    sso_only.make_sso_only(db, alice)
    assert alice.sso_only is True and alice.sftp_password_auth is False
    assert alice.password_hash.startswith("argon2:") and len(alice.password_hash) > 40 and alice.password_hash != "x"
    # Made twice: a different unknown password each time.
    first = alice.password_hash
    sso_only.make_sso_only(db, alice)
    assert alice.password_hash != first


def test_an_account_made_provider_only_keeps_no_session_its_password_made_and_owns_no_password(monkeypatch):
    """The password stops working: the sessions it made end with it (whoever holds one, a thief of the password
    included, would otherwise stay signed in until it expires). That is every web session that is not revoked,
    also one a later sign-in replaced (marked inactive, never revoked: its token still works), and an SFTP
    session a password made. What came through a provider stays, and so do the session the request itself came
    through (the person has just proved themselves at the provider in it), a temporary credential's, an SFTP
    session a key made, another account's and one that is revoked already. The hash holds random bytes from now,
    here and when passwords are allowed again: it is marked as a password somebody else set, so an account made
    an administrator later is sent a link to choose one, where it must type it."""
    privileged_accounts, sso_only = _mod()
    from _memory_db import MemoryDB
    from app.api import api_server as api
    from app.core import password_origin, security
    from app.core.models import ActiveSession, SsoSession
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    alice = _user(sso_only=False, password_set_by=None, password_set_by_other_at=None)

    def session(**extra):
        fields = dict(id=uuid.uuid4(), user_id=alice.id, is_active=True, revoked=False, temp_credential_id=None,
                      channel="web", expires_at=datetime(2026, 12, 21))
        fields.update(extra)
        return types.SimpleNamespace(**fields)

    by_password, from_before_channels = session(), session(channel=None)
    replaced_by_a_later_sign_in, sftp_by_password = session(is_active=False), session(channel="sftp")
    through_a_provider, this_request = session(), session()
    stay = [through_a_provider, this_request, session(channel="sftp", expires_at=None),       # a key made it
            session(temp_credential_id=uuid.uuid4()), session(user_id=uuid.uuid4()),
            session(is_active=False, revoked=True)]
    db = MemoryDB({ActiveSession: [by_password, from_before_channels, replaced_by_a_later_sign_in, sftp_by_password,
                                   *stay],
                   SsoSession: [types.SimpleNamespace(session_id=through_a_provider.id)]})
    ended, turns = [], []
    monkeypatch.setattr(api, "_sessions_turn", lambda db, user_id: turns.append((user_id, len(ended))))
    monkeypatch.setattr(api, "_revoke_sessions", lambda db, **kw: ended.append(kw) or len(kw["session_ids"]))
    sso_only.make_sso_only(db, alice, keep_session=this_request.id)
    assert ended == [{"session_ids": [by_password.id, from_before_channels.id, replaced_by_a_later_sign_in.id,
                                      sftp_by_password.id], "actor_username": "system", "durable": True}]
    assert turns == [(alice.id, 0)]                              # the account's turn, before its sessions are read
    assert password_origin.is_set_by_other(alice) and alice.password_set_by is None
    # Nothing to end: nothing is asked of the session machinery.
    del ended[:]
    assert sso_only.end_sessions_no_provider_made(db, _user("bob")) == 0 and ended == []
    # Passwords allowed again: the hash is still nobody's, and says so.
    password_origin.set_by_self(alice)
    sso_only.allow_password_sign_in(db, alice)
    assert alice.sso_only is False and password_origin.is_set_by_other(alice) and alice.password_set_by is None


@pytest.mark.parametrize("kind", ["administrator", "auditor_right"])
def test_a_privileged_account_is_never_made_sso_only(monkeypatch, kind):
    privileged_accounts, sso_only = _mod()
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: kind)
    root = _user("root", role="admin", sso_only=False)
    with pytest.raises(sso_only.Privileged) as refused:
        sso_only.make_sso_only(types.SimpleNamespace(), root)
    assert "root" in str(refused.value) and root.sso_only is False and root.password_hash == "x"


def test_who_is_privileged(monkeypatch):
    privileged_accounts, _ = _mod()
    from app.core import auditor_rights
    root, bob = _user("root", role="admin"), _user("bob")
    grants = {}
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: grants.get(user_id))
    db = types.SimpleNamespace()                      # no get_bind: the grants are asked directly
    assert privileged_accounts.kind(db, root) == "administrator"
    assert privileged_accounts.kind(db, bob) is None
    grants[bob.id] = object()
    assert privileged_accounts.kind(db, bob) == "auditor_right"
    assert privileged_accounts.kind(db, None) is None
    # A database without the grants table holds no grant.
    monkeypatch.setattr(auditor_rights, "_has_grants", lambda db: False)
    assert privileged_accounts.kind(types.SimpleNamespace(get_bind=lambda: None), bob) is None


def test_the_password_door_refuses_an_sso_only_account_after_the_hash_check(monkeypatch):
    set_bare_api_env()
    from app.core import security
    from app.services import auth_service as A
    from app.core import sign_in_lockout
    from app.core.models import User
    from test_sso_sign_in import DB
    alice = _user(sso_only=True, password_hash="right")
    seen = []
    monkeypatch.setattr(A, "verify_password", lambda plain, hashed: seen.append((plain, hashed)) or plain == "pw")
    monkeypatch.setattr(A, "account_locked", lambda user: False)
    monkeypatch.setattr(sign_in_lockout, "release_expired", lambda *a, **k: 0)
    monkeypatch.setattr(sign_in_lockout, "lock_in_force", lambda *a, **k: None)
    monkeypatch.setattr(sign_in_lockout, "count_at_limit", lambda *a, **k: None)
    db = DB({User: [alice]})
    committed = db.log
    svc = A.AuthService(db)
    counted = []
    monkeypatch.setattr(svc, "_record_failed_login", lambda name, ip, user=None: counted.append(name))
    with pytest.raises(A.InvalidCredentialsError) as refused:
        svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9")
    assert "identity provider" in str(refused.value) and seen == [("pw", "right")] and ("commit",) in committed and counted == []
    # A wrong password is still a wrong password: counted, and told apart from nothing.
    with pytest.raises(A.InvalidCredentialsError) as refused:
        svc._authenticate_in_turn(alice, "alice", "nope", "203.0.113.9")
    assert "Invalid username or password" in str(refused.value) and counted == ["alice"]


def test_no_reset_link_and_no_password_change_for_an_sso_only_account(monkeypatch):
    root, alice = _user("root", role="admin"), _user(sso_only=True)
    p = _provider()
    h = Resolving(monkeypatch, [root, alice], [p], identities=[_identity(alice, p)])
    S = h.S
    h.current_user = root
    monkeypatch.setitem(S.app.dependency_overrides, S.get_current_user, lambda: h.current_user)
    minted = []
    monkeypatch.setattr(S, "_mint_reset_link", lambda db, user, base_url, **kw: minted.append(user.username) or "https://x/reset/t")
    # The administrator's two routes refuse before anything is minted.
    status, body, _ = _call(S, "POST", f"/users/{alice.id}/reset-link")
    assert status == 409 and "provider" in body["detail"], body
    status, body, _ = _call(S, "POST", f"/users/{alice.id}/send-reset-link")
    assert status == 409, body
    assert minted == []
    # The self-service request answers as for anyone and mints nothing, with self-service reset on, mail set up
    # and a public address to build the link on (without them nobody gets a link, and the pin would hold for the
    # wrong reason).
    sent = []
    monkeypatch.setattr(S, "_public_base_url", lambda: "https://vault.example.test")
    monkeypatch.setattr(S, "_password_reset_policy", lambda db: (True, 3600))
    monkeypatch.setattr(S, "_smtp_configured", lambda db: True)
    monkeypatch.setattr(S, "_mint_and_send_reset_async", lambda user_id, base_url: sent.append(user_id))
    monkeypatch.setattr(S, "_resolve_reset_user", lambda db, identifier: alice)
    status, body, _ = _call(S, "POST", "/auth/forgot-password", {"identifier": "alice"})
    assert status == 202 and sent == [], body
    monkeypatch.setattr(S, "_resolve_reset_user", lambda db, identifier: root)
    status, body, _ = _call(S, "POST", "/auth/forgot-password", {"identifier": "root"})
    assert status == 202 and sent == [root.id], body                    # an ordinary account gets its link
    # A link that outlived the change is refused as any unusable link, at the form and at the reset.
    link = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, created_by=root.id, made_by_other=True,
                                 consumed_at=None, token_prefix="abc")
    monkeypatch.setattr(S, "_resolve_valid_reset_token", lambda db, token: link)
    refused = []
    monkeypatch.setattr(S, "_refuse_reset_link", lambda db, r, target, reason, *, ip: refused.append((target.username, reason)))
    status, body, _ = _call(S, "GET", "/reset/some-token")
    assert status == 404, body
    status, body, _ = _call(S, "POST", "/reset/some-token", {"new_password": "a-new-password-1"})
    assert status == 404 and refused == [("alice", "sso_only")] and alice.password_hash == "x", body
    # An administrator cannot set it a password or turn its SFTP password sign-in on, at the route.
    status, body, _ = _call(S, "PATCH", f"/users/{alice.id}", {"password": "a-new-password-1"})
    assert status == 409 and "provider" in body["detail"], body
    status, body, _ = _call(S, "PATCH", f"/users/{alice.id}", {"sftp_password_auth": True})
    assert status == 409 and "SSH key" in body["detail"], body
    assert alice.password_hash == "x" and alice.sftp_password_auth is True
    # The account cannot set a password.
    h.current_user = alice
    status, body, _ = _call(S, "PATCH", "/users/me", {"current_password": "pw", "new_password": "a-new-password-1"})
    assert status == 409 and "no password of its own" in body["detail"], body
    # Other self-service changes stand; the SFTP password sign-in cannot be turned back on, by anyone.
    status, body, _ = _call(S, "PATCH", "/users/me", {"sftp_enabled": False})
    assert status == 200, body
    alice.sftp_password_auth = False
    status, body, _ = _call(S, "PATCH", "/users/me", {"sftp_password_auth": True})
    assert status == 409 and "SSH key" in body["detail"], body
    assert alice.sftp_password_auth is False
    import pytest as _pytest
    from fastapi import HTTPException
    with _pytest.raises(HTTPException) as refused:
        S._refuse_sftp_password_for_sso_only(h.db, alice, True)        # the administrator's update asks the same
    assert refused.value.status_code == 409
    S._refuse_sftp_password_for_sso_only(h.db, alice, False)            # turning it off is always allowed
    S._refuse_sftp_password_for_sso_only(h.db, root, True)              # an ordinary account may turn it on


def test_no_administrator_sets_a_password_on_or_promotes_an_sso_only_account(monkeypatch):
    """A password set by an administrator would go live the moment the flag clears; the administrator role needs a
    password for the fixed step-ups. Both are refused while a provider whose people hold no password holds the
    account to none: at the credential change a held approval applies as well as at the route, and the auditor
    right's preconditions name it. (An account held only because it was made at a first sign-in is promoted:
    tests/test_sso_leavers.py.) Letting the account hold a password again clears the flag, sets a hash nobody
    knows and mints no link."""
    privileged_accounts, sso_only = _mod()
    from fastapi import HTTPException
    from app.core import credential_changes as cc
    from app.core import security
    import app.api.api_server as S
    alice = _user(sso_only=True, password_hash="unusable")
    with pytest.raises(HTTPException) as refused:
        S._make_credential_change(types.SimpleNamespace(), cc.PASSWORD, alice, {"password_hash": "admins-choice"},
                                  actor_id=uuid.uuid4(), actor_name="root")
    assert refused.value.status_code == 409 and alice.password_hash == "unusable"
    # The promotion is refused where every promotion passes (the Users page, the user-management API, an approval).
    from app.core import admin_grants, auditor_rights
    monkeypatch.setattr(auditor_rights, "promotion_refusal", lambda db, user: None)
    recorded = []
    monkeypatch.setattr(admin_grants, "record", lambda db, user_id, **kw: recorded.append(user_id))
    from _memory_db import MemoryDB
    from app.core.models import ExternalIdentity, SsoProvider
    holding = _provider(policy={"sso_password_login": "disabled"})
    linked = MemoryDB({SsoProvider: [holding], ExternalIdentity: [_identity(alice, holding)]})
    with pytest.raises(HTTPException) as refused:
        S._record_admin_grant(linked, alice, by=_user("root", role="admin"))
    assert refused.value.status_code == 409 and "allow password sign-in" in refused.value.detail and recorded == []
    assert alice.sso_only is True
    alice.sso_only = False
    monkeypatch.setattr(S, "_revoke_reset_links_outranked_by", lambda db, user, actor: None)
    from app.services import sign_in
    monkeypatch.setattr(S, "_revoke_sessions", lambda db, **kw: 0)          # a promotion ends the account's sessions
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda db, user_id: None)
    S._record_admin_grant(types.SimpleNamespace(), alice, by=_user("root", role="admin"))
    assert recorded == [alice.id]
    alice.sso_only = True
    # The auditor right's preconditions name it too.
    monkeypatch.setattr(auditor_rights, "active_totp", lambda db, user_id: object())
    monkeypatch.setattr(cc, "last_applied", lambda db, user_id, now: None)
    assert auditor_rights.preconditions(types.SimpleNamespace(), alice) == [auditor_rights.SSO_ONLY]
    assert "identity provider" in auditor_rights.text(auditor_rights.SSO_ONLY)
    # Allowing a password again sets a fresh unknown hash: nothing written meanwhile is a password. No reset link
    # is minted here; one is made the ordinary way, for this one account, under that route's own rules.
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    alice.password_hash = "admins-choice"
    minted = []
    monkeypatch.setattr(S, "_mint_reset_link", lambda *a, **kw: minted.append(a) or "https://x/reset/t")
    assert sso_only.allow_password_sign_in(types.SimpleNamespace(), alice) is None
    assert alice.sso_only is False and alice.password_hash.startswith("argon2:")
    assert alice.password_hash != "admins-choice" and minted == []
    assert not hasattr(sso_only, "restore_password_sign_in")


def test_the_sftp_door_refuses_an_sso_only_account_too(monkeypatch):
    """The SFTP password sign-in goes through the same service as the web's: an SSO-only account is refused there as
    well, whatever its SFTP password flag says."""
    set_bare_api_env()
    from app.core import sign_in_lockout
    from app.core.models import User
    from app.services import auth_service as A
    from test_sso_sign_in import DB
    alice = _user(sso_only=True, password_hash="right", sftp_password_auth=True)
    monkeypatch.setattr(A, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "right")
    monkeypatch.setattr(A, "account_locked", lambda user: False)
    for name in ("release_expired", "lock_in_force", "count_at_limit"):
        monkeypatch.setattr(sign_in_lockout, name, lambda *a, **k: None)
    svc = A.AuthService(DB({User: [alice]}))
    monkeypatch.setattr(svc, "_record_failed_login", lambda name, ip, user=None: None)
    with pytest.raises(A.InvalidCredentialsError) as refused:
        svc._authenticate_in_turn(alice, "alice", "pw", "203.0.113.9", channel=A.AuthService.SFTP)
    assert "identity provider" in str(refused.value)


def test_the_provider_setting_is_refused_while_a_privileged_account_is_linked_and_applied_both_ways(monkeypatch):
    privileged_accounts, sso_only = _mod()
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    root, bob, carol = _user("root", role="admin"), _user("bob", sso_only=False), _user("carol", sso_only=False)
    p = _provider()
    h = Resolving(monkeypatch, [root, bob, carol], [p],
                  identities=[_identity(root, p, subject="s-root"), _identity(bob, p, subject="s-bob"), _identity(carol, p, subject="s-carol")])
    from app.core import auditor_rights
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: object() if user_id == carol.id else None)
    why = sso_only.disabled_refusal(h.db, p)
    assert "root (an administrator)" in why and "carol (holding the auditor right" in why and "bob" not in why
    # Without them: bob becomes SSO-only; back to allowed: bob may hold a password again, and no link is minted
    # for anyone (a provider's setting never hands out a way into its linked accounts).
    h.identities()[:] = [i for i in h.identities() if i.user_id == bob.id]
    assert sso_only.disabled_refusal(h.db, p) is None
    minted = []
    monkeypatch.setattr(h.S, "_mint_reset_link", lambda db, user, base_url, **kw: minted.append((user.username, kw)) or "https://x/reset/t")
    p.policy = {"sso_password_login": "disabled"}
    changed = sso_only.apply_password_login(h.db, p)
    assert changed == {"made_sso_only": ["bob"], "restored": []}
    assert bob.sso_only is True and bob.sftp_password_auth is False and bob.password_hash.startswith("argon2:")
    unknown = bob.password_hash
    changed = sso_only.apply_password_login(h.db, p)
    assert changed == {"made_sso_only": [], "restored": []}                    # already so
    p.policy = {"sso_password_login": "allowed"}
    changed = sso_only.apply_password_login(h.db, p)
    assert changed == {"made_sso_only": [], "restored": ["bob"]}
    assert bob.sso_only is False and minted == []
    assert bob.password_hash.startswith("argon2:") and bob.password_hash != unknown    # still one nobody knows
    assert sso_only.apply_password_login(h.db, p) == {"made_sso_only": [], "restored": []}


def test_a_link_from_the_profile_tells_that_the_password_stopped_from_the_flag_as_committed(monkeypatch):
    """Restored by a save while the link waited for the account's turn, and ended again by this link: the owner
    is told. Read before the turn, the flag said there was no password to end."""
    privileged_accounts, sso_only = _mod()
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    alice = _user("alice")
    first = _provider(name="first", label="First", policy={"sso_password_login": "disabled"})
    second = _provider(name="second", label="Second", policy={"sso_password_login": "disabled"})
    h = Resolving(monkeypatch, [alice], [first, second], identities=[_identity(alice, first)])
    alice.sso_only = True
    h.current_user = alice
    status, out = h.start_link(second)
    assert status == 200, out
    state, _ = h.state_of(out["authorization_url"])
    h.claims_override = {"sub": "s-second"}
    status, location, _ = h.callback(second, state)
    assert location.startswith("/#sso-linked="), location
    turns = []

    def the_save_commits_while_the_link_waits(db, user_id):
        turns.append(str(user_id))
        if len(turns) == 1:
            first.policy = {"sso_password_login": "allowed"}
            alice.sso_only = False
    monkeypatch.setattr(h.S, "_sessions_turn", the_save_commits_while_the_link_waits)
    status, out = h.finish_link(location)
    assert status == 200 and out["linked"] is True and out["password_stopped"] is True, out
    assert alice.sso_only is True and turns and turns[0] == str(alice.id)


def test_a_provider_that_holds_its_people_to_no_password_covers_the_accounts_linked_later(monkeypatch):
    """The setting was saved, and then an account is linked: by its owner from Your account, or by its email
    address at a sign-in. Its password ends with the link, in the same transaction, so a person who leaves and
    is turned off at the provider cannot come back with the vault password. The owner is told."""
    privileged_accounts, sso_only = _mod()
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    alice, bob, carol = _user("alice"), _user("bob"), _user("carol")
    strict = _provider(name="strict", label="Company sign-in", policy={
        "sso_password_login": "disabled", "sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    lenient = _provider(name="lenient", label="Partner sign-in")
    h = Resolving(monkeypatch, [alice, bob, carol], [strict, lenient])
    assert sso_only.password_less(strict) and not sso_only.password_less(lenient)

    def self_link(user, provider, subject):
        h.current_user = user
        status, out = h.start_link(provider)
        assert status == 200, out
        state, _ = h.state_of(out["authorization_url"])
        h.claims_override = {"sub": subject}
        status, location, _ = h.callback(provider, state)
        assert location.startswith("/#sso-linked="), location
        return h.finish_link(location)

    # By its owner: the answer says so, the password is gone, SFTP password sign-in is off.
    status, out = self_link(alice, strict, "s-alice")
    assert status == 200 and out["linked"] is True and out["password_stopped"] is True, out
    assert alice.sso_only is True and alice.password_hash.startswith("argon2:") and alice.sftp_password_auth is False
    said = [body for ids, title, body in h.notice_bodies if ids == [str(alice.id)]]
    assert said and "no longer work" in said[-1] and "Company sign-in" in said[-1], h.notice_bodies
    # By its email address at a sign-in: the same, and the owner's notice says it.
    location, _ = _sign_in(h, strict, sub="s-bob", email="bob@example.test")
    assert location.startswith("/#sso="), location
    assert bob.sso_only is True and bob.password_hash.startswith("argon2:") and bob.sftp_password_auth is False
    said = [body for ids, title, body in h.notice_bodies if ids == [str(bob.id)]]
    assert said and "no longer work" in said[-1], h.notice_bodies
    # A provider that lets its people keep a password changes nothing at the link, and says nothing of it.
    status, out = self_link(carol, lenient, "s-carol")
    assert status == 200 and "password_stopped" not in out, out
    assert carol.sso_only is False and carol.password_hash == "x" and carol.sftp_password_auth is True
    said = [body for ids, title, body in h.notice_bodies if ids == [str(carol.id)]]
    assert said and "no longer work" not in said[-1]
    # And linked to both, an account is held by the stricter one.
    status, out = self_link(carol, strict, "s-carol-2")
    assert status == 200 and out["password_stopped"] is True and carol.sso_only is True


@pytest.mark.parametrize("standing", ["administrator", "auditor right"])
def test_a_privileged_account_flagged_provider_only_gets_its_password_back_and_fails_no_request(monkeypatch, standing):
    """An earlier release, run for a while after going back to it, knows nothing of the flag: it makes an account
    that signs in only through its provider an administrator, or gives it the auditor right. On this release such an
    account could not type a password at the step an administrator always meets, and could be sent no reset link.
    It is never held to its provider: settling it gives the password back, wherever it is met, and raises nothing
    (it used to fail the request that met it: a provider's removal, an unlink, a change of the password setting).
    At start every such account is settled, and named for the notices."""
    privileged_accounts, sso_only = _mod()
    from app.core import auditor_rights, security
    from app.core.models import RoleEnum, User
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    monkeypatch.setattr(auditor_rights, "_has_grants", lambda db: True)
    root = _user("root", role="admin")
    held = _user("held", sso_only=True, sftp_password_auth=False, password_hash="argon2:nobody-knows")
    plain = _user("plain", sso_only=True, sftp_password_auth=False, password_hash="argon2:nobody-knows-either")
    if standing == "administrator":
        held.role = RoleEnum.ADMIN
        monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: None)
    else:
        monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: object() if user_id == held.id else None)
    p = _provider(name="a", label="A", policy={"sso_password_login": "disabled"})
    h = Resolving(monkeypatch, [root, held, plain], [p],
                  identities=[_identity(held, p, subject="s-held"), _identity(plain, p, subject="s-plain")])
    assert privileged_accounts.kind(h.db, held) is not None and privileged_accounts.kind(h.db, plain) is None
    # The rule: never provider-only, whatever it is linked to; the ordinary account beside it still is.
    assert sso_only.should_be_sso_only(h.db, held) is False and sso_only.should_be_sso_only(h.db, held, also=p) is False
    assert sso_only.should_be_sso_only(h.db, plain) is True
    # Met by any settling (a removal, an unlink, a change of the setting): the password back, nothing raised.
    # Its password is left as it is: the release that made it an administrator may have given it a real one.
    before = held.password_hash
    assert sso_only.settle(h.db, held) == sso_only.RESTORED
    assert held.sso_only is False and held.password_hash == before
    assert sso_only.settle(h.db, held) is None and sso_only.settle(h.db, plain) is None and plain.sso_only is True
    # At start: every such account, and only those.
    held.sso_only = True
    held.password_hash = "argon2:the-one-an-administrator-set-on-the-earlier-release"
    restored = sso_only.settle_privileged(h.db)
    assert held.password_hash == "argon2:the-one-an-administrator-set-on-the-earlier-release"
    # An ordinary account that may hold a password again still gets one nobody knows, and it says so.
    from app.core import password_origin
    ordinary = _user("ordinary", sso_only=True, password_hash="argon2:whatever-was-written")
    sso_only.allow_password_sign_in(h.db, ordinary)
    assert ordinary.sso_only is False and ordinary.password_hash != "argon2:whatever-was-written"
    assert password_origin.nobody_knows(ordinary) is True
    assert [(r[1], r[3]) for r in restored] == [("held", privileged_accounts.TEXTS[privileged_accounts.kind(h.db, held)])]
    assert held.sso_only is False and plain.sso_only is True and root.sso_only is False
    assert sso_only.settle_privileged(h.db) == []


def test_the_privileged_accounts_are_settled_at_start_recorded_and_told(monkeypatch):
    """The start-up step: each account is recorded, its owner is told how to set a password, the administrators are
    told who they are; with none there is nothing to say; and it is among the steps the server runs at start."""
    import contextlib
    import inspect
    privileged_accounts, sso_only = _mod()
    from app.api import api_server as api
    from app.api import sso_providers_router as providers_router
    from app.core import audit_catalog, database
    rows, committed, told = [], [], []

    class _Db:
        def add(self, row):
            rows.append(row)

        def commit(self):
            committed.append(len(rows))

    monkeypatch.setattr(database, "get_db_context", lambda: contextlib.nullcontext(_Db()))
    monkeypatch.setattr(api.AuditLogger, "build_row", lambda self, **kw: kw)
    monkeypatch.setattr(providers_router, "_tell_accounts", lambda users, title, change: told.append(("owners", users, title, change)))
    monkeypatch.setattr(providers_router, "_tell_administrators", lambda by, title, body: told.append(("administrators", by, title, body)))
    one, two = uuid.uuid4(), uuid.uuid4()
    # "Forgot your password?" sends a link here: switched on, email configured, the public address set.
    from app.core import config
    monkeypatch.setattr(api, "_account_policy", lambda db: {"password_reset_enabled": True})
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    monkeypatch.setattr(config.settings, "allowed_hosts", "vault.example.test", raising=False)
    monkeypatch.setattr(sso_only, "settle_privileged", lambda db: [
        (one, "zoe", "zoe@example.test", "an administrator"), (two, "amy", None, "a holder of the auditor right")])
    api._settle_privileged_provider_only_accounts()
    assert [(r["action"], r["resource_id"], r["details"]["username"], r["details"]["reason"]) for r in rows] == [
        ("sso_password_sign_in_restored", str(one), "zoe", "an administrator"),
        ("sso_password_sign_in_restored", str(two), "amy", "a holder of the auditor right")]
    assert committed == [2]
    with_address, without, administrators = told
    assert with_address[1] == [(one, "zoe", "zoe@example.test")] and without[1] == [(two, "amy", None)]
    assert "may hold a password again" in with_address[2] and "\"Forgot your password?\"" in with_address[3]
    # The sign-in page sends a link only to an address: an account without one asks an administrator.
    assert without[3].endswith("Your account has no password yet: ask an administrator for a reset link.")
    assert administrators[0] == "administrators" and "amy, zoe" in administrators[3] and "reset link" in administrators[3]
    assert audit_catalog.lookup("sso_password_sign_in_restored").severity == "warning"
    # None to settle: nothing recorded beyond the empty commit, nobody told.
    rows.clear(), committed.clear(), told.clear()
    monkeypatch.setattr(sso_only, "settle_privileged", lambda db: [])
    api._settle_privileged_provider_only_accounts()
    assert rows == [] and told == []
    assert inspect.getsource(api).count("    _settle_privileged_provider_only_accounts()") == 1


def test_the_flag_follows_the_providers_an_account_is_still_linked_to(monkeypatch):
    """An account signs in only through its providers exactly while it is linked to one that holds its people to no
    password, whatever that provider's state. Unlinking that one lets the account hold a password again; allowing
    passwords at one provider does not lift another provider's rule; and the unlink that would leave a password-less
    account with no provider that is on is refused."""
    privileged_accounts, sso_only = _mod()
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    alice = _user("alice", sso_only=True)
    # Providers whose unlink is one step (they only pause keys): the flag is this test's subject.
    a = _provider(name="a", label="A", policy={"sso_password_login": "disabled", **ONE_STEP})
    b = _provider(name="b", label="B", policy=ONE_STEP)
    c = _provider(name="c", label="C", policy={"sso_password_login": "disabled", **ONE_STEP})
    on_a, on_b = _identity(alice, a, subject="s-a"), _identity(alice, b, subject="s-b")
    h = Resolving(monkeypatch, [alice], [a, b, c], identities=[on_a, on_b])
    assert sso_only.should_be_sso_only(h.db, alice) is True
    assert sso_only.should_be_sso_only(h.db, alice, without=on_a) is False
    assert sso_only.should_be_sso_only(h.db, alice, without=on_a, also=c) is True
    a.state = "disabled"                                  # a provider that is off still holds its people to no password
    assert sso_only.should_be_sso_only(h.db, alice) is True
    a.state = "enabled"
    # The remaining provider is off: the unlink would leave no way in, and is refused.
    b.state = "disabled"
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{on_a.id}")
    assert status == 409 and "no other identity on a provider that is on can sign you in now" in out["detail"], out
    assert alice.sso_only is True and len(h.identities()) == 2
    # With it on, the unlink goes through and the account may hold a password again; it is told how to set one.
    b.state = "enabled"
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{on_a.id}")
    assert status == 200 and out == {"removed": True, "sessions_ended": 0, "may_set_password": True,
                                     "ended_this_session": False}, out
    assert alice.sso_only is False and h.identities() == [on_b]
    said = [body for ids, title, body in h.notice_bodies if ids == [str(alice.id)]]
    assert "may hold a password again" in said[-1] and "ask an administrator for a reset link." in said[-1]
    assert "Forgot" not in said[-1]                     # self-service reset is off here
    # Linked to two that hold their people to no password: allowing passwords at one lifts nothing.
    from app.core.models import ExternalIdentity
    on_a2, on_c = _identity(alice, a, subject="s-a"), _identity(alice, c, subject="s-c")
    h.db.rows_of(ExternalIdentity)[:] = [on_a2, on_c]
    alice.sso_only = True
    a.policy = {"sso_password_login": "allowed"}
    assert sso_only.apply_password_login(h.db, a) == {"made_sso_only": [], "restored": []}
    assert alice.sso_only is True
    c.policy = {"sso_password_login": "allowed"}
    assert sso_only.apply_password_login(h.db, c) == {"made_sso_only": [], "restored": ["alice"]}
    assert alice.sso_only is False


# --------------------------------------------------------------------------- a passkey does not stand in for the provider

def _finish(h, user, methods, **kw):
    from app.services import sign_in as s
    return s.finish(h.db, s.SignInResult(user, list(methods), "203.0.113.9", **kw))


def test_a_passkey_does_not_stand_in_for_the_provider(monkeypatch):
    """A leaver disabled at the provider must lose access at the next sign-in: an account that signs in only through
    its provider is refused a passkey sign-in (a synced or a device-bound key, user-verified, passwordless allowed),
    told plainly to use the provider's button; one audit row with the password door's reason; nothing made."""
    from app.core.models import ActiveSession
    from app.services import sign_in as s
    alice, p = _user(sso_only=True), _provider(label="Contoso")
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    for method in (s.HARDWARE_KEY, s.SOFTWARE_KEY):
        with pytest.raises(s.ProviderOnly) as refused:
            _finish(h, alice, [method], user_verified=True, passwordless_allowed=True)
        assert refused.value.status_code == 403
        assert refused.value.detail == ("Your organisation signs this account in through Contoso. Use the "
                                        "\u201cContoso\u201d button on the sign-in page.")
    failures = [a for a in h.audits if a[0] == "login_failure"]
    assert failures == [("login_failure", "alice", s.PROVIDER_ONLY_REASON)] * 2
    assert h.db.rows_of(ActiveSession) == [] and alice.failed_login_attempts == 0
    # A key that is not user-verified (the password would follow) is refused the same way, before any step.
    with pytest.raises(s.ProviderOnly):
        _finish(h, alice, [s.HARDWARE_KEY], user_verified=False, passwordless_allowed=True)
    # No longer provider-only (the provider allows password sign-in again): the same passkey signs in like anyone's.
    alice.sso_only = False
    signed = _finish(h, alice, [s.HARDWARE_KEY], user_verified=True, passwordless_allowed=True)
    assert isinstance(signed, s.SignedIn) and len(h.db.rows_of(ActiveSession)) == 1


def test_after_the_provider_the_accounts_passkey_is_its_second_factor(monkeypatch):
    """The second step of a sign-in that came through the provider carries the provider (from the pending login), so
    the account's passkey proves the factor there; the provider's own sign-in finishes as before."""
    from app.services import sign_in as s
    alice, p = _user(sso_only=True), _provider()
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    monkeypatch.setattr(h.S, "_login_second_factor_in_effect", lambda db, user: True)
    # The provider's sign-in with a factor required: held for the second step, not refused.
    held = _finish(h, alice, [], provider_id=str(p.id), provider_sub="subject-1")
    assert isinstance(held, s.PendingStep) and held.body["stage"] == s.STAGE_SECOND_FACTOR
    # The second step with the passkey, the provider carried: finished.
    signed = _finish(h, alice, [s.HARDWARE_KEY], provider_id=str(p.id), provider_sub="subject-1")
    assert isinstance(signed, s.SignedIn)
    assert not [a for a in h.audits if a[0] == "login_failure"]
    # The whole provider sign-in through the routes, for the account that signs in only that way.
    monkeypatch.setattr(h.S, "_login_second_factor_in_effect", lambda db, user: False)
    location, _ = _sign_in(h, p)
    assert location.startswith("/#sso="), location
    status, body = h.finish(location)
    assert status == 200 and body.get("access_token"), body


def test_a_temporary_credential_is_left_to_the_freshness_rule(monkeypatch):
    """A temporary credential the account made from a provider session is not a sign-in of the account itself; the
    provider's freshness rule governs it, not this one."""
    from app.services import sign_in as s
    alice, p = _user(sso_only=True), _provider()
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    s.refuse_without_the_provider(h.db, s.SignInResult(alice, [s.PASSWORD], "203.0.113.9", is_temporary=True))


def test_the_message_names_the_provider_and_its_button(monkeypatch):
    """Each provider is named as its button names it: the administrators call this one "entra-prod", and the person
    has only ever seen "Contoso"."""
    privileged_accounts, sso_only = _mod()
    alice, p = _user(sso_only=True), _provider(name="entra-prod", label="Contoso")
    q = _provider(name="Fabrikam", label="Fabrikam SSO")
    h = Resolving(monkeypatch, [alice], [p, q], identities=[_identity(alice, p)])
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso. Use the \u201cContoso\u201d button on the sign-in page.")
    # Two providers: both, and both buttons.
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(_identity(alice, q, subject="s-q"))
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso or Fabrikam SSO. Use the \u201cContoso\u201d "
        "or \u201cFabrikam SSO\u201d button on the sign-in page.")
    # One provider on the sign-in page and one not: both named, the button of the one that has it.
    q.show_on_sign_in = False
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso or Fabrikam SSO. Use the \u201cContoso\u201d "
        "button on the sign-in page.")
    # A button without a label shows the provider's name, and the sentence names it so too.
    q.show_on_sign_in, q.label = True, ""
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso or Fabrikam. Use the \u201cContoso\u201d "
        "or \u201cFabrikam\u201d button on the sign-in page.")
    # A provider not on the sign-in page: its link.
    q.state = "disabled"
    p.show_on_sign_in = False
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso. Use the sign-in link your organisation gave you.")
    assert "entra-prod" not in sso_only.provider_only_message(h.db, alice)
    # No provider of the account enabled: ask an administrator.
    p.state = "disabled"
    assert "Ask your administrator" in sso_only.provider_only_message(h.db, alice)


def test_a_vault_address_single_sign_on_cannot_use_names_no_button(monkeypatch):
    """The vault's address cannot carry single sign-on: the sign-in page shows no provider's button and no sign-in
    through a provider starts. The person is told their organisation's sign-in is not available here now, not to
    use a button that is not there."""
    privileged_accounts, sso_only = _mod()
    from app.services import sso_sign_in
    alice, p = _user(sso_only=True), _provider(label="Contoso")
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    monkeypatch.setattr(sso_sign_in, "address_refusal", lambda: None)
    assert sso_only.provider_only_message(h.db, alice).endswith("Use the “Contoso” button on the sign-in page.")
    monkeypatch.setattr(sso_sign_in, "address_refusal",
                        lambda: "Single sign-on needs the vault's public address. It is not set.")
    assert sso_only.provider_only_message(h.db, alice) == sso_only.NO_PROVIDER_ON
    assert "not available on this vault right now" in sso_only.NO_PROVIDER_ON
    # A passkey alone: the same, and not a reset link, which is not made for an account that signs in only
    # through its provider.
    said = sso_only.passkey_after_the_provider_message(h.db, alice)
    assert said.startswith(sso_only.NO_PROVIDER_ON) and "button" not in said


def test_the_refusal_names_the_door_in_its_audit_row(monkeypatch):
    from app.services import sign_in as s
    alice, p = _user(sso_only=True), _provider()
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    seen = []

    class Audit:
        def __init__(self, db):
            pass

        def log_login_failure(self, username, ip, reason, **kw):
            seen.append((username, reason, kw.get("login_identifier"), kw.get("account")))
    monkeypatch.setattr(h.S, "AuditLogger", Audit)
    with pytest.raises(s.ProviderOnly):
        _finish(h, alice, [s.SOFTWARE_KEY], user_verified=True, passwordless_allowed=True)
    with pytest.raises(s.ProviderOnly):
        _finish(h, alice, [s.PASSWORD])
    assert seen == [("alice", s.PROVIDER_ONLY_REASON, "passkey", alice), ("alice", s.PROVIDER_ONLY_REASON, "username", alice)]


def test_the_password_door_and_the_pipeline_record_the_same_reason():
    import inspect
    set_bare_api_env()
    from app.services import auth_service, sign_in
    assert "raise InvalidCredentialsError(PROVIDER_ONLY_REASON)" in inspect.getsource(auth_service.AuthService._authenticate_in_turn)
    assert sign_in.PROVIDER_ONLY_REASON == "Account signs in only through its identity provider"


def test_a_provider_sign_in_is_finished_only_while_its_provider_is_on_and_the_account_linked(monkeypatch):
    """The provider answered at the callback; the code handed to the page lives a minute after it, and a held step
    (the account's factor, an administrator's password, an enrollment) five. A provider turned off in that time,
    by an administrator or by a change to its connection, ends the sign-ins under way with it, and so does an
    unlink: none becomes a session, and none stamps its identity as freshly signed in."""
    from fastapi import HTTPException
    from app.core.models import ExternalIdentity
    from app.services import sign_in as s
    alice, p = _user(), _provider()
    identity = _identity(alice, p)
    h = Resolving(monkeypatch, [alice], [p], identities=[identity])
    monkeypatch.setattr(h.S, "_login_second_factor_in_effect", lambda db, user: False)
    stamped = []
    monkeypatch.setattr(s, "_stamp_identity", lambda db, result: stamped.append(result.provider_id))

    def result(**extra):
        return s.SignInResult(alice, [], "203.0.113.9", provider_id=str(p.id), provider_sub="subject-1", **extra)
    s.refuse_unless_the_provider_stands(h.db, result())                                   # on, and linked
    s.refuse_unless_the_provider_stands(h.db, s.SignInResult(alice, [s.PASSWORD], "203.0.113.9"))            # no provider
    s.refuse_unless_the_provider_stands(h.db, result(is_temporary=True))
    for change in ("off", "draft", "unlinked", "gone", "not an id", "another identity", "no identity named"):
        p.state, rows, named, came_through = "enabled", h.db.rows_of(ExternalIdentity), str(p.id), "subject-1"
        if identity not in rows:
            rows.append(identity)
        if change in ("off", "draft"):
            p.state = "disabled" if change == "off" else "draft"
        elif change == "unlinked":
            rows.remove(identity)
        elif change == "gone":
            named = str(__import__("uuid").uuid4())
        elif change == "another identity":
            came_through = "the-identity-that-was-unlinked"       # the account links by another one now
        elif change == "no identity named":
            came_through = None
        else:
            named = "p1"
        before = len([a for a in h.audits if a[0] == "login_failure"])
        with pytest.raises(HTTPException) as refused:
            s.refuse_unless_the_provider_stands(h.db, s.SignInResult(alice, [], "203.0.113.9", provider_id=named,
                                                                     provider_sub=came_through))
        assert refused.value.status_code == 401 and "start again" in refused.value.detail, change
        assert len([a for a in h.audits if a[0] == "login_failure"]) == before + 1, change
    p.state = "enabled"
    if identity not in h.db.rows_of(ExternalIdentity):
        h.db.rows_of(ExternalIdentity).append(identity)
    # Through the routes: the provider answers, it is turned off, and the code the page holds finishes nothing.
    location, _ = _sign_in(h, p)
    assert location.startswith("/#sso="), location
    p.state = "disabled"
    status, body = h.finish(location)
    assert status == 401 and not (body or {}).get("access_token"), (status, body)
    assert stamped == []
    # The control: left on, the same sign-in is a session and stamps its identity.
    p.state = "enabled"
    location, _ = _sign_in(h, p)
    status, body = h.finish(location)
    assert status == 200 and body.get("access_token") and stamped == [str(p.id)], (status, body, stamped)


def test_the_rule_is_asked_in_the_one_place_every_sign_in_finishes():
    """Every way in finishes in the pipeline's ``finish``; the rule sits there once, after the account-state checks
    and before the second-factor table, so no route can skip it."""
    import inspect
    set_bare_api_env()
    from app.services import sign_in
    source = inspect.getsource(sign_in.finish)
    assert source.count("refuse_without_the_provider(db, result)") == 1
    assert source.count("refuse_unless_the_provider_stands(db, result)") == 1
    assert (source.index("refuse_without_the_provider(") < source.index("refuse_unless_the_provider_stands(")
            < source.index("second_factor_due("))
    assert (source.index("refuse_unless_the_account_may_sign_in(") < source.index("refuse_without_the_provider(")
            < source.index("second_factor_due("))
