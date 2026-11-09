"""Accounts that sign in only through their provider (app/core/sso_only.py, app/core/privileged_accounts.py): the
unusable password and the SFTP flag, never for a privileged account; the password door refusing the account after
the hash check with the reason in the audit; no reset link minted for it by anyone, a link that outlived the change
refused; no password change; the provider setting's save-time refusal naming the accounts; the setting applied to
the linked accounts both ways. Offline."""
import types
import uuid

import pytest

from _bare_api_env import set_bare_api_env
from test_sso_resolution import Resolving
from test_sso_sign_in import _call, _identity, _provider, _user

pytestmark = pytest.mark.unit


def _mod():
    set_bare_api_env()
    from app.core import privileged_accounts, sso_only
    return privileged_accounts, sso_only


def test_an_sso_only_account_has_a_password_nobody_knows_and_no_sftp_password(monkeypatch):
    privileged_accounts, sso_only = _mod()
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    alice = _user(sso_only=False)
    db = types.SimpleNamespace()
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: None)
    sso_only.make_sso_only(db, alice)
    assert alice.sso_only is True and alice.sftp_password_auth is False
    assert alice.password_hash.startswith("argon2:") and len(alice.password_hash) > 40 and alice.password_hash != "x"
    # Made twice: a different unknown password each time.
    first = alice.password_hash
    sso_only.make_sso_only(db, alice)
    assert alice.password_hash != first


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
        S._refuse_sftp_password_for_sso_only(alice, True)              # the administrator's update asks the same
    assert refused.value.status_code == 409
    S._refuse_sftp_password_for_sso_only(alice, False)                  # turning it off is always allowed
    S._refuse_sftp_password_for_sso_only(root, True)                    # an ordinary account may turn it on


def test_no_administrator_sets_a_password_on_or_promotes_an_sso_only_account(monkeypatch):
    """A password set by an administrator would go live the moment the flag clears; the administrator role needs a
    password for the fixed step-ups. Both are refused while the account signs in only through its provider: at the
    credential change a held approval applies as well as at the route, and the auditor right's preconditions name
    it; a restore re-randomizes the hash before the link is minted."""
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
    with pytest.raises(HTTPException) as refused:
        S._record_admin_grant(types.SimpleNamespace(), alice, by=_user("root", role="admin"))
    assert refused.value.status_code == 409 and "allow password sign-in" in refused.value.detail and recorded == []
    alice.sso_only = False
    monkeypatch.setattr(S, "_revoke_reset_links_outranked_by", lambda db, user, actor: None)
    S._record_admin_grant(types.SimpleNamespace(), alice, by=_user("root", role="admin"))
    assert recorded == [alice.id]
    alice.sso_only = True
    # The auditor right's preconditions name it too.
    monkeypatch.setattr(auditor_rights, "active_totp", lambda db, user_id: object())
    monkeypatch.setattr(cc, "last_applied", lambda db, user_id, now: None)
    assert auditor_rights.preconditions(types.SimpleNamespace(), alice) == [auditor_rights.SSO_ONLY]
    assert "identity provider" in auditor_rights.text(auditor_rights.SSO_ONLY)
    # A restore sets a fresh unknown hash before minting the link: nothing set meanwhile is a password.
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    alice.password_hash = "admins-choice"
    monkeypatch.setattr(S, "_mint_reset_link", lambda db, user, base_url, **kw: "https://x/reset/t")
    link = sso_only.restore_password_sign_in(types.SimpleNamespace(), alice, base_url="https://x", created_by_id=None)
    assert link == "https://x/reset/t" and alice.sso_only is False and alice.password_hash.startswith("argon2:")
    assert alice.password_hash != "admins-choice"


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
    # Without them: bob becomes SSO-only; back to allowed: restored with a reset link.
    h.identities()[:] = [i for i in h.identities() if i.user_id == bob.id]
    assert sso_only.disabled_refusal(h.db, p) is None
    minted = []
    monkeypatch.setattr(h.S, "_mint_reset_link", lambda db, user, base_url, **kw: minted.append((user.username, kw)) or "https://x/reset/t")
    changed = sso_only.apply_password_login(h.db, p, "disabled", base_url="https://vault.example.test", created_by_id=root.id)
    assert changed == {"made_sso_only": ["bob"], "restored": []}
    assert bob.sso_only is True and bob.sftp_password_auth is False and bob.password_hash.startswith("argon2:")
    changed = sso_only.apply_password_login(h.db, p, "disabled", base_url="https://vault.example.test", created_by_id=root.id)
    assert changed == {"made_sso_only": [], "restored": []}                    # already so
    changed = sso_only.apply_password_login(h.db, p, "allowed", base_url="https://vault.example.test", created_by_id=root.id)
    assert changed == {"made_sso_only": [], "restored": [("bob", "https://x/reset/t")]}
    assert bob.sso_only is False and minted == [("bob", {"created_by_id": root.id, "made_by_other": True})]
