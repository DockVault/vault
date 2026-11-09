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
    # The self-service request answers as for anyone and mints nothing.
    monkeypatch.setattr(S, "_resolve_reset_user", lambda db, identifier: alice)
    status, body, _ = _call(S, "POST", "/auth/forgot-password", {"identifier": "alice"})
    assert status == 202 and minted == []
    # The account cannot set a password.
    h.current_user = alice
    status, body, _ = _call(S, "PATCH", "/users/me", {"current_password": "pw", "new_password": "a-new-password-1"})
    assert status == 409 and "no password of its own" in body["detail"], body
    # Other self-service changes stand.
    status, body, _ = _call(S, "PATCH", "/users/me", {"sftp_enabled": False})
    assert status == 200, body


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
