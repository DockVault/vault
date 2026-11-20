"""Accounts that sign in only through their provider (app/core/sso_only.py, app/core/privileged_accounts.py): the
unusable password and the SFTP flag, never for a privileged account; the password door refusing the account after
the hash check with the reason in the audit; no reset link minted for it by anyone, a link that outlived the change
refused; no password change; the provider setting's save-time refusal naming the accounts; the setting applied to
the linked accounts both ways. Offline."""
import types
import uuid

import pytest

from _bare_api_env import set_bare_api_env
from test_sso_resolution import Resolving, _sign_in
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
    bases = []
    monkeypatch.setattr(S, "_public_base_url", lambda: "https://vault.example.test")
    monkeypatch.setattr(S, "_mint_reset_link", lambda db, user, base_url, **kw: bases.append(base_url) or "https://x/reset/t")
    link = sso_only.restore_password_sign_in(types.SimpleNamespace(), alice, created_by_id=None)
    assert link == "https://x/reset/t" and alice.sso_only is False and alice.password_hash.startswith("argon2:")
    assert bases == ["https://vault.example.test"]         # the configured address, which no caller hands in
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
    changed = sso_only.apply_password_login(h.db, p, "disabled", created_by_id=root.id)
    assert changed == {"made_sso_only": ["bob"], "restored": []}
    assert bob.sso_only is True and bob.sftp_password_auth is False and bob.password_hash.startswith("argon2:")
    changed = sso_only.apply_password_login(h.db, p, "disabled", created_by_id=root.id)
    assert changed == {"made_sso_only": [], "restored": []}                    # already so
    changed = sso_only.apply_password_login(h.db, p, "allowed", created_by_id=root.id)
    assert changed == {"made_sso_only": [], "restored": [("bob", "https://x/reset/t")]}
    assert bob.sso_only is False and minted == [("bob", {"created_by_id": root.id, "made_by_other": True})]


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
    alice, p = _user(sso_only=True), _provider()
    h = Resolving(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    for method in (s.HARDWARE_KEY, s.SOFTWARE_KEY):
        with pytest.raises(s.ProviderOnly) as refused:
            _finish(h, alice, [method], user_verified=True, passwordless_allowed=True)
        assert refused.value.status_code == 403
        assert refused.value.detail == ("Your organisation signs this account in through contoso. Use the "
                                        "\u201cSign in with Contoso\u201d button on the sign-in page.")
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
    held = _finish(h, alice, [], provider_id=str(p.id))
    assert isinstance(held, s.PendingStep) and held.body["stage"] == s.STAGE_SECOND_FACTOR
    # The second step with the passkey, the provider carried: finished.
    signed = _finish(h, alice, [s.HARDWARE_KEY], provider_id=str(p.id))
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
    privileged_accounts, sso_only = _mod()
    alice, p = _user(sso_only=True), _provider(name="Contoso", label="Sign in with Contoso")
    q = _provider(name="Fabrikam", label="Fabrikam SSO")
    h = Resolving(monkeypatch, [alice], [p, q], identities=[_identity(alice, p)])
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso. Use the \u201cSign in with Contoso\u201d button on "
        "the sign-in page.")
    # Two providers: both, and both buttons.
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(_identity(alice, q, subject="s-q"))
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso or Fabrikam. Use the \u201cSign in with Contoso\u201d "
        "or \u201cFabrikam SSO\u201d button on the sign-in page.")
    # One provider on the sign-in page and one not: both named, the button of the one that has it.
    q.show_on_sign_in = False
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso or Fabrikam. Use the \u201cSign in with Contoso\u201d "
        "button on the sign-in page.")
    # A button without a label shows the provider's name.
    q.show_on_sign_in, q.label = True, ""
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso or Fabrikam. Use the \u201cSign in with Contoso\u201d "
        "or \u201cFabrikam\u201d button on the sign-in page.")
    # A provider not on the sign-in page: its link.
    q.state = "disabled"
    p.show_on_sign_in = False
    assert sso_only.provider_only_message(h.db, alice) == (
        "Your organisation signs this account in through Contoso. Use the sign-in link your organisation gave you.")
    # No provider of the account enabled: ask an administrator.
    p.state = "disabled"
    assert "Ask your administrator" in sso_only.provider_only_message(h.db, alice)


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


def test_the_rule_is_asked_in_the_one_place_every_sign_in_finishes():
    """Every way in finishes in the pipeline's ``finish``; the rule sits there once, after the account-state checks
    and before the second-factor table, so no route can skip it."""
    import inspect
    set_bare_api_env()
    from app.services import sign_in
    source = inspect.getsource(sign_in.finish)
    assert source.count("refuse_without_the_provider(db, result)") == 1
    assert (source.index("refuse_unless_the_account_may_sign_in(") < source.index("refuse_without_the_provider(")
            < source.index("second_factor_due("))
