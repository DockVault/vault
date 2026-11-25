"""How a person whose account may hold a password again is told to get one (app/api/sso_providers_router.py,
set_a_password): through "Forgot your password?" on the sign-in page only where that link sends a reset link (the
self-service switch on, email configured, the vault's public address set, and an address on the account), and
otherwise from an administrator. The notices of a provider's removal, an unlink and the refusal of an unlink say the
same. Offline."""
from pathlib import Path

import pytest

from test_sso_providers_routes import Admin
from test_sso_sign_in import ONE_STEP, Harness, _call, _identity, _provider, _user

pytestmark = pytest.mark.unit

SELF_SERVICE = ("Your account has no password yet: set one with \"Forgot your password?\" on the sign-in page, or "
                "ask an administrator for a reset link.")
FROM_AN_ADMINISTRATOR = "Your account has no password yet: ask an administrator for a reset link."


def _self_service(monkeypatch, S, *, enabled=True, smtp=True, hosts="vault.example.test"):
    """The three things "Forgot your password?" needs to send a link, as a test sets them."""
    from app.core import config
    monkeypatch.setattr(S, "_account_policy", lambda db: {"password_reset_enabled": enabled})
    monkeypatch.setattr(S, "_smtp_configured", lambda db: smtp)
    monkeypatch.setattr(config.settings, "allowed_hosts", hosts, raising=False)


def test_the_sign_in_pages_link_is_named_only_where_it_sends_a_reset_link(monkeypatch):
    from app.api import api_server as S
    from app.api import sso_providers_router as R
    _self_service(monkeypatch, S)
    assert R.self_service_reset(None) is True
    assert R.set_a_password(None) == SELF_SERVICE
    # An account with no address gets no link from the sign-in page, whatever the vault has.
    assert R.set_a_password(None, has_address=False) == FROM_AN_ADMINISTRATOR
    for missing in ({"enabled": False}, {"smtp": False}, {"hosts": ""}):
        _self_service(monkeypatch, S, **missing)
        assert R.self_service_reset(None) is False, missing
        assert R.set_a_password(None) == FROM_AN_ADMINISTRATOR, missing
    # A setting that cannot be read offers the route that always works.
    monkeypatch.setattr(S, "_account_policy", lambda db: 1 / 0)
    assert R.set_a_password(None) == FROM_AN_ADMINISTRATOR


def test_no_text_names_a_forgot_password_link_the_sign_in_page_does_not_have():
    """The sign-in page's link reads "Forgot your password?"; nothing the vault says names it otherwise."""
    app = Path(__file__).resolve().parent.parent / "app"
    named = [str(path.relative_to(app)) for path in app.rglob("*.py")
             if "Forgot password" in path.read_text(encoding="utf-8")]
    assert named == []


def _a_removal(monkeypatch, *, self_service):
    from app.core import password_origin
    row = _provider(created_at=None, updated_at=None, state="disabled")
    dana = _user("dana")
    dana.password_hash, dana.password_nobody_knows = "argon2:of-random-bytes", None
    password_origin.mark_nobody_knows(dana)
    h = Admin(monkeypatch, [row], users=[dana], identities=[_identity(dana, row)])
    if self_service:
        _self_service(monkeypatch, h.S)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200 and out == {"removed": True}, out
    ((names, _title, text),) = h.accounts_told
    assert names == ["dana"]
    return text


def test_a_removal_tells_an_account_that_may_set_a_password_the_way_that_works_on_this_vault(monkeypatch):
    said = _a_removal(monkeypatch, self_service=False)
    assert said.endswith(" " + FROM_AN_ADMINISTRATOR) and "Forgot" not in said
    said = _a_removal(monkeypatch, self_service=True)
    assert said.endswith(" " + SELF_SERVICE)


def test_the_provider_save_says_whether_people_can_ask_for_their_own_reset_link(monkeypatch):
    row = _provider(created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"label": "Company sign-in"})
    assert status == 200 and out["self_service_reset"] is False, out
    _self_service(monkeypatch, h.S)
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"label": "Company sign-in"})
    assert status == 200 and out["changed"] == [] and out["self_service_reset"] is True, out
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"label": "Our sign-in"})
    assert status == 200 and out["changed"] == ["label"] and out["self_service_reset"] is True, out


@pytest.mark.parametrize("self_service", [False, True])
def test_an_owners_unlink_that_would_leave_no_way_in_says_how_to_set_a_password_here(monkeypatch, self_service):
    from app.core import password_origin
    dana, p = _user("dana", sso_only=False), _provider(policy=ONE_STEP)
    dana.password_hash, dana.password_nobody_knows = "argon2:of-random-bytes", None
    password_origin.mark_nobody_knows(dana)
    identity = _identity(dana, p)
    h = Harness(monkeypatch, [dana], [p], identities=[identity])
    if self_service:
        _self_service(monkeypatch, h.S)
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 409, out
    if self_service:
        assert "Set a password first (\"Forgot your password?\" on the sign-in page, or ask an administrator for a " \
               "reset link), then unlink." in out["detail"], out
    else:
        assert out["detail"].endswith("Set a password first (ask an administrator for a reset link), then unlink.")


@pytest.mark.parametrize("self_service", [False, True])
def test_an_administrators_unlink_says_who_can_set_the_password_it_gives_back(monkeypatch, self_service):
    """The identity alone held the account to no password: unlinked, it may hold one, and has none anybody can type
    until a reset link reaches it. The administrators read who can make one, the owner how to get one."""
    from app.api import sso_admin_router as A
    from app.api import sso_providers_router as R
    from app.api import sso_router
    from app.core import password_origin, security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    root, made = _user("root", role="admin"), _user("made", sso_only=True, password_hash="r1")
    made.password_set_by, made.password_set_by_other_at = None, None
    password_origin.mark_nobody_knows(made)
    p = _provider(state="disabled")
    made_with = _identity(made, p, subject="subject-made", linked_by="jit")
    h = Harness(monkeypatch, [root, made], [p], identities=[made_with])
    if self_service:
        _self_service(monkeypatch, h.S)
    told, owners = [], []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: None)
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append(body))
    monkeypatch.setattr(sso_router, "_tell_owner", lambda db, user, row, title, change, **how: owners.append(change))
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{made_with.id}")
    assert status == 200 and body["may_set_password"] is True, body
    if self_service:
        assert told[-1].endswith("It has none anybody can type until it sets one with \"Forgot your password?\" on "
                                 "the sign-in page, or you make a reset link for it (Users).")
        assert owners[-1].endswith(" " + SELF_SERVICE)
    else:
        assert told[-1].endswith("It has none anybody can type until you make a reset link for it (Users, Copy reset "
                                 "link).")
        assert owners[-1].endswith(" " + FROM_AN_ADMINISTRATOR)
