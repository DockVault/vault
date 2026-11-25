"""The owner's unlink of an identity, where its provider closes the account's other ways in once the person stops
signing in there (app/services/sso_sign_in.py unlink_asks_the_provider, app/api/sso_router.py unlink_my_identity).

An account with no identity has no days to run out, so a person the provider no longer signs in could unlink it on
the day before and keep the password for good. The unlink is confirmed by what such a person cannot give: a sign-in
through the provider, made now, staged for this session and for the unlink alone. The administrators are told of
every owner's unlink, and an administrator can unlink for somebody whose provider cannot confirm them. Offline."""
import time
from datetime import datetime, timedelta

import pytest

from test_sso_reauth import TESTED, Reauth
from test_sso_sign_in import Harness, _call, _identity, _provider, _user

pytestmark = pytest.mark.unit


def _sso():
    from app.services import sso_sign_in
    return sso_sign_in


def _confirm(h, p, **claims):
    """A fresh sign-in at ``p`` for the unlink, through the provider and back, staged by the tab that started it."""
    sso = _sso()
    status, out = h.start_reauth(p, action=sso.UNLINK_CONFIRMATION)
    assert status == 200, out
    state, record = h.state_of(out["authorization_url"])
    assert record["purpose"] == "step_up" and record["step_up_action"] == sso.UNLINK_CONFIRMATION
    h.claims_override = {"auth_time": int(time.time()) - 5, **claims}
    status, location, _ = h.callback(p, state)
    assert status == 302 and location.startswith("/#sso-stepup="), location
    status, body = h.finish_reauth(location)
    assert status == 200 and body["action"] == sso.UNLINK_CONFIRMATION, body


def _unlink(h, identity):
    return _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")[:2]


def _staged(h):
    return [k for k in h.redis.rows if k.startswith("sso:reauth:")]


def test_the_owners_unlink_is_confirmed_by_a_fresh_sign_in_through_the_provider(monkeypatch):
    """An account with a password of its own, linked by its owner. Without the confirmation the unlink is refused
    and says what to do; with it the identity goes, the confirmation is spent, and the administrators are told."""
    sso = _sso()
    alice, root = _user(), _user("root", role="admin")
    p = _provider(last_test=TESTED)
    identity = _identity(alice, p, last_sign_in_at=datetime.utcnow() - timedelta(days=29))
    h = Reauth(monkeypatch, [alice, root], [p], identities=[identity])
    status, out = _unlink(h, identity)
    assert status == 403, out
    assert out["detail"]["reason"] == "provider_confirmation_required"
    assert out["detail"]["action"] == sso.UNLINK_CONFIRMATION == "sso.identity.unlink"
    assert out["detail"]["provider"] == {"id": str(p.id), "label": p.label}
    assert out["detail"]["message"] == f"Sign in through {p.label} once more to confirm it is you, then unlink it."
    assert h.identities() == [identity]
    # The password an account has is never stood in for by its provider: a step-up's confirmation is still
    # refused to this account, and only the unlink's own may be started.
    status, out = h.start_reauth(p, action="account.second_factor")
    assert status == 403 and out["detail"]["reason"] == "password_required", out
    _confirm(h, p)
    assert _staged(h)
    status, out = _unlink(h, identity)
    assert status == 200 and out["removed"] is True, out
    assert h.identities() == [] and not _staged(h)
    assert ([str(root.id)], f"alice unlinked {p.label}") in h.notices, h.notices
    unlinked = [a for a in h.audits if a[0] == "sso_identity_unlinked"][-1]
    assert unlinked[2]["confirmed_at_provider"] is True and unlinked[2]["linked_by"] == "self"


def test_a_confirmation_counts_for_the_unlink_of_the_provider_it_was_made_at_and_for_nothing_else(monkeypatch):
    sso = _sso()
    from app.core import second_factor_actions as acts
    alice = _user()
    p, q = _provider(last_test=TESTED), _provider(name="fabrikam", label="Sign in with Fabrikam", last_test=TESTED)
    at_p, at_q = _identity(alice, p), _identity(alice, q, subject="subject-2")
    h = Reauth(monkeypatch, [alice], [p, q], identities=[at_p, at_q])
    assert acts.is_step_up_action(sso.UNLINK_CONFIRMATION) is False
    # Made at the other provider: it does not confirm this one's unlink, and is spent by the attempt.
    _confirm(h, q, sub="subject-2")
    status, out = _unlink(h, at_p)
    assert status == 403 and out["detail"]["reason"] == "provider_confirmation_required", out
    assert len(h.identities()) == 2 and not _staged(h)
    # No step-up takes it: staged for the unlink, the step-up route finds nothing for its own action.
    _confirm(h, p)
    assert h.step_up(action="account.second_factor", method="idp_reauth")[0] == 403
    assert h.step_up(action=sso.UNLINK_CONFIRMATION, method="idp_reauth")[0] in (400, 403, 404, 422)
    assert _staged(h)
    # Another session of the account does not take it either.
    h.session_hash = "another-session"
    assert _unlink(h, at_p)[0] == 403
    h.session_hash = "sess-hash"
    assert _unlink(h, at_p)[0] == 200 and h.identities() == [at_q]


@pytest.mark.parametrize("why", ["never tested with a sign-in time", "turned off"])
def test_a_provider_that_cannot_confirm_leaves_the_unlink_to_an_administrator(monkeypatch, why):
    alice = _user()
    p = _provider(last_test=None if why == "never tested with a sign-in time" else TESTED)
    identity = _identity(alice, p)
    h = Reauth(monkeypatch, [alice], [p], identities=[identity])
    if why == "turned off":
        # Confirmed a moment ago, and the provider was turned off since (an incident): what it said confirms
        # nothing now, as for a step-up.
        _confirm(h, p)
        p.state = "disabled"
    status, out = _unlink(h, identity)
    assert status == 409 and out["detail"]["reason"] == "provider_cannot_confirm", out
    assert out["detail"]["message"].endswith("so it is not unlinked here. Ask an administrator.")
    assert h.identities() == [identity]


def test_which_unlinks_ask_the_provider(monkeypatch):
    """Where the provider closes the other ways in: every identity but one the provider itself put on the account
    by a verified address, and every account the rule can hold."""
    sso = _sso()
    from app.core import privileged_accounts
    kind = [None]
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: kind[0])
    alice, p = _user(), _provider()
    for by in ("self", "jit", "invitation", "admin"):
        assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p, linked_by=by), p) is True, by
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p, linked_by="email"), p) is False
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p), None) is False
    only_pauses_keys = _provider(policy={"sso_lapse_ends_sign_in": False})
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, only_pauses_keys), only_pauses_keys) is False
    for standing in ("administrator", "auditor_right"):
        kind[0] = standing
        assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p), p) is False, standing


def test_an_identity_linked_by_email_and_one_on_a_provider_that_only_pauses_keys_are_unlinked_in_one_step(monkeypatch):
    alice, bob, root = _user(), _user("bob"), _user("root", role="admin")
    p = _provider(last_test=TESTED)
    q = _provider(name="fabrikam", label="Sign in with Fabrikam", policy={"sso_lapse_ends_sign_in": False})
    by_email, one_click = _identity(alice, p, linked_by="email"), _identity(bob, q, subject="subject-2")
    h = Reauth(monkeypatch, [alice, bob, root], [p, q], identities=[by_email, one_click])
    status, out = _unlink(h, by_email)
    assert status == 200 and out["removed"] is True, out
    assert [a for a in h.audits if a[0] == "sso_identity_unlinked"][-1][2]["confirmed_at_provider"] is False
    # Told to the administrators all the same: every unlink by its owner is.
    assert ([str(root.id)], f"alice unlinked {p.label}") in h.notices
    h.current_user = bob
    status, out = _unlink(h, one_click)
    assert status == 200 and h.identities() == [], out


def test_your_account_is_told_which_unlinks_ask_the_provider_and_whether_it_can_answer(monkeypatch):
    alice = _user()
    p, off = _provider(last_test=TESTED), _provider(name="fabrikam", label="Sign in with Fabrikam", state="disabled")
    h = Reauth(monkeypatch, [alice], [p, off],
               identities=[_identity(alice, p), _identity(alice, off, subject="subject-2", linked_by="email")])
    status, out = _call(h.S, "GET", "/users/me/identities")[:2]
    assert status == 200, out
    shown = {i["provider_id"]: i for i in out["identities"]}
    assert shown[str(p.id)]["unlink_asks_provider"] is True and shown[str(p.id)]["provider_can_confirm"] is True
    assert shown[str(off.id)]["unlink_asks_provider"] is False and shown[str(off.id)]["provider_can_confirm"] is False


def test_an_administrator_unlinks_an_identity_for_somebody_under_the_step_up_and_never_their_own(monkeypatch):
    """For a person whose provider cannot confirm their own unlink. A hold the identity's provider had on the
    account ends with the identity, and the administrators are told so; an account held to no password by this
    identity alone may hold one again."""
    from app.api import sso_admin_router as A
    from app.api import sso_providers_router as R
    from app.api import sso_router
    from app.core import password_origin, security
    from app.services import sso_freshness as F
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    root, alice, made = _user("root", role="admin"), _user(), _user("made", sso_only=True, password_hash="r1")
    made.password_set_by, made.password_set_by_other_at = None, None
    password_origin.mark_nobody_knows(made)
    p = _provider(state="disabled")
    held = _identity(alice, p, last_sign_in_at=datetime.utcnow() - timedelta(days=40), refused_at=datetime.utcnow())
    made_with = _identity(made, p, subject="subject-made", linked_by="jit", last_sign_in_at=datetime.utcnow())
    own = _identity(root, p, subject="subject-root")
    h = Harness(monkeypatch, [root, alice, made], [p], identities=[held, made_with, own])
    assert A._step_up.action == "admin.auth_policy.write"
    steps, told, owners = [], [], []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: steps.append(user.username))
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append((by, title, body)))
    monkeypatch.setattr(sso_router, "_tell_owner", lambda db, user, row, title, change: owners.append((user.username, change)))
    assert F.held_to_a_provider(h.db, alice) is not None
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{own.id}")
    assert status == 409 and body["detail"]["reason"] == "own_identity" and steps == []
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{held.id}")
    assert status == 200 and body == {"removed": True, "sessions_ended": 0, "held": True}, body
    assert steps == ["root"] and held not in h.identities() and F.held_to_a_provider(h.db, alice) is None
    # The record says what the unlink did: the hold it ended, and no password given back. The provider's refusal
    # ended with the identity, and is recorded as a refusal lifted, by way of the unlink.
    unlinked = [a[2] for a in h.audits if a[0] == "sso_identity_unlinked"][-1]
    assert unlinked["held"] is True and unlinked["restored"] is False and unlinked["identity_id"] == str(held.id)
    lifted = [a[2] for a in h.audits if a[0] == "sso_refusal_cleared"]
    assert lifted == [{"user_id": str(alice.id), "provider_id": str(p.id), "identity_id": str(held.id),
                       "via": "unlink"}]
    assert told[-1][1] == "An identity was unlinked by an administrator" and "the hold ended with the identity" in told[-1][2]
    assert owners[-1][0] == "alice" and owners[-1][1].startswith("root unlinked your account from ")
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{made_with.id}")
    assert status == 200 and body["may_set_password"] is True and body["held"] is False, body
    assert made.sso_only is False and "The account may hold a password again." in told[-1][2]
    # This identity alone held the account to no password: the unlink is what lets it set one, so it goes
    # through, and the administrators read that the account has none anybody can type until it does.
    assert "It has none anybody can type until it sets one" in told[-1][2] and "you make one for it (Users)" in told[-1][2]
    assert "Forgot password" in owners[-1][1]
    unlinked = [a[2] for a in h.audits if a[0] == "sso_identity_unlinked"][-1]
    assert unlinked["held"] is False and unlinked["restored"] is True
    assert len([a for a in h.audits if a[0] == "sso_refusal_cleared"]) == 1          # no refusal held this one
    assert [a[2]["linked_by"] for a in h.audits if a[0] == "sso_identity_unlinked"] == ["self", "jit"]
    assert _call(h.S, "DELETE", f"/admin/sso/identities/{held.id}")[0] == 404


@pytest.mark.parametrize("case", ["a password nobody knows", "held to no password by another provider that is off",
                                  "another provider that is on", "a password of its own"])
def test_an_administrators_unlink_that_would_leave_no_way_in_is_refused_with_what_to_do_first(monkeypatch, case):
    """The owner's own unlink refuses to remove the account's last way in. An administrator's did it without a
    word: the account was left with no password anybody can type and no provider that is on, and nobody was
    told. Refused the same way, in words that say what to do first; an account that is to have no access is
    turned off or deleted."""
    from app.api import sso_admin_router as A
    from app.api import sso_providers_router as R
    from app.api import sso_router
    from app.core import password_origin
    root, dana = _user("root", role="admin"), _user("dana", password_hash="r1")
    dana.password_set_by, dana.password_set_by_other_at = None, None
    p = _provider()                                             # on
    other = _provider(name="fabrikam", label="Sign in with Fabrikam",
                      state="enabled" if case == "another provider that is on" else "disabled",
                      policy={"sso_password_login": "disabled"} if case.startswith("held to no password") else {})
    identities = [_identity(dana, p, subject="subject-dana", linked_by="invitation", last_sign_in_at=datetime.utcnow())]
    if case != "a password of its own":
        password_origin.mark_nobody_knows(dana)
    if case in ("held to no password by another provider that is off", "another provider that is on"):
        identities.append(_identity(dana, other, subject="subject-dana-2", last_sign_in_at=datetime.utcnow()))
    if case.startswith("held to no password"):
        dana.sso_only = True
    h = Harness(monkeypatch, [root, dana], [p, other], identities=identities)
    told, owners = [], []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: None)
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append((by, title, body)))
    monkeypatch.setattr(sso_router, "_tell_owner", lambda db, user, row, title, change: owners.append((user.username, change)))
    ended = []
    monkeypatch.setattr(sso_router, "_end_what_came_through", lambda db, user, identity: ended.append(identity.id) or 0)
    del h.db.log[:]
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{identities[0].id}")
    if case in ("another provider that is on", "a password of its own"):
        assert status == 200 and body["removed"] is True, body
        assert identities[0] not in h.identities() and len(told) == 1 and len(owners) == 1
        return
    assert status == 409 and body["detail"]["reason"] == "no_way_in_left", body
    said = body["detail"]["message"]
    if case == "a password nobody knows":
        assert said == ("This is the only way dana can sign in: the account has no password anybody can type. Make "
                        "a reset link for it first (Users), so that it can set a password, then unlink. To take "
                        "the account's access away, turn the account off or delete it.")
    else:
        assert said == ("This is the only way dana can sign in now: the account signs in only through its "
                        "providers, and no other provider it is linked to is on. Turn that provider on, or allow "
                        "password sign-in for it, first. To take the account's access away, turn the account off "
                        "or delete it.")
    # Nothing was done: the identity is there, no session was ended, nothing was committed, recorded or told.
    assert identities[0] in h.identities() and ended == [] and ("commit",) not in h.db.log
    assert ("rollback",) in h.db.log and told == [] and owners == []
    assert not [a for a in h.audits if a[0] == "sso_identity_unlinked"]


def test_the_owners_own_link_and_unlink_record_what_they_did_to_the_password(monkeypatch):
    """A link to a provider whose people hold no password ends the account's password, and an unlink of it gives
    the password back: each record says so, as the provider's own save does for the accounts it touches."""
    import inspect
    from app.api import sso_router
    linked = inspect.getsource(sso_router.finish_link)
    assert '"linked_by": "self", "made_sso_only": bool(password_stopped)' in linked
    unlinked = inspect.getsource(sso_router.unlink_my_identity)
    assert '"restored": settled == sso_only.RESTORED' in unlinked
    at_sign_in = inspect.getsource(sso_router._record_resolution)
    assert '"identity_id": str(getattr(found.identity, "id", "") or "")' in at_sign_in
    assert '"made_sso_only": bool(found.password_stopped)' in at_sign_in
