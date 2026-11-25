"""The owner's unlink of an identity, where its provider closes the account's other ways in once the person stops
signing in there (app/services/sso_sign_in.py unlink_asks_the_provider, app/api/sso_router.py unlink_my_identity).

An account with no identity has no days to run out, so a person the provider no longer signs in could unlink it on
the day before and keep the password for good. The unlink is confirmed by what such a person cannot give: a sign-in
through the provider, made now, staged for this session and for the unlink alone. The administrators are told of
every owner's unlink, and an administrator can unlink for somebody whose provider cannot confirm them. Offline."""
import time
import types
import uuid
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
    """Exactly where the provider can hold the account: it closes the other ways in, it has something to hold
    the account by (days that run out, or a refusal that ends access), the identity is not one the provider
    itself put on the account by a verified address, and the account is one the hold reaches."""
    sso = _sso()
    from app.core import privileged_accounts
    from app.services import sso_freshness
    reached = [True]
    monkeypatch.setattr(sso_freshness, "may_be_held", lambda db, user: reached[0])
    monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: "auditor_right")   # not what is asked here
    alice, p = _user(), _provider()
    for by in ("self", "jit", "invitation", "admin"):
        assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p, linked_by=by), p) is True, by
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p, linked_by="email"), p) is False
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p), None) is False
    only_pauses_keys = _provider(policy={"sso_lapse_ends_sign_in": False})
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, only_pauses_keys), only_pauses_keys) is False
    # Nothing to hold the account by: no days and no refusal that ends access. No deadline ever stands on such a
    # provider, so nothing is asked (and a provider that cannot confirm leaves nobody to an administrator for it).
    for policy, asks in (({"sso_freshness_days": 0, "sso_refusal_ends_access": False}, False),
                         ({"sso_freshness_days": 0, "sso_refusal_ends_access": True}, True),
                         ({"sso_freshness_days": 30, "sso_refusal_ends_access": False}, True),
                         ({"sso_freshness_days": 1, "sso_refusal_ends_access": False}, True)):
        row = _provider(policy=policy)
        identity = _identity(alice, row)
        assert sso.unlink_asks_the_provider(None, alice, identity, row) is asks, policy
        if not asks:
            assert sso_freshness.deadline_of(identity, row) is None
    # An account the hold does not reach is asked nothing.
    reached[0] = False
    assert sso.unlink_asks_the_provider(None, alice, _identity(alice, p), p) is False


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
    monkeypatch.setattr(sso_router, "_tell_owner",
                        lambda db, user, row, title, change, advice=None: owners.append((user.username, change, advice)))
    assert F.held_to_a_provider(h.db, alice) is not None
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{own.id}")
    assert status == 409 and body["detail"]["reason"] == "own_identity" and steps == []
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{held.id}")
    assert status == 200 and body == {"removed": True, "sessions_ended": 0, "held": True, "keys_paused": False}, body
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
    # The owner did not do it, and has nothing to remove: the advice is the one for an administrator's change.
    assert owners[-1][2] == sso_router.BY_AN_ADMINISTRATOR == "If you did not expect this, ask an administrator."
    assert unlinked["unlinked_by"] == "administrator" and unlinked["keys_paused"] is False
    assert unlinked["due"] == held.refused_at.isoformat() + "Z" or unlinked["due"].endswith("Z")
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
    monkeypatch.setattr(sso_router, "_tell_owner",
                        lambda db, user, row, title, change, advice=None: owners.append((user.username, change, advice)))
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


def test_an_administrators_unlink_takes_the_turn_locks_the_identity_and_ends_what_came_through_it(monkeypatch):
    """The administrator's door does what the owner's does, in the same order: the account's turn at its sessions
    before any of its rows, the identity read again under a lock, and the sessions that came through the identity
    ended in the transaction that removes it. Without the turn, a sign-in through the identity that was being
    written kept its session after the identity was gone."""
    from app.api import sso_admin_router as A
    from app.api import sso_providers_router as R
    from app.api import sso_router
    from app.core.models import ExternalIdentity
    root, alice, p = _user("root", role="admin"), _user(), _provider()
    identity = _identity(alice, p, last_sign_in_at=datetime.utcnow())
    h = Harness(monkeypatch, [root, alice], [p], identities=[identity])
    order, told = [], []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: order.append("step up"))
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: order.append(("the turn", str(owner))))
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append(body))
    monkeypatch.setattr(sso_router, "_tell_owner", lambda db, user, row, title, change, advice=None: None)

    def ended(db, user, linked):
        # By now the identity is held: the lock was taken after the turn, and before anything is ended.
        order.append(("ended", user.username, str(linked.id)))
        assert [step for step in h.db.log if step[:2] == ("lock", ExternalIdentity)], h.db.log
        return 2
    monkeypatch.setattr(sso_router, "_end_what_came_through", ended)
    del h.db.log[:]
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{identity.id}")
    assert status == 200 and body == {"removed": True, "sessions_ended": 2, "held": False, "keys_paused": False}, body
    assert order == ["step up", ("the turn", str(alice.id)), ("ended", "alice", str(identity.id))]
    locks = [i for i, step in enumerate(h.db.log) if step[:2] == ("lock", ExternalIdentity)]
    assert len(locks) == 1 and locks[0] < h.db.log.index(("commit",))
    assert [a[2]["sessions"] for a in h.audits if a[0] == "sso_identity_unlinked"] == [2]


def test_what_came_through_an_identity_ends_with_it(monkeypatch):
    """The sessions a sign-in through the identity made are ended by the unlink, each owner's turn first, and the
    sign-ins of the account under way are spent; a session that came through another identity stays."""
    from app.api import sso_router
    from app.core.models import SsoSession
    from app.services import sign_in
    alice, p = _user(), _provider()
    identity = _identity(alice, p, subject="subject-1")
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    mine = [types.SimpleNamespace(session_id=uuid.uuid4(), provider_id=p.id, idp_sub="subject-1") for _ in range(2)]
    other = types.SimpleNamespace(session_id=uuid.uuid4(), provider_id=p.id, idp_sub="subject-2")
    h.db.tables.setdefault(SsoSession, []).extend(mine + [other])
    order = []
    monkeypatch.setattr(sso_router, "_owners_of", lambda db, ids: order.append(("owners", sorted(map(str, ids)))) or [alice.id])
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: order.append(("turn", str(owner))))
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, session_ids=None, actor_username=None, durable=False: (
        order.append(("revoke", sorted(map(str, session_ids)), actor_username, durable)) or len(session_ids)))
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda db, user_id: order.append(("spent", str(user_id))))
    wanted = sorted(str(s.session_id) for s in mine)
    assert sso_router._end_what_came_through(h.db, alice, identity) == 2
    assert order == [("owners", wanted), ("turn", str(alice.id)), ("revoke", wanted, "alice", True),
                     ("spent", str(alice.id))]
    # None came through it: nothing to end, and the sign-ins under way are spent all the same.
    del order[:]
    h.db.tables[SsoSession][:] = [other]
    assert sso_router._end_what_came_through(h.db, alice, identity) == 0 and order == [("spent", str(alice.id))]


def test_an_administrator_who_unlinks_their_own_identity_is_not_told_of_it_as_an_administrator(monkeypatch):
    """Every unlink by its owner is told to the administrators. The owner who is one reads their own notice as
    the owner, and not a second one that says somebody unlinked."""
    ada, root, p = _user("ada", role="admin"), _user("root", role="admin"), _provider()
    identity = _identity(ada, p, last_sign_in_at=datetime.utcnow())
    h = Harness(monkeypatch, [ada, root], [p], identities=[identity])
    h.current_user = ada
    monkeypatch.setattr(h.S, "_active_admins", lambda db: [ada, root])
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 200 and out["removed"] is True, out
    to_administrators = [ids for ids, title in h.notices if title == "ada unlinked " + (p.label or p.name)]
    assert to_administrators == [[str(root.id)]], h.notices


@pytest.mark.parametrize("case", ["a provider that only pauses keys", "days that ran out while the provider was off",
                                  "an account a hold does not reach"])
def test_an_administrators_unlink_says_a_pause_of_the_keys_where_nothing_was_held(monkeypatch, case):
    """'Held to its own sign-in' is said only where the hold applied. Where the provider only pauses keys, where
    its days ran out while it was off (they hold nothing then), and for an account a hold never reaches, what
    ended with the identity was a pause of the keys, and the record, the answer and the notice say that."""
    from app.api import sso_admin_router as A
    from app.api import sso_providers_router as R
    from app.api import sso_router
    from app.services import sso_freshness as F
    root = _user("root", role="admin")
    alice = _user(role="admin" if case == "an account a hold does not reach" else "user")
    p = _provider(state="disabled" if case.startswith("days") else "enabled",
                  policy={"sso_lapse_ends_sign_in": False} if case.startswith("a provider") else {})
    lapsed = _identity(alice, p, last_sign_in_at=datetime.utcnow() - timedelta(days=40))
    h = Harness(monkeypatch, [root, alice], [p], identities=[lapsed])
    told = []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: None)
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append(body))
    monkeypatch.setattr(sso_router, "_tell_owner", lambda db, user, row, title, change, advice=None: None)
    assert F.lapsed(h.db, alice.id) is not None and F.held_to_a_provider(h.db, alice) is None
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{lapsed.id}")
    assert status == 200 and (body["held"], body["keys_paused"]) == (False, True), body
    record = [a[2] for a in h.audits if a[0] == "sso_identity_unlinked"][-1]
    assert (record["held"], record["keys_paused"], record["unlinked_by"]) == (False, True, "administrator")
    assert record["due"].endswith("Z") and record["due"][:10] <= datetime.utcnow().strftime("%Y-%m-%d")
    assert "had paused that account's SSH keys, temporary credentials and devices" in told[-1]
    assert "held that account to its own sign-in" not in told[-1]


def test_an_identity_with_nothing_missed_is_unlinked_by_an_administrator_with_neither_said(monkeypatch):
    from app.api import sso_admin_router as A
    from app.api import sso_providers_router as R
    from app.api import sso_router
    root, alice, p = _user("root", role="admin"), _user(), _provider()
    fresh = _identity(alice, p, last_sign_in_at=datetime.utcnow())
    h = Harness(monkeypatch, [root, alice], [p], identities=[fresh])
    told = []
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: None)
    monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: told.append(body))
    monkeypatch.setattr(sso_router, "_tell_owner", lambda db, user, row, title, change, advice=None: None)
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{fresh.id}")
    assert status == 200 and (body["held"], body["keys_paused"]) == (False, False), body
    assert "paused" not in told[-1] and "held that account" not in told[-1]


def test_an_identity_that_goes_while_the_administrator_gives_the_step_up_is_answered_as_not_found(monkeypatch):
    """The step-up may commit, and what was loaded before it is read again afterwards. An identity its owner
    unlinked in that moment has no row to read again: asked for the account it belonged to then, the route
    answered an error. Whose account it is, is kept before the step-up."""
    from app.api import sso_admin_router as A
    class Gone(Exception):
        pass

    class Identity:
        """An identity row whose columns can no longer be read once it is deleted, as a session's object is."""
        deleted = False

        def __init__(self, source):
            self._user_id = source.user_id
            self.__dict__.update({k: v for k, v in vars(source).items() if k != "user_id"})

        @property
        def user_id(self):
            if self.deleted:
                raise Gone("the row was deleted: nothing to read again")
            return self._user_id

    root, alice, p = _user("root", role="admin"), _user(), _provider()
    identity = Identity(_identity(alice, p, last_sign_in_at=datetime.utcnow()))
    h = Harness(monkeypatch, [root, alice], [p], identities=[identity])
    turns = []
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: turns.append(str(owner)))

    def the_owner_unlinks_meanwhile(db, user, request):
        from app.core.models import ExternalIdentity
        h.db.rows_of(ExternalIdentity).remove(identity)
        identity.deleted = True
    monkeypatch.setattr(A, "_step_up", the_owner_unlinks_meanwhile)
    status, body, _ = _call(h.S, "DELETE", f"/admin/sso/identities/{identity.id}")
    assert status == 404, body
    assert turns == [str(alice.id)]                    # the turn of the account it belonged to, kept beforehand


def test_what_the_administrators_are_told_of_an_owners_unlink():
    """Whether the provider confirmed it, and if not, why none was asked; the day a sign-in there was due and
    whether the account had been warned; and what really stops waiting for the provider, by its own rules."""
    from app.api import sso_router
    from app.core import sso_policy
    from app.services import sso_freshness as F
    now = datetime(2026, 11, 25, 12, 0, 0)
    closes = sso_policy.effective(None)
    pauses = sso_policy.effective({"sso_lapse_ends_sign_in": False})
    nothing = sso_policy.effective({"sso_freshness_days": 0, "sso_refusal_ends_access": False})

    def standing(days_left, window=30):
        return F.Deadline(identity_id="i", user_id="u", provider_id="p", provider_name="Contoso",
                          due=now + timedelta(days=days_left), refused=False, window_days=window, ends_sign_in=True,
                          provider_on=True)

    def told(**kw):
        base = dict(asked=False, linked_by="self", standing=None, policy=closes, reached=True, now=now)
        base.update(kw)
        return sso_router.owners_unlink_text("alice", "Contoso", **base)
    tail = " Check the Users page if you did not expect this."
    closing = (" From now on Contoso says nothing about this account: what signs it in without Contoso (a password, "
               "passkeys) and its SSH keys no longer wait for a sign-in there.")
    assert told(asked=True) == ("alice removed Contoso from the ways their account signs in, after a fresh sign-in "
                                "through Contoso." + closing + tail)
    # The one unlink that stays one step: the record's reader must be able to find it, three days before it is due.
    assert told(linked_by="email", standing=standing(3)) == (
        "alice removed Contoso from the ways their account signs in. Contoso had put the identity on the account "
        "by its email address, so no fresh sign-in through Contoso was asked. A sign-in through Contoso was due by "
        "2026-11-28, and the account had been warned of it." + closing + tail)
    # Before the warning days, the day alone.
    assert "was due by 2026-12-15." in told(asked=True, standing=standing(20))
    assert "had been warned" not in told(asked=True, standing=standing(20))
    assert "had been warned" in told(asked=True, standing=standing(5)) and "had been warned" not in told(
        asked=True, standing=standing(5, window=2))                # a window of two days warns one day before
    # A provider that only pauses keys never held the password; an account a hold does not reach neither.
    keys_only = (" From now on Contoso says nothing about this account: its SSH keys, temporary credentials and "
                 "devices no longer wait for a sign-in there.")
    assert told(policy=pauses).endswith("signs in." + keys_only + tail)
    assert told(reached=False).endswith("signs in." + keys_only + tail)
    # A provider that asks nothing of the account's other ways in.
    assert told(policy=nothing) == ("alice removed Contoso from the ways their account signs in. Contoso asked "
                                    "nothing of this account's other ways in, so nothing else changes." + tail)
    assert told(policy=None).endswith("so nothing else changes." + tail)
    # A refusal has no day to name.
    import dataclasses
    assert "was due by" not in told(standing=dataclasses.replace(standing(-1), refused=True))


def test_the_owners_unlink_records_how_the_identity_was_linked_and_tells_the_administrators_by_email_too(monkeypatch):
    """The record says how the identity was linked as it was (not 'self' for every one), that its owner unlinked
    it, and the day a sign-in there was due. The provider could hold the account, and the identity was unlinked
    with no confirmation (it was linked by an address): the administrators are told in the app and by email."""
    ada, root, alice, p = _user("ada", role="admin"), _user("root", role="admin"), _user(), _provider()
    identity = _identity(alice, p, linked_by="email", last_sign_in_at=datetime.utcnow() - timedelta(days=27))
    h = Harness(monkeypatch, [alice, ada, root], [p], identities=[identity])
    h.current_user = alice
    monkeypatch.setattr(h.S, "_active_admins", lambda db: [ada, root])
    mailed = []
    monkeypatch.setattr(h.S, "_fire_action_email_bulk",
                        lambda db, key, recipients, context=None: mailed.append((key, sorted(r[1] for r in recipients), context)))
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 200 and out["removed"] is True, out
    record = [a[2] for a in h.audits if a[0] == "sso_identity_unlinked"][-1]
    assert (record["linked_by"], record["unlinked_by"], record["confirmed_at_provider"]) == ("email", "owner", False)
    assert record["due"].endswith("Z") and record["due"][:10] == (
        identity.last_sign_in_at + timedelta(days=30)).strftime("%Y-%m-%d")
    (ids, title), = [(ids, title) for ids, title in h.notices if title == "alice unlinked " + (p.label or p.name)]
    assert sorted(ids) == sorted([str(ada.id), str(root.id)])
    from app.core import setting_changes
    (key, names, context), = [m for m in mailed if m[0] == setting_changes.EMAIL_ACTION]
    assert names == ["ada", "root"] and context["by"] == "alice"
    assert "by its email address, so no fresh sign-in" in context["change"]
    assert "and the account had been warned of it" in context["change"]


def test_the_owner_is_advised_by_who_made_the_change(monkeypatch):
    """A change made from the owner's own account ends with what to do if it was not them. One an administrator
    made ends with the advice for that: the owner did not do it, and has nothing to remove."""
    from app.api import sso_router
    said = []
    api = types.SimpleNamespace(
        _notify_users=lambda ids, kind, title, body, target: said.append(body),
        _fire_action_email=lambda *a, **k: None, _change_time_text=lambda: "now")
    monkeypatch.setattr(sso_router, "_api", lambda: api)
    alice = _user()
    sso_router._tell_owner(None, alice, None, "t", "You unlinked your account from Contoso.")
    sso_router._tell_owner(None, alice, None, "t", "root unlinked your account from Contoso.",
                           advice=sso_router.BY_AN_ADMINISTRATOR)
    alice.sso_only = True
    sso_router._tell_owner(None, alice, None, "t", "You linked Contoso.")
    assert said == ["You unlinked your account from Contoso. If you did not do this, remove it and change your password.",
                    "root unlinked your account from Contoso. If you did not expect this, ask an administrator.",
                    "You linked Contoso. If you did not do this, tell an administrator at once."]


def test_the_owners_unlink_waits_a_short_time_for_the_accounts_turn_and_is_answered_as_busy(monkeypatch):
    """The owner's unlink runs on the server's one loop. A change that settles the account holds its turn until
    it commits: the unlink waits for it as a link does, and a turn still held is answered as busy, with nothing
    unlinked. Another failure of the database is not taken for a held turn."""
    from sqlalchemy.exc import OperationalError
    from app.core import sign_in_lockout
    from app.services import sign_in
    alice, p = _user(), _provider(policy={"sso_lapse_ends_sign_in": False})     # an unlink in one step
    identity = _identity(alice, p, last_sign_in_at=datetime.utcnow())
    h = Harness(monkeypatch, [alice], [p], identities=[identity])
    asked, real = [], sign_in.with_a_short_wait

    def the_short_wait(db, take):
        asked.append("the short wait")
        return real(db, take)
    code = ["55P03"]

    def still_held(db, owner):
        asked.append(("the turn", str(owner)))
        raise OperationalError("SELECT 1 FOR UPDATE", {}, types.SimpleNamespace(pgcode=code[0]))
    monkeypatch.setattr(sign_in, "with_a_short_wait", the_short_wait)
    monkeypatch.setattr(h.S, "_sessions_turn", still_held)
    rolled_back = h.db.log.count(("rollback",))
    status, body, headers = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 503 and headers.get("retry-after") == str(sign_in_lockout.BUSY_RETRY_SECONDS), (body, headers)
    assert body["detail"] == {"reason": "busy", "message": "Your account is being changed right now. Try again in a moment."}
    assert asked == ["the short wait", ("the turn", str(alice.id))]
    assert h.db.log.count(("rollback",)) == rolled_back + 1 and identity in h.identities()
    assert not [a for a in h.audits if a[0] == "sso_identity_unlinked"]
    code[0] = "40P01"                                           # a deadlock is not a turn that is held
    status, body, headers = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 500 and "retry-after" not in headers, body          # the server's own error, not "busy"
    assert identity in h.identities()
    # Let go, the same request unlinks.
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: None)
    assert _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")[0] == 200 and identity not in h.identities()


@pytest.mark.parametrize("policy, mailed", [
    (None, True),                                                              # it closes the other ways in
    ({"sso_lapse_ends_sign_in": False}, False),                                # it only pauses keys
    ({"sso_freshness_days": 0, "sso_refusal_ends_access": False}, False),      # it has nothing to hold by
    ({"sso_freshness_days": 0, "sso_refusal_ends_access": True}, True),        # a refusal there ends access
])
@pytest.mark.parametrize("linked_by", ["self", "email"])
def test_the_administrators_are_emailed_of_an_owners_unlink_only_where_the_provider_could_hold(monkeypatch, policy,
                                                                                               mailed, linked_by):
    """Every owner's unlink is told to the administrators in the app. The email goes only where the unlinked
    provider could hold the account to its own sign-in: the unlink a leaver makes. However the identity was
    linked: one linked by an address is unlinked there with no confirmation, which is the case the email is for."""
    from app.core import setting_changes
    from app.services import sso_sign_in as sso
    root, alice, p = _user("root", role="admin"), _user(), _provider(policy=policy)
    identity = _identity(alice, p, linked_by=linked_by, last_sign_in_at=datetime.utcnow())
    h = Harness(monkeypatch, [alice, root], [p], identities=[identity])
    h.current_user = alice
    monkeypatch.setattr(h.S, "_active_admins", lambda db: [root])
    monkeypatch.setattr(sso, "unlink_asks_the_provider", lambda db, user, identity, row: False)   # not what is asked here
    sent = []
    monkeypatch.setattr(h.S, "_fire_action_email_bulk",
                        lambda db, key, recipients, context=None: sent.append((key, [r[1] for r in recipients])))
    assert sso.provider_can_hold(h.db, alice, p) is mailed
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")
    assert status == 200 and out["removed"] is True, out
    assert [ids for ids, title in h.notices if title == "alice unlinked " + (p.label or p.name)] == [[str(root.id)]]
    assert [s for s in sent if s[0] == setting_changes.EMAIL_ACTION] == ([(setting_changes.EMAIL_ACTION, ["root"])]
                                                                          if mailed else [])


def test_no_email_goes_out_for_the_unlink_of_an_account_no_hold_reaches(monkeypatch):
    from app.core import setting_changes
    from app.services import sso_freshness
    from app.services import sso_sign_in as sso
    root, alice, p = _user("root", role="admin"), _user(), _provider()
    identity = _identity(alice, p, last_sign_in_at=datetime.utcnow())
    h = Harness(monkeypatch, [alice, root], [p], identities=[identity])
    h.current_user = alice
    monkeypatch.setattr(h.S, "_active_admins", lambda db: [root])
    monkeypatch.setattr(sso_freshness, "may_be_held", lambda db, user: False)
    sent = []
    monkeypatch.setattr(h.S, "_fire_action_email_bulk", lambda db, key, recipients, context=None: sent.append(key))
    assert sso.provider_can_hold(h.db, alice, p) is False and sso.provider_can_hold(h.db, alice, None) is False
    assert _call(h.S, "DELETE", f"/users/me/identities/{identity.id}")[0] == 200
    assert setting_changes.EMAIL_ACTION not in sent
    assert [ids for ids, title in h.notices if title == "alice unlinked " + (p.label or p.name)] == [[str(root.id)]]


def test_your_account_is_told_for_each_identity_why_its_unlink_would_be_refused(monkeypatch):
    """The page starts the provider's confirmation for an unlink that asks one. Where the unlink would be refused
    on the person's return whatever the provider says, the list says why for that identity, in the words the
    unlink itself answers, so that nobody is sent to the provider for nothing."""
    from app.api import sso_router
    from app.core import password_origin
    from app.services import sso_sign_in as sso
    monkeypatch.setattr(sso, "unlink_asks_the_provider", lambda db, user, identity, row: False)
    alice = _user()
    fine = _provider(name="fine", label="Fine")
    lapsed = _provider(name="lapsed", label="Lapsed")
    refusing = _provider(name="refusing", label="Refusing")
    made = _provider(name="maker", label="Maker", policy={"sso_jit_password": False})
    rows = {
        "fine": _identity(alice, fine, subject="s-fine", last_sign_in_at=datetime.utcnow()),
        "lapsed": _identity(alice, lapsed, subject="s-lapsed", last_sign_in_at=datetime.utcnow() - timedelta(days=40)),
        "refusing": _identity(alice, refusing, subject="s-refusing", last_sign_in_at=datetime.utcnow(),
                              refused_at=datetime.utcnow()),
    }
    h = Harness(monkeypatch, [alice], [fine, lapsed, refusing, made], identities=list(rows.values()))

    def told():
        out = _call(h.S, "GET", "/users/me/identities")[1]
        return {i["provider_id"]: i["unlink_refusal"] for i in out["identities"]}
    said = told()
    assert said[str(fine.id)] is None
    assert said[str(lapsed.id)] == {"reason": "sso_freshness_lapsed",
                                    "message": "Sign in through lapsed again before you unlink it."}
    assert said[str(refusing.id)] == {"reason": "sso_freshness_lapsed", "message": (
        "refusing refused your account; an administrator must clear that before you can unlink it.")}
    # What the list says is what the unlink answers.
    for name in ("lapsed", "refusing"):
        status, body, _ = _call(h.S, "DELETE", f"/users/me/identities/{rows[name].id}")
        assert status == 409 and body["detail"] == said[str(rows[name].provider_id)], body
    # The identity the account was made with, on a provider that holds such accounts to no password.
    from app.core.models import ExternalIdentity
    password_origin.mark_nobody_knows(alice)
    alice.sso_only = True
    made_with = _identity(alice, made, subject="s-made", linked_by="jit", last_sign_in_at=datetime.utcnow())
    h.db.rows_of(ExternalIdentity).append(made_with)
    said = told()
    assert said[str(made.id)] == {"reason": "made_here", "message": (
        "Your account was made at its first sign-in through Maker, which stays its way in: it is not unlinked here. "
        "Ask an administrator.")}
    status, body, _ = _call(h.S, "DELETE", f"/users/me/identities/{made_with.id}")
    assert status == 409 and body["detail"] == said[str(made.id)]["message"], body
    # The same for an account made when an invitation was accepted through that provider.
    made_with.linked_by = "invitation"
    assert told()[str(made.id)] == said[str(made.id)]
    status, body, _ = _call(h.S, "DELETE", f"/users/me/identities/{made_with.id}")
    assert status == 409 and body["detail"] == said[str(made.id)]["message"], body
    made_with.linked_by = "jit"
    # The last way in of an account with no password anybody can type.
    for row in list(h.identities()):
        if row is not rows["fine"]:
            h.db.rows_of(ExternalIdentity).remove(row)
    alice.sso_only = False
    said = told()
    assert said[str(fine.id)]["reason"] == "no_way_in_left"
    assert said[str(fine.id)]["message"].startswith("Your account has no password of its own, and no other identity")
    status, body, _ = _call(h.S, "DELETE", f"/users/me/identities/{rows['fine'].id}")
    assert status == 409 and body["detail"] == said[str(fine.id)]["message"], body
    alice.sso_only = True
    assert told()[str(fine.id)]["message"].startswith("Your account signs in only through single sign-on")
    # One rule for both: the unlink raises what the list's rule says.
    import inspect
    assert "refusal = owners_unlink_refusal(db, account, identity, row)" in inspect.getsource(sso_router.unlink_my_identity)


@pytest.mark.parametrize("claims, policy, shown, recorded", [
    ({"sub": "another-subject"}, None, "unlink_other_identity", "not_this_account"),
    ({"auth_time": int(time.time()) - 600}, None, "unlink_stale", "reauth_stale"),
    ({"amr": ["pwd"]}, {"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]}, "unlink_no_mfa", "reauth_no_mfa"),
])
def test_a_provider_that_cannot_confirm_this_person_says_who_can_unlink_for_them(monkeypatch, claims, policy, shown,
                                                                                recorded):
    """Carol's account at the provider was made anew with another subject, or signs in there without the second
    factor the vault trusts. The fresh sign-in for her unlink is refused every time; told only to start again,
    she never learns that an administrator can unlink it. The refusal says so, in a reason of its own; the
    record keeps the refusal's reason. A step-up refused the same way keeps its own words."""
    sso = _sso()
    carol = _user("carol")
    p = _provider(last_test=TESTED, policy=policy)
    identity = _identity(carol, p, last_sign_in_at=datetime.utcnow())
    h = Reauth(monkeypatch, [carol], [p], identities=[identity])
    status, out = h.start_reauth(p, action=sso.UNLINK_CONFIRMATION)
    assert status == 200, out
    state, _record = h.state_of(out["authorization_url"])
    h.claims_override = {"auth_time": int(time.time()) - 5, **claims}
    status, location, _ = h.callback(p, state)
    assert (status, location) == (302, "/#sso-error=" + shown), location
    assert [a[2]["reason"] for a in h.audits if a[0] == "sso_sign_in_refused"][-1] == recorded
    said = _call(h.S, "GET", "/auth/sso/reasons")[1]["reasons"][shown]
    assert said.endswith("ask an administrator to unlink it for you.") and "does not confirm the unlink" in said
    assert not _staged(h) and h.identities() == [identity]
    assert sso.said_for_an_unlink(recorded) == shown and sso.said_for_an_unlink("provider_error") == "provider_error"


def test_a_step_up_refused_at_the_provider_keeps_its_own_words(monkeypatch):
    sso = _sso()
    dana = _user("dana", sso_only=True)
    p = _provider(last_test=TESTED)
    h = Reauth(monkeypatch, [dana], [p], identities=[_identity(dana, p)])
    h.current_user = dana
    status, out = h.start_reauth(p)
    assert status == 200, out
    state, _record = h.state_of(out["authorization_url"])
    h.claims_override = {"auth_time": int(time.time()) - 600}
    status, location, _ = h.callback(p, state)
    assert location == "/#sso-error=" + sso.REAUTH_STALE, location
