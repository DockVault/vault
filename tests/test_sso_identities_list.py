"""What Your account is told of the caller's own organisation identities and of the providers they could link
(GET /users/me/identities), and what the start of a link and the owner's unlink answer to match it
(app/api/sso_router.py). Through the ASGI app against an in-memory database. Offline."""
import uuid

import pytest

from test_sso_sign_in import Harness, _call, _identity, _provider, _user

pytestmark = pytest.mark.unit


def _listed(h):
    status, out, _ = _call(h.S, "GET", "/users/me/identities")
    assert status == 200, out
    return out


def _offered(out):
    return {p["id"]: p for p in out["providers"]}


def test_a_provider_without_a_sign_in_button_is_offered_for_a_link_and_one_that_is_off_is_not(monkeypatch):
    """The sign-in page's button is about the sign-in page: a provider that is on and can serve a link is offered
    under Your account whether it shows one or not, since the texts that send people there to link it are true only
    then. A provider that is off is offered to nobody, linked or not."""
    alice = _user()
    hidden = _provider(name="hidden", label="Hidden", show_on_sign_in=False)
    off_linked = _provider(name="off-linked", label="Off", state="disabled")
    h = Harness(monkeypatch, [alice], [hidden, off_linked], identities=[_identity(alice, off_linked)])
    offered = _offered(_listed(h))
    assert str(hidden.id) in offered and offered[str(hidden.id)]["linked"] is False
    assert str(off_linked.id) not in offered
    # The identity on the provider that is off is still listed as the account's own.
    assert [i["provider_id"] for i in _listed(h)["identities"]] == [str(off_linked.id)]
    # And the link of the button-less provider starts.
    status, out = h.start_link(hidden)
    assert status == 200 and out["authorization_url"], out


def test_an_administrator_is_told_why_a_password_less_provider_cannot_be_linked_and_its_start_is_refused_at_once(
        monkeypatch):
    """An administrator's or auditor's account keeps a password of its own, so a provider whose people hold none never
    takes it. The list says so in place of the link, and says nothing of a password that would stop; the start
    refuses at once, before the step-up is spent and before anybody is sent to the provider."""
    from app.services import sso_sign_in as sso
    root = _user("root", role="admin")
    password_less = _provider(name="no-password", label="No password", policy={"sso_password_login": "disabled"})
    keeps = _provider(name="keeps", label="Keeps")
    h = Harness(monkeypatch, [root], [password_less, keeps])
    offered = _offered(_listed(h))
    refused = offered[str(password_less.id)]
    assert refused["linked"] is False and refused["ends_password"] is False
    assert refused["link_refusal"] == {"reason": "privileged_on_password_less",
                                       "message": sso.reason_text(sso.PRIVILEGED_ON_PASSWORD_LESS)}
    assert offered[str(keeps.id)]["link_refusal"] is None
    status, out = h.start_link(password_less)
    assert status == 409 and out["detail"] == refused["link_refusal"], out
    assert "authorization_url" not in out and h.step_ups == []
    assert not [key for key in h.redis.rows if key.startswith("sso:state:")]       # nobody is sent to the provider
    # A provider that lets its people keep a password is linked as before.
    status, out = h.start_link(keeps)
    assert status == 200 and out["authorization_url"] and h.step_ups == ["account.second_factor"], out


def test_an_account_that_is_not_privileged_is_still_told_that_a_password_less_provider_ends_its_password(monkeypatch):
    alice = _user()
    password_less = _provider(name="no-password", label="No password", policy={"sso_password_login": "disabled"})
    h = Harness(monkeypatch, [alice], [password_less])
    offered = _offered(_listed(h))[str(password_less.id)]
    assert offered["ends_password"] is True and offered["link_refusal"] is None


def test_an_administrators_invitation_says_a_provider_is_linked_afterwards_only_where_it_lets_accounts_keep_a_password():
    from app.services import sso_sign_in as sso
    said = sso.reason_text(sso.ADMINISTRATOR_INVITATION)
    assert said.endswith("Where your organisation's sign-in lets accounts keep a password, you can link it from Your "
                         "account afterwards."), said
    assert "you can link your organisation's sign-in from Your account afterwards" not in said


NO_PASSWORD = ("Your account has no password of its own, so another provider cannot be linked to it from here. Ask an "
               "administrator.")
SIGN_IN_WITH_THE_PASSWORD = "To link another provider, sign out and sign in with your password first."


def test_an_account_with_no_password_it_can_type_is_told_it_cannot_link_from_here_and_its_start_says_the_same(
        monkeypatch):
    """A link is started only from a session the password made. An account that signs in only through its provider,
    or one whose password nobody knows, never has such a session (a sign-in through a provider names no proof of
    its own): the list says so in place of the Link button, and the start answers the same sentence."""
    from app.core import password_origin
    alice = _user(sso_only=True)
    linked, other = _provider(name="linked", label="Linked"), _provider(name="other", label="Other")
    h = Harness(monkeypatch, [alice], [linked, other], identities=[_identity(alice, linked)])
    h.session_claims = {"amr": []}                     # what a sign-in through the provider carries
    offered = _offered(_listed(h))
    assert offered[str(other.id)]["link_refusal"] == {"reason": "no_password", "message": NO_PASSWORD}
    assert offered[str(linked.id)]["link_refusal"] is None            # already linked: nothing to start
    status, out = h.start_link(other)
    assert status == 403 and out["detail"] == {"reason": "no_password", "message": NO_PASSWORD}, out
    assert h.step_ups == [] and not [key for key in h.redis.rows if key.startswith("sso:state:")]
    # An account whose password nobody knows (made at a first sign-in) is told the same.
    alice.sso_only = False
    password_origin.mark_nobody_knows(alice)
    assert _offered(_listed(h))[str(other.id)]["link_refusal"]["reason"] == "no_password"
    assert h.start_link(other)[1]["detail"]["reason"] == "no_password"


def test_an_account_with_a_password_is_told_to_sign_in_with_it_before_a_link_and_one_that_did_is_offered_it(
        monkeypatch):
    alice = _user()
    p = _provider(name="other", label="Other")
    h = Harness(monkeypatch, [alice], [p])
    h.session_claims = {"amr": ["hwk"]}                 # a passkey made this session, not the password
    assert _offered(_listed(h))[str(p.id)]["link_refusal"] == {"reason": "password_proof_required",
                                                               "message": SIGN_IN_WITH_THE_PASSWORD}
    status, out = h.start_link(p)
    assert status == 403 and out["detail"]["reason"] == "password_proof_required", out
    h.session_claims = {"amr": ["pwd"]}
    assert _offered(_listed(h))[str(p.id)]["link_refusal"] is None
    assert h.start_link(p)[0] == 200
    # A token from before tokens named their proofs began with the password.
    h.session_claims = {"sub": str(alice.id)}
    assert _offered(_listed(h))[str(p.id)]["link_refusal"] is None


ONE_STEP = {"sso_lapse_ends_sign_in": False}       # an unlink asks nothing of the provider (tests/test_sso_sign_in.py)


def _signed_in_through(h, user, provider, subject, token="this-tab-token"):
    """The request's session: one a sign-in through ``provider`` as ``subject`` made, as its sso_sessions row says."""
    import types
    from app.core.models import ActiveSession, SsoSession
    from app.core.session_hash_utils import hash_session_token
    session_id = uuid.uuid4()
    h.db.rows_of(ActiveSession).append(types.SimpleNamespace(id=session_id, user_id=user.id,
                                                             session_token=hash_session_token(token)))
    h.db.rows_of(SsoSession).append(types.SimpleNamespace(session_id=session_id, provider_id=provider.id,
                                                          idp_sub=subject))
    h.session_claims = {"amr": [], "session_token": token}
    return session_id


def test_the_identity_this_session_came_through_is_marked_and_its_unlink_says_it_ended_this_session(monkeypatch):
    """A person who signed in through a provider and unlinks it is signed out here too: every session made through
    the identity ends with it. The list marks that identity, so the page can say so first, and the unlink's answer
    says the caller's own session ended, so the page signs out with a sentence instead of reading the list again."""
    alice = _user()
    p = _provider(name="contoso", label="Contoso", policy=ONE_STEP)
    q = _provider(name="fabrikam", label="Fabrikam", policy=ONE_STEP)
    through, other = _identity(alice, p, subject="subject-1"), _identity(alice, q, subject="subject-1")
    h = Harness(monkeypatch, [alice], [p, q], identities=[through, other])
    session_id = _signed_in_through(h, alice, p, "subject-1")
    marked = {i["provider_id"]: i["this_session"] for i in _listed(h)["identities"]}
    # The same subject at another provider is another identity.
    assert marked == {str(p.id): True, str(q.id): False}
    # A session no provider's sign-in made marks none.
    h.session_claims = {"amr": ["pwd"]}
    assert {i["this_session"] for i in _listed(h)["identities"]} == {False}
    h.session_claims = {"amr": [], "session_token": "this-tab-token"}
    revoked = []
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, **kw: revoked.append(kw["session_ids"]) or len(kw["session_ids"]))
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: None)
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{other.id}")
    assert status == 200 and out["ended_this_session"] is False and revoked == [], out
    status, out, _ = _call(h.S, "DELETE", f"/users/me/identities/{through.id}")
    assert status == 200 and out["ended_this_session"] is True and revoked == [[session_id]], out
