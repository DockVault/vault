"""An address confirmed for the account that holds it: by its owner with a code, by an administrator. Offline.

An address a person typed themselves is their claim, and the vault links no provider's sign-in to an account by
it (app/core/email_confirmation.py). Two ways make it the vault's own word without changing it: the owner types
back a code the vault sent there (POST /users/me/email/confirmation/request, then /users/me/email/confirmation),
and an administrator vouches for it (PATCH /users/{id} with ``email_confirmed``), which is a change to someone's
sign-in details like setting the address: counted, held for a second administrator and told to the owner the
same way.
"""
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from test_password_origin import _request, _user, api, cc, db, world  # noqa: F401  (the fixtures are used by name)

from app.core import email_confirmation  # noqa: E402
from app.core.models import AuditLog, CredentialChange, RoleEnum  # noqa: E402

pytestmark = pytest.mark.unit


def _patch(db, actor, target, **fields):
    return run_coroutine(api.update_user(user_id=target.id, user_update=api.UserUpdate(**fields), current_user=actor,
                                         db=db, request=_request()))


def _audited(db, action):
    return [row.details for row in db.query(AuditLog).filter(AuditLog.action == action).all()]


# --------------------------------------------------------------------------- an administrator vouches for it

def test_an_administrator_confirms_the_address_an_account_holds(db, world, monkeypatch):
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    told = []
    monkeypatch.setattr(api, "_notify_credential_change",
                        lambda db, kind, user, result, **kw: told.append((kind, user.username, dict(result), kw)))
    assert email_confirmation.confirmed(bob) is False
    _patch(db, ada, bob, confirm_email="Bob@Example.com")          # the address as read, in whatever letters
    db.refresh(bob)
    assert bob.email == "bob@example.com" and email_confirmation.confirmed(bob) is True
    # A change to someone's sign-in details: recorded as one, and the owner is told what it was.
    (change,) = db.query(CredentialChange).all()
    assert change.kind == cc.EMAIL and str(change.target_user_id) == str(bob.id)
    assert told == [("email", "bob", {"old_email": "bob@example.com", "new_email": "bob@example.com",
                                      "confirmed_only": True}, {"by_name": "ada"})]
    assert any((d.get("changes") or d).get("email_confirmed") == {"old": False, "new": True}
               for d in _audited(db, "user_updated"))
    # The record names the address that was vouched for, and who vouched.
    (row,) = db.query(AuditLog).filter(AuditLog.action == "email_confirmed").all()
    assert (row.user_id, row.resource_id) == (ada.id, str(bob.id))
    assert row.details == {"method": "administrator", "target_username": "bob", "email": "bob@example.com"}
    # Confirmed already: nothing is done, counted or told a second time.
    _patch(db, ada, bob, confirm_email="bob@example.com")
    assert db.query(CredentialChange).count() == 1 and len(told) == 1
    # Setting an address and confirming one are two requests: sent together, nothing is done.
    dan = _user(db, "dan")
    with pytest.raises(HTTPException) as refused:
        _patch(db, ada, dan, email="set@example.com", confirm_email="set@example.com")
    assert refused.value.status_code == 400 and "not both at once" in refused.value.detail
    db.refresh(dan)
    assert dan.email == "dan@example.com" and email_confirmation.confirmed(dan) is False and len(told) == 1


def test_what_an_administrator_read_is_what_is_confirmed_or_nothing_is(db, world):
    """An administrator's page shows mallory's address as it was when the list was read. Mallory then changes her
    own address, with her password alone, to one that is somebody else's, and asks to be confirmed. The request
    names the address the administrator read: the account holds another now, so nothing is confirmed (the
    confirmation would otherwise let the other person's sign-in through a provider be linked to mallory's
    account). Read again, the administrator sees the new address and decides about that one."""
    ada, mallory = _user(db, "ada", RoleEnum.ADMIN), _user(db, "mallory")
    shown = mallory.email
    mallory.email = "carol@example.com"                # her own change: the mark is gone with it
    db.commit()
    with pytest.raises(HTTPException) as refused:
        _patch(db, ada, mallory, confirm_email=shown)
    assert refused.value.status_code == 409 and refused.value.detail["reason"] == "address_changed"
    db.refresh(mallory)
    assert email_confirmation.confirmed(mallory) is False and db.query(CredentialChange).count() == 0
    assert _audited(db, "email_confirmed") == []
    for odd in ("", "not an address", "carol@example.com.evil.test"):
        with pytest.raises(HTTPException) as refused:
            _patch(db, ada, mallory, confirm_email=odd)
        assert refused.value.status_code == 409, odd
    assert email_confirmation.confirmed(mallory) is False


@pytest.mark.parametrize("standing", ["administrator", "auditor right"])
def test_no_confirmation_is_made_for_an_account_that_is_never_linked_by_its_address(db, world, monkeypatch, standing):
    """An administrator's account, and one that holds the auditor right, is never linked to a provider by its
    address. A confirmation would do nothing it is for, and would still count as a change to the account's sign-in
    details (its keys held, an auditor's right suspended): it is refused."""
    from app.core import privileged_accounts
    ada = _user(db, "ada", RoleEnum.ADMIN)
    target = _user(db, "eve", RoleEnum.ADMIN if standing == "administrator" else RoleEnum.USER)
    if standing == "auditor right":
        monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: "auditor_right" if user.id == target.id else None)
    with pytest.raises(HTTPException) as refused:
        _patch(db, ada, target, confirm_email=target.email)
    assert refused.value.status_code == 400 and "never linked to a provider" in refused.value.detail
    db.refresh(target)
    assert email_confirmation.confirmed(target) is False and db.query(CredentialChange).count() == 0


def test_what_the_owner_and_a_second_administrator_read_of_a_confirmation():
    title, text = api._credential_change_notice(cc.EMAIL, {"old_email": "bob@example.com", "new_email": "bob@example.com",
                                                           "confirmed_only": True})
    assert title == "Your email address was confirmed"
    assert text.startswith("An administrator confirmed that bob@example.com is your email address.")
    assert "your zero-knowledge vaults ask for a code sent by email for the next 14 days." in text
    # The copy sent by email goes to that very address: nothing in it is masked.
    assert api._credential_change_notice(cc.EMAIL, {"new_email": "bob@example.com", "confirmed_only": True},
                                         mask_new_email=True)[1] == text
    assert "was changed" in api._credential_change_notice(cc.EMAIL, {"old_email": "a@example.com",
                                                                     "new_email": "b@example.com"})[0]


@pytest.mark.parametrize("days, said", [(14, "for the next 14 days."), (3, "for the next 3 days."),
                                        (1, "for the next 1 day."), (0, None)])
def test_the_owners_notice_states_the_hold_this_vault_has(monkeypatch, days, said):
    """The hold on the key envelope after an administrator's change is a setting, from none to 14 days. The notice
    of a confirmation states the hold this vault has, and none where it has none."""
    from app.core import envelope_hold
    monkeypatch.setattr(envelope_hold, "hold_days", lambda: days)
    _title, text = api._credential_change_notice(cc.EMAIL, {"new_email": "bob@example.com", "confirmed_only": True})
    assert "Your organisation's sign-in can now find your account by it." in text
    if said is None:
        assert "zero-knowledge" not in text and text.endswith("can now find your account by it.")
    else:
        assert text.endswith("your zero-knowledge vaults ask for a code sent by email " + said)


def test_a_confirmation_is_told_as_one_and_moves_no_reset_link(db, world):
    """A confirmation is kept among the changes to the email address (it is counted and held like one), and it
    changes no address. Everything that reads such a record tells the two apart: the request reads "confirm the
    email address", the applied change "Email address confirmed"; and a self-service reset link asked for in
    the 14 days after it goes to the account's address with no word of an address that "was changed"."""
    ada, eve, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "eve", RoleEnum.ADMIN), _user(db, "bob")
    asked, applied = {"email": "bob@example.com", "confirm": True}, {"new_email": "bob@example.com", "confirmed_only": True}
    assert cc.is_confirmation(cc.EMAIL, asked) and cc.is_confirmation(cc.EMAIL, applied)
    assert not cc.is_confirmation(cc.EMAIL, {"email": "new@example.com"}) and not cc.is_confirmation(cc.EMAIL, None)
    assert not cc.is_confirmation(cc.PASSWORD, asked)
    assert cc.phrase(cc.EMAIL, asked) == "confirm the email address" and cc.phrase(cc.EMAIL) == "change the email address"
    assert cc.request_label(cc.EMAIL, asked) == "Confirm the email address"
    assert cc.label(cc.EMAIL, applied) == "Email address confirmed" and cc.label(cc.EMAIL) == "Email address change"
    # Applied at once: what the record keeps says it was a confirmation.
    _patch(db, ada, bob, confirm_email="bob@example.com")
    (made,) = db.query(CredentialChange).all()
    assert made.payload == {"previous_email": "bob@example.com", "new_email": "bob@example.com", "confirmed_only": True}
    assert cc.what_of(made) == (cc.EMAIL, made.payload) and cc.label(*cc.what_of(made)) == "Email address confirmed"
    assert cc.email_changes_in_window(db, bob.id) == []
    assert api._self_service_reset_destination(db, bob) == ("bob@example.com", "")
    # A real change of the address is still one, and still moves the link.
    made.payload = {"previous_email": "old@example.com", "new_email": "bob@example.com"}
    db.commit()
    assert [c.id for c in cc.email_changes_in_window(db, bob.id)] == [made.id]
    destination, note = api._self_service_reset_destination(db, bob)
    assert destination == "old@example.com" and "changed this account's email address" in note
    # Held for a second administrator: the lists and the notices name it as what it is.
    dan = _user(db, "dan")
    _patch(db, ada, dan, password="Admin-Chosen-8x!")
    _patch(db, ada, dan, confirm_email="dan@example.com")
    (waiting,) = [c for c in db.query(CredentialChange).all() if c.status == cc.HELD]
    assert api._credential_request_dict(waiting, "dan")["label"] == "Confirm the email address"
    said = []
    api_notify, api_account = api._notify_users, api._notify_account_change
    try:
        api._notify_users = lambda ids, ntype, title=None, body=None, **kw: said.append(body)
        api._notify_account_change = lambda db, user, **kw: said.append(kw["change"])
        api._announce_held_change(db, waiting, dan)
    finally:
        api._notify_users, api._notify_account_change = api_notify, api_account
    assert len(said) == 3 and all("confirm the email address for" in text for text in said), said
    assert not any("change the email address" in text for text in said)
    assert eve.id != ada.id


def test_a_held_confirmation_is_judged_again_when_it_is_applied(db, world, monkeypatch):
    """A confirmation is refused for an administrator's account and for a holder of the auditor right: neither is
    ever linked by its address, and the change would still hold its keys and suspend an auditor's right. Asked
    for while the account was an ordinary one and approved after it became one of those, it is refused the same
    way when it is applied, and so is a request that makes the account an administrator in the same breath."""
    from app.core import privileged_accounts
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    asked = {"email": "bob@example.com", "confirm": True}
    as_it_is = privileged_accounts.kind
    for became in ("an administrator", "a holder of the auditor right"):
        if became == "an administrator":
            bob.role = RoleEnum.ADMIN
        else:
            bob.role = RoleEnum.USER
            monkeypatch.setattr(privileged_accounts, "kind", lambda db, user: "auditor_right" if user.id == bob.id else None)
        with pytest.raises(HTTPException) as refused:
            api._make_credential_change(db, cc.EMAIL, bob, dict(asked), actor_id=ada.id, actor_name="ada")
        assert refused.value.status_code == 409 and "nothing was confirmed" in refused.value.detail, became
        assert "never linked to a provider" in refused.value.detail
        assert email_confirmation.confirmed(bob) is False
    monkeypatch.setattr(privileged_accounts, "kind", as_it_is)
    # One request that confirms the address and makes the account an administrator: nothing of it is done.
    carol = _user(db, "carol")
    with pytest.raises(HTTPException) as refused:
        _patch(db, ada, carol, confirm_email="carol@example.com", role=RoleEnum.ADMIN)
    assert refused.value.status_code == 400 and "never linked to a provider" in refused.value.detail
    db.refresh(carol)
    assert carol.role == RoleEnum.USER and email_confirmation.confirmed(carol) is False
    assert db.query(CredentialChange).count() == 0


def test_each_refusal_of_a_confirmation_has_its_own_answer(db, world):
    """The refusals of the request, one by one, in the order they are judged."""
    bob = _user(db, "bob")

    def refusal(**kw):
        told = dict(is_self=False, is_admin=True, named="bob@example.com")
        told.update(kw)
        return api._confirmation_refusal(db, bob, **told)

    assert refusal() is None
    assert refusal(is_self=True).status_code == 400 and "your own email address" in refusal(is_self=True).detail
    assert refusal(is_admin=False).status_code == 403
    assert refusal(is_admin=False).detail == "Only an administrator confirms someone's email address."
    assert refusal(named="other@example.com").status_code == 409
    assert refusal(becomes_administrator=True).status_code == 400
    assert refusal(is_self=True, is_admin=False).status_code == 400            # one's own comes first
    bob.email = None
    assert refusal().status_code == 400 and "no email address" in refusal().detail
    assert api._request_summary(cc.EMAIL, new_email="bob@example.com", confirm=True) == (
        "The address stays bob@example.com: it is confirmed as theirs")
    assert api._request_summary(cc.EMAIL, new_email="bob@example.com") == "New address: bob@example.com"


@pytest.mark.parametrize("who, target, status, says", [
    ("ada", "ada", 400, "Confirm your own email address"),        # never one's own: the code is for that
    ("ada", "nobody", 400, "no email address to confirm"),
])
def test_a_confirmation_that_is_not_an_administrators_to_give_is_refused(db, world, who, target, status, says):
    people = {"ada": _user(db, "ada", RoleEnum.ADMIN), "bob": _user(db, "bob")}
    nobody = _user(db, "nobody")
    nobody.email = None
    db.commit()
    people["nobody"] = nobody
    with pytest.raises(HTTPException) as refused:
        _patch(db, people[who], people[target], confirm_email=people[target].email or "nobody@example.com")
    assert refused.value.status_code == status and says in str(refused.value.detail)
    assert db.query(CredentialChange).count() == 0
    assert not any(email_confirmation.confirmed(u) for u in people.values())
    # Somebody who is no administrator confirms nobody's address but changes nothing of another account at all.
    with pytest.raises(HTTPException) as refused:
        _patch(db, people["bob"], people["nobody"], confirm_email="nobody@example.com")
    assert refused.value.status_code == 403 and email_confirmation.confirmed(people["nobody"]) is False


def test_a_confirmation_is_for_the_address_it_was_asked_for(db, world):
    """Applied at once or after it waited for a second administrator, the confirmation is the mark alone, for the
    address the account held when it was asked. An account that holds another address by then is not confirmed
    by it, and its address is not put back."""
    ada, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "bob")
    asked = {"email": "bob@example.com", "confirm": True}
    out = api._make_credential_change(db, cc.EMAIL, bob, dict(asked), actor_id=ada.id, actor_name="ada")
    assert out == {"old_email": "bob@example.com", "new_email": "bob@example.com", "confirmed_only": True}
    assert email_confirmation.confirmed(bob) is True
    # The same address in other letters is the same address.
    bob.email_confirmed_at = bob.email_confirmed_for = None
    api._make_credential_change(db, cc.EMAIL, bob, {"email": "Bob@Example.com", "confirm": True}, actor_id=ada.id,
                                actor_name="ada")
    assert email_confirmation.confirmed(bob) is True
    # The account changed its address while the request waited.
    bob.email = "moved@example.com"
    assert email_confirmation.confirmed(bob) is False
    for held in (asked, {"email": None, "confirm": True}):
        with pytest.raises(HTTPException) as refused:
            api._make_credential_change(db, cc.EMAIL, bob, dict(held), actor_id=ada.id, actor_name="ada")
        assert refused.value.status_code == 409 and "changed since" in refused.value.detail
    assert bob.email == "moved@example.com" and email_confirmation.confirmed(bob) is False
    bob.email = None
    with pytest.raises(HTTPException):
        api._make_credential_change(db, cc.EMAIL, bob, dict(asked), actor_id=ada.id, actor_name="ada")
    assert bob.email is None


def test_a_second_change_within_the_window_waits_for_another_administrator(db, world):
    """The confirmation counts like every change to someone's sign-in details: after another one within 14 days
    it is not made on one administrator's word."""
    ada, eve, bob = _user(db, "ada", RoleEnum.ADMIN), _user(db, "eve", RoleEnum.ADMIN), _user(db, "bob")
    _patch(db, ada, bob, password="Admin-Chosen-8x!")
    answer = _patch(db, ada, bob, confirm_email="bob@example.com")
    db.refresh(bob)
    assert email_confirmation.confirmed(bob) is False, "not on one administrator's word"
    assert answer.status_code == 202
    body = json.loads(answer.body)
    assert len(body["held_changes"]) == 1 and "confirmed as theirs" in json.dumps(body)
    (waiting,) = [c for c in db.query(CredentialChange).all() if c.kind == cc.EMAIL]
    assert waiting.payload == {"email": "bob@example.com", "confirm": True}
    # What the second administrator's approval then applies is the mark, for that address.
    api._apply_credential_change(db, cc.EMAIL, bob, dict(waiting.payload), actor_id=ada.id, actor_name="ada",
                                 link_maker_id=eve.id)
    assert email_confirmation.confirmed(bob) is True and bob.email == "bob@example.com"


def test_an_account_reads_whether_its_own_address_is_confirmed(db, world):
    bob = _user(db, "bob")
    assert run_coroutine(api.get_current_user_info(current_user=bob)).email_confirmed is False
    email_confirmation.confirm(bob)
    assert run_coroutine(api.get_current_user_info(current_user=bob)).email_confirmed is True


# --------------------------------------------------------------------------- the owner, with a code

class _Codes:
    """The code machinery and the mail, standing in: what was issued, to where, and what was sent."""

    CODE = "ab12cd34ef56"                  # as the vault makes them: twelve lower-case hex characters

    def __init__(self, monkeypatch, smtp=True):
        from app.core import email_actions, otp_service, rate_limiter
        self.issued, self.sent, self.asked, self.tried = [], [], [], []
        self.limiter = (True, 0, 0)                     # what the limiter answers; an exception is raised

        def limit(**kw):
            self.asked.append((kw["prefix"], kw["identifier"], kw["limit"], kw["window"], kw["fail_open"]))
            if isinstance(self.limiter, Exception):
                raise self.limiter
            return self.limiter

        monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", limit)
        monkeypatch.setattr(api, "_smtp_configured", lambda db: smtp)
        monkeypatch.setattr(api, "_email_change_otp_ttl_minutes", lambda db: 5)
        monkeypatch.setattr(otp_service, "issue", lambda db, **kw: self.issued.append(kw) or self.CODE)
        monkeypatch.setattr(otp_service, "verify", lambda db, **kw: self.tried.append(kw["code"]) or SimpleNamespace(
            ok=bool(self.issued) and kw["code"] == self.CODE and kw["purpose"] == self.issued[-1]["purpose"]
            and kw["user_id"] == self.issued[-1]["user_id"],
            destination=self.issued[-1]["destination"] if self.issued else None))
        monkeypatch.setattr(email_actions, "send_action_email",
                            lambda db, key, *, recipient, action_context, raise_errors=False: (
                                self.sent.append((key, recipient, action_context))))

    def request(self, db, user):
        return run_coroutine(api.request_email_confirmation(request=_request(), current_user=user, db=db))

    def confirm(self, db, user, code):
        return run_coroutine(api.confirm_own_email(body=api.EmailConfirmationCode(code=code), request=_request(),
                                                   current_user=user, db=db))


def test_a_person_confirms_the_address_they_hold_with_the_code_sent_to_it(db, world, monkeypatch):
    bob = _user(db, "bob")
    bob.email = "Bob@Example.com"                    # as the person typed it
    db.commit()
    codes = _Codes(monkeypatch)
    answer = codes.request(db, bob)
    assert answer.status_code == 202 and json.loads(answer.body) == {"sent": True, "expires_in_minutes": 5}
    (issued,) = codes.issued
    assert (issued["purpose"], issued["user_id"], issued["destination"], issued["ttl_minutes"]) == (
        "email_confirm", bob.id, "bob@example.com", 5)
    assert codes.sent == [("email_confirm", {"email": "bob@example.com", "username": "bob"},
                           {"code": codes.CODE, "expires": "in 5 minutes"})]
    # Three codes in five minutes for one account, and refused while the limiter cannot be asked.
    assert codes.asked == [("email_confirm_code", str(bob.id), 3, 300, False)]
    # A wrong code confirms nothing.
    with pytest.raises(HTTPException) as refused:
        codes.confirm(db, bob, "000000000000")
    assert refused.value.status_code == 400 and email_confirmation.confirmed(bob) is False
    # The address changed after the code was sent: the code was for another address.
    bob.email = "other@example.com"
    db.commit()
    with pytest.raises(HTTPException) as refused:
        codes.confirm(db, bob, codes.CODE)
    assert refused.value.status_code == 409 and "changed since" in refused.value.detail
    assert email_confirmation.confirmed(bob) is False
    bob.email = "Bob@Example.com"
    db.commit()
    # Typed as a phone gives it: capitals, a space before and after. It is the same code.
    assert codes.confirm(db, bob, "  AB12CD34EF56 ") == {"email": "Bob@Example.com", "email_confirmed": True}
    assert codes.tried[-1] == codes.CODE
    db.refresh(bob)
    assert email_confirmation.confirmed(bob) is True and bob.email == "Bob@Example.com"
    assert ("email_confirm_try", str(bob.id), 10, 300, False) in codes.asked          # ten tries in five minutes
    assert _audited(db, "email_confirmation_requested") == [{}]
    assert _audited(db, "email_confirmed") == [{"method": "code", "email": "Bob@Example.com"}]
    # Confirmed: there is nothing more to ask a code for.
    with pytest.raises(HTTPException) as refused:
        codes.request(db, bob)
    assert refused.value.status_code == 409 and refused.value.detail["reason"] == "already_confirmed"
    assert len(codes.issued) == 1


@pytest.mark.parametrize("state, status, says", [
    ("a temporary credential", 403, "Temporary credentials"),
    ("no address", 400, "no email address to confirm"),
    ("a vault that sends no email", 400, "An administrator can confirm your address"),
])
def test_a_code_is_sent_only_where_it_can_prove_something(db, world, monkeypatch, state, status, says):
    bob = _user(db, "bob")
    codes = _Codes(monkeypatch, smtp=state != "a vault that sends no email")
    if state == "a temporary credential":
        bob._is_temp_session = True
    elif state == "no address":
        bob.email = None
        db.commit()
    with pytest.raises(HTTPException) as refused:
        codes.request(db, bob)
    assert refused.value.status_code == status and says in str(refused.value.detail)
    assert codes.issued == [] and codes.sent == []
    if state == "a temporary credential":
        with pytest.raises(HTTPException) as refused:
            codes.confirm(db, bob, codes.CODE)
        assert refused.value.status_code == 403


def test_the_code_is_its_own_and_no_other_codes(db, world, monkeypatch):
    """The code that confirms a held address is not the one that changes an address: neither stands in for the
    other, since each is issued and checked under its own purpose."""
    bob = _user(db, "bob")
    codes = _Codes(monkeypatch)
    codes.request(db, bob)
    codes.issued[-1]["purpose"] = "email_change"            # as if only an address change had been asked for
    with pytest.raises(HTTPException) as refused:
        codes.confirm(db, bob, codes.CODE)
    assert refused.value.status_code == 400 and email_confirmation.confirmed(bob) is False


@pytest.mark.parametrize("limiter, status", [("used up", 429), ("cannot be asked", 503)])
def test_a_code_and_a_try_are_refused_once_the_accounts_budget_is_used_up_or_cannot_be_counted(db, world, monkeypatch,
                                                                                               limiter, status):
    """A code is mail sent to an address, and a try is a guess at a code. Neither goes on once the account's budget
    is used up (429, saying when to come back), and neither goes uncounted: while the limiter cannot be asked, both
    are refused for the moment (503). No code is made and none is looked at."""
    import time
    from app.core.rate_limiter import RateLimiterUnavailable
    bob = _user(db, "bob")
    codes = _Codes(monkeypatch)
    codes.request(db, bob)                                  # one code is out, so a try could succeed
    made = len(codes.issued)
    codes.limiter = (False, 0, int(time.time()) + 120) if limiter == "used up" else RateLimiterUnavailable("away")
    for act in (lambda: codes.request(db, bob), lambda: codes.confirm(db, bob, codes.CODE)):
        with pytest.raises(HTTPException) as refused:
            act()
        assert refused.value.status_code == status, refused.value.detail
        if status == 429:
            assert int(refused.value.headers["Retry-After"]) > 0
    assert len(codes.issued) == made and codes.tried == [] and email_confirmation.confirmed(bob) is False
