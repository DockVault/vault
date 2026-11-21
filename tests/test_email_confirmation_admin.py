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
    _patch(db, ada, bob, email_confirmed=True)
    db.refresh(bob)
    assert bob.email == "bob@example.com" and email_confirmation.confirmed(bob) is True
    # A change to someone's sign-in details: recorded as one, and the owner is told what it was.
    (change,) = db.query(CredentialChange).all()
    assert change.kind == cc.EMAIL and str(change.target_user_id) == str(bob.id)
    assert told == [("email", "bob", {"old_email": "bob@example.com", "new_email": "bob@example.com",
                                      "confirmed_only": True}, {"by_name": "ada"})]
    assert any((d.get("changes") or d).get("email_confirmed") == {"old": False, "new": True}
               for d in _audited(db, "user_updated"))
    # Confirmed already: nothing is done, counted or told a second time.
    _patch(db, ada, bob, email_confirmed=True)
    assert db.query(CredentialChange).count() == 1 and len(told) == 1
    # Sent with a new address, the address is what changes (and an administrator's change confirms it).
    _patch(db, ada, _user(db, "dan"), email="set@example.com", email_confirmed=True)
    dan = db.query(api.User).filter(api.User.username == "dan").one()
    assert dan.email == "set@example.com" and email_confirmation.confirmed(dan) is True
    assert told[-1][2] == {"old_email": "dan@example.com", "new_email": "set@example.com"}


def test_what_the_owner_and_a_second_administrator_read_of_a_confirmation():
    title, text = api._credential_change_notice(cc.EMAIL, {"old_email": "bob@example.com", "new_email": "bob@example.com",
                                                           "confirmed_only": True})
    assert title == "Your email address was confirmed"
    assert text.startswith("An administrator confirmed that bob@example.com is your email address.")
    # The copy sent by email goes to that very address: nothing in it is masked.
    assert api._credential_change_notice(cc.EMAIL, {"new_email": "bob@example.com", "confirmed_only": True},
                                         mask_new_email=True)[1] == text
    assert "was changed" in api._credential_change_notice(cc.EMAIL, {"old_email": "a@example.com",
                                                                     "new_email": "b@example.com"})[0]
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
        _patch(db, people[who], people[target], email_confirmed=True)
    assert refused.value.status_code == status and says in str(refused.value.detail)
    assert db.query(CredentialChange).count() == 0
    assert not any(email_confirmation.confirmed(u) for u in people.values())
    # Somebody who is no administrator confirms nobody's address but changes nothing of another account at all.
    with pytest.raises(HTTPException) as refused:
        _patch(db, people["bob"], people["ada"], email_confirmed=True)
    assert refused.value.status_code == 403 and email_confirmation.confirmed(people["ada"]) is False


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
    answer = _patch(db, ada, bob, email_confirmed=True)
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

    def __init__(self, monkeypatch, smtp=True):
        from app.core import email_actions, otp_service, rate_limiter
        self.issued, self.sent, self.asked = [], [], []
        monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit",
                            lambda **kw: self.asked.append((kw["prefix"], kw["identifier"])) or (True, 0, 0))
        monkeypatch.setattr(api, "_smtp_configured", lambda db: smtp)
        monkeypatch.setattr(api, "_email_change_otp_ttl_minutes", lambda db: 5)
        monkeypatch.setattr(otp_service, "issue", lambda db, **kw: self.issued.append(kw) or "123456")
        monkeypatch.setattr(otp_service, "verify", lambda db, **kw: SimpleNamespace(
            ok=bool(self.issued) and kw["code"] == "123456" and kw["purpose"] == self.issued[-1]["purpose"]
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
                           {"code": "123456", "expires": "in 5 minutes"})]
    assert codes.asked == [("email_confirm_code", str(bob.id))]
    # A wrong code confirms nothing.
    with pytest.raises(HTTPException) as refused:
        codes.confirm(db, bob, "000000")
    assert refused.value.status_code == 400 and email_confirmation.confirmed(bob) is False
    # The address changed after the code was sent: the code was for another address.
    bob.email = "other@example.com"
    db.commit()
    with pytest.raises(HTTPException) as refused:
        codes.confirm(db, bob, "123456")
    assert refused.value.status_code == 409 and "changed since" in refused.value.detail
    assert email_confirmation.confirmed(bob) is False
    bob.email = "Bob@Example.com"
    db.commit()
    assert codes.confirm(db, bob, "123456") == {"email": "Bob@Example.com", "email_confirmed": True}
    db.refresh(bob)
    assert email_confirmation.confirmed(bob) is True and bob.email == "Bob@Example.com"
    assert ("email_confirm_try", str(bob.id)) in codes.asked
    assert _audited(db, "email_confirmation_requested") == [{}] and _audited(db, "email_confirmed") == [{"by": "code"}]
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
            codes.confirm(db, bob, "123456")
        assert refused.value.status_code == 403


def test_the_code_is_its_own_and_no_other_codes(db, world, monkeypatch):
    """The code that confirms a held address is not the one that changes an address: neither stands in for the
    other, since each is issued and checked under its own purpose."""
    bob = _user(db, "bob")
    codes = _Codes(monkeypatch)
    codes.request(db, bob)
    codes.issued[-1]["purpose"] = "email_change"            # as if only an address change had been asked for
    with pytest.raises(HTTPException) as refused:
        codes.confirm(db, bob, "123456")
    assert refused.value.status_code == 400 and email_confirmation.confirmed(bob) is False
