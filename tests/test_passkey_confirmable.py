"""Whether a provisional passkey can be confirmed, said before anybody tries.

A passkey added within 14 days after an administrator changed the account's sign-in details is provisional, and its
owner confirms it with a factor older than it: the authenticator app set up before it (or one of that app's recovery
codes), or an ordinary passkey added before it that can still be used. After a second-factor reset, or a password an
administrator set for someone who never had a second factor, there is nothing older: the key becomes ordinary on its
own when its 14 days end, and nothing the owner does sooner can change that.

So the server says of each provisional key whether something can confirm it (``confirmable``), in the list and in
the answer to the registration; the confirmation is refused before the step-up is spent when nothing can; the notice
of the added key promises a confirmation only where one can be given. Your account shows the Confirm button only
where it can work, and says when the key becomes ordinary where it cannot; the toast after adding one says which.

The routes run through the ASGI app offline (tests/test_passkey_routes.py's harness); the page's own functions run
in Node (tests/test_account_passkeys_page.py's harness).
"""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from test_account_passkeys_page import account_node
from test_passkey_routes import Harness, _call, _user

pytestmark = pytest.mark.unit


def _provisional(monkeypatch, **harness):
    """An account an administrator changed the sign-in details of yesterday, with a passkey added today: provisional."""
    from app.core import credential_changes as cc
    user = _user()
    change = types.SimpleNamespace(id=uuid.uuid4(), target_user_id=user.id, status=cc.MADE,
                                   applied_at=datetime.utcnow() - timedelta(days=1), kind=cc.PASSWORD)
    h = Harness(monkeypatch, user, changes=[change], **harness)
    status, shown, _ = h.register(label="new")
    assert status == 201 and shown["provisional"] is True, shown
    (row,) = h.rows()
    return h, row, shown


def _listed(h, row):
    status, body = _call(h.S, "GET", "/users/me/passkeys")
    assert status == 200, body
    return next(k for k in body["passkeys"] if k["id"] == str(row.id))


def _older_key(h, row, **extra):
    fields = dict(id=uuid.uuid4(), user_id=h.user.id, credential_id=b"older-" + uuid.uuid4().bytes, uv_initialized=True,
                  retired_at=None, provisional_until=None, created_at=row.created_at - timedelta(days=30),
                  transports=None, label="old", backup_eligible=False, cose_alg=-7, last_used_at=None,
                  rp_id=row.rp_id, attested=False)
    fields.update(extra)
    key = types.SimpleNamespace(**fields)
    h.rows().append(key)
    return key


def test_a_provisional_key_with_nothing_older_is_said_not_confirmable_and_its_confirmation_spends_no_step_up(monkeypatch):
    h, row, shown = _provisional(monkeypatch)
    assert shown["confirmable"] is False
    assert _listed(h, row)["confirmable"] is False
    # The notice of the added key promises no confirmation: the key becomes ordinary on its own, on its day.
    change = h.emails[-1]["context"]["change"]
    assert "confirm it with an older factor" not in change, change
    assert change.endswith("does not count for the actions that need your own factor until "
                           f"{row.provisional_until.date().isoformat()}."), change
    # A page that still offers the button: refused at once, and a step-up proved for it is left unspent.
    spent = len(h.receipts)
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 409 and "Nothing older can vouch for this passkey" in out["detail"], out
    assert len(h.receipts) == spent, h.receipts
    assert row.provisional_until is not None
    # Without a step-up at all, the same answer: no ceremony is asked for a confirmation that cannot happen.
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm")
    assert status == 409 and "Nothing older can vouch for this passkey" in out["detail"], out


def test_an_authenticator_app_set_up_before_the_key_makes_it_confirmable(monkeypatch):
    from app.core.models import SecondFactorEnrollment
    h, row, _ = _provisional(monkeypatch)
    h.db.rows_of(SecondFactorEnrollment).append(types.SimpleNamespace(
        id=uuid.uuid4(), user_id=h.user.id, method="totp", status="active",
        created_at=row.created_at - timedelta(days=40), confirmed_at=row.created_at - timedelta(days=40)))
    assert _listed(h, row)["confirmable"] is True
    status, out = _call(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": "ok"})
    assert status == 200 and out["provisional"] is False, out


def test_an_app_set_up_after_the_key_does_not(monkeypatch):
    from app.core.models import SecondFactorEnrollment
    h, row, _ = _provisional(monkeypatch)
    h.db.rows_of(SecondFactorEnrollment).append(types.SimpleNamespace(
        id=uuid.uuid4(), user_id=h.user.id, method="totp", status="active",
        created_at=row.created_at + timedelta(minutes=5), confirmed_at=row.created_at + timedelta(minutes=5)))
    assert _listed(h, row)["confirmable"] is False


def test_an_older_ordinary_key_that_can_still_be_used_makes_it_confirmable_and_no_other_older_key_does(monkeypatch):
    h, row, _ = _provisional(monkeypatch)
    # Older, but provisional itself; older, but made at another address (no browser offers it here, so it proves
    # no step-up); added after this one: none of them can confirm it.
    _older_key(h, row, provisional_until=datetime.utcnow() + timedelta(days=5))
    _older_key(h, row, rp_id="old-name.example.test")
    _older_key(h, row, created_at=row.created_at + timedelta(minutes=1))
    assert _listed(h, row)["confirmable"] is False
    _older_key(h, row)
    assert _listed(h, row)["confirmable"] is True


def test_an_ordinary_key_is_never_said_to_wait_for_a_confirmation(monkeypatch):
    h = Harness(monkeypatch, _user())
    status, shown, _ = h.register(label="plain")
    assert status == 201 and shown["provisional"] is False and shown["confirmable"] is False
    (row,) = h.rows()
    assert _listed(h, row)["confirmable"] is False


# --------------------------------------------------------------------------- the page

def test_your_account_offers_confirm_only_where_something_can_confirm_the_key():
    got = account_node(r"""
answers['GET /users/me/passkeys'] = LIST([
    KEY('can', { provisional: true, provisional_until: '2026-07-01T09:00:00Z', confirmable: true }),
    KEY('cannot', { provisional: true, provisional_until: '2026-07-01T09:00:00Z', confirmable: false })]);
await renderAccountPasskeys();
out({ rows: rows(), until: day('2026-07-01T09:00:00Z') });
""")
    can, cannot = got["rows"]
    until = got["until"]
    assert can["buttons"] == ["Confirm", "Rename", "Remove"], can
    assert can["lines"][2:] == [f"Waiting for your confirmation until {until}: an administrator changed your sign-in "
                                "details recently."], can
    assert cannot["buttons"] == ["Rename", "Remove"], cannot
    assert cannot["lines"][2:] == [f"Provisional until {until}: an administrator changed your sign-in details "
                                   "recently, and nothing older on your account can confirm it. It becomes ordinary "
                                   "on its own then."], cannot


@pytest.mark.parametrize("answer, toast", [
    ({"provisional": False, "confirmable": False}, "Passkey added."),
    ({"provisional": True, "confirmable": True, "provisional_until": "2026-07-01T09:00:00Z"},
     "Passkey added. Confirm it with your authenticator app, a recovery code or an older passkey."),
    ({"provisional": True, "confirmable": False, "provisional_until": "2026-07-01T09:00:00Z"},
     "Passkey added. It is provisional until {until}, then becomes ordinary on its own."),
], ids=["ordinary", "confirmable", "nothing older"])
def test_the_toast_after_adding_a_key_says_what_the_server_answered_of_it(answer, toast):
    got = account_node(r"""
answers['POST /users/me/passkeys/register/options'] = { challenge_id: 'c-1', options: {}, provisional: true };
answers['POST /users/me/passkeys/register/verify'] = Object.assign({ id: 'k-new', label: '' }, ANSWER);
await _addPasskey();
out({ toasts, until: day('2026-07-01T09:00:00Z') });
""".replace("ANSWER", __import__("json").dumps(answer)))
    assert got["toasts"] == [["success", toast.format(until=got["until"])]]
