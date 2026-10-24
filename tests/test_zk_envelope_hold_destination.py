"""Where the code that releases an encryption-key envelope goes during the hold, offline on a real database.

The hold starts when an administrator changes someone's sign-in details (app/core/envelope_hold.py). The code
must reach the person, not whoever made the change. That administrator can sign in with a password they set
and move the account's address through its own settings, which is not recorded as an administrator's change;
a code sent to the account's address as it is now would follow them. So every applied change keeps the
address the account had just before it, and the code goes to the one kept on the earliest change that holds
the account. test_zk_envelope_hold_live.py drives the same through the routes, with a mail sink.
"""
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import envelope_hold as H  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AccountInvitation, AdminGrant, AuditLog, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit

OTHER_KINDS = [cc.PASSWORD, cc.RESET_LINK, cc.SECOND_FACTOR, cc.SSH_KEY]


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(settings, "zk_envelope_hold_days", 14)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'dest.db'}")
        for model in (User, CredentialChange, AdminGrant, AccountInvitation, AuditLog):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def applied(monkeypatch):
    """Applying a change is stood in for: it records what it was asked for, and an email change moves the
    address as the real one does."""
    calls = []

    def apply(db, kind, target, payload, **_kw):
        calls.append(kind)
        if kind == cc.EMAIL:
            old, target.email = target.email, payload["email"]
            return {"old_email": old, "new_email": target.email}
        return {}
    monkeypatch.setattr(api, "_apply_credential_change", apply)
    monkeypatch.setattr(api, "_announce_decided_change", lambda *a, **k: None)
    return calls


def _user(db, name, email=None, role=RoleEnum.USER):
    u = User(username=name, email=email, password_hash="x", role=role, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def _made(db, admin, target, kind, payload=None):
    outcome = api._credential_change(db, admin, target, kind, summary="s", payload=payload or {})
    db.commit()
    assert outcome.held is False
    return outcome.change


@pytest.mark.parametrize("kind", OTHER_KINDS)
def test_every_change_made_keeps_the_address_the_account_had(db, applied, kind):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    row = _made(db, alice, carol, kind)
    assert applied == [kind]
    assert db.get(CredentialChange, row.id).payload == {"email_at_change": "carol@example.com"}


def test_an_email_change_keeps_the_address_before_and_after_as_it_did(db, applied):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    row = _made(db, alice, carol, cc.EMAIL, {"email": "new@example.org"})
    assert db.get(CredentialChange, row.id).payload == {"previous_email": "carol@example.com",
                                                         "new_email": "new@example.org"}


@pytest.mark.parametrize("kind", OTHER_KINDS)
def test_an_approved_change_keeps_the_address_the_account_had(db, applied, kind):
    alice, bob = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "bob", role=RoleEnum.ADMIN)
    carol = _user(db, "carol", "carol@example.com")
    held = cc.hold(db, kind=kind, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                   summary="s", payload={"secret": "what it would set"})
    db.commit()
    api._approve_credential_change(db, held, carol, approver=bob)
    row = db.get(CredentialChange, held.id)
    assert row.status == cc.APPROVED
    # What the request would have set is gone; the address it found is kept.
    assert row.payload == {"email_at_change": "carol@example.com"}


def test_the_code_does_not_follow_an_address_moved_through_the_accounts_own_settings(db, applied):
    """The administrator sets a password, signs in with it, and moves the address themselves: a
    self-service change, which records nothing here. The code still goes to the person's address."""
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _made(db, alice, carol, cc.PASSWORD)
    carol.email = "taker@example.net"
    db.commit()
    assert H.code_destination(db, carol) == "carol@example.com"


def test_after_an_administrators_email_change_the_code_goes_to_the_address_before_it(db, applied):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _made(db, alice, carol, cc.EMAIL, {"email": "taker@example.net"})
    assert carol.email == "taker@example.net"
    assert H.code_destination(db, carol) == "carol@example.com"


def _row(db, user, kind, days_ago, payload, *, released=False):
    now = cc.utcnow()
    row = CredentialChange(target_user_id=user.id, kind=kind, status=cc.MADE, requested_by_name="admin",
                           requested_at=now - timedelta(days=days_ago), applied_at=now - timedelta(days=days_ago),
                           payload=payload, envelope_released_at=now if released else None)
    db.add(row)
    db.commit()
    return row


def test_the_earliest_change_that_holds_the_account_decides(db):
    carol = _user(db, "carol", "now@example.net")
    _row(db, carol, cc.PASSWORD, 5, {"email_at_change": "first@example.com"})
    _row(db, carol, cc.EMAIL, 2, {"previous_email": "second@example.com", "new_email": "x@example.net"})
    _row(db, carol, cc.SSH_KEY, 1, {"email_at_change": "third@example.com"})
    assert H.code_destination(db, carol) == "first@example.com"


def test_a_change_the_host_operator_released_no_longer_decides(db):
    carol = _user(db, "carol", "now@example.net")
    _row(db, carol, cc.PASSWORD, 5, {"email_at_change": "first@example.com"}, released=True)
    _row(db, carol, cc.SSH_KEY, 1, {"email_at_change": "third@example.com"})
    assert H.code_destination(db, carol) == "third@example.com"


@pytest.mark.parametrize("kind,payload", [
    (cc.PASSWORD, None),                                        # recorded before 0.34.0
    (cc.PASSWORD, {}),
    (cc.PASSWORD, {"email_at_change": None}),                   # the account had no address
    (cc.PASSWORD, {"email_at_change": "  "}),
    (cc.EMAIL, {"previous_email": None, "new_email": "taker@example.net"}),
    (cc.EMAIL, {"new_email": "taker@example.net"}),
])
def test_without_a_known_address_before_the_change_nothing_is_sent(db, kind, payload):
    """Never the address the account has now: the host operator releases the account instead."""
    carol = _user(db, "carol", "taker@example.net")
    _row(db, carol, kind, 1, payload)
    assert H.code_destination(db, carol) is None


def test_an_account_nothing_holds_has_no_destination(db):
    carol = _user(db, "carol", "carol@example.com")
    assert H.code_destination(db, carol) is None
    _row(db, carol, cc.PASSWORD, 20, {"email_at_change": "carol@example.com"})     # past the hold
    assert H.code_destination(db, carol) is None


def test_the_route_sends_the_code_where_the_hold_says():
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
    body = src[src.index("async def send_envelope_release_code("):src.index("async def release_envelope_hold(")]
    assert body.count("envelope_hold.code_destination(db, current_user)") == 1
    assert "_self_service_reset_destination" not in body and "current_user.email" not in body
