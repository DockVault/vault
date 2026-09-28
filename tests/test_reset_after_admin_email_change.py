"""For 14 days after an administrator changed someone's email address, a self-service reset link goes
to the address the account had before, offline on a real database.

Otherwise an administrator could move the address to one they control and finish the takeover through
the public forgot-password form, with one credential change on record. test_password_reset.py drives
the same through the routes, with a mail sink, on a running stack."""
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
from app.core.models import AccountInvitation, AdminGrant, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'reset.db'}")
        for model in (User, CredentialChange, AdminGrant, AccountInvitation):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, email=None, role=RoleEnum.USER):
    u = User(username=name, email=email, password_hash="x", role=role, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def _moved(db, user, admin, old, new, days_ago):
    row = cc.record_made(db, kind=cc.EMAIL, target_id=user.id, requester_id=admin.id,
                         requester_name=admin.username, now=cc.utcnow() - timedelta(days=days_ago))
    row.payload = cc.applied_email_payload({"old_email": old, "new_email": new})
    user.email = new
    db.commit()
    return row


def test_with_no_administrator_change_the_link_goes_to_the_account(db):
    carol = _user(db, "carol", "carol@example.com")
    assert api._self_service_reset_destination(db, carol) == ("carol@example.com", "")


def test_within_fourteen_days_of_an_administrators_change_it_goes_to_the_old_address(db):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _moved(db, carol, alice, "carol@example.com", "attacker@example.net", days_ago=13)
    address, note = api._self_service_reset_destination(db, carol)
    assert address == "carol@example.com"
    assert "changed this account's email address" in note and "14 days" in note
    assert "attacker@example.net" not in note


def test_after_several_changes_it_goes_to_the_address_before_the_first(db):
    alice, bob, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "bob", role=RoleEnum.ADMIN), \
        _user(db, "carol", "carol@example.com")
    _moved(db, carol, alice, "carol@example.com", "one@example.net", days_ago=5)
    _moved(db, carol, bob, "one@example.net", "two@example.net", days_ago=1)
    assert api._self_service_reset_destination(db, carol)[0] == "carol@example.com"


def test_after_fourteen_days_it_goes_to_the_account_again(db):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _moved(db, carol, alice, "carol@example.com", "new@example.org", days_ago=15)
    assert api._self_service_reset_destination(db, carol) == ("new@example.org", "")


def test_an_address_the_person_chose_since_stands(db):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _moved(db, carol, alice, "carol@example.com", "new@example.org", days_ago=2)
    carol.email = "carol-chose@example.com"          # their own change, which asks for their password
    db.commit()
    assert api._self_service_reset_destination(db, carol) == ("carol-chose@example.com", "")


def test_with_no_address_before_the_change_nothing_is_sent(db):
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol")
    _moved(db, carol, alice, None, "attacker@example.net", days_ago=1)
    assert api._self_service_reset_destination(db, carol) is None


def test_an_administrators_email_change_keeps_the_address_before_and_after(db, monkeypatch):
    # The route's own code: the first change in the window is made and recorded with both addresses.
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _user(db, "bob", role=RoleEnum.ADMIN)
    outcome = api._credential_change(db, alice, carol, cc.EMAIL, summary="s", payload={"email": "new@example.org"})
    db.commit()
    assert outcome.held is False and carol.email == "new@example.org"
    (row,) = db.query(CredentialChange).all()
    assert row.payload == {"previous_email": "carol@example.com", "new_email": "new@example.org"}
    assert api._self_service_reset_destination(db, carol)[0] == "carol@example.com"


def test_the_forgot_password_thread_sends_where_the_destination_says(db, monkeypatch):
    import contextlib
    from app.core import database
    alice, carol = _user(db, "alice", role=RoleEnum.ADMIN), _user(db, "carol", "carol@example.com")
    _moved(db, carol, alice, "carol@example.com", "attacker@example.net", days_ago=1)
    sent = []

    class _Now:
        def __init__(self, target, args=(), daemon=None):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(api.threading, "Thread", _Now)
    monkeypatch.setattr(database, "get_db_context", lambda: contextlib.nullcontext(db))
    monkeypatch.setattr(api, "_mint_and_send_reset", lambda s, u, base, *, created_by_id, to=None, note_html="":
                        sent.append((u.username, to, bool(note_html))))
    api._mint_and_send_reset_async(carol.id, "https://vault.example.com")
    assert sent == [("carol", "carol@example.com", True)]


def test_an_approved_email_change_keeps_the_address_before_and_after(db, monkeypatch):
    from app.core.models import AuditLog
    AuditLog.__table__.create(db.get_bind())
    monkeypatch.setattr(api, "_announce_decided_change", lambda *a, **k: None)
    alice, bob, carol = (_user(db, "alice", role=RoleEnum.ADMIN), _user(db, "bob", role=RoleEnum.ADMIN),
                         _user(db, "carol", "carol@example.com"))
    held = cc.hold(db, kind=cc.EMAIL, target_id=carol.id, requester_id=alice.id, requester_name="alice",
                   summary="s", payload={"email": "new@example.org"})
    db.commit()
    api._approve_credential_change(db, held, carol, approver=bob)
    row = db.get(CredentialChange, held.id)
    assert row.status == cc.APPROVED
    assert row.payload == {"previous_email": "carol@example.com", "new_email": "new@example.org"}


def test_the_link_goes_to_the_address_given_with_the_note(monkeypatch):
    from types import SimpleNamespace
    from app.core import email_actions
    got = []
    monkeypatch.setattr(api, "_mint_reset_link", lambda *a, **k: "https://vault.example.com/?reset=t")
    monkeypatch.setattr(api, "_password_reset_policy", lambda db: (True, 30))
    monkeypatch.setattr(email_actions, "send_action_email", lambda db, key, *, recipient, action_context=None,
                        footer_html="", **_k: got.append((key, recipient["email"], footer_html)) or True)
    user = SimpleNamespace(id="u-1", username="carol", email="attacker@example.net")
    assert api._mint_and_send_reset(None, user, "https://vault.example.com", created_by_id=None,
                                    to="carol@example.com", note_html="<p>why</p>") is True
    assert got == [("password_reset", "carol@example.com", "<p>why</p>")]
