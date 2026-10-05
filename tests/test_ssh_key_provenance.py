"""Who added an SSH key, and telling its owner when the administrator who added it leaves, offline on a
real database.

A key an administrator adds to someone's account signs in to SFTP as that person. The key now keeps the
name of whoever added it (kept when that account is deleted), the key lists show it, and when an
administrator who added keys to other people's accounts is demoted, deactivated, locked or deleted, each
such account's owner is told (in the app and by email, with a link to where a key is removed), every
other administrator is told in the app, and one audit row is written per account. The keys are never
switched off. test_ssh_key_provenance_live.py drives the routes on a running stack.
"""
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import email_actions as ea  # noqa: E402
from app.core.models import (AccountInvitation, AdminGrant, AuditLog, CredentialChange,  # noqa: E402
                             PasswordResetToken, RoleEnum, User, UserSSHKey)

pytestmark = pytest.mark.unit

APP = Path(__file__).resolve().parent.parent / "app"


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'keys.db'}")
        for model in (User, UserSSHKey, AdminGrant, CredentialChange, AuditLog, AccountInvitation,
                      PasswordResetToken):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role=RoleEnum.ADMIN, **kw):
    u = User(username=name, email=kw.pop("email", f"{name}@example.com"), password_hash="x", role=role,
             is_active=kw.pop("is_active", True), is_locked=kw.pop("is_locked", False), **kw)
    db.add(u)
    db.commit()
    return u


def _add_key(db, owner, *, by, name, host=False):
    """Add a key the way every route does (_apply_credential_change), as ``by`` or the host operator."""
    payload = {"name": name, "key_type": "ssh-ed25519", "public_key": f"ssh-ed25519 AAAA{name}",
               "fingerprint": f"SHA256:{name}"}
    out = api._apply_credential_change(
        db, cc.SSH_KEY, owner, payload, actor_id=None if host else by.id,
        actor_name=cc.HOST_OPERATOR if host else by.username, for_someone_else=host or by.id != owner.id)
    db.commit()
    return out["ssh_key"]


@pytest.fixture
def told(monkeypatch):
    """What was told after the commit: notices (recipients, type, title, body, target) and emails (key,
    address, username, context)."""
    out = SimpleNamespace(notices=[], emails=[])
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title, body=None, target=None, **_k:
                        out.notices.append((sorted(ids), ntype, title, body, target)))
    monkeypatch.setattr(api, "_fire_action_email", lambda _db, key, *, email, username=None, action_context=None:
                        out.emails.append((key, email, username, dict(action_context or {}))))
    monkeypatch.setattr(api, "_notify_account_change", lambda *a, **k: None)
    monkeypatch.setattr(ea, "vault_url", lambda: "")   # the link's base is then the request's own
    return out


# --------------------------------------------------------------------------- who added it

def test_a_key_keeps_the_name_of_whoever_added_it(db):
    ada, bob = _user(db, "ada"), _user(db, "bob", role=RoleEnum.USER)
    by_admin = _add_key(db, bob, by=ada, name="desk")
    own = _add_key(db, bob, by=bob, name="laptop")
    by_host = _add_key(db, bob, by=None, name="backup", host=True)
    assert (by_admin.created_by, by_admin.created_by_name) == (ada.id, "ada")
    assert (own.created_by, own.created_by_name) == (bob.id, "bob")
    assert (by_host.created_by, by_host.created_by_name) == (None, cc.HOST_OPERATOR)


def test_the_list_says_who_added_each_key_and_whether_it_was_someone_else(db):
    ada, bob = _user(db, "ada"), _user(db, "bob", role=RoleEnum.USER)
    by_admin = _add_key(db, bob, by=ada, name="desk")
    own = _add_key(db, bob, by=bob, name="laptop")
    by_host = _add_key(db, bob, by=None, name="backup", host=True)
    # The maker's account deleted: its id is gone (SET NULL), its name is kept.
    gone = _add_key(db, bob, by=ada, name="old")
    gone.created_by = None
    # A key from before the name was kept, whose maker nothing names: not known.
    unknown = UserSSHKey(user_id=bob.id, name="ancient", public_key="k", fingerprint="SHA256:ancient")
    db.add(unknown)
    db.commit()
    shown = {k.name: (k.added_by, k.added_by_other)
             for k in (api._ssh_key_response(key, bob) for key in (by_admin, own, by_host, gone, unknown))}
    assert shown == {"desk": ("ada", True), "laptop": ("bob", False), "backup": (cc.HOST_OPERATOR, True),
                     "old": ("ada", True), "ancient": (None, None)}


def test_the_list_route_shows_it(db):
    ada, bob = _user(db, "ada"), _user(db, "bob", role=RoleEnum.USER)
    _add_key(db, bob, by=ada, name="desk")
    keys = run_coroutine(api.list_ssh_keys(user_id=bob.id, current_user=bob, db=db))
    assert [(k.name, k.added_by, k.added_by_other) for k in keys] == [("desk", "ada", True)]


# --------------------------------------------------------------------------- an administrator leaves

@pytest.mark.parametrize("because", ["demoted", "deactivated", "locked", "deleted"])
def test_the_keys_an_administrator_added_are_reported_when_they_leave(db, because):
    boss, ada = _user(db, "boss"), _user(db, "ada")
    bob, carol = _user(db, "bob", role=RoleEnum.USER), _user(db, "carol", role=RoleEnum.USER)
    _add_key(db, bob, by=ada, name="desk")
    _add_key(db, bob, by=ada, name="build")
    _add_key(db, carol, by=ada, name="phone")
    _add_key(db, ada, by=ada, name="hers")          # her own key: nobody else's account
    _add_key(db, carol, by=boss, name="boss-made")  # another administrator's key
    _add_key(db, carol, by=carol, name="own")       # carol's own key
    lost = api._account_lost_standing(db, ada, actor=boss, because=because)
    db.commit()
    report = lost.keys
    assert (report["maker"], report["because"]) == ("ada", because)
    assert [(o["username"], o["email"], o["keys"]) for o in report["owners"]] == [
        ("bob", "bob@example.com", [("desk", "SHA256:desk"), ("build", "SHA256:build")]),
        ("carol", "carol@example.com", [("phone", "SHA256:phone")])]
    rows = db.query(AuditLog).filter(AuditLog.action == "ssh_keys_adder_left").order_by(AuditLog.resource_id).all()
    assert sorted((r.resource_id, r.user_id, r.status) for r in rows) == sorted(
        [(str(bob.id), boss.id, "success"), (str(carol.id), boss.id, "success")])
    by_account = {r.details["target_username"]: r.details for r in rows}
    assert by_account["bob"] == {"target_username": "bob", "added_by": "ada", "added_by_left_because": because,
                                 "keys": [{"name": "desk", "fingerprint": "SHA256:desk"},
                                          {"name": "build", "fingerprint": "SHA256:build"}]}
    # Never switched off: every key is still there.
    assert db.query(UserSSHKey).count() == 6


@pytest.mark.parametrize("state", [{"is_active": False}, {"is_locked": True}, {"role": RoleEnum.USER}])
def test_an_account_that_could_not_act_already_is_not_reported_again(db, state):
    boss, ada = _user(db, "boss"), _user(db, "ada")
    bob = _user(db, "bob", role=RoleEnum.USER)
    _add_key(db, bob, by=ada, name="desk")
    for field, value in state.items():
        setattr(ada, field, value)
    db.commit()
    lost = api._account_lost_standing(db, ada, actor=boss, because="deleted")
    assert lost.keys is None
    assert db.query(AuditLog).filter(AuditLog.action == "ssh_keys_adder_left").count() == 0


def test_an_administrator_who_added_no_key_for_anyone_reports_nothing(db):
    boss, ada = _user(db, "boss"), _user(db, "ada")
    _add_key(db, ada, by=ada, name="hers")
    assert api._account_lost_standing(db, ada, actor=boss, because="demoted").keys is None
    assert db.query(AuditLog).count() == 0


def test_the_owners_and_the_other_administrators_are_told(db, told):
    boss, ada = _user(db, "boss"), _user(db, "ada")
    _user(db, "idle", is_active=False)                      # a deactivated administrator: not told
    bob, carol = _user(db, "bob", role=RoleEnum.USER), _user(db, "carol", role=RoleEnum.USER)
    _add_key(db, bob, by=ada, name="desk")
    _add_key(db, bob, by=ada, name="build")
    _add_key(db, carol, by=ada, name="phone")
    lost = api._account_lost_standing(db, ada, actor=boss, because="locked")
    db.commit()
    api._announce_lost_standing(db, lost, SimpleNamespace(base_url="https://vault.example.com/"))
    to_bob, to_carol, to_admins = told.notices
    assert to_bob[:3] == ([str(bob.id)], "ssh_keys_adder_left", "Check the SSH keys on your account")
    assert to_bob[4] == "#profile"
    assert ('The administrator ada added the SSH keys "desk" (SHA256:desk) and "build" (SHA256:build) to your '
            "account, and ada was locked by an administrator. They still sign in to SFTP as you.") in to_bob[3]
    assert "remove them in Your account, under SSH keys" in to_bob[3]
    assert ('added the SSH key "phone" (SHA256:phone) to your account' in to_carol[3]
            and "It still signs in to SFTP as you." in to_carol[3] and "remove it in Your account" in to_carol[3])
    # Every other active administrator: boss (who locked her) included, ada and the deactivated one not.
    assert to_admins[:3] == ([str(boss.id)], "ssh_keys_adder_left", "SSH keys an administrator added")
    assert to_admins[4] == "#users"
    assert "ada was locked by an administrator. ada had added SSH keys to the accounts of bob and carol." in to_admins[3]
    (mail_bob, mail_carol) = told.emails
    assert mail_bob[:3] == ("ssh_keys_adder_left", "bob@example.com", "bob")
    assert mail_bob[3]["link"] == "https://vault.example.com/#profile"
    assert mail_bob[3]["change"] in to_bob[3]
    assert mail_carol[:3] == ("ssh_keys_adder_left", "carol@example.com", "carol")


def test_nothing_is_told_when_nothing_was_done(db, told):
    api._announce_lost_standing(db, [])
    boss, ada = _user(db, "boss"), _user(db, "ada")
    api._announce_lost_standing(db, api._account_lost_standing(db, ada, actor=boss, because="demoted"))
    assert told.notices == [] and told.emails == []


def test_the_email_to_the_owner_is_one_that_cannot_be_switched_off_and_carries_the_link():
    spec = ea.SPEC_BY_KEY["ssh_keys_adder_left"]
    assert spec["category"] == ea.SYSTEM
    for token in ("action.change", "action.link"):
        assert token in ea.DEFAULT_TEMPLATES["ssh_keys_adder_left"]["body_html"]
    # A template that drops the link falls back to the built-in body.
    assert ea._fallback_body_if_missing_required_token(ea.SYSTEM, "<p>{{action.change}}</p>", spec) == \
        spec["default_body_html"]


def test_the_boot_names_the_makers_of_older_keys():
    source = (APP / "api" / "api_server.py").read_text(encoding="utf-8")
    body = source[source.index("def _run_lightweight_migrations():"):]
    body = body[:body.index("with get_db_context() as db:")]
    column = "ALTER TABLE user_ssh_keys ADD COLUMN IF NOT EXISTS created_by_name VARCHAR(255)"
    assert body.count(column) == 1
    # Filled after the column is added, from the account, then from the audit log.
    assert body.index(column) < body.index("SSH_KEY_MAKER_FROM_ACCOUNT,") < body.index("SSH_KEY_MAKER_FROM_AUDIT,")
    assert "k.created_by_name IS NULL" in api.SSH_KEY_MAKER_FROM_ACCOUNT
    assert "k.created_by = u.id" in api.SSH_KEY_MAKER_FROM_ACCOUNT
    audit = api.SSH_KEY_MAKER_FROM_AUDIT
    for part in ("k.created_by_name IS NULL AND k.created_by IS NULL", "a.action = 'ssh_key_add'",
                 "a.resource_id = CAST(k.user_id AS TEXT)", "a.details ->> 'fingerprint' = k.fingerprint",
                 "ORDER BY a.timestamp DESC LIMIT 1"):
        assert part in audit, part


def test_the_add_route_answers_with_who_added_it(db):
    import base64
    import os
    bob = _user(db, "bob", role=RoleEnum.USER)
    line = "ssh-ed25519 " + base64.b64encode(os.urandom(51)).decode()
    key = run_coroutine(api.add_ssh_key(user_id=bob.id, body=api.SSHKeyCreate(name="laptop", public_key=line),
                                        request=SimpleNamespace(headers={}, client=None), current_user=bob, db=db))
    assert (key.name, key.added_by, key.added_by_other) == ("laptop", "bob", False)
