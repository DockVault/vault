"""The locked email that tells a vault's owner about compliance access (app/core/email_actions.py, the action
``compliance_access_notice``), offline: always on, always its built-in subject and body whatever template a row
binds it to, never bindable in Email Studio, and, as sent through the outbox, free of every vault, file and folder
name, the justification and the people named."""
import asyncio
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import admin_grants  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import email_actions as ea  # noqa: E402
from app.core import email_send  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_notices as on  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 2, 10, 0)
KEY = on.EMAIL_ACTION
TEXT = dict(purpose="litigation_hold", legal_basis="legal_obligation",
            justification="Preserve the records named in the claim against mallory.",
            owner_note="Files deleted from your vaults are kept for a legal matter.")
SENTINELS = ("Payroll 2026", "salaries-q3.xlsx", "Board minutes", "Preserve the records named", "mallory")


@pytest.fixture
def made():
    from _kept_db import kept_database
    with kept_database() as (make, engine):
        yield make, engine


@pytest.fixture
def db(made):
    session = made[0]()
    yield session
    session.close()


@pytest.fixture
def outgoing(monkeypatch):
    """Every message handed to SMTP (the sending profile resolves to a fake server)."""
    sent = []
    monkeypatch.setattr(email_send, "resolve_default_config",
                        lambda db_: {"smtp_server": "smtp.example.test", "smtp_port": 25,
                                     "from_email": "vault@example.test", "from_name": "Vault"})
    monkeypatch.setattr(email_send, "smtp_send", lambda cfg, msg: sent.append(msg))
    monkeypatch.setattr(ea, "brand_name", lambda db_: "Acme Vault")
    return sent


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    from app.core import sftp_versions
    monkeypatch.setattr(holds, "deliver", lambda notices: None)
    after_commit.handler(on._NUDGES, lambda items: None)
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: sftp_versions.VersionCheck(True, sftp_versions.SAME, ("0.34.0",)))
    yield
    after_commit.handler(on._NUDGES, on._nudge)


def _seeded(db):
    ea.seed_email_actions(db)
    ea.seed_default_templates(db)
    return db.get(m.EmailAction, KEY)


def _custom_template(db):
    t = m.EmailTemplate(name="softer", subject="Nothing to worry about",
                        body_html="<p>All is well, {{user.username}}. Nothing was opened.</p>")
    db.add(t)
    db.commit()
    return t


def _send(db, context=None):
    return ea.send_action_email(db, KEY, recipient={"email": "olga@example.test", "username": "olga"},
                                action_context=context or {"change": "Legal hold on your vaults.", "code": "C-2026-0001",
                                                           "when": "now"}, raise_errors=True)


def _text(msg):
    body = msg.get_body(("plain",))
    return str(msg["subject"]), body.get_content() if body is not None else ""


# --------------------------------------------------------------------------- the catalog and the seed

def test_the_owners_notice_is_a_locked_action():
    spec = ea.SPEC_BY_KEY[KEY]
    assert spec["category"] == ea.LOCKED and ea.LOCKED in ea.ALWAYS_ON
    assert "{{action.change}}" in spec["default_body_html"] and "{{vault.name}}" in spec["default_body_html"]


def test_the_seed_leaves_it_on_and_bound_to_nothing(db):
    action = _seeded(db)
    assert action.category == ea.LOCKED and action.enabled is True and action.template_id is None
    assert db.query(m.EmailTemplate).filter(m.EmailTemplate.default_key == KEY).count() == 0, \
        "no template is made for a wording no template can change"


def test_the_seed_undoes_a_binding_or_a_switch_written_straight_to_its_row(db):
    action = _seeded(db)
    action.template_id, action.enabled = _custom_template(db).id, False
    db.commit()
    ea.seed_email_actions(db)
    db.refresh(action)
    assert action.template_id is None and action.enabled is True


# --------------------------------------------------------------------------- what is sent

def test_a_template_bound_to_it_is_ignored(db, outgoing):
    action = _seeded(db)
    action.template_id = _custom_template(db).id
    db.commit()
    assert _send(db) is True
    subject, text = _text(outgoing[0])
    assert subject == "Access to your vaults: case C-2026-0001"
    assert "Legal hold on your vaults." in text and "All is well" not in text and "Nothing was opened" not in text
    assert "Sent by Acme Vault." in text, "the brand applies"


def test_a_row_turned_off_still_sends(db, outgoing):
    action = _seeded(db)
    action.enabled = False
    db.commit()
    assert _send(db) is True and len(outgoing) == 1


def test_a_row_whose_category_was_changed_still_sends_the_built_in_wording(db, outgoing):
    action = _seeded(db)
    action.category, action.template_id, action.enabled = ea.OPTIONAL, _custom_template(db).id, False
    db.commit()
    assert _send(db) is True
    assert _text(outgoing[0])[0] == "Access to your vaults: case C-2026-0001"


def test_the_bulk_trigger_treats_it_as_always_on(db, monkeypatch):
    from app.api import api_server
    from app.core import database
    action = _seeded(db)
    action.enabled = False
    db.commit()
    seen = []
    monkeypatch.setattr(ea, "send_action_email", lambda db_, key, **kw: seen.append((key, kw["recipient"]["email"])))

    class _Ctx:
        def __enter__(self):
            return db

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(database, "get_db_context", lambda: _Ctx())
    started = []
    monkeypatch.setattr(api_server.threading, "Thread",
                        lambda target, args, daemon: SimpleNamespace(start=lambda: started.append(target(*args))))
    api_server._fire_action_email_bulk(db, KEY, [("olga@example.test", "olga")], {"change": "x"})
    assert seen == [(KEY, "olga@example.test")] and started


# --------------------------------------------------------------------------- Email Studio

def _studio_update(db, payload):
    from app.api import email_studio_router as studio
    admin = SimpleNamespace(id=uuid.uuid4(), username="ada")
    return asyncio.run(studio.update_action(KEY, studio.ActionUpdateIn(**payload), request=None, admin=admin, db=db))


@pytest.mark.parametrize("payload", [{"template_id": None}, {"enabled": False}, {}])
def test_email_studio_cannot_change_it(db, payload):
    _seeded(db)
    with pytest.raises(HTTPException) as refused:
        _studio_update(db, payload)
    assert refused.value.status_code == 409


def test_email_studio_cannot_bind_a_template_to_it(db):
    _seeded(db)
    t = _custom_template(db)
    with pytest.raises(HTTPException) as refused:
        _studio_update(db, {"template_id": str(t.id)})
    assert refused.value.status_code == 409
    assert db.get(m.EmailAction, KEY).template_id is None


def test_email_studio_still_binds_the_other_actions(db, monkeypatch):
    from app.api import email_studio_router as studio
    _seeded(db)
    t = _custom_template(db)
    monkeypatch.setattr(studio, "_audit", lambda *a, **k: None)
    admin = SimpleNamespace(id=uuid.uuid4(), username="ada")
    out = asyncio.run(studio.update_action("share_created", studio.ActionUpdateIn(template_id=t.id), request=None,
                                           admin=admin, db=db))
    assert out["template_id"] == str(t.id)


def test_the_page_shows_it_read_only():
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = js.index("function buildActionRow(")
    body = js[start:js.index("\nfunction ", start + 10)]
    assert "const locked = a.category === 'locked';" in body
    locked_branch = body[body.index("if (locked) {"):body.index("} else {", body.index("if (locked) {"))]
    assert "built-in wording (cannot be changed)" in locked_branch and "createElement('select')" not in locked_branch
    assert "if (a.category === 'optional') {" in body, "no on/off switch for a locked email"


# --------------------------------------------------------------------------- as sent, end to end

def test_as_sent_it_names_no_vault_file_folder_justification_or_person_named(made, db, outgoing):
    ea.seed_email_actions(db)
    ada = m.User(username="ada", email="ada@example.test", password_hash="x", role=m.RoleEnum.ADMIN, is_active=True,
                 is_locked=False)
    olga = m.User(username="olga", email="olga@example.test", password_hash="x", role=m.RoleEnum.USER,
                  is_active=True, is_locked=False)
    mallory = m.User(username="mallory", email="m@example.test", password_hash="x", role=m.RoleEnum.USER,
                     is_active=True, is_locked=False)
    db.add_all([ada, olga, mallory])
    db.commit()
    admin_grants.record(db, ada.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=NOW - timedelta(days=400))
    vault = m.Vault(id=uuid.uuid4(), name="Payroll 2026", owner_id=olga.id)
    db.add(vault)
    db.commit()
    folder = m.Folder(id=uuid.uuid4(), vault_id=vault.id, name="Board minutes")
    db.add(folder)
    db.add(m.File(id=uuid.uuid4(), vault_id=vault.id, folder_id=folder.id, name="salaries-q3.xlsx",
                  original_name="salaries-q3.xlsx", size_bytes=10, storage_path="x", mime_type="text/plain"))
    db.commit()
    case = holds.place_hold_only(db, ada, [vault.id], now=NOW, **TEXT)
    db.add(m.ComplianceCasePerson(case_id=case.id, user_id=mallory.id, why="named"))
    db.commit()
    make, engine = made
    assert on.send_due(make, engine=engine, now=lambda: NOW) == [on.SENT]
    (msg,) = outgoing
    subject, text = _text(msg)
    assert subject == f"Access to your vaults: case {case.number}"
    assert "Legal hold on your vaults" in text and str(msg["to"]) == "olga@example.test"
    raw = msg.as_string()
    for sentinel in SENTINELS:
        assert sentinel not in raw, sentinel
