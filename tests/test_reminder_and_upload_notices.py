"""The two notices written to the maker of a thing without them asking: the reminder before a share or a link
expires (the sweep's _tell_about_expiry) and the word that a file arrived on an upload link (the upload's
_tell_receiver_owner), offline on a real (SQLite) database, with the mail captured.

Each names the thing by its kind only (a share of a vault, a folder or a file; a public link and its tag; a note
link; an upload link and its label) and deep-links to the page that manages it. Neither puts a vault's name, a
note's title or a file's name into the notice's title or text, nor into what the email is given: those names are
sealed at rest, and the notice's columns and the mail are in the clear. Each is given once: the notice ledger
remembers what was told, so dismissing the notification does not bring it, or its email, back. Both emails are on
by default (an administrator can turn either off in Email Studio), and their links are built from the configured
public address only, never from the request, which for an upload is the anonymous uploader's: with no address
configured the email goes out without a link. The matching live tests
(tests/test_api_expiry_reminders.py, tests/test_api_upload_links_collect.py) drive the routes on a running stack.
"""
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session as _Session

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import database, email_actions, expiry_reminders  # noqa: E402
from app.core import models as m  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime.utcnow().replace(microsecond=0)
SECRET_VAULT = "Project Falcon acquisition"
SECRET_NOTE = "Board minutes, not for circulation"
SECRET_FILE = "Board pack, third quarter.xlsx"


@pytest.fixture
def db(monkeypatch):
    """A database the helpers reach the way the web process does (get_db_context), with no live socket."""
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        @contextmanager
        def ctx():
            s = make()
            try:
                yield s
                s.commit()
            except Exception:
                s.rollback()
                raise
            finally:
                s.close()

        monkeypatch.setattr(database, "get_db_context", ctx)
        monkeypatch.setattr(api, "_fire_offloop", lambda *a, **k: None)
        session = make()
        yield session
        session.close()


@pytest.fixture(autouse=True)
def _ids_given_as_text():
    # Postgres's driver takes a UUID given as text, which is how the helpers hand over a recipient; SQLite's
    # binding does not. Coerce at flush, as the driver would.
    def coerce(session, _ctx, _instances):
        for obj in session.new:
            v = getattr(obj, "user_id", None)
            if isinstance(v, str):
                obj.user_id = uuid.UUID(v)

    sa.event.listen(_Session, "before_flush", coerce)
    yield
    sa.event.remove(_Session, "before_flush", coerce)


@pytest.fixture
def emails(monkeypatch):
    """Every email handed to send_action_email, as (key, recipient, action_context)."""
    sent = []

    def capture(db_, key, *, recipient, action_context=None, **_kw):
        sent.append((key, recipient, dict(action_context or {})))
        return True

    monkeypatch.setattr(email_actions, "send_action_email", capture)
    return sent


@pytest.fixture
def owner(db):
    u = m.User(username="olga", email="olga@example.test", password_hash="x", role=m.RoleEnum.USER,
               is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def vault(db, owner, name=SECRET_VAULT):
    v = m.Vault(id=uuid.uuid4(), name=name, owner_id=owner.id, type="standard", file_count=0, total_size_bytes=0)
    db.add(v)
    db.commit()
    return v


def share(db, owner, v, *, expires_at, target_type="folder"):
    tag = m.ShareTag(name=f"Normal {uuid.uuid4().hex[:6]}")
    db.add(tag)
    db.commit()
    s = m.Share(creator_id=owner.id, vault_id=v.id, tag_id=tag.id, target_type=target_type,
                claim_audience="anyone_internal", audience_user_ids=[], audience_department_ids=[],
                expires_at=expires_at, created_at=NOW - timedelta(days=5), view_only=False, status="active")
    db.add(s)
    db.commit()
    return s


def note_link(db, owner, *, expires_at):
    link = m.NoteLink(owner_id=owner.id, token_len=20, title_snapshot=SECRET_NOTE, body_snapshot="the minutes",
                      expires_at=expires_at, created_at=NOW - timedelta(days=5))
    db.add(link)
    db.commit()
    return link


def notices(db, kind, owner):
    db.expire_all()
    return (db.query(m.Notification).filter(m.Notification.user_id == owner.id, m.Notification.type == kind)
            .order_by(m.Notification.created_at).all())


def everything_said(rows, emails):
    """Every string a reader of the database or of the mailbox would see."""
    out = [r.title for r in rows] + [r.body or "" for r in rows]
    for _key, recipient, context in emails:
        out += [str(v) for v in context.values()] + [str(v) for v in recipient.values()]
    return out


# --------------------------------------------------------------------------- named by kind, never by a sealed name

def test_a_reminder_names_the_kind_of_thing_never_the_vault_or_the_note(db, owner, emails, monkeypatch):
    monkeypatch.setattr(email_actions, "vault_url", lambda: "https://vault.example.test")
    v = vault(db, owner)
    soon = NOW + timedelta(hours=20)
    share(db, owner, v, expires_at=soon)
    note_link(db, owner, expires_at=soon)

    items = {i["kind"]: i for i in expiry_reminders.due(db, now=NOW)}
    assert set(items) == {"share", "note_link"}
    for item in items.values():
        assert api._tell_about_expiry(item) is True

    rows = notices(db, "expiry_reminder", owner)
    assert len(rows) == 2 and len(emails) == 2
    for text in everything_said(rows, emails) + [i["title"] for i in items.values()]:
        assert SECRET_VAULT not in text, "the sealed vault name reached a notice or an email"
        assert SECRET_NOTE not in text, "the sealed note title reached a notice or an email"
    by_target = {r.target: r for r in rows}
    assert by_target["#shared/by-me"].title.startswith("Your share of a folder expires ")
    assert by_target["#notes/shared"].title.startswith("Your note link expires ")
    assert {e[0] for e in emails} == {"expiry_reminder"}
    assert sorted(e[2]["link"] for e in emails) == ["https://vault.example.test/#notes/shared",
                                                     "https://vault.example.test/#shared/by-me"]


def test_an_upload_notice_names_the_link_never_the_file(db, owner, emails):
    receiver = SimpleNamespace(id=uuid.uuid4(), label="Signed contracts")
    file = SimpleNamespace(original_name=SECRET_FILE)
    api._tell_receiver_owner(db, None, receiver, owner, None, file)

    rows = notices(db, "receiver_upload", owner)
    assert len(rows) == 1 and len(emails) == 1
    for text in everything_said(rows, emails):
        assert SECRET_FILE not in text, "the uploaded file's name reached a notice or an email"
    assert rows[0].title == "Files received on Signed contracts" and rows[0].target == "#uploadlinks/drops"
    assert rows[0].body.startswith("A file arrived on Signed contracts.")
    assert emails[0][0] == "receiver_upload_received" and emails[0][1]["email"] == "olga@example.test"
    assert "your upload link Signed contracts" in emails[0][2]["change"]


def dismiss(row, owner, db):
    """The person dismisses a notification from the bell: the real route, which deletes the row."""
    run_coroutine(api.dismiss_notification(row.id, current_user=owner, db=db))


def ledger(db, owner):
    db.expire_all()
    return db.query(m.NoticeLedger).filter(m.NoticeLedger.user_id == owner.id).all()


# --------------------------------------------------------------------------- once, even after a dismissal

def test_a_dismissed_reminder_is_not_written_or_emailed_again(db, owner, emails):
    v = vault(db, owner)
    share(db, owner, v, expires_at=NOW + timedelta(hours=20))
    [item] = expiry_reminders.due(db, now=NOW)

    assert api._tell_about_expiry(item) is True            # the first sweep: a notice and an email
    assert api._tell_about_expiry(item) is False           # the next sweep: nothing more
    rows = notices(db, "expiry_reminder", owner)
    assert len(rows) == 1 and len(emails) == 1 and len(ledger(db, owner)) == 1
    dismiss(rows[0], owner, db)
    assert notices(db, "expiry_reminder", owner) == []
    assert api._tell_about_expiry(item) is False           # ten minutes later: the dismissal stands
    assert notices(db, "expiry_reminder", owner) == [] and len(emails) == 1
    # Moved to another day: one more reminder, as before.
    item = dict(item, expires_at=item["expires_at"] + timedelta(days=1))
    assert api._tell_about_expiry(item) is True
    assert len(notices(db, "expiry_reminder", owner)) == 1 and len(emails) == 2


def test_a_dismissed_upload_notice_does_not_come_back_within_the_hour(db, owner, emails):
    receiver = SimpleNamespace(id=uuid.uuid4(), label="Signed contracts")
    api._tell_receiver_owner(db, None, receiver, owner, None, SimpleNamespace(original_name="a.pdf"))
    api._tell_receiver_owner(db, None, receiver, owner, None, SimpleNamespace(original_name="b.pdf"))
    rows = notices(db, "receiver_upload", owner)
    assert len(rows) == 1 and len(emails) == 1
    dismiss(rows[0], owner, db)
    api._tell_receiver_owner(db, None, receiver, owner, None, SimpleNamespace(original_name="c.pdf"))
    assert notices(db, "receiver_upload", owner) == [] and len(emails) == 1


def test_the_ledger_holds_no_name_and_the_sweep_forgets_it_after_thirty_days(db, owner, emails):
    v = vault(db, owner)
    share(db, owner, v, expires_at=NOW + timedelta(hours=20))
    [item] = expiry_reminders.due(db, now=NOW)
    assert api._tell_about_expiry(item) is True
    [row] = ledger(db, owner)
    assert row.dedup_key == f"{expiry_reminders.dedup_key(item)}:{owner.id}"
    assert SECRET_VAULT not in row.dedup_key and set(m.NoticeLedger.__table__.columns.keys()) ==         {"id", "user_id", "dedup_key", "created_at"}
    db.add(m.NoticeLedger(user_id=owner.id, dedup_key="old:key", created_at=NOW - timedelta(days=31)))
    db.add(m.NoticeLedger(user_id=owner.id, dedup_key="recent:key", created_at=NOW - timedelta(days=29)))
    db.commit()
    expiry_reminders.sweep_once(lambda _item: False, now=NOW)
    assert sorted(r.dedup_key for r in ledger(db, owner)) == sorted([row.dedup_key, "recent:key"])


# --------------------------------------------------------------------------- the emails: on by default, link from the configured address

def test_the_two_emails_are_on_by_default_and_every_other_optional_one_is_off(db):
    on = {a["key"] for a in email_actions.ACTION_CATALOG if a["default_enabled"]}
    optional = {a["key"] for a in email_actions.ACTION_CATALOG if a["category"] == email_actions.OPTIONAL}
    assert on & optional == {"receiver_upload_received", "expiry_reminder"}
    assert {a["key"] for a in email_actions.ACTION_CATALOG if a["category"] in email_actions.ALWAYS_ON} <= on
    # Seeded that way, and bound to their default templates, so they send as soon as mail is set up.
    assert email_actions.seed_email_actions(db) == len(email_actions.ACTION_CATALOG)
    email_actions.seed_default_templates(db)
    rows = {a.key: a for a in db.query(m.EmailAction).all()}
    for key in ("receiver_upload_received", "expiry_reminder"):
        assert rows[key].enabled is True and rows[key].template_id is not None, key
    for key in optional - on:
        assert rows[key].enabled is False, key
    # Seeding again changes no administrator's choice.
    rows["expiry_reminder"].enabled = False
    db.commit()
    assert email_actions.seed_email_actions(db) == 0
    db.expire_all()
    assert db.get(m.EmailAction, "expiry_reminder").enabled is False


def test_the_upload_email_links_only_to_the_configured_address_or_not_at_all(db, owner, emails, monkeypatch):
    receiver = SimpleNamespace(id=uuid.uuid4(), label="Signed contracts")
    uploader = SimpleNamespace(base_url="https://evil.example/", headers={"host": "evil.example"})
    monkeypatch.setattr(email_actions, "vault_url", lambda: "https://vault.example.test")
    api._tell_receiver_owner(db, uploader, receiver, owner, None, SimpleNamespace(original_name="a.pdf"))
    assert emails[-1][2]["link"] == "https://vault.example.test/#uploadlinks/drops"
    # No public address configured: no link, and never the uploader's host.
    monkeypatch.setattr(email_actions, "vault_url", lambda: "")
    other = SimpleNamespace(id=uuid.uuid4(), label="Receipts")
    api._tell_receiver_owner(db, uploader, other, owner, None, SimpleNamespace(original_name="b.pdf"))
    assert emails[-1][2]["link"] == "" and "evil.example" not in str(emails[-1][2])
    # The reminder's link follows the same rule.
    v = vault(db, owner)
    share(db, owner, v, expires_at=NOW + timedelta(hours=20))
    [item] = expiry_reminders.due(db, now=NOW)
    assert api._tell_about_expiry(item) is True
    assert emails[-1][0] == "expiry_reminder" and emails[-1][2]["link"] == ""


def test_an_email_with_no_address_goes_out_without_a_link():
    from app.core import email_sanitize
    for key, text in (("receiver_upload_received", "Open your upload links"), ("expiry_reminder", "Open Acme vault")):
        body = email_actions.DEFAULT_TEMPLATES[key]["body_html"]
        with_link = email_sanitize.token_context(brand_name="Acme vault", action={
            "link": "https://vault.example.test/#uploadlinks/drops", "change": "A file arrived.", "expires": "soon"})
        html, _ = email_sanitize.render_for_send(body, context=with_link, load_resource=lambda _r: None)
        assert 'href="https://vault.example.test/#uploadlinks/drops"' in html and text in html
        without = email_sanitize.token_context(brand_name="Acme vault", action={
            "link": "", "change": "A file arrived.", "expires": "soon"})
        html, _ = email_sanitize.render_for_send(body, context=without, load_resource=lambda _r: None)
        assert "<a " not in html and 'href=' not in html, html
        assert text in html and "A file arrived." in html
