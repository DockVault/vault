"""What is due a reminder before it expires (app/core/expiry_reminders.py), offline on a real (SQLite)
database, and the module's pure helpers.

A share, a public link, a note link or an upload link that expires within the window, still works and was
made for longer than the window is due once per thing and expiry date; one made for less is not (its maker
chose that lifetime minutes ago), nor is a link whose uses or uploads are spent. Each is named by its kind only: a vault's name, a note's title and a file's name are sealed
at rest, and a notice is written in the clear, so none of them is read here. Each item leads to the page in
the web app that manages the thing. tests/test_api_expiry_reminders.py runs the sweep through the web
container, as the loop runs it.
"""
import inspect
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import expiry_reminders  # noqa: E402
from app.core import models as m  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 3, 10, 12, 0, 0)
WINDOW = timedelta(hours=expiry_reminders.WINDOW_HOURS)
SECRET_VAULT = "Project Falcon acquisition"
SECRET_NOTE = "Board minutes, not for circulation"


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def user(db, name="olga"):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=m.RoleEnum.USER,
               is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def vault(db, owner, name=SECRET_VAULT):
    v = m.Vault(id=uuid.uuid4(), name=name, owner_id=owner.id, type="standard", file_count=0, total_size_bytes=0)
    db.add(v)
    db.commit()
    return v


def share(db, owner, v, *, expires_at, created_at=NOW - timedelta(days=5), target_type="vault"):
    tag = db.query(m.ShareTag).filter(m.ShareTag.name == "Normal").first()
    if tag is None:
        tag = m.ShareTag(name="Normal")
        db.add(tag)
        db.commit()
    s = m.Share(creator_id=owner.id, vault_id=v.id, tag_id=tag.id, target_type=target_type,
                claim_audience="anyone_internal", audience_user_ids=[], audience_department_ids=[],
                expires_at=expires_at, created_at=created_at, view_only=False, status="active")
    db.add(s)
    db.commit()
    return s


def public_link(db, owner, v, *, expires_at, created_at=NOW - timedelta(days=5), tag=None, **kw):
    link = m.PublicLink(owner_id=owner.id, vault_id=v.id, tag_id=tag.id if tag else None, target_type="file",
                        token_hash=uuid.uuid4().hex + uuid.uuid4().hex, token_len=20,
                        expires_at=expires_at, created_at=created_at, **kw)
    db.add(link)
    db.commit()
    return link


def note_link(db, owner, *, expires_at, created_at=NOW - timedelta(days=5), **kw):
    link = m.NoteLink(owner_id=owner.id, token_len=20, title_snapshot=SECRET_NOTE, body_snapshot="the minutes",
                      expires_at=expires_at, created_at=created_at, **kw)
    db.add(link)
    db.commit()
    return link


def receiver(db, owner, v, *, expires_at, created_at=NOW - timedelta(days=5), label="Signed pages", **kw):
    r = m.Receiver(owner_id=owner.id, vault_id=v.id, label=label, token_hash=uuid.uuid4().hex + uuid.uuid4().hex,
                   token_len=20, expires_at=expires_at, created_at=created_at, **kw)
    db.add(r)
    db.commit()
    return r


def test_the_module_reads_no_name_that_is_sealed_at_rest():
    """What is due is decided from the rows alone; no title holds a file's name, a vault's or a note's."""
    src = inspect.getsource(expiry_reminders.due)
    assert "original_name" not in src and "File" not in src.replace("NoteLinkTag", "")
    assert "Vault" not in src and "title_snapshot" not in src
    assert ".name" not in src.replace("NoteLinkTag.name", "")


def test_one_reminder_per_thing_and_expiry_date():
    assert expiry_reminders.dedup_key({"kind": "share", "id": "x", "expires_at": datetime(2026, 1, 2, 3)}) == \
        "expiry_reminder:share:x:2026-01-02"


def test_the_time_left_in_words():
    now = datetime(2026, 1, 1, 12)
    assert expiry_reminders.in_words(now + timedelta(minutes=30), now) == "within the hour"
    assert expiry_reminders.in_words(now + timedelta(hours=5), now) == "in about 5 hours"
    assert expiry_reminders.in_words(now + timedelta(hours=47), now) == "in about 1 day"


def test_each_kind_is_named_by_its_kind_and_leads_to_its_page(db):
    olga = user(db)
    v = vault(db, olga)
    drop = vault(db, olga, name="x7q2m")
    tag = m.NoteLinkTag(name="Confidential")
    db.add(tag)
    db.commit()
    soon = NOW + timedelta(hours=20)
    s = share(db, olga, v, expires_at=soon, target_type="folder")
    p = public_link(db, olga, v, expires_at=soon, tag=tag)
    n = note_link(db, olga, expires_at=soon)
    r = receiver(db, olga, drop, expires_at=soon)

    items = {i["kind"]: i for i in expiry_reminders.due(db, now=NOW)}
    assert set(items) == {"share", "public_link", "note_link", "receiver"}
    assert items["share"]["title"] == "Your share of a folder" and items["share"]["target"] == "#shared/by-me"
    assert items["public_link"]["title"] == "Your public link (Confidential link)"
    assert items["public_link"]["target"] == f"#vault/{v.id}/public-links"
    assert items["note_link"]["title"] == "Your note link" and items["note_link"]["target"] == "#notes/shared"
    assert items["receiver"]["title"] == "Your upload link Signed pages"
    assert items["receiver"]["target"] == "#uploadlinks/drops"
    for item in items.values():
        assert SECRET_VAULT not in item["title"] and SECRET_NOTE not in item["title"]
        assert item["owner_id"] == str(olga.id) and item["expires_at"] == soon
    assert {items["share"]["id"], items["public_link"]["id"], items["note_link"]["id"], items["receiver"]["id"]} == \
        {str(s.id), str(p.id), str(n.id), str(r.id)}
    # A share of a whole vault and a public link under no tag are named by their kind alone.
    share(db, olga, v, expires_at=soon)
    public_link(db, olga, v, expires_at=soon)
    titles = sorted(i["title"] for i in expiry_reminders.due(db, now=NOW))
    assert "Your share of a vault" in titles and "Your public link" in titles


# --------------------------------------------------------------------------- made for longer than the window

def test_a_thing_made_for_less_than_the_window_is_not_reminded(db):
    olga = user(db)
    v = vault(db, olga)
    soon = NOW + timedelta(hours=20)
    short = share(db, olga, v, expires_at=soon, created_at=NOW - timedelta(minutes=10))     # a one-day share
    long = share(db, olga, v, expires_at=soon, created_at=NOW - timedelta(days=5))          # in its last two days
    edge = share(db, olga, v, expires_at=soon, created_at=soon - WINDOW)                     # made a window before
    note_link(db, olga, expires_at=soon, created_at=NOW - timedelta(hours=1))
    public_link(db, olga, v, expires_at=soon, created_at=soon - WINDOW + timedelta(seconds=1))
    receiver(db, olga, vault(db, olga, name="k2p9x"), expires_at=soon, created_at=NOW - timedelta(hours=23))

    due = {(i["kind"], i["id"]) for i in expiry_reminders.due(db, now=NOW)}
    assert due == {("share", str(long.id)), ("share", str(edge.id))}, due
    assert ("share", str(short.id)) not in due


def test_a_spent_link_is_not_reminded(db):
    olga = user(db)
    v = vault(db, olga)
    soon = NOW + timedelta(hours=20)
    spent_public = public_link(db, olga, v, expires_at=soon, max_uses=3, use_count=3)
    open_public = public_link(db, olga, v, expires_at=soon, max_uses=3, use_count=2)
    unlimited_public = public_link(db, olga, v, expires_at=soon, max_uses=None, use_count=99)
    spent_note = note_link(db, olga, expires_at=soon, max_uses=1, use_count=1)
    open_note = note_link(db, olga, expires_at=soon, max_uses=2, use_count=1)
    spent_drop = receiver(db, olga, vault(db, olga, name="a1"), expires_at=soon, max_uploads=5, upload_count=5)
    open_drop = receiver(db, olga, vault(db, olga, name="a2"), expires_at=soon, max_uploads=5, upload_count=4)

    due = {i["id"] for i in expiry_reminders.due(db, now=NOW)}
    assert due == {str(x.id) for x in (open_public, unlimited_public, open_note, open_drop)}, due
    assert not due & {str(x.id) for x in (spent_public, spent_note, spent_drop)}
