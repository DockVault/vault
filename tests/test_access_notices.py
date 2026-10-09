"""Telling a vault's owner when someone else gives a person access to one of their vaults (app/core/access_notices.py),
offline, on a real (SQLite) database.

What a person holds is read as PermissionService reads it (one parity table); a change tells the owner, in the
change's own session, when it gives someone a permission they did not hold: a grant to them, to their department,
adding them to a department (with its vaults and the shares addressed to it), or removing their own member row
when their departments hold more. In the app always; by email (an outbox row, kind access_granted) only when the
one who made the change could not open the vault; never for the owner's own change; one notice per owner. The
notice names the person, their account's age, its maker and whether its password was set by someone else, and
never a vault's name. The four routes ask before they write and tell before they commit (static pins);
test_access_notices_live.py drives them on a running stack.
"""
import re
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import access_notices as an  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import email_actions  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_access  # noqa: E402
from app.core import owner_notices as on  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"
SECRET_NAME = "Mergers and acquisitions 2027"
NOW = an.utcnow()


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    after_commit.handler(on._NUDGES, lambda items: None)
    after_commit.handler(on._WAKE, lambda items: None)
    monkeypatch.setattr(on, "contact", lambda db_: None)
    yield
    after_commit.handler(on._NUDGES, on._nudge)
    after_commit.handler(on._WAKE, lambda _items: on.wake())


def user(db, name, role=m.RoleEnum.USER, **kw):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False, **kw)
    db.add(u)
    db.commit()
    return u


def vault(db, owner, kind="standard"):
    v = m.Vault(id=uuid.uuid4(), name=SECRET_NAME, owner_id=owner.id, type=kind, file_count=0, total_size_bytes=0)
    db.add(v)
    db.commit()
    return v


def member(db, v, u, level):
    perms = an.LEVELS.index(level)
    db.execute(m.vault_members.insert().values(
        vault_id=v.id, user_id=u.id, read_permission=perms >= 0, write_permission=perms >= 1,
        delete_permission=perms >= 2, manage_permission=perms >= 3))
    db.commit()


def department(db, name, *people):
    g = m.Group(id=uuid.uuid4(), name=name)
    db.add(g)
    db.commit()
    for p in people:
        join(db, g, p)
    return g


def join(db, g, u):
    db.execute(m.user_groups.insert().values(user_id=u.id, group_id=g.id, group_role="member"))


def give(db, v, g, permission="read"):
    db.execute(m.vault_group_access.insert().values(vault_id=v.id, group_id=g.id, permission=permission))


@pytest.fixture
def cast(db):
    ada = user(db, "ada", m.RoleEnum.ADMIN)
    olga = user(db, "olga")
    xavier = user(db, "xavier", created_by=ada.id, password_set_by=ada.id,
                  password_set_by_other_at=NOW - timedelta(days=1), created_at=NOW - timedelta(days=2))
    yuri = user(db, "yuri", created_at=NOW - timedelta(days=400))
    return SimpleNamespace(ada=ada, olga=olga, xavier=xavier, yuri=yuri, v1=vault(db, olga), v2=vault(db, olga))


def notices(db, owner=None):
    q = db.query(m.Notification).filter(m.Notification.type == an.NOTICE_TYPE)
    if owner is not None:
        q = q.filter(m.Notification.user_id == owner.id)
    return q.all()


def outbox(db):
    return db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.kind == an.KIND).all()


def written(db):
    return [r for r in db.query(m.AuditLog).filter(m.AuditLog.action == "owner_notice_written").all()
            if (r.details or {}).get("kind") == an.KIND]


def grant(db, granter, v, who, level):
    """What POST /vaults/{id}/permissions does, around its write: watch, write, tell."""
    reach = an.Reach(db, granter)
    reach.watch(v, [who.id], via=an.GRANT)
    db.execute(m.vault_members.delete().where((m.vault_members.c.vault_id == v.id)
                                              & (m.vault_members.c.user_id == who.id)))
    rank = an.LEVELS.index(level)
    db.execute(m.vault_members.insert().values(vault_id=v.id, user_id=who.id, read_permission=True,
                                               write_permission=rank >= 1, delete_permission=rank >= 2,
                                               manage_permission=rank >= 3))
    return reach.tell(now=NOW)


# --------------------------------------------------------------------------- what a person holds

def test_what_a_person_holds_is_what_the_permission_service_resolves(db, cast):
    """One table, both readers: owner; member rows at each level; a member row overriding a department's write;
    departments read and write (the higher wins); a zero-knowledge vault never through a department; nothing."""
    from app.core.authorization import PermissionService
    zk = vault(db, cast.olga, kind="zero_knowledge")
    people = {n: user(db, n) for n in ("r", "w", "d", "mg", "row_over", "dept_r", "dept_w", "both", "none", "zk_row")}
    member(db, cast.v1, people["r"], "read")
    member(db, cast.v1, people["w"], "write")
    member(db, cast.v1, people["d"], "delete")
    member(db, cast.v1, people["mg"], "manage")
    member(db, cast.v1, people["row_over"], "read")
    member(db, zk, people["zk_row"], "write")
    reads = department(db, "Readers", people["dept_r"], people["both"], people["zk_row"])
    writes = department(db, "Writers", people["dept_w"], people["both"], people["row_over"])
    give(db, cast.v1, reads, "read")
    give(db, cast.v1, writes, "write")
    give(db, zk, writes, "write")
    db.commit()
    everyone = [cast.olga] + list(people.values())
    service = PermissionService(db)
    for v in (cast.v1, zk, cast.v2):
        mine = an.held_many(db, v, [p.id for p in everyone])
        for p in everyone:
            theirs = service.get_vault_permissions(p, v.id) or an.NONE
            assert mine[str(p.id)] == {k: bool(theirs.get(k)) for k in an.LEVELS}, (v.type, p.username)
    assert an.held_many(db, cast.v1, [people["row_over"].id])[str(people["row_over"].id)]["write"] is False
    assert an.held_many(db, zk, [people["dept_w"].id])[str(people["dept_w"].id)] == an.NONE


def test_many_people_are_read_in_chunks_with_the_same_answer(db, cast, monkeypatch):
    monkeypatch.setattr(an, "_CHUNK", 2)
    people = [user(db, f"p{i}") for i in range(5)]
    member(db, cast.v1, people[0], "write")
    give(db, cast.v1, department(db, "Big", *people[3:]), "read")
    db.commit()
    held = an.held_many(db, cast.v1, [p.id for p in people])
    assert [an.level_of(held[str(p.id)]) for p in people] == ["write", None, None, "read", "read"]


# --------------------------------------------------------------------------- a grant to a person

def test_an_administrator_who_is_not_a_member_tells_the_owner_in_the_app_and_by_email_in_the_grants_session(db, cast):
    assert grant(db, cast.ada, cast.v1, cast.xavier, "read") == 1
    [n] = notices(db, cast.olga)
    [row] = outbox(db)
    [audit] = written(db)
    assert n.target == f"#vault/{cast.v1.id}" and n.title == "Someone was given access to your vault"
    assert row.user_id == cast.olga.id and row.case_id is None and row.status == on.PENDING
    assert on.open_destination(row, on.ADDRESS) == "olga@example.test"
    assert audit.details["email_status"] == on.CASE_QUEUED and audit.details["count"] == 1
    assert audit.details["vaults"] == 1 and audit.resource_id == str(cast.olga.id)
    # Nothing is committed yet: the change's own rollback takes the notice with it.
    db.rollback()
    assert not notices(db) and not outbox(db) and not written(db)


def test_the_notice_names_the_person_their_accounts_age_maker_and_who_set_its_password(db, cast):
    grant(db, cast.ada, cast.v1, cast.xavier, "write")
    [n] = notices(db, cast.olga)
    assert "ada gave xavier read and write access to one of your vaults." in n.body
    assert "xavier's account was created on" in n.body and "(2 days ago) by ada" in n.body
    assert "its password was set by ada on" in n.body and "not by them" in n.body
    assert "If you did not expect this, open the vault" in n.body


def test_an_account_with_its_own_password_and_no_recorded_maker_says_so(db, cast):
    grant(db, cast.ada, cast.v1, cast.yuri, "read")
    [n] = notices(db, cast.olga)
    assert "(400 days ago); who created it is not recorded; its password is their own." in n.body


def test_the_owners_own_grant_tells_nobody(db, cast):
    assert grant(db, cast.olga, cast.v1, cast.xavier, "manage") == 0
    assert not notices(db) and not outbox(db) and not written(db)


def test_a_manager_of_the_vault_tells_the_owner_in_the_app_only(db, cast):
    manager = user(db, "mona")
    member(db, cast.v1, manager, "manage")
    assert grant(db, manager, cast.v1, cast.xavier, "read") == 1
    [n] = notices(db, cast.olga)
    assert "mona gave xavier read access" in n.body
    assert not outbox(db)
    [audit] = written(db)
    assert audit.details["email_status"] == "in_app_only" and audit.details["copy_to_previous"] is False


def test_a_member_through_a_department_counts_as_a_member(db, cast):
    colleague = user(db, "cora")
    give(db, cast.v1, department(db, "Finance", colleague), "read")
    db.commit()
    grant(db, colleague, cast.v1, cast.xavier, "read")
    assert len(notices(db, cast.olga)) == 1 and not outbox(db)


def test_restating_or_lowering_access_tells_nobody_and_widening_says_widened(db, cast):
    member(db, cast.v1, cast.xavier, "write")
    assert grant(db, cast.ada, cast.v1, cast.xavier, "write") == 0
    assert grant(db, cast.ada, cast.v1, cast.xavier, "read") == 0
    assert not notices(db)
    assert grant(db, cast.ada, cast.v1, cast.xavier, "manage") == 1
    [n] = notices(db, cast.olga)
    assert "ada widened xavier's access to one of your vaults to full (manage" in n.body


def test_a_grant_to_the_owner_of_the_vault_is_not_watched(db, cast):
    reach = an.Reach(db, cast.ada)
    reach.watch(cast.v1, [cast.olga.id], via=an.GRANT)
    assert reach.vaults == [] and reach.tell(now=NOW) == 0


def test_an_unknown_way_in_is_refused():
    with pytest.raises(ValueError):
        an.Reach(None, SimpleNamespace(id=uuid.uuid4())).watch(SimpleNamespace(owner_id=uuid.uuid4(), id=uuid.uuid4()),
                                                                [uuid.uuid4()], via="sideways")


def test_a_notice_that_cannot_be_written_fails_the_change(db, cast, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("the notifications table is full")
    monkeypatch.setattr(on, "notify_in_transaction", broken)
    with pytest.raises(RuntimeError):
        grant(db, cast.ada, cast.v1, cast.xavier, "read")


# --------------------------------------------------------------------------- departments

def test_a_grant_to_a_department_names_the_members_it_gives_access_and_no_one_else(db, cast):
    already = user(db, "ann")
    member(db, cast.v1, already, "read")      # a member row overrides the department: she gains nothing
    finance = department(db, "Finance", cast.xavier, cast.yuri, already, cast.olga)
    db.commit()
    reach = an.Reach(db, cast.ada)
    reach.watch(cast.v1, [cast.xavier.id, cast.yuri.id, already.id, cast.olga.id], via=an.DEPARTMENT,
                department=finance.name)
    give(db, cast.v1, finance, "write")
    assert reach.tell(now=NOW) == 1
    [n] = notices(db, cast.olga)
    assert n.title == "2 people were given access to your vault"
    assert "ada gave the department “Finance”, which xavier belongs to, read and write access" in n.body
    assert "which yuri belongs to" in n.body and "ann" not in n.body
    [row] = outbox(db)
    assert [p["username"] for p in row.details["people"]] == ["xavier", "yuri"]


def test_joining_a_department_tells_each_owner_once_for_all_their_vaults(db, cast):
    otto = user(db, "otto")
    v3 = vault(db, otto)
    sales = department(db, "Sales")
    for v in (cast.v1, cast.v2, v3):
        give(db, v, sales, "read")
    db.commit()
    reach = an.Reach(db, cast.ada)
    for v in (cast.v1, cast.v2, v3):
        reach.watch(v, [cast.xavier.id], via=an.JOINED, department=sales.name)
    join(db, sales, cast.xavier)
    assert reach.tell(now=NOW) == 2
    [n] = notices(db, cast.olga)
    assert n.title == "Someone was given access to 2 of your vaults" and n.target is None
    assert "ada added xavier to the department “Sales”, which has read access to 2 of your vaults." in n.body
    [o] = notices(db, otto)
    assert o.target == f"#vault/{v3.id}" and "to one of your vaults" in o.body
    assert sorted(str(r.user_id) for r in outbox(db)) == sorted([str(cast.olga.id), str(otto.id)])
    olga_row = next(r for r in outbox(db) if r.user_id == cast.olga.id)
    assert sorted(olga_row.details["vault_ids"]) == sorted([str(cast.v1.id), str(cast.v2.id)])


def _share(v, *, departments, status="active", expires=NOW + timedelta(days=3), audience="departments"):
    return SimpleNamespace(id=uuid.uuid4(), vault_id=v.id, status=status, expires_at=expires,
                           claim_audience=audience, audience_user_ids=[], audience_department_ids=departments)


def test_joining_a_department_a_share_is_addressed_to_tells_the_owner_of_the_shared_item(db, cast):
    legal = department(db, "Legal")
    reader = user(db, "rita")
    member(db, cast.v1, reader, "read")       # she reads both vaults already: the shares give her nothing
    member(db, cast.v2, reader, "read")
    db.commit()
    shares = [_share(cast.v1, departments=[str(legal.id)]), _share(cast.v1, departments=[str(legal.id)]),
              _share(cast.v2, departments=[str(legal.id)]),
              _share(cast.v1, departments=[str(legal.id)], status="revoked"),
              _share(cast.v1, departments=[str(legal.id)], expires=NOW - timedelta(minutes=1)),
              _share(cast.v1, departments=[], audience="anyone_internal")]
    reach = an.Reach(db, cast.ada)
    for s in shares:
        reach.watch_share(s, cast.v1 if s.vault_id == cast.v1.id else cast.v2, [cast.xavier.id, reader.id],
                          department=legal.name)
    join(db, legal, cast.xavier)
    join(db, legal, reader)
    assert reach.tell(now=NOW) == 1
    [n] = notices(db, cast.olga)
    assert "ada added xavier to the department “Legal”, that 3 shares of items in 2 of your vaults are" in n.body
    assert "xavier can now claim them." in n.body and "rita" not in n.body


def test_a_share_of_a_zero_knowledge_vault_is_never_watched(db, cast):
    zk = vault(db, cast.olga, kind="zero_knowledge")
    reach = an.Reach(db, cast.ada)
    reach.watch_share(_share(zk, departments=["x"]), zk, [cast.xavier.id])
    assert reach.shares == []


def test_removing_a_member_row_the_departments_exceed_tells_the_owner(db, cast):
    member(db, cast.v1, cast.xavier, "read")
    give(db, cast.v1, department(db, "Writers", cast.xavier, cast.yuri), "write")
    member(db, cast.v1, cast.yuri, "delete")
    db.commit()
    reach = an.Reach(db, cast.ada)
    reach.watch(cast.v1, [cast.xavier.id], via=an.ROW_REMOVED)
    reach.watch(cast.v1, [cast.yuri.id], via=an.ROW_REMOVED)
    db.execute(m.vault_members.delete().where(m.vault_members.c.vault_id == cast.v1.id))
    assert reach.tell(now=NOW) == 1
    [n] = notices(db, cast.olga)
    assert "ada removed xavier's own access row on one of your vaults, so xavier's departments now give xavier "\
           "read and write access there." in n.body
    assert "yuri" not in n.body    # delete -> write is a narrowing


def test_more_people_than_a_notice_describes_are_counted(db, cast, monkeypatch):
    monkeypatch.setattr(an, "PEOPLE_SHOWN", 2)
    people = [user(db, f"m{i}") for i in range(5)]
    crowd = department(db, "Crowd", *people)
    db.commit()
    reach = an.Reach(db, cast.ada)
    reach.watch(cast.v1, [p.id for p in people], via=an.DEPARTMENT, department=crowd.name)
    give(db, cast.v1, crowd)
    reach.tell(now=NOW)
    [n] = notices(db, cast.olga)
    assert n.title == "5 people were given access to your vault" and "And 3 more people." in n.body
    [audit] = written(db)
    assert audit.details["count"] == 5


# --------------------------------------------------------------------------- never a vault's name

def test_no_notice_record_or_email_holds_a_vaults_name(db, cast):
    sales = department(db, "Sales")
    give(db, cast.v1, sales)
    db.commit()
    reach = an.Reach(db, cast.ada)
    reach.watch(cast.v1, [cast.xavier.id], via=an.JOINED, department=sales.name)
    join(db, sales, cast.xavier)
    reach.tell(now=NOW)
    grant(db, cast.ada, cast.v2, cast.yuri, "manage")
    db.commit()
    blobs = [n.title + " " + (n.body or "") + " " + str(n.target) for n in notices(db)]
    blobs += [str(r.details) for r in outbox(db)] + [str(r.details) for r in written(db)]
    blobs += [str(on.email_context(db, r, None)) for r in outbox(db)]
    assert len(blobs) == 2 + 2 + 2 + 2
    for blob in blobs:
        assert SECRET_NAME not in blob, blob


# --------------------------------------------------------------------------- the email

def test_the_email_has_its_own_locked_action_and_the_words_as_of_the_grant(db, cast, monkeypatch):
    spec = email_actions.SPEC_BY_KEY[an.EMAIL_ACTION]
    assert spec["category"] == email_actions.LOCKED
    assert "vault.name" not in spec["default_subject"]
    assert on.email_action(an.KIND) == an.EMAIL_ACTION and on.email_action(on.ACTIVATION) == on.EMAIL_ACTION
    grant(db, cast.ada, cast.v1, cast.xavier, "read")
    db.commit()
    [row] = outbox(db)
    sent = []
    monkeypatch.setattr(email_actions, "send_action_email",
                        lambda db_, key, recipient, action_context, raise_errors: sent.append(
                            (key, recipient, action_context)) or True)
    on.send_email(db, row, None, "olga@example.test", "olga")
    [(key, recipient, context)] = sent
    assert key == an.EMAIL_ACTION and recipient["email"] == "olga@example.test"
    assert context["change"].startswith("Someone was given access to your vault. ada gave xavier read access")
    # The account's age is as of the notice, not of the send: a row written a day earlier says one day.
    row.created_at = NOW - timedelta(days=1)
    assert "(1 day ago)" in on.email_context(db, row, None)["change"]


def test_the_sender_sends_a_case_less_access_notice_and_records_it(db, cast):
    grant(db, cast.ada, cast.v1, cast.xavier, "read")
    db.commit()
    [row] = outbox(db)
    assert on._attempt(db, row, NOW, lambda *a: None) == on.SENT
    db.commit()
    sent = db.query(m.AuditLog).filter(m.AuditLog.action == "owner_notice_email_sent").all()
    assert [r.details["kind"] for r in sent] == [an.KIND]


def test_the_compliance_banner_neither_counts_nor_marks_access_notices(db, cast):
    grant(db, cast.ada, cast.v1, cast.xavier, "read")
    db.commit()
    assert owner_access.unseen(db, cast.olga) == []
    assert owner_access.mark_seen(db, cast.olga) == 0
    [row] = outbox(db)
    assert row.seen_at is None


# --------------------------------------------------------------------------- the routes

def _route(name: str) -> str:
    source = API.read_text(encoding="utf-8")
    start = source.index(f"def {name}(")
    end = source.index("\n@app.", start)
    return source[start:end]


@pytest.mark.parametrize("name,via,write", [
    ("grant_vault_permission", "GRANT", "db.execute(_ins.on_conflict_do_update("),
    ("grant_vault_group_access", "DEPARTMENT", "insert(vault_group_access)"),
    ("add_group_members", "JOINED", "user_groups.insert()"),
    ("revoke_vault_permission", "ROW_REMOVED", "sql_delete(vault_members)"),
])
def test_each_route_watches_before_it_writes_and_tells_before_it_commits(name, via, write):
    body = _route(name)
    watch = body.index(f"via=access_notices.{via}")
    assert body.count("access_notices.Reach(db, current_user)") == 1
    assert watch < body.index(write)
    assert body.count("reach.tell()") == 1
    tell = body.index("reach.tell()")
    assert body.index(write) < tell < body.index("db.commit()", tell)
    # No commit between the write and the notice: they are one transaction.
    assert "db.commit()" not in body[body.index(write):tell]


def test_a_change_that_watched_nothing_reads_nothing():
    class _NoSession:
        def __getattr__(self, name):
            raise AssertionError(f"read the database: {name}")
    assert an.Reach(_NoSession(), SimpleNamespace(id=uuid.uuid4())).tell() == 0


def test_joining_watches_the_shares_addressed_to_the_department_too():
    body = _route("add_group_members")
    assert re.search(r"Share\.audience_department_ids\.contains\(\[str\(group_id\)\]\)", body)
    assert body.index("reach.watch_share(") < body.index("user_groups.insert()")
