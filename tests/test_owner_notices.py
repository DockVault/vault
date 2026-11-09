"""Telling a vault's owner about compliance access to their vaults (app/core/owner_notices.py), offline on a real
(SQLite) database: the notification in the step's own transaction, the email outbox row beside it with its address
sealed as it was then (and a copy to the address before a recent administrator's change), the sender's retries
after 1, 5 and 15 minutes, the failure that raises an alert, and a row a crash left behind that a later pass sends.
test_owner_notices_live.py does the same on a running stack, with a real SMTP server."""
import threading
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import admin_grants  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_notices as on  # noqa: E402
from app.core.security import open_case_field  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 2, 10, 0)
OLD = timedelta(days=400)
TEXT = dict(purpose="litigation_hold", legal_basis="legal_obligation",
            justification="Preserve the records named in the claim served on 2026-10-30.",
            owner_note="Files deleted from your vaults are kept for a legal matter.")


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


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    """No administrator notices or live nudges leave the test; the SFTP check passes."""
    from app.core import sftp_versions
    monkeypatch.setattr(holds, "deliver", lambda notices: None)
    monkeypatch.setattr(on, "_nudge", lambda items: None)
    after_commit.handler(on._NUDGES, lambda items: None)
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: sftp_versions.VersionCheck(True, sftp_versions.SAME, ("0.34.0",)))
    monkeypatch.setattr(on, "contact", lambda db_: None)
    yield
    after_commit.handler(on._NUDGES, on._nudge)


def _user(db, name, role=m.RoleEnum.USER, email="default"):
    u = m.User(username=name, email=f"{name}@example.test" if email == "default" else email, password_hash="x",
               role=role, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    if role == m.RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=NOW - OLD)
        db.commit()
    return u


def _vault(db, owner, name="Payroll 2026"):
    v = m.Vault(id=uuid.uuid4(), name=name, owner_id=owner.id)
    db.add(v)
    db.commit()
    return v


@pytest.fixture
def people(db):
    ada = _user(db, "ada", m.RoleEnum.ADMIN)
    olga = _user(db, "olga")
    return SimpleNamespace(ada=ada, olga=olga, v1=_vault(db, olga), v2=_vault(db, olga))


def _place(db, who, vaults, now=NOW):
    case = holds.place_hold_only(db, who, [v.id for v in vaults], now=now, **TEXT)
    db.commit()
    return case


def _outbox(db, **filters):
    q = db.query(m.ComplianceNoticeOutbox)
    for key, value in filters.items():
        q = q.filter(getattr(m.ComplianceNoticeOutbox, key) == value)
    return q.order_by(m.ComplianceNoticeOutbox.created_at).all()


def _rows(db, action):
    return db.query(m.AuditLog).filter(m.AuditLog.action == action).order_by(m.AuditLog.timestamp).all()


class Sent:
    """A fake email channel: what was sent, and the failures to answer with."""

    def __init__(self):
        self.messages = []
        self.fail = []

    def __call__(self, db, row, case, address, username):
        if self.fail:
            category = self.fail.pop(0)
            if category is not None:
                raise on.SendFailed(category)
        self.messages.append((address, row.kind, case.number if case is not None else None))


def _pass(made, at, sent, **kw):
    make, engine = made
    return on.send_due(make, engine=engine, now=lambda: at, send=sent, **kw)


# --------------------------------------------------------------------------- in the transaction

def test_the_notification_is_written_in_the_callers_transaction(db, people):
    on.notify_in_transaction(db, [people.olga.id, people.olga.id], title="t", body="b", dedup="e1")
    assert after_commit.pending(db, on._NUDGES) == [{"user_id": str(people.olga.id), "type": on.NOTICE_TYPE,
                                                     "target": on.TARGET}]
    db.rollback()
    assert db.query(m.Notification).count() == 0, "it never outlives a step that rolled back"
    on.notify_in_transaction(db, [people.olga.id], title="t", body="b", dedup="e2")
    db.commit()
    (row,) = db.query(m.Notification).all()
    assert row.user_id == people.olga.id and row.dedup_key == "e2" and row.type == "compliance_access"


def test_placing_a_hold_writes_the_owners_notice_outbox_row_and_record_with_it(db, people):
    case = _place(db, people.ada, [people.v1, people.v2])
    (note,) = db.query(m.Notification).filter(m.Notification.user_id == people.olga.id).all()
    assert note.type == "compliance_access" and note.title == "Legal hold on your vaults"
    assert case.number in note.body and "2 vaults you own" in note.body
    (row,) = _outbox(db)
    assert row.case_id == case.id and row.user_id == people.olga.id and row.kind == on.HOLD_PLACED
    assert row.status == on.PENDING and row.attempts == 0 and row.next_attempt_at == NOW
    assert row.details == {"vaults": 2} and row.sent_to == []
    assert row.created_at == NOW
    # The address is sealed, bound to the row; never stored in the clear.
    assert "olga@example.test" not in (row.address_enc or "")
    assert open_case_field(row.id, row.address_enc, "notice_address") == "olga@example.test"
    assert row.previous_address_enc is None
    (written,) = _rows(db, "owner_notice_written")
    assert written.case_id == case.id and written.resource_id == str(people.olga.id)
    assert written.details["kind"] == "hold_placed" and written.details["email_status"] == "queued"
    assert case.notice_email_status == "queued"


def test_a_failure_to_write_the_notice_fails_the_placing(db, people, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("the notification could not be written")
    monkeypatch.setattr(on, "notify_in_transaction", broken)
    with pytest.raises(RuntimeError):
        holds.place_hold_only(db, people.ada, [people.v1.id], now=NOW, **TEXT)
    db.rollback()
    assert db.query(m.ComplianceCase).count() == 0 and db.query(m.LegalHoldVault).count() == 0
    assert holds.held_vault_ids(db) == set(), "nothing is held without its owner's notice"


def test_a_failure_to_write_the_outbox_row_fails_the_placing(db, people, monkeypatch):
    from app.core import security
    real = security.seal_case_field

    def broken(case_id, value, field, **kw):
        if field == "notice_address":
            raise ValueError("cannot seal")
        return real(case_id, value, field, **kw)
    monkeypatch.setattr(security, "seal_case_field", broken)
    with pytest.raises(ValueError):
        holds.place_hold_only(db, people.ada, [people.v1.id], now=NOW, **TEXT)
    db.rollback()
    assert db.query(m.LegalHoldVault).count() == 0 and db.query(m.Notification).count() == 0


def test_an_owner_without_an_address_is_told_in_the_app_and_the_case_says_so(db, people):
    nemo = _user(db, "nemo", email=None)
    case = _place(db, people.ada, [_vault(db, nemo)])
    (row,) = _outbox(db)
    assert row.status == on.NO_ADDRESS and row.address_enc is None and row.next_attempt_at is None
    assert db.query(m.Notification).filter(m.Notification.user_id == nemo.id).count() == 1
    assert case.notice_email_status == "no_email_address"
    assert _rows(db, "owner_notice_written")[0].details["email_status"] == "no_email_address"


def _email_change(db, user, before, after, *, applied, status=cc.MADE):
    db.add(m.CredentialChange(target_user_id=user.id, kind=cc.EMAIL, status=status, requested_by_name="ada",
                              requested_at=applied, applied_at=applied,
                              payload={"previous_email": before, "new_email": after}))
    db.commit()


def test_a_recent_administrators_change_of_the_address_sends_a_copy_to_the_one_before(db, people):
    _email_change(db, people.olga, "olga.private@example.test", "olga@example.test",
                  applied=datetime.utcnow() - timedelta(days=3))
    _place(db, people.ada, [people.v1])
    (row,) = _outbox(db)
    assert open_case_field(row.id, row.previous_address_enc, "notice_previous_address") == "olga.private@example.test"
    assert _rows(db, "owner_notice_written")[0].details["copy_to_previous"] is True


def test_no_copy_after_fourteen_days_or_once_the_owner_chose_another_address(db, people):
    _email_change(db, people.olga, "old@example.test", "olga@example.test",
                  applied=datetime.utcnow() - timedelta(days=15))
    assert on.destinations(db, people.olga) == ("olga@example.test", None)
    _email_change(db, people.olga, "old@example.test", "admins-pick@example.test",
                  applied=datetime.utcnow() - timedelta(days=2))
    assert on.destinations(db, people.olga) == ("olga@example.test", None), \
        "the owner changed it again since: their own choice stands"
    people.olga.email = "admins-pick@example.test"
    db.commit()
    assert on.destinations(db, people.olga) == ("admins-pick@example.test", "old@example.test")


def test_a_change_not_applied_gives_no_copy(db, people):
    _email_change(db, people.olga, "old@example.test", "olga@example.test",
                  applied=datetime.utcnow() - timedelta(days=1), status="held")
    assert on.destinations(db, people.olga) == ("olga@example.test", None)


def test_two_notices_never_share_a_key(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.confirm(db, case, by=_user(db, "bob", m.RoleEnum.ADMIN), now=NOW)
    db.commit()
    keys = [r.dedup_key for r in _outbox(db)]
    assert len(keys) == len(set(keys)) == 2
    dedup = [n.dedup_key for n in db.query(m.Notification).filter(m.Notification.user_id == people.olga.id)]
    assert len(set(dedup)) == 2


def test_two_owners_in_one_step_each_get_their_own(db, people):
    oscar = _user(db, "oscar")
    _place(db, people.ada, [people.v1, _vault(db, oscar)])
    rows = _outbox(db)
    assert {r.user_id for r in rows} == {people.olga.id, oscar.id} and len({r.dedup_key for r in rows}) == 2
    assert {r.details["vaults"] for r in rows} == {1}


@pytest.mark.parametrize("step,kind,title", [
    ("confirm", on.HOLD_CONFIRMED, "Legal hold confirmed"),
    ("release", on.HOLD_RELEASED, "Legal hold released"),
    ("lapse", on.HOLD_LAPSED, "Legal hold lapsed"),
])
def test_every_step_of_a_hold_tells_its_owners_through_the_outbox(db, people, step, kind, title):
    case = _place(db, people.ada, [people.v1])
    if step == "confirm":
        holds.confirm(db, case, by=_user(db, "bob", m.RoleEnum.ADMIN), now=NOW)
    elif step == "release":
        holds.release(db, case, by=people.ada, reason="The claim was withdrawn.", now=NOW + timedelta(hours=1))
    else:
        holds.lapse_due(db, NOW + timedelta(days=7))
    db.commit()
    rows = _outbox(db)
    assert [r.kind for r in rows] == [on.HOLD_PLACED, kind]
    titles = [n.title for n in db.query(m.Notification).filter(m.Notification.user_id == people.olga.id)
              .order_by(m.Notification.created_at)]
    assert titles[-1] == title


def test_an_undone_release_tells_the_owner(db, people, monkeypatch):
    # The undo reads the clock for itself and is refused once the release's purge time has passed: read from the
    # wall clock, that time passed the purge delay after NOW, whatever day the suite runs.
    monkeypatch.setattr(holds, "utcnow", lambda: NOW + timedelta(hours=2))
    bob = _user(db, "bob", m.RoleEnum.ADMIN)
    case = _place(db, people.ada, [people.v1])
    holds.confirm(db, case, by=bob, now=NOW)
    holds.release(db, case, by=people.ada, reason="The claim was withdrawn.", now=NOW + timedelta(hours=1))
    holds.undo_release(db, case, by=bob, now=NOW + timedelta(hours=2))
    db.commit()
    assert [r.kind for r in _outbox(db)][-1] == on.HOLD_RESTORED


def test_a_release_whose_caller_tells_the_owners_itself_writes_none(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.release(db, case, by=people.ada, reason="Closed.", now=NOW + timedelta(hours=1), tell_owners=False)
    db.commit()
    assert [r.kind for r in _outbox(db)] == [on.HOLD_PLACED]


# --------------------------------------------------------------------------- the sender

def test_a_due_row_is_sent_and_recorded(made, db, people):
    case = _place(db, people.ada, [people.v1])
    sent = Sent()
    assert _pass(made, NOW, sent) == [on.SENT]
    assert sent.messages == [("olga@example.test", on.HOLD_PLACED, case.number)]
    db.expire_all()
    (row,) = _outbox(db)
    assert row.status == on.SENT and row.sent_at == NOW and row.attempts == 1 and row.sent_to == [on.ADDRESS]
    assert db.get(m.ComplianceCase, case.id).notice_email_status == "sent"
    (done,) = _rows(db, "owner_notice_email_sent")
    assert done.case_id == case.id and done.details["attempts"] == 1
    assert _pass(made, NOW + timedelta(hours=1), sent) == [], "a sent row is never sent again"


def test_a_row_that_is_not_due_yet_waits(made, db, people):
    _place(db, people.ada, [people.v1], now=NOW)
    assert _pass(made, NOW - timedelta(seconds=1), Sent()) == []


def test_failures_are_tried_again_after_1_5_and_15_minutes_then_raise_an_alert(made, db, people):
    case = _place(db, people.ada, [people.v1])
    sent = Sent()
    sent.fail = ["transport"] * 4
    expected = [(NOW, 1), (NOW + timedelta(minutes=1), 5), (NOW + timedelta(minutes=6), 15)]
    for at, wait in expected:
        assert _pass(made, at - timedelta(seconds=1), sent) == [], "not due a second before its time"
        assert _pass(made, at, sent) == [on.RETRYING]
        db.expire_all()
        (row,) = _outbox(db)
        assert row.next_attempt_at == at + timedelta(minutes=wait) and row.last_error_class == "transport"
        assert db.get(m.ComplianceCase, case.id).notice_email_status == "retrying"
    assert db.query(m.SecurityAlert).count() == 0
    last = NOW + timedelta(minutes=21)
    assert _pass(made, last - timedelta(seconds=1), sent) == []
    assert _pass(made, last, sent) == [on.FAILED]
    db.expire_all()
    (row,) = _outbox(db)
    assert row.status == on.FAILED and row.attempts == 4 and row.next_attempt_at is None
    assert db.get(m.ComplianceCase, case.id).notice_email_status == "failed"
    (alert,) = db.query(m.SecurityAlert).all()
    assert alert.event_type == "owner_notice_email_failed" and alert.severity == "warning"
    assert alert.user_id == people.olga.id and alert.details["case_number"] == case.number
    assert "Payroll" not in alert.message
    (failed,) = _rows(db, "owner_notice_email_failed")
    assert failed.status == "failure" and failed.case_id == case.id
    assert _pass(made, last + timedelta(days=1), sent) == [], "a failed row is not tried again"
    assert sent.messages == []


def test_a_row_sent_on_its_last_retry_is_sent(made, db, people):
    _place(db, people.ada, [people.v1])
    sent = Sent()
    sent.fail = ["transport", "transport", "transport", None]
    for at in (NOW, NOW + timedelta(minutes=1), NOW + timedelta(minutes=6)):
        _pass(made, at, sent)
    assert _pass(made, NOW + timedelta(minutes=21), sent) == [on.SENT]
    assert db.query(m.SecurityAlert).count() == 0


def test_the_copy_to_the_address_before_is_sent_too_and_a_retry_sends_only_what_is_missing(made, db, people):
    _email_change(db, people.olga, "olga.private@example.test", "olga@example.test",
                  applied=datetime.utcnow() - timedelta(days=3))
    _place(db, people.ada, [people.v1])
    calls = []

    def send(db_, row, case, address, username):
        calls.append(address)
        if address == "olga.private@example.test" and calls.count(address) == 1:
            raise on.SendFailed("transport")
    assert _pass(made, NOW, send) == [on.RETRYING]
    db.expire_all()
    assert _outbox(db)[0].sent_to == [on.ADDRESS]
    assert _pass(made, NOW + timedelta(minutes=1), send) == [on.SENT]
    assert calls == ["olga@example.test", "olga.private@example.test", "olga.private@example.test"]
    db.expire_all()
    assert _outbox(db)[0].sent_to == [on.ADDRESS, on.PREVIOUS]


def test_an_address_changed_after_the_notice_does_not_reroute_it(made, db, people):
    _place(db, people.ada, [people.v1])
    people.olga.email = "taken-over@example.test"
    db.commit()
    sent = Sent()
    _pass(made, NOW, sent)
    assert sent.messages[0][0] == "olga@example.test"


def test_a_row_a_crash_left_unsent_is_sent_by_a_later_pass_of_another_session(made, db, people):
    """The step committed; the process stopped before sending. Nothing is lost: the row is in the database, and
    any later pass, in this process or another, sends it."""
    _place(db, people.ada, [people.v1])
    db.close()
    sent = Sent()
    assert _pass(made, NOW + timedelta(hours=3), sent) == [on.SENT]
    assert len(sent.messages) == 1


def test_a_pass_never_sends_while_another_holds_the_senders_turn(made, db, people):
    _place(db, people.ada, [people.v1])
    assert on._local_turn.acquire(blocking=False)
    try:
        assert _pass(made, NOW, Sent()) == []
    finally:
        on._local_turn.release()


def test_a_pass_stops_at_its_row_limit(made, db, people):
    oscar = _user(db, "oscar")
    _place(db, people.ada, [people.v1, _vault(db, oscar)])
    assert _pass(made, NOW, Sent(), max_rows=1) == [on.SENT]
    assert _pass(made, NOW, Sent(), max_rows=5) == [on.SENT]


def test_a_send_that_breaks_is_a_failed_attempt(made, db, people):
    _place(db, people.ada, [people.v1])

    def broken(*a):
        raise KeyError("boom")
    assert _pass(made, NOW, broken) == [on.RETRYING]
    db.expire_all()
    assert _outbox(db)[0].last_error_class == "KeyError"


def test_what_the_case_shows_of_its_owners_emails():
    assert on.case_status([]) is None
    assert on.case_status([on.SENT, on.NO_ADDRESS]) == "sent"
    assert on.case_status([on.NO_ADDRESS]) == "no_email_address"
    assert on.case_status([on.SENT, on.PENDING]) == "queued"
    assert on.case_status([on.PENDING, on.RETRYING]) == "retrying"
    assert on.case_status([on.RETRYING, on.FAILED, on.SENT]) == "failed"


def test_a_commit_wakes_the_sender(db, people, monkeypatch):
    woken = []
    monkeypatch.setattr(on, "wake", lambda: woken.append(1))
    after_commit.handler(on._WAKE, lambda items: on.wake())
    _place(db, people.ada, [people.v1])
    assert woken == [1]
    after_commit.handler(on._WAKE, lambda items: on.wake())


def test_the_sender_runs_on_a_thread_of_its_own_started_by_the_web_process(monkeypatch):
    import inspect
    from app.api import api_server
    started = []
    monkeypatch.setattr(on, "_loop", lambda poll: started.append(threading.current_thread().name))
    monkeypatch.setattr(on, "_thread", None)
    assert on.start(poll=0.01) is True
    on._thread.join(timeout=5)
    assert started == ["owner-notices"]
    source = inspect.getsource(api_server.lifespan)
    assert "owner_notices.start()" in source
    loop = inspect.getsource(api_server.cleanup_expired_sessions)
    assert "owner_notices" not in loop and "send_due" not in loop


# --------------------------------------------------------------------------- what a notice says

SENTINELS = ("Payroll 2026", "salaries-q3.xlsx", "Board minutes", "Preserve the records named in the claim",
             "mallory")


def test_no_notice_names_a_vault_file_folder_the_justification_or_a_person_named(made, db, people):
    """Sentinel names everywhere the database holds one: none reaches the notification, the outbox row, the record
    or the email."""
    mallory = _user(db, "mallory")
    folder = m.Folder(id=uuid.uuid4(), vault_id=people.v1.id, name="Board minutes")
    db.add(folder)
    db.add(m.File(id=uuid.uuid4(), vault_id=people.v1.id, folder_id=folder.id, name="salaries-q3.xlsx",
                  original_name="salaries-q3.xlsx", size_bytes=10, storage_path="x", mime_type="text/plain"))
    db.commit()
    case = _place(db, people.ada, [people.v1])
    db.add(m.ComplianceCasePerson(case_id=case.id, user_id=mallory.id, why="named"))
    db.commit()
    contexts = []

    def capture(db_, row, case_, address, username):
        contexts.append(on.email_context(db_, row, case_))
    _pass(made, NOW, capture)
    for kind in on.KINDS:
        f = on.facts(db, case, kind, {"vaults": 1, "files": 2, "by": "ada"})
        contexts.append({"text": " ".join(on.notice_text(f)[1]) + on.notice_text(f)[0]})
    blobs = [n.title + " " + (n.body or "") for n in db.query(m.Notification)]
    blobs += [str(r.details) for r in _outbox(db)] + [str(r.details) for r in db.query(m.AuditLog)]
    blobs += [str(c) for c in contexts]
    for blob in blobs:
        for sentinel in SENTINELS:
            assert sentinel not in blob, (sentinel, blob)
    assert contexts and contexts[0]["code"] == case.number


def test_the_activation_notice_says_who_until_when_and_what_cannot_be_opened():
    f = on.Facts(kind=on.ACTIVATION, number="C-2026-0007", purpose="internal_investigation",
                 legal_basis="legitimate_interests", auditor="jane", approver="sam",
                 ends_at=datetime(2026, 10, 11, 14, 2), can_export=True, vaults=3, zero_knowledge=1,
                 with_password=1, hold=True, contact="privacy@example.test")
    title, lines = on.notice_text(f)
    text = " ".join(lines)
    assert title == "An investigation can open 3 of your vaults"
    assert "Case C-2026-0007 · Purpose: internal investigation · Legal basis: legitimate interests." in text
    assert "jane (auditor) can view files and export copies until 11 Oct 2026, 14:02 UTC. Approved by sam." in text
    assert "A legal hold keeps files deleted from those vaults until the case ends." in text
    assert "1 of them is zero-knowledge" in text and "the auditor must type it" in text
    assert "Questions or objections: privacy@example.test." in text
    title, lines = on.notice_text(on.Facts(**{**f.__dict__, "approver": on.HOST_OPERATOR, "vaults": 1,
                                              "can_export": False, "hold": False, "zero_knowledge": 0,
                                              "with_password": 2, "password_override": True, "contact": None}))
    text = " ".join(lines)
    assert title == "An investigation can open 1 of your vaults" and "Approved by the server's operator." in text
    assert "export" not in text and "legal hold" not in text and "zero-knowledge" not in text
    assert "may open them without the password" in text and "your administrator" in text


def test_the_note_is_in_the_email_of_an_activation_never_in_the_notification(made, db, people):
    case = _place(db, people.ada, [people.v1])
    row = _outbox(db)[0]
    row.kind = on.ACTIVATION
    db.commit()
    ctx = on.email_context(db, row, case)
    assert TEXT["owner_note"] in ctx["change"]
    note = db.query(m.Notification).filter(m.Notification.user_id == people.olga.id).first()
    assert TEXT["owner_note"] not in note.body
    title, body = on.app_text(on.facts(db, case, on.ACTIVATION, {"vaults": 1}), has_note=True)
    assert "The auditor's note to you is on Access to my vaults." in body and TEXT["owner_note"] not in body
    row.kind = on.HOLD_PLACED
    assert TEXT["owner_note"] not in on.email_context(db, row, case)["change"]


def test_a_sender_skips_a_row_another_sender_holds_instead_of_waiting_for_it(db, monkeypatch):
    """The sender's advisory lock keeps a second sender out; each row is still read FOR UPDATE SKIP LOCKED, so one
    that got in anyway moves on to the next row. (PostgreSQL's clause; SQLite has no row locks.)"""
    from sqlalchemy.dialects import postgresql
    sql = " ".join(str(on.due_query(db, NOW).statement.compile(dialect=postgresql.dialect())).split())
    assert sql.endswith("FOR UPDATE SKIP LOCKED"), sql
    picked = SimpleNamespace(first=lambda: "the next row")
    monkeypatch.setattr(on, "due_query", lambda db_, now: picked)
    assert on.due(db, NOW) == "the next row"
