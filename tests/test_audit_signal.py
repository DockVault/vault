"""The Activity signal: a committed audit row sends its id and category, and nothing else.

Runs a real SQLAlchemy session against SQLite with the listener installed on its factory, so what is
tested is what a commit, a rollback and a savepoint really do, not what the code says they do. The
publishing thread is replaced by a list, except in the test of the thread itself."""
import json
import queue
import threading
import time
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app.core import audit_signal
from app.core.models import AuditLog, User
from app.services.audit_logger import AuditLogger

pytestmark = pytest.mark.unit


@pytest.fixture
def factory(tmp_path):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'signal.db'}")
    User.__table__.create(engine)
    AuditLog.__table__.create(engine)
    f = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    assert audit_signal.install(f) is True
    yield f
    engine.dispose()


@pytest.fixture
def sent(monkeypatch):
    got = []
    monkeypatch.setattr(audit_signal, "enqueue", lambda row_id, category: got.append((row_id, category)))
    return got


def test_a_row_logged_and_committed_sends_its_id_and_category(factory, sent):
    db = factory()
    row = AuditLogger(db).log_action(action="login_failure", status="failure", username="someone",
                                     ip_address="203.0.113.9", details={"reason": "bad password"})
    assert sent == [(str(row.id), "sign_in")]


def test_a_row_built_into_the_callers_transaction_sends_when_that_commits(factory, sent):
    db = factory()
    db.add(AuditLogger(db).build_row(action="file_expired", status="success"))
    db.flush()
    assert sent == []                                   # flushed is not committed
    db.commit()
    assert [c for _i, c in sent] == ["files"]


def test_a_rolled_back_row_sends_nothing(factory, sent):
    db = factory()
    db.add(AuditLogger(db).build_row(action="login_failure", status="failure"))
    db.flush()
    db.rollback()
    db.commit()                                         # a later, empty commit
    assert sent == []


def test_a_row_inside_a_rolled_back_savepoint_sends_nothing_and_its_neighbour_still_does(factory, sent):
    db = factory()
    kept = AuditLogger(db).build_row(action="login_success", status="success")
    db.add(kept)
    sp = db.begin_nested()
    db.add(AuditLogger(db).build_row(action="login_failure", status="failure"))
    db.flush()
    sp.rollback()
    db.commit()
    assert sent == [(str(kept.id), "sign_in")]


def test_a_closed_session_sends_nothing_later(factory, sent):
    db = factory()
    db.add(AuditLogger(db).build_row(action="login_failure", status="failure"))
    db.flush()
    db.close()                                          # the request ended without a commit
    assert audit_signal._INFO_KEY not in db.info         # nothing is held for a later transaction
    db.commit()
    factory().commit()
    assert sent == []


def test_a_commit_without_audit_rows_sends_nothing(factory, sent):
    db = factory()
    db.add(User(username="u1", password_hash="x"))
    db.commit()
    assert sent == []


def test_an_action_the_catalog_does_not_know_is_legacy(factory, sent):
    db = factory()
    AuditLogger(db).log_action(action="something_from_an_old_release", status="success")
    assert [c for _i, c in sent] == ["legacy"]


def test_a_factory_that_is_not_a_session_factory_is_left_alone():
    # The boot path builds its factory with sessionmaker; a stand-in (a test's fake) must not break it.
    assert audit_signal.install(object()) is False


def test_the_message_names_only_ids_and_categories():
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    msg = json.loads(audit_signal.message([(a, "sign_in"), (b, "files")]))
    assert msg == {"events": [{"id": a, "category": "sign_in"}, {"id": b, "category": "files"}]}


@pytest.mark.parametrize("bad", [
    {"id": "not-a-uuid", "category": "files"},
    {"id": str(uuid.uuid4()), "category": "files and <b>"},
    {"id": str(uuid.uuid4()), "category": ""},
    {"id": str(uuid.uuid4()), "category": 3},
    "a string",
])
def test_reading_a_message_drops_anything_malformed(bad):
    good = {"id": str(uuid.uuid4()), "category": "files"}
    assert audit_signal.parse_message(json.dumps({"events": [bad, good]})) == [good]


def test_reading_a_message_keeps_only_the_two_fields():
    row = {"id": str(uuid.uuid4()), "category": "sign_in", "username": "maria", "ip": "203.0.113.9"}
    assert audit_signal.parse_message(json.dumps({"events": [row]})) == [
        {"id": row["id"], "category": "sign_in"}]


def test_reading_something_that_is_not_a_message_gives_nothing():
    for raw in ("", "not json", "[]", json.dumps({"events": "x"}), None):
        assert audit_signal.parse_message(raw) == []


def test_a_full_queue_drops_the_signal_instead_of_blocking(monkeypatch):
    monkeypatch.setattr(audit_signal, "_queue", queue.Queue(maxsize=1))
    monkeypatch.setattr(audit_signal, "_ensure_worker", lambda: None)
    before = audit_signal.dropped
    started = time.monotonic()
    assert audit_signal.enqueue(str(uuid.uuid4()), "files") is True
    assert audit_signal.enqueue(str(uuid.uuid4()), "files") is False
    assert time.monotonic() - started < 1
    assert audit_signal.dropped == before + 1


def test_the_thread_publishes_queued_signals_together(monkeypatch):
    published, done = [], threading.Event()

    def capture(text):
        published.append(json.loads(text))
        if sum(len(m["events"]) for m in published) >= 3:
            done.set()

    monkeypatch.setattr(audit_signal, "_publish", capture)
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for i in ids:
        audit_signal.enqueue(i, "files")
    assert done.wait(5), published
    assert [e["id"] for m in published for e in m["events"]] == ids


def test_publishing_while_redis_is_down_does_not_raise(monkeypatch):
    from app.core import database, redis_guard

    class Down:
        def publish(self, *a):
            raise ConnectionError("redis is down")

    monkeypatch.setattr(database, "redis_client", Down())
    monkeypatch.setattr(redis_guard, "_guard_open_until", 0.0)
    try:
        audit_signal._publish(audit_signal.message([(str(uuid.uuid4()), "files")]))
    finally:
        redis_guard.guard_record_success()      # leave the shared guard as it was found
