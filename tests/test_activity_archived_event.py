"""One event read on its own (GET /activity/events/{event_id}: a copied link to an event, the details read again)
when its day is archived, offline, on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py):

- an event of an archived day is no row of audit_logs any more: read with its time (``at``), it is found in the
  archived hour that time names, as the Events list shows it; without its time, or with the time of another hour,
  it is not found, and an id that is a row is never looked for in the archive;
- while the server cannot tell which days are archived, a look for it in an hour that could be archived is refused
  with 503 and Retry-After, as the list's read; an event that is a row is answered all the same.

The page's side (the link and the details carry the event's time) is in test_activity_page_helpers.py and
test_activity_auditor_form.py; the same read on Postgres in test_activity_archive_live.py.
"""
import uuid
from datetime import datetime, time, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _audit_chain_env import Env, T0
from app.core import audit_archive as arc
from app.core import audit_integrity as ai
from app.core import retention
from app.core.models import AuditArchiveBlock

pytestmark = pytest.mark.unit

ARCHIVED = (T0 - timedelta(days=100)).date()
HOT = (T0 - timedelta(days=2)).date()
ADMIN = SimpleNamespace(id="a-1", username="alice", role="admin")


def at(day, hour, minute=0):
    return datetime.combine(day, time(hour, minute))


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    # The names an event shows are read from tables this database does not have: the event as the list shows it is
    # enough here (test_activity_archive_live.py reads them on Postgres).
    from app.services import activity_names as an
    monkeypatch.setattr(an, "names_for", lambda db, viewer, events: [{"vault": None, "item": None} for _ in events])
    monkeypatch.setattr(an, "recorded_names_for", lambda db, viewer, rows, unlocked=frozenset(): [None for _ in rows])
    monkeypatch.setattr(an, "unlocked_vaults", lambda db, viewer, request: frozenset())
    monkeypatch.setattr(an, "temp_credential_names", lambda db, events: None)
    yield e
    e.close()


def _archived(env):
    """Rows on an archived day (three, one per hour) and on a recent one (two), sealed and the old day archived.
    Returns {id: time} of the archived day's rows and the id of a recent row."""
    rows = {}
    for h in (3, 9, 15):
        when = at(ARCHIVED, h, 17) + timedelta(microseconds=123456)
        rows[str(env.row(when, action="vault_created", username="bob"))] = when
    recent = str(env.row(at(HOT, 8, 5)))
    env.row(at(HOT, 12, 5))
    env.run_until_sealed()
    for _ in range(3):
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert {arc._as_date(d) for (d,) in db.query(AuditArchiveBlock.day).all()} == {ARCHIVED}
    return rows, recent


def _event(env, event_id, at_=None):
    from app.api import api_server as api
    with env.session() as db:
        return api.activity_event(event_id, at=at_, case=None, request=None, current_user=ADMIN, db=db)


def _missing(env, event_id, at_=None):
    with pytest.raises(HTTPException) as refused:
        _event(env, event_id, at_)
    return refused.value


def test_an_archived_event_is_read_from_the_archive_with_its_time(env):
    rows, recent = _archived(env)
    for event_id, when in rows.items():
        one = _event(env, event_id, when.isoformat() + "+00:00")
        assert one["id"] == event_id and one["timestamp"] == when.isoformat() + "+00:00"
        assert one["action"] == "vault_created" and one["username"] == "bob"
        assert one["names"] == {"vault": None, "item": None}
    # As the page sends it: the time the details carry, and the same instant in milliseconds from another zone.
    event_id, when = sorted(rows.items(), key=lambda kv: kv[1])[1]
    assert _event(env, event_id, (when + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+02:00")["id"] \
        == event_id
    # The time names an hour: any time in the event's hour finds it, a later one too.
    assert _event(env, event_id, when.replace(minute=59, second=59).isoformat())["id"] == event_id
    # A row is read from the rows, with or without a time.
    assert _event(env, recent)["id"] == recent
    assert _event(env, recent, at(ARCHIVED, 3).isoformat())["id"] == recent


def test_an_archived_event_is_not_found_without_its_time_or_in_another_hour(env):
    rows, _recent = _archived(env)
    event_id, when = sorted(rows.items(), key=lambda kv: kv[1])[0]
    for given in (None, "", "not a time", (when + timedelta(hours=1)).isoformat(),
                  (when - timedelta(days=1)).isoformat(), at(HOT, 8).isoformat()):
        refused = _missing(env, event_id, given)
        assert refused.status_code == 404 and refused.detail == "That event is not in the log.", given
    assert _missing(env, str(uuid.uuid4()), when.isoformat()).status_code == 404       # no such event at all
    assert _missing(env, "not-an-id", when.isoformat()).status_code == 404
    assert _missing(env, event_id, "9999-12-31T23:30:00").status_code == 404           # the calendar's last hour


def test_an_archived_event_is_refused_while_the_archived_days_cannot_be_told(env, monkeypatch):
    rows, recent = _archived(env)
    event_id, when = sorted(rows.items(), key=lambda kv: kv[1])[0]
    st = env.fresh_process()
    monkeypatch.setattr(ai, "READ_WAIT_SECONDS", 0.05)
    assert st.mutex.acquire(timeout=5)              # the chain lock held past the wait: the chain cannot be read
    try:
        refused = _missing(env, event_id, when.isoformat())
        assert refused.status_code == 503 and refused.headers == {"Retry-After": "60"}
        assert refused.detail.startswith("The archived days of the audit log cannot be read yet")
        assert _event(env, recent, when.isoformat())["id"] == recent              # a row: answered
        # An hour no archived day can reach: no row there is no event there.
        assert _missing(env, str(uuid.uuid4()), at(HOT, 8).isoformat()).status_code == 404
    finally:
        st.mutex.release()
    assert st.view_read is False
    assert _event(env, event_id, when.isoformat())["id"] == event_id               # read once the lock is free
    assert st.view_read is True


def test_the_event_route_reads_the_archived_hour_through_the_case_filters_and_the_same_view():
    """The look in the archive runs the same filters as the read of the rows (a selected case's among them), and the
    event found either way is shown by the one helper that gives the names through their gate."""
    import inspect
    from app.api import api_server as api
    one = inspect.getsource(api.activity_event)
    assert one.count("**_case_filters(selection)") == 2
    assert one.count("_activity_event_view(db, current_user, request, selection, row)") == 2
    assert one.count("with archive.source(db, hour, end) as src:") == 1
    assert one.index("archive.ids_are_rows(db, [event_id])") < one.index("with archive.source(")
