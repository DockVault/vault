"""The Events list's paging, its live reads, and the filters added with them, without a database.

Where it matters what a condition keeps, the query runs against rows held in memory (tests/_memory_db.py);
where only the SQL can say it (ILIKE, a sub-select), the query is compiled for PostgreSQL and read. The
live API tests run all of it against a real database."""
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Query

from _memory_db import MemoryDB
from app.core.models import AuditLog
from app.services import activity_events as ev

pytestmark = pytest.mark.unit


def _rows():
    """Nine rows over five instants, three of them sharing one instant, so the id breaks ties."""
    base = datetime(2026, 9, 27, 8, 0, 0)
    stamps = [base, base + timedelta(seconds=1), base + timedelta(seconds=2), base + timedelta(seconds=2),
              base + timedelta(seconds=2), base + timedelta(seconds=3), base + timedelta(seconds=4),
              base + timedelta(seconds=4), base + timedelta(seconds=5)]
    return [SimpleNamespace(id=uuid.UUID(int=i + 1), timestamp=t, action="login_failure", status="failure")
            for i, t in enumerate(stamps)]


def _key(r):
    return (r.timestamp, r.id)


@pytest.mark.parametrize("pick", range(9))
def test_newer_and_older_split_the_log_around_any_row(pick):
    rows = _rows()
    db = MemoryDB({AuditLog: rows})
    anchor = rows[pick]
    newer = ev.newer_than(db.query(AuditLog), AuditLog, _key(anchor)).all()
    older = ev.after_cursor(db.query(AuditLog), AuditLog, _key(anchor)).all()
    assert {r.id for r in newer} == {r.id for r in rows if _key(r) > _key(anchor)}
    assert {r.id for r in older} == {r.id for r in rows if _key(r) < _key(anchor)}
    # Every row is in exactly one of the three: nothing is shown twice or lost by a live list.
    assert len(newer) + len(older) + 1 == len(rows)


def test_a_page_count_is_at_least_one():
    assert ev.page_count(0, 25) == 1
    assert ev.page_count(25, 25) == 1
    assert ev.page_count(26, 25) == 2
    assert ev.page_count(101, 50) == 3


def test_a_numbered_page_starts_after_the_pages_before_it():
    assert ev.page_offset(1, 25) == 0
    assert ev.page_offset(3, 50) == 100
    assert ev.page_offset(0, 50) == 0                     # page numbers start at 1


def test_a_page_too_far_in_is_not_opened_by_skipping_rows():
    size = 100
    last = ev.MAX_OFFSET // size + 1
    assert ev.page_offset(last, size) == ev.MAX_OFFSET
    assert ev.page_offset(last + 1, size) is None


def test_the_page_sizes_the_page_offers_are_all_allowed():
    assert ev.PAGE_SIZES == (25, 50, 100)
    assert max(ev.PAGE_SIZES) <= ev.MAX_PAGE


def test_row_ids_are_read_once_each_and_the_rest_ignored():
    a, b = uuid.uuid4(), uuid.uuid4()
    assert ev.parse_ids([str(a), "nope", str(b), str(a).upper(), ""]) == [a, b]


def test_at_most_so_many_ids_are_read():
    assert len(ev.parse_ids(str(uuid.uuid4()) for _ in range(ev.MAX_IDS + 5))) == ev.MAX_IDS


def test_an_ids_filter_keeps_only_those_rows():
    rows = _rows()
    db = MemoryDB({AuditLog: rows})
    wanted = [str(rows[1].id), str(rows[7].id), str(uuid.uuid4())]
    got = ev.build_events_query(db.query(AuditLog), AuditLog, ids=wanted).all()
    assert sorted(r.id for r in got) == sorted([rows[1].id, rows[7].id])


def test_an_ids_filter_with_nothing_readable_matches_nothing():
    rows = _rows()
    db = MemoryDB({AuditLog: rows})
    assert ev.build_events_query(db.query(AuditLog), AuditLog, ids=["x", "y"]).all() == []


def _sql(**filters):
    q = ev.build_events_query(Query(AuditLog), AuditLog, **filters)
    return q.statement.compile(dialect=postgresql.dialect())


def test_a_credential_name_matches_the_stored_name_or_an_older_rows_credential():
    compiled = _sql(temp_credential="temp_ab%")
    sql = str(compiled)
    assert "audit_logs.temp_credential_name ILIKE" in sql
    # An older row stored only the id: it matches through the credential's current name.
    assert "audit_logs.temp_credential_name IS NULL" in sql
    assert "audit_logs.temp_credential_id IN (SELECT temporary_credentials.id" in sql
    assert "temporary_credentials.temp_username ILIKE" in sql
    # The name is matched as typed, its wildcards escaped.
    assert "%temp\\_ab\\%%" in set(compiled.params.values())


def test_no_credential_name_filter_adds_no_condition():
    assert " WHERE " not in str(_sql())


@pytest.mark.parametrize("text,expected", [
    (" Al ", "al"), ("temp_", "temp_"), ("", None), ("   ", None), (None, None), ("x" * 65, None),
])
def test_a_typeahead_prefix_is_trimmed_and_lower_cased(text, expected):
    assert ev.typeahead_prefix(text) == expected


def test_the_typeahead_range_covers_every_name_with_the_prefix_and_no_other():
    # In byte order, which is the order of the index the typeahead walks.
    prefix = "al"
    hi = (prefix + ev._TOP).encode()
    inside = ["al", "alice", "al.ice", "aléx", "al\U0001f600", "al￿"]
    outside = ["ak", "am", "a", "b", "alz"[:1]]
    assert all(prefix.encode() <= n.encode() < hi for n in inside)
    assert not any(prefix.encode() <= n.encode() < hi for n in outside)


def test_a_row_view_carries_the_credentials_name():
    row = SimpleNamespace(
        id=uuid.uuid4(), timestamp=datetime(2026, 9, 27, 8, 0, 0), username="alex",
        temp_credential_id=uuid.uuid4(), temp_credential_name="temp_contractor", action="login_success",
        status="success", channel="web", ip_address="203.0.113.9", method="POST", endpoint="/auth/login",
        user_agent=None, resource_type=None, resource_id=None, details=None, error_message=None)
    assert ev.row_view(row)["temp_credential_name"] == "temp_contractor"


def test_an_export_names_the_credential_and_keeps_its_id_last():
    headings = [h for h, _ in ev.EXPORT_COLUMNS]
    assert headings[6] == "Temporary credential"
    assert dict(ev.EXPORT_COLUMNS)["Temporary credential"] == "temp_credential_name"
    assert ev.EXPORT_COLUMNS[-1] == ("Temporary credential ID", "temp_credential_id")
