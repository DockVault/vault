"""The Events tab's filters, paging and row view, without a database.

The SQL is checked by compiling the query for PostgreSQL and reading it; the live API tests run it."""
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Query

from app.core.models import AuditLog
from app.services import activity_events as ev

pytestmark = pytest.mark.unit


def _sql(**filters) -> str:
    q = ev.build_events_query(Query(AuditLog), AuditLog, **filters)
    return str(q.statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))


def test_failed_covers_every_stored_spelling():
    assert set(ev.statuses_for(["failed"])) == {"failure", "failed", "error", "refused"}
    assert ev.statuses_for(["success", "nonsense"]) == ["success"]


@pytest.mark.parametrize("text, expected", [
    ("203.0.113.7", "203.0.113.7/32"),
    ("203.0.113.0/24", "203.0.113.0/24"),
    ("203.0.113.9/24", "203.0.113.0/24"),     # host bits are allowed and dropped
    ("2001:db8::/32", "2001:db8::/32"),
    ("  198.51.100.1 ", "198.51.100.1/32"),
])
def test_an_ip_filter_reads_an_address_or_a_block(text, expected):
    assert str(ev.parse_ip_filter(text)) == expected


@pytest.mark.parametrize("text", ["", "not-an-ip", "fe80::1%eth0", "1.2.3.4/33", "9" * 80])
def test_an_unreadable_ip_filter_is_none(text):
    assert ev.parse_ip_filter(text) is None


def test_the_cursor_round_trips_and_a_bad_one_means_the_first_page():
    ts, rid = datetime(2026, 9, 26, 3, 4, 5, 123456), uuid.uuid4()
    assert ev.decode_cursor(ev.encode_cursor(ts, rid)) == (ts, rid)
    for bad in (None, "", "%%%", "bm90LWEtY3Vyc29y", "x" * 300):
        assert ev.decode_cursor(bad) is None


def test_a_category_filter_includes_older_spellings():
    sql = _sql(categories=["files"])
    assert "'file_upload'" in sql and "'file_uploaded'" in sql
    assert "'login_success'" not in sql


def test_the_legacy_category_is_everything_the_catalog_does_not_know():
    sql = _sql(categories=["legacy"])
    assert "NOT IN" in sql and "'login_success'" in sql


def test_unknown_choices_match_nothing_instead_of_everything():
    for filters in ({"categories": ["nope"]}, {"channels": ["nope"]}, {"statuses": ["nope"]},
                    {"ip": "not-an-ip"}, {"temp_credential_id": "not-a-uuid"}):
        assert "false" in _sql(**filters).lower(), filters


def test_the_unknown_channel_is_rows_without_one():
    sql = _sql(channels=["sftp", "unknown"])
    assert "channel IN ('sftp')" in sql and "channel IS NULL" in sql


def test_a_cidr_is_matched_only_on_rows_holding_a_plain_address():
    sql = _sql(ip="203.0.113.0/24")
    assert "CASE WHEN" in sql and "<<=" in sql and "INET" in sql
    assert _sql(ip="203.0.113.7").count("ip_address = '203.0.113.7'") == 1


def test_text_filters_escape_wildcards():
    # Read the bound values: a literal-bind compile doubles % and backslashes for the driver.
    q = ev.build_events_query(Query(AuditLog), AuditLog, text="50%_off", username="a_b")
    compiled = q.statement.compile(dialect=postgresql.dialect())
    params = set(compiled.params.values())
    assert "%50\\%\\_off%" in params and "%a\\_b%" in params
    assert "ESCAPE" in str(compiled)


def test_a_row_names_its_event_and_keeps_utc():
    r = SimpleNamespace(
        id=uuid.uuid4(), timestamp=datetime(2026, 9, 26, 3, 4, 5), username="maria", temp_credential_id=None,
        action="USER_UPDATED", status="success", channel=None, ip_address="203.0.113.7", method="PUT",
        endpoint="/users/{user_id}", user_agent="ua", resource_type="user", resource_id="1", details={},
        error_message=None)
    v = ev.row_view(r)
    assert v["label"] == "User updated" and v["category"] == "accounts"
    assert v["timestamp"].endswith("+00:00")
    r.action = "something_old"
    v = ev.row_view(r)
    assert (v["label"], v["category"]) == ("Other (legacy)", "legacy")
