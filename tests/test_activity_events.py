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


def _batches(rows, size):
    """A fetch_batch over a list: returns (batch, next cursor), the cursor None after a short batch."""
    calls = []

    def fetch(after):
        start = 0 if after is None else after
        calls.append(start)
        got = rows[start:start + size]
        return got, (start + size if len(got) == size else None)
    return fetch, calls


def _view(i, **extra):
    row = {"timestamp": f"2026-09-26T0{i % 10}:00:00+00:00", "label": "Sign-in failed", "action": "login_failure",
           "username": f"user{i}", "details": {"reason": "bad password"}, "ip_address": "203.0.113.9"}
    row.update(extra)
    return row


def test_a_csv_export_has_the_headings_then_a_line_per_event():
    import csv, io
    fetch, calls = _batches([_view(i) for i in range(5)], size=2)
    text = "".join(ev.export_lines(fetch, "csv", total=5))
    table = list(csv.reader(io.StringIO(text)))
    assert table[0] == [h for h, _ in ev.EXPORT_COLUMNS]
    assert [r[5] for r in table[1:]] == [f"user{i}" for i in range(5)]
    assert table[1][14] == '{"reason": "bad password"}'
    assert calls == [0, 2, 4]                 # batch by batch, stopping after the short one


def test_a_csv_cell_that_would_run_as_a_formula_is_quoted():
    import csv, io
    fetch, _ = _batches([_view(0, username="=HYPERLINK(\"http://x\")"), _view(1, username="-2+3")], size=10)
    table = list(csv.reader(io.StringIO("".join(ev.export_lines(fetch, "csv", total=2)))))
    assert table[1][5] == "'=HYPERLINK(\"http://x\")" and table[2][5] == "'-2+3"


def test_an_export_stops_at_the_cap_and_says_how_many_were_left_out():
    import csv, io, json
    rows = [_view(i) for i in range(7)]
    fetch, _ = _batches(rows, size=3)
    table = list(csv.reader(io.StringIO("".join(ev.export_lines(fetch, "csv", total=7, cap=4)))))
    assert len(table) == 1 + 4 + 1
    assert table[-1] == ["# Export stopped at 4 of 7 events. Narrow the filters to export the rest."]
    fetch, _ = _batches(rows, size=3)
    lines = [json.loads(line) for line in ev.export_lines(fetch, "ndjson", total=7, cap=4)]
    assert [line.get("username") for line in lines[:4]] == ["user0", "user1", "user2", "user3"]
    assert lines[-1] == {"truncated": True, "exported": 4, "total": 7,
                         "message": "Export stopped at 4 of 7 events. Narrow the filters to export the rest."}


def test_a_complete_export_has_no_closing_note():
    import json
    fetch, _ = _batches([_view(i) for i in range(3)], size=3)
    lines = [json.loads(line) for line in ev.export_lines(fetch, "ndjson", total=3)]
    assert len(lines) == 3 and all("truncated" not in line for line in lines)


def test_an_export_ends_when_it_started():
    started = datetime(2026, 9, 26, 5, 0, 0)
    assert ev.export_filters(started=started)["end"] == started
    assert ev.export_filters(started=started, end=datetime(2027, 1, 1))["end"] == started
    earlier = datetime(2026, 9, 1)
    assert ev.export_filters(started=started, end=earlier, username="x") == {"end": earlier, "username": "x"}


def test_an_export_batch_continues_after_the_cursor_newest_first():
    cursor = (datetime(2026, 9, 26, 5, 0, 0), uuid.UUID(int=7))
    q = ev.export_page(Query(AuditLog), AuditLog, {"statuses": ["failed"]}, cursor, batch=3)
    compiled = q.statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "audit_logs.timestamp < %(timestamp_1)s" in sql and "audit_logs.id < %(id_1)s" in sql
    assert "ORDER BY audit_logs.timestamp DESC, audit_logs.id DESC" in sql
    assert compiled.params["param_1"] == 3 and compiled.params["timestamp_1"] == cursor[0]
    first = str(ev.export_page(Query(AuditLog), AuditLog, {}, None).statement.compile(dialect=postgresql.dialect()))
    assert "audit_logs.id <" not in first


def test_rows_gone_since_the_count_leave_no_closing_note():
    import json
    fetch, _ = _batches([_view(i) for i in range(3)], size=10)      # counted 5, two were deleted since
    lines = [json.loads(line) for line in ev.export_lines(fetch, "ndjson", total=5, cap=100)]
    assert len(lines) == 3 and all("truncated" not in line for line in lines)
