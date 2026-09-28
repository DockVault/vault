"""The Events tab's filters, paging and row view, without a database.

The SQL is checked by compiling the query for PostgreSQL and reading it; the live API tests run it."""
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Query

from app.core import audit_catalog
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
    assert v["automatic"] is False


def _stored(action, status, **extra):
    row = dict(id=uuid.uuid4(), timestamp=datetime(2026, 9, 26, 3, 4, 5), username=None, temp_credential_id=None,
               action=action, status=status, channel=None, ip_address=None, method=None, endpoint=None,
               user_agent=None, resource_type=None, resource_id=None, details=None, error_message=None)
    row.update(extra)
    return SimpleNamespace(**row)


@pytest.mark.parametrize("action, status, category, label, automatic", [
    ("account_auto_locked", "success", "sign_in", "New sign-ins paused after failed sign-ins", False),
    ("account_auto_unlocked", "success", "sign_in", "Sign-ins resumed", False),
    ("file_expired", "success", "files", "File deleted at its expiry", True),
    ("vault_self_access_refused", "refused", "security", "Self-granted vault access refused", False),
])
def test_the_lock_expiry_and_self_grant_events_are_named_and_filed(action, status, category, label, automatic):
    """The label the filters list for each event (a row with details may read more exactly, below)."""
    assert audit_catalog.label_for(action) == label
    v = ev.row_view(_stored(action, status, details={}))
    assert (v["label"], v["category"], v["automatic"]) == (
        audit_catalog.row_label(action, {}), category, automatic)
    assert f"'{action}'" in _sql(categories=[category])
    others = [k for k, _ in audit_catalog.CATEGORIES if k != category]
    assert f"'{action}'" not in _sql(categories=others)


@pytest.mark.parametrize("action, details, label", [
    ("account_auto_locked", {"scope": "address", "address": "10.0.0.7"}, "New sign-ins paused from one address"),
    ("account_auto_locked", {"scope": "account"}, "New sign-ins paused from every address"),
    ("account_auto_unlocked", {"scope": "address"}, "Sign-ins resumed"),
    ("account_auto_unlocked", {"scope": "account", "cleared_by": "timer"}, "Sign-ins resumed"),
    # Written before 0.33.0, with no scope: the lock then held the whole account.
    ("account_auto_locked", {"failed_attempts": 5}, "Account locked after failed sign-ins"),
    ("account_auto_unlocked", None, "Account unlocked when its lock ran out"),
])
def test_an_automatic_lock_reads_by_its_scope_in_the_users_pages_words(action, details, label):
    """Most automatic locks now pause new sign-ins from one address and leave sessions running: a row
    says so rather than "Account locked", and a search for its words finds it."""
    assert ev.row_view(_stored(action, "success", details=details))["label"] == label
    assert action in ev.actions_labelled(label.split(" from ")[0])


# Filter sets whose counts must put the lock, file-expiry and self-grant events where they belong: the
# Events filters as the page sends them for "failed sign-ins", "refusals and denials" and "failed or
# refused".
FILTER_SETS = {
    "Events": {},
    "Failed sign-ins": {"categories": ["sign_in"], "statuses": ["failed"]},
    "Refusals and denials": {"categories": ["security"]},
    "Failed or refused": {"statuses": ["failed"]},
}


def test_the_filters_count_locks_expiry_and_self_grant_refusals_where_they_belong():
    """Run through the Events query against rows held in memory. The lock is the outcome of failures
    already counted as failed sign-ins, and succeeds as a lock, so it is not a failed sign-in again; a
    file deleted at its expiry is an event and nothing else; a self-grant refused is a refusal."""
    from _memory_db import MemoryDB

    rows = [_stored(a, s) for a, s in (
        ("login_failure", "failure"),
        ("account_auto_locked", "success"),
        ("account_auto_unlocked", "success"),
        ("file_expired", "success"),
        ("vault_self_access_refused", "refused"),
    )]
    db = MemoryDB({AuditLog: rows})
    counted = {tile: sorted(r.action for r in ev.build_events_query(db.query(AuditLog), AuditLog, **f).all())
               for tile, f in FILTER_SETS.items()}
    assert counted == {
        "Events": sorted(r.action for r in rows),
        "Failed sign-ins": ["login_failure"],
        "Refusals and denials": ["vault_self_access_refused"],
        "Failed or refused": ["login_failure", "vault_self_access_refused"],
    }


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


class _SuggestionDb:
    """Holds one account, "ana-account", and would answer any read of the audit log with a typed name."""

    def __init__(self):
        self.log_reads = 0

    def query(self, *_cols):
        rows = [("ana-account", True)]

        class _Q:
            def filter(self, *_a):
                return self

            def order_by(self, *_a):
                return self

            def limit(self, _n):
                return self

            def all(self):
                return rows
        return _Q()

    def execute(self, *_a, **_k):
        self.log_reads += 1
        return SimpleNamespace(all=lambda: [("ana-Hunter2!Pass",)], scalar=lambda: "ana-Hunter2!Pass")


def test_the_username_typeahead_suggests_accounts_and_never_reads_the_log():
    """A name typed at a failed sign-in can hold a password: it is never suggested, and the log is not
    even read for suggestions."""
    db = _SuggestionDb()
    assert ev.username_suggestions(db, "ana", 10) == [{"username": "ana-account", "account": True, "active": True}]
    assert db.log_reads == 0
    assert ev.username_suggestions(db, "", 10) == []
