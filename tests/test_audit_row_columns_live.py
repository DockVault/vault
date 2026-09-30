"""The audit row's new columns on a running stack's database.

audit_logs has seal_nonce, privacy_version, recorded, ip_via and case_id, and security_alerts has ip_via,
each nullable with no default, and the statements that add them were recorded as applied at start. A row
written now keeps them empty. test_audit_row_columns.py checks the model, the statements and the hooks
offline.
"""
import uuid

import pytest
import requests

from _account_change_helpers import psql
from conftest import BASE_URL

EXPECTED = {
    ("audit_logs", "seal_nonce"): ("bytea", None),
    ("audit_logs", "privacy_version"): ("integer", None),
    ("audit_logs", "recorded"): ("jsonb", None),
    ("audit_logs", "ip_via"): ("character varying", 24),
    ("audit_logs", "case_id"): ("uuid", None),
    ("security_alerts", "ip_via"): ("character varying", 24),
}


def test_the_columns_are_there_nullable_and_without_a_default():
    rows = psql(
        "SELECT table_name, column_name, data_type, coalesce(character_maximum_length::text, ''), "
        "is_nullable, coalesce(column_default, '') FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND (table_name, column_name) IN ("
        + ", ".join(f"('{t}', '{c}')" for t, c in EXPECTED) + ") ORDER BY 1, 2")
    found = {}
    for line in rows.splitlines():
        table, column, data_type, length, nullable, default = line.split("|")
        found[(table, column)] = (data_type, int(length) if length else None, nullable, default)
    assert set(found) == set(EXPECTED), sorted(set(EXPECTED) - set(found))
    for key, (data_type, length) in EXPECTED.items():
        assert found[key] == (data_type, length, "YES", ""), (key, found[key])


def test_the_statements_that_add_them_were_recorded_as_applied():
    rows = psql("SELECT summary, outcome FROM schema_steps WHERE summary LIKE 'ALTER TABLE audit_logs ADD "
                "COLUMN IF NOT EXISTS seal_nonce%' OR summary = 'ALTER TABLE security_alerts ADD COLUMN IF "
                "NOT EXISTS ip_via VARCHAR(24)' ORDER BY summary")
    lines = rows.splitlines()
    assert len(lines) == 2, rows
    assert all(line.endswith("|applied") for line in lines), rows


def test_a_row_written_now_has_its_id_and_leaves_them_empty():
    name = f"nobody-{uuid.uuid4().hex[:10]}"
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": name, "password": "not-the-password"},
                      timeout=30)
    assert r.status_code in (401, 429), r.status_code
    out = psql("SELECT id, seal_nonce IS NULL, privacy_version IS NULL, recorded IS NULL, ip_via IS NULL, "
               f"case_id IS NULL FROM audit_logs WHERE username = '{name}'")
    lines = out.splitlines()
    assert lines, "the failed sign-in wrote no audit row"
    for line in lines:
        row_id, *empty = line.split("|")
        assert uuid.UUID(row_id).version == 4
        assert empty == ["t"] * 5, line
