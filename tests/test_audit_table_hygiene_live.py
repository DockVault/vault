"""The audit table's upkeep on a running stack (app/core/background_maintenance.py).

Once background maintenance has run after the start, the audit log's timestamp has one index, and the
table's autovacuum acts after 2 % of its rows changed. On a stack first made by a release that built the
duplicate index, the start drops it; on a fresh one it was never built. test_audit_table_hygiene.py covers
the steps offline.
"""
import time

import pytest

from _account_change_helpers import psql

pytestmark = pytest.mark.integration


def _timestamp_indexes():
    return sorted(psql("SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = "
                       "'audit_logs' AND indexdef LIKE '%(\"timestamp\")'").split())


def _options():
    return psql("SELECT coalesce(array_to_string(reloptions, ','), '') FROM pg_class c JOIN pg_namespace n ON "
                "n.oid = c.relnamespace WHERE c.relname = 'audit_logs' AND n.nspname = current_schema()")


def test_after_the_start_the_timestamp_is_indexed_once_and_autovacuum_is_tuned():
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and (_timestamp_indexes() != ["idx_audit_timestamp"]
                                           or "autovacuum_vacuum_scale_factor=0.02" not in _options()):
        time.sleep(2)
    assert _timestamp_indexes() == ["idx_audit_timestamp"]
    options = _options().split(",")
    assert {"autovacuum_vacuum_scale_factor=0.02", "autovacuum_analyze_scale_factor=0.02"} <= set(options)
    assert psql("SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                "WHERE c.relname = 'idx_audit_timestamp' AND i.indisvalid") == "1"
