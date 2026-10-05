"""The audit table's upkeep (app/core/background_maintenance.py, app/core/models.py), offline.

The audit log's timestamp is indexed once, by idx_audit_timestamp: a new schema no longer builds the second,
identical ix_audit_logs_timestamp, and background maintenance drops it, concurrently, from an install made
before. The same maintenance sets the table's autovacuum to act after 2 % of its rows changed. Both are
background steps, which never wait for a lock without a timeout (test_background_maintenance.py).
"""
import pytest
import sqlalchemy as sa

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import background_maintenance as BM  # noqa: E402
from app.core.models import AuditLog  # noqa: E402

pytestmark = pytest.mark.unit


def test_a_new_schema_indexes_the_audit_timestamp_once():
    on_timestamp = [ix.name for ix in AuditLog.__table__.indexes if [c.name for c in ix.columns] == ["timestamp"]]
    assert on_timestamp == ["idx_audit_timestamp"]
    assert not AuditLog.__table__.c.timestamp.index


def test_the_create_statements_hold_one_timestamp_index():
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex
    created = [str(CreateIndex(ix).compile(dialect=postgresql.dialect())) for ix in AuditLog.__table__.indexes]
    assert [s for s in created if s.endswith("(timestamp)")] == [
        "CREATE INDEX idx_audit_timestamp ON audit_logs (timestamp)"]


def test_background_maintenance_drops_the_duplicate_and_tunes_autovacuum():
    steps = {step.name: step for step in BM.STEPS}
    drop = steps["ix_audit_logs_timestamp"]
    assert (drop.kind, drop.sql) == (BM.DROP_INDEX, "DROP INDEX CONCURRENTLY IF EXISTS ix_audit_logs_timestamp")
    tune = steps["audit_logs_autovacuum"]
    assert tune.kind == BM.STATEMENT
    assert tune.sql == ("ALTER TABLE audit_logs SET (autovacuum_vacuum_scale_factor = 0.02, "
                        "autovacuum_analyze_scale_factor = 0.02)")
    for option in ("autovacuum_vacuum_scale_factor=0.02", "autovacuum_analyze_scale_factor=0.02"):
        assert option in tune.done_sql
    assert "current_schema()" in tune.done_sql
    assert "idx_audit_timestamp" not in steps


def test_the_steps_are_not_schema_steps():
    # A schema step would run at start, holding its lock while audit writes wait; these run afterwards.
    from app.api import api_server as api
    import inspect
    migrations = inspect.getsource(api._run_lightweight_migrations)
    assert "ix_audit_logs_timestamp" not in migrations and "autovacuum" not in migrations
