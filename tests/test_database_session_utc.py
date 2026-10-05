"""Every app connection's session runs in UTC, offline.

The timestamp columns hold UTC with no zone attached, and a zone-aware value bound into one (the audit
log's time, a permission's grant time, a comparison with "now") is converted through the session's time
zone, which was the database's. On a database set to another zone those values were off by its offset.
The engine now sets the session's zone to UTC on every connection, beside its lock timeout.
test_database_session_utc_live.py checks it on a running stack whose database is set behind UTC.
"""
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import database  # noqa: E402

pytestmark = pytest.mark.unit


def test_every_connection_runs_its_session_in_utc(monkeypatch):
    seen = {}

    def fake_create_engine(url, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr(database, "create_engine", fake_create_engine)
    monkeypatch.setattr(database, "_engine", None)
    monkeypatch.setattr(database.settings, "database_url", "postgresql://u:p@db:5432/x")
    monkeypatch.setattr(database, "runtime_is_initialized", lambda: True)
    with pytest.raises(Exception):
        database.initialize_consumers()
    options = seen["connect_args"]["options"].split()
    assert options.count("-c") == 2
    assert "timezone=UTC" in options and f"lock_timeout={database._LOCK_TIMEOUT_MS}" in options
