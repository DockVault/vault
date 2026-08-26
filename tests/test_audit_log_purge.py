"""The one-time boot purge strips residual plaintext names from legacy audit-log rows.

The AuditLogger redacts file/folder/old/new/vault_name from an audit row's details before storing it;
rows written before that carry the names in the clear. purge_audit_log_names removes them once (a
system_settings marker makes it a no-op afterwards). Runs against a throwaway Postgres.
"""
from __future__ import annotations

import base64
import os
import secrets
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module", autouse=True)
def _runtime_secrets():
    previous = {k: os.environ.get(k) for k in ("ENCRYPTION_KEY", "DATABASE_URL", "JWT_SECRET_KEY")}
    os.environ.setdefault("ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost/db")
    os.environ.setdefault("JWT_SECRET_KEY", secrets.token_hex(32))
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        from app.core import config as _config
        _config._runtime_initialized = False
    except Exception:                     # noqa: BLE001
        pass


_PG_NAME = "dvhx-pg-audit"
_PG_PW = secrets.token_hex(16)
_PG_DB = "auditdb"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def _pg():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    port = _free_port()
    subprocess.run(["docker", "rm", "-f", _PG_NAME], capture_output=True, text=True)
    up = subprocess.run(
        ["docker", "run", "-d", "--name", _PG_NAME, "-e", "POSTGRES_PASSWORD=" + _PG_PW,
         "-e", "POSTGRES_DB=" + _PG_DB, "-p", "%d:5432" % port, "postgres:15-alpine"],
        capture_output=True, text=True)
    if up.returncode != 0:
        pytest.skip("could not start throwaway postgres: %s" % up.stderr[:200])
    try:
        from sqlalchemy import create_engine, text
        from sqlalchemy.engine import URL
        from app.core.models import Base
        url = URL.create("postgresql+psycopg2", username="postgres", password=_PG_PW,
                         host="localhost", port=port, database=_PG_DB)
        engine, last = None, None
        for _ in range(45):
            try:
                cand = create_engine(url)
                with cand.connect() as c:
                    c.execute(text("SELECT 1"))
                engine = cand
                break
            except Exception as exc:
                last = exc
                time.sleep(1)
        if engine is None:
            pytest.skip("throwaway postgres never accepted a connection: %r" % last)
        Base.metadata.create_all(bind=engine)
        yield engine
        engine.dispose()
    finally:
        subprocess.run(["docker", "rm", "-f", _PG_NAME], capture_output=True, text=True)


def _session(engine):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=engine)()


@pytest.mark.docker
def test_purge_strips_legacy_names_keeps_other_keys_and_is_idempotent(_pg):
    from app.core.models import AuditLog, SystemSetting
    from app.core.audit_migrations import purge_audit_log_names, _MARKER_KEY
    s = _session(_pg)
    try:
        # Legacy rows carrying residual names (as written before the AuditLogger redacted them).
        a = AuditLog(action="vault.rename", status="success",
                     details={"vault_name": "Merger Q3", "old_name": "Merger",
                              "new_name": "Merger Q3", "resource_id": "v1", "ok": True})
        b = AuditLog(action="file.upload", status="success",
                     details={"file_name": "salaries.csv", "folder_name": "HR", "size": 42})
        c = AuditLog(action="login", status="success", details={"ip": "10.0.0.1"})  # no names
        s.add_all([a, b, c])
        s.commit()
        aid, bid, cid = a.id, b.id, c.id

        assert purge_audit_log_names(s) == 2, "only the two rows carrying name keys are updated"

        s.expire_all()
        da = s.get(AuditLog, aid).details
        assert not any(k in da for k in ("vault_name", "old_name", "new_name")), "name keys stripped"
        assert da.get("resource_id") == "v1" and da.get("ok") is True, "non-name keys preserved"
        db_ = s.get(AuditLog, bid).details
        assert "file_name" not in db_ and "folder_name" not in db_ and db_.get("size") == 42
        assert s.get(AuditLog, cid).details == {"ip": "10.0.0.1"}, "a name-less row is untouched"

        # A marker is set, so the table is never scanned again -> a second run is a no-op.
        assert s.query(SystemSetting).filter(SystemSetting.key == _MARKER_KEY).first() is not None
        assert purge_audit_log_names(s) == 0
    finally:
        s.close()


@pytest.mark.docker
def test_purge_on_a_clean_db_sets_the_marker(_pg):
    """No legacy rows -> nothing updated, but the marker is still set so later boots don't rescan."""
    from app.core.models import SystemSetting
    from app.core.audit_migrations import purge_audit_log_names, _MARKER_KEY
    s = _session(_pg)
    try:
        # Ensure a clean slate for this assertion (the module test above may have set the marker).
        s.query(SystemSetting).filter(SystemSetting.key == _MARKER_KEY).delete()
        s.commit()
        assert purge_audit_log_names(s) == 0
        assert s.query(SystemSetting).filter(SystemSetting.key == _MARKER_KEY).first() is not None
    finally:
        s.close()
