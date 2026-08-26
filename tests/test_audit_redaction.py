"""Audit-log at-rest redaction, exercised against a throwaway Postgres.

Names that are encrypted in their own tables (file/folder/vault names) must not be persisted in
cleartext in audit_logs.details. This drives the real AuditLogger.log_action against a disposable
database and asserts the persisted row carries no such name, while non-name context survives.
"""
import secrets
import shutil
import socket
import subprocess
import time
import uuid

import pytest

pytestmark = pytest.mark.unit

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
def _pg_engine():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    port = _free_port()
    subprocess.run(["docker", "rm", "-f", _PG_NAME], capture_output=True, text=True)
    up = subprocess.run(
        ["docker", "run", "-d", "--name", _PG_NAME,
         "-e", "POSTGRES_PASSWORD=" + _PG_PW, "-e", "POSTGRES_DB=" + _PG_DB,
         "-p", "%d:5432" % port, "postgres:15-alpine"],
        capture_output=True, text=True)
    if up.returncode != 0:
        pytest.skip("could not start throwaway postgres: %s" % up.stderr[:200])
    try:
        from sqlalchemy import create_engine, text
        from sqlalchemy.engine import URL
        from app.core.models import Base
        url = URL.create("postgresql+psycopg2", username="postgres", password=_PG_PW,
                         host="localhost", port=port, database=_PG_DB)
        engine, last_err = None, None
        for _ in range(45):
            try:
                candidate = create_engine(url)
                with candidate.connect() as conn:
                    conn.execute(text("SELECT 1"))
                engine = candidate
                break
            except Exception as exc:
                last_err = exc
                time.sleep(1)
        if engine is None:
            pytest.skip("throwaway postgres never accepted a real connection: %r" % last_err)
        Base.metadata.create_all(bind=engine)
        yield engine
        engine.dispose()
    finally:
        subprocess.run(["docker", "rm", "-f", _PG_NAME], capture_output=True, text=True)


@pytest.fixture
def db(_pg_engine):
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker
    session = sessionmaker(bind=_pg_engine)()
    session.execute(text("TRUNCATE TABLE audit_logs RESTART IDENTITY CASCADE"))
    session.commit()
    try:
        yield session
    finally:
        session.close()


@pytest.mark.docker
def test_audit_details_redact_names_but_keep_context(db):
    from app.core.models import AuditLog
    from app.services.audit_logger import AuditLogger
    vid = uuid.uuid4()
    AuditLogger(db).log_action(
        action="vault_created", status="success", username="admin",
        resource_type="vault", resource_id=str(vid),
        details={"vault_name": "Project Falcon", "file_name": "salaries.csv", "count": 3},
    )
    db.commit()
    row = db.query(AuditLog).filter(AuditLog.action == "vault_created").first()
    assert row is not None
    stored = row.details or {}
    assert "vault_name" not in stored, "vault_name must not persist in audit details at rest"
    assert "file_name" not in stored, "file_name must not persist in audit details at rest"
    assert stored.get("count") == 3, "non-name context must be preserved"
    assert row.resource_id == str(vid), "the vault is still identified by its UUID resource_id"
