"""Clean upgrade from a v0.16.1-shaped schema: dropping temporary_credentials.encrypted_password.

Simulates a pre-upgrade install (the deprecated column present, with a stale value in a real row),
applies the boot-DDL drop, and asserts the column and its data are gone while the row's other columns
survive - and that re-applying the drop is a no-op (idempotent, as the boot DDL runs every start).
"""
import secrets
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.unit

_PG_NAME = "dvhx-pg-dropcol"
_PG_PW = secrets.token_hex(16)
_PG_DB = "dropcoldb"

_DROP_DDL = "ALTER TABLE temporary_credentials DROP COLUMN IF EXISTS encrypted_password"


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


def _columns(conn, table):
    from sqlalchemy import text
    return [r[0] for r in conn.execute(text(
        "SELECT column_name FROM information_schema.columns WHERE table_name=:t"), {"t": table})]


@pytest.mark.docker
def test_clean_upgrade_drops_encrypted_password_and_keeps_data(_pg_engine):
    from sqlalchemy import text
    import uuid
    from datetime import datetime, timedelta, timezone
    from app.core.models import RoleEnum, TemporaryCredential, User
    from sqlalchemy.orm import sessionmaker

    # Simulate a v0.16.1 install: re-add the deprecated column the current model no longer declares.
    with _pg_engine.begin() as conn:
        if "encrypted_password" not in _columns(conn, "temporary_credentials"):
            conn.execute(text("ALTER TABLE temporary_credentials ADD COLUMN encrypted_password TEXT"))
        assert "encrypted_password" in _columns(conn, "temporary_credentials")

    # A real user + temp-credential row, then a stale ciphertext in the deprecated column (raw, since
    # the ORM model no longer maps it) - so we can prove the row's OTHER data survives the drop.
    session = sessionmaker(bind=_pg_engine)()
    try:
        user = User(username="upg_user_" + secrets.token_hex(3),
                    email="upg_%s@example.co" % secrets.token_hex(3),
                    password_hash="x", role=RoleEnum.USER)
        session.add(user)
        session.flush()
        now = datetime.now(timezone.utc)
        cred = TemporaryCredential(user_id=user.id, temp_username="upg_tc_" + secrets.token_hex(3),
                                   credential_hash="chash", deactivate_at=now + timedelta(minutes=20),
                                   expires_at=now + timedelta(hours=1))
        session.add(cred)
        session.commit()
        tc_name = cred.temp_username
        session.execute(text("UPDATE temporary_credentials SET encrypted_password='STALE-CIPHERTEXT' "
                             "WHERE temp_username=:n"), {"n": tc_name})
        session.commit()
    finally:
        session.close()

    # Apply the boot-DDL drop TWICE - it runs on every boot, so it must be idempotent.
    with _pg_engine.begin() as conn:
        conn.execute(text(_DROP_DDL))
        conn.execute(text(_DROP_DDL))

    # The column and its data are gone; sibling columns and the row survive.
    with _pg_engine.begin() as conn:
        cols = _columns(conn, "temporary_credentials")
        assert "encrypted_password" not in cols, "the deprecated column must be dropped"
        assert "credential_hash" in cols and "password_shown" in cols, "sibling columns must survive"
        row = conn.execute(text("SELECT temp_username, credential_hash FROM temporary_credentials "
                                "WHERE temp_username=:n"), {"n": tc_name}).first()
        assert row is not None and row[0] == tc_name and row[1] == "chash", "the row's data must survive"


@pytest.mark.docker
def test_drop_is_a_clean_noop_on_a_fresh_schema(_pg_engine):
    # A fresh install's model never declared encrypted_password, so the drop must be a clean no-op.
    from sqlalchemy import text
    with _pg_engine.begin() as conn:
        conn.execute(text(_DROP_DDL))          # column already absent on the current schema
        assert "encrypted_password" not in _columns(conn, "temporary_credentials")
