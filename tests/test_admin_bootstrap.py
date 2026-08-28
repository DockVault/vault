"""Admin seed-once bootstrap, exercised against a throwaway Postgres.

The host runs a fixed-name live vault-db, so a second full stack can't run beside it; instead these
tests stand up a UNIQUE-named throwaway postgres, create the schema from the models, and drive
app.core.admin_bootstrap.bootstrap_admin directly. Marked `unit` (module) + `docker` (each test) so
the offline lane skips them and the Docker-capable lane runs them.
"""
import secrets
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.unit

_PG_NAME = "dvhx-pg-bootstrap"
_PG_PW = secrets.token_hex(16)   # generated per run, never a hard-coded secret literal
_PG_DB = "bootstrapdb"


def _test_pw():
    """A random, policy-compliant throwaway password (keeps hard-coded secret literals out of tests)."""
    return "Aa1!" + secrets.token_urlsafe(18)


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
        # Build the URL with the password as a parameter (not embedded in the string) so no credential
        # literal appears in source.
        url = URL.create("postgresql+psycopg2", username="postgres", password=_PG_PW,
                         host="localhost", port=port, database=_PG_DB)
        # Retry a REAL connection: the postgres entrypoint starts a temporary init server (which
        # pg_isready can accept), then restarts for real, so the reliable readiness signal is an actual
        # SELECT succeeding, not pg_isready.
        engine, last_err = None, None
        for _ in range(45):
            try:
                candidate = create_engine(url)
                with candidate.connect() as conn:
                    conn.execute(text("SELECT 1"))
                engine = candidate
                break
            except Exception as exc:  # OperationalError during the initdb restart window
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
    # Fresh state per test: truncate the tables these tests touch (CASCADE clears any user-linked rows).
    session.execute(text("TRUNCATE TABLE users, system_settings RESTART IDENTITY CASCADE"))
    session.commit()
    try:
        yield session
    finally:
        session.close()


def _set_admin_env(monkeypatch, username, password=None, email="admin@example.co"):
    from app.core.config import settings
    monkeypatch.setattr(settings, "admin_username", username)
    monkeypatch.setattr(settings, "admin_password", _test_pw() if password is None else password)
    monkeypatch.setattr(settings, "admin_email", email)


def _admin_count(db):
    from app.core.models import RoleEnum, User
    return db.query(User).filter(User.role == RoleEnum.ADMIN).count()


def _marker_present(db):
    from app.core.admin_bootstrap import ADMIN_BOOTSTRAP_MARKER
    from app.core.models import SystemSetting
    return db.query(SystemSetting).filter(SystemSetting.key == ADMIN_BOOTSTRAP_MARKER).first() is not None


@pytest.mark.docker
def test_seeds_once_then_changed_username_is_refused(db, monkeypatch):
    from app.core.admin_bootstrap import bootstrap_admin
    from app.core.models import RoleEnum, User
    _set_admin_env(monkeypatch, "admin")
    assert bootstrap_admin(db) == "seeded"
    assert _admin_count(db) == 1 and _marker_present(db)
    # A later boot with a DIFFERENT ADMIN_USERNAME must NOT mint a second admin (the injection).
    _set_admin_env(monkeypatch, "attacker_admin")
    assert bootstrap_admin(db) == "already-bootstrapped"
    admins = db.query(User).filter(User.role == RoleEnum.ADMIN).all()
    assert len(admins) == 1 and admins[0].username == "admin", "a changed ADMIN_USERNAME must not inject a new admin"


@pytest.mark.docker
def test_pre_existing_admin_is_marked_not_seeded(db, monkeypatch):
    from app.core.admin_bootstrap import bootstrap_admin
    from app.core.models import RoleEnum
    from app.services.auth_service import AuthService
    # A deployment that already has an admin but no marker (predates this fix).
    AuthService(db).create_user(username="owner", email="owner@example.co",
                                password=_test_pw(), role=RoleEnum.ADMIN)
    db.commit()
    _set_admin_env(monkeypatch, "attacker_admin")
    assert bootstrap_admin(db) == "marked-existing"
    assert _admin_count(db) == 1 and _marker_present(db)   # no new admin, marker now set


@pytest.mark.docker
def test_no_password_does_not_mark_so_a_later_boot_can_seed(db, monkeypatch):
    from app.core.admin_bootstrap import bootstrap_admin
    _set_admin_env(monkeypatch, "admin", password="   ")   # whitespace == blank
    assert bootstrap_admin(db) == "no-password"
    assert not _marker_present(db) and _admin_count(db) == 0
    # A later boot WITH a password bootstraps the first admin (password=None -> generated).
    _set_admin_env(monkeypatch, "admin")
    assert bootstrap_admin(db) == "seeded"
    assert _admin_count(db) == 1 and _marker_present(db)
