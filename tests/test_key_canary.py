"""The startup key canary refuses to boot when the configured ENCRYPTION_KEY cannot open the data this
deployment sealed, without ever bricking a healthy one.

A one-row canary in system_settings is seeded under the deployment key on first sight, then verified on
every later boot. A definitive wrong-key signal is fatal (EncryptionKeyMismatch); ambiguous conditions
are non-fatal. These run against a throwaway Postgres so the real ORM + a real DB exercise it end to end.
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
    except Exception:                     # noqa: BLE001 - teardown must never fail the suite
        pass


_PG_NAME = "dvhx-pg-canary"
_PG_PW = secrets.token_hex(16)
_PG_DB = "canarydb"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _load_fernet_ok():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def _pg():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if _load_fernet_ok() is False:
        pytest.skip("cryptography not available")
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


def _clear_canary(s):
    from app.core.models import SystemSetting
    from app.core.key_canary import _CANARY_KEY
    s.query(SystemSetting).filter(SystemSetting.key == _CANARY_KEY).delete()
    s.commit()


@pytest.mark.docker
def test_canary_seeds_on_first_sight_then_verifies_ok(_pg):
    from app.core.key_canary import verify_or_seed_key_canary, _CANARY_KEY
    from app.core.models import SystemSetting
    s = _session(_pg)
    try:
        _clear_canary(s)
        # First sight: no row -> seed under the current key.
        assert verify_or_seed_key_canary(s) == "seeded"
        row = s.query(SystemSetting).filter(SystemSetting.key == _CANARY_KEY).first()
        assert row is not None and row.value.get("ct"), "a canary ciphertext was stored"
        # Every later boot with the SAME key verifies clean.
        assert verify_or_seed_key_canary(s) == "ok"
        assert verify_or_seed_key_canary(s) == "ok"
    finally:
        _clear_canary(s)
        s.close()


@pytest.mark.docker
def test_canary_refuses_boot_on_a_wrong_key(_pg):
    """A canary sealed under a DIFFERENT key stands in for a wrong-key boot: the current key cannot
    open it, so the guard must raise rather than let a migration run under a key that would corrupt."""
    from cryptography.fernet import Fernet
    from app.core.key_canary import (verify_or_seed_key_canary, EncryptionKeyMismatch,
                                      _CANARY_KEY, _CANARY_PLAINTEXT)
    from app.core.models import SystemSetting
    s = _session(_pg)
    try:
        _clear_canary(s)
        foreign_ct = Fernet(Fernet.generate_key()).encrypt(_CANARY_PLAINTEXT).decode("ascii")
        s.add(SystemSetting(key=_CANARY_KEY, value={"ct": foreign_ct, "v": 1}))
        s.commit()
        with pytest.raises(EncryptionKeyMismatch):
            verify_or_seed_key_canary(s)
    finally:
        _clear_canary(s)
        s.close()


@pytest.mark.docker
def test_canary_row_without_ciphertext_is_not_fatal(_pg):
    """A malformed canary row (no ciphertext) cannot be verified but must NOT brick a deployment --
    the guard is defense-in-depth, never a new failure mode."""
    from app.core.key_canary import verify_or_seed_key_canary, _CANARY_KEY
    from app.core.models import SystemSetting
    s = _session(_pg)
    try:
        _clear_canary(s)
        s.add(SystemSetting(key=_CANARY_KEY, value={}))
        s.commit()
        assert verify_or_seed_key_canary(s) == "skipped:no-ct"
    finally:
        _clear_canary(s)
        s.close()
