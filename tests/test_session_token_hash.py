"""Session tokens are stored as their SHA-256 hash at rest, and legacy rows are rehashed at boot.

A database read must not yield a usable session credential. Tokens are hashed before storage; the
plaintext lives only in the client's JWT, and verification hashes the presented token to match the
stored row. A one-time boot migration converts any pre-existing plaintext row to its hash WITHOUT
logging anyone out (the client still holds the plaintext).

The boot rehash is exercised end-to-end against a throwaway Postgres; the auth-flow invariants that
are too heavy to import (they pull the whole app / its credential validation) are pinned from source.
"""
from __future__ import annotations

import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# --- the hashing model (pure) -------------------------------------------------------------------

def test_a_token_is_stored_as_its_hash_and_verified_by_hashing_the_presented_token():
    from app.core.session_hash_utils import hash_session_token, is_token_hashed
    from app.core.security import generate_session_token

    token = generate_session_token()
    at_rest = hash_session_token(token)
    assert at_rest != token, "the stored value must not be the plaintext token"
    assert is_token_hashed(at_rest) and not is_token_hashed(token)
    # verification: hash the presented token and compare to the stored value
    assert hash_session_token(token) == at_rest
    assert hash_session_token(token + "x") != at_rest


# --- the boot rehash (throwaway Postgres) -------------------------------------------------------

_PG_NAME = "dvhx-pg-sesshash"
_PG_PW = secrets.token_hex(16)
_PG_DB = "sesshashdb"


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


@pytest.mark.docker
def test_boot_rehash_hashes_a_legacy_plaintext_token_without_logging_out(_pg_engine):
    from sqlalchemy.orm import sessionmaker
    from app.core.models import RoleEnum, User, ActiveSession
    from app.core.security import generate_session_token
    from app.core.session_hash_utils import hash_session_token, is_token_hashed
    from app.core.session_migrations import rehash_plaintext_session_tokens

    session = sessionmaker(bind=_pg_engine)()
    try:
        user = User(username="sess_" + secrets.token_hex(3),
                    email="sess_%s@example.co" % secrets.token_hex(3),
                    password_hash="x", role=RoleEnum.USER)
        session.add(user)
        session.flush()

        # A pre-upgrade session: the token is stored in PLAINTEXT.
        legacy_plaintext = generate_session_token()
        legacy = ActiveSession(session_token=legacy_plaintext, user_id=user.id, ip_address="10.0.0.1")
        # A session written after the upgrade already stores the hash.
        already_plaintext = generate_session_token()
        modern = ActiveSession(session_token=hash_session_token(already_plaintext),
                               user_id=user.id, ip_address="10.0.0.2")
        session.add_all([legacy, modern])
        session.commit()
        legacy_id, modern_id = legacy.id, modern.id
        modern_stored_before = modern.session_token

        # Boot migration.
        n = rehash_plaintext_session_tokens(session)
        session.commit()
        assert n == 1, "exactly the one plaintext row is rehashed"

        session.expire_all()
        legacy = session.get(ActiveSession, legacy_id)
        modern = session.get(ActiveSession, modern_id)
        # The legacy row now holds the hash of its old plaintext...
        assert legacy.session_token == hash_session_token(legacy_plaintext)
        assert is_token_hashed(legacy.session_token)
        # ...and the client that still holds the plaintext verifies against it (no forced logout).
        found = session.query(ActiveSession).filter(
            ActiveSession.session_token == hash_session_token(legacy_plaintext)).first()
        assert found is not None and found.id == legacy_id
        # The already-hashed row is untouched (not double-hashed).
        assert modern.session_token == modern_stored_before

        # Idempotent: a second run changes nothing.
        assert rehash_plaintext_session_tokens(session) == 0
    finally:
        session.close()


# --- the auth-flow invariants (pinned from source) ----------------------------------------------

def test_create_session_stores_the_hash_not_the_plaintext():
    src = _read("app/services/auth_service.py")
    assert "session_token=hash_session_token(session_token)" in src, (
        "_create_session must persist the hash, not the raw token")


def test_verify_session_matches_on_the_hash_and_fails_closed_on_revocation():
    src = _read("app/services/auth_service.py")
    # DB fallback matches the stored hash and excludes revoked rows
    assert "ActiveSession.session_token == hash_session_token(session_token)" in src
    assert re.search(r"ActiveSession\.revoked == False", src), "the DB fallback must exclude revoked"
    # the Redis-cache short-circuit also re-checks revoked (fail closed)
    assert "session.is_active and not session.revoked" in src, (
        "the cache path must reject a session revoked after it was cached")


def test_terminate_uses_the_stored_hash_directly_no_double_hash():
    src = _read("app/services/auth_service.py")
    assert 'redis_key = f"session:{session.session_token}"' in src, (
        "the Redis key is derived from the stored hash directly; re-hashing it would miss the key")
    assert "hash_session_token(session.session_token)" not in src, "must not double-hash a stored row"


def test_the_rehash_runs_at_boot():
    """Pin the CALL, not just the definition: a migration that is defined but never invoked leaves
    plaintext tokens at rest. Scope to the lifespan body so the def line can't satisfy this."""
    src = _read("app/api/api_server.py")
    start = src.index("async def lifespan")
    end = src.index("app.router.lifespan_context", start)   # the line that installs the lifespan
    lifespan_body = src[start:end]
    assert "_rehash_plaintext_session_tokens()" in lifespan_body, (
        "the boot rehash must be CALLED inside lifespan, not merely defined")


def test_no_plaintext_session_token_comparison_survives():
    """Every ActiveSession.session_token comparison, in ANY app module, must go through
    hash_session_token — globbed rather than a fixed file list so a new module can't reintroduce a
    plaintext comparison unguarded. (\\s* spans newlines, so a wrapped right-hand side is caught.)"""
    scanned = 0
    for path in sorted((ROOT / "app").glob("**/*.py")):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\.session_token ==\s*([^\n]+)", src):
            scanned += 1
            rhs = m.group(1)
            assert "hash_session_token" in rhs, (
                "%s compares session_token against a non-hashed value: %s"
                % (path.relative_to(ROOT), rhs.strip()))
    assert scanned >= 8, "expected the known session_token comparison sites to be scanned, got %d" % scanned
