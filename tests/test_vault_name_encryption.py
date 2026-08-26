"""A Standard vault's name is sealed at rest and read back transparently.

`Vault.name` was plaintext at rest, and it is used as the SFTP directory name -- so a read that ever
saw a sealed blob instead of the plaintext would rename a live customer's SFTP directory. Now a
Standard vault stores its name in `enc_name` (AES-GCM, per-vault key) with the plaintext column
NULL, a load/refresh event decrypts it back into `name`, and a boot backfill seals legacy rows.
ZK vaults are left untouched (their name is browser-sealed in a later phase).

Runs against a throwaway Postgres so the real ORM load event + a real DB exercise the whole chain.
"""
from __future__ import annotations

import base64
import os
import secrets
import shutil
import socket
import subprocess
import time
import uuid

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


_PG_NAME = "dvhx-pg-vaultname"
_PG_PW = secrets.token_hex(16)
_PG_DB = "vaultnamedb"


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close(); return port


def _crypto_ok():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def _pg():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if not _crypto_ok():
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


def _a_user(session):
    from app.core.models import RoleEnum, User
    u = User(username="v_" + secrets.token_hex(3), email="v_%s@example.co" % secrets.token_hex(3),
             password_hash="x", role=RoleEnum.USER)
    session.add(u); session.flush(); return u


def _raw(engine, field, vault_id):
    from sqlalchemy import text
    with engine.connect() as c:
        return c.execute(text("SELECT %s FROM vaults WHERE id=:i" % field), {"i": str(vault_id)}).scalar()


def _mk_vault(session, owner, name, vtype="standard"):
    from app.core.models import Vault
    from app.services.vault_service import _seal_vault_name
    v = Vault(id=uuid.uuid4(), owner_id=owner.id, type=vtype)
    _seal_vault_name(v, name)                 # seals (Standard) or leaves plaintext (ZK)
    session.add(v); session.commit(); return v


@pytest.mark.docker
def test_a_standard_vault_name_is_sealed_and_reads_back(_pg):
    from app.core.models import Vault
    s = _session(_pg)
    try:
        u = _a_user(s)
        v = _mk_vault(s, u, "Finance Vault")
        vid = v.id
        assert _raw(_pg, "enc_name", vid), "enc_name is populated at rest"
        assert _raw(_pg, "name", vid) is None, "the plaintext name column is NULL at rest"
        s.expire_all()
        got = s.get(Vault, vid)
        assert got.name == "Finance Vault", "the load event decrypts the name transparently"
        # This is exactly what the SFTP layer reads for the directory name; must be the plaintext.
        assert (got.name or f"vault_{got.id}") == "Finance Vault"
    finally:
        s.close()


@pytest.mark.docker
def test_rename_reseals_the_name(_pg):
    from app.core.models import Vault
    s = _session(_pg)
    try:
        u = _a_user(s)
        v = _mk_vault(s, u, "Old Name")
        vid = v.id
        before = _raw(_pg, "enc_name", vid)
        # Rename via the same seal helper (what update_vault / the rename endpoint call).
        from app.services.vault_service import _seal_vault_name
        v2 = s.get(Vault, vid)
        _seal_vault_name(v2, "New Name")
        s.commit()
        assert _raw(_pg, "enc_name", vid) != before, "the rename re-seals"
        assert _raw(_pg, "name", vid) is None
        s.expire_all()
        assert s.get(Vault, vid).name == "New Name"
    finally:
        s.close()


@pytest.mark.docker
def test_a_zero_knowledge_vault_name_is_not_sealed_by_this_phase(_pg):
    from app.core.models import Vault
    s = _session(_pg)
    try:
        u = _a_user(s)
        v = _mk_vault(s, u, "ZK Project", vtype="zero_knowledge")
        vid = v.id
        assert _raw(_pg, "name", vid) == "ZK Project", "ZK name stays plaintext (browser-sealed later)"
        assert _raw(_pg, "enc_name", vid) is None, "this phase does not seal ZK vaults"
        s.expire_all()
        assert s.get(Vault, vid).name == "ZK Project"
    finally:
        s.close()


@pytest.mark.docker
def test_backfill_seals_legacy_plaintext_and_is_idempotent(_pg):
    from sqlalchemy import text
    from app.core.models import Vault
    from app.services.vault_service import _seal_vault_name
    s = _session(_pg)
    try:
        u = _a_user(s)
        # A LEGACY plaintext Standard vault written via raw SQL (bypassing the seal helper).
        vid = uuid.uuid4()
        s.execute(text("INSERT INTO vaults (id, owner_id, name, type, team_key_version, dek_version, "
                       "created_at, updated_at) VALUES (:i,:o,:n,'standard',1,1,now(),now())"),
                  {"i": str(vid), "o": str(u.id), "n": "Legacy Vault"})
        s.commit()
        assert _raw(_pg, "name", vid) == "Legacy Vault" and _raw(_pg, "enc_name", vid) is None

        # The backfill loop (as in _backfill_encrypted_names): seal standard vaults with enc_name NULL.
        def _run_backfill():
            sealed = 0
            for v in s.query(Vault).filter(Vault.type == "standard").all():
                if getattr(v, "enc_name", None) is None and v.name is not None:
                    _seal_vault_name(v, v.name)
                    sealed += 1
            s.commit()
            return sealed

        assert _run_backfill() >= 1
        assert _raw(_pg, "enc_name", vid), "backfill sealed the legacy row"
        assert _raw(_pg, "name", vid) is None
        s.expire_all()
        assert s.get(Vault, vid).name == "Legacy Vault", "still reads back as the original plaintext"
        # Idempotent: a second run finds nothing to seal (load event set name from enc_name, but the
        # raw enc_name is already set, so the filter/skip holds).
        s.expire_all()
        assert _run_backfill() == 0
    finally:
        s.close()


def test_wrong_vault_decrypt_raises():
    if not _crypto_ok():
        pytest.skip("cryptography not available")
    from app.core.security import encrypt_object_field, decrypt_object_field
    a, b = uuid.uuid4(), uuid.uuid4()
    token = encrypt_object_field(a, a, "Secret", "name")
    assert decrypt_object_field(a, a, token, "name") == "Secret"
    with pytest.raises(Exception):
        decrypt_object_field(b, b, token, "name")          # wrong vault -> key/AAD mismatch
