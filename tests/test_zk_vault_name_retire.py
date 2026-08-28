"""The retire-version floor must count a zero-knowledge vault's OWN sealed-name epoch.

A ZK vault name/description is sealed under a DEK epoch (vaults.name_key_version), exactly like a ZK
folder name -- and, like a folder name, the vault row has no content epoch of its own. If retire does
not count that epoch, retiring the member keys below it strands the name: enc_name stays stored but no
member can ever decrypt it. These run against a throwaway Postgres so the real ORM + a real DB exercise
the floor computation the endpoint uses under its row lock.
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


_PG_NAME = "dvhx-pg-vaultname"
_PG_PW = secrets.token_hex(16)
_PG_DB = "vaultnamedb"


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


def _a_user(session):
    from app.core.models import RoleEnum, User
    u = User(username="v_" + secrets.token_hex(3), email="v_%s@example.co" % secrets.token_hex(3),
             password_hash="x", role=RoleEnum.USER)
    session.add(u)
    session.flush()
    return u


def _vault(session, owner, *, vtype="zero_knowledge", enc_name=None, name_key_version=None):
    # Seed the row directly: _lowest_epoch_in_use only reads enc_name / name_key_version off the
    # object and queries File/Folder by vault_id, so a real (heavy, credential-manager-dependent)
    # create_vault is unnecessary. A 'zk2:' enc_name is skipped by the load listener, so it stays
    # intact across a flush.
    import uuid
    from app.core.models import Vault
    v = Vault(id=uuid.uuid4(), owner_id=owner.id, type=vtype,
              enc_name=enc_name, name_key_version=name_key_version)
    session.add(v)
    session.flush()
    return v


@pytest.mark.docker
def test_lowest_epoch_counts_the_vault_name(_pg):
    from app.api.ecc_router import _lowest_epoch_in_use
    from app.core.models import Folder
    s = _session(_pg)
    try:
        u = _a_user(s)
        # Name sealed at epoch 1; a folder sealed at a HIGHER epoch 3. Without counting the name the
        # floor would be 3 and a retire would delete the epoch-1 key the name needs.
        vault = _vault(s, u, enc_name="zk2:sealed-name-blob", name_key_version=1)
        s.add(Folder(vault_id=vault.id, name_key_version=3))
        s.flush()

        assert _lowest_epoch_in_use(s, vault.id, vault) == 1, "the vault name at epoch 1 pins the floor"

        # Drop the sealed name -> nothing at epoch 1 remains; the folder (epoch 3) is now the floor.
        vault.enc_name = None
        s.flush()
        assert _lowest_epoch_in_use(s, vault.id, vault) == 3, "with no sealed name, the name pins nothing"
    finally:
        s.close()


@pytest.mark.docker
def test_lowest_epoch_defaults_a_nameless_epoch_to_one(_pg):
    """A sealed name whose name_key_version is NULL (a legacy row sealed by the first build at the
    constant epoch 1) must be treated as epoch 1, not ignored."""
    from app.api.ecc_router import _lowest_epoch_in_use
    from app.core.models import Folder
    s = _session(_pg)
    try:
        u = _a_user(s)
        vault = _vault(s, u, enc_name="zk2:legacy-sealed", name_key_version=None)
        s.add(Folder(vault_id=vault.id, name_key_version=4))
        s.flush()
        assert _lowest_epoch_in_use(s, vault.id, vault) == 1, "NULL name epoch => 1, pins the floor"
    finally:
        s.close()


@pytest.mark.docker
def test_lowest_epoch_is_none_when_nothing_references_an_epoch(_pg):
    """No files, no folders, no sealed name -> nothing references an epoch -> None (the endpoint then
    keeps only the current epoch)."""
    from app.api.ecc_router import _lowest_epoch_in_use
    s = _session(_pg)
    try:
        u = _a_user(s)
        vault = _vault(s, u, vtype="standard", enc_name=None)
        s.flush()
        assert _lowest_epoch_in_use(s, vault.id, vault) is None
    finally:
        s.close()


@pytest.mark.docker
def test_lowest_epoch_counts_a_standard_vault_at_rest_sealed_name(_pg):
    """A Standard vault seals its name at rest (enc_name set), so its epoch (NULL => 1) also pins the
    floor. Harmless and intentional -- retire only deletes ZK member-key rows (Standard vaults have
    none) and a lower floor deletes FEWER -- so lock the behaviour: enc_name present => floor 1."""
    from app.api.ecc_router import _lowest_epoch_in_use
    s = _session(_pg)
    try:
        u = _a_user(s)
        vault = _vault(s, u, vtype="standard", enc_name="atrest-sealed-name-blob", name_key_version=None)
        s.flush()
        assert _lowest_epoch_in_use(s, vault.id, vault) == 1
    finally:
        s.close()
