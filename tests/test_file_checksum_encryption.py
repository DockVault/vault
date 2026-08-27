"""A file's content checksum (files.checksum_sha256) is sealed at rest and read back transparently.

The SHA-256 of a file's content is a weak confirmation oracle for a DB/backup reader, so it is sealed
into enc_checksum (AES-GCM, per-file key) with the plaintext column NULL, and a load/refresh event
decrypts it back into checksum_sha256. UNLIKE the file name, the checksum is server-computed for EVERY
file (zero-knowledge + Standard), so it is always decrypted -- never left opaque like a ZK name blob.

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


_PG_NAME = "dvhx-pg-checksum"
_PG_PW = secrets.token_hex(16)
_PG_DB = "checksumdb"


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


def _raw(engine, field, file_id):
    from sqlalchemy import text
    with engine.connect() as c:
        return c.execute(text("SELECT %s FROM files WHERE id=:i" % field), {"i": str(file_id)}).scalar()


def _a_user_and_vault(session, vtype="standard"):
    from app.core.models import RoleEnum, User, Vault
    u = User(username="c_" + secrets.token_hex(3), email="c_%s@example.co" % secrets.token_hex(3),
             password_hash="x", role=RoleEnum.USER)
    session.add(u)
    session.flush()
    v = Vault(id=uuid.uuid4(), owner_id=u.id, type=vtype, name="V")
    session.add(v)
    session.flush()
    return u, v


def _mk_file(session, vault, checksum, *, enc_name=None):
    from app.core.models import File
    from app.services.vault_service import _seal_file_checksum
    f = File(id=uuid.uuid4(), vault_id=vault.id, size_bytes=10, storage_path="/x/y",
             checksum_sha256=checksum, enc_name=enc_name)
    _seal_file_checksum(f)                 # server-side seal (all files)
    session.add(f)
    session.commit()
    return f


@pytest.mark.docker
def test_a_file_checksum_is_sealed_and_reads_back(_pg):
    from app.core.models import File
    from app.core.security import is_zk_sealed_name
    s = _session(_pg)
    try:
        _u, v = _a_user_and_vault(s)
        f = _mk_file(s, v, "a" * 64)
        fid = f.id
        assert _raw(_pg, "enc_checksum", fid), "enc_checksum populated at rest"
        assert _raw(_pg, "checksum_sha256", fid) is None, "the plaintext checksum column is NULL at rest"
        assert not is_zk_sealed_name(_raw(_pg, "enc_checksum", fid)), "a SERVER seal, not a zk2: blob"
        s.expire_all()
        assert s.get(File, fid).checksum_sha256 == "a" * 64, "the load event decrypts it transparently"
    finally:
        s.close()


@pytest.mark.docker
def test_checksum_is_sealed_and_decrypted_for_a_zk_file_too(_pg):
    """A ZK file's name is a browser zk2: blob the listener leaves opaque -- but the checksum is
    server-computed and MUST still be sealed at rest AND decrypted on load (it is handled before the
    name/MIME ZK early-return)."""
    from app.core.models import File
    s = _session(_pg)
    try:
        _u, v = _a_user_and_vault(s, vtype="zero_knowledge")
        f = _mk_file(s, v, "b" * 64, enc_name="zk2:browser-sealed-name")
        fid = f.id
        assert _raw(_pg, "enc_checksum", fid), "the checksum is sealed even for a ZK file"
        assert _raw(_pg, "checksum_sha256", fid) is None
        s.expire_all()
        got = s.get(File, fid)
        assert got.checksum_sha256 == "b" * 64, "the checksum is decrypted despite the ZK name blob"
        assert got.enc_name == "zk2:browser-sealed-name", "the ZK name blob is left opaque"
    finally:
        s.close()


@pytest.mark.docker
def test_backfill_seals_legacy_checksums_and_is_idempotent(_pg):
    from sqlalchemy import text
    from app.core.models import File
    from app.core.file_migrations import backfill_file_checksums
    s = _session(_pg)
    try:
        _u, v = _a_user_and_vault(s)
        # LEGACY rows via raw SQL: plaintext checksum, enc_checksum NULL (bypass the seal helper).
        ids = [uuid.uuid4() for _ in range(3)]
        for i, fid in enumerate(ids):
            s.execute(text("INSERT INTO files (id, vault_id, size_bytes, storage_path, checksum_sha256, "
                           "created_at) VALUES (:i,:v,10,'/x',:c,now())"),
                      {"i": str(fid), "v": str(v.id), "c": ("c%02d" % i) * 16})
        s.commit()
        assert _raw(_pg, "checksum_sha256", ids[0]).startswith("c00"), "seeded plaintext"
        assert _raw(_pg, "enc_checksum", ids[0]) is None

        assert backfill_file_checksums(s) == 3, "all three legacy rows sealed"
        for i, fid in enumerate(ids):
            assert _raw(_pg, "enc_checksum", fid), "sealed at rest"
            assert _raw(_pg, "checksum_sha256", fid) is None
        s.expire_all()
        assert s.get(File, ids[0]).checksum_sha256 == "c00" * 16, "reads back as the original plaintext"

        # Idempotent: a second run finds nothing to seal.
        assert backfill_file_checksums(s) == 0
    finally:
        s.close()


@pytest.mark.docker
def test_a_corrupt_enc_checksum_is_left_as_is_not_blanked(_pg):
    """Fail-safe: an undecryptable enc_checksum leaves checksum_sha256 as-is and never crashes a load."""
    from app.core.models import File
    s = _session(_pg)
    try:
        _u, v = _a_user_and_vault(s)
        f = File(id=uuid.uuid4(), vault_id=v.id, size_bytes=10, storage_path="/x",
                 checksum_sha256="still-here", enc_checksum="not-a-valid-seal")
        s.add(f)
        s.commit()
        fid = f.id
        s.expire_all()
        assert s.get(File, fid).checksum_sha256 == "still-here", "undecryptable enc_checksum -> left as-is"
    finally:
        s.close()


def test_the_upload_path_seals_the_checksum_after_content_mac():
    """Static guard: the upload/finalize path MUST call _seal_file_checksum, and AFTER content_mac is
    computed. The helper + backfill tests above would still pass if the upload call were deleted (they
    call the helper directly), leaving every new upload's checksum plaintext at rest -- and sealing
    BEFORE content_mac would MAC a NULLed checksum. Pin both so neither can be silently broken."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "app" / "services" / "vault_service.py").read_text(
        encoding="utf-8")
    def_pos = src.index("def _seal_file_checksum(file)")
    # The CALL is a later occurrence than the `def`; .index raises (test fails) if the call was deleted.
    call_pos = src.index("_seal_file_checksum(file)", def_pos + len("def _seal_file_checksum(file)"))
    assert src.index("content_mac=_content_mac(") < call_pos, \
        "the checksum must be sealed AFTER content_mac is computed (else the ETag would MAC a NULL)"
