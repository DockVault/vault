"""The two tables behind the key proof: their shape, their constraints, and the purge of old challenges.

Offline. The shape is read from the models, which is what create_all builds on a fresh database and on
an existing one alike (both tables are new, so no boot statement is involved). The constraints are
exercised in a throwaway SQLite database; tests/test_zk_key_proof_schema_live.py checks the same against
the deployment's PostgreSQL, where the foreign keys' delete rules live.
"""
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import session_retention as R  # noqa: E402
from app.core.models import Base, VaultKeyProof, ZkKeyProofChallenge  # noqa: E402
from app.services import zk_key_proof as kp  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 1, 12, 0, 0)


def _fks(table):
    return {fk.parent.name: (fk.column.table.name, fk.column.name, fk.ondelete) for fk in table.foreign_keys}


def test_the_proof_table_has_the_designed_shape():
    t = VaultKeyProof.__table__
    assert t.name == "vault_key_proofs"
    nullable = {c.name: c.nullable for c in t.columns}
    assert nullable == {
        "id": False, "vault_id": False, "dek_epoch": False, "format": False,
        "proof_public_key": True, "sealed_private_key": True, "dek_check": True, "lineage_tag": True,
        "source": False, "created_by": True, "created_at": False,
    }
    # The cascades are declared on the foreign keys, so they live in the database and still fire under
    # an image that has never heard of this table.
    assert _fks(t) == {"vault_id": ("vaults", "id", "CASCADE"), "created_by": ("users", "id", "SET NULL")}
    uniques = [tuple(c.name for c in u.columns) for u in t.constraints if isinstance(u, sa.UniqueConstraint)]
    assert ("vault_id", "dek_epoch") in uniques
    assert t.c.format.server_default.arg == "1"
    assert isinstance(t.c.format.type, sa.SmallInteger)


def test_the_challenge_table_has_the_designed_shape():
    t = ZkKeyProofChallenge.__table__
    assert t.name == "zk_key_proof_challenges"
    nullable = {c.name: c.nullable for c in t.columns}
    assert nullable == {
        "id": False, "user_id": False, "vault_id": False, "op": False, "server_private_key_sealed": False,
        "nonce": False, "mode": False, "dek_epoch": False, "team_epoch": False, "verifier_sha256": True,
        "created_at": False,
    }
    # The vault a create challenge names does not exist yet, so vault_id deliberately has no foreign key.
    assert _fks(t) == {"user_id": ("users", "id", "CASCADE")}
    assert "server_private_key" not in t.c, "the one-time key is stored only sealed"
    assert any(i.columns.keys() == ["user_id", "created_at"] for i in t.indexes)


def test_no_existing_table_is_changed():
    """Both tables are new: an older image ignores them, and nothing that image reads changes shape."""
    for table in (VaultKeyProof.__table__, ZkKeyProofChallenge.__table__):
        assert table.name in Base.metadata.tables
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    for name in ("vault_key_proofs", "zk_key_proof_challenges"):
        assert f"ALTER TABLE {name}" not in src, f"{name} is built by create_all, not altered at boot"


# ------------------------------------------------------------------------------ in a database

@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'proofs.db'}")
        VaultKeyProof.__table__.create(engine)
        ZkKeyProofChallenge.__table__.create(engine)
        s = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield s
        s.close()
        engine.dispose()


def _proof(db, vault_id, epoch, **over):
    row = VaultKeyProof(vault_id=vault_id, dek_epoch=epoch, source="create",
                        proof_public_key="P", sealed_private_key="S", dek_check="C")
    for k, v in over.items():
        setattr(row, k, v)
    db.add(row)
    db.commit()
    return row


def test_one_row_per_vault_and_epoch(db):
    vault = uuid.uuid4()
    _proof(db, vault, 1)
    _proof(db, vault, 2, source="rotate")
    _proof(db, uuid.uuid4(), 1)
    with pytest.raises(IntegrityError):
        _proof(db, vault, 2, source="bootstrap")
    db.rollback()


@pytest.mark.parametrize("over", [
    {"source": "import"},
    {"sealed_private_key": None},
    {"dek_check": None},
    {"proof_public_key": None},
])
def test_a_row_is_a_known_source_and_either_complete_or_hierarchical(db, over):
    with pytest.raises(IntegrityError):
        _proof(db, uuid.uuid4(), 1, **over)
    db.rollback()


def test_a_hierarchical_row_carries_no_direct_material(db):
    row = _proof(db, uuid.uuid4(), 3, proof_public_key=None, sealed_private_key=None, dek_check=None,
                 source="rotate", lineage_tag="T")
    assert row.format == 1


def _challenge(db, created):
    row = ZkKeyProofChallenge(user_id=uuid.uuid4(), vault_id=uuid.uuid4(), op="share",
                              server_private_key_sealed="sealed", nonce="n", mode="direct",
                              dek_epoch=1, team_epoch=1, created_at=created)
    db.add(row)
    db.commit()
    return row.id


def test_challenges_past_their_lifetime_are_purged_and_live_ones_kept(db):
    ttl = timedelta(seconds=kp.CHALLENGE_TTL_SECONDS)
    old = _challenge(db, NOW - ttl - timedelta(seconds=1))
    edge = _challenge(db, NOW - ttl + timedelta(seconds=1))
    fresh = _challenge(db, NOW)
    assert R.purge_expired_key_proof_challenges(db, now=NOW) == 1
    db.commit()
    left = {r.id for r in db.query(ZkKeyProofChallenge).all()}
    assert left == {edge, fresh} and old not in left


def test_the_periodic_cleanup_runs_the_challenge_purge_and_commits_it():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    reaper = src[src.index("async def cleanup_expired_sessions"):]
    reaper = reaper[:reaper.index("\ndef ")]
    assert reaper.count("purge_expired_key_proof_challenges(db)") == 1
    call = reaper.index("purge_expired_key_proof_challenges(db)")
    assert reaper.index("db.commit()", call) < reaper.index("db.rollback()", call)
