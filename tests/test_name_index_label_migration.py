"""Every name-index-key row gets the label that names its bytes: the marker-guarded boot relabel.

The write site used to omit `wrapping_algorithm`, so every `VaultMemberIndexKey` row took the column
default -- the LEGACY direct-DEK label -- while the bytes have always been a v2 name-index wrap. The
write site now stamps NAME_INDEX_ALGO (pinned in test_key_wrap_algorithm_generations); this pins the
one-shot relabel of the rows already written: it touches every row that does not carry a name-index
label (the legacy default AND a NULL), leaves a correct row alone, records a marker so a later boot
scans nothing, and respects that marker even for a wrong-labelled row added afterwards. Run on a
throwaway sqlite schema so the REAL query/update/add run, following test_notelink_token_hashing.
"""
import pytest

pytestmark = pytest.mark.unit

import _bare_api_env  # noqa: E402
_bare_api_env.set_bare_api_env()

from pathlib import Path  # noqa: E402

from app.core.key_wrap_algorithms import (  # noqa: E402
    DIRECT_DEK_ALGO_LEGACY, DIRECT_DEK_ALGO_V2, NAME_INDEX_ALGO, TEAMPRIV_ALGO_V2,
)

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"


def _sqlite_models():
    """A throwaway VaultMemberIndexKey + SystemSetting schema (the postgres UUID/JSONB models won't
    create_all on sqlite; the migration only touches wrapping_algorithm + the marker)."""
    import sqlalchemy as sa
    from sqlalchemy.orm import declarative_base, sessionmaker
    Base = declarative_base()

    class VaultMemberIndexKey(Base):
        __tablename__ = "vmik_probe"
        id = sa.Column(sa.Integer, primary_key=True)
        wrapping_algorithm = sa.Column(sa.String(50), default=DIRECT_DEK_ALGO_LEGACY)

    class SystemSetting(Base):
        __tablename__ = "ss_probe"
        key = sa.Column(sa.String, primary_key=True)
        value = sa.Column(sa.JSON)

    engine = sa.create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return VaultMemberIndexKey, SystemSetting, sessionmaker(bind=engine)()


@pytest.fixture
def migration_env(monkeypatch):
    import app.core.models as models
    Row, SystemSetting, s = _sqlite_models()
    monkeypatch.setattr(models, "VaultMemberIndexKey", Row, raising=False)
    monkeypatch.setattr(models, "SystemSetting", SystemSetting, raising=False)
    return Row, SystemSetting, s


def _labels(Row, s):
    return sorted((r.id, r.wrapping_algorithm) for r in s.query(Row).all())


def test_the_relabel_touches_every_row_that_is_not_a_name_index_row_and_only_those(migration_env):
    from app.core.name_index_label_migration import relabel_name_index_keys
    Row, SystemSetting, s = migration_env
    s.add_all([
        Row(id=1),                                       # the column default: the legacy member-key label
        Row(id=2),                                       # made NULL below: never labelled at all
        Row(id=3, wrapping_algorithm=DIRECT_DEK_ALGO_V2),   # a member-key label of the current generation
        Row(id=4, wrapping_algorithm=TEAMPRIV_ALGO_V2),     # the other member-key kind
        Row(id=5, wrapping_algorithm=NAME_INDEX_ALGO),   # already right: left alone
    ])
    s.commit()
    # A real NULL, by UPDATE: constructing the row with None would have taken the column default
    # (the ORM substitutes it), and the NULL leg of this test would have been the legacy leg twice.
    s.query(Row).filter(Row.id == 2).update({Row.wrapping_algorithm: None}, synchronize_session=False)
    s.commit()
    assert _labels(Row, s)[:2] == [(1, DIRECT_DEK_ALGO_LEGACY), (2, None)]
    assert relabel_name_index_keys(s) == 4
    assert _labels(Row, s) == [(i, NAME_INDEX_ALGO) for i in range(1, 6)]
    marker = s.query(SystemSetting).filter_by(key="name_index_key_labels_v2").first()
    assert marker is not None and marker.value == {"rows": 4}


def test_the_relabel_is_idempotent_and_the_marker_is_respected(migration_env):
    from app.core.name_index_label_migration import relabel_name_index_keys
    Row, SystemSetting, s = migration_env
    s.add(Row(id=1)); s.commit()
    assert relabel_name_index_keys(s) == 1
    assert relabel_name_index_keys(s) == 0              # a second boot: nothing scanned, nothing changed
    # A wrong-labelled row that appears AFTER the marker is not this migration's business: the marker
    # means "the rows that predate the stamped write site are done", and it is never re-run.
    s.add(Row(id=2, wrapping_algorithm=DIRECT_DEK_ALGO_LEGACY)); s.commit()
    assert relabel_name_index_keys(s) == 0
    assert _labels(Row, s) == [(1, NAME_INDEX_ALGO), (2, DIRECT_DEK_ALGO_LEGACY)]


def test_a_fresh_db_sets_the_marker_with_nothing_to_relabel(migration_env):
    from app.core.name_index_label_migration import relabel_name_index_keys
    Row, SystemSetting, s = migration_env
    assert relabel_name_index_keys(s) == 0
    marker = s.query(SystemSetting).filter_by(key="name_index_key_labels_v2").first()
    assert marker is not None and marker.value == {"rows": 0}


def test_the_relabel_runs_at_boot_after_the_schema_migrations_and_never_blocks_boot():
    src = API.read_text(encoding="utf-8")
    assert "_relabel_name_index_keys()" in src
    assert src.index("_run_lightweight_migrations()") < src.index("    _relabel_name_index_keys()")
    body = src[src.index("def _relabel_name_index_keys():"):]
    body = body[:body.index("\ndef ", 1)]
    assert "relabel_name_index_keys(db)" in body
    assert "except Exception" in body, "a failed relabel must not block boot; it retries next boot"
