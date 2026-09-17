"""Note-link tokens are hashed at rest (part a): the migration marker + hashing behaviour on a
throwaway sqlite schema, and source-pins for the endpoint wiring that needs the full app + DB.

The live upgrade proof (seed through the product on the old code, rebuild in place, redeem after) is a
live-lane test; here we pin the migration's idempotency/marker and the at-rest contract offline.
"""
import hashlib

import pytest

pytestmark = pytest.mark.unit

import _bare_api_env  # noqa: E402
_bare_api_env.set_bare_api_env()

from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"


def _sqlite_models():
    """A throwaway NoteLink + SystemSetting schema, monkeypatched into the migration's imports so the
    REAL migration query/update/add run against sqlite (the postgres UUID/JSONB models won't
    create_all on sqlite; the migration only touches id/token/token_hash + the marker)."""
    import sqlalchemy as sa
    from sqlalchemy.orm import declarative_base, sessionmaker
    Base = declarative_base()

    class NoteLink(Base):
        __tablename__ = "nl_probe"
        id = sa.Column(sa.Integer, primary_key=True)
        token = sa.Column(sa.String)
        token_hash = sa.Column(sa.String)

    class SystemSetting(Base):
        __tablename__ = "ss_probe"
        key = sa.Column(sa.String, primary_key=True)
        value = sa.Column(sa.JSON)

    engine = sa.create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return NoteLink, SystemSetting, sessionmaker(bind=engine)()


@pytest.fixture
def migration_env(monkeypatch):
    import app.core.models as models
    NoteLink, SystemSetting, s = _sqlite_models()
    monkeypatch.setattr(models, "NoteLink", NoteLink, raising=False)
    monkeypatch.setattr(models, "SystemSetting", SystemSetting, raising=False)
    return NoteLink, SystemSetting, s


def test_the_migration_hashes_every_plaintext_token_and_nulls_it(migration_env):
    from app.core.notelink_token_migration import backfill_notelink_token_hashes
    NoteLink, SystemSetting, s = migration_env
    s.add_all([NoteLink(id=1, token="alpha"), NoteLink(id=2, token="bravo")])
    s.commit()

    assert backfill_notelink_token_hashes(s) == 2
    s.expire_all()
    for row_id, tok in ((1, "alpha"), (2, "bravo")):
        row = s.get(NoteLink, row_id)
        assert row.token is None                                             # cleartext gone
        assert row.token_hash == hashlib.sha256(tok.encode()).hexdigest()    # hash derived from the plaintext
    assert s.get(SystemSetting, "notelink_tokens_hashed") is not None        # marker set


def test_the_migration_is_idempotent_and_restart_safe(migration_env):
    from app.core.notelink_token_migration import backfill_notelink_token_hashes
    NoteLink, SystemSetting, s = migration_env
    s.add(NoteLink(id=1, token="alpha"))
    s.commit()
    assert backfill_notelink_token_hashes(s) == 1
    first_hash = s.get(NoteLink, 1).token_hash

    # A second boot re-hashes nothing (the marker short-circuits) and the hash is unchanged...
    assert backfill_notelink_token_hashes(s) == 0
    assert s.get(NoteLink, 1).token_hash == first_hash
    # ...even if a stray plaintext row somehow appears afterwards: the marker means no re-scan.
    s.add(NoteLink(id=2, token="late"))
    s.commit()
    assert backfill_notelink_token_hashes(s) == 0
    assert s.get(NoteLink, 2).token is not None   # untouched -- new rows are hashed at creation, not here


def test_a_fresh_db_sets_the_marker_with_nothing_to_migrate(migration_env):
    from app.core.notelink_token_migration import backfill_notelink_token_hashes
    NoteLink, SystemSetting, s = migration_env
    assert backfill_notelink_token_hashes(s) == 0
    assert s.get(SystemSetting, "notelink_tokens_hashed") is not None   # marker still set -> never re-scans


def test_the_token_hash_helper_is_sha256_and_not_the_plaintext():
    import app.api.api_server as api
    assert api._notelink_token_hash("secret-tok") == hashlib.sha256(b"secret-tok").hexdigest()
    assert "secret-tok" not in api._notelink_token_hash("secret-tok")


# ---- source-pins for the endpoint wiring (needs the full app + DB; the live lane exercises it) ----
def _create_src():
    s = API.read_text(encoding="utf-8")
    start = s.index("async def create_note_link(")
    return s[start:s.index("\n@app.", start)]


def test_the_token_is_stored_hashed_never_in_cleartext():
    body = _create_src()
    assert "token_hash=_notelink_token_hash(token)" in body      # store the hash
    assert "token=token" not in body                             # never store the plaintext
    assert "NoteLink.token_hash == _notelink_token_hash(cand)" in body  # collision check by hash


def test_the_plaintext_token_is_shown_once_at_creation_and_never_relisted():
    src = API.read_text(encoding="utf-8")
    # The owner list dict carries neither the token nor a url_path embedding it...
    dict_fn = src[src.index("def _notelink_public_dict("):src.index("def _notelink_fail_key(")]
    assert '"token": link.token' not in dict_fn and 'f"/l/{link.token}"' not in dict_fn
    # ...but creation returns the plaintext token ONCE.
    create = _create_src()
    assert 'created["token"] = token' in create and 'created["url_path"] = f"/l/{token}"' in create


def test_redeem_looks_up_by_hash_with_a_constant_time_confirm():
    src = API.read_text(encoding="utf-8")
    redeem = src[src.index("async def redeem_note_link("):]
    redeem = redeem[:redeem.index("\n@app.")]
    assert "NoteLink.token_hash == _presented_hash" in redeem
    assert "hmac.compare_digest(link.token_hash" in redeem
    assert "NoteLink.token == token" not in redeem   # no plaintext lookup remains


def test_the_lockout_key_hashes_the_token_and_paths_are_log_redacted():
    src = API.read_text(encoding="utf-8")
    assert 'f"notelink:fail:{_notelink_token_hash(token)}"' in src   # no cleartext token in the Redis key
    red = (ROOT / "app" / "core" / "log_redaction.py").read_text(encoding="utf-8")
    assert "/l/" in red and "/note-links/" in red and "/redeem" in red


def test_the_boot_ddl_and_migration_are_wired():
    src = API.read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS token_hash VARCHAR(64)" in src
    assert "uq_notelink_token_hash" in src and "WHERE token_hash IS NOT NULL" in src
    assert "note_public_links ALTER COLUMN token DROP NOT NULL" in src
    # the backfill runs at boot after the DDL (it needs the token_hash column)
    assert "_backfill_notelink_tokens()" in src
    assert src.index("_run_lightweight_migrations()") < src.index("_backfill_notelink_tokens()")
