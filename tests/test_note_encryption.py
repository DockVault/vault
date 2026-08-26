"""Note title/body (and public-link snapshots) are sealed at rest and read back transparently.

Notes were stored plaintext. Now a before-flush event seals content at every write (so no write site
can miss it), a load event decrypts it back into the same attribute, and a boot backfill seals legacy
rows. These run against a throwaway Postgres so the real ORM events + a real DB exercise the whole
chain (in-memory SQLite would not reproduce the flush/load event timing the same way).
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
    """Configure a throwaway ENCRYPTION_KEY so the at-rest crypto can derive keys. The first crypto
    call latches initialize_runtime() from the environment; restore it on teardown."""
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


_PG_NAME = "dvhx-pg-notes"
_PG_PW = secrets.token_hex(16)
_PG_DB = "notesdb"
_MARK = "nenc1:"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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


def _load_fernet_ok():
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def _session(engine):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=engine)()


def _a_user(session):
    from app.core.models import RoleEnum, User
    u = User(username="n_" + secrets.token_hex(3), email="n_%s@example.co" % secrets.token_hex(3),
             password_hash="x", role=RoleEnum.USER)
    session.add(u)
    session.flush()
    return u


def _raw(engine, table, field, row_id):
    from sqlalchemy import text
    with engine.connect() as c:
        return c.execute(text("SELECT %s FROM %s WHERE id=:i" % (field, table)),
                         {"i": str(row_id)}).scalar()


@pytest.mark.docker
def test_a_new_note_is_sealed_at_rest_and_reads_back_plaintext(_pg):
    from app.core.models import Note
    s = _session(_pg)
    try:
        u = _a_user(s)
        n = Note(owner_id=u.id, title="Quarterly plan", body="secret body text", adopted=True)
        s.add(n)
        s.commit()
        nid = n.id
        # RAW columns are sealed...
        assert _raw(_pg, "notes", "title", nid).startswith(_MARK)
        assert _raw(_pg, "notes", "body", nid).startswith(_MARK)
        # ...and a fresh ORM read decrypts transparently.
        s.expire_all()
        got = s.get(Note, nid)
        assert got.title == "Quarterly plan" and got.body == "secret body text"
    finally:
        s.close()


@pytest.mark.docker
def test_updating_reseals_only_the_changed_field(_pg):
    from app.core.models import Note
    s = _session(_pg)
    try:
        u = _a_user(s)
        n = Note(owner_id=u.id, title="t1", body="b1", adopted=True)
        s.add(n)
        s.commit()
        nid = n.id
        title_before = _raw(_pg, "notes", "title", nid)
        body_before = _raw(_pg, "notes", "body", nid)

        # Change only the title.
        n.title = "t2"
        s.commit()
        assert _raw(_pg, "notes", "title", nid) != title_before, "changed title re-sealed"
        assert _raw(_pg, "notes", "body", nid) == body_before, "unchanged body not re-encrypted"
        s.expire_all()
        assert s.get(Note, nid).title == "t2" and s.get(Note, nid).body == "b1"

        # An unrelated update must not touch the sealed content at all.
        title_now = _raw(_pg, "notes", "title", nid)
        n2 = s.get(Note, nid)
        n2.is_favorite = True
        s.commit()
        assert _raw(_pg, "notes", "title", nid) == title_now, "is_favorite toggle left title untouched"
    finally:
        s.close()


@pytest.mark.docker
def test_a_public_link_snapshot_is_sealed(_pg):
    from app.core.models import Note, NoteLink
    s = _session(_pg)
    try:
        u = _a_user(s)
        link = NoteLink(owner_id=u.id, token=secrets.token_hex(8), token_len=16,
                        title_snapshot="shared title", body_snapshot="shared body", secret_kind="none")
        s.add(link)
        s.commit()
        lid = link.id
        assert _raw(_pg, "note_public_links", "title_snapshot", lid).startswith(_MARK)
        assert _raw(_pg, "note_public_links", "body_snapshot", lid).startswith(_MARK)
        s.expire_all()
        got = s.get(NoteLink, lid)
        assert got.title_snapshot == "shared title" and got.body_snapshot == "shared body"
    finally:
        s.close()


@pytest.mark.docker
def test_a_note_whose_plaintext_starts_with_the_marker_is_still_sealed(_pg):
    from app.core.models import Note
    s = _session(_pg)
    try:
        u = _a_user(s)
        n = Note(owner_id=u.id, title="nenc1:not actually sealed", body="b", adopted=True)
        s.add(n)
        s.commit()
        nid = n.id
        raw = _raw(_pg, "notes", "title", nid)
        assert raw.startswith(_MARK) and raw != "nenc1:not actually sealed", "user marker text is sealed"
        s.expire_all()
        assert s.get(Note, nid).title == "nenc1:not actually sealed"
    finally:
        s.close()


@pytest.mark.docker
def test_a_sent_note_copy_is_resealed_under_its_own_key(_pg):
    """'Send note' inserts a NEW row (title/body copied from the ORM-decrypted source). It must be
    sealed under the COPY's own id -- a different ciphertext than the source, decrypting to the same
    plaintext -- mirroring POST /notes/{id}/send's `Note(title=src.title, body=src.body)`."""
    from app.core.models import Note
    s = _session(_pg)
    try:
        sender = _a_user(s)
        recipient = _a_user(s)
        src = Note(owner_id=sender.id, title="shared secret", body="the body", adopted=True)
        s.add(src)
        s.commit()
        src_id = src.id
        s.expire_all()
        src = s.get(Note, src_id)                    # load -> event decrypts title/body to plaintext
        copy = Note(owner_id=recipient.id, title=src.title, body=src.body, adopted=False)
        s.add(copy)
        s.commit()
        copy_id = copy.id
        assert copy_id != src_id
        src_raw = _raw(_pg, "notes", "title", src_id)
        copy_raw = _raw(_pg, "notes", "title", copy_id)
        assert copy_raw.startswith(_MARK), "the sent copy is sealed at rest"
        assert copy_raw != src_raw, "sealed under the copy's OWN key (different ciphertext)"
        s.expire_all()
        assert s.get(Note, copy_id).title == "shared secret"
    finally:
        s.close()


@pytest.mark.docker
def test_a_long_title_round_trips_needing_the_text_widen(_pg):
    """A title near the old String(255) limit seals to a >255-char blob, so the column MUST be TEXT."""
    from app.core.models import Note
    s = _session(_pg)
    try:
        u = _a_user(s)
        long_title = "T" * 250
        n = Note(owner_id=u.id, title=long_title, body="b", adopted=True)
        s.add(n)
        s.commit()
        nid = n.id
        raw = _raw(_pg, "notes", "title", nid)
        assert raw.startswith(_MARK) and len(raw) > 255, "the sealed title exceeds 255 chars"
        s.expire_all()
        assert s.get(Note, nid).title == long_title
    finally:
        s.close()


@pytest.mark.docker
def test_backfill_seals_legacy_plaintext_and_is_idempotent(_pg):
    from sqlalchemy import text
    from app.core.models import Note
    from app.core.note_migrations import backfill_note_content
    s = _session(_pg)
    try:
        u = _a_user(s)
        # Insert a LEGACY plaintext note via raw SQL (bypassing the before-flush seal event).
        nid = __import__("uuid").uuid4()
        s.execute(text("INSERT INTO notes (id, owner_id, title, body, is_favorite, adopted, "
                       "created_at, updated_at) VALUES (:i,:o,:t,:b,false,true,now(),now())"),
                  {"i": str(nid), "o": str(u.id), "t": "legacy title", "b": "legacy body"})
        s.commit()
        assert _raw(_pg, "notes", "title", nid) == "legacy title", "seeded plaintext"

        sealed = backfill_note_content(s)
        s.commit()
        assert sealed >= 1
        assert _raw(_pg, "notes", "title", nid).startswith(_MARK), "backfill sealed the legacy row"
        s.expire_all()
        assert s.get(Note, nid).title == "legacy title", "still reads back as the original plaintext"

        # Idempotent: a second run seals nothing.
        assert backfill_note_content(s) == 0
    finally:
        s.close()


@pytest.mark.docker
def test_backfill_never_reseals_a_marked_value_it_cannot_decrypt(_pg):
    """A row that carries the seal marker but will not decrypt is what a genuine seal under a
    MISMATCHED ENCRYPTION_KEY looks like. The backfill must LEAVE IT UNTOUCHED -- re-sealing would
    double-encrypt it under a key nobody keeps (permanent, silent loss on one wrong-key boot). Here
    we stand in for the wrong-key case with an AAD mismatch: a token sealed and bound to a DIFFERENT
    row id, which the backfill cannot distinguish from a wrong-key seal and must treat identically."""
    import uuid
    from sqlalchemy import text
    from app.core.security import encrypt_note_field, decrypt_note_field
    from app.core.note_migrations import backfill_note_content
    s = _session(_pg)
    try:
        u = _a_user(s)
        nid = uuid.uuid4()
        other = uuid.uuid4()
        # A genuine seal, but bound (via AAD) to `other`, not to `nid`. Stored under `nid` it carries
        # the marker yet cannot be decrypted for `nid` -- exactly the wrong-key shape.
        foreign_title = encrypt_note_field(other, "bank pin 4417", "title")
        assert foreign_title.startswith(_MARK)
        s.execute(text("INSERT INTO notes (id, owner_id, title, body, is_favorite, adopted, "
                       "created_at, updated_at) VALUES (:i,:o,:t,:b,false,true,now(),now())"),
                  {"i": str(nid), "o": str(u.id), "t": foreign_title, "b": "plain body"})
        s.commit()
        assert _raw(_pg, "notes", "title", nid) == foreign_title, "seeded the undecryptable marked value"

        updated = backfill_note_content(s)
        s.commit()

        after = _raw(_pg, "notes", "title", nid)
        # The undecryptable marked title is BYTE-IDENTICAL: never re-sealed (no double-encryption).
        assert after == foreign_title, "backfill must never re-seal a marker-carrying value"
        # It is still recoverable under its true binding -- nothing was lost.
        assert decrypt_note_field(other, after, "title") == "bank pin 4417"
        # The genuinely-plaintext body on the SAME row WAS still sealed (backfill still does its job).
        assert _raw(_pg, "notes", "body", nid).startswith(_MARK)
        assert updated >= 1
        s.expire_all()
        # Idempotent + non-lossy across boots: a second run re-seals nothing (title skipped, not
        # re-encrypted each time).
        assert backfill_note_content(s) == 0
    finally:
        s.close()


def test_wrong_row_decrypt_raises():
    if not _load_fernet_ok():
        pytest.skip("cryptography not available")
    import uuid
    from app.core.security import encrypt_note_field, decrypt_note_field
    a, b = uuid.uuid4(), uuid.uuid4()
    token = encrypt_note_field(a, "hello", "title")
    assert decrypt_note_field(a, token, "title") == "hello"
    with pytest.raises(Exception):
        decrypt_note_field(b, token, "title")          # wrong row id (AAD/key mismatch)
    with pytest.raises(Exception):
        decrypt_note_field(a, token, "body")           # wrong field (AAD mismatch)
