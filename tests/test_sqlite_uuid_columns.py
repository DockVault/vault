"""An id the offline tests store in SQLite comes back as it was written.

The tests that run without a stack use SQLite, which decides how to store a value from the type its
column is declared with. A column declared ``UUID`` gets numeric affinity: a value that reads as a
number is stored as that number. A random id's hex now and then is exactly that, only digits or
digits around a single 'e', and comes back as a number (1e999... is the float inf), so whichever test
drew it failed for no reason it could see.

The ids here are built to read as numbers, which makes that failure certain instead of rare.
"""
from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import admin_grants  # noqa: E402
from app.core.models import AdminGrant, Base, CredentialChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit

# Valid ids whose hex SQLite reads as a number when the column has numeric affinity.
NUMBERLIKE = [
    uuid.UUID("1e999000000000000000000000000000"),   # too large for a float: inf
    uuid.UUID("2e999000000000000000000000000000"),   # inf as well: equal to the one above
    uuid.UUID("12345678901234567890123456789012"),   # only digits: too long for an integer
    uuid.UUID("0000000000000000000000000000e001"),   # zero
]


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'ids.db'}")
        for model in (User, AdminGrant, CredentialChange):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, user_id, name):
    u = User(id=user_id, username=name, email=None, password_hash="x", role=RoleEnum.ADMIN,
             is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def test_every_uuid_column_is_text_on_sqlite():
    # SQLite's rule: a declared type containing CHAR, CLOB or TEXT has text affinity.
    columns = [(t.name, c.name, c.type.compile(dialect=sqlite.dialect()))
               for t in Base.metadata.sorted_tables for c in t.columns
               if isinstance(c.type, sa.types.UUID)]
    assert len(columns) > 50, "the models' UUID columns were not found"
    numeric = [(t, c, declared) for t, c, declared in columns
               if not any(word in declared.upper() for word in ("CHAR", "CLOB", "TEXT"))]
    assert not numeric, f"UUID columns SQLite would give numeric affinity: {numeric[:5]}"


def test_an_id_that_reads_as_a_number_comes_back_as_written(db):
    for i, user_id in enumerate(NUMBERLIKE):
        _user(db, user_id, f"u{i}")
    db.expunge_all()
    assert sorted(u.id for u in db.query(User).all()) == sorted(NUMBERLIKE)
    for user_id in NUMBERLIKE:
        assert db.get(User, user_id).id == user_id


def test_a_lineage_through_ids_that_read_as_numbers_is_kept_whole(db):
    root, a, b = NUMBERLIKE[0], NUMBERLIKE[2], NUMBERLIKE[3]   # three that stay distinct as numbers
    for user_id, name in ((root, "root"), (a, "a"), (b, "b")):
        _user(db, user_id, name)
    admin_grants.record(db, a, granted_by_id=root, granted_by_name="root")
    admin_grants.record(db, b, granted_by_id=a, granted_by_name="a")
    db.commit()
    db.expunge_all()
    grants = admin_grants.of(db, [a, b])
    assert grants[b].lineage == [str(a), str(root)]
    assert grants[b].granted_by_id == a
