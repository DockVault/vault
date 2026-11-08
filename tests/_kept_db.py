"""A throwaway SQLite database with every table of the model and the kept tables of the legal holds, for the
offline tests of the holds (test_blob_gate.py, test_legal_holds.py). Holds no tests.

What only Postgres has becomes SQLite's own: a default written as SQL (``now() AT TIME ZONE 'utc'``) becomes
CURRENT_TIMESTAMP, a JSONB column a JSON one, greatest() and least() are defined, and an index over a Postgres
expression is left out; nothing else changes. SQLite has no triggers here: a test writes the kept rows the
database's triggers would write.

The tables are created once per run, in a database file of their own, and each test's database is a copy of that
file: copying the model's tables and creating them took most of a test's time, and they make the same file every
time. A model whose tables differ from the ones the file was made from (a name, a column or an index) gets a file
of its own.
"""
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

# The empty databases made so far: the tables each was made from -> (its directory, the file).
_MADE = {}


def _tables():
    from app.core import models as m
    return list(m.Base.metadata.sorted_tables) + list(m.KeptBase.metadata.sorted_tables)


def _shape(tables):
    """What a database is made from: each table's name, its columns with their types, and its indexes."""
    return tuple((t.name, tuple((c.name, repr(c.type)) for c in t.columns),
                  tuple(sorted(str(ix.name) for ix in t.indexes))) for t in tables)


def _empty_database() -> Path:
    tables = _tables()
    shape = _shape(tables)
    if shape not in _MADE:
        holder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        path = Path(holder.name) / "empty.db"
        engine = sa.create_engine(f"sqlite:///{path}")
        try:
            copies = sa.MetaData()
            for table in tables:
                copy = table.to_metadata(copies)
                for column in copy.columns:
                    default = getattr(column.server_default, "arg", None)
                    if default is not None and "now()" in str(default):
                        column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
                    if isinstance(column.type, JSONB):
                        column.type = sa.JSON()
                for index in list(copy.indexes):
                    if any("::" in str(e) for e in index.expressions):
                        copy.indexes.discard(index)
            copies.create_all(engine)
        finally:
            engine.dispose()
        _MADE[shape] = (holder, path)
    return _MADE[shape][1]


@contextmanager
def kept_database():
    """(sessionmaker, engine) of a fresh database; disposed afterwards."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        path = Path(tmp) / "holds.db"
        shutil.copyfile(_empty_database(), path)
        engine = sa.create_engine(f"sqlite:///{path}")

        @sa.event.listens_for(engine, "connect")
        def _functions(connection, _record):
            # The counters' updates use Postgres' greatest() and least().
            connection.create_function("greatest", -1, lambda *a: max(v for v in a if v is not None))
            connection.create_function("least", -1, lambda *a: min(v for v in a if v is not None))

        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        try:
            yield make, engine
        finally:
            engine.dispose()
