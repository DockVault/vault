"""A throwaway SQLite database with every table of the model and the kept tables of the legal holds, for the
offline tests of the holds (test_blob_gate.py, test_legal_holds.py). Holds no tests.

What only Postgres has becomes SQLite's own: a default written as SQL (``now() AT TIME ZONE 'utc'``) becomes
CURRENT_TIMESTAMP, a JSONB column a JSON one, greatest() and least() are defined, and an index over a Postgres
expression is left out; nothing else changes. SQLite has no triggers here: a test writes the kept rows the
database's triggers would write.
"""
import tempfile
from contextlib import contextmanager
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker


@contextmanager
def kept_database():
    """(sessionmaker, engine) of a fresh database; disposed afterwards."""
    from app.core import models as m
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'holds.db'}")

        @sa.event.listens_for(engine, "connect")
        def _functions(connection, _record):
            # The counters' updates use Postgres' greatest() and least().
            connection.create_function("greatest", -1, lambda *a: max(v for v in a if v is not None))
            connection.create_function("least", -1, lambda *a: min(v for v in a if v is not None))

        copies = sa.MetaData()
        for table in list(m.Base.metadata.sorted_tables) + list(m.KeptBase.metadata.sorted_tables):
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
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        try:
            yield make, engine
        finally:
            engine.dispose()
