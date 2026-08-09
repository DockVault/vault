"""A row lock is only worth taking if you read the row after taking it.

Three handlers lock a vault row and then compare a version column against a value the client sent.
The lock makes that comparison meaningful — without it another request can commit in between and
the check passes against a number that is already gone.

But locking a row the session has *already loaded* does not refresh it. SQLAlchemy's identity map
returns the instance it is holding, attributes and all, so the `FOR UPDATE` is emitted and the row
is genuinely locked while the value compared afterwards predates the lock. `populate_existing()`
is what forces the refresh, and every one of these handlers reads the vault once on the way in
before it locks anything.

The failure is intermittent rather than absolute, which is worse: an unrelated cleanup on one of
these paths commits only when it finds work, and a commit expires the instance and makes the next
read fresh. So the optimistic check works or does not depending on whether something else happened
to have something to do.

**Why these are source and behaviour tests rather than a concurrency test.** Each HTTP request gets
its own session, so two sequenced requests never share an identity map and the staleness cannot be
produced by driving the API — a test that rotated twice would pass either way. What can be tested
is the library behaviour the guard depends on, and the presence of the guard itself.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
ECC_ROUTER = ROOT / "app" / "api" / "ecc_router.py"
APP_DIR = ROOT / "app"


def test_a_locked_reread_of_a_loaded_row_is_stale_without_populate_existing():
    """Pin the library behaviour the guard exists for.

    If a future SQLAlchemy refreshed on `with_for_update()` by itself, this fails and the guards
    become unnecessary rather than load-bearing — which is worth learning from a test rather than
    from a comment that has quietly become false.
    """
    sa = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import declarative_base, sessionmaker

    Base = declarative_base()

    class Row(Base):
        __tablename__ = "locked_reread_probe"
        id = sa.Column(sa.Integer, primary_key=True)
        version = sa.Column(sa.Integer)

    # A file-backed database, because two sessions must see each other's commits.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'probe.db'}")
        Base.metadata.create_all(engine)
        # The application's own session flags.
        Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)

        seed = Session()
        seed.add(Row(id=1, version=1))
        seed.commit()
        seed.close()

        reader = Session()
        entry = reader.query(Row).filter(Row.id == 1).first()   # the handler's entry read
        assert entry.version == 1

        writer = Session()                                       # a concurrent rotation commits
        writer.query(Row).filter(Row.id == 1).update({"version": 2})
        writer.commit()
        writer.close()

        stale = reader.query(Row).filter(Row.id == 1).with_for_update().first()
        assert stale is entry, "the identity map returned a different instance than expected"
        assert stale.version == 1, (
            "a locked re-read refreshed on its own -- if this is now the library's behaviour, the "
            "populate_existing() guards in ecc_router are no longer load-bearing"
        )

        fresh = (reader.query(Row).populate_existing()
                 .filter(Row.id == 1).with_for_update().first())
        assert fresh.version == 2, "populate_existing() did not refresh the instance"
        reader.close()
        # Windows will not remove the file while the pool still holds a handle on it.
        engine.dispose()


def test_every_locked_vault_reread_refreshes():
    """The guard itself, on every handler that takes the vault lock to read a version off it.

    Written as a source rule because the behavioural one is unreachable: the staleness needs two
    reads of one row in ONE session, and every request has its own.

    Scanned across the whole application tree rather than one module. An earlier version of this
    rule looked only at the router, and a fourth site in a different file went on comparing a
    pre-lock epoch while its three siblings were being fixed -- the rule was narrower than the
    problem, which is the least useful kind of guard.
    """
    offenders = []
    for path in sorted(APP_DIR.rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        # Collapse so a multi-line query still reads as one expression.
        flat = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
        for q in re.findall(r"db\.query\(Vault\)[^;]{0,160}?with_for_update\(\)", flat):
            if "populate_existing()" not in q:
                offenders.append(f"{path.relative_to(ROOT)}: {q}")
    assert not offenders, (
        "a vault row is locked and then read without refreshing it, so the value compared came "
        "from before the lock:\n  " + "\n  ".join(offenders)
    )


def test_the_rule_above_actually_finds_the_locked_reads():
    """Non-vacuity: a rule that matched nothing would pass silently and guard nothing."""
    found = 0
    for path in sorted(APP_DIR.rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        flat = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
        found += len(re.findall(r"db\.query\(Vault\)[^;]{0,160}?with_for_update\(\)", flat))
    assert found >= 4, f"expected at least four locked vault reads, matched {found}"


def test_the_optimistic_checks_still_read_from_the_locked_row():
    """The refresh is pointless if the comparison then reads the pre-lock object.

    Both handlers bind the locked query to `locked` and must take their version from that, not from
    the `vault` loaded on the way in. Cheap to get wrong in a refactor and invisible if you do.
    """
    source = ECC_ROUTER.read_text(encoding="utf-8")
    flat = re.sub(r"\s+", " ", source)
    for label, snippet in (
        ("rotation", "current = getattr(locked, 'dek_version', 1) or 1"),
        ("retire", "dek_floor = min_in_use if min_in_use is not None else (getattr(locked, 'dek_version', 1) or 1)"),
    ):
        assert snippet in flat, f"the {label} path no longer reads its epoch from the locked row"
