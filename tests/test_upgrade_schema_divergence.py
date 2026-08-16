"""What a fresh install's schema looks like next to an upgraded one.

There is no migration framework, which is a deliberate choice rather than an oversight: a
hand-maintained list of idempotent DDL statements is replayed on every boot, and across all public
history it has been maintained correctly.

Two columns are declared `nullable=False` on the model and added by an `ALTER TABLE ... ADD COLUMN`
that omits `NOT NULL`, so a fresh install gets the model's schema and an upgraded install gets the
ALTER's. The list is perfectly capable of expressing the difference -- it already carries six
statements that change a column's nullability after the fact, including
`ALTER TABLE vault_member_keys ALTER COLUMN key_version SET NOT NULL`. That statement is the
template for the fix; what is missing is the two lines that were never written.

`ADD COLUMN ... NOT NULL` is NOT the fix and cannot be: on a database where the column already
exists, `ADD COLUMN IF NOT EXISTS` is a no-op, so every deployment that already upgraded keeps its
nullable column forever while a fresh install looks correct. The replay test below models both
shapes separately so it can tell the two candidate fixes apart, rather than reporting "divergence
closed" for the one that closes nothing.

The suite also already has a real fresh-vs-upgraded harness -- it boots the previous release, writes
data with it, then brings the candidate up over the same volumes. What that harness checks is three
things it names: one column's nullability, one index, one table. It never enumerates, so a column
whose ALTER drifts from its declaration is not covered by it, and neither of these two is.

These are CHARACTERIZATION tests. They record today's behaviour so a later phase can flip them, the
convention the `characterization` marker already marks elsewhere in this suite. A failure here is
not a regression -- it means the divergence has been closed and these should become an assertion
that the two schemas agree. One test below is a premise guard rather than a characterization and
says so in its own docstring; it will not flip on the recommended fix.

Marked per test. The two that read only source guard the premise and need nothing running, so they
belong in the offline lane and in CI; the two that ask a live database its shape skip without one.
Nothing here writes to a real table: the live half reads `information_schema`, and the replay runs
against uniquely-named scratch tables it creates and drops.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import uuid

import pytest

pytestmark = pytest.mark.characterization

# Declared `nullable=False` on the model, added by boot DDL without NOT NULL, and never followed by
# an ALTER COLUMN ... SET NOT NULL. An upgraded deployment therefore permits NULL in a column a
# fresh one forbids. The type is the column's physical type, used to build the "already upgraded"
# scratch shape below.
DIVERGENT = {
    "can_create_temp_credentials": "boolean",
    "vault_access_mode": "varchar(32)",
}
TABLE = "temporary_credentials"


def _string_literals(source):
    """Every string literal in `source`, with adjacent literals already joined.

    Read through the parser rather than by matching source text: SQL here is written across
    adjacent string literals and contains its own quoted values, which defeat a regex over the raw
    file in opposite directions.
    """
    literals = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.append(node.value)
        elif isinstance(node, ast.JoinedStr):
            literals.append(" ? ".join(
                part.value for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)))
    return literals


def _boot_statements():
    """The statements the deployment replays at boot, as the parser sees them.

    UPDATEs as well as ALTERs. The list carries data migrations alongside the schema ones, and a
    tightening fix needs both -- SET NOT NULL cannot apply to a column that still holds NULLs, so
    the backfill is part of the fix and has to be part of the replay.
    """
    from pathlib import Path
    boot = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(
        encoding="utf-8")
    return [s for s in _string_literals(boot)
            if s.strip().upper().startswith(("ALTER TABLE ", "UPDATE "))]


def _db_container():
    return os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _docker(args, timeout=60):
    """Run a docker command, treating an absent or wedged engine as "cannot test"."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"cannot reach the docker engine: {exc}")


def _psql(sql, on_error="fail"):
    """Ask the deployment's own database, through its own container.

    `on_error` is explicit at every call site and defaults to FAIL. An earlier version skipped on
    any non-zero exit, which meant a SQL statement that genuinely errored -- a replayed DDL step
    that no longer applies, say -- reported as "cannot query the deployment database" and went
    green in CI, indistinguishable from "there is no database here". That is a false pass in the
    one place this file executes anything, so a query that is expected to work now fails loudly and
    only the callers that are genuinely probing for existence opt into skipping.
    """
    # Read the credentials from the container's own environment rather than guessing: the defaults
    # differ between deployments, and a wrong guess makes this skip with a connection error, which
    # reads as "cannot test" when it means "asked the wrong question".
    container = _db_container()
    probe = _docker(["docker", "exec", container, "sh", "-c",
                     "echo $POSTGRES_USER; echo $POSTGRES_DB"])
    if probe.returncode != 0:
        pytest.skip(f"cannot reach the database container {container}")
    lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
    user = os.environ.get("VAULT_DB_USER") or (lines[0] if lines else "postgres")
    database = os.environ.get("VAULT_DB_NAME") or (lines[1] if len(lines) > 1 else user)

    out = _docker(["docker", "exec", container, "psql", "-U", user, "-d", database, "-tAc", sql])
    if out.returncode != 0:
        detail = (out.stderr or "").strip()[:300]
        if on_error == "skip":
            pytest.skip(f"cannot query the deployment database: {detail}")
        raise AssertionError(f"query failed: {detail}\n  sql: {sql}")
    return out.stdout.strip()


def _drop(table):
    """Best-effort teardown that can never raise.

    Deliberately not through `_psql`: on failure that either skips or raises, and either one
    raised from a `finally` REPLACES the in-flight exception -- so a teardown hiccup would turn the
    flip this file exists to produce into a silent SKIP or a misleading error.
    """
    subprocess.run(
        ["docker", "exec", _db_container(), "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "DROP TABLE IF EXISTS {table}"'],
        capture_output=True, text=True, timeout=60, check=False)


def _replay_onto(scratch, column):
    """Replay every boot statement naming `column` onto `scratch`. Returns how many ran.

    EVERY statement, not just the ADD COLUMN: replaying one of them would make the scratch table a
    partial reproduction, and would keep reporting a nullable column after a follow-up
    `SET NOT NULL` had already fixed real deployments.
    """
    replayed = 0
    for statement in _boot_statements():
        if column not in statement:
            continue
        prefix = next((p for p in (f"ALTER TABLE {TABLE} ", f"UPDATE {TABLE} ")
                       if statement.startswith(p)), None)
        if prefix is None:
            continue
        retargeted = statement.replace(prefix, prefix.replace(TABLE, scratch, 1), 1)
        # str.replace is a no-op on a miss, which would send the statement at the REAL table.
        # Refuse rather than rely on the statements happening to be idempotent. Checked by
        # substring rather than by word position: the table sits at a different index in
        # "ALTER TABLE x" than in "UPDATE x", and an index that is right for one is a false
        # rejection for the other.
        assert scratch in retargeted, retargeted
        assert TABLE not in retargeted, retargeted
        _psql(retargeted)
        replayed += 1
    assert replayed, f"no boot statement mentions {column}; the premise has changed"
    return replayed


def _nullability(table, columns):
    rows = _psql(
        "SELECT json_agg(json_build_object('c', column_name, 'n', is_nullable)) "
        f"FROM information_schema.columns WHERE table_name = '{table}' "
        f"AND column_name IN ({', '.join(repr(c) for c in columns)})")
    if not rows or rows == "null":
        return {}
    return {row["c"]: row["n"] for row in json.loads(rows)}


@pytest.mark.unit
def test_the_model_and_the_boot_ddl_disagree_about_nullability():
    """The source of the divergence: a declaration, an ALTER that does not implement it, and no
    follow-up statement that would.

    All three parts are asserted. Checking only the ADD COLUMN would let the real fix land -- a
    separate `ALTER COLUMN ... SET NOT NULL`, the idiom already used for five other columns -- while
    this test stayed green, which is the one thing a characterization test must not do.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    models = (root / "app" / "core" / "models.py").read_text(encoding="utf-8")
    statements = _boot_statements()

    # Non-vacuity: the parser really did find the DDL list, and it really does contain the idiom
    # this test says is available, so "no SET NOT NULL for these two" means something.
    assert len(statements) > 20, f"only found {len(statements)} boot statements; the list has moved"
    assert any(re.search(r"ALTER COLUMN \w+ SET NOT NULL", s) for s in statements), (
        "the boot DDL no longer contains a SET NOT NULL anywhere, so the claim that the fix is "
        "available in an existing idiom has stopped being true")

    for column in DIVERGENT:
        declaration = next((line for line in models.splitlines()
                            if line.strip().startswith(f"{column} = Column(")), None)
        assert declaration, f"{column} is no longer declared on the model"
        assert "nullable=False" in declaration, (
            f"{column} no longer declares nullable=False; this test's premise has changed")

        added = [s for s in statements if f"ADD COLUMN IF NOT EXISTS {column}" in s]
        assert added, f"{column} is no longer added by the boot DDL"
        for statement in added:
            assert "NOT NULL" not in statement, (
                f"the boot DDL now ADDS {column} as NOT NULL. On its own that is not a fix: on any "
                "database where the column already exists the statement is a no-op, so every "
                "deployment that already upgraded keeps a nullable column while a fresh install "
                "looks correct. Pair it with ALTER COLUMN ... SET NOT NULL, or use that alone")

        tightened = [s for s in statements
                     if re.search(rf"ALTER COLUMN {column} SET NOT NULL", s)]
        assert not tightened, (
            f"{column} is now tightened to NOT NULL by the boot DDL ({tightened}); the divergence "
            "has been closed and these tests should become an assertion that a fresh and an "
            "upgraded schema are identical")


@pytest.mark.unit
def test_the_upgrade_harness_checks_named_things_rather_than_the_whole_schema():
    """Why the divergence survives despite a fresh-vs-upgraded harness already existing.

    The harness does the expensive part -- previous release, seeded data, same-volume upgrade,
    health wait -- and asserts a fixed list of names. Anything not on that list, including both
    columns above, is upgraded without anyone looking. Closing this gap is a matter of widening a
    working harness, not building one.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    harness_path = root / "tests" / "test_upgrade_email_nullable.py"
    assert harness_path.exists(), (
        "the fresh-vs-upgraded harness has moved; this test's premise has changed")
    harness = harness_path.read_text(encoding="utf-8")

    # It really does upgrade over the old release's volumes -- otherwise it proves nothing about an
    # upgraded install and the gap here would be far wider than "it does not enumerate".
    assert "BASELINE_IMAGE" in harness and "ghcr.io/dockvault/vault:v" in harness

    # Every schema question it asks names the one thing it is asking about. A query that SELECTs a
    # column list without pinning which column -- the shape of a set comparison -- is what widening
    # looks like, and is what should flip this.
    asked = [q for q in _string_literals(harness)
             if "information_schema" in q or "pg_indexes" in q or "pg_catalog" in q]
    assert len(asked) >= 3, (
        f"found {len(asked)} schema queries in the harness; the loop below would pass by asking "
        "nothing")
    for query in asked:
        enumerates = (re.search(r"\bcolumn_name\b", query)
                      and not re.search(r"column_name\s*=\s*'", query))
        assert not enumerates, (
            "the harness now asks an open-ended schema question (%s); if it compares a fresh "
            "install against an upgraded one, this characterization is obsolete" % query.strip())
        assert re.search(r"(column_name|table_name|indexname)\s*=\s*'", query), (
            "the harness now asks an unpinned schema question (%s); if it compares a fresh "
            "install against an upgraded one, this characterization is obsolete" % query.strip())

    for column in DIVERGENT:
        assert column not in harness, (
            "%s is now covered by the upgrade harness; this characterization is obsolete" % column)


@pytest.mark.integration
def test_replaying_the_boot_ddl_leaves_both_install_shapes_nullable():
    """Reproduce the divergence rather than infer it from source, for BOTH shapes separately.

    The live database here reports NOT NULL for both columns, because this deployment created the
    table from the model. The upgraded shape only appears where the columns arrived through the
    ALTER, so it has to be built rather than found.

    Two scratch tables, because the two candidate fixes differ exactly here:

      * FRESH   -- a table that never had the column; the boot DDL adds it.
      * UPGRADED -- a table that already has the column, nullable, which is the shape every
        deployment that upgraded through the current release is in today.

    `ADD COLUMN ... NOT NULL` changes the fresh shape and leaves the upgraded one untouched, so it
    would report "fixed" while fixing nothing. `ALTER COLUMN ... SET NOT NULL` changes both. Telling
    them apart is the whole reason this test builds two tables instead of one.
    """
    run = uuid.uuid4().hex[:8]
    fresh, upgraded = f"schema_fresh_{run}", f"schema_upgraded_{run}"

    _psql(f"CREATE TABLE {fresh} (id integer)")
    try:
        _psql(f"CREATE TABLE {upgraded} (id integer)")
        try:
            # One row holding NULL in both columns, so the upgraded table is populated the way a
            # real one is. Without it, SET NOT NULL would succeed on an empty table and a fix that
            # forgot its backfill would look complete here while failing on every real deployment.
            # With it, the replay reports that failure loudly (_psql defaults to raising).
            for column, coltype in DIVERGENT.items():
                # The upgraded shape, stated rather than derived: today's deployments hold this
                # column nullable, which is the defect these tests exist to record.
                _psql(f"ALTER TABLE {upgraded} ADD COLUMN {column} {coltype}")
            _psql(f"INSERT INTO {upgraded} (id) VALUES (1)")

            for column in DIVERGENT:
                _replay_onto(fresh, column)
                _replay_onto(upgraded, column)

            after_fresh = _nullability(fresh, DIVERGENT)
            after_upgraded = _nullability(upgraded, DIVERGENT)
            assert set(after_fresh) == set(DIVERGENT), after_fresh
            assert set(after_upgraded) == set(DIVERGENT), after_upgraded

            print(f"[characterization] boot DDL onto a fresh table:    {after_fresh}")
            print(f"[characterization] boot DDL onto an upgraded table: {after_upgraded}")

            # Diagnose before asserting, so exactly one message fires and it is the right one.
            # Asserting on the fresh shape first would report "renamed rather than closed" for the
            # fix that closes it properly, which is precisely the wrong thing to tell a maintainer.
            assert after_fresh == after_upgraded, (
                f"a fresh table now gets {after_fresh} while an existing deployment gets "
                f"{after_upgraded}. The divergence has been RENAMED, not closed: ADD COLUMN is a "
                "no-op where the column already exists, so this changes new installs only and "
                "leaves every upgraded one exactly as it was. Use ALTER COLUMN ... SET NOT NULL")
            assert all(v == "YES" for v in after_fresh.values()), (
                f"both install shapes now agree on {after_fresh}; the divergence this records has "
                "been closed and these tests should become an assertion that a fresh and an "
                "upgraded schema are identical")
        finally:
            _drop(upgraded)
    finally:
        _drop(fresh)


@pytest.mark.integration
def test_the_database_under_test_is_the_fresh_half_not_the_upgraded_one():
    """A PREMISE GUARD, not a characterization -- it will not flip on the recommended fix.

    It exists because the replay test above builds the upgraded shape by hand, and that is only
    the right thing to do if the live database really is the fresh half. If this deployment were
    itself an upgraded one, the divergence could be read straight off it and the scratch tables
    would be unnecessary indirection.

    It is not inert: closing the divergence downward instead -- relaxing the model to
    `nullable=True` -- makes a fresh install start reporting YES, and this goes red.
    """
    email_nullable = _psql(
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_name = 'users' AND column_name = 'email'", on_error="skip")
    if not email_nullable:
        pytest.skip("users.email is absent; this database is not a vault schema")

    nullability = _nullability(TABLE, DIVERGENT)
    if not nullability:
        pytest.skip(f"{TABLE} does not exist in this database")
    assert set(nullability) == set(DIVERGENT), (
        f"expected both columns to exist, found {sorted(nullability)}")

    print(f"\n[premise] {TABLE} nullability on the deployment under test: {nullability}")
    assert all(value == "NO" for value in nullability.values()), (
        "this database permits NULL in columns the model forbids, which is the upgraded half of "
        f"the divergence ({nullability}). The replay test above assumes the fresh half -- if this "
        "deployment was upgraded into its current shape, that assumption is wrong and the "
        "divergence can be read directly from it instead")
