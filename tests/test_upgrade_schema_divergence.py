"""A fresh install and an upgraded one must end up with the same schema.

There is no migration framework, which is a deliberate choice: a hand-maintained list of idempotent
DDL statements is replayed on every boot. What that list could not express by accident was a
column's nullability. Two columns were declared `nullable=False` on the model and added by an
`ALTER TABLE ... ADD COLUMN` that omitted `NOT NULL`, so a fresh install got the model's schema and
an upgraded install got the ALTER's -- one release, two physical schemas, and nothing comparing
them.

`ADD COLUMN ... NOT NULL` was not the fix and could not be: where the column already exists the
statement is a no-op, so it would have changed new installs only and left every upgraded one
exactly as it was. The fix is a backfill followed by `ALTER COLUMN ... SET NOT NULL`, the idiom the
list already used for five other columns.

These tests were CHARACTERIZATION -- they recorded the divergence so that closing it would make
them fail. It did, and they are now assertions that it stays closed. The end-to-end comparison of a
real fresh install against a real upgraded one lives in `test_upgrade_email_nullable.py`, which
boots the previous release and upgrades over its volumes; what is here is the cheap source-level
and single-database half that runs without either.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import uuid

import pytest

CONVERGED = {
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

    UPDATEs as well as ALTERs: a tightening needs its backfill, and replaying one without the other
    would not reproduce what a boot does.
    """
    from pathlib import Path
    boot = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(
        encoding="utf-8")
    return [s for s in _string_literals(boot)
            if s.strip().upper().startswith(("ALTER TABLE ", "UPDATE "))]


def _db_container():
    return os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _docker(args, timeout=60):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"cannot reach the docker engine: {exc}")


def _psql(sql, on_error="fail"):
    """Ask the deployment's own database, through its own container.

    `on_error` defaults to FAIL. Skipping on any non-zero exit meant a statement that genuinely
    errored reported as "cannot query the deployment database" and went green, indistinguishable
    from having no database at all -- a false pass in the one place this file executes anything.
    """
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
    """Teardown that cannot raise: an exception from a `finally` replaces the one in flight, so a
    hiccup here would hide a real failure."""
    subprocess.run(
        ["docker", "exec", _db_container(), "sh", "-c",
         f'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "DROP TABLE IF EXISTS {table}"'],
        capture_output=True, text=True, timeout=60, check=False)


def _replay_onto(scratch, column):
    """Replay every boot statement naming `column` onto `scratch`. Returns how many ran."""
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


def _table_exists(table):
    """Whether the table is in this database at all.

    Deliberately separate from reading its columns. A column that has gone missing makes the
    column query come back empty too, and that is precisely the divergence under test -- so the
    two cannot share an answer.
    """
    found = _psql("SELECT count(*) FROM information_schema.tables "
                  f"WHERE table_name = '{table}'")
    return found.strip() not in ("", "0")


@pytest.mark.unit
def test_the_boot_ddl_implements_what_the_model_declares():
    """The source of the old divergence, now the source of its fix.

    Three things together, because any two of them still leave a hole: the model declares NOT NULL,
    the ADD COLUMN does not claim to do it, and a later statement actually does. Dropping the third
    is how the divergence existed in the first place.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    models = (root / "app" / "core" / "models.py").read_text(encoding="utf-8")
    statements = _boot_statements()
    assert len(statements) > 20, f"only found {len(statements)} boot statements; the list has moved"

    for column in CONVERGED:
        declaration = next((line for line in models.splitlines()
                            if line.strip().startswith(f"{column} = Column(")), None)
        assert declaration, f"{column} is no longer declared on the model"
        assert "nullable=False" in declaration, (
            f"{column} no longer declares nullable=False. If the model was relaxed deliberately, "
            "the boot DDL's SET NOT NULL has to go with it or upgraded installs will diverge the "
            "other way")

        tightened = [s for s in statements
                     if re.search(rf"ALTER COLUMN {column} SET NOT NULL", s)]
        assert tightened, (
            f"nothing in the boot DDL tightens {column} to NOT NULL, so an upgraded install keeps "
            "the nullable column the ADD COLUMN gave it while a fresh install gets the model's")

        backfilled = [s for s in statements
                      if s.startswith(f"UPDATE {TABLE} ") and column in s and "IS NULL" in s]
        assert backfilled, (
            f"{column} is tightened with no backfill before it, so SET NOT NULL will fail on any "
            "deployment holding a row written before the column existed")


@pytest.mark.integration
def test_replaying_the_boot_ddl_converges_both_install_shapes():
    """Reproduce both shapes and check they agree, rather than infer it from source.

    Two scratch tables, because the two candidate fixes differ exactly here:

      * FRESH -- a table that never had the column; the boot DDL adds it.
      * UPGRADED -- a table that already has the column, nullable, holding a row, which is the
        shape every deployment that upgraded through an earlier release was in.

    `ADD COLUMN ... NOT NULL` would change the fresh shape and leave the upgraded one untouched.
    Only the backfill-then-tighten pair changes both, and only the row in the upgraded table makes
    a missing backfill visible -- SET NOT NULL succeeds on an empty table whether or not anyone
    remembered it.
    """
    run = uuid.uuid4().hex[:8]
    fresh, upgraded = f"schema_fresh_{run}", f"schema_upgraded_{run}"

    _psql(f"CREATE TABLE {fresh} (id integer)")
    try:
        _psql(f"CREATE TABLE {upgraded} (id integer)")
        try:
            for column, coltype in CONVERGED.items():
                _psql(f"ALTER TABLE {upgraded} ADD COLUMN {column} {coltype}")
            _psql(f"INSERT INTO {upgraded} (id) VALUES (1)")

            for column in CONVERGED:
                _replay_onto(fresh, column)
                _replay_onto(upgraded, column)

            after_fresh = _nullability(fresh, CONVERGED)
            after_upgraded = _nullability(upgraded, CONVERGED)
            assert set(after_fresh) == set(CONVERGED), after_fresh
            assert set(after_upgraded) == set(CONVERGED), after_upgraded

            assert after_fresh == after_upgraded, (
                f"a fresh table gets {after_fresh} while an existing deployment gets "
                f"{after_upgraded}; the two shapes have diverged again")
            assert all(value == "NO" for value in after_fresh.values()), (
                f"both shapes agree on {after_fresh}, but the model declares these NOT NULL. The "
                "tightening has been lost")
        finally:
            _drop(upgraded)
    finally:
        _drop(fresh)


@pytest.mark.integration
def test_this_deployment_holds_the_converged_shape():
    """The live database, which after this change should match the model whichever way it got here.

    Kept separate from the replay above because it asks a different question: not "do the
    statements converge" but "did they, here".
    """
    if not _table_exists(TABLE):
        pytest.skip(f"{TABLE} does not exist in this database")
    # An empty answer from here on means the columns are absent, which is divergence rather than
    # a reason to stand down -- the assertion below is what says so.
    nullability = _nullability(TABLE, CONVERGED)
    assert set(nullability) == set(CONVERGED), (
        f"expected both columns to exist, found {sorted(nullability)}")
    assert all(value == "NO" for value in nullability.values()), (
        f"this deployment permits NULL in columns the model forbids ({nullability}). If it was "
        "upgraded rather than installed fresh, the tightening did not reach it")


CREATED_BY_FK = "temporary_credentials_created_by_temp_credential_id_fkey"


@pytest.mark.unit
def test_the_boot_ddl_adds_the_created_by_temp_credential_fk():
    """temporary_credentials.created_by_temp_credential_id is declared with a self-referential
    ForeignKey(ondelete='SET NULL'), so create_all makes that constraint on a fresh install. The
    boot DDL that carries the column to an existing deployment must add the constraint too -- else a
    fresh install has the FK and an upgraded one does not, and deleting a temp credential that minted
    others leaves their provenance pointer dangling instead of nulling it (the same divergence class
    that files.modified_by had). This was red while the boot DDL added the column without the FK.
    """
    from pathlib import Path
    boot = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(
        encoding="utf-8")
    assert re.search(
        rf"ADD CONSTRAINT\s+{CREATED_BY_FK}\s+FOREIGN KEY\s*\(\s*created_by_temp_credential_id\s*\)"
        r"\s+REFERENCES\s+temporary_credentials\s*\(\s*id\s*\)\s+ON DELETE SET NULL",
        boot, re.IGNORECASE), (
        "the boot DDL adds temporary_credentials.created_by_temp_credential_id (declared with a "
        "ForeignKey) but never adds its FOREIGN KEY; a fresh create_all install gets the constraint "
        "and an upgraded one does not.")
    # Guarded so a re-run, and a fresh install that already carries create_all's identically-named
    # constraint, are both no-ops rather than a duplicate-constraint error. The guard is qualified by
    # conrelid: constraint names are unique per TABLE in Postgres, so a name-only check could be
    # satisfied by a same-named constraint on a different table and skip adding the one it means to.
    assert re.search(
        rf"FROM pg_constraint\s+WHERE conname\s*=\s*'{CREATED_BY_FK}'\s+"
        r"AND conrelid\s*=\s*'temporary_credentials'::regclass",
        boot, re.IGNORECASE), (
        "the created_by_temp_credential_id FK add is not guarded by a table-qualified pg_constraint "
        "existence check (conname AND conrelid), so it could fail on a fresh install that already has "
        "create_all's constraint, or be fooled by a same-named constraint on another table.")
    # And the FK add is preceded by a backfill that nulls any pre-existing dangling ids -- without it
    # ADD CONSTRAINT fails on a diverged install that accumulated some, rolls back, and crash-loops
    # that boot step every restart. It is the load-bearing line, so it is pinned too. Written as a
    # correlated NOT EXISTS (not NOT IN, which is silently never-true if the subquery yields a NULL).
    assert re.search(
        r"UPDATE temporary_credentials\b.*?SET created_by_temp_credential_id\s*=\s*NULL"
        r".*?NOT EXISTS\s*\(\s*SELECT 1 FROM temporary_credentials\b.*?"
        r"=\s*t\.created_by_temp_credential_id",
        boot, re.IGNORECASE | re.DOTALL), (
        "the FK add is not preceded by a null-the-dangling-ids backfill; ADD CONSTRAINT would fail "
        "and crash-loop the boot on a diverged install that accumulated dangling children.")


def _created_by_fk_do_block():
    """The exact guarded DO block from the boot DDL that adds the self-referential FK, as a string.

    Pulled from the source so the convergence test below replays the REAL statement -- a SQL error,
    an inverted guard, or a dropped backfill in it is then caught by an executing test, not only by
    the source-regex one.
    """
    from pathlib import Path
    boot = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(
        encoding="utf-8")
    blocks = [s for s in _string_literals(boot)
              if s.lstrip().startswith("DO $$") and CREATED_BY_FK in s]
    assert len(blocks) == 1, (
        f"expected exactly one boot DO block adding {CREATED_BY_FK}, found {len(blocks)}")
    return blocks[0]


@pytest.mark.integration
def test_the_boot_ddl_block_converges_an_upgraded_table_and_nulls_dangling_ids():
    """Replay the REAL guarded FK block onto a table in the UPGRADED shape (column present, no FK,
    holding a dangling id) and prove it converges. A fresh create_all database carries the FK from
    birth, so only this upgraded-shape replay actually exercises the fix -- on a fresh install the
    block's guard finds the constraint and does nothing. The column is self-referential, so the
    block is retargeted onto one scratch table.
    """
    run = uuid.uuid4().hex[:8]
    scratch = f"tc_fkconv_{run}"
    block = _created_by_fk_do_block().replace(TABLE, scratch)
    parent = "11111111-1111-1111-1111-111111111111"
    child = "22222222-2222-2222-2222-222222222222"
    orphan = "33333333-3333-3333-3333-333333333333"
    missing = "99999999-9999-9999-9999-999999999999"
    fk_count = (f"SELECT count(*) FROM pg_constraint "
                f"WHERE conrelid = '{scratch}'::regclass AND contype = 'f'")
    _psql(f"CREATE TABLE {scratch} (id uuid PRIMARY KEY, created_by_temp_credential_id uuid)")
    try:
        _psql(f"INSERT INTO {scratch} (id) VALUES ('{parent}')")
        _psql(f"INSERT INTO {scratch} (id, created_by_temp_credential_id) "
              f"VALUES ('{child}', '{parent}')")
        _psql(f"INSERT INTO {scratch} (id, created_by_temp_credential_id) "
              f"VALUES ('{orphan}', '{missing}')")
        assert _psql(fk_count) == "0", "the scratch table is not in the upgraded (no-FK) shape"

        _psql(block)

        deltype = _psql(f"SELECT confdeltype FROM pg_constraint "
                        f"WHERE conrelid = '{scratch}'::regclass AND contype = 'f'")
        assert deltype == "n", (
            f"the block did not add the self-referential FK with ON DELETE SET NULL "
            f"(confdeltype={deltype!r})")
        assert _psql(f"SELECT created_by_temp_credential_id IS NULL FROM {scratch} "
                     f"WHERE id = '{orphan}'") == "t", (
            "the dangling id was not nulled before the FK was added -- ADD CONSTRAINT would have "
            "failed on it")
        assert _psql(f"SELECT created_by_temp_credential_id FROM {scratch} "
                     f"WHERE id = '{child}'") == parent, "a valid provenance pointer was nulled"

        _psql(block)  # idempotent: the guard finds the FK and does nothing
        assert _psql(fk_count) == "1", "re-running the block duplicated or dropped the FK"

        _psql(f"DELETE FROM {scratch} WHERE id = '{parent}'")
        assert _psql(f"SELECT created_by_temp_credential_id IS NULL FROM {scratch} "
                     f"WHERE id = '{child}'") == "t", (
            "deleting a parent did not null its child's pointer (ON DELETE SET NULL is not in effect)")
    finally:
        _drop(scratch)


@pytest.mark.integration
def test_this_deployment_holds_the_created_by_temp_credential_fk():
    """The live database carries the self-referential FK, whichever way it got here. Kept alongside
    the replay above because it asks the "did they, here" question, not "do the statements converge";
    on a fresh install the FK comes from create_all, on an upgraded one from the boot block.
    """
    if not _table_exists(TABLE):
        pytest.skip(f"{TABLE} does not exist in this database")
    # confdeltype 'n' == ON DELETE SET NULL; an empty answer means the FK is absent (divergence).
    deltype = _psql(
        f"SELECT confdeltype FROM pg_constraint WHERE conname = '{CREATED_BY_FK}'", on_error="skip")
    assert deltype == "n", (
        "the live temporary_credentials table is missing its created_by_temp_credential_id foreign "
        f"key or its delete rule is not SET NULL (confdeltype={deltype!r}). A deployment upgraded "
        "before this fix diverges from a fresh install and dangles a child on parent deletion.")
