"""Every column the models declare on a table 0.33.5 already had reaches an install upgraded from 0.33.5.

create_all builds the tables an install lacks and never changes a table it has. An install upgraded from 0.33.5 has
every table 0.33.5 declared (tests/_schema_0_33_5.py), so a column added since to one of them reaches it only through
an ADD COLUMN among the statements the start runs (app/api/api_server.py, _run_lightweight_migrations). Almost every
other test runs on a fresh install, where create_all builds the column with its table: a missing statement would pass
them all and leave every upgraded install without the column, and each request that reads it failing (a column of
active_sessions is read by every signed-in request). test_upgrade_email_nullable.py compares a fresh install with one
upgraded from an older release on real stacks; a table made after that release is new to it, so it cannot see this.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import _schema_0_33_5 as older  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import password_origin  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_ADD = re.compile(r"\bADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?(\w+)\"?", re.IGNORECASE)
_TABLE = re.compile(r"^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?\"?(\w+)\"?", re.IGNORECASE)


def _strings(node) -> list:
    """Every string literal under ``node``, an f-string's literal parts joined."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
        elif isinstance(n, ast.JoinedStr):
            out.append("".join(p.value for p in n.values if isinstance(p, ast.Constant) and isinstance(p.value, str)))
    return out


def _start():
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    (func,) = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_run_lightweight_migrations"]
    return tree, func


def _start_statements() -> list:
    """The statements the start's migrations hold: the literals inside _run_lightweight_migrations, the
    module-level statements it names (AUDIT_ROW_COLUMNS_DDL), and the users' columns it adds through
    password_origin.add_columns_once."""
    tree, func = _start()
    named = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
    out = _strings(func)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in named for t in node.targets):
            out += _strings(node.value)
    calls = [n for n in ast.walk(func) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "add_columns_once" and getattr(n.func.value, "id", "") == "password_origin"]
    if calls:
        out.append(password_origin.COLUMNS_DDL)
    return out


def _added_at_start() -> set:
    """{(table, column)} each ALTER TABLE ... ADD COLUMN of the start adds."""
    added = set()
    for statement in _start_statements():
        table = _TABLE.match(statement)
        if table:
            added |= {(table.group(1), column) for column in _ADD.findall(statement)}
    return added


def _new_on_older_tables() -> list:
    out = []
    for name, table in sorted(m.Base.metadata.tables.items()):
        if name in older.TABLES:
            out += [(name, c) for c in sorted(table.columns.keys()) if c not in older.TABLES[name]]
    return out


def test_every_column_added_since_0_33_5_to_a_table_it_had_is_added_by_the_start():
    added = _added_at_start()
    missing = [f"{t}.{c}" for t, c in _new_on_older_tables() if (t, c) not in added]
    assert not missing, (
        "the models declare these columns on tables 0.33.5 already had, and no ADD COLUMN of the start adds "
        "them, so an install upgraded from 0.33.5 never gets them: " + ", ".join(missing))


def test_the_guard_sees_the_columns_it_is_about():
    """Not vacuous: the columns 0.34.0 adds to older tables are found as new and as added, a column the start does
    not add is found missing, and every table 0.33.5 had is still declared."""
    new = set(_new_on_older_tables())
    for column in (("active_sessions", "zk_envelope_released_at"), ("credential_changes", "envelope_released_at"),
                   ("user_keypairs", "registered_after_admin_change"), ("vaults", "rotation_owed_epoch"),
                   ("audit_logs", "case_id"), ("users", "password_set_by_other_at")):
        assert column in new and column in _added_at_start(), column
    assert set(older.TABLES) <= set(m.Base.metadata.tables), "a table 0.33.5 had is no longer declared"
    assert ("vaults", "a_column_nobody_adds") not in _added_at_start()


@pytest.mark.parametrize("statement, columns", [
    ("ALTER TABLE t ADD COLUMN IF NOT EXISTS a INTEGER", {("t", "a")}),
    ("ALTER TABLE t ADD COLUMN IF NOT EXISTS a BYTEA, ADD COLUMN IF NOT EXISTS b JSONB", {("t", "a"), ("t", "b")}),
    ("ALTER TABLE t ADD COLUMN a INTEGER", {("t", "a")}),
    ("ALTER TABLE t ALTER COLUMN a SET NOT NULL", set()),
    ("UPDATE t SET a = 1", set()),
])
def test_how_a_statement_is_read(monkeypatch, statement, columns):
    monkeypatch.setattr(sys.modules[__name__], "_start_statements", lambda: [statement])
    assert _added_at_start() == columns


def test_the_start_runs_what_the_guard_reads():
    """The module-level statements and the users' columns are run by the start's migrations, not only declared."""
    _tree, func = _start()
    body = ast.unparse(func)
    assert "AUDIT_ROW_COLUMNS_DDL" in body and "password_origin.add_columns_once(db)" in body
    assert "db.execute(text(COLUMNS_DDL))" in Path(password_origin.__file__).read_text(encoding="utf-8")


def test_the_older_schema_listed_is_0_33_5s(tmp_path):
    """The list is what the models at the v0.33.5 tag declare: read from that tag's tree, in a process of its own,
    when the checkout has the tag."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available")
    archive = subprocess.run([git, "archive", "--format=tar", "v0.33.5", "app"], cwd=ROOT, capture_output=True,
                             timeout=120)
    if archive.returncode != 0:
        pytest.skip("the v0.33.5 tag is not in this checkout")
    tree = tmp_path / "v0.33.5"
    tree.mkdir()
    with tempfile.TemporaryFile() as raw:
        raw.write(archive.stdout)
        raw.seek(0)
        with tarfile.open(fileobj=raw) as tar:
            tar.extractall(tree, filter="data")
    script = tmp_path / "dump.py"
    script.write_text("import json, os, sys\nsys.path.insert(0, os.getcwd())\nfrom app.core import models\n"
                      "tables = models.Base.metadata.tables.items()\n"
                      "print(json.dumps({n: sorted(t.columns.keys()) for n, t in tables}))\n", encoding="utf-8")
    done = subprocess.run([sys.executable, "-I", str(script)], cwd=tree, capture_output=True, text=True,
                          timeout=180, env=dict(os.environ))
    assert done.returncode == 0, done.stderr[-2000:]
    found = json.loads(done.stdout.strip().splitlines()[-1])
    assert {name: tuple(columns) for name, columns in found.items()} == older.TABLES
