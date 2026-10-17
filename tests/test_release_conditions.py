"""The detect queries kept for the release commit's upgrade-matrix conditions (tests/_release_conditions.py),
offline: each is one statement that only reads, names the tables it is listed with, which exist; the queries run
on the database being upgraded read only what 0.33.2 has; the condition that blocks a rollback has a query; and
the ids are ones the matrix accepts. tests/test_release_conditions_live.py runs each against a database.
"""
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import _release_conditions as rc  # noqa: E402
from app.core.models import Base  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_WRITES = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|vacuum|lock|set|call|do)\b",
                     re.IGNORECASE)


def _matrix_script():
    spec = importlib.util.spec_from_file_location("upgrade_matrix_conditions", ROOT / ".github" / "scripts" /
                                                  "upgrade_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _named_tables(sql):
    return set(re.findall(r"\b(?:from|join)\s+([a-z_]+)\b", sql, re.IGNORECASE)) - {"select"}


def test_every_query_is_one_statement_that_only_reads():
    for cid, sql in rc.DETECT.items():
        assert sql.lstrip().upper().startswith(("SELECT", "WITH")), cid
        assert ";" not in sql, cid
        assert not _WRITES.search(sql), cid


def test_each_query_finds_rows_only_where_its_condition_applies():
    for cid, sql in rc.DETECT.items():
        if "count(" in sql.lower():
            assert "HAVING count(*) > 0" in sql or sql.rstrip().endswith("> 0"), cid


def test_each_query_reads_the_tables_it_is_listed_with_and_they_exist():
    tables = set(Base.metadata.tables)
    assert set(rc.TABLES) == set(rc.DETECT)
    for cid, sql in rc.DETECT.items():
        assert _named_tables(sql) - {"t"} == rc.TABLES[cid], cid
        assert rc.TABLES[cid] <= tables, cid


def test_the_queries_on_the_database_being_upgraded_read_only_what_0_33_2_has():
    for cid, sql in rc.DETECT.items():
        if cid in rc.ON_UPGRADED:
            continue
        for table in rc.TABLES[cid]:
            assert table in rc.OLDER_SCHEMA, (cid, table)
            columns = set(re.findall(r"\b([a-z_]+)\s*(?:<|IS\b)", sql))
            current = set(Base.metadata.tables[table].columns.keys())
            assert rc.OLDER_SCHEMA[table] <= current, table
            assert columns <= set().union(*(rc.OLDER_SCHEMA[t] for t in rc.TABLES[cid])), (cid, columns)


def test_the_archive_condition_counts_what_archiving_moves_when_it_starts():
    """Archiving starts AUDIT_ARCHIVE_START_AFTER_DAYS after the upgrade and moves the days before the day
    AUDIT_HOT_DAYS ago: with the defaults, the days before the day their difference ago today."""
    from app.core import audit_archive
    from app.core import settings_registry as reg
    days = reg.spec_for(audit_archive.HOT_DAYS_KEY).default - reg.spec_for(audit_archive.START_AFTER_KEY).default
    assert days == 76
    assert (f"WHERE timestamp < date_trunc('day', (now() AT TIME ZONE 'utc') - interval '{days} days') "
            in rc.DETECT["audit-history-compressed-after-90-days"])


def test_the_older_schema_listed_is_0_33_2s():
    try:
        out = subprocess.run(["git", "show", "v0.33.2:app/core/models.py"], cwd=ROOT, capture_output=True, text=True,
                             timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"git is not available: {exc}")
    if out.returncode != 0:
        pytest.skip("the v0.33.2 tag is not in this checkout")
    source = out.stdout
    for table, columns in rc.OLDER_SCHEMA.items():
        start = source.index(f"__tablename__ = '{table}'")
        end = source.find("\nclass ", start)
        body = source[start:end if end > 0 else None]
        for column in columns:
            assert re.search(rf"^\s+{column} = Column\(", body, re.MULTILINE), (table, column)


def test_the_condition_ids_are_ones_the_matrix_accepts_and_the_rollback_one_has_a_query():
    um = _matrix_script()
    for cid in list(rc.DETECT) + list(rc.WITHOUT_DETECT):
        assert um._ID_RE.fullmatch(cid), cid
    assert len(set(rc.DETECT) | set(rc.WITHOUT_DETECT)) == len(rc.DETECT) + len(rc.WITHOUT_DETECT)
    assert rc.BLOCKS_ROLLBACK <= set(rc.DETECT) and rc.BLOCKS_ROLLBACK <= rc.ON_UPGRADED
    conditions = [{"id": cid, "summary": "s", "detect": sql, **({"blocks_rollback": True}
                                                               if cid in rc.BLOCKS_ROLLBACK else {})}
                  for cid, sql in rc.DETECT.items()] + [{"id": cid, "summary": "s"} for cid in rc.WITHOUT_DETECT]
    for condition in conditions:
        assert set(condition) <= um._CONDITION_KEYS
