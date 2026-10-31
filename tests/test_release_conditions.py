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


def test_a_text_kept_here_is_for_a_condition_listed_and_one_the_matrix_takes():
    um = _matrix_script()
    assert set(rc.SUMMARY) <= set(rc.DETECT) | set(rc.WITHOUT_DETECT)
    for cid, text in rc.SUMMARY.items():
        assert text == text.strip() and "\n" not in text and all(32 <= ord(ch) < 127 for ch in text), cid
        condition = {"id": cid, "summary": text, **({"detect": rc.DETECT[cid]} if cid in rc.DETECT else {})}
        assert set(condition) <= um._CONDITION_KEYS


def test_the_envelope_holds_text_and_query_say_what_the_code_does():
    """Each fact the text states is the code's: the setting and its default, the window the query counts and the
    statuses and kinds it reads, where the code goes and when none can be sent, the two refusals and their statuses,
    and the host operator's action."""
    from datetime import timedelta
    from types import SimpleNamespace
    from app.core import credential_changes as cc
    from app.core import envelope_hold
    from app.core.config import Settings
    from app.services import zk_key_proof
    cid = "zk-envelope-held-after-admin-reset"
    text, sql = rc.SUMMARY[cid], rc.DETECT[cid]
    assert cid not in rc.ON_UPGRADED and cid not in rc.BLOCKS_ROLLBACK, "read on the database being upgraded"
    assert Settings.model_fields["zk_envelope_hold_days"].default == envelope_hold.MAX_DAYS == 14
    assert "for ZK_ENVELOPE_HOLD_DAYS days (14 by default)" in text and "ZK_ENVELOPE_HOLD_DAYS=0" in text
    assert cc.WINDOW == timedelta(days=14) and "in the 14 days before the upgrade" in text
    assert "c.applied_at > (now() AT TIME ZONE 'utc') - interval '14 days'" in sql
    assert set(cc.APPLIED) == {"made", "approved"} and "c.status IN ('made', 'approved')" in sql
    # Of each account, the earliest change: the one the code's address is read from. Only an email change kept the
    # address it replaced, as 0.33.x recorded it; one that replaced no address sends no code, like any other kind.
    assert "DISTINCT ON (c.target_user_id)" in sql and "ORDER BY c.target_user_id, c.applied_at)" in sql
    assert cc.EMAIL == "email" and "c.payload->>'previous_email' AS previous_email" in sql
    assert "FILTER (WHERE kind <> 'email' OR coalesce(btrim(previous_email), '') = '')" in sql
    def recorded(before):
        return cc.applied_email_payload({"old_email": before, "new_email": "new@example.com"})
    assert recorded("old@example.com")["previous_email"] == "old@example.com"
    assert cc.address_before(SimpleNamespace(kind=cc.EMAIL, payload=recorded("old@example.com"))) == "old@example.com"
    assert cc.address_before(SimpleNamespace(kind=cc.EMAIL, payload=recorded(None))) == ""
    assert cc.address_before(SimpleNamespace(kind="password", payload=None)) is None
    assert "or an email change of an account that had no address, or on a deployment without mail" in text
    assert "JOIN user_keypairs k ON k.user_id = c.target_user_id" in sql
    for reason in ("zk-envelope-hold", "zk-envelope-hold-no-mail"):
        status = zk_key_proof.REFUSALS[reason][0]
        assert f"({status} {reason})" in text or f"answers {status} {reason})" in text, reason
    router = (ROOT / "app" / "api" / "ecc_router.py").read_text(encoding="utf-8")
    assert 'raise zk_key_proof.KeyProofRefusal("zk-envelope-hold")' in router
    # No address to send the code to is the refusal without mail.
    assert ('address = (envelope_hold.code_destination(db, current_user) or "").strip()\n'
            '    if not address or not _smtp_configured(db):\n'
            '        raise zk_key_proof.KeyProofRefusal("zk-envelope-hold-no-mail")') in router
    tool = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    assert '("release-key-hold", ' in tool and "python dockvault.py accounts --action release-key-hold" in text


def test_the_envelope_holds_text_says_whom_its_check_cannot_count():
    """The query counts the accounts that have a key at the upgrade. The hold reads no key: an account changed in
    the 14 days before that sets up a key while the hold lasts is held too (tests/test_zk_envelope_hold.py), and no
    query run before can count it, so the text and the README say a check that finds none is not the all-clear."""
    cid = "zk-envelope-held-after-admin-reset"
    text, sql = rc.SUMMARY[cid], rc.DETECT[cid]
    assert sql.count("JOIN user_keypairs k ON k.user_id = c.target_user_id") == 1
    assert text.count("and an account changed then that has no key yet is held as soon as it sets one up, until the "
                      "hold ends.") == 1
    assert text.count("The check below counts the accounts held at the first start and those only the server's "
                      "operator can release; it cannot count an account that sets up a key later, so a check that "
                      "finds none does not mean no account will be held.") == 1
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("### Upgrading to 0.34.0")
    section = " ".join(readme[start:readme.index("\n### ", start + 1)].split())
    item = section[section.index("**Encryption keys of accounts an administrator changed lately:**"):]
    item = item[:item.index(" - **")]
    assert item.count("and changes made before the upgrade count, also for someone who sets up a key only after the "
                      "upgrade, while the hold lasts.") == 1


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
