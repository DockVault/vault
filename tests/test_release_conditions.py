"""The upgrade-matrix conditions of 0.34.0 kept for the release commit (tests/_release_conditions.py), offline:
each query is one statement that only reads, names the tables it is listed with, which exist; the queries run on
the database being upgraded read only what 0.33.2 has; the conditions that block a rollback have a query; the ids
are ones the matrix accepts; each text kept there says what the code does; and the matrix, once it declares 0.34.0,
carries every condition on every edge into it, none of which leaves from below 0.33.6.
tests/test_release_conditions_live.py runs each query against a database.
"""
import copy
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import _release_conditions as rc  # noqa: E402
from app.core.models import Base, KeptBase  # noqa: E402

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
    tables = set(Base.metadata.tables) | set(KeptBase.metadata.tables)
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


def test_every_condition_is_listed_once_and_each_set_is_drawn_from_them():
    assert len(rc.CONDITIONS) == len(set(rc.CONDITIONS))
    assert set(rc.CONDITIONS) == set(rc.DETECT) | set(rc.WITHOUT_DETECT)
    assert set(rc.SUMMARY) <= set(rc.CONDITIONS)
    assert rc.BLOCKS_ROLLBACK <= rc.ON_UPGRADED <= set(rc.DETECT)


# --------------------------------------------------------------------------- the release commit's matrix

def _key(version):
    return tuple(int(part) for part in version.split("."))


def _matrix():
    return json.loads((ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8"))


def test_the_matrix_carries_every_condition_on_every_edge_into_0_34_0_from_0_33_6_or_later():
    """The check the release commit's matrix must pass. Until that commit declares 0.34.0 its VERSION is below it;
    from that commit on, the matrix declares it and every edge into it is checked."""
    matrix = _matrix()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if rc.INTO not in matrix["versions"]:
        assert _key(version) < _key(rc.INTO), f"VERSION is {version}: the matrix must declare {rc.INTO}"
        return
    assert rc.edge_problems(matrix) == []


def _with_the_release():
    """The matrix as the release commit would make it from this file (_release_conditions.with_the_release)."""
    return rc.with_the_release(_matrix())


def test_the_tests_build_the_same_release_from_the_matrix_the_release_commit_leaves(monkeypatch):
    """At the release commit docs/upgrade-matrix.json declares 0.34.0 and its edge from 0.33.6 itself: the release
    these tests check is built from the releases before 0.34.0, so it is the same one then as now."""
    released = _with_the_release()
    monkeypatch.setitem(globals(), "_matrix", lambda: copy.deepcopy(released))
    assert _with_the_release() == released
    assert rc.before_the_release(released) == rc.before_the_release(json.loads(
        (ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8")))


def _edge(data, source):
    (edge,) = [e for e in data["edges"] if e["from"] == source and e["to"] == rc.INTO]
    return edge


def test_a_release_entry_made_from_this_file_passes_the_matrix_check_and_this_one():
    data = _with_the_release()
    _matrix_script().validate_matrix(data, released_ceiling=rc.INTO)
    assert rc.edge_problems(data) == []


def _drop(cid):
    def change(data):
        edge = _edge(data, rc.SOURCE_FLOOR)
        edge["conditions"] = [c for c in edge["conditions"] if c["id"] != cid]
    return change


def _alter(cid, key, value):
    def change(data):
        (condition,) = [c for c in _edge(data, rc.SOURCE_FLOOR)["conditions"] if c["id"] == cid]
        if value is None:
            condition.pop(key, None)
        else:
            condition[key] = value
    return change


def _edge_from(source, kind="direct", conditions=True):
    def change(data):
        edge = {"from": source, "to": rc.INTO, "kind": kind, "reversible": False, "requires_backup": True}
        if kind == "blocked":
            edge["reason"] = "Upgrade to 0.33.6 first."
        if conditions:
            edge["conditions"] = [rc.condition(cid) for cid in rc.CONDITIONS]
        data["edges"].append(edge)
    return change


@pytest.mark.parametrize("change, found", [
    (_drop("legal-holds-block-rollback"), "the edge 0.33.6 -> 0.34.0 lacks the condition legal-holds-block-rollback"),
    (_drop("container-output-rotates"), "the edge 0.33.6 -> 0.34.0 lacks the condition container-output-rotates"),
    (_alter("recording-levels-changed", "blocks_rollback", None),
     "the edge 0.33.6 -> 0.34.0 leaves blocks_rollback off recording-levels-changed, which blocks a rollback"),
    (_alter("panel-retention-not-read", "blocks_rollback", True),
     "the edge 0.33.6 -> 0.34.0 marks panel-retention-not-read with blocks_rollback, which blocks none"),
    (_alter("audit-retention-runs-on-a-timer", "detect", "SELECT 1"),
     "the edge 0.33.6 -> 0.34.0 gives audit-retention-runs-on-a-timer another detect query than the one kept here"),
    (_alter("older-images-refuse-newer-data", "summary", "Another text."),
     "the edge 0.33.6 -> 0.34.0 gives older-images-refuse-newer-data another text than the one kept here"),
    (_edge_from("0.33.2"), "the edge 0.33.2 -> 0.34.0 skips 0.33.6: an edge into 0.34.0 leaves from 0.33.6 or later"),
    (_edge_from("0.33.5", conditions=False),
     "the edge 0.33.5 -> 0.34.0 lacks the condition audit-history-compressed-after-90-days"),
])
def test_the_check_finds_an_edge_into_0_34_0_that_lacks_a_condition_or_skips_0_33_6(change, found):
    data = _with_the_release()
    change(data)
    assert found in rc.edge_problems(data)


def test_the_matrix_check_takes_an_edge_that_skips_0_33_6_so_only_this_one_refuses_it():
    """An edge into the first release of the next line is a step from any release of the line before it
    (.github/scripts/upgrade_matrix.py), so the matrix's own check takes 0.33.2 -> 0.34.0 with no condition."""
    data = _with_the_release()
    _edge_from("0.33.2", conditions=False)(data)
    _matrix_script().validate_matrix(data, released_ceiling=rc.INTO)
    assert "the edge 0.33.2 -> 0.34.0 skips 0.33.6: an edge into 0.34.0 leaves from 0.33.6 or later" in (
        rc.edge_problems(data))


def test_an_edge_marked_blocked_from_below_0_33_6_is_left_alone():
    data = _with_the_release()
    _edge_from("0.33.2", kind="blocked", conditions=False)(data)
    assert rc.edge_problems(data) == []


def test_a_declared_0_34_0_with_no_edge_that_can_be_taken_into_it_is_found():
    data = _with_the_release()
    data["edges"] = [e for e in data["edges"] if e["to"] != rc.INTO]
    assert rc.edge_problems(data) == ["no edge that can be taken leads into 0.34.0"]


# --------------------------------------------------------------------------- the texts and queries kept here

def test_the_rollback_conditions_of_the_data_markers_are_the_markers_own():
    """The queries are the ones each marker keeps its row by, so the matrix finds what stops the older image."""
    from app.core import legal_hold_marker, recording_marker
    assert rc.DETECT["recording-levels-changed"] == recording_marker.STRICTER_SQL
    hold = legal_hold_marker.CONDITION
    assert rc.DETECT[hold["id"]] == hold["detect"] == legal_hold_marker.DETECT_SQL
    assert rc.SUMMARY[hold["id"]] == hold["summary"] and hold["blocks_rollback"] is True
    for cid in ("recording-levels-changed", "legal-holds-block-rollback", "older-images-refuse-newer-data"):
        assert cid in rc.BLOCKS_ROLLBACK and cid in rc.ON_UPGRADED, cid


def test_the_recording_levels_text_names_the_kinds_the_marker_counts():
    """Lowering any of the four kinds below Full writes the marker; lowering vault and file names, which earlier
    releases recorded no more of, does not."""
    from app.core import audit_privacy as ap
    from app.core import recording_marker
    text = rc.SUMMARY["recording-levels-changed"]
    assert text.count("names typed at sign-in, email addresses, IP addresses and browser descriptions") == 1
    kinds = (ap.SIGNIN_NAMES, ap.EMAILS, ap.IP, ap.USER_AGENT)
    assert all(ap.POLICY_ONE[kind] == ap.FULL for kind in kinds)
    for kind in kinds:
        assert recording_marker.records_less(dict(ap.POLICY_ONE, **{kind: ap.NONE})), kind
    assert not recording_marker.records_less(dict(ap.POLICY_ONE, **{ap.NAMES: ap.NONE}))
    assert "0.33.1 and later refuse to start" in text and "unless --force-downgrade is given" in text
    tool = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    assert '"--force-downgrade", dest="force_downgrade"' in tool


def test_the_text_on_older_images_names_the_reader_and_the_escape():
    from app.core import data_requirements as dr
    text = rc.SUMMARY["older-images-refuse-newer-data"]
    assert f"{dr.ESCAPE_VARIABLE}=true in .env" in text and f"the table {dr.TABLE}" in text
    assert "0.33.1 and later refuse to start" in text and "0.33.0 and earlier do not read the table" in text
    assert rc.DETECT["older-images-refuse-newer-data"] == (f"SELECT key, requires_at_least, reason, since "
                                                           f"FROM {dr.TABLE} ORDER BY key")


def test_the_text_on_older_images_names_every_record_kept_in_data_requirements():
    """Every module that writes a row into data_requirements, by the key it writes, and the words the text uses for
    it: a record added later that an earlier release cannot read must be named there too."""
    from app.core import audit_archive, compliance_marker, legal_hold_marker, recording_marker
    named = {"app/core/audit_archive.py": (audit_archive.MARKER_KEY, "archived audit days"),
             "app/core/legal_hold_marker.py": (legal_hold_marker.KEY, "legal holds and what they kept"),
             "app/core/recording_marker.py": (recording_marker.KEY, "recording levels below Full"),
             "app/core/compliance_marker.py": (compliance_marker.KEY, "open compliance cases and the records of "
                                                                      "compliance access while they must be kept")}
    # A module writes the row with an INSERT of its own, or through recording_marker.write_row, the one upsert the
    # markers that write theirs the same way share (the legal holds' marker does).
    writes = re.compile(r"INSERT INTO \{(?:\w+\.)?TABLE\} \(key, requires_at_least|\bwrite_row\(")
    writers = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "app").rglob("*.py")
                     if writes.search(path.read_text(encoding="utf-8")))
    assert writers == sorted(named)
    assert len({key for key, _words in named.values()}) == len(named)
    text = rc.SUMMARY["older-images-refuse-newer-data"]
    for path, (key, words) in named.items():
        assert text.count(words) == 1, (path, key)
    assert ("for as long as it lasts: archived audit days, legal holds and what they kept, recording levels below "
            "Full, and open compliance cases and the records") in text


def test_the_promotion_text_says_what_a_rollback_leaves_unrecorded():
    """The origin of a password is read from the audit log once, when 0.34.0 adds its columns; nothing reads what an
    earlier release did after a rollback (app/core/password_origin.py, add_columns_once)."""
    from app.core import password_origin
    text = rc.SUMMARY["promotion-resets-passwords-set-by-others"]
    assert text.count("a password an administrator set while it ran counts as the person's own") == 1
    assert text.count("At the upgrade this is read once from the audit log") == 1
    assert "A password set while an older release ran afterwards is not recorded" in (
        " ".join(password_origin.add_columns_once.__doc__.split()))
    assert "promotion-resets-passwords-set-by-others" in rc.WITHOUT_DETECT


def test_the_archive_texts_say_when_archiving_starts_again():
    """Archiving starts AUDIT_ARCHIVE_START_AFTER_DAYS after the first start, and again after a gap in sealing of
    more than 12 hours in which an earlier release wrote to the audit log, or of more than RESTART_AFTER whatever it
    held (app/core/audit_archive.py, grace_from); restored days take RESTORE_LOW to RESTORE_HIGH times their size."""
    from datetime import timedelta
    from app.core import audit_archive as arc
    from app.core import audit_chain_times as times
    from app.core import settings_registry as reg
    assert reg.spec_for(arc.START_AFTER_KEY).default == 14 and arc.RESTART_AFTER == timedelta(days=3)
    assert times.GAP_US == 12 * 3600 * 1000000
    said = ("more than 12 hours on an earlier release that wrote to the audit log, or more than 3 days on one or "
            "stopped")
    for cid in ("audit-history-compressed-after-90-days", "archived-audit-history-hidden"):
        assert rc.SUMMARY[cid].count(said) == 1, cid
    assert f"{arc.RESTORE_LOW} to {arc.RESTORE_HIGH} times their compressed size" in (
        rc.SUMMARY["archived-audit-history-hidden"])
