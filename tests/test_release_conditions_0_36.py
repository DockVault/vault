"""The upgrade-matrix conditions of 0.36.0 kept for the release commit (tests/_release_conditions_0_36.py), offline:
each query is one statement that only reads; the tables and columns it names are the ones listed with it, the models
have them, of the types its operators need, and those about coming back are 0.35.2's; each query and text says what
the code it describes does; the ids and keys are ones the matrix accepts; a matrix built from this file passes the
matrix check; and the matrix, once it declares 0.36.0, carries the one edge into it, from 0.35.2, with every
condition as kept here.
"""
import hashlib
import importlib.util
import inspect
import json
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import _release_conditions_0_36 as rc  # noqa: E402
from app.core.models import Base, KeptBase  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_WRITES = re.compile(r"\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|vacuum|lock|set|call|do)\b",
                     re.IGNORECASE)
# The queries write SQL's keywords in capitals; these are the lower-case words they use that name no table or column.
_SQL_WORDS = {"count", "encode", "sha256", "convert_to", "make_interval", "days", "now", "json_typeof",
              "json_array_length", "int", "false"}


def _matrix_script():
    spec = importlib.util.spec_from_file_location("upgrade_matrix_conditions_0_36", ROOT / ".github" / "scripts" /
                                                  "upgrade_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _matrix():
    return json.loads((ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8"))


def _tables():
    return {**Base.metadata.tables, **KeptBase.metadata.tables}


def _named(sql):
    """What a query names, from its text: {table: columns named through its alias} and the other names, with the
    string literals, the SQL words, the tables, their aliases and the query's own labels taken out."""
    bare = re.sub(r"'(?:[^']|'')*'", "''", sql)
    tables = set(re.findall(r"\b(?:FROM|JOIN) ([a-z_]+)\b", bare))
    aliases = {alias: table for table, alias in re.findall(r"\b(?:FROM|JOIN) ([a-z_]+) ([a-z])\b", bare)}
    labels = set(re.findall(r"\bAS ([a-z_]+)\b", bare)) | set(re.findall(r"\) ([a-z]) WHERE\b", bare))
    through_alias = {table: set() for table in tables}
    for alias, column in re.findall(r"\b([a-z])\.([a-z_]+)\b", bare):
        through_alias[aliases[alias]].add(column)
    rest = set(re.findall(r"\b[a-z_][a-z0-9_]*\b", re.sub(r"\b[a-z]\.[a-z_]+\b", "", bare)))
    return through_alias, rest - _SQL_WORDS - tables - set(aliases) - labels


def _git_show(path, tag="v" + rc.SOURCE):
    try:
        out = subprocess.run(["git", "show", f"{tag}:{path}"], cwd=ROOT, capture_output=True, text=True,
                             encoding="utf-8", timeout=60)
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"git show did not finish within {exc.timeout} s")
    if out.returncode != 0:
        pytest.fail(f"cannot read {path} at {tag}; these tests need the release tags (a full clone with tags)")
    return out.stdout


# --------------------------------------------------------------------------- the queries and what they read

def test_every_query_is_one_statement_that_only_reads():
    for cid, sql in rc.DETECT.items():
        assert sql.lstrip().upper().startswith(("SELECT", "WITH")), cid
        assert ";" not in sql, cid
        assert not _WRITES.search(sql), cid


def test_each_query_names_exactly_the_tables_and_columns_listed_with_it():
    assert set(rc.READS) == set(rc.DETECT)
    for cid, sql in rc.DETECT.items():
        through_alias, rest = _named(sql)
        listed = rc.READS[cid]
        assert set(through_alias) == set(listed), cid
        for table, columns in through_alias.items():
            assert columns <= listed[table], (cid, table, columns - listed[table])
        named = rest.union(*through_alias.values())
        assert named == set().union(*listed.values()), (cid, named ^ set().union(*listed.values()))


def test_every_table_and_column_a_query_reads_is_in_the_models_or_the_catalog():
    tables = _tables()
    for cid, reads in rc.READS.items():
        for table, columns in reads.items():
            if table in rc.CATALOG:
                assert columns <= rc.CATALOG[table], (cid, table)
                continue
            assert table in tables, (cid, table)
            assert columns <= set(tables[table].columns.keys()), (cid, table, columns - set(tables[table].columns.keys()))


def test_the_columns_are_of_the_types_the_queries_operators_need():
    tables = _tables()

    def column(table, name):
        return tables[table].columns[name].type

    # json_typeof and json_array_length take json; on jsonb they fail. ->> and #>> take either.
    assert isinstance(column("managed_settings", "value"), JSON)
    assert not isinstance(column("managed_settings", "value"), JSONB)
    for table, name in (("system_settings", "value"), ("sso_providers", "policy"), ("credential_changes", "payload")):
        assert isinstance(column(table, name), JSON), (table, name)
    # The digest is of the hash as text, 64 hex characters.
    assert isinstance(column("users", "password_hash"), String)
    assert isinstance(column("users", "password_nobody_knows"), String)
    assert column("users", "password_nobody_knows").length == 64
    assert isinstance(column("users", "sso_only"), Boolean)
    # Compared with now() AT TIME ZONE 'utc', a timestamp without a time zone.
    for name in ("refused_at", "last_sign_in_at", "linked_at"):
        assert isinstance(column("external_identities", name), DateTime), name
        assert not column("external_identities", name).timezone, name


def test_the_queries_about_coming_back_read_only_what_0_35_2_has():
    """They run on the database being upgraded: a 0.35.2 one, which may or may not have been on 0.36 before."""
    source = _git_show("app/core/models.py")
    coming_back = [cid for cid in rc.DETECT if cid not in rc.ON_UPGRADED]
    assert coming_back == ["back-on-0-36-after-an-earlier-release", "privileged-accounts-keep-a-password"]
    for cid in coming_back:
        for table, columns in rc.READS[cid].items():
            if table in rc.CATALOG:
                continue
            start = source.index(f"__tablename__ = '{table}'")
            end = source.find("\nclass ", start)
            body = source[start:end if end > 0 else None]
            for name in columns:
                assert re.search(rf"^\s+{name} = Column\(", body, re.MULTILINE), (cid, table, name)


def test_the_tables_that_tell_a_database_was_on_0_36_are_the_ones_0_36_makes():
    source = _git_show("app/core/models.py")
    tables = re.findall(r"'([a-z_]+)'", rc.DETECT["back-on-0-36-after-an-earlier-release"].split("IN (", 1)[1])
    assert tables[:2] == ["webauthn_credentials", "external_identities"]
    for table in tables[:2]:
        assert table in Base.metadata.tables, table
        assert f"__tablename__ = '{table}'" not in source, table


# --------------------------------------------------------------------------- each query says what the code does

def test_the_mark_of_a_password_nobody_knows_is_the_digest_the_query_computes():
    from app.core import password_origin
    sql = rc.DETECT["passwords-nobody-knows"]
    assert "password_nobody_knows = encode(sha256(convert_to(password_hash, 'UTF8')), 'hex')" in sql
    stored = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
    user = SimpleNamespace(password_hash=stored, password_nobody_knows=None)
    password_origin.mark_nobody_knows(user)
    assert user.password_nobody_knows == hashlib.sha256(stored.encode("utf-8")).hexdigest()
    assert password_origin.nobody_knows(user)
    # Any later hash ends the mark without clearing it, as the query's equality does.
    user.password_hash = stored + "x"
    assert not password_origin.nobody_knows(user)
    # The accounts held to their provider are counted by the condition before it.
    assert "NOT COALESCE(sso_only, false)" in sql and "WHERE sso_only" in rc.DETECT["provider-only-accounts"]


def test_the_refusal_the_query_counts_is_the_one_in_force():
    from app.services import sso_freshness
    sql = rc.DETECT["people-a-provider-no-longer-admits"]
    assert "(e.refused_at IS NOT NULL AND (e.last_sign_in_at IS NULL OR e.refused_at >= e.last_sign_in_at))" in sql
    day = datetime(2026, 6, 1)
    for refused in (None, day - timedelta(days=1), day, day + timedelta(days=1)):
        for last in (None, day):
            as_queried = refused is not None and (last is None or refused >= last)
            identity = SimpleNamespace(refused_at=refused, last_sign_in_at=last)
            assert sso_freshness.refusal_in_force(identity) is as_queried, (refused, last)


def test_the_days_the_query_counts_are_the_providers_freshness_days():
    from app.core import sso_policy
    from app.services import sso_freshness
    sql = rc.DETECT["people-a-provider-no-longer-admits"]
    assert sso_policy.DEFAULTS["sso_freshness_days"] == 30 and sso_policy._INTS["sso_freshness_days"][0] == 0
    assert "COALESCE((p.policy->>'sso_freshness_days')::int, 30) > 0" in sql
    assert ("COALESCE(e.last_sign_in_at, e.linked_at) + make_interval(days => "
            "COALESCE((p.policy->>'sso_freshness_days')::int, 30)) <= (now() AT TIME ZONE 'utc')") in sql
    # The days run from the last sign-in through the provider, else from the link, and count while the provider is
    # off, so the query reads every provider whatever its state.
    linked, signed_in = datetime(2026, 5, 1), datetime(2026, 5, 20)
    off = SimpleNamespace(policy={}, name="p", label="", state="disabled")
    for last, since in ((None, linked), (signed_in, signed_in)):
        identity = SimpleNamespace(id=1, user_id=2, provider_id=3, refused_at=None, last_sign_in_at=last,
                                   linked_at=linked)
        assert sso_freshness.deadline_of(identity, off).due == since + timedelta(days=30)
    assert "p.state" not in sql
    unasked = SimpleNamespace(id=1, user_id=2, provider_id=3, refused_at=None, last_sign_in_at=None, linked_at=linked)
    assert sso_freshness.deadline_of(unasked, SimpleNamespace(policy={"sso_freshness_days": 0}, name="p", label="",
                                                              state="enabled")) is None
    # A deadline is missed on its day, as the query's <= counts it.
    assert "found.due <= now" in inspect.getsource(sso_freshness.lapsed)


def test_the_second_factors_the_query_counts_are_the_ones_an_earlier_release_ignores():
    from app.core import second_factor, sso_policy
    sql = rc.DETECT["second-factors-an-earlier-release-does-not-know"]
    assert "s.status = 'active'" in sql and 'SecondFactorEnrollment.status == "active"' in inspect.getsource(
        second_factor._active_enrollment)
    assert "w.retired_at IS NULL" in sql
    assert sso_policy.DEFAULTS["sso_trust_idp_mfa"] is False and "sso_trust_idp_mfa" in sso_policy._BOOLS
    assert sso_policy.effective({"sso_trust_idp_mfa": True})["sso_trust_idp_mfa"] is True
    assert "p.state = 'enabled' AND p.policy->>'sso_trust_idp_mfa' = 'true'" in sql
    assert 'SsoProvider.state == "enabled"' in (ROOT / "app" / "services" / "sso_sign_in.py").read_text(
        encoding="utf-8")


def test_the_passkey_requirement_the_query_reads_lives_only_in_the_settings_store():
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as ws
    sql = rc.DETECT["role-must-hold-a-passkey"]
    assert (ws.MODE, ws.REQUIRED_ROLES, ws.REQUIRED_FOR_ROLES) == ("webauthn_mode", "webauthn_required_roles",
                                                                   "required_for_roles")
    assert f"m.key = '{ws.MODE}' AND m.value #>> '{{}}' = '{ws.REQUIRED_FOR_ROLES}'" in sql
    assert f"r.key = '{ws.REQUIRED_ROLES}'" in sql
    for key in (ws.MODE, ws.REQUIRED_ROLES):
        assert registry.spec_for(key).env is None, key      # no deployment value: the stored row is all there is
    assert registry.spec_for(ws.REQUIRED_ROLES).kind == "list"
    assert "db.query(ManagedSetting).all()" in (ROOT / "app" / "core" / "settings_registry.py").read_text(
        encoding="utf-8")


def test_the_passkey_text_states_the_defaults():
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as ws
    text = rc.SUMMARY["passkeys-on-by-default"]
    assert registry.spec_for(ws.MODE).default == ws.OPTIONAL
    assert registry.spec_for(ws.SIGN_IN_ROLES).default == ["user", "external"] and "admin" not in ws.SIGN_IN_CHOICES
    assert ("From 0.36.0 passkeys are on as an option (Settings, Sign-in methods): anyone may add one under Your "
            "account, and for the roles user and external a passkey that verifies the person signs in by itself; an "
            "administrator always types the password too.") in text


def test_a_held_confirmation_of_an_address_is_what_the_query_and_0_35_2_read():
    from app.core import credential_changes as cc
    sql = rc.DETECT["held-address-confirmations"]
    assert f"status = '{cc.HELD}' AND payload->>'confirm' = 'true'" in sql
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert 'db, current_user, user, "email",' in server
    assert 'payload={"email": normalize_email(user.email), "confirm": True}' in server
    assert cc.EMAIL == "email"
    # 0.35.2 knows no confirmation: approving the held change writes the address it names over the account's.
    older = _git_show("app/api/api_server.py")
    apply = older[older.index("def _make_credential_change("):]
    apply = apply[:apply.index("\ndef ", 1)]
    email = apply[apply.index("    if kind == cc.EMAIL:\n"):]
    email = email[:email.index("\n    if kind == ", 1)]
    assert 'new_email = payload.get("email")' in email and "target.email = new_email" in email
    assert "confirm" not in apply


def test_the_reset_switch_and_the_restored_sign_in_are_the_codes_own():
    from app.core import account_policy, audit_catalog
    server = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert '_SETTINGS_KEY = "global"' in server
    policy = server[server.index("\ndef _account_policy(db: Session) -> dict:"):]
    assert "SystemSetting.key == _SETTINGS_KEY" in policy[:policy.index("\ndef ", 1)]
    assert account_policy.effective_account_policy(None)["password_reset_enabled"] is False
    assert ("COALESCE((SELECT value->>'password_reset_enabled' FROM system_settings WHERE key = 'global'), 'false')"
            in rc.DETECT["provider-only-accounts"])
    assert "sso_password_sign_in_restored" in {action.name for action in audit_catalog.ACTIONS}
    assert 'action="sso_password_sign_in_restored"' in server
    assert "action = 'sso_password_sign_in_restored'" in rc.DETECT["privileged-accounts-keep-a-password"]


# --------------------------------------------------------------------------- the texts and the matrix

def test_every_condition_is_listed_once_and_each_set_is_drawn_from_them():
    assert len(rc.CONDITIONS) == len(set(rc.CONDITIONS))
    assert set(rc.CONDITIONS) == set(rc.DETECT) | set(rc.WITHOUT_DETECT)
    assert not set(rc.DETECT) & set(rc.WITHOUT_DETECT)
    assert set(rc.SUMMARY) == set(rc.CONDITIONS), "every condition's text is kept here, none only elsewhere"
    assert rc.ON_UPGRADED <= set(rc.DETECT)
    assert all(rc.SUMMARY[cid].startswith("Going back:") for cid in rc.ON_UPGRADED)
    assert all(rc.SUMMARY[cid].startswith("Coming back to 0.36") for cid in set(rc.DETECT) - rc.ON_UPGRADED)


def test_the_conditions_shown_on_the_way_back_are_the_ones_checked_on_the_upgraded_database():
    """dockvault.py shows, on the way back from 0.36.0, the edge's conditions whose text begins "Going back"
    (plan_downgrade_path); those must be exactly the ones whose queries run on the upgraded database."""
    assert {cid for cid in rc.CONDITIONS if rc.SUMMARY[cid].startswith("Going back")} == rc.ON_UPGRADED


def test_the_ids_texts_and_keys_are_ones_the_matrix_takes():
    um = _matrix_script()
    for cid in rc.CONDITIONS:
        assert um._ID_RE.fullmatch(cid), cid
        text = rc.SUMMARY[cid]
        assert text == text.strip() and "\n" not in text and all(32 <= ord(ch) < 127 for ch in text), cid
        assert set(rc.condition(cid)) <= um._CONDITION_KEYS
    assert set(rc.EDGE) | {"conditions"} <= um._EDGE_KEYS


def test_a_release_made_from_this_file_passes_the_matrix_check_and_this_one():
    data = rc.with_the_release(_matrix())
    _matrix_script().validate_matrix(data, released_ceiling=rc.INTO)
    assert rc.edge_problems(data) == []


def test_the_tests_build_the_same_release_from_the_matrix_the_release_commit_leaves():
    released = rc.with_the_release(_matrix())
    assert rc.with_the_release(released) == released


def test_the_matrix_carries_the_one_edge_into_0_36_0_once_it_declares_it():
    """The check the release commit's matrix must pass. Until it declares 0.36.0, the VERSION is below it."""
    matrix = _matrix()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if rc.INTO not in matrix["versions"]:
        assert tuple(map(int, version.split("."))) < tuple(map(int, rc.INTO.split("."))), version
        return
    assert rc.edge_problems(matrix) == []


def _drop(cid):
    def change(edge):
        edge["conditions"] = [c for c in edge["conditions"] if c["id"] != cid]
    return change


def _alter(cid, key, value):
    def change(edge):
        (found,) = [c for c in edge["conditions"] if c["id"] == cid]
        found[key] = value
    return change


def _swap(edge):
    edge["conditions"][1], edge["conditions"][2] = edge["conditions"][2], edge["conditions"][1]


def _set(key, value):
    def change(edge):
        edge[key] = value
    return change


@pytest.mark.parametrize("change, found", [
    (_drop("held-address-confirmations"), "the edge 0.35.2 -> 0.36.0 lists the conditions"),
    (_swap, "the edge 0.35.2 -> 0.36.0 lists the conditions"),
    (_alter("people-a-provider-no-longer-admits", "detect", "SELECT 1"),
     "the edge 0.35.2 -> 0.36.0 gives people-a-provider-no-longer-admits another text, query or flag"),
    (_alter("role-must-hold-a-passkey", "summary", "Another text."),
     "the edge 0.35.2 -> 0.36.0 gives role-must-hold-a-passkey another text, query or flag"),
    (_alter("passwords-nobody-knows", "blocks_rollback", True),
     "the edge 0.35.2 -> 0.36.0 gives passwords-nobody-knows another text, query or flag"),
    (_set("requires_backup", True), "the edge 0.35.2 -> 0.36.0 has requires_backup True, not False"),
    (_set("reversible", False), "the edge 0.35.2 -> 0.36.0 has reversible False, not True"),
])
def test_the_check_finds_an_edge_that_differs_from_the_one_kept_here(change, found):
    data = rc.with_the_release(_matrix())
    (edge,) = [e for e in data["edges"] if e["to"] == rc.INTO]
    change(edge)
    assert any(problem.startswith(found) for problem in rc.edge_problems(data)), rc.edge_problems(data)


def test_the_check_finds_another_edge_into_0_36_0_or_none():
    data = rc.with_the_release(_matrix())
    data["edges"].append(dict(rc.edge(), **{"from": "0.34.5"}))
    assert rc.edge_problems(data) == ["the edges into 0.36.0 leave from ['0.35.2', '0.34.5'], not from 0.35.2 alone"]
    data["edges"] = [e for e in data["edges"] if e["to"] != rc.INTO]
    assert rc.edge_problems(data) == ["the edges into 0.36.0 leave from [], not from 0.35.2 alone"]
