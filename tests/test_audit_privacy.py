"""The recording levels, offline: what an audit row keeps of the personal data attached to it.

app/core/audit_privacy.py decides, for every row AuditLogger.build_row makes (web and SFTP alike), what its
username, address, user agent and details keep, at the lower of the deployment's .env limit and the stored
level, and stamps the policy version. These tests read every call site for the detail keys it can write,
write real rows at each level on each channel, and check the start-up checks, the lock, the never-raise path
and the alerts. test_audit_privacy_live.py checks the same on a running stack.
"""
import ast
import collections
import inspect
import re
import tempfile
import textwrap
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_fingerprints as fp  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, AuditPrivacyPolicy, SecurityAlert, User  # noqa: E402
from app.services import audit_logger  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
FULL_LEVELS = {k: ap.FULL for k in ap.POLICY_KEYS}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    ap._reset_for_tests()
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    # A key of its own: without one a fingerprint cannot be made, and a row at the fingerprint level would be
    # written by the fallback (version -1, nothing recorded) and still pass a test that reads only what it lacks.
    monkeypatch.setattr(settings, "audit_fingerprint_key", "k" * 64)
    yield
    ap._reset_for_tests()


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'audit.db'}")
        for model in (User, AuditLog, AuditPrivacyPolicy, SecurityAlert):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _levels(**changed):
    levels = dict(ap.POLICY_ONE)
    levels.update(changed)
    return levels


def _stored(factory):
    db = factory()
    try:
        return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).first()
    finally:
        db.close()


# --------------------------------------------------------------------------- every key at every call site

AUDIT_FUNCTIONS = {"log_action", "build_row", "log_custom_action"}


def _trees():
    return {p: ast.parse(p.read_text(encoding="utf-8")) for p in APP.rglob("*.py")}


def _wrappers(trees):
    """Every function with a parameter named ``details`` (positional or keyword-only): the audit writes and every
    helper a caller hands its details to. Reaching too far is harmless: it only asks that more keys be
    classified. For each, the positions that parameter can take among a call's positional arguments."""
    found = {name: set() for name in AUDIT_FUNCTIONS}
    for tree in trees.values():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            positional = [a.arg for a in fn.args.posonlyargs + fn.args.args]
            if "details" in positional:
                skip = 1 if positional and positional[0] in ("self", "cls") else 0
                found.setdefault(fn.name, set()).add(positional.index("details") - skip)
            elif "details" in [a.arg for a in fn.args.kwonlyargs]:
                found.setdefault(fn.name, set())
    return found


def _returned_dicts(trees):
    """function name -> the dict expressions it returns (directly, or through a name it assigned one to)."""
    out = collections.defaultdict(list)
    for tree in trees.values():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            assigned = collections.defaultdict(list)
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned[target.id].append(node.value)
            for node in ast.walk(fn):
                if isinstance(node, ast.Return) and node.value is not None:
                    value = node.value
                    out[fn.name] += assigned.get(value.id, []) if isinstance(value, ast.Name) else [value]
    return out


def _paths(node, prefix=""):
    """Every key path a dict expression spells out (``key``, ``parent.key``)."""
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                yield prefix + k.value
                yield from _paths(v, prefix + k.value + ".")
            elif k is None:
                yield from _paths(v, prefix)              # **{...}: the keys it spreads in
    elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "dict":
        for kw in node.keywords:
            if kw.arg:
                yield prefix + kw.arg
    elif isinstance(node, ast.DictComp) and len(node.generators) == 1:
        # {k: v for k, v in (("key", value), ...)}: the pairs' first items; {k: f(k) for k in ("key", ...)}: the
        # names it iterates.
        source = node.generators[0].iter
        if isinstance(source, (ast.Tuple, ast.List)):
            for pair in source.elts:
                if (isinstance(pair, ast.Tuple) and pair.elts and isinstance(pair.elts[0], ast.Constant)
                        and isinstance(pair.elts[0].value, str)):
                    yield prefix + pair.elts[0].value
                elif isinstance(pair, ast.Constant) and isinstance(pair.value, str):
                    yield prefix + pair.value


def detail_paths(trees, root=ROOT):
    """path -> where it is written, for every literal detail key reachable from an audit write: a dict passed
    as details, or assigned (or subscript-assigned) to the name passed, in the same function."""
    wrappers = _wrappers(trees)
    returned = _returned_dicts(trees)
    found = collections.defaultdict(set)
    for path, tree in trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            assigned = collections.defaultdict(list)
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assigned[target.id].append(node.value)
                        elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                              and isinstance(target.slice, ast.Constant)):
                            assigned[target.value.id].append(ast.Dict(keys=[target.slice], values=[node.value]))
            for call in ast.walk(fn):
                if not isinstance(call, ast.Call):
                    continue
                callee = getattr(call.func, "attr", None) or getattr(call.func, "id", None)
                if callee not in wrappers:
                    continue
                given = [kw.value for kw in call.keywords if kw.arg == "details"]
                given += [call.args[i] for i in wrappers[callee] if i < len(call.args)]
                todo, seen = list(given), 0
                while todo and seen < 50:
                    node = todo.pop()
                    seen += 1
                    if isinstance(node, ast.Name):
                        todo += assigned.get(node.id, [])
                    elif isinstance(node, ast.BoolOp):
                        todo += node.values
                    elif isinstance(node, ast.IfExp):
                        todo += [node.body, node.orelse]
                    elif isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) in returned:
                        # A helper's result passed as the details: the dicts it returns.
                        todo += returned[getattr(node.func, "id", None) or node.func.attr]
                    else:
                        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "dict":
                            todo += node.args
                        for key in _paths(node):
                            found[key].add(f"{path.relative_to(root).as_posix()}:{call.lineno}")
    return found


def test_every_detail_key_a_call_site_writes_is_classified():
    paths = detail_paths(_trees())
    assert len(paths) > 120                 # the whole application, not a partial scan
    for wanted in ("email", "session_id", "filters.ip", "changes.password", "file_name", "error", "via"):
        assert wanted in paths, wanted
    unclassified = {p: sorted(w)[:2] for p, w in paths.items() if ap.kind_of(p) is None}
    assert not unclassified, ("detail keys with no recording kind; add each to audit_privacy.DETAIL_KEYS "
                              f"with what it holds: {unclassified}")


def test_the_scan_finds_a_key_through_a_variable_and_a_wrapper_and_reports_it(tmp_path):
    source = textwrap.dedent('''
        def _helper(db, actor, details=None):
            AuditLogger(db).log_action(action="x", status="success", user=actor, details=details)

        def route(db, actor):
            details = {"made_up_key": 1}
            details["second_made_up"] = 2
            AuditLogger(db).build_row(action="y", status="success", details=details)
            _helper(db, actor, {"third_made_up": {"inner_made_up": 3}})
    ''')
    found = detail_paths({tmp_path / "fake.py": ast.parse(source)}, root=tmp_path)
    assert set(found) == {"made_up_key", "second_made_up", "third_made_up", "third_made_up.inner_made_up"}
    assert [p for p in found if ap.kind_of(p) is not None] == []


def test_the_registry_holds_only_known_kinds_and_its_names_are_the_redacted_names():
    assert set(ap.DETAIL_KEYS.values()) <= set(ap.KINDS)
    names = {k for k, kind in ap.DETAIL_KEYS.items() if kind == ap.NAME}
    assert names == {"file_name", "folder_name", "old_name", "new_name", "vault_name"}
    assert set(audit_logger.REDACTED_NAME_KEYS) == names
    for secret in ("session_token", "password", "token", "passcode"):
        assert ap.kind_of(secret) == ap.SECRET
    assert ap.kind_of("changes.anything") == ap.IDENTIFIER
    assert ap.kind_of("changes.email") == ap.EMAIL
    assert ap.kind_of("filters.something_new") is None
    assert ap.kind_of("nobody_knows") is None


# --------------------------------------------------------------------------- levels on real rows

CHANNEL_NAMES = ("web", "sftp", "public_link")


def _write(factory, channel, *, levels, version=7, user_id=None, username="typed name", ip="198.51.100.77",
           ua="Mozilla/5.0 test", details=None, action="login_failure"):
    ap.use(ap.Policy(version, levels))
    db = factory()
    try:
        AuditLogger(db).log_action(action=action, status="failure", user_id=user_id, username=username,
                                   ip_address=ip, user_agent=ua, details=details, channel=channel)
    finally:
        db.close()
    return _stored(factory)


@pytest.mark.parametrize("channel", CHANNEL_NAMES)
@pytest.mark.parametrize("level,column,extra", [
    ("full", "198.51.100.77", None),
    ("shortened", None, "198.51.100.0/24"),
    ("none", None, None),
])
def test_the_address_at_each_level_on_each_channel(factory, channel, level, column, extra):
    row = _write(factory, channel, levels=_levels(ip=level))
    assert row.channel == channel and row.privacy_version == 7
    assert row.ip_address == column
    assert (row.recorded or {}).get("ip") == extra


@pytest.mark.parametrize("channel", CHANNEL_NAMES)
@pytest.mark.parametrize("level", ["full", "fingerprint", "none"])
def test_a_name_typed_at_a_failed_sign_in_at_each_level(factory, channel, level):
    row = _write(factory, channel, levels=_levels(signin_names=level))
    assert row.privacy_version == 7
    assert row.username == ("typed name" if level == "full" else None)
    kept = fp.fingerprint(fp.SIGNIN, "typed name") if level == "fingerprint" else None
    assert (row.recorded or {}).get("signin_name") == kept
    assert "typed name" not in repr(row.recorded)


def test_an_accounts_own_username_is_always_recorded(factory):
    db = factory()
    ada = User(username="ada", email="ada@example.test", password_hash="x")
    db.add(ada)
    db.commit()
    row = _write(factory, "web", levels={k: ap.NONE for k in ap.POLICY_KEYS}, user_id=ada.id, username=None,
                 action="login_success")
    assert row.username == "ada" and row.user_id == ada.id
    host = _write(factory, "web", levels={k: ap.NONE for k in ap.POLICY_KEYS}, username="operator@host",
                  action="user_updated")
    assert host.username == "operator@host"


@pytest.mark.parametrize("channel", CHANNEL_NAMES)
@pytest.mark.parametrize("level", ["full", "none"])
def test_the_user_agent_and_email_addresses_at_each_level(factory, channel, level):
    details = {"email": "ada@example.test", "to": "bob@example.test",
               "changes": {"email": {"old": "a@example.test", "new": "b@example.test"}, "role": {"old": 1, "new": 2}},
               "old_email": "c@example.test", "new_email": "d@example.test", "target_username": "ada"}
    row = _write(factory, channel, levels=_levels(emails=level, user_agent=level), details=details)
    assert row.user_agent == ("Mozilla/5.0 test" if level == "full" else None)
    if level == "full":
        assert row.details == details
    else:
        assert row.details == {"changes": {"role": {"old": 1, "new": 2}}, "target_username": "ada"}
    assert "example.test" not in repr(row.recorded) or level == "full"


@pytest.mark.parametrize("level", ["full", "fingerprint", "none"])
def test_names_are_never_kept_in_the_details(factory, level):
    details = {"file_name": "q3.xlsx", "folder_name": "HR", "old_name": "a", "new_name": "b", "vault_name": "V",
               "vault_id": "v-1"}
    row = _write(factory, "web", levels=_levels(names=level), details=details, action="file_uploaded")
    assert row.details == {"vault_id": "v-1"}
    for name in ("q3.xlsx", "HR", "'a'", "'b'", "'V'"):
        assert name not in repr(row.details)


def test_secrets_are_never_recorded_and_an_error_keeps_only_its_type(factory):
    details = {"session_token": "abc", "password": "pw", "token": "t", "session_id": "s-1", "error": "ValueError"}
    row = _write(factory, "web", levels=FULL_LEVELS, details=details, action="terminate_session")
    assert row.details == {"session_id": "s-1", "error": "ValueError"}
    row = _write(factory, "web", levels=FULL_LEVELS, details={"error": "boom: the file q3.xlsx is gone"},
                 action="file_upload")
    assert row.details == {}


def test_filter_values_follow_their_kinds(factory):
    details = {"format": "csv", "filters": {"ip": "203.0.113.9", "q": "salary", "user": "bob",
                                            "temp_credential": "contractor", "category": "files"}}
    row = _write(factory, "web", levels=_levels(ip="shortened", signin_names="none"), details=details,
                 action="audit_exported")
    assert row.details == {"format": "csv", "filters": {"category": "files"}}
    assert row.recorded["details"] == {"filters.ip": "203.0.113.0/24"}


def test_ipv6_and_mapped_addresses_are_shortened_to_their_networks():
    assert ap.shorten("2001:db8:1:2:3:4:5:6") == "2001:db8:1::/48"
    assert ap.shorten("::ffff:198.51.100.9") == "198.51.100.0/24"
    assert ap.shorten("testclient") is None
    assert ap.shorten(" 192.0.2.1 ") == "192.0.2.0/24"


def test_a_shortened_level_drops_an_address_it_cannot_read(factory):
    row = _write(factory, "web", levels=_levels(ip="shortened"), ip="testclient")
    assert row.ip_address is None and row.recorded is None


def test_an_address_longer_than_the_column_is_cut_rather_than_failing_the_row(factory):
    row = _write(factory, "web", levels=FULL_LEVELS, ip="1" * 80)
    assert row.ip_address == "1" * ap.IP_COLUMN_LENGTH


def test_at_policy_one_a_row_is_recorded_as_before_except_names(factory):
    """What earlier releases recorded, and what the proxy harness reads (.github/scripts/proxy_matrix.py
    reads audit_logs.ip_address for a failed sign-in by its username)."""
    harness = (ROOT / ".github" / "scripts" / "proxy_matrix.py").read_text(encoding="utf-8")
    assert "ip_address" in harness and "username" in harness
    row = _write(factory, "web", levels=dict(ap.POLICY_ONE), version=1,
                 details={"reason": "Invalid credentials", "vault_name": "V"})
    assert (row.username, row.ip_address, row.user_agent) == ("typed name", "198.51.100.77", "Mozilla/5.0 test")
    assert row.details == {"reason": "Invalid credentials"} and row.recorded is None and row.privacy_version == 1
    # NULL, as an earlier release leaves it, not a JSON null.
    db = factory()
    assert db.execute(sa.text("SELECT recorded IS NULL FROM audit_logs")).scalar() == 1
    db.close()


def test_a_process_that_writes_no_deployments_rows_holds_policy_one(monkeypatch):
    def no_database():
        raise AssertionError("read the database")

    monkeypatch.setattr(ap, "_default_session_factory", no_database)
    assert ap.current() == ap.DEFAULT_POLICY
    assert ap.DEFAULT_POLICY.version == 1 and dict(ap.DEFAULT_POLICY.levels) == ap.POLICY_ONE


def test_a_deployments_process_reads_the_policy_before_its_first_row(factory, monkeypatch):
    db = factory()
    db.add(AuditPrivacyPolicy(version=9, reason="admin", **{**FULL_LEVELS, "ip": "none"}))
    db.commit()
    db.close()
    monkeypatch.setattr(ap, "_default_session_factory", factory)
    ap.require()
    row = AuditLogger(factory()).build_row(action="logout", status="success", ip_address="192.0.2.1")
    assert row.privacy_version == 9 and row.ip_address is None
    from app.core import host_operator
    assert inspect.getsource(host_operator._run).count("audit_privacy.require()") == 1


# --------------------------------------------------------------------------- the .env limit, the lock

def test_a_limit_below_the_stored_level_wins_at_write_time(factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_ip", "shortened")
    monkeypatch.setattr(settings, "audit_max_signin_names", "none")
    row = _write(factory, "sftp", levels=FULL_LEVELS)
    assert row.ip_address is None and row.recorded == {"ip": "198.51.100.0/24"}
    assert row.username is None


def test_a_direct_edit_of_the_table_above_the_limit_is_ignored(factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_emails", "none")
    db = factory()
    db.add(AuditPrivacyPolicy(version=5, reason="admin", **{**FULL_LEVELS, "emails": "full"}))
    db.add(AuditPrivacyPolicy(version=6, reason="admin", **{**FULL_LEVELS, "ip": "everything"}))
    db.commit()
    db.close()
    policy = ap.load(factory)
    assert policy.version == 6
    assert ap.effective(policy.levels)["emails"] == ap.NONE
    assert ap.effective(policy.levels)["ip"] == ap.NONE          # not a level: the strictest
    db = factory()
    AuditLogger(db).log_action(action="test_email_sent", status="success", details={"to": "x@example.test"},
                               ip_address="192.0.2.1")
    db.close()
    row = _stored(factory)
    assert row.details == {} and row.ip_address is None and row.privacy_version == 6


def test_the_lock_makes_each_limit_the_level(factory, monkeypatch):
    monkeypatch.setattr(settings, "settings_locked_keys", "audit_levels")
    monkeypatch.setattr(settings, "audit_max_ip", "shortened")
    stored = {k: ap.NONE for k in ap.POLICY_KEYS}
    assert ap.effective(stored) == {**FULL_LEVELS, "ip": "shortened"}
    row = _write(factory, "web", levels=stored)
    assert row.username == "typed name" and row.recorded == {"ip": "198.51.100.0/24"}
    monkeypatch.setattr(settings, "settings_locked_keys", "*")
    assert ap.locked()
    monkeypatch.setattr(settings, "settings_locked_keys", "rate_limits")
    assert not ap.locked()


def test_the_lock_group_is_known_to_the_settings_lock(monkeypatch):
    from app.core import settings_registry
    monkeypatch.setattr(settings, "settings_locked_keys", "audit_levels")
    assert "audit_levels" not in settings_registry.unknown_locked_tokens()


@pytest.mark.parametrize("name", sorted(ap.ENV_NAMES.values()))
def test_a_limit_that_cannot_be_read_refuses_to_start_and_names_the_line(name, monkeypatch):
    from app.core import config
    from app.core.config import RuntimeBootstrapError, Settings
    candidate = Settings(**{name.lower(): "everything"})
    with pytest.raises(RuntimeBootstrapError) as raised:
        config._validate_runtime_settings(candidate)
    assert raised.value.code == "audit-recording-limit-invalid"
    assert f"{name} must be one of" in raised.value.safe_message
    assert f"{name}=full" in raised.value.safe_message
    assert "everything" not in raised.value.safe_message


@pytest.mark.parametrize("key,bad", [("emails", "shortened"), ("ip", "fingerprint"), ("user_agent", "shortened"),
                                     ("names", "shortened")])
def test_a_level_a_kind_does_not_have_is_unreadable(key, bad, monkeypatch):
    monkeypatch.setattr(settings, ap.env_field(key), bad)
    assert [p for p in ap.env_problems(settings) if p.startswith(ap.ENV_NAMES[key])]


def test_an_unreadable_limit_counts_as_none_where_it_is_read(monkeypatch):
    monkeypatch.setattr(settings, "audit_max_ip", "everything")
    assert ap.env_limits()["ip"] == ap.NONE
    assert ap.effective(FULL_LEVELS)["ip"] == ap.NONE


def test_the_limits_read_case_and_spaces_alike(monkeypatch):
    monkeypatch.setattr(settings, "audit_max_ip", " Shortened ")
    assert ap.env_problems(settings) == [] and ap.env_limits()["ip"] == "shortened"


# --------------------------------------------------------------------------- the start

def test_the_start_writes_policy_one_once(factory):
    first = ap.prepare(factory)
    second = ap.prepare(factory)
    assert first == second == ap.Policy(1, ap.POLICY_ONE)
    db = factory()
    rows = db.query(AuditPrivacyPolicy).all()
    assert [(r.version, r.reason, r.created_by_name) for r in rows] == [(1, "initial", "server configuration")]
    audits = db.query(AuditLog).filter(AuditLog.action == "audit_privacy_changed").all()
    assert len(audits) == 1 and audits[0].details["levels"] == ap.POLICY_ONE
    assert audits[0].username == "server configuration"
    db.close()
    assert ap.current() == first


def test_a_lowered_limit_is_written_as_a_new_version_signed_by_the_server(factory, monkeypatch):
    ap.prepare(factory)
    monkeypatch.setattr(settings, "audit_max_ip", "shortened")
    monkeypatch.setattr(settings, "audit_max_emails", "none")
    policy = ap.prepare(factory)
    assert policy.version == 2
    assert dict(policy.levels) == {**ap.POLICY_ONE, "ip": "shortened", "emails": "none"}
    db = factory()
    latest = db.query(AuditPrivacyPolicy).filter(AuditPrivacyPolicy.version == 2).one()
    assert (latest.reason, latest.created_by_name, latest.created_by) == ("limit", "server configuration", None)
    row = db.query(AuditLog).filter(AuditLog.resource_id == "2").one()
    assert row.details["old"] == ap.POLICY_ONE and row.details["previous_version"] == 1
    assert row.details["limits"]["ip"] == "shortened"
    db.close()
    assert ap.current() == policy                              # held as the policy in force
    assert ap.prepare(factory).version == 2                    # nothing more to bring down
    monkeypatch.setattr(settings, "audit_max_ip", "full")
    assert ap.prepare(factory).version == 2                    # a raised limit raises no level


def test_a_version_the_server_signs_keeps_its_name_whatever_the_level_of_typed_names(factory, monkeypatch):
    ap.prepare(factory)
    monkeypatch.setattr(settings, "audit_max_signin_names", "fingerprint")
    assert ap.prepare(factory).version == 2
    monkeypatch.setattr(settings, "audit_max_signin_names", "none")
    assert ap.prepare(factory).version == 3
    db = factory()
    rows = db.query(AuditLog).filter(AuditLog.action == ap.CHANGED_ACTION).order_by(AuditLog.resource_id).all()
    db.close()
    assert [r.resource_id for r in rows] == ["1", "2", "3"]
    for row in rows:
        assert (row.username, row.user_id) == ("server configuration", None)
        assert row.privacy_version >= 1 and "signin_name" not in (row.recorded or {})


def test_only_a_name_with_no_account_that_is_not_the_servers_own_counts_as_typed():
    assert not ap.username_is_typed(AuditLog(username=ap.SERVER_CONFIGURATION))
    assert not ap.username_is_typed(AuditLog(username="operator@host"))
    assert ap.username_is_typed(AuditLog(username="server configuration2"))
    assert not ap.username_is_typed(AuditLog(username="typed name", user_id=uuid.uuid4()))


def test_with_the_lock_the_start_sets_each_level_to_its_limit(factory, monkeypatch):
    monkeypatch.setattr(settings, "settings_locked_keys", "audit_levels")
    policy = ap.prepare(factory)
    assert policy.version == 2 and dict(policy.levels) == FULL_LEVELS
    db = factory()
    assert db.query(AuditPrivacyPolicy).filter(AuditPrivacyPolicy.version == 2).one().reason == "locked"
    db.close()


def test_the_start_takes_the_policies_lock_in_its_transaction():
    source = inspect.getsource(ap.prepare)
    assert source.index("lock_policies(db)") < source.index("read_latest(db)") < source.index("db.commit()")
    lock_source = inspect.getsource(ap.lock_policies)
    assert "pg_advisory_xact_lock" in lock_source


def test_the_web_app_starts_the_levels_before_any_row_and_sftp_without_waiting():
    from app.api import api_server
    from app.sftp import sftp_server
    life = inspect.getsource(api_server.lifespan)
    assert life.count("audit_privacy.start()") == 1
    assert life.index("_run_lightweight_migrations()") < life.index("audit_privacy.start()") < life.index(
        "_seed_admin_user()")
    sftp = inspect.getsource(sftp_server)
    assert sftp.count("audit_privacy.start(load_now=False)") == 1


# --------------------------------------------------------------------------- never raises, never loses a row

def test_a_failure_writes_the_row_without_personal_values_and_raises_an_alert(factory, monkeypatch):
    def broken(stored, settings=None):
        raise KeyError("boom")

    monkeypatch.setattr(ap, "effective", broken)
    ap.use(ap.Policy(3, FULL_LEVELS))
    db = factory()
    AuditLogger(db).log_action(action="login_failure", status="failure", username="eve", ip_address="192.0.2.8",
                               user_agent="UA", details={"reason": "x", "email": "e@example.test",
                                                         "filters": {"ip": "192.0.2.8"}})
    db.close()
    row = _stored(factory)
    assert row.privacy_version == ap.FALLBACK_VERSION == -1
    assert (row.username, row.ip_address, row.user_agent, row.recorded) == (None, None, None, None)
    db = factory()
    assert db.execute(sa.text("SELECT recorded IS NULL FROM audit_logs")).scalar() == 1
    db.close()
    assert row.details == {"reason": "x"}
    assert ap.pending_alerts() == [{"reason": "failed", "subject": "KeyError", "action": "login_failure"}]


def test_a_failure_while_reading_the_policy_is_one_too(factory, monkeypatch):
    def unreachable():
        raise ConnectionError("no database")

    monkeypatch.setattr(ap, "_default_session_factory", unreachable)
    ap.require()
    db = factory()
    row = AuditLogger(db).build_row(action="logout", status="success", username="operator@host",
                                    ip_address="192.0.2.8")
    assert row.privacy_version == -1 and row.username == "operator@host" and row.ip_address is None


def test_the_fallback_clears_what_was_already_recorded(factory):
    import uuid as _uuid
    from datetime import datetime
    row = AuditLog(id=_uuid.uuid4(), action="x", status="success", timestamp=datetime.utcnow(),
                   ip_address="192.0.2.1", recorded={"ip": "192.0.2.0/24", "details": {"filters.ip": "x"}})
    ap.fallback(row, {"count": 1, "email": "e@example.test"}, ValueError())
    db = factory()
    db.add(row)
    db.commit()
    assert db.execute(sa.text("SELECT recorded IS NULL, ip_address IS NULL FROM audit_logs")).one() == (1, 1)
    db.close()
    assert _stored(factory).details == {"count": 1}


def test_the_fallback_never_raises_whatever_the_row(monkeypatch):
    class Hostile:
        action = "x"

        def __setattr__(self, name, value):
            raise RuntimeError("no")

    ap.fallback(Hostile(), {"a": 1}, ValueError())
    ap.apply(Hostile(), {"a": 1})


def test_a_key_nothing_classifies_is_dropped_noted_and_alerted_once(factory):
    for _ in range(3):
        row = _write(factory, "web", levels=FULL_LEVELS, details={"reason": "x", "brand_new": "a value"},
                     action="thing_done")
        assert row.details == {"reason": "x"} and row.recorded == {"dropped": ["brand_new"]}
    assert ap.pending_alerts() == [{"reason": "unclassified", "subject": "brand_new", "action": "thing_done"}]


def test_a_key_that_is_not_a_plain_name_is_noted_without_its_text(factory):
    row = _write(factory, "web", levels=FULL_LEVELS, details={"Bob's salary is 90000": 1}, action="x")
    assert row.recorded == {"dropped": ["(a key that is not a plain name)"]}
    assert "salary" not in repr(ap.pending_alerts())


def test_details_that_are_not_a_set_of_keys_are_not_recorded(factory):
    db = factory()
    row = AuditLogger(db).build_row(action="x", status="success", details=["a@example.test"])
    assert row.details is None and row.recorded == {"dropped": ["(details that are not a set of keys)"]}


def test_the_alerts_are_written_by_the_background_turn_once_each(factory):
    ap.raise_alert(ap.UNCLASSIFIED, "brand_new", "thing_done")
    ap.raise_alert(ap.FAILED, "KeyError", "login_failure")
    assert ap.flush_alerts(factory) == 2 and ap.pending_alerts() == []
    db = factory()
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.message).all()
    assert [a.event_type for a in alerts] == ["audit_recording_degraded"] * 2
    assert {a.details["subject"] for a in alerts} == {"brand_new", "KeyError"}
    assert all(a.username is None and a.ip_address is None for a in alerts)
    db.close()
    assert ap.raise_alert(ap.UNCLASSIFIED, "brand_new", "thing_done") is False   # inside the cooldown


def test_an_alert_that_cannot_be_written_stays_queued(monkeypatch):
    ap.raise_alert(ap.FAILED, "KeyError", "x")

    def no_database():
        raise RuntimeError("down")

    assert ap.flush_alerts(no_database) == 0 and len(ap.pending_alerts()) == 1


def test_the_row_is_built_from_the_callers_details_and_the_callers_dict_is_untouched(factory):
    details = {"vault_name": "Finance", "email": "a@example.test", "vault_id": "v"}
    ap.use(ap.Policy(4, _levels(emails="none")))
    row = AuditLogger(factory()).build_row(action="vault_created", status="success", details=details)
    assert row.details == {"vault_id": "v"}
    assert details == {"vault_name": "Finance", "email": "a@example.test", "vault_id": "v"}


# --------------------------------------------------------------------------- the container's output

def test_the_failed_sign_in_line_shows_name_and_address_at_their_levels(monkeypatch):
    ap.use(ap.Policy(2, _levels(signin_names="none", ip="shortened")))
    assert ap.for_output(ap.SIGNIN_NAME, "eve") == "(not recorded)"
    assert ap.for_output(ap.ADDRESS, "198.51.100.4") == "198.51.100.0/24"
    ap.use(ap.Policy(3, FULL_LEVELS))
    assert ap.for_output(ap.SIGNIN_NAME, "eve") == "eve"
    from app.services import security_monitor
    source = inspect.getsource(security_monitor.SecurityMonitor.record_failed_login)
    line = source[source.index('logger.info(f"Failed login recorded'):]
    line = line[:line.index("\n\n") if "\n\n" in line else len(line)]
    assert "for_output(SIGNIN_NAME, username)" in line and "for_output(ADDRESS, ip_address)" in line
    assert "{username}" not in line and "{ip_address}" not in line


def test_for_output_never_raises(monkeypatch):
    monkeypatch.setattr(ap, "current", lambda: 1 / 0)
    assert ap.for_output(ap.ADDRESS, "192.0.2.1") == "(not recorded)"


# --------------------------------------------------------------------------- the call sites that carried more

def test_ending_a_session_records_neither_its_token_nor_its_address():
    from app.api import api_server
    source = inspect.getsource(api_server)
    blocks = [m.start() for m in re.finditer(r'action="terminate_session"', source)]
    assert len(blocks) == 2
    for start in blocks:
        call = source[start:source.index("\n        )", start)]
        assert "session_token" not in call and "ip_address" not in call, call


def test_a_failed_upload_records_the_errors_type_not_its_text():
    from app.api import api_server
    source = inspect.getsource(api_server)
    assert source.count("details={'error': type(e).__name__, 'file_name': upload_file.filename}") == 1
    assert "'error': str(e)" not in source and '"error": str(e)' not in source


def test_an_email_change_records_its_addresses_under_email_keys():
    from app.api import api_server
    source = inspect.getsource(api_server)
    assert source.count('details={"old_email": old_email, "new_email": new_email}') == 1
    assert ap.kind_of("old_email") == ap.kind_of("new_email") == ap.EMAIL


# --------------------------------------------------------------------------- the Events filters

def _events(factory, **filters):
    from app.services.activity_events import build_events_query
    db = factory()
    try:
        return [r.action for r in build_events_query(db.query(AuditLog), AuditLog, **filters).all()]
    finally:
        db.close()


def test_a_shortened_address_is_found_by_an_exact_address_and_a_narrow_block(factory):
    _write(factory, "web", levels=_levels(ip="shortened"), ip="198.51.100.77", action="short_row")
    _write(factory, "web", levels=FULL_LEVELS, ip="198.51.100.77", action="full_row")
    _write(factory, "web", levels=FULL_LEVELS, ip="203.0.113.1", action="other_row")
    assert sorted(_events(factory, ip="198.51.100.5")) == ["short_row"]
    assert sorted(_events(factory, ip="198.51.100.77")) == ["full_row", "short_row"]
    assert _events(factory, ip="203.0.113.1") == ["other_row"]


def test_the_shortened_match_for_each_kind_of_filter():
    import ipaddress
    from app.services.activity_events import shortened_match
    exact = shortened_match(AuditLog, ipaddress.ip_network("198.51.100.5/32"))
    narrow = shortened_match(AuditLog, ipaddress.ip_network("198.51.100.64/26"))
    wide = shortened_match(AuditLog, ipaddress.ip_network("198.51.0.0/16"))
    v6 = shortened_match(AuditLog, ipaddress.ip_network("2001:db8:1:2::/64"))
    block = shortened_match(AuditLog, ipaddress.ip_network("198.51.100.0/24"))
    assert exact.right.value == narrow.right.value == block.right.value == "198.51.100.0/24"
    assert v6.right.value == "2001:db8:1::/48"
    assert "<<=" in str(wide.compile(compile_kwargs={"literal_binds": True}))


def test_the_row_view_and_the_legacy_export_show_a_shortened_address(factory):
    from app.api import api_server
    from app.services.activity_events import row_view
    row = _write(factory, "web", levels=_levels(ip="shortened"))
    assert row_view(row)["ip_address"] == "198.51.100.0/24" and row_view(row)["privacy_version"] == 7
    assert api_server._audit_row_to_dict(row)["ip_address"] == "198.51.100.0/24"


def test_only_a_text_recorded_value_is_shown():
    from types import SimpleNamespace
    from app.services.activity_events import recorded_value
    assert recorded_value(SimpleNamespace(recorded={"ip": "192.0.2.0/24"}), "ip") == "192.0.2.0/24"
    assert recorded_value(SimpleNamespace(recorded={"ip": {"a": 1}}), "ip") is None
    assert recorded_value(SimpleNamespace(recorded=None), "ip") is None
    assert recorded_value(SimpleNamespace(), "ip") is None


def test_the_most_active_addresses_count_shortened_networks():
    from app.services import activity_summary
    source = inspect.getsource(activity_summary)
    assert source.count('func.coalesce(AuditLog.ip_address, AuditLog.recorded["ip"].as_string())') == 1


def test_the_recorded_values_are_indexed_in_the_background():
    from app.core import background_maintenance as bm
    steps = {s.name: s for s in bm.STEPS}
    assert "((recorded->>'ip'))" in steps["ix_audit_logs_recorded_ip"].sql
    assert "((recorded->>'signin_name'))" in steps["ix_audit_logs_recorded_signin_name"].sql
    assert all(steps[n].kind == bm.CREATE_INDEX for n in ("ix_audit_logs_recorded_ip",
                                                           "ix_audit_logs_recorded_signin_name"))


# --------------------------------------------------------------------------- the table, config, catalogue

def test_the_policies_table_only_grows():
    from app.api import api_server
    ddl = " ".join(api_server.AUDIT_PRIVACY_POLICIES_DDL)
    assert "BEFORE UPDATE OR DELETE ON audit_privacy_policies" in ddl
    assert "BEFORE TRUNCATE ON audit_privacy_policies" in ddl
    assert "RAISE EXCEPTION" in ddl
    source = inspect.getsource(api_server._run_lightweight_migrations)
    assert source.count("*AUDIT_PRIVACY_POLICIES_DDL") == 1
    columns = AuditPrivacyPolicy.__table__.c
    assert [c.name for c in columns if c.name in ap.POLICY_KEYS] == list(ap.POLICY_KEYS)
    assert all(not columns[k].nullable for k in ap.POLICY_KEYS)


def test_the_limits_are_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    from app.core.config import Settings
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for key, name in ap.ENV_NAMES.items():
        assert Settings.model_fields[name.lower()].default == "full"
        assert example.count(f"\n# {name}=full\n") == 1
    spec = importlib.util.spec_from_file_location("dockvault_levels", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config({"AUDIT_MAX_IP": "shortened", "AUDIT_MAX_NAMES": "full"}, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert "AUDIT_MAX_IP=shortened" in lines
    assert not [line for line in lines if line.startswith("AUDIT_MAX_NAMES")]


def test_the_change_is_in_the_catalogue():
    from app.core import audit_catalog
    entry = audit_catalog.lookup(ap.CHANGED_ACTION)
    assert entry is not None and entry.category == "administration"


def test_the_inventory_lists_the_table_and_the_limits():
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    assert "`audit_privacy_policies` (new in 0.34.0)" in text
    for name in ap.ENV_NAMES.values():
        assert f"`{name}`" in text
