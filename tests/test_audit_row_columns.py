"""The audit row's new columns and the hooks AuditLogger.build_row calls before a row is written, offline.

Five columns on audit_logs (seal_nonce, privacy_version, recorded, ip_via, case_id) and ip_via on
security_alerts are nullable with no default, added at start by one statement per table, so Postgres
adds them without rewriting a row and a release that does not know them ignores them. build_row sets
the row's id itself, then calls four hooks in a fixed order (app/services/audit_row_hooks.py); privacy
applies the recording levels (tests/test_audit_privacy.py), and the others leave the row alone. test_audit_row_columns_live.py checks the columns on a
running stack's database.
"""
import ast
import inspect
import re
import tempfile
import textwrap
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.models import AuditLog, SecurityAlert, User  # noqa: E402
from app.services import audit_logger, audit_row_hooks  # noqa: E402
from app.services.audit_logger import AuditLogger, REDACTED_NAME_KEYS  # noqa: E402

pytestmark = pytest.mark.unit

AUDIT_COLUMNS = {"seal_nonce": "BYTEA", "privacy_version": "INTEGER", "recorded": "JSONB",
                 "ip_via": "VARCHAR(24)", "case_id": "UUID"}
HOOKS = ("provenance", "case", "privacy", "seal_nonce")


def _pg_type(column):
    return column.type.compile(dialect=postgresql.dialect())


# --------------------------------------------------------------------------- the columns

@pytest.mark.parametrize("name,pg_type", sorted(AUDIT_COLUMNS.items()))
def test_each_audit_column_is_nullable_with_no_default(name, pg_type):
    column = AuditLog.__table__.c[name]
    assert column.nullable and not column.primary_key
    assert column.default is None and column.server_default is None
    assert _pg_type(column) == pg_type


def test_security_alerts_gains_ip_via_the_same_way():
    column = SecurityAlert.__table__.c["ip_via"]
    assert column.nullable and column.default is None and column.server_default is None
    assert _pg_type(column) == _pg_type(AuditLog.__table__.c["ip_via"]) == "VARCHAR(24)"


def _added(ddl):
    """name -> type for each ADD COLUMN IF NOT EXISTS in one ALTER TABLE, and the rest of the text."""
    added = dict(re.findall(r"ADD COLUMN IF NOT EXISTS (\w+) ([A-Z]+(?:\(\d+\))?)(?=,|$)", ddl))
    return added


def test_one_statement_adds_the_five_columns_with_the_models_types_and_nothing_else():
    ddl = api.AUDIT_ROW_COLUMNS_DDL
    assert ddl.startswith("ALTER TABLE audit_logs ")
    assert _added(ddl) == AUDIT_COLUMNS
    assert ddl.count("ADD COLUMN IF NOT EXISTS") == len(AUDIT_COLUMNS)
    # Nothing that would make Postgres rewrite the table or refuse the older release's inserts.
    assert not re.search(r"\b(DEFAULT|NOT NULL|PRIMARY|REFERENCES|UNIQUE|CHECK)\b", ddl, re.I)


def _migration_statements():
    """The elements of the `statements` list _run_lightweight_migrations replays at start."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(api._run_lightweight_migrations)))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "statements" for t in node.targets)
                and isinstance(node.value, ast.BinOp) and isinstance(node.value.right, ast.List)):
            return node.value.right.elts
    raise AssertionError("the start-up statement list was not found")


def test_the_start_up_statements_add_them():
    elements = _migration_statements()
    names = [e.id for e in elements if isinstance(e, ast.Name)]
    texts = [e.value for e in elements if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    assert names.count("AUDIT_ROW_COLUMNS_DDL") == 1
    assert texts.count("ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS ip_via VARCHAR(24)") == 1


# --------------------------------------------------------------------------- build_row and its hooks

@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'audit.db'}")
        for model in (User, AuditLog):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def calls(monkeypatch):
    """Each hook, recording the row's id, the row itself and (for privacy) the details it was given."""
    seen = []

    def recorder(name):
        def hook(row, *rest):
            seen.append((name, row.id, row, rest))
        return hook

    for name in HOOKS:
        monkeypatch.setattr(audit_row_hooks, name, recorder(name))
    return seen


def test_build_row_sets_the_id_before_any_hook_and_calls_each_once_in_order(db, calls):
    row = AuditLogger(db).build_row(action="thing_done", status="success", username="ada")
    assert [c[0] for c in calls] == list(HOOKS)
    assert all(c[2] is row for c in calls)
    ids = {c[1] for c in calls}
    assert len(ids) == 1 and isinstance(row.id, uuid.UUID) and ids == {row.id}
    assert row.id.version == 4


def test_the_id_the_hooks_saw_is_the_one_stored(db, calls):
    row = AuditLogger(db).log_action(action="thing_done", status="success", username="ada")
    seen = calls[0][1]
    db.expire_all()
    stored = db.query(AuditLog).one()
    assert stored.id == seen == row.id


def test_every_row_gets_its_own_id(db, calls):
    first = AuditLogger(db).build_row(action="a", status="success")
    second = AuditLogger(db).build_row(action="a", status="success")
    assert first.id != second.id


def test_privacy_is_given_a_copy_of_the_callers_details_and_alone_gives_the_row_any(db, calls):
    details = {"file_name": "report.pdf", "vault_name": "Finance", "size": 3, "parts": {"n": 1}, "tags": ["a"]}
    row = AuditLogger(db).build_row(action="file_uploaded", status="success", details=details)
    (privacy,) = [c for c in calls if c[0] == "privacy"]
    (raw,) = privacy[3]
    assert raw == {"file_name": "report.pdf", "vault_name": "Finance", "size": 3, "parts": {"n": 1}, "tags": ["a"]}
    # build_row gives the row no details of its own: what it keeps is the recording levels' decision
    # (app/core/audit_privacy.py), here replaced by a recorder that decides nothing.
    assert row.details is None
    assert set(REDACTED_NAME_KEYS) >= {"file_name", "vault_name"}
    # A copy, all the way down: a hook that changes what it was given, or a value inside it, changes neither
    # the caller's dict nor the row.
    raw["size"] = 99
    raw.pop("file_name")
    raw["parts"]["n"] = 2
    raw["tags"].append("b")
    assert details == {"file_name": "report.pdf", "vault_name": "Finance", "size": 3, "parts": {"n": 1}, "tags": ["a"]}
    assert row.details is None


def test_privacy_is_given_what_the_caller_passed_when_it_is_not_a_dict(db, calls):
    AuditLogger(db).build_row(action="thing_done", status="success", details=None)
    AuditLogger(db).build_row(action="thing_done", status="success", details={"size": 1})
    raws = [c[3][0] for c in calls if c[0] == "privacy"]
    assert raws == [None, {"size": 1}]


def test_the_other_hooks_leave_their_columns_empty_and_privacy_stamps_the_policy(db):
    row = AuditLogger(db).log_action(action="thing_done", status="success", username="ada",
                                     details={"file_name": "x", "count": 1}, ip_address="192.0.2.7")
    db.expire_all()
    stored = db.query(AuditLog).one()
    assert (stored.seal_nonce, stored.ip_via, stored.case_id) == (None, None, None)
    # Policy 1 (app/core/audit_privacy.py) records what earlier releases did: no names, the rest in full,
    # and nothing in another form.
    assert (stored.privacy_version, stored.recorded) == (1, None)
    assert stored.id == row.id and stored.details == {"count": 1} and stored.ip_address == "192.0.2.7"


class _Untouchable:
    """A row stand-in that fails the moment anything is set on it or deleted from it."""
    id = uuid.uuid4()

    def __setattr__(self, name, value):
        raise AssertionError(f"a hook set {name}")

    def __delattr__(self, name):
        raise AssertionError(f"a hook deleted {name}")


@pytest.mark.parametrize("name", [h for h in HOOKS if h != "privacy"])
def test_each_hook_but_privacy_changes_nothing_and_returns_nothing(name):
    hook = getattr(audit_row_hooks, name)
    assert hook(_Untouchable()) is None


def test_privacy_hands_the_row_to_the_recording_levels(monkeypatch):
    from app.core import audit_privacy
    seen = []
    monkeypatch.setattr(audit_privacy, "apply", lambda row, raw: seen.append((row, raw)))
    row, raw = object(), {"file_name": "x"}
    assert audit_row_hooks.privacy(row, raw) is None
    assert seen == [(row, raw)] and raw == {"file_name": "x"}


def test_the_hooks_are_called_through_the_module_so_they_can_be_filled_in_one_place():
    # build_row names each hook through the module at call time, never a copy bound at import.
    source = inspect.getsource(AuditLogger.build_row)
    for name in HOOKS:
        assert source.count(f"audit_row_hooks.{name}(") == 1, name
    assert not re.search(r"from app\.services\.audit_row_hooks import", inspect.getsource(audit_logger))
