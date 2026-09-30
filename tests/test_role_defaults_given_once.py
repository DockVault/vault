"""A role default an administrator revoked stays revoked across restarts, offline on a real database.

Every start used to grant each account that is not an administrator every default of its role again,
so a default an administrator had revoked (the permission to create vaults, to delete files, to hand
out temporary credentials) came back at the next restart, with nothing recorded. Now each group records
the revision of the defaults in which it became one (FunctionalityGroup.default_since), each account the
revision it has been given (users.permission_defaults_revision), and a start gives an account only the
defaults newer than that, once, recording each. `python dockvault.py accounts --action
regranted-defaults` lists what earlier restarts granted back (app/core/host_operator.py).
test_role_defaults_given_once_live.py restarts a running stack.
"""
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import endpoint_permissions as ep  # noqa: E402
from app.core import host_operator  # noqa: E402
from app.core.api_catalog import GRANTABLE_API_CATALOG  # noqa: E402
from app.core.models import AuditLog, RoleEnum, User, UserEndpointPermission  # noqa: E402

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 1, 12, 0, 0)


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'defaults.db'}")
        for model in (User, UserEndpointPermission, AuditLog):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _account(db, role=RoleEnum.USER, revision=None, name=None):
    account = User(id=uuid.uuid4(), username=name or f"u{uuid.uuid4().hex[:8]}", password_hash="x", role=role,
                   permission_defaults_revision=revision)
    db.add(account)
    db.flush()
    return account


def _held(db, account):
    return {row[0] for row in db.query(UserEndpointPermission.endpoint_group).filter(
        UserEndpointPermission.user_id == account.id).all()}


def _granted_rows(db):
    return db.query(AuditLog).filter(AuditLog.action == ep.DEFAULT_GRANTED_ACTION).all()


@pytest.fixture
def a_newer_default(monkeypatch):
    """USER_VIEW made a default of the user role in revision 2, as a later release would."""
    group = GRANTABLE_API_CATALOG["USER_VIEW"]
    monkeypatch.setattr(group, "default_for_roles", ["user", "admin"])
    monkeypatch.setattr(group, "default_since", 2)
    return "USER_VIEW"


# --------------------------------------------------------------------------- a start

def test_a_revoked_default_stays_revoked_at_the_next_start(db):
    account = _account(db)
    ep.grant_default_permissions_for_role(str(account.id), account.role, db)
    ep.revoke_endpoint_permission(str(account.id), "VAULT_CREATE", db)
    before = _held(db, account)
    assert "VAULT_CREATE" not in before

    assert ep.grant_newer_role_defaults(db) == {"accounts": 0, "grants": 0}
    assert ep.grant_newer_role_defaults(db) == {"accounts": 0, "grants": 0}
    assert _held(db, account) == before
    assert not _granted_rows(db)


def test_an_account_an_earlier_release_left_gets_nothing_at_its_first_start(db):
    # No revision recorded: it holds revision 1's defaults, less what was revoked since the last start.
    account = _account(db, revision=None)
    ep._insert_permission_groups(account.id, ep.role_default_groups(RoleEnum.USER), db, None)
    ep.revoke_endpoint_permission(str(account.id), "FILE_DELETE", db)
    before = _held(db, account)

    assert ep.grant_newer_role_defaults(db) == {"accounts": 1, "grants": 0}
    db.expire_all()
    assert _held(db, account) == before and "FILE_DELETE" not in before
    assert db.get(User, account.id).permission_defaults_revision == ep.current_defaults_revision() == 1
    assert not _granted_rows(db)


def test_a_default_added_in_a_later_revision_is_granted_once_and_recorded(db, a_newer_default):
    account = _account(db, revision=1)
    ep._insert_permission_groups(account.id, ep.role_default_groups(RoleEnum.USER, since=0), db, None)
    ep.revoke_endpoint_permission(str(account.id), a_newer_default, db)
    ep.revoke_endpoint_permission(str(account.id), "VAULT_DELETE", db)
    assert ep.current_defaults_revision() == 2

    assert ep.grant_newer_role_defaults(db) == {"accounts": 1, "grants": 1}
    db.expire_all()
    assert a_newer_default in _held(db, account)
    assert "VAULT_DELETE" not in _held(db, account), "only the newer default, not a revoked older one"
    assert db.get(User, account.id).permission_defaults_revision == 2
    (row,) = _granted_rows(db)
    assert row.resource_id == str(account.id) and row.user_id is None and row.status == "success"
    assert row.details["endpoint_group"] == a_newer_default
    assert (row.details["from_revision"], row.details["to_revision"]) == (1, 2)

    # Revoked after it was given: the next start leaves it revoked.
    ep.revoke_endpoint_permission(str(account.id), a_newer_default, db)
    assert ep.grant_newer_role_defaults(db) == {"accounts": 0, "grants": 0}
    assert a_newer_default not in _held(db, account)
    assert len(_granted_rows(db)) == 1


def test_an_account_an_earlier_release_left_gets_a_later_revisions_default(db, a_newer_default):
    account = _account(db, revision=None)
    assert ep.grant_newer_role_defaults(db) == {"accounts": 1, "grants": 1}
    assert _held(db, account) == {a_newer_default}


def test_a_newer_default_brings_what_it_depends_on(db, monkeypatch):
    group = GRANTABLE_API_CATALOG["USER_MANAGE"]          # depends on USER_VIEW
    monkeypatch.setattr(group, "default_for_roles", ["user", "admin"])
    monkeypatch.setattr(group, "default_since", 2)
    account = _account(db, revision=1)
    assert ep.grant_newer_role_defaults(db)["grants"] == 2
    assert _held(db, account) == {"USER_VIEW", "USER_MANAGE"}


def test_administrators_are_left_alone(db, a_newer_default):
    admin = _account(db, role=RoleEnum.ADMIN, revision=None)
    assert ep.grant_newer_role_defaults(db) == {"accounts": 0, "grants": 0}
    assert _held(db, admin) == set() and db.get(User, admin.id).permission_defaults_revision is None


def test_an_account_given_the_current_revision_is_not_touched(db, a_newer_default):
    account = _account(db, revision=2)
    assert ep.grant_newer_role_defaults(db) == {"accounts": 0, "grants": 0}
    assert _held(db, account) == set()


# --------------------------------------------------------------------------- what records the revision

def test_creating_an_account_records_the_current_revision(db, a_newer_default):
    account = _account(db, revision=None)
    ep.grant_default_permissions_for_role(str(account.id), account.role, db)
    assert db.get(User, account.id).permission_defaults_revision == 2


def test_a_change_of_role_records_the_current_revision(db):
    account = _account(db, role=RoleEnum.ADMIN, revision=None)
    ep.reset_to_role_defaults(account.id, RoleEnum.USER, db)
    db.commit()
    assert db.get(User, account.id).permission_defaults_revision == 1


def test_the_start_up_backfill_is_the_revision_aware_one():
    import ast
    import inspect
    from app.api import api_server
    tree = ast.parse(inspect.getsource(api_server._backfill_default_permissions))
    called = {getattr(n.func, "id", getattr(n.func, "attr", None)) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert "grant_newer_role_defaults" in called
    assert "grant_default_permissions_for_role" not in called


def test_the_boot_ddl_adds_the_column():
    root = Path(__file__).resolve().parent.parent
    source = (root / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert source.count(
        '"ALTER TABLE users ADD COLUMN IF NOT EXISTS permission_defaults_revision INTEGER"') == 1


def test_the_grant_is_catalogued_as_the_servers_own():
    from app.core import audit_catalog
    entry = audit_catalog.lookup(ep.DEFAULT_GRANTED_ACTION)
    assert entry is not None and entry.category == "accounts" and entry.automatic


# --------------------------------------------------------------------------- regranted-defaults

def _audit(db, action, account, when, **details):
    db.add(AuditLog(id=uuid.uuid4(), action=action, status="success", resource_type="permission",
                    resource_id=str(account.id), timestamp=when, details=details))


def _row(db, account, group, when, by=None):
    db.add(UserEndpointPermission(id=uuid.uuid4(), user_id=account.id, endpoint_group=group, granted_at=when,
                                  granted_by=by))


def _listed(db):
    db.commit()
    return {(r["username"], r["group"]) for r in host_operator.regranted_defaults(db)}


def test_a_default_revoked_and_granted_again_by_a_restart_is_listed(db):
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="VAULT_VIEW",
           revoked_groups=["VAULT_VIEW", "VAULT_CREATE", "FILE_VIEW"])
    _row(db, a, "VAULT_CREATE", T0 + timedelta(hours=3))
    _row(db, a, "VAULT_VIEW", T0 + timedelta(hours=3))
    db.commit()
    (first, second) = sorted(host_operator.regranted_defaults(db), key=lambda r: r["group"])
    assert (first["username"], first["group"], second["group"]) == ("alice", "VAULT_CREATE", "VAULT_VIEW")
    assert first["revoked_at"] == T0.isoformat() + "Z"
    assert first["granted_again_at"] == (T0 + timedelta(hours=3)).isoformat() + "Z"


def test_a_revocation_from_the_earliest_releases_names_only_its_group(db):
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE")
    _row(db, a, "FILE_DELETE", T0 + timedelta(minutes=5))
    assert _listed(db) == {("alice", "FILE_DELETE")}


def test_a_revocation_that_held_is_not_listed(db):
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _row(db, a, "FILE_UPLOAD", T0 + timedelta(hours=1))           # a different group
    assert _listed(db) == set()


def test_a_row_older_than_the_revocation_is_not_listed(db):
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _row(db, a, "FILE_DELETE", T0 - timedelta(hours=1))
    assert _listed(db) == set()


def test_a_permission_an_administrator_granted_again_is_not_listed(db):
    a = _account(db, name="alice")
    admin = _account(db, role=RoleEnum.ADMIN, name="root")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _row(db, a, "FILE_DELETE", T0 + timedelta(hours=1), by=admin.id)
    assert _listed(db) == set()


@pytest.mark.parametrize("action,details", [
    ("GRANT_PERMISSION", {"endpoint_group": "FILE_DELETE", "granted_groups": ["FILE_VIEW", "FILE_DELETE"]}),
    ("GRANT_PERMISSION", {"endpoint_group": "FILE_DELETE"}),
    ("permissions_reset_for_role", {"added": ["FILE_DELETE"], "removed": []}),
    ("permission_default_granted", {"endpoint_group": "FILE_DELETE"}),
])
def test_a_grant_the_audit_log_explains_is_not_listed(db, action, details):
    # An administrator's grant whose granter was deleted since (granted_by NULL), a change of role, or a
    # start giving a newer default: each is recorded, and none is a restart undoing a revocation.
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _audit(db, action, a, T0 + timedelta(hours=1), **details)
    _row(db, a, "FILE_DELETE", T0 + timedelta(hours=1))
    assert _listed(db) == set()


def test_a_prerequisite_an_administrators_grant_brought_back_is_not_listed(db):
    # Granting FILE_DELETE grants FILE_VIEW, which it needs, with it: the row names FILE_DELETE and lists both.
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_VIEW", revoked_groups=["FILE_VIEW"])
    _audit(db, "GRANT_PERMISSION", a, T0 + timedelta(hours=1), endpoint_group="FILE_DELETE",
           granted_groups=["FILE_VIEW", "FILE_DELETE"])
    _row(db, a, "FILE_VIEW", T0 + timedelta(hours=1))
    assert _listed(db) == set()


def test_an_explanation_older_than_the_latest_revocation_does_not_count(db):
    a = _account(db, name="alice")
    _audit(db, "GRANT_PERMISSION", a, T0 - timedelta(days=1), endpoint_group="FILE_DELETE")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _row(db, a, "FILE_DELETE", T0 + timedelta(hours=1))
    assert _listed(db) == {("alice", "FILE_DELETE")}


def test_the_latest_revocation_counts(db):
    a = _account(db, name="alice")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _audit(db, "REVOKE_PERMISSION", a, T0 + timedelta(days=2), endpoint_group="FILE_DELETE",
           revoked_groups=["FILE_DELETE"])
    _row(db, a, "FILE_DELETE", T0 + timedelta(days=1))           # given back, then revoked again since
    assert _listed(db) == set()


def test_another_accounts_revocation_does_not_count(db):
    a, b = _account(db, name="alice"), _account(db, name="bob")
    _audit(db, "REVOKE_PERMISSION", a, T0, endpoint_group="FILE_DELETE", revoked_groups=["FILE_DELETE"])
    _row(db, b, "FILE_DELETE", T0 + timedelta(hours=1))
    assert _listed(db) == set()


def test_a_failed_revocation_does_not_count(db):
    a = _account(db, name="alice")
    db.add(AuditLog(id=uuid.uuid4(), action="REVOKE_PERMISSION", status="failure", resource_type="permission",
                    resource_id=str(a.id), timestamp=T0, details={"endpoint_group": "FILE_DELETE"}))
    _row(db, a, "FILE_DELETE", T0 + timedelta(hours=1))
    assert _listed(db) == set()


def test_the_host_tool_offers_the_action():
    import importlib.util
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("dockvault_cli", root / "dockvault.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    assert "regranted-defaults" in dict(cli.ACCOUNT_ACTIONS)
    assert "regranted-defaults" in host_operator.ACTIONS
    assert host_operator.build_parser().parse_args(["regranted-defaults"]).action == "regranted-defaults"
