"""Static and pure checks for the endpoint-permission contract."""

import ast
from pathlib import Path

import pytest

from app.core.api_catalog import (
    API_CATALOG,
    GRANTABLE_API_CATALOG,
    NON_GRANTABLE_ENDPOINT_GROUPS,
    dependency_closure,
    dependent_closure,
    validate_catalog,
)


pytestmark = pytest.mark.unit

_APP = Path("app")


def _guarded_group_names():
    guarded = set()
    for source_path in _APP.rglob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "require_endpoint_permission"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                guarded.add(node.args[0].value)
    return guarded


def test_guarded_and_grantable_groups_are_an_exact_set():
    assert _guarded_group_names() == set(GRANTABLE_API_CATALOG)


def test_infrastructure_groups_are_catalogued_but_never_grantable():
    assert NON_GRANTABLE_ENDPOINT_GROUPS == {"SYSTEM_HEALTH", "AUTH_LOGIN"}
    assert NON_GRANTABLE_ENDPOINT_GROUPS <= set(API_CATALOG)
    assert NON_GRANTABLE_ENDPOINT_GROUPS.isdisjoint(GRANTABLE_API_CATALOG)


def test_catalog_dependency_graph_is_valid_and_transitive():
    assert validate_catalog() == []
    assert dependency_closure("FILE_DOWNLOAD") == ["VAULT_VIEW", "FILE_VIEW"]
    assert set(dependent_closure("FILE_VIEW")) == {
        "FILE_DOWNLOAD",
        "FILE_UPLOAD",
        "FILE_DELETE",
        "FOLDER_MANAGE",
    }


def test_vault_membership_management_does_not_grant_user_directory_access():
    assert dependency_closure("VAULT_PERMISSIONS") == ["VAULT_VIEW"]


def test_application_enforces_the_contract_after_route_declaration():
    source = Path("app/api/api_server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "validate_endpoint_permission_contract"
    ]
    assert len(calls) == 1
