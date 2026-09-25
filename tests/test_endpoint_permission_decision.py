"""The endpoint-permission decision can be asked without logging a refusal.

The vault list shows a member count only on the vaults whose member list the caller may see, which
depends on the member-list permission group. Asking that through check_endpoint_permission would
write an "endpoint_permission_denied" audit row for every user without it, on every page load, and
bury the refusals a defender needs to see. endpoint_permission_denial is the same decision with no
audit row and no exception; check_endpoint_permission is that decision plus both, so the two cannot
drift apart.
"""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import app.core.endpoint_permissions as ep
import app.core.temp_scope as ts
from app.core.models import RoleEnum

pytestmark = pytest.mark.unit

GROUP = "VAULT_PERMISSIONS"


@pytest.fixture
def audited(monkeypatch):
    rows = []
    monkeypatch.setattr(ep, "_audit_endpoint_denial",
                        lambda db, user, group, reason: rows.append((group, reason)))
    return rows


def _holds(monkeypatch, held):
    monkeypatch.setattr(ep, "_user_has_required_groups", lambda db, user_id, group: held)


def _user(role=RoleEnum.USER, temp=False):
    user = SimpleNamespace(id=uuid.uuid4(), role=role)
    if temp:
        user._is_temp_session = True
    return user


def test_asking_writes_no_audit_row_and_raises_nothing(monkeypatch, audited):
    _holds(monkeypatch, False)
    assert ep.endpoint_permission_denial(object(), _user(), GROUP) == "missing_required_group"
    assert audited == [], "a question about permission was logged as a refusal"


def test_the_check_still_logs_and_refuses_the_same_decision(monkeypatch, audited):
    _holds(monkeypatch, False)
    with pytest.raises(HTTPException) as refused:
        ep.check_endpoint_permission(object(), _user(), GROUP)
    assert refused.value.status_code == 403
    assert GROUP in refused.value.detail
    assert audited == [(GROUP, "missing_required_group")]


def test_a_permitted_caller_is_neither_refused_nor_logged(monkeypatch, audited):
    _holds(monkeypatch, True)
    assert ep.endpoint_permission_denial(object(), _user(), GROUP) is None
    ep.check_endpoint_permission(object(), _user(), GROUP)
    _holds(monkeypatch, False)
    assert ep.endpoint_permission_denial(object(), _user(RoleEnum.ADMIN), GROUP) is None
    assert audited == []


def test_a_temporary_credential_is_judged_by_its_scope_even_for_an_admin(monkeypatch, audited):
    _holds(monkeypatch, True)
    monkeypatch.setattr(ts, "temp_session_allows_group", lambda user, group, kwargs: False)
    admin_temp = _user(RoleEnum.ADMIN, temp=True)
    assert ep.endpoint_permission_denial(object(), admin_temp, GROUP) == "temp_credential_scope"
    assert audited == []
    with pytest.raises(HTTPException) as refused:
        ep.check_endpoint_permission(object(), admin_temp, GROUP)
    assert refused.value.status_code == 403
    assert "Temporary credential scope" in refused.value.detail
    assert audited == [(GROUP, "temp_credential_scope")]


def test_a_temporary_credential_in_scope_still_needs_its_owner_groups(monkeypatch, audited):
    monkeypatch.setattr(ts, "temp_session_allows_group", lambda user, group, kwargs: True)
    _holds(monkeypatch, False)
    assert ep.endpoint_permission_denial(object(), _user(temp=True), GROUP) == "missing_required_group"
    assert ep.endpoint_permission_denial(object(), _user(RoleEnum.ADMIN, temp=True), GROUP) is None
    assert audited == []
