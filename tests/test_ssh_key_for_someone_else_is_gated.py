"""Adding an SSH key to someone else's account takes the USER_MANAGE permission and the
admin.user.manage step-up, like the other four credential changes, offline.

A key signs in to SFTP as the account it is on. Setting someone's password, sending them a reset link,
resetting their second factor and changing their email all ask for both; adding a key was the one
credential change that asked for neither. Adding your OWN key is not an administrator's action and
asks for neither. test_api_second_factor_admin_routes.py drives the step-up on a running stack."""
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import endpoint_permissions  # noqa: E402

pytestmark = pytest.mark.unit


class _Parsed(Exception):
    """Raised by the stand-in key parser: the route got past its gates."""


@pytest.fixture
def gates(monkeypatch):
    seen = []

    def permission(db, user, group, kwargs=None):
        seen.append(("permission", group))

    def step_up(db, user, request, action):
        seen.append(("step_up", action))
        raise HTTPException(status_code=403, detail={"second_factor_required": True, "action": action})

    def parse(_key):
        raise _Parsed()

    monkeypatch.setattr(endpoint_permissions, "check_endpoint_permission", permission)
    monkeypatch.setattr(api, "_enforce_step_up", step_up)
    monkeypatch.setattr(api, "_parse_ssh_public_key", parse)
    return seen


def _add(monkeypatch, caller_id, target_id):
    monkeypatch.setattr(api, "_ssh_key_target_user", lambda uid, cu, db, write=False: SimpleNamespace(id=target_id))
    caller = SimpleNamespace(id=caller_id, username="alice", role=api.RoleEnum.ADMIN)
    body = api.SSHKeyCreate(name="laptop", public_key="ssh-ed25519 AAAA")
    return run_coroutine(api.add_ssh_key(user_id=target_id, body=body, request=SimpleNamespace(headers={}),
                                         current_user=caller, db=None))


def test_a_key_for_someone_else_needs_the_permission_and_the_step_up(monkeypatch, gates):
    with pytest.raises(HTTPException) as refused:
        _add(monkeypatch, uuid.uuid4(), uuid.uuid4())
    assert refused.value.status_code == 403
    assert gates == [("permission", "USER_MANAGE"), ("step_up", "admin.user.manage")]


def test_your_own_key_needs_neither(monkeypatch, gates):
    me = uuid.uuid4()
    with pytest.raises(_Parsed):
        _add(monkeypatch, me, me)
    assert gates == []
