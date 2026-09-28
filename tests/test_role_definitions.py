"""The role catalogue the Users page shows says what each role can do in this release.

0.33.0 removed the Live Monitor page (the Activity page took its place), but the administrator's role
still listed "Access live monitoring" among its permissions.
"""
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _async_run import run_coroutine  # noqa: E402
from app.api import user_management_api as um  # noqa: E402

pytestmark = pytest.mark.unit


def test_no_role_promises_the_live_monitor_that_is_gone():
    roles = run_coroutine(um.get_role_definitions(current_user=SimpleNamespace(role="admin")))
    admin = next(r for r in roles if r.role == "admin")
    assert "Manage temporary credentials" in admin.permissions            # the list itself was read
    assert [p for r in roles for p in r.permissions if "monitor" in p.lower()] == []
