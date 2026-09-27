"""The host operator's account tool (python -m app.core.host_operator), offline: the checks it makes
before it changes anything. test_host_operator_live.py runs it inside a running stack, and
test_dockvault_accounts.py covers the dockvault.py side that drives it."""
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit


def test_the_host_tool_changes_nothing_unless_the_username_is_typed_again():
    from app.core.host_operator import confirmation_problem
    assert confirmation_problem("alice", "alice") is None
    for typed in (None, "", "Alice", "alice ", "bob"):
        assert confirmation_problem("alice", typed), typed
    assert confirmation_problem("", "")


def test_the_host_tool_temporary_password_is_strong():
    from app.core.host_operator import temporary_password
    seen = set()
    for _ in range(50):
        pw = temporary_password()
        assert len(pw) == 20
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)
        seen.add(pw)
    assert len(seen) == 50
