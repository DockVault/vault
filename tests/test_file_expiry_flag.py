"""The web app is told whether this server enforces file expiry.

With ENFORCE_FILE_EXPIRY=false nothing is deleted, but the web app still offered "expire files after"
and "delete uploads after" as if it were. GET /zk-enabled, the capabilities the web app reads at
sign-in (any signed-in user, never anonymous), now carries ``file_expiry_enforced``, and the web app
qualifies every retention it shows when it is false (tests/test_file_expiry_ui_text.py). This drives
the real endpoint function with the setting each way.
"""
import types

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core.config import settings  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def capabilities(monkeypatch):
    # Everything else the endpoint reports, held still: this is about one field.
    monkeypatch.setattr(S, "_allowed_vault_types", lambda: {"standard"})
    monkeypatch.setattr(S, "_zk_enabled", lambda db: False)
    monkeypatch.setattr(S, "_user_must_use_zk", lambda db, user: False)
    monkeypatch.setattr(S, "_zk_vault_count", lambda db: 0)
    monkeypatch.setattr(S, "_zk_idle_lock_minutes", lambda db: 0)
    monkeypatch.setattr(S, "_resolved_download_sink", lambda request, db, user: {"sink": "buffered"})

    def read():
        return run_coroutine(S.get_zk_enabled(request=None, current_user=types.SimpleNamespace(),
                                              db=None))
    return read


@pytest.mark.parametrize("enforced", [True, False])
def test_the_capabilities_say_whether_expiry_is_enforced(capabilities, monkeypatch, enforced):
    monkeypatch.setattr(settings, "enforce_file_expiry", enforced)
    assert capabilities()["file_expiry_enforced"] is enforced


def test_it_is_not_on_the_anonymous_policy():
    """The sign-in screen's public policy stays the small allowlist it is."""
    src = (S.PROJECT_ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index('@app.get("/auth/policy")')
    assert "file_expiry" not in src[start:src.index("\n@app.", start + 1)]
