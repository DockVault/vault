"""Permission settings UI must reflect dependency side effects from the server."""

from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_APP_JS = Path("static/js/app.js").read_text(encoding="utf-8")


def test_permission_dependency_copy_describes_automatic_grants():
    assert " · also grants ${g.dependencies.map(dep => escapeHtml(dep)).join(', ')}" in _APP_JS
    assert " · needs ${g.dependencies.join(', ')}" not in _APP_JS


def test_permission_toggles_apply_server_reported_grant_and_revoke_cascades():
    assert "result.granted_groups" in _APP_JS
    assert "result.revoked_groups" in _APP_JS
    assert "changedGroups.has(toggle.dataset.group)" in _APP_JS
