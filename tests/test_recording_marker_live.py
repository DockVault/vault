"""The rollback marker of the recording levels on a running stack (app/core/recording_marker.py).

A save that records less than earlier releases puts the marker in data_requirements, in the save's
transaction, and the upgrade condition's detect query finds the same; setting the levels back removes it.
"""
import pytest

from _account_change_helpers import psql
from _recording_levels import levels_restored  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

ACTION = "admin.audit_privacy.write"
DETECT = ("SELECT count(*) FROM audit_privacy_policies WHERE version = (SELECT max(version) FROM "
          "audit_privacy_policies) AND (signin_names <> 'full' OR emails <> 'full' OR ip <> 'full' OR "
          "user_agent <> 'full')")


def _save(admin, password, levels):
    receipt = admin.post("/auth/second-factor/step-up",
                         json={"action": ACTION, "method": "password", "code": password}).json()["receipt"]
    r = admin.put("/settings/recording", json={"levels": levels}, headers={"X-Second-Factor": receipt})
    assert r.status_code == 200, r.text
    return r.json()["version"]


def _marker():
    return psql("SELECT coalesce((SELECT key || '|' || requires_at_least || '|' || (since IS NOT NULL)::text "
                "FROM data_requirements WHERE key = 'recording-levels'), '')")


def test_the_marker_is_there_while_the_levels_record_less(admin, admin_creds, levels_restored):
    version = (open("VERSION", encoding="utf-8").read().strip())
    _save(admin, admin_creds["password"], dict(levels_restored, ip="shortened"))
    key, required, since = _marker().split("|")
    assert key == "recording-levels" and since == "true"
    assert required == (version if tuple(map(int, version.split("."))) < (0, 34, 0) else "0.34.0")
    assert psql(DETECT) == "1"
    _save(admin, admin_creds["password"], dict(levels_restored, ip="full"))
    assert _marker() == "" and psql(DETECT) == "0"
