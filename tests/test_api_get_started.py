"""The administrators' Get-started checklist (GET and POST /admin/get-started).

Read from the deployment where it can be (mail set up and a test message sent, a public address, the
second-factor policy) and from what an administrator recorded where it cannot (a backup, the policy kept
optional on purpose, the list dismissed); only an interactive administrator reads or writes it; recorded.
"""
import os
import subprocess

import pytest

from conftest import ApiClient

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


@pytest.fixture
def fresh(admin):
    before = admin.get("/admin/get-started").json().get("recorded") or {}
    admin.post("/admin/get-started", json={"reset": True})
    yield
    admin.post("/admin/get-started", json={"reset": True})
    for key, flag in (("backup_recorded_at", "backup_recorded"), ("second_factor_decided_at", "second_factor_decided"),
                      ("dismissed_at", "dismissed")):
        if before.get(key):
            admin.post("/admin/get-started", json={flag: True})


def test_the_view_reads_the_deployment_and_what_was_recorded(admin, fresh):
    view = admin.get("/admin/get-started").json()
    assert set(view["items"]) == {"email", "public_address", "second_factor", "backup"}
    assert view["items"]["backup"] is False and view["dismissed"] is False
    assert view["items"]["email"] == (view["email_configured"] and view["test_email_sent"])
    mode = admin.get("/settings").json().get("mfa_mode")
    assert view["items"]["second_factor"] == (mode == "required")
    # Recording a backup and keeping the policy optional tick their items; dismissing hides the list.
    after = admin.post("/admin/get-started", json={"backup_recorded": True}).json()
    assert after["items"]["backup"] is True
    after = admin.post("/admin/get-started", json={"second_factor_decided": True}).json()
    assert after["items"]["second_factor"] is True
    after = admin.post("/admin/get-started", json={"dismissed": True}).json()
    assert after["dismissed"] is True
    # Start over clears what was recorded.
    again = admin.post("/admin/get-started", json={"reset": True}).json()
    assert again["items"]["backup"] is False and again["dismissed"] is False
    assert admin.post("/admin/get-started", json={"nothing": True}).status_code == 400
    assert int(_psql("SELECT count(*) FROM audit_logs WHERE action='get_started_updated'")) >= 4


def test_only_an_administrator_reads_or_writes_it(admin):
    u = admin.create_user(role="user")
    try:
        c = ApiClient()
        c.login(u["_username"], u["_password"])
        assert c.get("/admin/get-started").status_code == 403
        assert c.post("/admin/get-started", json={"backup_recorded": True}).status_code == 403
    finally:
        admin.delete_user(u["id"])
